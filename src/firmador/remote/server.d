/* Firmador is a program to sign documents using AdES standards.

Copyright (C) Firmador authors.

This file is part of Firmador.

Firmador is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Firmador is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Firmador.  If not, see <http://www.gnu.org/licenses/>.  */

/**
 * Firmador Remoto (RemoteHttpWorker): el servidor local con el que las páginas autorizadas
 * piden firmas (@contract remote-api). /ok y /doRegister se atienden con cualquier origen;
 * lo demás sólo con orígenes autorizados (o que el usuario autoriza en ese momento en el
 * modo simplificado). Rutas: /certificates, /sign, /multipleSign, /signDocument,
 * /authenticate, /close, y /{nombre} para enviar un documento a la ventana y sondear su
 * resultado (202 mientras espera, 200 con el firmado, 406 si se rechazó; DELETE lo quita).
 */
module firmador.remote.server;

import core.sync.mutex : Mutex;
import std.algorithm : startsWith;
import std.datetime.systime : Clock;
import std.format : format;
import std.json : JSONValue, toJSON;
import std.logger : error, info, warning;
import std.string : strip;

import firmador.cards.cardinfo;
import firmador.cards.detector : SmartCardDetector;
import firmador.configuration : remoteAppId;
import firmador.connections.config : firmadorRemotoService;
import firmador.documents.document;
import firmador.documents.mimetype : SupportedMimeType;
import firmador.gui.guiinterface;
import firmador.i18n : t;
import firmador.remote.dto;
import firmador.remote.http;
import firmador.remote.origins;
import firmador.remote.slot;
import firmador.settings : Settings;
import firmador.settingsmanager : currentSettings;
import firmador.signers.common : rootCause;
import firmador.signers.documentsigner : SigningInput;
import firmador.signers.xades : XadesSigner;
import firmador.util.base64 : encodeBase64;
import firmador.util.json : parseJsonText;

/// Respuesta JSON.
private immutable(ubyte)[] jsonBytes(const JSONValue value) @safe {
  return cast(immutable(ubyte)[]) toJSON(value);
}

/// Servidor de Firmador Remoto en un puerto.
final class RemoteServer {
  private GuiInterface gui;
  private SmartCardDetector detector;
  private ushort port;
  private HttpServer server;
  private Mutex slotsLock;
  private RemoteDocumentSlot[string] slots;

  this(GuiInterface gui, SmartCardDetector detector, ushort port) @safe {
    this.gui = gui;
    this.detector = detector;
    this.port = port;
    slotsLock = new Mutex;
  }

  ushort listeningPort() const pure nothrow @safe @nogc {
    return port;
  }

  /**
   * Empieza a atender. Si el puerto está ocupado o no se puede abrir, lo informa en el
   * panel de conexiones y devuelve false.
   */
  bool start() @trusted {
    if (isLoopbackPortInUse(port)) {
      reportErrors([t("remote_http_worker_port_busy") ~ " " ~ format("%d", port)]);
      return false;
    }
    try {
      server = new HttpServer(port, &handle);
      server.start();
      info(t("remote_http_worker_listening_on"), " ", port);
      return true;
    } catch (Exception exception) {
      error(t("remote_http_worker_error_starting_server"), " ", port, ": ", exception.msg);
      reportErrors([t("remote_http_worker_error_starting_server") ~ " " ~ format("%d", port)]);
      return false;
    }
  }

  /// Deja de atender.
  void stop() @safe {
    if (server !is null) server.stop();
  }

  /// Está atendiendo su puerto.
  bool isRunning() pure @safe {
    return server !is null && server.isRunning();
  }

  /// Documento enviado con ese nombre, o null.
  RemoteDocumentSlot findDocument(string name) pure @trusted {
    synchronized (slotsLock) {
      if (auto slot = name in slots) return *slot;
      return null;
    }
  }

  private void reportErrors(string[] errors) @safe {
    string[] cleaned;
    foreach (message; errors) if (message.strip.length) cleaned ~= message.strip;
    if (cleaned.length == 0) return;
    error(t("remote_http_worker_error"), cleaned);
    gui.connectionErrors(firmadorRemotoService, cleaned);
  }

  private CardSignInfo cardFor(string identifier) @safe {
    try {
      foreach (card; detector.readCardsWithIdentity()) if (matchesIdentifier(card, identifier)) return card;
    } catch (Exception exception) {
      error(t("remote_http_worker_error_get_cards"), ": ", exception.msg);
    }
    return null;
  }

  private void handle(ref const HttpRequest request, ref HttpResponse response) @trusted {
    string origin = request.header("origin");
    if (origin is null) origin = "null";
    response.setHeader("Access-Control-Allow-Private-Network", "true");
    auto settings = currentSettings();
    // /doRegister y /ok los usa una página que todavía no está autorizada.
    if (request.path.startsWith("/doRegister") || request.path.startsWith("/ok")) {
      response.setHeader("Access-Control-Allow-Origin", "*");
    } else if (isOriginAllowed(settings, origin)) {
      response.setHeader("Access-Control-Allow-Origin", origin);
    } else {
      auto pending = awaitPendingAuthorization(origin);
      bool simplified = !settings.simplified_mode.isNull && settings.simplified_mode.get;
      // Con la ventana de autorización abierta se espera su respuesta; en el modo
      // simplificado (sin pestaña de conexiones) se pregunta en la propia solicitud.
      if ((!pending.isNull && pending.get) || (pending.isNull && simplified && authorizeOrigin(gui, settings, origin))) {
        response.setHeader("Access-Control-Allow-Origin", origin);
      } else {
        synchronized (settings) settings.addNoAuthorizedHost(origin);
        response.setHeader("Access-Control-Allow-Origin", "null");
        response.status = 403;
        reportErrors([t("remote_http_worker_error_origin_not_allowed") ~ origin]);
        return;
      }
    }
    response.setHeader("Vary", "Origin");
    response.setHeader("Referrer-Policy", "unsafe-url");
    response.addHeader("Access-Control-Allow-Headers", "X-PINGOTHER, Origin, X-Requested-With, Content-Type, Accept");
    response.addHeader("Access-Control-Allow-Headers", "*");
    try {
      route(request, response, origin);
    } catch (Exception exception) {
      auto cause = rootCause(exception);
      error("Error procesando petición ", request.path, ": ", cause.msg);
      gui.showError(cause);
      response = HttpResponse(204);
      reportErrors([cause.msg]);
    }
  }

  private void route(ref const HttpRequest request, ref HttpResponse response, string origin) @trusted {
    string path = request.path;
    bool preflight = request.method == "OPTIONS";
    if (path == "/certificates") {
      JSONValue[] cards;
      foreach (card; detector.readCardsWithIdentity()) cards ~= card.toJson();
      response.json(jsonBytes(JSONValue(cards)));
      return;
    }
    // Las rutas de firma aceptan la consulta previa de CORS; /signDocument y /multipleSign van antes que /sign.
    SigningRoute[4] signingRoutes = [SigningRoute("/signDocument", &signDocument),
      SigningRoute("/multipleSign", &multipleSign), SigningRoute("/sign", &signPrepared),
      SigningRoute("/authenticate", &authenticate)];
    foreach (signingRoute; signingRoutes) {
      if (!path.startsWith(signingRoute.prefix)) continue;
      if (preflight) response.status = 204;
      else signingRoute.handler(request, response);
      return;
    }
    if (path.startsWith("/ok")) {
      JSONValue status;
      status["app"] = remoteAppId;
      status["port"] = port;
      status["authorized"] = isOriginAllowed(currentSettings(), origin);
      response.json(jsonBytes(status));
    } else if (path.startsWith("/doRegister")) {
      if (isOriginAllowed(currentSettings(), origin)) response.status = 202;
      else response.status = authorizeOrigin(gui, currentSettings(), origin) ? 200 : 403;
    } else if (path == "/close") {
      info("Firmador Remoto: /close");
      response.status = 200;
    } else {
      documentExchange(request, response);
    }
  }

  /// Envío de un documento a la ventana y sondeo de su resultado.
  private void documentExchange(ref const HttpRequest request, ref HttpResponse response) @trusted {
    string name = request.path.length > 1 ? request.path[1 .. $] : "";
    if (request.method == "DELETE") {
      synchronized (slotsLock) {
        response.status = (name in slots) !is null ? 200 : 404;
        slots.remove(name);
      }
      return;
    }
    bool hasBody = request.body.length > 0;
    RemoteDocumentSlot slot;
    bool fresh;
    synchronized (slotsLock) {
      auto previous = name in slots;
      // Un documento rechazado se puede volver a enviar con contenido.
      bool rejected = previous !is null && (*previous).status == RemoteStatus.notAcceptable;
      if (previous is null || (rejected && hasBody)) {
        slot = new RemoteDocumentSlot(name, request.body, hasBody ? RemoteStatus.accepted : RemoteStatus.noContent);
        if (hasBody) {
          slots[name] = slot;
          fresh = true;
        }
      } else {
        slot = *previous;
      }
    }
    if (fresh) {
      info("Firmador Remoto recibió el documento ", name);
      gui.loadRemoteDocument(slot);
    }
    auto status = slot.status;
    response.status = status;
    if (status != RemoteStatus.noContent) {
      response.body = slot.signed;
      response.setHeader("Content-Type", "text/plain; charset=ISO-8859-1");
    }
  }

  /**
   * Lo común de las rutas de firma: busca la credencial `serial` (400 si no está o, con
   * `needsCertificate`, si no trae su certificado), pide el PIN con la descripción e imagen
   * de la página (406 si no se da), firma con `sign` y responde su JSON (406 si no se pudo
   * firmar: `sign` devuelve null). Después cierra la sesión de la tarjeta, para que la
   * próxima firma vuelva a pedir el PIN.
   */
  private void signWithRemoteCard(ref HttpResponse response, string serial, string description,
      immutable(ubyte)[] image, scope JSONValue delegate(CardSignInfo card) @safe sign, bool needsCertificate = false)
      @trusted {
    auto card = cardFor(serial);
    if (card is null || (needsCertificate && card.certificate is null)) {
      response.status = 400;
      return;
    }
    scope (exit) card.destroyPin();
    if (!gui.requestRemotePin(card, description, image)) {
      response.status = 406;
      return;
    }
    JSONValue answer;
    try {
      answer = sign(card);
    } finally {
      detector.restoreSessions();
    }
    if (answer.isNull) {
      response.status = 406;
      return;
    }
    response.json(jsonBytes(answer));
  }

  /// /sign: firma un resumen preparado por el servidor de la página.
  private void signPrepared(ref const HttpRequest request, ref HttpResponse response) @trusted {
    auto signRequest = parseRemoteSignRequest(parseJsonText(cast(string) request.body, "La solicitud /sign"));
    signWithRemoteCard(response, signRequest.serialNumber, signRequest.documentName, requestImage(signRequest.b64image),
      (card) {
        auto answers = signRemoteRequests(gui, card, [signRequest]);
        return answers is null ? JSONValue(null) : answers[0];
      });
  }

  /// /multipleSign: varios resúmenes con un solo PIN.
  private void multipleSign(ref const HttpRequest request, ref HttpResponse response) @trusted {
    auto requests = parseRemoteSignRequests(parseJsonText(cast(string) request.body, "La solicitud /multipleSign"));
    if (requests.length == 0) {
      response.status = 400;
      return;
    }
    signWithRemoteCard(response, requests[0].serialNumber, t("remote_http_worker_multiple_sign_documents"), null,
      (card) {
        auto answers = signRemoteRequests(gui, card, requests);
        return answers is null ? JSONValue(null) : JSONValue(answers);
      });
  }

  /// /signDocument: firma un documento completo con los ajustes que trae.
  private void signDocument(ref const HttpRequest request, ref HttpResponse response) @trusted {
    auto signRequest = parseSignDocumentRequest(parseJsonText(cast(string) request.body, "La solicitud /signDocument"),
      currentSettings());
    auto document = new Document(gui, signRequest.document, "document" ~ signRequest.extension);
    document.setSettings(signRequest.settings);
    signWithRemoteCard(response, signRequest.serialNumber, t("remote_http_worker_signing_from_web"), null, (card) {
      document.sign(card);
      auto signed = document.signedContent;
      if (signed is null) return JSONValue(null);
      JSONValue result;
      result["bytes"] = encodeBase64(signed);
      return result;
    });
  }

  /// /authenticate: firma el XML de autorización de ingreso a una plataforma.
  private void authenticate(ref const HttpRequest request, ref HttpResponse response) @trusted {
    auto authRequest = parseAuthenticationRequest(parseJsonText(cast(string) request.body, "La solicitud /authenticate"));
    signWithRemoteCard(response, authRequest.serialNumber, authenticationDescription(authRequest),
      requestImage(authRequest.b64image), (card) {
        SigningInput input;
        input.content = authenticationDocument(authRequest, card.certificate, Clock.currTime);
        input.name = "autorizacion.xml";
        input.mimeType = SupportedMimeType.XML;
        input.settings = currentSettings();
        auto signed = new XadesSigner(gui, true).sign(input, card);
        return signed is null ? JSONValue(null) : remoteDocumentJson(signed, "autorizacion_autenticacion.xml");
      }, true);
  }
}

/// Ruta de firma de Firmador Remoto: el prefijo de la ruta y quién la atiende.
private struct SigningRoute {
  string prefix;
  void delegate(ref const HttpRequest request, ref HttpResponse response) @trusted handler;
}
