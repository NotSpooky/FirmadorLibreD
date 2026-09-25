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
 * Servicios externos con documentos virtuales (RemoteIntegration, VirtualSigner y
 * ConnectionUtils en la versión Java, @contract external-service): el servicio publica
 * documentos que se firman en su servidor; Firmador presenta los certificados de la
 * tarjeta, abre el inicio de sesión en el navegador, guarda los tokens en el almacén
 * cifrado (firmador.connections.tokenstore) y atiende los eventos del servicio (SSE):
 * firmar, alert, load, notification, login, validation y cancelled.
 *
 * Firmar un documento virtual va en dos pasos: requestHashesToSign pide al servicio que
 * prepare los resúmenes, que llegan como evento «firmar»; completeSignRequests los firma
 * con la tarjeta y los devuelve. Un 403 en cualquier petición con sesión cierra la
 * conexión (ConnectionManager.forbidden). El TLS se verifica con las raíces del sistema.
 */
module firmador.connections.external;

import core.atomic : atomicLoad, atomicStore;
import core.sync.mutex : Mutex;
import core.thread : Thread;
import std.array : replace;
import std.base64 : Base64;
import std.exception : enforce;
import std.format : format;
import std.json : JSONType, JSONValue, toJSON;
import std.logger : error, info;
import std.socket : Socket;
import std.string : indexOf, strip;
import std.uuid : parseUUID, UUID, UUIDParsingException;

import firmador.cards.cardinfo : CardSignInfo, matchesIdentifier;
import firmador.configuration : integrationUserAgent;
import firmador.connections.config;
import firmador.connections.connection;
import firmador.connections.tokenstore;
import firmador.documents.document : Document;
import firmador.gui.guiinterface : NotificationType;
import firmador.i18n : t;
import firmador.net.http;
import firmador.remote.dto : parseRemoteSignRequests, requestImage, RemoteSignRequest, signRemoteRequests;
import firmador.settings : Settings;
import firmador.settingsjson : settingsToJson;
import firmador.settingsmanager : currentSettings;
import firmador.util.desktop : openUrl;
import firmador.util.json;

/// Respuesta a la negociación (201): token de conexión, ruta de alta y, si la trae, URL de inicio de sesión.
struct ExternalNegotiation {
  string connectionToken;
  string url;
  string loginUrl;
}

/**
 * Interpreta la negociación.
 *
 * Throws: JsonShapeException si falta un campo.
 */
ExternalNegotiation parseExternalNegotiation(const JSONValue json) pure @safe {
  enum what = "La negociación con el servicio";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  ExternalNegotiation negotiation;
  negotiation.connectionToken = requiredString(json, "connection_token", what);
  negotiation.url = requiredString(json, "url", what);
  negotiation.loginUrl = optionalString(json, "login_url", what);
  return negotiation;
}

/// Respuesta al alta de la tarjeta (201): flujo de eventos, identificador del firmador y alias de los tokens.
struct ExternalSession {
  string sseUrl;
  string firmadorId;
  string tokenAlias;
}

/**
 * Interpreta el alta de la tarjeta.
 *
 * Throws: JsonShapeException si falta un campo.
 */
ExternalSession parseExternalSession(const JSONValue json) pure @safe {
  enum what = "El alta en el servicio";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  ExternalSession session;
  session.sseUrl = requiredString(json, "sse_url", what);
  session.firmadorId = requiredString(json, "firmador_id", what);
  session.tokenAlias = requiredString(json, "alias", what);
  return session;
}

/// Tokens que entrega el servicio al terminar el inicio de sesión («login»).
struct LoginInfo {
  string accessToken;
  string refreshToken;
  string idToken;
  string tokenAlias;
  string user;
}

/// Documento virtual publicado por el servicio («load»).
struct VirtualDocumentInfo {
  UUID id;
  string name;
  string mimeType;
  int pages;
  string serial;
  string origin;
  string expirationDate;
  string createdAt;
}

/// Evento del servicio, ya interpretado.
struct ExternalEvent {
  enum Kind { ignored, sign, expired, deactivated, alert, load, notification, login, validation, cancelled }
  Kind kind;
  /// sign: resúmenes que hay que firmar.
  RemoteSignRequest[] signRequests;
  /// expired: identificador del documento vencido.
  string documentKey;
  /// alert, deactivated, notification: texto que se muestra.
  string message;
  /// load: documentos publicados.
  VirtualDocumentInfo[] documents;
  /// login: tokens de la sesión.
  LoginInfo login;
  /// validation, cancelled: documento al que se refiere.
  UUID documentId;
  /// validation: reporte de validación.
  string report;
}

/**
 * Interpreta un evento del flujo del servicio por su «accion».
 *
 * Throws: JsonShapeException si la acción es conocida pero le faltan datos.
 */
ExternalEvent parseExternalEvent(const JSONValue json) @safe {
  enum what = "El evento del servicio";
  ExternalEvent event;
  if (!isObject(json)) return event;
  string action = optionalString(json, "accion", what);
  switch (action) {
    case "firmar":
      event.kind = ExternalEvent.Kind.sign;
      auto documents = member(json, "documents");
      enforce!JsonShapeException(documents !is null, what ~ ": falta «documents»");
      event.signRequests = parseRemoteSignRequests(*documents);
      break;
    case "alert":
      auto message = member(json, "message");
      if (message is null || message.type == JSONType.null_) return event;
      if (isObject(*message)) {
        string kind = optionalString(*message, "event", what);
        if (kind == "expired") {
          event.kind = ExternalEvent.Kind.expired;
          event.documentKey = jsonText(requiredMember(*message, "id", what));
        } else if (kind == "desactivate") {
          event.kind = ExternalEvent.Kind.deactivated;
          event.message = optionalString(*message, "message", what);
        }
      } else {
        event.kind = ExternalEvent.Kind.alert;
        event.message = jsonText(*message);
      }
      break;
    case "load":
      event.kind = ExternalEvent.Kind.load;
      auto documents = member(json, "documents");
      enforce!JsonShapeException(documents !is null, what ~ ": falta «documents»");
      foreach (item; arrayItems(*documents, what ~ ": «documents»")) event.documents ~= parseVirtualDocument(item);
      break;
    case "notification":
      event.kind = ExternalEvent.Kind.notification;
      auto message = member(json, "message");
      enforce!JsonShapeException(message !is null, what ~ ": falta «message»");
      event.message = jsonText(*message);
      break;
    case "login":
      event.kind = ExternalEvent.Kind.login;
      auto info_ = member(json, "login_info");
      enforce!JsonShapeException(info_ !is null && isObject(*info_), what ~ ": falta «login_info»");
      event.login.accessToken = requiredString(*info_, "access_token", what);
      event.login.refreshToken = requiredString(*info_, "refresh_token", what);
      event.login.idToken = requiredString(*info_, "id_token", what);
      event.login.tokenAlias = requiredString(*info_, "alias", what);
      event.login.user = optionalString(*info_, "user_logged", what);
      break;
    case "validation":
      event.kind = ExternalEvent.Kind.validation;
      auto report = member(json, "report");
      enforce!JsonShapeException(report !is null, what ~ ": falta «report»");
      event.report = jsonText(*report);
      event.documentId = requiredUuid(json, "documentid", what);
      break;
    case "cancelled":
      event.kind = ExternalEvent.Kind.cancelled;
      event.documentId = requiredUuid(json, "documentid", what);
      break;
    default:
      break;
  }
  return event;
}

/// Documento de un evento «load».
private VirtualDocumentInfo parseVirtualDocument(const JSONValue json) @safe {
  enum what = "El documento virtual";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  VirtualDocumentInfo document;
  document.id = requiredUuid(json, "documentid", what);
  document.name = jsonText(requiredMember(json, "documentName", what));
  document.mimeType = jsonText(requiredMember(json, "mimetype", what));
  long pages = optionalLong(json, "pages", -1, what);
  enforce!JsonShapeException(pages >= 0 && pages <= int.max, what ~ ": «pages» debe ser un entero no negativo");
  document.pages = cast(int) pages;
  // String.valueOf en la versión Java: un campo ausente se veía como «null».
  document.serial = jsonText(member(json, "serial"));
  document.origin = jsonText(member(json, "origin"));
  document.expirationDate = jsonText(member(json, "expirationDate"));
  document.createdAt = jsonText(member(json, "createdAt"));
  return document;
}

private const(JSONValue) requiredMember(const JSONValue json, string key, string what) pure @safe {
  auto found = member(json, key);
  enforce!JsonShapeException(found !is null && found.type != JSONType.null_, format("%s: falta «%s»", what, key));
  return *found;
}

/// Texto de un valor como toString de Jackson: el texto tal cual y lo demás en JSON; «null» si falta.
private string jsonText(const(JSONValue)* value) @safe {
  if (value is null) return "null";
  return jsonText(*value);
}

private string jsonText(const JSONValue value) @safe {
  if (value.type == JSONType.string) return value.str;
  if (value.type == JSONType.null_) return "null";
  return toJSON(value);
}

private UUID requiredUuid(const JSONValue json, string key, string what) @safe {
  string text = jsonText(requiredMember(json, key, what));
  try {
    // parseUUID consume el rango que recibe por referencia: se le pasa una copia.
    string copy = text;
    return parseUUID(copy);
  } catch (UUIDParsingException) {
    throw new JsonShapeException(format("%s: «%s» no es un UUID", what, key));
  }
}

/// Identificación sin el prefijo de tipo (getIdentification: lo que sigue al primer guion).
string identificationSuffix(string identification) pure nothrow @safe {
  auto dash = identification.indexOf('-');
  return dash >= 0 ? identification[dash + 1 .. $] : identification;
}

/**
 * Reporte de un documento virtual que envía el servicio, en HTML (notifyReportDocument):
 * sin la línea del nombre temporal del documento y sin líneas en blanco repetidas; si no
 * tiene firmas, el aviso de que no las tiene. `signatures` recibe la cantidad declarada.
 */
string virtualReportHtml(string report, out size_t signatures) @safe {
  import std.conv : ConvException, to;
  import std.regex : ctRegex, matchFirst, replaceAll;
  import firmador.xml.dom : escapeXml;
  signatures = 0;
  auto count = matchFirst(report, ctRegex!`Contiene\s+(\d+)\s+firma`);
  if (!count.empty) {
    try {
      signatures = count[1].to!size_t;
    } catch (ConvException) {
      signatures = 0;
    }
  }
  if (signatures == 0) return "<html>Este documento no tiene ninguna firma digital.</html>";
  string cleaned = replaceAll(report, ctRegex!`El documento doc_[0-9]+\.pdf[^\n]*`, "").strip;
  cleaned = replaceAll(cleaned, ctRegex!`(\n\s*){2,}`, "\n");
  return "<html>" ~ escapeXml(cleaned).replace("\n", "<br>") ~ "</html>";
}

/// Alias con que se guardan en el almacén los tokens de la tarjeta en el servicio.
private string cardTokenAlias(string cardIdentification, string service) pure nothrow @safe {
  return tokenAlias(identificationSuffix(cardIdentification), service);
}

/// La tarjeta es la del documento: su identificación sin los cuatro primeros caracteres es el serial.
bool cardMatchesDocumentSerial(string cardIdentification, string serial) pure nothrow @safe {
  return cardIdentification.length >= 4 && cardIdentification[4 .. $] == serial;
}

/// URL de validación de un documento: su id antes de «get_validate_document/».
string documentValidationUrl(string validateUrl, UUID documentId) pure @safe {
  return validateUrl.replace("get_validate_document/", documentId.toString ~ "/get_validate_document/");
}

/// Inicia la integración con un servicio externo (WorkerFactory de ConnectionManager).
ConnectionWorker startExternal(ConnectionManager manager, Connection connection) @safe {
  auto worker = new ExternalIntegration(manager, connection);
  worker.start();
  return worker;
}

/// Hilo de la conexión con un servicio externo.
final class ExternalIntegration : IntegrationWorker {
  this(ConnectionManager manager, Connection connection) pure @safe {
    super(manager, connection, "Code:19");
  }

  /// Al detenerse cierra la sesión en el servicio (espera la red).
  protected override void afterStop() @trusted {
    closeSession();
  }

  protected override void listen() @trusted {
    auto config = connection.config;
    string negotiationUrl = withQuery(connection.url(config.negotiationUrl, "negociación"), [["alias", config.service]]);
    auto negotiated = httpGet(negotiationUrl, ["User-Agent": integrationUserAgent]);
    if (negotiated.status != 201) {
      error(format("La negociación con %s respondió %d %s", connection.name, negotiated.status, negotiated.statusText));
      report(t("ucr_integration_not_connected") ~ " Code:20");
      return;
    }
    auto negotiation = parseExternalNegotiation(parseJsonText(negotiated.text, "La negociación con el servicio"));
    manager.connectionView().connectionChanged(connection);

    auto certificates = manager.cards().authenticationAndSignCertificates();
    if (!certificates.complete) {
      report(t("gaudi_integration_not_certificate_detected"));
      return;
    }
    JSONValue registration;
    registration["cert_auth"] = certificates.authentication.base64;
    registration["cert_sign"] = certificates.signing.base64;
    registration["host_name"] = Socket.hostName;
    auto registered = httpPost(connection.url(negotiation.url, "alta"), cast(const(ubyte)[]) toJSON(registration),
      "application/json", ["X-Connection-Token": negotiation.connectionToken]);
    if (registered.status == 403) {
      error("El servicio ", connection.name, " no reconoce al usuario: ", registered.text);
      manager.interface_().showNotification(format(
        "Atención: usted no se encuentra registrado en los servicios de firma digital de %s", connection.name),
        NotificationType.warning);
      return;
    }
    if (registered.status != 201) {
      error(format("El alta en %s respondió %d: %s", connection.name, registered.status, registered.text));
      report(t("ucr_integration_not_connected") ~ format(" Code:20 (HTTP %d)", registered.status));
      return;
    }
    auto session = parseExternalSession(parseJsonText(registered.text, "El alta en el servicio"));
    requireHttpsUrl(session.sseUrl, "El flujo de eventos del servicio");
    string loginUrl = negotiation.loginUrl.length ? negotiation.loginUrl : connection.url(config.loginUrl,
      "inicio de sesión");
    openUrl(requireHttpsUrl(loginUrl, "El inicio de sesión del servicio"), currentSettings().preferredBrowser);
    saveToken(session.tokenAlias, TokenType.firmadorId, session.firmadorId);

    int status = httpEventStream(session.sseUrl, null, (string data) {
      handleEvent(data);
      return !isCancelled();
    }, &cancelled);
    if (isCancelled()) return;
    if (status != 200) {
      report(t("ucr_internal_error") ~ format(" Code:18 (HTTP %d)", status));
    } else {
      report(formatLostConnection(connection.name));
    }
    // Se cierra en otro hilo: stop espera a que termine el cierre de sesión.
    auto closer = new Thread({ manager.stop(connection); });
    closer.isDaemon = true;
    closer.start();
  }

  /// Atiende un evento; los errores se informan sin cortar el flujo.
  private void handleEvent(string data) @trusted {
    auto gui = manager.interface_();
    auto view = manager.connectionView();
    try {
      auto event = parseExternalEvent(parseJsonText(data, "El evento del servicio"));
      final switch (event.kind) {
        case ExternalEvent.Kind.ignored:
          break;
        case ExternalEvent.Kind.sign:
          view.signRequestsReceived(event.signRequests, connection.service);
          break;
        case ExternalEvent.Kind.expired:
          view.virtualExpired(event.documentKey);
          break;
        case ExternalEvent.Kind.deactivated:
          info("El servicio ", connection.name, " desactivó la operación en curso");
          view.loadingFinished();
          gui.showNotification(event.message, NotificationType.warning);
          break;
        case ExternalEvent.Kind.alert:
          gui.showNotification(event.message, NotificationType.warning);
          break;
        case ExternalEvent.Kind.load:
          info("Cargando ", event.documents.length, " documentos virtuales de ", connection.name);
          Document[] documents;
          foreach (document; event.documents) {
            documents ~= new Document(gui, document.id, document.name, document.mimeType, connection.service,
              document.pages, document.serial, document.origin, document.expirationDate, document.createdAt);
          }
          view.virtualDocumentsLoaded(documents);
          break;
        case ExternalEvent.Kind.notification:
          view.virtualBatchFinished();
          gui.showNotification(event.message, NotificationType.success);
          break;
        case ExternalEvent.Kind.login:
          info("Guardando los tokens de la sesión en ", connection.name);
          saveToken(event.login.tokenAlias, TokenType.access, event.login.accessToken);
          saveToken(event.login.tokenAlias, TokenType.refresh, event.login.refreshToken);
          saveToken(event.login.tokenAlias, TokenType.id, event.login.idToken);
          connection.setLogged(true, event.login.user);
          view.connectionChanged(connection);
          gui.showNotification(t("guiswing_login_complete"), NotificationType.info);
          break;
        case ExternalEvent.Kind.validation:
          view.virtualReport(event.documentId, event.report);
          break;
        case ExternalEvent.Kind.cancelled:
          info("El servicio ", connection.name, " canceló el documento ", event.documentId);
          view.virtualCancelled(event.documentId);
          break;
      }
    } catch (Exception exception) {
      error("Error al procesar un evento de ", connection.name, " CODE:11: ", exception.msg);
      report(t("gaudi_integration_internal_error") ~ " Code:11");
    }
  }

  /// Avisa al servicio que termina la sesión (close_session); los fallos sólo se registran.
  private void closeSession() @trusted {
    try {
      auto cards = manager.cards().readListSmartCard();
      if (cards.length == 0) return;
      string alias_ = cardTokenAlias(cards[0].identification, connection.service);
      auto tokens = readTokenStore();
      JSONValue body;
      body["firmador_id"] = tokenOf(tokens, alias_, TokenType.firmadorId);
      string[string] headers = ["User-Agent": integrationUserAgent];
      info("Cerrando la sesión en ", connection.name, " (sesión iniciada: ", connection.isLogged(), ")");
      if (connection.isLogged()) {
        headers["Authorization"] = "Bearer " ~ tokenOf(tokens, alias_, TokenType.access);
        body["id_token_hint"] = tokenOf(tokens, alias_, TokenType.id);
      }
      auto response = httpPost(connection.url(connection.config.endSessionUrl, "cierre de sesión"),
        cast(const(ubyte)[]) toJSON(body), "application/json", headers);
      info("El cierre de sesión en ", connection.name, " respondió ", response.status);
    } catch (Exception exception) {
      error("Error al cerrar la sesión en ", connection.name, ": ", exception.msg);
    } finally {
      connection.setLogged(false, "");
    }
  }
}

/// Tokens de una tarjeta en un servicio, leídos del almacén.
private struct ServiceTokens {
  string access;
  string refresh;
  string firmadorId;
}

private ServiceTokens tokensFor(string identification, string service) @safe {
  auto entries = readTokenStore();
  string alias_ = cardTokenAlias(identification, service);
  info("Usando los tokens de ", alias_);
  return ServiceTokens(tokenOf(entries, alias_, TokenType.access), tokenOf(entries, alias_, TokenType.refresh),
    tokenOf(entries, alias_, TokenType.firmadorId));
}

private string[string] sessionHeaders(const ServiceTokens tokens) pure @safe {
  return ["Authorization": "Bearer " ~ tokens.access, "X-Refresh-Token": tokens.refresh];
}

/**
 * Petición con la sesión de la tarjeta en un servicio: busca la conexión, lleva los tokens
 * en los encabezados y, si responde 403 (sesión vencida o rechazada), se lo pasa a
 * ConnectionManager.forbidden. Quien llama interpreta el estado.
 *
 * Throws: Exception si no hay conexión para el servicio o la petición falla.
 */
private HttpResponse sessionRequest(ConnectionManager manager, string service, const ServiceTokens tokens,
    string method, scope string delegate(Connection connection) @safe urlOf, const(ubyte)[] body) @trusted {
  auto connection = manager.find(service);
  enforce(connection !is null, format("No hay una conexión para el servicio %s", service));
  auto headers = sessionHeaders(tokens);
  if (body.length) headers["Content-Type"] = "application/json";
  auto response = httpRequest(method, urlOf(connection), body, headers);
  if (response.status == 403) manager.forbidden(service);
  return response;
}

/**
 * Primera tarjeta detectada que cumple `matches`, o null. Si no se pueden leer las
 * tarjetas, lo avisa y da null.
 */
private CardSignInfo detectedCard(ConnectionManager manager, scope bool delegate(CardSignInfo card) @safe matches)
    @trusted {
  try {
    auto cards = manager.cards().readListSmartCard();
    info("Tarjetas detectadas: ", cards.length);
    foreach (card; cards) if (matches(card)) return card;
  } catch (Exception exception) {
    error("No se pudieron leer las tarjetas: ", exception.msg);
    manager.interface_().showNotification(t("gaudi_integration_not_certificate_detected"), NotificationType.error);
  }
  return null;
}

/// Tarjeta del titular de un documento virtual (getCardInfoByIdentification), o null.
private CardSignInfo cardForDocumentSerial(ConnectionManager manager, string serial) @safe {
  return detectedCard(manager, (card) => cardMatchesDocumentSerial(card.identification, serial));
}

/// Agrupa, en el orden de llegada, los elementos que tienen la misma clave.
private T[][] groupInOrder(alias key, T)(T[] items) {
  T[][] groups;
  foreach (item; items) {
    auto itemKey = key(item);
    ptrdiff_t found = -1;
    foreach (index, group; groups) {
      if (key(group[0]) == itemKey) {
        found = index;
        break;
      }
    }
    if (found < 0) groups ~= [item];
    else groups[found] ~= item;
  }
  return groups;
}

/**
 * Lotes de documentos virtuales para requestHashesToSign: cada pedido va a un solo
 * servicio y se firma con la tarjeta de un solo titular.
 */
Document[][] signingBatches(Document[] documents) pure @safe {
  import std.typecons : tuple;
  return groupInOrder!(document => tuple(document.service, document.serial))(documents);
}

/**
 * Pide al servicio que prepare los resúmenes de los documentos con los ajustes dados
 * (getHashToSign; `settings` null usa los vigentes). Los resúmenes llegan después como
 * evento «firmar». Devuelve false si no se pudo, tras informarlo.
 *
 * Throws: Exception si los documentos no son de un mismo servicio y titular (se agrupan
 * con signingBatches).
 */
bool requestHashesToSign(ConnectionManager manager, Document[] documents, Settings settings) @trusted {
  import std.algorithm : all;
  enforce(documents.length > 0, "No se indicaron documentos virtuales para firmar");
  string service = documents[0].service;
  enforce(documents.all!(document => document.service == service && document.serial == documents[0].serial),
    format("Los documentos virtuales de un pedido deben ser de un mismo servicio y titular (el primero es de %s)",
    service));
  auto card = cardForDocumentSerial(manager, documents[0].serial);
  if (card is null) {
    error("No se encontró la tarjeta de firma de los documentos virtuales");
    return false;
  }
  try {
    auto tokens = tokensFor(card.identification, service);
    JSONValue payload;
    string[] ids;
    foreach (document; documents) ids ~= document.id.toString;
    payload["ids"] = ids;
    payload["firmador_id"] = tokens.firmadorId;
    payload["settings"] = settingsToJson(settings is null ? currentSettings() : settings);
    auto response = sessionRequest(manager, service, tokens, "POST",
      (connection) => connection.url(connection.config.signUrl, "firma"), cast(const(ubyte)[]) toJSON(payload));
    if (response.status == 201) return true;
    error(format("La preparación de la firma en %s respondió %d: %s", service, response.status, response.text));
    return false;
  } catch (Exception exception) {
    error("Error al obtener los resúmenes a firmar: ", exception.msg);
    manager.interface_().showNotification(t("connection_panel_error_token"), NotificationType.error);
    return false;
  }
}

/**
 * Firma con la tarjeta los resúmenes que preparó el servicio, con un solo PIN, y los
 * devuelve (VirtualSigner.sign). Devuelve false si no se completó, tras informarlo.
 */
bool completeSignRequests(ConnectionManager manager, RemoteSignRequest[] requests, string service) @trusted {
  auto gui = manager.interface_();
  if (requests.length == 0) {
    error("El servicio no envió documentos para firmar");
    return false;
  }
  auto card = detectedCard(manager, (candidate) => matchesIdentifier(candidate, requests[0].serialNumber));
  if (card is null) {
    error("No se encontró la tarjeta de firma ", requests[0].serialNumber, " que pide el servicio");
    gui.showNotification(t("gaudi_integration_not_certificate_detected"), NotificationType.error);
    return false;
  }
  scope (exit) card.destroyPin();
  manager.cards().restoreSessions();
  if (!gui.requestRemotePin(card, requests[0].documentName, requestImage(requests[0].b64image))) {
    gui.showNotification(t("virtual_ping_panel_error"), NotificationType.error);
    return false;
  }
  auto signatures = signRemoteRequests(gui, card, requests);
  if (signatures is null) return false;
  try {
    auto signatureList = JSONValue(signatures);
    auto response = sessionRequest(manager, service, tokensFor(card.identification, service), "POST",
      (connection) => connection.url(connection.config.completeUrl, "firma completa"),
      cast(const(ubyte)[]) toJSON(signatureList));
    if (response.status == 200) return true;
    error(format("El servicio %s no aceptó las firmas: %d %s", service, response.status, response.text));
    return false;
  } catch (Exception exception) {
    error("Error al enviar las firmas al servicio ", service, ": ", exception.msg);
    gui.showNotification(t("connection_panel_internal_error_image"), NotificationType.error);
    return false;
  }
}

/// Petición con sesión sobre un documento virtual; devuelve el estado o 0 si falló antes de responder.
private int documentRequest(ConnectionManager manager, Document document, string method,
    string delegate(Connection connection) @safe urlOf, const(ubyte)[] body) @trusted {
  auto card = cardForDocumentSerial(manager, document.serial);
  if (card is null) {
    error("No se encontró la tarjeta de firma del documento virtual ", document.name);
    return 0;
  }
  try {
    return sessionRequest(manager, document.service, tokensFor(card.identification, document.service), method, urlOf,
      body).status;
  } catch (Exception exception) {
    error("Error en la petición sobre el documento virtual ", document.name, ": ", exception.msg);
    manager.interface_().showNotification(t("connection_panel_internal_error_image"), NotificationType.error);
    return 0;
  }
}

/// Borra un documento virtual del servicio (deleteDocument); true si respondió 204.
bool deleteVirtualDocument(ConnectionManager manager, Document document) @safe {
  JSONValue body;
  body["documentid"] = document.id.toString;
  int status = documentRequest(manager, document, "POST",
    (Connection connection) => connection.url(connection.config.deleteUrl, "borrado"),
    cast(const(ubyte)[]) toJSON(body));
  if (status == 204) return true;
  if (status != 0) manager.interface_().showNotification(t("connection_panel_internal_error_image"),
    NotificationType.error);
  return false;
}

/**
 * Pide al servicio que valide un documento virtual (validateVirtualDocument); el reporte
 * llega después como evento «validation». true si respondió 200.
 */
bool validateVirtualDocument(ConnectionManager manager, Document document) @safe {
  return documentRequest(manager, document, "GET",
    (Connection connection) => documentValidationUrl(connection.url(connection.config.validateUrl, "validación"),
      document.id), null) == 200;
}

private __gshared bool[string] previewsInFlight;
private __gshared Mutex previewLock;

shared static this() {
  previewLock = new Mutex;
}

/**
 * Imagen de una página de un documento virtual (getPageImageFromApi), tal como la
 * entrega el servicio (PNG o JPEG). null si ya se está pidiendo esa página o si falló,
 * tras informarlo.
 */
immutable(ubyte)[] virtualPagePreview(ConnectionManager manager, Document document, int page) @trusted {
  string key = format("%s#%d", document.id, page);
  synchronized (previewLock) {
    if (key in previewsInFlight) return null;
    previewsInFlight[key] = true;
  }
  scope (exit) synchronized (previewLock) previewsInFlight.remove(key);
  JSONValue body;
  body["document_id"] = document.id.toString;
  body["page_number"] = page;
  auto card = cardForDocumentSerial(manager, document.serial);
  if (card is null) {
    manager.interface_().showNotification(t("connection_panel_error_token"), NotificationType.error);
    return null;
  }
  try {
    auto response = sessionRequest(manager, document.service, tokensFor(card.identification, document.service), "POST",
      (connection) => connection.url(connection.config.previewUrl, "vista previa"), cast(const(ubyte)[]) toJSON(body));
    if (response.status == 403) return null;
    if (response.status != 200) {
      error(format("La vista previa de %s respondió %d", document.name, response.status));
      manager.interface_().showNotification(t("signpanel_problem_render_image"), NotificationType.error);
      return null;
    }
    string encoded = response.text.strip;
    if (encoded.length >= 2 && encoded[0] == '"' && encoded[$ - 1] == '"') encoded = encoded[1 .. $ - 1];
    return Base64.decode(encoded).idup;
  } catch (Exception exception) {
    error("Error al obtener la página ", page, " de ", document.name, ": ", exception.msg);
    manager.interface_().showNotification(t("connection_panel_internal_error_image"), NotificationType.error);
    return null;
  }
}

/**
 * Pide al servicio que vuelva a publicar los documentos virtuales (reloadVirtualDocuments),
 * con la sesión de la primera tarjeta detectada que tenga una en el servicio; llegan como
 * evento «load». Un 403 cierra la conexión (sessionRequest). true si respondió 200.
 */
bool reloadVirtualDocuments(ConnectionManager manager, Connection connection) @trusted {
  try {
    auto entries = readTokenStore();
    auto card = detectedCard(manager,
      (candidate) => hasToken(entries, cardTokenAlias(candidate.identification, connection.service), TokenType.access));
    if (card is null) {
      error("Ninguna tarjeta detectada tiene una sesión iniciada en ", connection.name);
      return false;
    }
    auto tokens = tokensFor(card.identification, connection.service);
    auto response = sessionRequest(manager, connection.service, tokens, "GET",
      (target) => withQuery(target.url(target.config.virtualDocumentsUrl, "documentos virtuales"),
        [["firmador_id", tokens.firmadorId]]), null);
    if (response.status != 200 && response.status != 403) {
      error(format("La recarga de los documentos virtuales de %s respondió %d: %s", connection.name, response.status,
        response.text));
    }
    return response.status == 200;
  } catch (Exception exception) {
    error("Error al recargar los documentos virtuales de ", connection.name, ": ", exception.msg);
    return false;
  }
}

@("should interpret every service event when reading the event stream")
unittest {
  string uuid = "0b8e5c9e-6a4f-4f0a-9d7e-2f6c1a0b3c4d";
  auto load = parseExternalEvent(parseJsonText(`{"accion":"load","documents":[{"documentid":"` ~ uuid
    ~ `","documentName":"a.pdf","mimetype":"application/pdf","pages":"3","serial":123,"createdAt":"hoy"}]}`, "x"));
  assert(load.kind == ExternalEvent.Kind.load && load.documents.length == 1);
  assert(load.documents[0].pages == 3 && load.documents[0].serial == "123");
  assert(load.documents[0].origin == "null" && load.documents[0].createdAt == "hoy");
  auto expired = parseExternalEvent(parseJsonText(`{"accion":"alert","message":{"event":"expired","id":7}}`, "x"));
  assert(expired.kind == ExternalEvent.Kind.expired && expired.documentKey == "7");
  auto alert = parseExternalEvent(parseJsonText(`{"accion":"alert","message":"Cuidado"}`, "x"));
  assert(alert.kind == ExternalEvent.Kind.alert && alert.message == "Cuidado");
  auto validation = parseExternalEvent(parseJsonText(`{"accion":"validation","report":"<r/>","documentid":"` ~ uuid
    ~ `"}`, "x"));
  assert(validation.kind == ExternalEvent.Kind.validation && validation.documentId.toString == uuid);
  auto login = parseExternalEvent(parseJsonText(`{"accion":"login","login_info":{"access_token":"a",`
    ~ `"refresh_token":"r","id_token":"i","alias":"1-1UCR","user_logged":"Ana"}}`, "x"));
  assert(login.kind == ExternalEvent.Kind.login && login.login.user == "Ana" && login.login.tokenAlias == "1-1UCR");
  assert(parseExternalEvent(parseJsonText(`{"accion":"otra"}`, "x")).kind == ExternalEvent.Kind.ignored);
  assert(parseExternalEvent(parseJsonText("{}", "x")).kind == ExternalEvent.Kind.ignored);
}

@("should reject events whose document identifiers are not UUIDs when parsing")
unittest {
  import std.exception : assertThrown;
  assertThrown!JsonShapeException(parseExternalEvent(parseJsonText(`{"accion":"cancelled","documentid":"x"}`, "x")));
  assertThrown!JsonShapeException(parseExternalEvent(parseJsonText(`{"accion":"load","documents":[{}]}`, "x")));
}

@("should derive token aliases, card matches and validation URLs like the Java version")
unittest {
  assert(identificationSuffix("CPF-01-0123-0456") == "01-0123-0456");
  assert(identificationSuffix("sinGuion") == "sinGuion");
  assert(cardMatchesDocumentSerial("CPF-0101230456", "0101230456"));
  assert(!cardMatchesDocumentSerial("CPF", ""));
  auto id = parseUUID("0b8e5c9e-6a4f-4f0a-9d7e-2f6c1a0b3c4d");
  assert(documentValidationUrl("https://s/api/get_validate_document/", id)
    == "https://s/api/0b8e5c9e-6a4f-4f0a-9d7e-2f6c1a0b3c4d/get_validate_document/");
}

@("should keep one batch per key in arrival order when grouping virtual documents")
unittest {
  assert(groupInOrder!(name => name[0])(["a1", "b1", "a2", "c1", "b2"]) == [["a1", "a2"], ["b1", "b2"], ["c1"]]);
  assert(groupInOrder!(name => name[0])(cast(string[]) null).length == 0);
}

@("should keep the declared signature count and drop the temporary name line when showing a virtual report")
unittest {
  size_t signatures;
  string html = virtualReportHtml("El documento doc_123.pdf está firmado\n\n\nContiene 2 firmas <válidas>", signatures);
  assert(signatures == 2);
  assert(html == "<html>Contiene 2 firmas &lt;válidas&gt;</html>");
  assert(virtualReportHtml("Sin firmas", signatures) == "<html>Este documento no tiene ninguna firma digital.</html>");
  assert(signatures == 0);
}
