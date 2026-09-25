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
 * Conexión Gaudi (GaudiIntegration): cliente del hub SignalR 1.4 del BCCR, con el que
 * las entidades piden firmas de autenticación a la tarjeta del usuario (@contract
 * bccr-signalr). Negocia, abre el flujo serverSentEvents presentando los certificados de
 * autenticación y de firma, y ante cada mensaje «Firme» pide PIN y código, firma con
 * SHA256withRSA los dos resúmenes (a: documento, b: resumen) y contesta «FirmaRealizada»
 * por /send. Un hilo vigila que la tarjeta siga puesta; si se retira o se pierde el hub,
 * la conexión se reinicia (ConnectionManager.restart). El TLS del hub se verifica sólo
 * con la raíz nacional incluida.
 */
module firmador.connections.gaudi;

import core.atomic : atomicLoad, atomicStore;
import core.thread : Thread;
import core.time : dur;
import std.base64 : Base64, Base64Exception;
import std.exception : enforce;
import std.format : format;
import std.json : JSONType, JSONValue, toJSON;
import std.logger : error, info, warning;
import std.socket : Socket;
import std.string : strip;

import firmador.configuration : bccrConnect, bccrStartNegotiation, bccrTlsRootCertificate, bccrUrl, integrationUserAgent;
import firmador.connections.connection;
import firmador.i18n : t;
import firmador.net.http;
import firmador.tokens.pkcs11 : Pkcs11Exception;
import firmador.tokens.token : SecretPin;
import firmador.util.base64 : encodeBase64;
import firmador.util.json;
import firmador.x509.certificate : bundledCertificate, certificatePem;

/// Datos de la negociación SignalR (ConnectionToken, ConnectionId y Url).
struct GaudiNegotiation {
  string connectionToken;
  string connectionId;
  /// Ruta del hub, relativa a bccrUrl.
  string url;
}

/**
 * Interpreta la respuesta de /negotiate.
 *
 * Throws: JsonShapeException si falta un campo.
 */
GaudiNegotiation parseGaudiNegotiation(const JSONValue json) @safe {
  enum what = "La negociación con el BCCR";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  GaudiNegotiation negotiation;
  negotiation.connectionToken = requiredString(json, "ConnectionToken", what);
  negotiation.connectionId = requiredString(json, "ConnectionId", what);
  negotiation.url = requiredString(json, "Url", what);
  enforce!JsonShapeException(negotiation.url.length && negotiation.url[0] == '/',
    what ~ ": «Url» debe ser una ruta del mismo servidor");
  return negotiation;
}

/// Parámetros de consulta de /connect y /send.
string[2][] gaudiQueryParameters(const GaudiNegotiation negotiation) pure nothrow @safe {
  return [
    ["connectionData", `[{"name":"administradordeclientes"}]`],
    ["connectionToken", negotiation.connectionToken],
    ["connectionId", negotiation.connectionId],
    ["transport", "serverSentEvents"],
  ];
}

/// Solicitud de firma («Firme») del hub; los nombres de una letra son los del BCCR.
struct GaudiSignRequest {
  /// a: resumen del documento, en base64.
  string documentHash;
  /// b: resumen del resumen, en base64.
  string summaryHash;
  /// c: resumen del documento para mostrar.
  string summary;
  /// d: entidad que pide la firma.
  string entityName;
  /// e: logo de la entidad.
  immutable(ubyte)[] logo;
  /// g: identificador de la solicitud, que se devuelve tal cual.
  JSONValue requestId;
}

/**
 * Lee un mensaje del hub; devuelve true y llena `request` si es una solicitud «Firme». Los
 * demás, como el «{}» con que SignalR mantiene viva la conexión, dan false.
 *
 * Throws: JsonShapeException si es «Firme» pero le faltan datos.
 */
bool parseGaudiMessage(const JSONValue message, out GaudiSignRequest request) @safe {
  enum what = "La solicitud de firma del BCCR";
  auto calls = member(message, "M");
  if (calls is null || calls.type != JSONType.array) return false;
  auto items = arrayItems(*calls, what);
  if (items.length == 0 || !isObject(items[0])) return false;
  auto method = member(items[0], "M");
  if (method is null || method.type != JSONType.string || method.str != "Firme") return false;
  auto arguments = member(items[0], "A");
  enforce!JsonShapeException(arguments !is null && arguments.type == JSONType.array,
    what ~ ": faltan los argumentos «A»");
  auto argumentList = arrayItems(*arguments, what);
  enforce!JsonShapeException(argumentList.length > 0 && isObject(argumentList[0]), what ~ ": «A» está vacío");
  auto data = argumentList[0];
  request.documentHash = requiredString(data, "a", what);
  request.summaryHash = requiredString(data, "b", what);
  request.summary = requiredString(data, "c", what);
  request.entityName = requiredString(data, "d", what);
  request.logo = requiredBase64(data, "e", what).idup;
  auto requestId = member(data, "g");
  enforce!JsonShapeException(requestId !is null, what ~ ": falta el identificador «g»");
  request.requestId = *requestId;
  return true;
}

/**
 * Respuesta «FirmaRealizada» en el formulario de /send (data=JSON): rechazada (d = 2)
 * sin firmas, o aceptada (d = 0) con el código y las firmas en base64.
 */
string gaudiAnswerForm(const GaudiSignRequest request, bool rejected, string code, string documentSignature,
    string summarySignature) @safe {
  JSONValue answer;
  answer["e"] = request.requestId;
  answer["d"] = rejected ? 2 : 0;
  answer["c"] = rejected ? "" : code;
  if (!rejected) {
    answer["a"] = documentSignature;
    answer["b"] = summarySignature;
  }
  JSONValue message;
  message["H"] = "administradorDeClientes";
  message["M"] = "FirmaRealizada";
  message["A"] = JSONValue([answer]);
  message["I"] = 0;
  return "data=" ~ urlEncode(toJSON(message));
}

/// El hub confirmó la respuesta.
bool gaudiAnswerAccepted(string response) pure @safe {
  return response.strip == `{"I":"0"}`;
}

/// Cabecera Arquitectura: «amd64» en sistemas de 64 bits, «x86» en los de 32, como la versión Java.
string gaudiArchitecture() pure nothrow @safe @nogc {
  return size_t.sizeof == 8 ? "amd64" : "x86";
}

/// Opciones HTTP del hub: TLS verificado sólo con la raíz nacional.
private HttpOptions bccrOptions() @safe {
  HttpOptions options;
  options.caPem = certificatePem(bundledCertificate!bccrTlsRootCertificate().der);
  return options;
}

/// Inicia la integración con el BCCR (WorkerFactory de ConnectionManager).
ConnectionWorker startGaudi(ConnectionManager manager, Connection connection) @safe {
  auto worker = new GaudiIntegration(manager, connection);
  worker.start();
  return worker;
}

/// Hilo de la conexión con el hub del BCCR.
final class GaudiIntegration : IntegrationWorker {
  private string sendUrl;

  this(ConnectionManager manager, Connection connection) @safe {
    super(manager, connection, "Code:14");
  }

  /// Negocia, abre el flujo de eventos y lo atiende hasta que se cierre o se detenga.
  protected override void listen() @trusted {
    auto options = bccrOptions();
    auto negotiated = httpGet(bccrUrl ~ bccrStartNegotiation, ["User-Agent": integrationUserAgent], options);
    enforce(negotiated.status == 200, format("La negociación con el BCCR respondió %d %s", negotiated.status,
      negotiated.statusText));
    auto negotiation = parseGaudiNegotiation(parseJsonText(negotiated.text, "La negociación con el BCCR"));

    auto certificates = manager.cards().authenticationAndSignCertificates();
    if (!certificates.complete) {
      report(t("gaudi_integration_not_certificate_detected"));
      return;
    }
    string hubUrl = bccrUrl ~ negotiation.url;
    sendUrl = withQuery(hubUrl ~ "/send", gaudiQueryParameters(negotiation));
    string[string] headers = [
      "Accept": "text/event-stream",
      "CertificadoAutenticacion": certificates.authentication.base64,
      "CertificadoFirmante": certificates.signing.base64,
      "NombreDelSistemaOperativo": operatingSystemName(),
      "VersionDelSistemaOperativo": operatingSystemVersion(),
      "IpPrivada": "127.0.0.1",
      "Arquitectura": gaudiArchitecture(),
      "NombreDelHost": Socket.hostName,
      "User-Agent": integrationUserAgent,
      "Content-Encoding": "gzip",
    ];
    startCardMonitor();
    int status = httpEventStream(withQuery(hubUrl ~ bccrConnect, gaudiQueryParameters(negotiation)), headers,
      (string data) { handleMessage(data); return !isCancelled(); }, &cancelled, options);
    if (isCancelled()) return;
    if (status != 200) {
      report(t("gaudi_integration_internal_error") ~ format(" Code:15 (HTTP %d)", status));
      return;
    }
    info("Se ha cerrado la conexión con el servidor del BCCR");
    report(t("gaudi_integration_lost_connection"));
    manager.restart(connection);
  }

  /// Atiende un mensaje del hub; los errores se informan sin cortar el flujo.
  private void handleMessage(string data) @trusted {
    try {
      GaudiSignRequest request;
      if (!parseGaudiMessage(parseJsonText(data, "El mensaje del BCCR"), request)) return;
      if (!sign(request)) report(t("gaudi_integration_not_signed"));
    } catch (Exception exception) {
      error("Error al procesar un mensaje del BCCR CODE:11: ", exception.msg);
      report(t("gaudi_integration_internal_error") ~ " Code:11");
    }
  }

  /**
   * Pide PIN y código, firma los dos resúmenes y envía la respuesta. Si el usuario
   * rechaza o la firma falla se envía el rechazo, para que la entidad no quede esperando.
   */
  private bool sign(const GaudiSignRequest request) @trusted {
    auto answer = manager.connectionView().requestPinAndCode(request.logo, request.entityName, request.summary, "");
    string documentSignature, summarySignature;
    bool rejected = !answer.accepted;
    if (!rejected) {
      scope (exit) answer.pin.destroy();
      summarySignature = signedHash(request, request.summaryHash, answer.pin);
      documentSignature = summarySignature is null ? null : signedHash(request, request.documentHash, answer.pin);
      if (summarySignature is null || documentSignature is null) {
        error("No se pudieron firmar los resúmenes de la solicitud del BCCR");
        report(t("guadi_integration_no_private_key_found"));
        rejected = true;
      }
    }
    string form = gaudiAnswerForm(request, rejected, answer.code, documentSignature, summarySignature);
    scope (exit) manager.cards().restoreSessions();
    try {
      auto response = httpPost(sendUrl, cast(const(ubyte)[]) form, "application/x-www-form-urlencoded",
        ["User-Agent": integrationUserAgent], bccrOptions());
      if (response.status < 200 || response.status >= 300) {
        error(format("El BCCR rechazó la respuesta firmada: %d %s", response.status, response.text));
        return false;
      }
      return !rejected && gaudiAnswerAccepted(response.text);
    } catch (Exception exception) {
      error("Error enviando la respuesta firmada al BCCR code:16: ", exception.msg);
      return false;
    }
  }

  /**
   * Firma un resumen (base64) con la clave de firma, pidiendo otra vez el PIN si la
   * tarjeta lo rechaza, hasta cinco intentos (getSignedHash). null si no se pudo.
   */
  private string signedHash(const GaudiSignRequest request, string hashBase64, ref SecretPin pin) @trusted {
    ubyte[] hash;
    try {
      hash = Base64.decode(hashBase64);
    } catch (Base64Exception) {
      error("El resumen que envió el BCCR no está en base64");
      return null;
    }
    foreach (attempt; 0 .. 5) {
      if (isCancelled()) return null;
      try {
        return encodeBase64(manager.cards().signWithSignKey(pin, hash));
      } catch (Pkcs11Exception exception) {
        error("La tarjeta rechazó la firma de la solicitud del BCCR: ", exception.msg);
        if (exception.msg == "CKR_PIN_LOCKED") {
          report(t("guiswing_show_error_pkcs11_pinlocked"));
          return null;
        }
        if (exception.msg != "CKR_PIN_INCORRECT") {
          report(t("guiswing_show_error_pkcs11_notfound"));
          return null;
        }
        report(t("guiswing_show_error_pkcs11_pinincorrect"));
      } catch (Exception exception) {
        error("No se encontró la clave privada de firma: ", exception.msg);
        report(t("guadi_integration_no_private_key_found"));
        manager.restart(connection);
        return null;
      }
      auto retry = manager.connectionView().requestPinAndCode(request.logo, request.entityName, request.summary,
        t("gaudi_integration_incorrect_pin"));
      if (!retry.accepted) return null;
      pin.destroy();
      pin = retry.pin;
    }
    return null;
  }

  /// Vigila la tarjeta cada tres segundos; si se retira, reinicia la conexión.
  private void startCardMonitor() @trusted {
    info("Iniciando monitoreo de tarjeta");
    auto monitor = new Thread({
      while (!isCancelled()) {
        if (!manager.cards().isCardPresent()) {
          warning("¡Tarjeta extraída!");
          report("Tarjeta extraída, cerrando conexión");
          manager.restart(connection);
          return;
        }
        Thread.sleep(dur!"seconds"(3));
      }
    });
    monitor.isDaemon = true;
    monitor.start();
  }
}

/// Nombre del sistema como os.name de Java.
private string operatingSystemName() pure nothrow @safe @nogc {
  version (Windows) return "Windows";
  else version (OSX) return "Mac OS X";
  else version (linux) return "Linux";
  else version (FreeBSD) return "FreeBSD";
  else return "Unknown";
}

/// Versión del sistema como os.version de Java (versión del núcleo en Unix).
private string operatingSystemVersion() @trusted {
  version (Posix) {
    import core.sys.posix.sys.utsname : uname, utsname;
    import std.string : fromStringz;
    utsname name;
    if (uname(&name) != 0) return "";
    return fromStringz(name.release.ptr).idup;
  } else version (Windows) {
    import core.sys.windows.windows : GetModuleHandleW, GetProcAddress, OSVERSIONINFOW;
    // RtlGetVersion no miente como GetVersionEx a los programas sin manifiesto.
    alias RtlGetVersion = extern (Windows) int function(OSVERSIONINFOW*) nothrow @nogc;
    auto ntdll = GetModuleHandleW("ntdll.dll"w.ptr);
    if (ntdll is null) return "";
    auto getVersion = cast(RtlGetVersion) GetProcAddress(ntdll, "RtlGetVersion");
    if (getVersion is null) return "";
    OSVERSIONINFOW versionInfo;
    versionInfo.dwOSVersionInfoSize = OSVERSIONINFOW.sizeof;
    if (getVersion(&versionInfo) != 0) return "";
    return format("%d.%d", versionInfo.dwMajorVersion, versionInfo.dwMinorVersion);
  } else {
    return "";
  }
}

@("should extract the signing request and answer in the hub format when a Firme message arrives")
unittest {
  import std.algorithm : canFind, startsWith;
  import std.uri : decodeComponent;
  import std.array : replace;
  string message = `{"C":"x","M":[{"H":"AdministradorDeClientes","M":"Firme","A":[{"a":"QQ==","b":"Qg==",`
    ~ `"c":"Resumen","d":"Banco","e":"AAEC","f":60,"g":42,"h":1}]}]}`;
  GaudiSignRequest request;
  assert(parseGaudiMessage(parseJsonText(message, "prueba"), request));
  assert(request.entityName == "Banco" && request.logo == [0, 1, 2] && request.requestId.integer == 42);
  string form = gaudiAnswerForm(request, false, "1234", "firmaA", "firmaB");
  assert(form.startsWith("data="));
  auto answer = parseJsonText(decodeComponent(form["data=".length .. $].replace("+", " ")), "prueba");
  assert(answer["M"].str == "FirmaRealizada" && answer["H"].str == "administradorDeClientes");
  assert(answer["A"][0]["e"].integer == 42 && answer["A"][0]["d"].integer == 0);
  assert(answer["A"][0]["a"].str == "firmaA" && answer["A"][0]["c"].str == "1234");
  auto rejected = gaudiAnswerForm(request, true, "1234", null, null);
  assert(!decodeComponent(rejected).canFind("1234") && decodeComponent(rejected).canFind(`"d":2`));
}

@("should ignore other hub messages and require the negotiation fields when parsing")
unittest {
  import std.exception : assertThrown;
  GaudiSignRequest request;
  assert(!parseGaudiMessage(parseJsonText(`{"C":"d","M":[]}`, "x"), request));
  assert(!parseGaudiMessage(parseJsonText("{}", "x"), request));
  assert(!parseGaudiMessage(parseJsonText(`{"M":[{"M":"Otro"}]}`, "x"), request));
  assertThrown!JsonShapeException(parseGaudiMessage(parseJsonText(`{"M":[{"M":"Firme","A":[{}]}]}`, "x"), request));
  auto negotiation = parseGaudiNegotiation(parseJsonText(
    `{"Url":"/wcfv2/hub","ConnectionToken":"t+/=","ConnectionId":"id"}`, "x"));
  assert(withQuery("https://h" ~ negotiation.url ~ "/connect", gaudiQueryParameters(negotiation))
    == "https://h/wcfv2/hub/connect?connectionData=%5B%7B%22name%22%3A%22administradordeclientes%22%7D%5D"
    ~ "&connectionToken=t%2B%2F%3D&connectionId=id&transport=serverSentEvents");
  assertThrown!JsonShapeException(parseGaudiNegotiation(parseJsonText(
    `{"Url":"https://evil/","ConnectionToken":"t","ConnectionId":"i"}`, "x")));
  assert(gaudiAnswerAccepted(` {"I":"0"} `) && !gaudiAnswerAccepted(`{"I":"1"}`));
}
