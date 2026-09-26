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
 * Datos de las conexiones (la parte de Connection que se guarda, StartConnection y
 * ServicesUrlsIO en la versión Java): servicesUrls.xml en el directorio de configuración
 * (@contract services-urls-xml), las conexiones por omisión (Firmador Remoto y Gaudi) y
 * los archivos .firmadorconn con que un servicio externo se da de alta (@contract
 * firmadorconn). La conexión en marcha está en firmador.connections.connection.
 *
 * Las rutas de los servicios externos se guardan relativas a la URL base, que debe ser
 * https: toda URL completa se comprueba para que no cambie de servidor al concatenarla.
 */
module firmador.connections.config;

import std.algorithm : any, canFind, map, startsWith;
import std.array : array;
import std.conv : ConvException, to;
import std.exception : basicExceptionCtors, enforce;
import std.file : exists, readText;
import std.format : format;
import std.json : JSONValue;
import std.logger : info;
import std.path : buildPath;
import std.string : indexOf, strip, toLower;

import firmador.configuration : defaultRemotePort;
import firmador.logging : withContext;
import firmador.settingsmanager : configDirectory, writeFileAtomically;
import firmador.util.json;
import firmador.validation.model : DocumentValidationResult, Indication, indicationName;
import firmador.validation.sources : ValidationSource;
import firmador.validators.xmlvalidator : validateXml;
import firmador.xml.dom : escapeXml, XmlDocument, XmlNode;

/// Nombre (y servicio) de la conexión de Firmador Remoto.
enum string firmadorRemotoService = "Firmador Remoto";
/// Nombre (y servicio) de la conexión con el hub del BCCR.
enum string gaudiService = "Gaudi";

/// Archivo de las conexiones dentro del directorio de configuración.
enum string servicesUrlsFileName = "servicesUrls.xml";

/// Error en los datos de una conexión (archivo, JSON o URL no válidos).
class ConnectionConfigException : Exception {
  mixin basicExceptionCtors;
}

/// Qué atiende una conexión.
enum ConnectionKind {
  /// Servidor HTTP local para las páginas que firman con Firmador.
  firmadorRemoto,
  /// Hub SignalR del BCCR.
  gaudi,
  /// Servicio externo con sesión y documentos virtuales (flujo de la UCR).
  external,
}

/**
 * Una conexión tal como se guarda: nombre, servicio, puerto (Firmador Remoto) y rutas
 * de los servicios externos, relativas a `baseUrl`.
 */
struct ConnectionConfig {
  string name;
  string service;
  ushort port;
  string baseUrl;
  string negotiationUrl;
  string negotiationStartUrl;
  string completeUrl;
  string endSessionUrl;
  string previewUrl;
  string signUrl;
  string deleteUrl;
  string loginUrl;
  string validateUrl;
  string virtualDocumentsUrl;
  /// Se inicia al abrir la aplicación.
  bool startOn;
}

/// Tipo de la conexión según su servicio.
ConnectionKind connectionKind(string service) pure nothrow @safe @nogc {
  if (service == firmadorRemotoService) return ConnectionKind.firmadorRemoto;
  if (service == gaudiService) return ConnectionKind.gaudi;
  return ConnectionKind.external;
}

/// Conexiones que siempre existen (StartConnection): Firmador Remoto en 3516 y Gaudi.
ConnectionConfig[] defaultConnections() pure nothrow @safe {
  ConnectionConfig remote;
  remote.name = firmadorRemotoService;
  remote.service = firmadorRemotoService;
  remote.port = defaultRemotePort;
  ConnectionConfig gaudi;
  gaudi.name = gaudiService;
  gaudi.service = gaudiService;
  return [remote, gaudi];
}

/// Las conexiones leídas más las por omisión cuyo servicio falte (loadConnectionPanel).
ConnectionConfig[] withDefaultConnections(const ConnectionConfig[] loaded) pure nothrow @safe {
  ConnectionConfig[] result = loaded.dup;
  foreach (fallback; defaultConnections()) {
    if (!loaded.any!(existing => existing.service == fallback.service)) result ~= fallback;
  }
  return result;
}

/**
 * Esquema y autoridad (servidor y puerto) de una URL absoluta http(s), en minúsculas.
 *
 * Throws: ConnectionConfigException si no es una URL http(s) con servidor.
 */
string urlOrigin(string url) pure @safe {
  string lowered = url.toLower;
  string scheme = lowered.startsWith("https://") ? "https://" : lowered.startsWith("http://") ? "http://" : null;
  enforce!ConnectionConfigException(scheme !is null, format("«%s» no es una URL http(s)", url));
  string rest = lowered[scheme.length .. $];
  size_t end = rest.length;
  foreach (index, character; rest) {
    if (character == '/' || character == '?' || character == '#') {
      end = index;
      break;
    }
  }
  string authority = rest[0 .. end];
  enforce!ConnectionConfigException(authority.length > 0 && !authority.canFind('@') && !authority.canFind('\\'),
    format("«%s» no indica un servidor válido", url));
  return scheme ~ authority;
}

/**
 * Comprueba que una URL sea https (lo que traen los servicios para abrir sesión o recibir
 * eventos) y la devuelve.
 *
 * Throws: ConnectionConfigException si no lo es.
 */
string requireHttpsUrl(string url, string what) pure @safe {
  enforce!ConnectionConfigException(url.toLower.startsWith("https://"), format("%s debe ser una URL https: «%s»",
    what, url));
  urlOrigin(url);
  return url;
}

/**
 * URL completa de una ruta de la conexión (getXxxUrl(true)): la base más la ruta.
 *
 * Throws: ConnectionConfigException si falta la ruta o la URL resultante apunta a otro
 * servidor que la base.
 */
string serviceUrl(const ConnectionConfig config, string relative, string what) pure @safe {
  enforce!ConnectionConfigException(relative.length > 0, format("La conexión %s no tiene la ruta de %s",
    config.name, what));
  string full = config.baseUrl ~ relative;
  enforce!ConnectionConfigException(urlOrigin(full) == urlOrigin(config.baseUrl),
    format("La ruta de %s de la conexión %s cambia de servidor: «%s»", what, config.name, relative));
  return full;
}

/**
 * Comprueba una conexión externa antes de usarla o guardarla: nombre y servicio, base
 * https, y rutas que no cambian de servidor.
 *
 * Throws: ConnectionConfigException con el campo que falla.
 */
void validateExternalConfig(const ConnectionConfig config) pure @safe {
  enforce!ConnectionConfigException(config.name.strip.length > 0, "La conexión no tiene nombre");
  enforce!ConnectionConfigException(config.service.strip.length > 0, format("La conexión %s no tiene servicio",
    config.name));
  requireHttpsUrl(config.baseUrl, format("La URL base de la conexión %s", config.name));
  static foreach (entry; serviceUrlFields) {
    if (__traits(getMember, config, entry[0]).length) serviceUrl(config, __traits(getMember, config, entry[0]), entry[0]);
  }
}

/**
 * Rutas de servicio de una conexión externa: el campo de ConnectionConfig (que es también
 * su elemento en servicesUrls.xml) y su nombre en el JSON de alta (.firmadorconn). En el
 * JSON, los nombres de las dos rutas de negociación van cruzados respecto a los del XML.
 */
private enum string[2][] serviceUrlFields = [
  ["negotiationUrl", "negotiation_start_url"], ["negotiationStartUrl", "negotiation_connection"],
  ["completeUrl", "document_complete_url"], ["endSessionUrl", "end_session_url"],
  ["previewUrl", "document_preview_url"], ["signUrl", "document_sign_url"], ["deleteUrl", "document_delete_url"],
  ["loginUrl", "login_url"], ["validateUrl", "validate_url"], ["virtualDocumentsUrl", "virtual_documents_url"],
];

/// Elementos de texto de servicesUrls.xml (campos de ConnectionConfig), en el orden en que se escriben.
private enum string[] servicesUrlsElements = ["service", "baseUrl"] ~ serviceUrlFields.map!(entry => entry[0]).array;

/**
 * servicesUrls.xml con las conexiones (ServicesUrlsIO.save): un elemento «connection»
 * por conexión con su nombre como atributo; los valores vacíos no se escriben.
 */
string formatServicesUrls(const ConnectionConfig[] connections) pure @safe {
  string xml = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>` ~ "\n<servicesUrls>\n";
  foreach (config; connections) {
    xml ~= `  <connection name="` ~ escapeXml(config.name) ~ "\">\n";
    static foreach (element; servicesUrlsElements) {
      if (__traits(getMember, config, element).length) {
        xml ~= "    <" ~ element ~ ">" ~ escapeXml(__traits(getMember, config, element)) ~ "</" ~ element ~ ">\n";
      }
    }
    xml ~= "    <port>" ~ config.port.to!string ~ "</port>\n";
    xml ~= "    <startOn>" ~ (config.startOn ? "true" : "false") ~ "</startOn>\n";
    xml ~= "  </connection>\n";
  }
  return xml ~ "</servicesUrls>\n";
}

/**
 * Lee servicesUrls.xml (ServicesUrlsIO.load). Las conexiones externas se validan como
 * al darlas de alta.
 *
 * Throws: ConnectionConfigException si el XML no tiene la forma esperada o una conexión
 * no es válida; XmlException si no es XML.
 */
ConnectionConfig[] parseServicesUrls(const(ubyte)[] xml) @safe {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  auto root = document.root;
  enforce!ConnectionConfigException(root.isElement("", "servicesUrls"),
    format("%s debe tener «servicesUrls» como raíz", servicesUrlsFileName));
  ConnectionConfig[] connections;
  foreach (element; root.childrenNamed("", "connection")) {
    ConnectionConfig config;
    config.name = element.attribute("name");
    static foreach (field; servicesUrlsElements) {
      __traits(getMember, config, field) = childText(element, field);
    }
    string port = childText(element, "port");
    try {
      config.port = port.length ? port.to!ushort : 0;
    } catch (ConvException) {
      throw new ConnectionConfigException(format("El puerto «%s» de la conexión %s no es válido", port, config.name));
    }
    string startOn = childText(element, "startOn");
    // Boolean.parseBoolean: sólo «true», sin importar mayúsculas, es verdadero.
    config.startOn = startOn.toLower == "true";
    if (connectionKind(config.service) == ConnectionKind.external) validateExternalConfig(config);
    connections ~= config;
  }
  return connections;
}

/// Texto recortado del primer hijo con ese nombre, o vacío.
private string childText(XmlNode parent, string name) @safe {
  auto found = parent.child("", name);
  return found.isNull ? "" : found.text.strip;
}

/**
 * Conexión de un JSON de alta (.firmadorconn, Connection(String json)), con los nombres
 * de campo del servicio.
 *
 * Throws: JsonShapeException si falta un campo; ConnectionConfigException si una URL no
 * es válida.
 */
ConnectionConfig connectionFromJson(const JSONValue json) pure @safe {
  enum what = "La conexión";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  ConnectionConfig config;
  config.name = requiredString(json, "name", what);
  config.service = requiredString(json, "service", what);
  config.baseUrl = requiredString(json, "base_url", what);
  static foreach (entry; serviceUrlFields) {
    __traits(getMember, config, entry[0]) = requiredString(json, entry[1], what);
  }
  enforce!ConnectionConfigException(connectionKind(config.service) == ConnectionKind.external,
    format("Una conexión importada no puede usar el servicio reservado «%s»", config.service));
  validateExternalConfig(config);
  return config;
}

/// Contenido de un archivo .firmadorconn: el JSON y, si viene, el XML firmado que lo avala.
struct ConnectionFile {
  string json;
  /// XML firmado (null si el archivo no trae firma).
  string signedXml;
}

/**
 * Separa las partes de un .firmadorconn: el JSON entre «-----BEGIN JSON-----» y
 * «-----END JSON-----» (o todo el archivo si no hay marcas) y el XML firmado entre
 * «-----BEGIN SIGNED-XML-----» y «-----END SIGNED-XML-----».
 */
ConnectionFile parseConnectionFile(string content) pure @safe {
  ConnectionFile file;
  string json = between(content, "-----BEGIN JSON-----", "-----END JSON-----");
  file.json = json !is null ? json : content.strip;
  file.signedXml = between(content, "-----BEGIN SIGNED-XML-----", "-----END SIGNED-XML-----");
  return file;
}

/// Texto recortado entre dos marcas, o null si falta alguna.
private string between(string content, string begin, string end) pure @safe {
  auto start = content.indexOf(begin);
  if (start < 0) return null;
  string rest = content[start + begin.length .. $];
  auto stop = rest.indexOf(end);
  if (stop < 0) return null;
  return rest[0 .. stop].strip;
}

/// Resultado de validar el XML firmado de un .firmadorconn.
struct ConnectionSignature {
  /// La firma es válida (TOTAL_PASSED o PASSED).
  bool valid;
  /// Firmante (QualifiedName del reporte), o «Desconocido».
  string signerName;
  /// Indicación de la primera firma, para el aviso de error.
  string indication;
}

/**
 * Resume la validación del XML firmado como hacía AddConnection con el reporte simple:
 * la primera firma decide. La firma avala al firmante, no el JSON: la ventana debe
 * mostrar ambos para que el usuario decida.
 */
ConnectionSignature summarizeConnectionSignature(const DocumentValidationResult result) pure @safe {
  ConnectionSignature summary = ConnectionSignature(false, "Desconocido", "UNKNOWN");
  if (result.signatures.length == 0) return summary;
  auto first = result.signatures[0];
  if (first.certificateChain.length) summary.signerName = first.certificateChain[0].subject.readableName;
  summary.indication = indicationName(first.indication);
  summary.valid = first.indication == Indication.totalPassed || first.indication == Indication.passed;
  return summary;
}

/**
 * Valida el XML firmado de un .firmadorconn en línea (con revocación).
 *
 * Throws: Exception si el XML no se puede interpretar.
 */
ConnectionSignature checkConnectionSignature(string signedXml) @trusted {
  info("Validando la firma del archivo de conexión");
  auto result = validateXml(cast(immutable(ubyte)[]) signedXml, "conexion.xml", new ValidationSource);
  auto summary = summarizeConnectionSignature(result);
  info("Firma del archivo de conexión: ", summary.indication, " de ", summary.signerName);
  return summary;
}

/// Ruta de servicesUrls.xml.
string servicesUrlsPath() @safe {
  return buildPath(configDirectory(), servicesUrlsFileName);
}

/**
 * Lee las conexiones guardadas; vacío si todavía no hay archivo.
 *
 * Throws: Exception con la ruta si el archivo no se puede leer o interpretar.
 */
ConnectionConfig[] loadConnections() @trusted {
  string path = servicesUrlsPath();
  if (!exists(path)) return null;
  info("Leyendo las conexiones de ", path);
  return withContext("No se pudieron leer las conexiones de " ~ path,
    () => parseServicesUrls(cast(const(ubyte)[]) readText(path)));
}

/**
 * Guarda las conexiones.
 *
 * Throws: Exception con la ruta si no se puede escribir.
 */
void saveConnections(const ConnectionConfig[] connections) @trusted {
  string path = servicesUrlsPath();
  withContext("No se pudieron guardar las conexiones en " ~ path, {
    writeFileAtomically(path, formatServicesUrls(connections));
    info("Conexiones guardadas en ", path);
  });
}

version (unittest) {
  private ConnectionConfig externalExample() pure nothrow @safe {
    ConnectionConfig config;
    config.name = "Firma UCR";
    config.service = "UCR";
    config.baseUrl = "https://firma.ucr.ac.cr";
    config.negotiationUrl = "/api/negotiate/";
    config.completeUrl = "/api/complete/";
    config.signUrl = "/api/sign/";
    config.loginUrl = "/login/";
    config.validateUrl = "/api/documents/get_validate_document/";
    config.startOn = true;
    return config;
  }
}

@("should restore every field when writing and reading servicesUrls.xml")
unittest {
  auto connections = withDefaultConnections([externalExample()]);
  connections[0].name = `Firma "UCR" & <otros>`;
  auto parsed = parseServicesUrls(cast(const(ubyte)[]) formatServicesUrls(connections));
  assert(parsed == connections);
  assert(parsed.length == 3);
  assert(parsed[1].service == firmadorRemotoService && parsed[1].port == 3516);
  assert(parsed[2].service == gaudiService && !parsed[2].startOn);
}

@("should add only the missing default connections when merging loaded ones")
unittest {
  ConnectionConfig remote;
  remote.name = "Mi remoto";
  remote.service = firmadorRemotoService;
  remote.port = 3520;
  auto merged = withDefaultConnections([remote]);
  assert(merged.length == 2);
  assert(merged[0].port == 3520);
  assert(merged[1].service == gaudiService);
}

@("should reject service paths that move the request to another host when building URLs")
unittest {
  import std.exception : assertThrown;
  auto config = externalExample();
  assert(serviceUrl(config, config.signUrl, "firma") == "https://firma.ucr.ac.cr/api/sign/");
  assertThrown!ConnectionConfigException(serviceUrl(config, ".evil.example/x", "firma"));
  assertThrown!ConnectionConfigException(serviceUrl(config, "@evil.example/x", "firma"));
  assertThrown!ConnectionConfigException(serviceUrl(config, "", "firma"));
  config.baseUrl = "http://firma.ucr.ac.cr";
  assertThrown!ConnectionConfigException(validateExternalConfig(config));
  assert(urlOrigin("HTTPS://Firma.UCR.ac.cr:8443/a?b") == "https://firma.ucr.ac.cr:8443");
}

@("should split the JSON and the signed XML when reading a firmadorconn file")
unittest {
  auto signed = parseConnectionFile("x\n-----BEGIN JSON-----\n{\"a\":1}\n-----END JSON-----\n"
    ~ "-----BEGIN SIGNED-XML-----\n<a/>\n-----END SIGNED-XML-----\n");
  assert(signed.json == `{"a":1}` && signed.signedXml == "<a/>");
  auto plain = parseConnectionFile("  {\"a\":2}\n");
  assert(plain.json == `{"a":2}` && plain.signedXml is null);
}

@("should map the service field names and refuse reserved services when importing a connection")
unittest {
  import std.exception : assertThrown;
  string json = `{"name":"Firma UCR","service":"UCR","base_url":"https://firma.ucr.ac.cr",`
    ~ `"negotiation_start_url":"/n/","negotiation_connection":"/c/","document_complete_url":"/done/",`
    ~ `"end_session_url":"/end/","document_preview_url":"/preview/","document_sign_url":"/sign/",`
    ~ `"document_delete_url":"/delete/","login_url":"/login/","validate_url":"/v/get_validate_document/",`
    ~ `"virtual_documents_url":"/docs/"}`;
  auto config = connectionFromJson(parseJsonText(json, "la prueba"));
  assert(config.negotiationUrl == "/n/" && config.negotiationStartUrl == "/c/");
  assert(!config.startOn && config.port == 0);
  import std.array : replace;
  assertThrown!ConnectionConfigException(connectionFromJson(parseJsonText(json.replace(`"UCR"`, `"Gaudi"`), "x")));
  assertThrown!JsonShapeException(connectionFromJson(parseJsonText(`{"name":"x"}`, "x")));
}
