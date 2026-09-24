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
 * Mensajes JSON de Firmador Remoto, de las conexiones y del shell (@contract remote-dto),
 * con los nombres que les daba Jackson en la versión Java: la petición de firma de un
 * resumen preparado por un servidor (FirmadorRemoteDocument), su respuesta
 * (RemoteSignatureValueDTO con SignatureValueDTO), el documento firmado (RemoteDocument de
 * DSS), la petición de firma de un documento completo (/signDocument) y la de
 * autenticación (AuthenticationRequest) con el XML de autorización que se firma.
 */
module firmador.remote.dto;

import std.algorithm : canFind;
import std.base64 : Base64;
import std.datetime.systime : Clock, SysTime;
import std.exception : enforce;
import std.format : format;
import std.json : JSONType, JSONValue, toJSON;
import std.process : environment;
import std.string : indexOf;
import std.uuid : parseUUID, UUID, UUIDParsingException;

import firmador.asn1.oids : oidCommonName, oidSerialNumber;
import firmador.cards.cardinfo : CardSignInfo;
import firmador.crypto.openssl : pbkdf2Sha256;
import firmador.gui.guiinterface : GuiInterface;
import firmador.settings : Settings;
import firmador.settingsjson : settingsFromJson;
import firmador.signers.common : signPreparedData;
import firmador.util.base64 : encodeBase64;
import firmador.util.datetime : costaRicaTimeZone;
import firmador.util.json;
import firmador.x509.certificate;

/// Petición de firma de un resumen preparado por un servidor (FirmadorRemoteDocument).
struct RemoteSignRequest {
  /// Serial o identificación de la credencial con que firmar.
  string serialNumber;
  /// Lo que se firma (tobesigned.bytes).
  immutable(ubyte)[] toBeSigned;
  /// Identificador del documento en el servidor, si lo trae.
  string documentId;
  /// Certificado con que el servidor preparó la firma, si lo trae.
  Certificate certificate;
  string documentName;
  string b64Document;
  string hostname;
  /// Imagen que acompaña la petición (data URL o base64).
  string b64image;
  string mimeType;
}

/**
 * Interpreta una petición de firma de resumen.
 *
 * Throws: JsonShapeException con el campo si no tiene la forma esperada.
 */
RemoteSignRequest parseRemoteSignRequest(const JSONValue json) @safe {
  enum what = "La solicitud de firma";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  RemoteSignRequest request;
  request.serialNumber = requiredString(json, "serialnumber", what);
  auto toBeSigned = member(json, "tobesigned");
  enforce!JsonShapeException(toBeSigned !is null && isObject(*toBeSigned), what ~ ": falta «tobesigned»");
  request.toBeSigned = requiredBase64(*toBeSigned, "bytes", what ~ ": «tobesigned»").idup;
  request.documentId = optionalString(json, "documentid", what);
  if (request.documentId !is null) {
    try {
      // parseUUID consume el rango que recibe por referencia: se valida una copia.
      string copy = request.documentId;
      parseUUID(copy);
    } catch (UUIDParsingException) {
      throw new JsonShapeException(what ~ ": «documentid» no es un UUID");
    }
  }
  string certificate = optionalString(json, "certificate", what);
  if (certificate !is null) request.certificate = parseCertificate(decodeBase64Field(certificate, what ~ ": «certificate»"));
  request.documentName = optionalString(json, "documentName", what);
  request.b64Document = optionalString(json, "b64Document", what);
  request.hostname = optionalString(json, "hostname", what);
  request.b64image = optionalString(json, "b64image", what);
  request.mimeType = optionalString(json, "mimetype", what);
  return request;
}

/// Lista de peticiones (/multipleSign y las conexiones).
RemoteSignRequest[] parseRemoteSignRequests(const JSONValue json) @safe {
  RemoteSignRequest[] requests;
  foreach (item; arrayItems(json, "La lista de solicitudes de firma")) requests ~= parseRemoteSignRequest(item);
  return requests;
}

/// Nombre del servidor que muestra la petición: el suyo, INSTANCE_HOSTNAME o localhost.
string requestHostname(const RemoteSignRequest request) @safe {
  if (request.hostname.length) return request.hostname;
  return environment.get("INSTANCE_HOSTNAME", "localhost");
}

/// Bytes de la imagen de una petición (quita el prefijo de data URL), o null si no es base64.
immutable(ubyte)[] requestImage(string b64image) @safe {
  if (b64image.length == 0) return null;
  auto comma = b64image.indexOf(',');
  string encoded = comma >= 0 ? b64image[comma + 1 .. $] : b64image;
  try {
    return Base64.decode(encoded).idup;
  } catch (Exception) {
    return null;
  }
}

/// Nombre DSS del algoritmo de la firma de un resumen (SignatureValueDTO.algorithm).
string signatureAlgorithmName(bool rsa) pure nothrow @safe @nogc {
  return rsa ? "RSA_SHA256" : "ECDSA_SHA256";
}

/**
 * Firma con la credencial cada resumen preparado, con el PIN que ya tiene, y arma la
 * respuesta de cada uno (remoteSignatureJson). Null si alguno no se pudo firmar; el motivo
 * ya se le mostró al usuario (signPreparedData).
 */
JSONValue[] signRemoteRequests(GuiInterface gui, CardSignInfo card, const RemoteSignRequest[] requests) @safe {
  JSONValue[] answers;
  foreach (request; requests) {
    auto signature = signPreparedData(gui, card, request.toBeSigned);
    if (signature is null) return null;
    answers ~= remoteSignatureJson(request, signature.value, signature.rsa, signature.certificate);
  }
  return answers;
}

/**
 * Respuesta a una petición de firma de resumen (RemoteSignatureValueDTO): la firma, el
 * documento y el certificado de la petición (o el de la credencial si no lo traía).
 */
JSONValue remoteSignatureJson(const RemoteSignRequest request, const(ubyte)[] signatureValue, bool rsa,
    const Certificate cardCertificate) @safe {
  JSONValue signature;
  signature["algorithm"] = signatureAlgorithmName(rsa);
  signature["value"] = encodeBase64(signatureValue);
  JSONValue json;
  json["signature"] = signature;
  json["documentid"] = request.documentId is null ? JSONValue(null) : JSONValue(request.documentId);
  auto certificate = request.certificate !is null ? request.certificate : cardCertificate;
  json["certificate"] = certificate is null ? JSONValue(null) : JSONValue(certificate.base64);
  return json;
}

/// Documento firmado (RemoteDocument de DSS: bytes, digestAlgorithm y name).
JSONValue remoteDocumentJson(const(ubyte)[] bytes, string name) @safe {
  JSONValue json;
  json["bytes"] = encodeBase64(bytes);
  json["digestAlgorithm"] = JSONValue(null);
  json["name"] = name is null ? JSONValue(null) : JSONValue(name);
  return json;
}

/// Petición de firma de un documento completo (/signDocument).
struct SignDocumentRequest {
  immutable(ubyte)[] document;
  /// Extensión con punto (".pdf" si no la trae, como la versión Java).
  string extension;
  string serialNumber;
  /// Ajustes del documento (los vigentes si no los trae).
  Settings settings;
}

/**
 * Interpreta /signDocument.
 *
 * Throws: JsonShapeException con el campo si no tiene la forma esperada.
 */
SignDocumentRequest parseSignDocumentRequest(const JSONValue json, const Settings base) @safe {
  enum what = "La solicitud /signDocument";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  SignDocumentRequest request;
  request.document = requiredBase64(json, "b64Document", what).idup;
  request.extension = optionalString(json, "DocumentExtension", what);
  if (request.extension is null) request.extension = ".pdf";
  enforce!JsonShapeException(request.extension.length >= 2 && request.extension[0] == '.'
    && !request.extension.canFind('/') && !request.extension.canFind('\\'), what ~ ": «DocumentExtension» no es válida");
  request.serialNumber = requiredString(json, "serialnumber", what);
  auto settings = member(json, "settings");
  request.settings = settings is null || settings.type == JSONType.null_ ? new Settings(base)
    : settingsFromJson(*settings, base);
  return request;
}

/// Petición de autenticación (AuthenticationRequest).
struct AuthenticationRequest {
  string serialNumber;
  string authCode;
  string b64Salt;
  string authIdentifier;
  string authTime;
  string domain;
  string b64image;
}

/**
 * Interpreta /authenticate.
 *
 * Throws: JsonShapeException con el campo si no tiene la forma esperada.
 */
AuthenticationRequest parseAuthenticationRequest(const JSONValue json) @safe {
  enum what = "La solicitud de autenticación";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  AuthenticationRequest request;
  request.serialNumber = requiredString(json, "serialnumber", what);
  request.authCode = requiredString(json, "authCode", what);
  request.b64Salt = requiredString(json, "b64Salt", what);
  request.authIdentifier = requiredString(json, "authIdentifier", what);
  request.authTime = requiredString(json, "authTime", what);
  request.domain = requiredString(json, "domain", what);
  request.b64image = optionalString(json, "b64image", what);
  decodeBase64Field(request.b64Salt, what ~ ": «b64Salt»");
  return request;
}

/// Últimos seis caracteres del código, los que se muestran para confirmar (getShortAuthCode).
string shortAuthCode(const AuthenticationRequest request) pure @safe {
  return request.authCode.length > 6 ? request.authCode[$ - 6 .. $] : null;
}

/// Iteraciones PBKDF2 del código de autorización (generateAuthCode).
enum int authCodeIterations = 100_000;

/// Escapa texto para el XML de autorización.
private string xmlText(string text) pure @safe {
  import firmador.xml.dom : escapeXml;
  return escapeXml(text);
}

/**
 * XML de autorización que se firma (resources/xml/authentication_template.xml): datos de
 * la petición, nombre e identificación del certificado, el código derivado con
 * PBKDF2-HMAC-SHA256 (100 000 iteraciones, 256 bits) y la fecha de emisión en Costa Rica.
 */
immutable(ubyte)[] authenticationDocument(const AuthenticationRequest request, const Certificate certificate,
    SysTime now) @safe {
  import std.array : replace;
  import firmador.util.datetime : formatJavaDate, DateLanguage;
  string template_ = import("xml/authentication_template.xml");
  auto salt = decodeBase64Field(request.b64Salt, "b64Salt");
  string derived = encodeBase64(pbkdf2Sha256(request.authCode, salt, authCodeIterations, 32));
  string emitted = formatJavaDate("dd/MM/yyyy HH:mm:ss", now.toOtherTZ(costaRicaTimeZone()), DateLanguage.spanish);
  string xml = template_.replace("{REQUEST_DATE}", xmlText(request.authTime)).replace("{DOMAIN}", xmlText(request.domain))
    .replace("{TRANSACTION}", xmlText(request.authIdentifier))
    .replace("{SIGNER}", xmlText(certificate.subject.first(oidCommonName)))
    .replace("{IDENTIFICATION}", xmlText(certificate.subject.first(oidSerialNumber)))
    .replace("{AUTHCODE}", derived).replace("{EMITION_DATE}", emitted);
  return cast(immutable(ubyte)[]) xml;
}

/// Texto de la petición de autenticación que se muestra al pedir el PIN.
string authenticationDescription(const AuthenticationRequest request) pure @safe {
  return format("<br>Solicitud de autenticación con la información<br>Dominio: <strong>%s</strong> <br>Código: "
    ~ "<strong>%s</strong>", xmlText(request.domain), xmlText(shortAuthCode(request)));
}

@("should parse a server signing request and answer with the Jackson field names")
unittest {
  import firmador.crypto.openssl : makeTestIdentity;
  auto certificate = parseCertificate(makeTestIdentity("Firmante remoto", "x").certificateDer);
  auto json = parseJsonText(`{"serialnumber":"123","tobesigned":{"bytes":"AAEC"},"documentid":`
    ~ `"d1b8c3a0-5a1f-4c3e-9e21-0a1b2c3d4e5f","documentName":"contrato.pdf","otro":1}`, "prueba");
  auto request = parseRemoteSignRequest(json);
  assert(request.toBeSigned == [0, 1, 2] && request.documentName == "contrato.pdf");
  auto answer = remoteSignatureJson(request, [9, 9], true, certificate);
  assert(answer["signature"]["algorithm"].str == "RSA_SHA256");
  assert(answer["signature"]["value"].str == "CQk=");
  assert(answer["documentid"].str == "d1b8c3a0-5a1f-4c3e-9e21-0a1b2c3d4e5f");
  assert(answer["certificate"].str == certificate.base64);
  import std.exception : assertThrown;
  assertThrown!JsonShapeException(parseRemoteSignRequest(parseJsonText(`{"serialnumber":"1"}`, "p")));
}

@("should derive the authorization code and escape request data in the signed XML")
unittest {
  import firmador.crypto.openssl : makeTestIdentity;
  import std.algorithm : canFind;
  auto certificate = parseCertificate(makeTestIdentity("JUAN <PEREZ>", "x").certificateDer);
  AuthenticationRequest request;
  request.authCode = "ABCDEF123456";
  request.b64Salt = encodeBase64(cast(const(ubyte)[]) "sal");
  request.authIdentifier = "T-1";
  request.authTime = "2026-09-23";
  request.domain = "a.cr&b";
  string xml = cast(string) authenticationDocument(request, certificate, Clock.currTime);
  assert(xml.canFind("<Dominio>a.cr&amp;b</Dominio>"));
  assert(xml.canFind("<Nombre>JUAN &lt;PEREZ&gt;</Nombre>"));
  string expected = Base64.encode(pbkdf2Sha256("ABCDEF123456", cast(const(ubyte)[]) "sal", 100_000, 32)).idup;
  assert(xml.canFind("<CodigoAutorizacion>" ~ expected ~ "</CodigoAutorizacion>"));
  assert(shortAuthCode(request) == "123456");
}
