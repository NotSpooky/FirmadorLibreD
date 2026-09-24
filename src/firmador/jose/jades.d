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
 * Firmas JAdES (ETSI TS 119 182-1) sobre JWS (RFC 7515) como las armaba DSS 6.4 en la
 * versión Java (FirmadorJAdES): serialización JSON general, contenido envolvente en
 * base64url, cabecera protegida con alg, cty, kid, x5t#S256, x5c, typ e iat; nivel T con
 * sigTst, LT con xVals y rVals (o tstVD si ya hay sello de archivo) y LTA con arcTst, todos
 * como componentes base64url de etsiU. También lee JWS en serialización compacta y JSON
 * aplanada para validarlos.
 */
module firmador.jose.jades;

import std.algorithm : canFind;
import std.array : appender;
import std.base64 : Base64URLNoPadding, Base64Exception;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;
import std.json : JSONType, JSONValue, toJSON;
import std.logger : info;
import std.string : indexOf, split;
import std.utf : validate, UTFException;

import firmador.cms.tsp : parseTimeStampToken, TimeStampToken, Timestamper;
import firmador.crypto.digest;
import firmador.crypto.openssl : RawSignatureEncoding, rawSignatureEncoding, SignatureAlgorithm;
import firmador.util.json;
import firmador.util.base64 : encodeBase64;
import firmador.validation.certpath : missingFrom, ValidationData;
import firmador.validation.cmsverify : timestampSignerCertificate;
import firmador.validation.pool : CertificatePool;
import firmador.x509.certificate;

/// El JWS no tiene la forma esperada.
class JwsException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// base64url sin relleno (RFC 7515 §2).
string base64Url(const(ubyte)[] bytes) pure @safe {
  return Base64URLNoPadding.encode(bytes).idup;
}

/**
 * Bytes de un texto base64url (acepta relleno).
 *
 * Throws: JwsException con `what` si el texto no es base64url.
 */
immutable(ubyte)[] decodeBase64Url(string text, string what) pure @safe {
  string trimmed = text;
  while (trimmed.length && trimmed[$ - 1] == '=') trimmed = trimmed[0 .. $ - 1];
  try {
    return Base64URLNoPadding.decode(trimmed).idup;
  } catch (Base64Exception) {
    throw new JwsException(format("%s no está codificado en base64url", what));
  }
}

/// Nombre JWA del algoritmo de firma (lo que DSS pone en alg).
string jwsAlgorithmName(bool rsa, DigestAlgorithm digest) pure @safe {
  string bits;
  switch (digest) {
    case DigestAlgorithm.sha256: bits = "256"; break;
    case DigestAlgorithm.sha384: bits = "384"; break;
    case DigestAlgorithm.sha512: bits = "512"; break;
    default: throw new JwsException(format("JWS no admite el resumen %s", digest));
  }
  return (rsa ? "RS" : "ES") ~ bits;
}

/**
 * Algoritmo de un nombre JWA y si es ECDSA (valor r||s).
 *
 * Throws: JwsException si el algoritmo no se admite (incluido "none").
 */
SignatureAlgorithm signatureAlgorithmFromJws(string name, out bool ecdsa) pure @safe {
  SignatureAlgorithm algorithm;
  enforce!JwsException(name.length == 5, format("Algoritmo JWS no admitido: %s", name));
  switch (name[2 .. $]) {
    case "256": algorithm.digest = DigestAlgorithm.sha256; break;
    case "384": algorithm.digest = DigestAlgorithm.sha384; break;
    case "512": algorithm.digest = DigestAlgorithm.sha512; break;
    default: throw new JwsException(format("Algoritmo JWS no admitido: %s", name));
  }
  switch (name[0 .. 2]) {
    case "RS": algorithm.kind = SignatureAlgorithm.Kind.rsaPkcs1; break;
    case "PS":
      algorithm.kind = SignatureAlgorithm.Kind.rsaPss;
      algorithm.mgfDigest = algorithm.digest;
      algorithm.saltLength = cast(int) digestLength(algorithm.digest);
      break;
    case "ES":
      algorithm.kind = SignatureAlgorithm.Kind.ecdsa;
      ecdsa = true;
      break;
    default: throw new JwsException(format("Algoritmo JWS no admitido: %s", name));
  }
  return algorithm;
}

/// Texto JSON entre comillas con los escapes de RFC 8259.
string jsonQuoted(string text) pure @safe {
  auto output = appender!string;
  output ~= '"';
  foreach (char character; text) {
    switch (character) {
      case '"': output ~= `\"`; break;
      case '\\': output ~= `\\`; break;
      case '\n': output ~= `\n`; break;
      case '\r': output ~= `\r`; break;
      case '\t': output ~= `\t`; break;
      case '\b': output ~= `\b`; break;
      case '\f': output ~= `\f`; break;
      default:
        if (character < 0x20) output ~= format(`\u%04x`, cast(int) character);
        else output ~= character;
        break;
    }
  }
  output ~= '"';
  return output[];
}

/// IssuerSerial DER en base64 (el kid de DSS: generateKid).
string jadesKid(const Certificate certificate) pure @safe {
  return encodeBase64(issuerSerialDer(certificate));
}

/// Tipo MIME como lo escribe DSS en cty: sin "application/" si no queda otra barra.
string jwsContentType(string mimeType) pure @safe {
  enum prefix = "application/";
  if (mimeType.length > prefix.length && mimeType[0 .. prefix.length] == prefix
      && mimeType[prefix.length .. $].indexOf('/') < 0) return mimeType[prefix.length .. $];
  return mimeType;
}

/// Lo que define una firma JAdES nueva.
struct JadesParameters {
  SysTime signingTime;
  Certificate signingCertificate;
  bool rsa = true;
  /// Tipo MIME del contenido firmado (cty).
  string mimeType;
}

/// Firma preparada: cabecera y contenido codificados y lo que firma la tarjeta.
struct PreparedJades {
  string protectedHeader;
  string payload;
  immutable(ubyte)[] dataToSign;
  RawSignatureEncoding signatureEncoding;
}

/**
 * Arma la cabecera protegida y la entrada de firma (cabecera.contenido) de una firma
 * envolvente.
 */
PreparedJades prepareJadesSignature(const(ubyte)[] content, const JadesParameters parameters) @safe {
  enforce!JwsException(parameters.signingCertificate !is null, "Falta el certificado de firma");
  PreparedJades prepared;
  prepared.signatureEncoding = rawSignatureEncoding(parameters.rsa, parameters.signingCertificate);
  auto certificate = parameters.signingCertificate;
  string header = "{" ~ `"alg":` ~ jsonQuoted(jwsAlgorithmName(parameters.rsa, DigestAlgorithm.sha256));
  if (parameters.mimeType.length) header ~= `,"cty":` ~ jsonQuoted(jwsContentType(parameters.mimeType));
  header ~= `,"kid":` ~ jsonQuoted(jadesKid(certificate));
  header ~= `,"x5t#S256":` ~ jsonQuoted(base64Url(certificate.digest(DigestAlgorithm.sha256)));
  header ~= `,"x5c":[` ~ jsonQuoted(certificate.base64) ~ "]";
  header ~= `,"typ":"jose+json"`;
  header ~= format(`,"iat":%d`, parameters.signingTime.toUnixTime!long);
  header ~= "}";
  prepared.protectedHeader = base64Url(cast(const(ubyte)[]) header);
  prepared.payload = base64Url(content);
  prepared.dataToSign = cast(immutable(ubyte)[]) (prepared.protectedHeader ~ "." ~ prepared.payload);
  return prepared;
}

/// JWS en serialización JSON general con la firma (en ECDSA, el DER que dio el dispositivo).
immutable(ubyte)[] completeJadesSignature(const PreparedJades prepared, const(ubyte)[] signatureValue) @safe {
  auto value = prepared.signatureEncoding.encode(signatureValue);
  Jws jws;
  jws.payload = prepared.payload;
  JwsSignature signature;
  signature.protectedHeader = prepared.protectedHeader;
  signature.signature = base64Url(value);
  jws.signatures = [signature];
  return serializeJws(jws);
}

/// Componente de etsiU: nombre (sigTst, xVals…), valor y cómo venía escrito.
struct EtsiUComponent {
  string name;
  JSONValue value;
  /// Texto base64url tal como está en el documento; null si venía como objeto JSON.
  string encoded;
  /// Elemento original de la lista etsiU, para volver a escribirlo sin cambios.
  JSONValue item;
}

/// Una firma del JWS.
struct JwsSignature {
  string protectedHeader;
  /// Cabecera protegida ya interpretada.
  JSONValue header;
  string signature;
  /// Cabecera no protegida sin etsiU (null si no hay otros miembros).
  JSONValue unprotected;
  EtsiUComponent[] etsiU;
}

/// JWS interpretado.
struct Jws {
  /// Contenido tal como está en el documento (vacío si es separado).
  string payload;
  JwsSignature[] signatures;
}

private EtsiUComponent parseEtsiUItem(const JSONValue item) @trusted {
  EtsiUComponent component;
  component.item = cast(JSONValue) item;
  JSONValue container;
  if (item.type == JSONType.string) {
    component.encoded = item.str;
    auto decoded = decodeBase64Url(item.str, "Un componente de etsiU");
    container = parseJsonText(cast(string) decoded, "Un componente de etsiU");
  } else {
    container = cast(JSONValue) item;
  }
  auto keys = objectKeys(container, "Un componente de etsiU");
  enforce!JwsException(keys.length == 1, "Cada componente de etsiU debe tener un solo miembro");
  component.name = keys[0];
  component.value = container[keys[0]];
  return component;
}

private JwsSignature parseSignatureObject(string protectedHeader, string signatureValue, const(JSONValue)* unprotected)
    @trusted {
  JwsSignature signature;
  signature.protectedHeader = protectedHeader;
  signature.signature = signatureValue;
  auto headerText = decodeBase64Url(protectedHeader, "La cabecera protegida");
  try {
    validate(cast(string) headerText);
  } catch (UTFException) {
    throw new JwsException("La cabecera protegida no es UTF-8");
  }
  signature.header = parseJsonText(cast(string) headerText, "La cabecera protegida");
  enforce!JwsException(isObject(signature.header), "La cabecera protegida no es un objeto JSON");
  if (unprotected !is null && unprotected.type != JSONType.null_) {
    enforce!JwsException(isObject(*unprotected), "La cabecera no protegida no es un objeto JSON");
    JSONValue others = JSONValue(string[string].init);
    foreach (key, value; unprotected.object) {
      if (key == "etsiU") {
        foreach (item; arrayItems(value, "etsiU")) signature.etsiU ~= parseEtsiUItem(item);
      } else {
        others[key] = value;
      }
    }
    if (others.object.length) signature.unprotected = others;
  }
  return signature;
}

/**
 * Interpreta un JWS en serialización compacta, JSON aplanada o JSON general.
 *
 * Throws: JwsException o JsonShapeException con el motivo si no es un JWS.
 */
Jws parseJws(const(ubyte)[] bytes) @trusted {
  string text = cast(string) bytes.idup;
  try {
    validate(text);
  } catch (UTFException) {
    throw new JwsException("El JWS no es texto UTF-8");
  }
  import std.string : strip;
  string trimmed = text.strip;
  Jws jws;
  if (trimmed.length && trimmed[0] != '{') {
    auto parts = trimmed.split(".");
    enforce!JwsException(parts.length == 3, "Un JWS compacto debe tener tres partes separadas por puntos");
    jws.payload = parts[1];
    jws.signatures = [parseSignatureObject(parts[0], parts[2], null)];
    return jws;
  }
  auto root = parseJsonText(trimmed, "El JWS");
  enforce!JwsException(isObject(root), "El JWS debe ser un objeto JSON");
  jws.payload = optionalString(root, "payload", "El JWS");
  if (!isAbsent(root, "signatures")) {
    foreach (item; arrayItems(root["signatures"], "signatures")) {
      jws.signatures ~= parseSignatureObject(requiredString(item, "protected", "Una firma del JWS"),
        requiredString(item, "signature", "Una firma del JWS"), member(item, "header"));
    }
  } else {
    jws.signatures = [parseSignatureObject(requiredString(root, "protected", "El JWS"),
      requiredString(root, "signature", "El JWS"), member(root, "header"))];
  }
  enforce!JwsException(jws.signatures.length > 0, "El JWS no tiene firmas");
  return jws;
}

/// Escribe el JWS en serialización JSON general (la que usaba la versión Java).
immutable(ubyte)[] serializeJws(const Jws jws) @trusted {
  auto output = appender!string;
  output ~= `{"payload":` ~ jsonQuoted(jws.payload) ~ `,"signatures":[`;
  foreach (index, signature; jws.signatures) {
    if (index) output ~= ",";
    output ~= `{"protected":` ~ jsonQuoted(signature.protectedHeader);
    if (signature.etsiU.length || signature.unprotected.type == JSONType.object) {
      JSONValue header = JSONValue(string[string].init);
      if (signature.unprotected.type == JSONType.object) {
        foreach (key, value; signature.unprotected.object) header[key] = value;
      }
      JSONValue[] items;
      foreach (component; signature.etsiU) items ~= cast(JSONValue) component.item;
      if (items.length) header["etsiU"] = JSONValue(items);
      output ~= `,"header":` ~ toJSON(header);
    }
    output ~= `,"signature":` ~ jsonQuoted(signature.signature) ~ "}";
  }
  output ~= "]}";
  return cast(immutable(ubyte)[]) output[];
}

/// El contenido va sin codificar (RFC 7797, b64 = false).
bool unencodedPayload(const JwsSignature signature) @safe {
  return optionalBool(signature.header, "b64", true, "La cabecera protegida") == false;
}

/**
 * Contenido como entra en la firma y en los sellos: el del documento o, si es separado
 * (payload vacío), el archivo dado codificado igual.
 */
string effectivePayload(const Jws jws, const JwsSignature signature, const(ubyte)[] detachedContent) @safe {
  if (jws.payload.length || detachedContent is null) return jws.payload;
  return unencodedPayload(signature) ? cast(string) detachedContent.idup : base64Url(detachedContent);
}

/// Entrada de la firma: cabecera protegida, punto y contenido.
immutable(ubyte)[] signingInput(const JwsSignature signature, string payload) pure @safe {
  return cast(immutable(ubyte)[]) (signature.protectedHeader ~ "." ~ payload);
}

/// Lo que sella un sigTst: el valor de firma en base64url.
immutable(ubyte)[] signatureTimestampData(const JwsSignature signature) pure @safe {
  return cast(immutable(ubyte)[]) signature.signature;
}

/**
 * Lo que sella un arcTst (JAdESTimestampMessageDigestBuilder de DSS): contenido, cabecera,
 * firma y los componentes de etsiU anteriores al índice `until`, separados por puntos.
 *
 * Throws: JwsException si algún componente anterior no está codificado en base64url.
 */
immutable(ubyte)[] archiveTimestampData(const JwsSignature signature, string payload, size_t until) @trusted {
  auto output = appender!(immutable(ubyte)[]);
  output ~= cast(immutable(ubyte)[]) (payload ~ "." ~ signature.protectedHeader ~ "." ~ signature.signature ~ ".");
  foreach (index, component; signature.etsiU) {
    if (index >= until) break;
    // Sin canonicalización JSON (DSS tampoco la hace), sólo se sellan componentes base64url.
    enforce!JwsException(component.encoded !is null,
      "El sello de archivo sólo se admite con componentes de etsiU codificados en base64url");
    output ~= cast(immutable(ubyte)[]) component.encoded;
  }
  return output[];
}

/// Tokens de un tstContainer ({"tstTokens":[{"val":…}]}).
immutable(ubyte)[][] tstContainerTokens(const JSONValue container) @safe {
  immutable(ubyte)[][] tokens;
  auto list = member(container, "tstTokens");
  enforce!JwsException(list !is null, "Contenedor de sellos sin tstTokens");
  foreach (token; arrayItems(*list, "tstTokens")) tokens ~= requiredBase64(token, "val", "Un sello de etsiU").idup;
  return tokens;
}

private EtsiUComponent newComponent(string name, string valueJson) @trusted {
  EtsiUComponent component;
  component.name = name;
  string container = "{" ~ jsonQuoted(name) ~ ":" ~ valueJson ~ "}";
  component.value = parseJsonText(valueJson, "Un componente nuevo de etsiU");
  component.encoded = base64Url(cast(const(ubyte)[]) container);
  component.item = JSONValue(component.encoded);
  return component;
}

private string tstContainerJson(const TimeStampToken token) @safe {
  return `{"tstTokens":[{"val":` ~ jsonQuoted(encodeBase64(token.der)) ~ "}]}";
}

/// Añade un sigTst a la firma `index` (nivel T).
immutable(ubyte)[] addJadesSignatureTimestamp(const(ubyte)[] document, size_t index, scope Timestamper stamp)
    @trusted {
  auto jws = parseJws(document);
  enforce!JwsException(index < jws.signatures.length, format("El JWS no tiene la firma %d", index));
  auto token = stamp(digestOf(DigestAlgorithm.sha256, signatureTimestampData(jws.signatures[index])));
  jws.signatures[index].etsiU ~= newComponent("sigTst", tstContainerJson(token));
  info("Sello de tiempo de firma JAdES añadido");
  return serializeJws(jws);
}

/**
 * Certificados y revocaciones que ya lleva la firma (x5c, xVals, rVals y tstVD); ignora
 * los que no se pueden leer.
 */
ValidationData jadesEmbeddedData(const JwsSignature signature) @trusted {
  ValidationData data;
  void addCertificate(const(ubyte)[] der) {
    try {
      data.addCertificate(parseCertificate(der));
    } catch (Exception) {
      // Un certificado ilegible no aporta a la validación.
    }
  }
  void addXVals(const JSONValue list) {
    foreach (item; arrayItems(list, "xVals")) {
      auto certificate = member(item, "x509Cert");
      if (certificate !is null) addCertificate(requiredBase64(*certificate, "val", "Un certificado de xVals"));
    }
  }
  void addRVals(const JSONValue values) {
    auto crls = member(values, "crlVals");
    if (crls !is null) foreach (item; arrayItems(*crls, "crlVals")) data.crls ~= requiredBase64(item, "val", "Una CRL").idup;
    auto ocsps = member(values, "ocspVals");
    if (ocsps !is null) {
      foreach (item; arrayItems(*ocsps, "ocspVals")) data.ocspResponses ~= requiredBase64(item, "val", "Una respuesta OCSP").idup;
    }
  }
  foreach (text; optionalStringList(signature.header, "x5c", "La cabecera protegida")) {
    addCertificate(decodeBase64Field(text, "Un certificado de x5c"));
  }
  foreach (component; signature.etsiU) {
    try {
      if (component.name == "xVals") addXVals(component.value);
      else if (component.name == "rVals") addRVals(component.value);
      else if (component.name == "tstVD") {
        auto xVals = member(component.value, "xVals");
        if (xVals !is null) addXVals(*xVals);
        auto rVals = member(component.value, "rVals");
        if (rVals !is null) addRVals(*rVals);
      }
    } catch (Exception) {
      // Un valor mal formado no aporta a la validación.
    }
  }
  return data;
}

private string valuesJson(const(Certificate)[] certificates) @safe {
  string list = "[";
  foreach (index, certificate; certificates) {
    if (index) list ~= ",";
    list ~= `{"x509Cert":{"val":` ~ jsonQuoted(certificate.base64) ~ "}}";
  }
  return list ~ "]";
}

private string revocationJson(const(ubyte[])[] crls, const(ubyte[])[] ocsps) @safe {
  string[] members;
  string listOf(const(ubyte[])[] items) {
    string list = "[";
    foreach (index, item; items) list ~= (index ? "," : "") ~ `{"val":` ~ jsonQuoted(encodeBase64(item)) ~ "}";
    return list ~ "]";
  }
  if (crls.length) members ~= `"crlVals":` ~ listOf(crls);
  if (ocsps.length) members ~= `"ocspVals":` ~ listOf(ocsps);
  import std.array : join;
  return "{" ~ members.join(",") ~ "}";
}

/**
 * Añade los datos de validación a la firma `index` (nivel LT): sin sello de archivo se
 * reemplazan xVals y rVals; con él, lo nuevo va en un tstVD, como DSS.
 */
immutable(ubyte)[] addJadesValidationData(const(ubyte)[] document, size_t index, const ValidationData data) @trusted {
  auto jws = parseJws(document);
  enforce!JwsException(index < jws.signatures.length, format("El JWS no tiene la firma %d", index));
  auto signature = &jws.signatures[index];
  bool archived = signature.etsiU.canFind!(component => component.name == "arcTst");
  while (signature.etsiU.length && (signature.etsiU[$ - 1].name == "tstVD" || signature.etsiU[$ - 1].name == "anyValData")) {
    signature.etsiU = signature.etsiU[0 .. $ - 1];
  }
  if (!archived) {
    EtsiUComponent[] kept;
    foreach (component; signature.etsiU) if (component.name != "xVals" && component.name != "rVals") kept ~= component;
    signature.etsiU = kept;
  }
  auto missing = missingFrom(data, jadesEmbeddedData(*signature));
  bool revocations = missing.crls.length || missing.ocspResponses.length;
  if (archived) {
    string[] members;
    if (missing.certificates.length) members ~= `"xVals":` ~ valuesJson(missing.certificates);
    if (revocations) members ~= `"rVals":` ~ revocationJson(missing.crls, missing.ocspResponses);
    import std.array : join;
    if (members.length) signature.etsiU ~= newComponent("tstVD", "{" ~ members.join(",") ~ "}");
  } else {
    if (missing.certificates.length) signature.etsiU ~= newComponent("xVals", valuesJson(missing.certificates));
    if (revocations) signature.etsiU ~= newComponent("rVals", revocationJson(missing.crls, missing.ocspResponses));
  }
  info("Datos de validación JAdES añadidos");
  return serializeJws(jws);
}

/**
 * Lo que necesita el nivel LT de la firma: en `certificates`, el de firma (el de x5c que
 * coincide con x5t#S256, o el primero si la cabecera no lo trae) y los de las autoridades
 * de sus sigTst y arcTst (buscados también en `pool`); en las revocaciones, las que ya
 * incluye. Es lo que recibe SigningServices.validationData (firmador.signers.common).
 *
 * Throws: JwsException si la firma no incluye su certificado de firma; Exception si el
 * certificado de la autoridad de un sello no está en el sello ni en `pool`.
 */
ValidationData jadesSigningMaterial(const JwsSignature signature, CertificatePool pool) @trusted {
  auto embedded = jadesEmbeddedData(signature);
  ValidationData material;
  material.ocspResponses = embedded.ocspResponses;
  material.crls = embedded.crls;
  string thumbprint = optionalString(signature.header, "x5t#S256", "La cabecera protegida");
  foreach (certificate; embedded.certificates) {
    if (thumbprint is null || base64Url(certificate.digest(DigestAlgorithm.sha256)) == thumbprint) {
      material.addCertificate(certificate);
      break;
    }
  }
  enforce!JwsException(material.certificates.length, "La firma JAdES no incluye su certificado de firma");
  foreach (component; signature.etsiU) {
    if (component.name != "sigTst" && component.name != "arcTst") continue;
    foreach (der; tstContainerTokens(component.value)) {
      material.addCertificate(timestampSignerCertificate(parseTimeStampToken(der), pool));
    }
  }
  return material;
}

/**
 * Añade un arcTst a la firma `index` (nivel LTA) sobre todo lo que ya tiene.
 *
 * Throws: JwsException si el contenido es separado y no se da; lo que lance el sellador.
 */
immutable(ubyte)[] addJadesArchiveTimestamp(const(ubyte)[] document, size_t index, scope Timestamper stamp,
    const(ubyte)[] detachedContent = null) @trusted {
  auto jws = parseJws(document);
  enforce!JwsException(index < jws.signatures.length, format("El JWS no tiene la firma %d", index));
  auto signature = &jws.signatures[index];
  string payload = effectivePayload(jws, *signature, detachedContent);
  enforce!JwsException(payload.length, "Falta el contenido firmado para el sello de archivo");
  auto data = archiveTimestampData(*signature, payload, signature.etsiU.length);
  auto token = stamp(digestOf(DigestAlgorithm.sha256, data));
  signature.etsiU ~= newComponent("arcTst", tstContainerJson(token));
  info("Sello de archivo JAdES añadido");
  return serializeJws(jws);
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity, verifySignature;
  import std.datetime.date : DateTime;
  import std.datetime.timezone : UTC;
}

@("should produce a general JSON JWS whose signing input verifies and whose header matches DSS")
unittest {
  auto identity = makeTestIdentity("Firmante JAdES", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  JadesParameters parameters;
  parameters.signingTime = SysTime(DateTime(2026, 9, 22, 15, 0, 0), UTC());
  parameters.signingCertificate = certificate;
  parameters.mimeType = "application/json";
  auto content = cast(const(ubyte)[]) `{"monto":100}`;
  auto prepared = prepareJadesSignature(content, parameters);
  auto signed = completeJadesSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));
  auto jws = parseJws(signed);
  assert(jws.signatures.length == 1);
  assert(decodeBase64Url(jws.payload, "payload") == content);
  auto header = jws.signatures[0].header;
  assert(requiredString(header, "alg", "h") == "RS256");
  assert(requiredString(header, "cty", "h") == "json");
  assert(requiredString(header, "typ", "h") == "jose+json");
  assert(optionalLong(header, "iat", 0, "h") == parameters.signingTime.toUnixTime!long);
  bool ecdsa;
  auto algorithm = signatureAlgorithmFromJws("RS256", ecdsa);
  assert(verifySignature(certificate.subjectPublicKeyInfoDer, algorithm, signingInput(jws.signatures[0], jws.payload),
    decodeBase64Url(jws.signatures[0].signature, "firma")));
  assert(jadesEmbeddedData(jws.signatures[0]).certificates.length == 1);
}

@("should keep existing etsiU components byte for byte and stamp them in order when archiving")
unittest {
  auto first = newComponent("sigTst", `{"tstTokens":[{"val":"AAEC"}]}`);
  JwsSignature signature;
  signature.protectedHeader = base64Url(cast(const(ubyte)[]) `{"alg":"RS256"}`);
  signature.signature = "firma";
  signature.etsiU = [first];
  auto data = cast(string) archiveTimestampData(signature, "contenido", 1);
  assert(data == "contenido." ~ signature.protectedHeader ~ ".firma." ~ first.encoded);
  Jws jws;
  jws.payload = "contenido";
  jws.signatures = [signature];
  auto reparsed = parseJws(serializeJws(jws));
  assert(reparsed.signatures[0].etsiU[0].encoded == first.encoded);
  assert(tstContainerTokens(reparsed.signatures[0].etsiU[0].value) == [cast(immutable(ubyte)[]) [0, 1, 2]]);
}
