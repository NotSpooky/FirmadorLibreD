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
 * OCSP (RFC 6960): la solicitud del estado de un certificado y la lectura de la respuesta
 * básica. La verificación de la firma del respondedor y de su autorización está en
 * firmador.validation.revocation.
 */
module firmador.cms.ocsp;

import std.bigint : BigInt;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;
import std.typecons : Nullable;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.crypto.digest;
import firmador.x509.certificate;
import firmador.x509.name;

/// Estado de un certificado según OCSP.
enum CertificateStatus { good, revoked, unknown }

/// Identificador del certificado consultado (CertID).
struct OcspCertId {
  DigestAlgorithm digest;
  immutable(ubyte)[] issuerNameHash;
  immutable(ubyte)[] issuerKeyHash;
  BigInt serialNumber;

  /// Identifica a `certificate` emitido por `issuer`.
  bool matches(const Certificate certificate, const Certificate issuer) const @safe {
    return serialNumber == certificate.serialNumber
      && issuerNameHash == digestOf(digest, certificate.issuer.der)
      && issuerKeyHash == digestOf(digest, issuer.publicKeyBits);
  }
}

/// Respuesta sobre un certificado.
struct OcspSingleResponse {
  OcspCertId certId;
  CertificateStatus status;
  SysTime revocationTime;
  int revocationReason = -1;
  SysTime thisUpdate;
  Nullable!SysTime nextUpdate;
}

/// Respuesta OCSP básica ya interpretada.
struct OcspResponse {
  /// OCSPResponse completo (lo que se guarda en /OCSPs de PDF y en XAdES).
  immutable(ubyte)[] der;
  /// BasicOCSPResponse (lo que se guarda en revocationValues de CAdES).
  immutable(ubyte)[] basicDer;
  immutable(ubyte)[] tbsResponseData;
  bool responderByKey;
  DistinguishedName responderName;
  immutable(ubyte)[] responderKeyHash;
  SysTime producedAt;
  OcspSingleResponse[] responses;
  string signatureAlgorithmOid;
  immutable(ubyte)[] signatureAlgorithmParameters;
  immutable(ubyte)[] signature;
  Certificate[] certificates;

  /// Respuesta que corresponde a `certificate` emitido por `issuer`, o null.
  const(OcspSingleResponse)* responseFor(const Certificate certificate, const Certificate issuer) const @safe {
    foreach (index; 0 .. responses.length) {
      if (responses[index].certId.matches(certificate, issuer)) return &responses[index];
    }
    return null;
  }

  /// El certificado es el que firma la respuesta según ResponderID.
  bool isResponder(const Certificate candidate) const @safe {
    if (responderByKey) return digestOf(DigestAlgorithm.sha1, candidate.publicKeyBits) == responderKeyHash;
    return candidate.subject.matches(responderName);
  }
}

/// El respondedor contestó con un estado de error o algo que no es una respuesta básica.
class OcspException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// OCSPRequest sin firmar ni nonce (como OnlineOCSPSource de DSS) para un certificado.
ubyte[] buildOcspRequest(const Certificate certificate, const Certificate issuer,
    DigestAlgorithm digest = DigestAlgorithm.sha1) @safe {
  auto certId = derSequence(derAlgorithm(digestOid(digest), true), derOctetString(digestOf(digest, certificate.issuer.der)),
    derOctetString(digestOf(digest, issuer.publicKeyBits)), certificate.serialNumberDer);
  auto tbsRequest = derSequence(derSequence(derSequence(certId)));
  return derSequence(tbsRequest);
}

private immutable string[] responseStatusNames = ["successful", "malformedRequest", "internalError", "tryLater",
  "(sin uso)", "sigRequired", "unauthorized"];

/**
 * Lee un OCSPResponse o directamente un BasicOCSPResponse.
 *
 * Throws: OcspException si el estado no es successful o la respuesta no es básica;
 * Asn1Exception si la estructura está mal formada.
 */
OcspResponse parseOcspResponse(const(ubyte)[] der) @safe {
  auto root = parseDer(der);
  auto children = root.children();
  enforce!Asn1Exception(children.length >= 1, "Respuesta OCSP vacía");
  const(ubyte)[] basic;
  OcspResponse response;
  if (children[0].isUniversal(UniversalTag.enumerated)) {
    long status = children[0].smallIntegerValue;
    if (status != 0) {
      string name = status >= 0 && status < responseStatusNames.length ? responseStatusNames[cast(size_t) status] : "?";
      throw new OcspException(format("El respondedor OCSP contestó %s (%d)", name, status));
    }
    enforce!OcspException(children.length == 2 && children[1].isContext(0), "La respuesta OCSP no trae contenido");
    auto responseBytes = parseDer(children[1].content).reader();
    enforce!OcspException(responseBytes.next("el tipo de respuesta").oidValue == oidOcspBasic,
      "La respuesta OCSP no es una respuesta básica");
    basic = responseBytes.next("la respuesta básica").octetStringValue;
    response.der = der.idup;
  } else {
    basic = der;
    // Se reconstruye el OCSPResponse para guardarlo donde se espera la respuesta completa.
    response.der = derSequence(derTlv(0x0A, [0]), derContextConstructed(0,
      derSequence(derOid(oidOcspBasic), derOctetString(der)))).idup;
  }
  response.basicDer = basic.idup;

  auto basicReader = parseDer(basic).reader();
  auto tbs = basicReader.next("los datos de la respuesta");
  response.tbsResponseData = tbs.raw.idup;
  auto algorithm = parseAlgorithmIdentifier(basicReader.next("el algoritmo de firma OCSP"),
    "El algoritmo de firma OCSP");
  response.signatureAlgorithmOid = algorithm.oid;
  response.signatureAlgorithmParameters = algorithm.parameters;
  response.signature = basicReader.next("la firma OCSP").bitStringBytes.idup;
  DerElement certificates;
  if (basicReader.nextContext(0, certificates)) {
    foreach (certificate; parseDer(certificates.content).children()) response.certificates ~= parseCertificate(certificate.raw);
  }

  auto tbsReader = tbs.reader();
  DerElement ignored;
  tbsReader.nextContext(0, ignored);
  auto responder = tbsReader.next("el identificador del respondedor");
  if (responder.isContext(1)) {
    response.responderName = parseName(parseDer(responder.content));
  } else {
    enforce!Asn1Exception(responder.isContext(2), "Identificador de respondedor OCSP no válido");
    response.responderByKey = true;
    response.responderKeyHash = parseDer(responder.content).octetStringValue.idup;
  }
  response.producedAt = tbsReader.next("la fecha de producción").timeValue;
  foreach (single; tbsReader.next("las respuestas").children()) response.responses ~= parseSingleResponse(single);
  return response;
}

private OcspSingleResponse parseSingleResponse(const DerElement element) @safe {
  OcspSingleResponse single;
  auto reader = element.reader();
  auto certId = reader.next("el identificador del certificado").reader();
  single.certId.digest = digestFromOid(parseAlgorithmIdentifier(certId.next("el algoritmo del identificador"),
    "El algoritmo del identificador OCSP").oid);
  single.certId.issuerNameHash = certId.next("el resumen del nombre del emisor").octetStringValue.idup;
  single.certId.issuerKeyHash = certId.next("el resumen de la clave del emisor").octetStringValue.idup;
  single.certId.serialNumber = certId.next("el serial").integerValue;
  auto status = reader.next("el estado del certificado");
  if (status.isContext(0)) {
    single.status = CertificateStatus.good;
  } else if (status.isContext(1)) {
    single.status = CertificateStatus.revoked;
    auto revoked = DerReader(parseDerSequenceContent(status.content));
    single.revocationTime = revoked.next("la fecha de revocación").timeValue;
    DerElement reason;
    if (revoked.nextContext(0, reason)) single.revocationReason = cast(int) parseDer(reason.content).smallIntegerValue;
  } else {
    single.status = CertificateStatus.unknown;
  }
  single.thisUpdate = reader.next("thisUpdate").timeValue;
  DerElement nextUpdate;
  if (reader.nextContext(0, nextUpdate)) single.nextUpdate = parseDer(nextUpdate.content).timeValue;
  return single;
}

@("should identify the certificate by issuer name, issuer key and serial when building a request")
unittest {
  auto issuer = bundledCertificate!"certs/CA RAIZ NACIONAL - COSTA RICA v2.crt"();
  auto certificate = bundledCertificate!"certs/CA POLITICA PERSONA FISICA - COSTA RICA v2.crt"();
  auto request = parseDer(buildOcspRequest(certificate, issuer));
  auto certId = request.children()[0].children()[0].children()[0].children()[0].children();
  OcspCertId id;
  id.digest = digestFromOid(certId[0].children()[0].oidValue);
  id.issuerNameHash = certId[1].octetStringValue.idup;
  id.issuerKeyHash = certId[2].octetStringValue.idup;
  id.serialNumber = certId[3].integerValue;
  assert(id.matches(certificate, issuer));
  assert(!id.matches(issuer, issuer));
}

@("should report the responder status when an OCSP response is not successful")
unittest {
  import std.exception : collectExceptionMsg;
  import std.algorithm : canFind;
  assert(collectExceptionMsg(parseOcspResponse(derSequence(derTlv(0x0A, [6])))).canFind("unauthorized"));
}
