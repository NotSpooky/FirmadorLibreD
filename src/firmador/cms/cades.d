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
 * Firmas CAdES separadas (ETSI EN 319 122-1) como las armaba DSS 6.4: atributos
 * content-type, signing-time, message-digest y signing-certificate-v2; nivel T con
 * signature-time-stamp; LT con certificados y revocaciones en el SignedData; LTA con
 * archive-time-stamp-v3, cuyo sello lleva el ats-hash-index-v3 (§5.5.2 y §5.5.3).
 */
module firmador.cms.cades;

import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.logger : info;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.cms.signeddata;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.validation.certpath : ValidationData;
import firmador.validation.cmsverify : findSignerCertificate, timestampSignerCertificate;
import firmador.validation.pool : CertificatePool;
import firmador.x509.certificate;

/// Atributos firmados CAdES-B sobre el resumen SHA-256 del contenido.
ubyte[] cadesSignedAttributes(const(ubyte)[] contentDigest, const Certificate signingCertificate, SysTime signingTime)
    pure @safe {
  SignedAttributesInput input = {
    contentDigest: contentDigest,
    signingCertificate: signingCertificate,
    includeSigningTime: true,
    signingTime: signingTime,
  };
  return buildSignedAttributes(input);
}

/// SignedData separado (sin contenido encapsulado) con la firma y los certificados.
ubyte[] cadesCms(const(ubyte)[] signedAttributes, const(ubyte)[] signatureValue, bool rsa,
    const Certificate signingCertificate, const(Certificate)[] chain) pure @safe {
  SignedDataInput input = {
    rsa: rsa,
    signingCertificate: signingCertificate,
    certificates: [signingCertificate] ~ chain,
    signedAttributes: signedAttributes,
    signature: signatureValue,
  };
  return buildSignedData(input);
}

private const(SignerInfo) onlySigner(const SignedData data) pure @safe {
  enforce!Asn1Exception(data.signerInfos.length == 1,
    "La firma CAdES debe tener exactamente un firmante para extenderla");
  return data.signerInfos[0];
}

/**
 * Lo que necesita el nivel LT de la firma: en `certificates`, los de sus firmantes y los de
 * las autoridades de sus sellos de firma y de archivo (buscados también en `pool`); en las
 * revocaciones, las que ya incluye. Es lo que recibe validationData
 * (firmador.signers.common).
 *
 * Throws: Exception si el certificado de un firmante o de la autoridad de un sello no está
 * en la firma ni en `pool`.
 */
ValidationData cadesSigningMaterial(const(ubyte)[] cms, CertificatePool pool) @safe {
  auto data = parseSignedData(cms);
  ValidationData material;
  material.ocspResponses = data.ocspResponses;
  material.crls = data.crls;
  foreach (signer; data.signerInfos) {
    auto certificate = findSignerCertificate(data, signer, pool);
    enforce(certificate !is null, "La firma no incluye el certificado de su firmante");
    material.addCertificate(certificate);
    foreach (oid; [oidSignatureTimeStampToken, oidArchiveTimestampV3]) {
      foreach (attribute; signer.unsignedAttributesOf(oid)) {
        material.addCertificate(timestampSignerCertificate(parseTimeStampToken(attribute.values[0].raw), pool));
      }
    }
  }
  return material;
}

/// Añade un signature-time-stamp sobre el valor de la firma (nivel T).
immutable(ubyte)[] addCadesSignatureTimestamp(const(ubyte)[] cms, scope Timestamper stamp) @safe {
  auto signer = onlySigner(parseSignedData(cms));
  auto token = stamp(digestOf(DigestAlgorithm.sha256, signer.signature));
  info("Sello de tiempo de firma CAdES obtenido");
  return extendSignedData(cms, [cmsAttribute(oidSignatureTimeStampToken, token.der)], null, null, null).idup;
}

/// Añade al SignedData los certificados y revocaciones que todavía no tiene (nivel LT).
immutable(ubyte)[] addCadesValidationData(const(ubyte)[] cms, const ValidationData data) pure @safe {
  const(ubyte[])[] certificates;
  foreach (certificate; data.certificates) certificates ~= certificate.der;
  return extendSignedData(cms, null, certificates, data.crls, data.ocspResponses).idup;
}

/// Campos del SignerInfo que cubre el sello de archivo: todos menos los atributos no firmados.
private ubyte[] signerFieldsForArchive(const SignerInfo signer) pure @safe {
  ubyte[] fields;
  foreach (field; parseDer(signer.raw).children()) {
    if (field.isContext(1)) continue;
    fields ~= field.raw;
  }
  return fields;
}

/**
 * ATSHashIndexV3 del firmante (el valor DER del atributo ats-hash-index-v3): resúmenes de
 * cada certificado y revocación del SignedData y de cada valor de atributo no firmado.
 * Incluye el AlgorithmIdentifier aunque sea SHA-256, como DSS.
 */
ubyte[] atsHashIndexV3(const SignedData data, const SignerInfo signer, DigestAlgorithm digest) pure @safe {
  ubyte[][] certificates;
  foreach (raw; data.certificatesRaw) certificates ~= derOctetString(digestOf(digest, raw));
  ubyte[][] revocations;
  foreach (crl; data.crls) revocations ~= derOctetString(digestOf(digest, crl));
  foreach (ocsp; data.ocspResponses) {
    revocations ~= derOctetString(digestOf(digest, derContextConstructed(1, derOid(oidRevocationInfoOcsp), ocsp)));
  }
  ubyte[][] attributes;
  foreach (attribute; signer.unsignedAttributes) {
    auto type = derOid(attribute.oid);
    foreach (value; attribute.values) attributes ~= derOctetString(digestOf(digest, type ~ value.raw));
  }
  return derSequence(derSequence(derOid(digestOid(digest))), derSequence(certificates), derSequence(revocations),
    derSequence(attributes));
}

/**
 * Lo que resume un archive-time-stamp-v3 (EN 319 122-1 §5.5.3): tipo de contenido,
 * resumen del contenido firmado, campos firmados del firmante y el índice de resúmenes.
 */
ubyte[] archiveTimestampV3Data(const SignedData data, const SignerInfo signer, const(ubyte)[] contentDigest,
    const(ubyte)[] hashIndex) pure @safe {
  return derOid(data.eContentType) ~ contentDigest ~ signerFieldsForArchive(signer) ~ hashIndex;
}

/**
 * Añade un archive-time-stamp-v3 (nivel LTA). `content` es el documento firmado por la
 * firma separada.
 *
 * Throws: Asn1Exception si la firma no tiene un único firmante; lo que lance el sellador.
 */
immutable(ubyte)[] addCadesArchiveTimestamp(const(ubyte)[] cms, const(ubyte)[] content, scope Timestamper stamp)
    @safe {
  auto data = parseSignedData(cms);
  auto signer = onlySigner(data);
  auto contentDigest = data.hasEContent ? digestOf(DigestAlgorithm.sha256, data.eContent)
    : digestOf(DigestAlgorithm.sha256, content);
  enforce!Asn1Exception(data.hasEContent || content.length, "Falta el documento firmado para el sello de archivo");
  auto hashIndex = atsHashIndexV3(data, signer, DigestAlgorithm.sha256);
  auto imprint = digestOf(DigestAlgorithm.sha256, archiveTimestampV3Data(data, signer, contentDigest, hashIndex));
  auto token = stamp(imprint);
  // El índice va como atributo no firmado del firmante del sello (no lo cubre la firma de la TSA).
  auto indexedToken = extendSignedData(token.der, [cmsAttribute(oidAtsHashIndexV3, hashIndex)], null, null, null);
  info("Sello de archivo CAdES obtenido");
  return extendSignedData(cms, [cmsAttribute(oidArchiveTimestampV3, indexedToken)], null, null, null).idup;
}

/// Resultado de comprobar el índice de un sello de archivo contra la firma.
struct HashIndexCheck {
  /// DER del índice tal como está en el sello (lo que entra en el resumen).
  immutable(ubyte)[] hashIndex;
  DigestAlgorithm digest = DigestAlgorithm.sha256;
  /// Todos los resúmenes del índice están en la firma.
  bool complete;
}

/**
 * Lee el ats-hash-index-v3 del sello y comprueba que cada resumen corresponda a un
 * certificado, revocación o valor de atributo no firmado de la firma.
 *
 * Throws: Asn1Exception si el sello no tiene el índice o está mal formado.
 */
HashIndexCheck checkAtsHashIndex(const SignedData data, const SignerInfo signer, const TimeStampToken token)
    pure @safe {
  auto tokenSigner = token.signedData.signerInfos[0];
  auto attributes = tokenSigner.unsignedAttributesOf(oidAtsHashIndexV3);
  enforce!Asn1Exception(attributes.length == 1 && attributes[0].values.length == 1,
    "El sello de archivo no tiene un único ats-hash-index-v3");
  HashIndexCheck check;
  auto index = attributes[0].values[0];
  check.hashIndex = index.raw.idup;
  auto fields = index.children();
  size_t next = 0;
  if (fields.length == 4) {
    check.digest = digestFromOid(parseAlgorithmIdentifier(fields[0], "El resumen del ats-hash-index-v3").oid);
    next = 1;
  }
  enforce!Asn1Exception(fields.length - next == 3, "ats-hash-index-v3 mal formado");
  auto expected = parseDer(atsHashIndexV3(data, signer, check.digest)).children();
  check.complete = true;
  foreach (part; 0 .. 3) {
    auto present = expected[1 + part].children();
    foreach (hash; fields[next + part].children()) {
      bool found = false;
      foreach (candidate; present) if (candidate.raw == hash.raw) found = true;
      if (!found) check.complete = false;
    }
  }
  return check;
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
  import std.datetime.systime : Clock;
}

@("should compute a hash index that lists the certificates and unsigned attributes of the signature")
unittest {
  auto identity = makeTestIdentity("Firmante CAdES", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = cast(const(ubyte)[]) "documento";
  auto attributes = cadesSignedAttributes(digestOf(DigestAlgorithm.sha256, content), certificate, Clock.currTime);
  auto cms = cadesCms(attributes, identity.key.sign(DigestAlgorithm.sha256, attributes), true, certificate, []);
  auto data = parseSignedData(cms);
  assert(!data.hasEContent);
  assert(data.signerInfos[0].signedAttribute(oidSigningTime) !is null);
  auto index = parseDer(atsHashIndexV3(data, data.signerInfos[0], DigestAlgorithm.sha256)).children();
  assert(index.length == 4);
  assert(index[1].children().length == 1);
  assert(index[1].children()[0].octetStringValue == digestOf(DigestAlgorithm.sha256, certificate.der));
  assert(index[3].children().length == 0);
}
