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
 * CMS SignedData (RFC 5652): lectura de firmas y sellos de tiempo, y construcción de las
 * firmas CAdES que usan PAdES y CAdES (EN 319 122-1): atributos firmados, SignerInfo y la
 * incorporación de atributos no firmados, certificados y revocaciones al extender el
 * nivel. Sin E/S; la firma la aporta el dispositivo (firmador.tokens).
 */
module firmador.cms.signeddata;

import std.algorithm : canFind, map;
import std.array : array;
import std.bigint : BigInt;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.crypto.digest;
import firmador.x509.certificate;
import firmador.x509.name;

/// Atributo CMS: tipo y valores.
struct CmsAttribute {
  string oid;
  DerElement[] values;
  immutable(ubyte)[] raw;
}

/// Firmante de un SignedData.
struct SignerInfo {
  int version_;
  /// Identificador del firmante: emisor y serial, o identificador de clave.
  DistinguishedName sidIssuer;
  BigInt sidSerial;
  immutable(ubyte)[] sidKeyIdentifier;
  bool sidIsKeyIdentifier;
  DigestAlgorithm digestAlgorithm;
  /// Atributos firmados con su etiqueta [0] original; se firman con la etiqueta SET.
  immutable(ubyte)[] signedAttributesRaw;
  CmsAttribute[] signedAttributes;
  string signatureAlgorithmOid;
  immutable(ubyte)[] signatureAlgorithmParameters;
  immutable(ubyte)[] signature;
  CmsAttribute[] unsignedAttributes;
  immutable(ubyte)[] raw;

  /// DER que cubre la firma: los atributos firmados con la etiqueta SET (RFC 5652 §5.4).
  ubyte[] signedAttributesForSignature() const pure @safe {
    enforce!Asn1Exception(signedAttributesRaw.length > 0, "El firmante no tiene atributos firmados");
    auto element = parseDer(signedAttributesRaw);
    return derTlv(0x31, element.content);
  }

  /// Primer atributo firmado del tipo pedido, o null.
  const(CmsAttribute)* signedAttribute(string oid) const pure @safe {
    foreach (index; 0 .. signedAttributes.length) if (signedAttributes[index].oid == oid) return &signedAttributes[index];
    return null;
  }

  /// Atributos no firmados del tipo pedido.
  const(CmsAttribute)[] unsignedAttributesOf(string oid) const pure @safe {
    const(CmsAttribute)[] found;
    foreach (ref attribute; unsignedAttributes) if (attribute.oid == oid) found ~= attribute;
    return found;
  }

  /// El certificado es el de este firmante.
  bool identifies(const Certificate certificate) const @safe {
    if (sidIsKeyIdentifier) return certificate.subjectKeyIdentifier == sidKeyIdentifier;
    return certificate.issuer.matches(sidIssuer) && certificate.serialNumber == sidSerial;
  }
}

/// SignedData ya interpretado.
struct SignedData {
  immutable(ubyte)[] contentInfoRaw;
  int version_;
  immutable(ubyte)[][] digestAlgorithmsRaw;
  string eContentType;
  /// Contenido encapsulado; null si la firma es separada (detached).
  immutable(ubyte)[] eContent;
  bool hasEContent;
  Certificate[] certificates;
  immutable(ubyte)[][] certificatesRaw;
  /// CRL (CertificateList) incluidas en el campo crls.
  immutable(ubyte)[][] crls;
  /// Respuestas OCSP incluidas como otherRevocationInfo (id-ri-ocsp-response).
  immutable(ubyte)[][] ocspResponses;
  SignerInfo[] signerInfos;
}

/**
 * Interpreta un ContentInfo con SignedData (una firma CMS o un sello de tiempo).
 *
 * Throws: Asn1Exception con el campo que falla si no es un SignedData bien formado.
 */
SignedData parseSignedData(const(ubyte)[] contentInfo) @safe {
  auto root = parseDer(contentInfo);
  auto rootReader = root.reader();
  enforce!Asn1Exception(rootReader.next("el tipo de contenido").oidValue == oidSignedData,
    "El contenido CMS no es un SignedData");
  auto explicitContent = rootReader.next("el contenido del SignedData");
  enforce!Asn1Exception(explicitContent.isContext(0), "SignedData sin la etiqueta [0]");
  auto signedDataElement = parseDer(explicitContent.content);

  SignedData data;
  data.contentInfoRaw = contentInfo.idup;
  auto reader = signedDataElement.reader();
  data.version_ = cast(int) reader.next("la versión del SignedData").smallIntegerValue;
  foreach (algorithm; reader.next("los algoritmos de resumen").children()) data.digestAlgorithmsRaw ~= algorithm.raw.idup;
  auto encapsulated = reader.next("el contenido encapsulado").reader();
  data.eContentType = encapsulated.next("el tipo de contenido encapsulado").oidValue;
  DerElement eContent;
  if (encapsulated.nextContext(0, eContent)) {
    data.hasEContent = true;
    data.eContent = parseDer(eContent.content).octetStringValue.idup;
  }
  DerElement certificatesElement;
  if (reader.nextContext(0, certificatesElement)) {
    foreach (choice; parseDerSequenceContent(certificatesElement.content)) {
      if (!choice.isSequence) continue; // certificados de atributos u otros formatos
      data.certificatesRaw ~= choice.raw.idup;
      data.certificates ~= parseCertificate(choice.raw);
    }
  }
  DerElement crlsElement;
  if (reader.nextContext(1, crlsElement)) {
    foreach (choice; parseDerSequenceContent(crlsElement.content)) {
      if (choice.isSequence) {
        data.crls ~= choice.raw.idup;
      } else if (choice.isContext(1)) {
        auto other = DerReader(parseDerSequenceContent(choice.content));
        string format_ = other.next("el formato de revocación").oidValue;
        auto value = other.next("el valor de revocación");
        if (format_ == oidRevocationInfoOcsp) data.ocspResponses ~= value.raw.idup;
      }
    }
  }
  foreach (signerElement; reader.next("los firmantes").children()) data.signerInfos ~= parseSignerInfo(signerElement);
  reader.finish("el SignedData");
  return data;
}

private CmsAttribute[] parseAttributes(const DerElement element) @safe {
  CmsAttribute[] attributes;
  foreach (attributeElement; parseDerSequenceContent(element.content)) {
    auto reader = attributeElement.reader();
    CmsAttribute attribute;
    attribute.oid = reader.next("el tipo del atributo").oidValue;
    attribute.values = reader.next("los valores del atributo").children();
    // RFC 5652: attrValues es SET SIZE (1..MAX); quien lee el atributo toma el primero.
    enforce!Asn1Exception(attribute.values.length > 0, format("El atributo %s no trae valores", attribute.oid));
    attribute.raw = attributeElement.raw.idup;
    attributes ~= attribute;
  }
  return attributes;
}

private SignerInfo parseSignerInfo(const DerElement element) @safe {
  SignerInfo signer;
  signer.raw = element.raw.idup;
  auto reader = element.reader();
  signer.version_ = cast(int) reader.next("la versión del firmante").smallIntegerValue;
  auto sid = reader.next("el identificador del firmante");
  if (sid.isContext(0)) {
    signer.sidIsKeyIdentifier = true;
    signer.sidKeyIdentifier = sid.content.idup;
  } else {
    auto sidReader = sid.reader();
    signer.sidIssuer = parseName(sidReader.next("el emisor del firmante"));
    signer.sidSerial = sidReader.next("el serial del firmante").integerValue;
  }
  signer.digestAlgorithm = digestFromOid(parseAlgorithmIdentifier(reader.next("el resumen del firmante"),
    "El algoritmo de resumen del firmante").oid);
  DerElement signedAttributes;
  if (reader.nextContext(0, signedAttributes)) {
    signer.signedAttributesRaw = signedAttributes.raw.idup;
    signer.signedAttributes = parseAttributes(signedAttributes);
  }
  auto signatureAlgorithm = parseAlgorithmIdentifier(reader.next("el algoritmo de firma"),
    "El algoritmo de firma del firmante");
  signer.signatureAlgorithmOid = signatureAlgorithm.oid;
  signer.signatureAlgorithmParameters = signatureAlgorithm.parameters;
  signer.signature = reader.next("la firma").octetStringValue.idup;
  DerElement unsignedAttributes;
  if (reader.nextContext(1, unsignedAttributes)) signer.unsignedAttributes = parseAttributes(unsignedAttributes);
  reader.finish("el firmante");
  return signer;
}

/// Valor del atributo message-digest.
immutable(ubyte)[] messageDigestOf(const SignerInfo signer) @safe {
  auto attribute = signer.signedAttribute(oidMessageDigest);
  enforce!Asn1Exception(attribute !is null && attribute.values.length == 1,
    "La firma no tiene exactamente un atributo message-digest");
  return attribute.values[0].octetStringValue.idup;
}

/// Fecha del atributo signing-time, si lo tiene.
bool signingTimeOf(const SignerInfo signer, out SysTime time) @safe {
  auto attribute = signer.signedAttribute(oidSigningTime);
  if (attribute is null || attribute.values.length == 0) return false;
  time = attribute.values[0].timeValue;
  return true;
}

/// Referencia al certificado firmante en signing-certificate(-v2): resumen y algoritmo.
struct SigningCertificateReference {
  DigestAlgorithm digest;
  immutable(ubyte)[] certificateHash;
  bool hasIssuerSerial;
  BigInt issuerSerial;
}

/**
 * Referencias de signing-certificate-v2 (o de signing-certificate con SHA-1).
 *
 * Throws: Asn1Exception si el atributo existe pero está mal formado.
 */
SigningCertificateReference[] signingCertificateReferences(const SignerInfo signer) @safe {
  SigningCertificateReference[] references;
  auto v2 = signer.signedAttribute(oidSigningCertificateV2);
  auto v1 = signer.signedAttribute(oidSigningCertificate);
  auto attribute = v2 !is null ? v2 : v1;
  if (attribute is null || attribute.values.length == 0) return references;
  // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, policies OPTIONAL }
  auto certs = attribute.values[0].reader().next("los certificados del firmante").children();
  foreach (essCertId; certs) {
    auto reader = essCertId.reader();
    SigningCertificateReference reference;
    reference.digest = DigestAlgorithm.sha1;
    if (v2 !is null) {
      reference.digest = DigestAlgorithm.sha256;
      DerElement first = reader.next("el identificador del certificado");
      if (first.isSequence) {
        reference.digest = digestFromOid(parseAlgorithmIdentifier(first, "El resumen del certificado del firmante").oid);
        first = reader.next("el resumen del certificado");
      }
      reference.certificateHash = first.octetStringValue.idup;
    } else {
      reference.certificateHash = reader.next("el resumen del certificado").octetStringValue.idup;
    }
    DerElement issuerSerial;
    if (reader.nextUniversal(UniversalTag.sequence, issuerSerial)) {
      auto issuerReader = issuerSerial.reader();
      issuerReader.next("el emisor");
      reference.hasIssuerSerial = true;
      reference.issuerSerial = issuerReader.next("el serial").integerValue;
    }
    references ~= reference;
  }
  return references;
}

// ---------------------------------------------------------------------------------------
// Construcción

/// Atributo CMS DER con un solo valor.
ubyte[] cmsAttribute(string oid, const(ubyte)[] value) pure @safe {
  return derSequence(derOid(oid), derSet(value));
}

/// signing-certificate-v2 con el resumen SHA-256 del certificado (EN 319 122-1 §5.2.2.3).
ubyte[] signingCertificateV2Attribute(const Certificate certificate) @safe {
  // ESSCertIDv2 con SHA-256: el algoritmo es el valor por omisión y en DER se omite. El
  // issuerSerial se omite como recomienda la norma para el nivel baseline.
  auto essCertId = derSequence(derOctetString(certificate.digest(DigestAlgorithm.sha256)));
  auto signingCertificate = derSequence(derSequence(essCertId));
  return cmsAttribute(oidSigningCertificateV2, signingCertificate);
}

/// Datos de los atributos firmados de una firma CAdES/PAdES nivel B.
struct SignedAttributesInput {
  string contentType = oidData;
  const(ubyte)[] contentDigest;
  const(Certificate) signingCertificate;
  /// Se incluye signing-time (CAdES sí, PAdES no: la fecha va en /M del diccionario).
  bool includeSigningTime;
  SysTime signingTime;
  /// Atributos firmados adicionales ya codificados (política, rol…).
  const(ubyte[])[] extra;
}

/// Atributos firmados en DER como SET OF (lo que se firma).
ubyte[] buildSignedAttributes(const SignedAttributesInput input) @safe {
  ubyte[][] attributes = [
    cmsAttribute(oidContentType, derOid(input.contentType)),
    cmsAttribute(oidMessageDigest, derOctetString(input.contentDigest)),
    signingCertificateV2Attribute(input.signingCertificate),
  ];
  if (input.includeSigningTime) attributes ~= cmsAttribute(oidSigningTime, derUtcTime(input.signingTime));
  foreach (attribute; input.extra) attributes ~= attribute.dup;
  return derSetOf(attributes);
}

/// OID del algoritmo de firma de SignerInfo para la clave y el resumen.
string cmsSignatureAlgorithmOid(bool rsa, DigestAlgorithm digest) pure @safe {
  if (rsa) {
    switch (digest) {
      case DigestAlgorithm.sha1: return oidSha1WithRsa;
      case DigestAlgorithm.sha384: return oidSha384WithRsa;
      case DigestAlgorithm.sha512: return oidSha512WithRsa;
      default: return oidSha256WithRsa;
    }
  }
  switch (digest) {
    case DigestAlgorithm.sha1: return oidEcdsaWithSha1;
    case DigestAlgorithm.sha384: return oidEcdsaWithSha384;
    case DigestAlgorithm.sha512: return oidEcdsaWithSha512;
    default: return oidEcdsaWithSha256;
  }
}

/// Parámetros para ensamblar un SignedData de un firmante.
struct SignedDataInput {
  DigestAlgorithm digest = DigestAlgorithm.sha256;
  bool rsa = true;
  const(Certificate) signingCertificate;
  /// Certificados que se incluyen en el campo certificates (el firmante primero).
  const(Certificate)[] certificates;
  /// Atributos firmados como los devolvió buildSignedAttributes.
  const(ubyte)[] signedAttributes;
  const(ubyte)[] signature;
  /// Atributos no firmados ya codificados (sello de tiempo…).
  const(ubyte[])[] unsignedAttributes;
  /// Contenido encapsulado; null para una firma separada.
  const(ubyte)[] encapsulatedContent;
  string contentType = oidData;
  /// CRL y respuestas OCSP para el campo crls (nivel LT).
  const(ubyte[])[] crls;
  const(ubyte[])[] ocspResponses;
}

/// ContentInfo DER con el SignedData de un firmante.
ubyte[] buildSignedData(const SignedDataInput input) @safe {
  auto digestAlgorithm = derAlgorithm(digestOid(input.digest), false);
  auto issuerAndSerial = derSequence(input.signingCertificate.issuer.der, input.signingCertificate.serialNumberDer);
  auto signedAttributesImplicit = derRetag(input.signedAttributes, TagClass.contextSpecific, 0);
  ubyte[] signatureAlgorithm = input.rsa ? derAlgorithm(cmsSignatureAlgorithmOid(true, input.digest), true)
    : derAlgorithm(cmsSignatureAlgorithmOid(false, input.digest), false);
  ubyte[][] signerFields = [derInteger(1), issuerAndSerial, digestAlgorithm, signedAttributesImplicit,
    signatureAlgorithm, derOctetString(input.signature)];
  if (input.unsignedAttributes.length) {
    ubyte[][] unsigned;
    foreach (attribute; input.unsignedAttributes) unsigned ~= attribute.dup;
    signerFields ~= derRetag(derSetOf(unsigned), TagClass.contextSpecific, 1);
  }
  auto signerInfo = derSequence(signerFields);

  ubyte[] encapsulated = input.encapsulatedContent is null ? derSequence(derOid(input.contentType))
    : derSequence(derOid(input.contentType), derContextConstructed(0, derOctetString(input.encapsulatedContent)));
  ubyte[][] certificates;
  foreach (certificate; input.certificates) certificates ~= certificate.der.dup;
  ubyte[][] fields = [derInteger(1), derSetOf([digestAlgorithm]), encapsulated];
  if (certificates.length) fields ~= derRetag(derSetOf(certificates), TagClass.contextSpecific, 0);
  ubyte[][] revocations;
  foreach (crl; input.crls) revocations ~= crl.dup;
  foreach (ocsp; input.ocspResponses) {
    revocations ~= derContextConstructed(1, derOid(oidRevocationInfoOcsp), ocsp);
  }
  if (revocations.length) fields ~= derRetag(derSetOf(revocations), TagClass.contextSpecific, 1);
  fields ~= derSetOf([signerInfo]);
  return derSequence(derOid(oidSignedData), derContextConstructed(0, derSequence(fields)));
}

/**
 * Reescribe un SignedData añadiendo atributos no firmados al único firmante y, si se dan,
 * certificados y revocaciones (extensión a T, LT y LTA de una firma CAdES). Conserva los
 * atributos firmados y la firma tal cual.
 *
 * Throws: Asn1Exception si el SignedData no tiene exactamente un firmante.
 */
ubyte[] extendSignedData(const(ubyte)[] contentInfo, const(ubyte[])[] newUnsignedAttributes,
    const(ubyte[])[] newCertificates, const(ubyte[])[] newCrls, const(ubyte[])[] newOcspResponses) @safe {
  auto root = parseDer(contentInfo);
  auto rootChildren = root.children();
  auto signedDataElement = parseDer(rootChildren[1].content);
  auto fields = signedDataElement.children();
  DerElement[] prefix;
  DerElement certificatesField;
  bool hasCertificates;
  DerElement crlsField;
  bool hasCrls;
  DerElement signerInfosField;
  foreach (field; fields) {
    if (field.isContext(0)) {
      certificatesField = field;
      hasCertificates = true;
    } else if (field.isContext(1)) {
      crlsField = field;
      hasCrls = true;
    } else if (field.isSet && prefix.length >= 3) {
      signerInfosField = field;
    } else {
      prefix ~= field;
    }
  }
  auto signers = signerInfosField.children();
  enforce!Asn1Exception(signers.length == 1, format("Se esperaba un firmante y hay %d", signers.length));

  ubyte[][] certificates;
  if (hasCertificates) foreach (existing; parseDerSequenceContent(certificatesField.content)) certificates ~= existing.raw.dup;
  foreach (certificate; newCertificates) {
    bool present = false;
    foreach (existing; certificates) if (existing == certificate) present = true;
    if (!present) certificates ~= certificate.dup;
  }
  ubyte[][] revocations;
  if (hasCrls) foreach (existing; parseDerSequenceContent(crlsField.content)) revocations ~= existing.raw.dup;
  void addRevocation(ubyte[] encoded) {
    foreach (existing; revocations) if (existing == encoded) return;
    revocations ~= encoded;
  }
  foreach (crl; newCrls) addRevocation(crl.dup);
  foreach (ocsp; newOcspResponses) addRevocation(derContextConstructed(1, derOid(oidRevocationInfoOcsp), ocsp));

  auto signerFields = signers[0].children();
  ubyte[][] rebuiltSigner;
  ubyte[][] unsigned;
  foreach (field; signerFields) {
    if (field.isContext(1)) {
      foreach (attribute; parseDerSequenceContent(field.content)) unsigned ~= attribute.raw.dup;
    } else {
      rebuiltSigner ~= field.raw.dup;
    }
  }
  foreach (attribute; newUnsignedAttributes) unsigned ~= attribute.dup;
  if (unsigned.length) rebuiltSigner ~= derRetag(derSetOf(unsigned), TagClass.contextSpecific, 1);

  ubyte[][] rebuilt;
  foreach (field; prefix) rebuilt ~= field.raw.dup;
  if (certificates.length) rebuilt ~= derRetag(derSetOf(certificates), TagClass.contextSpecific, 0);
  if (revocations.length) rebuilt ~= derRetag(derSetOf(revocations), TagClass.contextSpecific, 1);
  rebuilt ~= derSet(derSequence(rebuiltSigner));
  return derSequence(rootChildren[0].raw.dup, derContextConstructed(0, derSequence(rebuilt)));
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity, verifySignature, signatureAlgorithmFrom;
}

@("should produce a signed data whose signer attributes verify with the signing key when building CAdES")
unittest {
  import std.datetime.systime : Clock;
  auto identity = makeTestIdentity("Firmante CMS", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  ubyte[] content = cast(ubyte[]) "contenido firmado".dup;
  SignedAttributesInput attributesInput = {
    contentDigest: digestOf(DigestAlgorithm.sha256, content),
    signingCertificate: certificate,
    includeSigningTime: true,
    signingTime: Clock.currTime,
  };
  auto signedAttributes = buildSignedAttributes(attributesInput);
  auto signature = identity.key.sign(DigestAlgorithm.sha256, signedAttributes);
  SignedDataInput input = {
    signingCertificate: certificate,
    certificates: [certificate],
    signedAttributes: signedAttributes,
    signature: signature,
  };
  auto parsed = parseSignedData(buildSignedData(input));
  assert(parsed.eContentType == oidData && !parsed.hasEContent);
  assert(parsed.certificates.length == 1 && parsed.signerInfos.length == 1);
  auto signer = parsed.signerInfos[0];
  assert(signer.identifies(certificate));
  assert(messageDigestOf(signer) == digestOf(DigestAlgorithm.sha256, content));
  auto references = signingCertificateReferences(signer);
  assert(references.length == 1 && references[0].certificateHash == certificate.digest(DigestAlgorithm.sha256));
  SysTime signingTime;
  assert(signingTimeOf(signer, signingTime));
  auto algorithm = signatureAlgorithmFrom(signer.signatureAlgorithmOid, null, signer.digestAlgorithm);
  assert(verifySignature(certificate.subjectPublicKeyInfoDer, algorithm, signer.signedAttributesForSignature,
    signer.signature));
}

@("should keep the signature intact and add attributes, certificates and revocations when extending")
unittest {
  auto identity = makeTestIdentity("Firmante CMS", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  SignedAttributesInput attributesInput = {
    contentDigest: new ubyte[32],
    signingCertificate: certificate,
  };
  auto signedAttributes = buildSignedAttributes(attributesInput);
  SignedDataInput input = {
    signingCertificate: certificate,
    certificates: [certificate],
    signedAttributes: signedAttributes,
    signature: [1, 2, 3],
  };
  auto original = buildSignedData(input);
  auto root = bundledCertificate!"certs/CA RAIZ NACIONAL - COSTA RICA v2.crt"();
  auto extended = extendSignedData(original, [cmsAttribute(oidSignatureTimeStampToken, derNull())],
    [root.der.dup, certificate.der.dup], [], [derSequence(derInteger(0))]);
  auto parsed = parseSignedData(extended);
  assert(parsed.certificates.length == 2);
  assert(parsed.ocspResponses.length == 1);
  auto signer = parsed.signerInfos[0];
  assert(signer.signature == [1, 2, 3]);
  assert(signer.signedAttributesRaw == parseSignedData(original).signerInfos[0].signedAttributesRaw);
  assert(signer.unsignedAttributesOf(oidSignatureTimeStampToken).length == 1);
}
