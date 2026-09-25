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
 * Certificados X.509 (RFC 5280): lectura de DER y PEM y de las extensiones que usan la
 * firma y la validación (uso de clave, restricciones básicas, usos extendidos, AIA,
 * puntos de distribución de CRL, identificadores de clave). La verificación
 * criptográfica de la firma de un certificado está en firmador.crypto.openssl.
 */
module firmador.x509.certificate;

import std.algorithm : canFind, startsWith;
import std.array : appender, replace;
import std.base64 : Base64;
import std.bigint : BigInt;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;
import std.string : indexOf, strip;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.crypto.digest : DigestAlgorithm, digestOf;
import firmador.util.base64 : encodeBase64;
import firmador.x509.name;

/// Extensión tal como viene en el certificado.
struct Extension {
  string oid;
  bool critical;
  immutable(ubyte)[] value;
}

/// Certificado X.509 ya interpretado. Dos certificados son el mismo si su DER es idéntico.
final class Certificate {
  immutable(ubyte)[] der;
  immutable(ubyte)[] tbsDer;
  int version_;
  BigInt serialNumber;
  immutable(ubyte)[] serialNumberDer;
  AlgorithmIdentifier signatureAlgorithm;
  immutable(ubyte)[] signatureValue;
  DistinguishedName issuer;
  DistinguishedName subject;
  SysTime notBefore;
  SysTime notAfter;
  immutable(ubyte)[] subjectPublicKeyInfoDer;
  string publicKeyAlgorithmOid;
  immutable(ubyte)[] publicKeyBits;
  Extension[] extensions;

  /// Bits de KeyUsage completados hasta 9 (como X509Certificate.getKeyUsage); null si no tiene la extensión.
  bool[] keyUsage;
  /// Es una CA según BasicConstraints.
  bool isCa;
  /// Longitud máxima de ruta de BasicConstraints, o -1 si no se limita.
  int pathLengthConstraint = -1;
  string[] extendedKeyUsages;
  string[] ocspUrls;
  string[] caIssuersUrls;
  string[] crlUrls;
  immutable(ubyte)[] subjectKeyIdentifier;
  immutable(ubyte)[] authorityKeyIdentifier;
  string[] policyOids;
  /// Tiene id-pkix-ocsp-nocheck: la respuesta OCSP de su emisor no se revisa a su vez.
  bool ocspNoCheck;
  /// Extensiones críticas que la aplicación no interpreta.
  string[] unknownCriticalExtensions;

  override bool opEquals(Object other) const pure @safe {
    auto certificate = cast(const Certificate) other;
    return certificate !is null && certificate.der == der;
  }

  override size_t toHash() const pure nothrow @trusted {
    return hashOf(der);
  }

  /// Serial en decimal (BigInteger.toString() en Java), como lo publica la API remota.
  string serialDecimal() const pure @safe {
    return toDecimalString(serialNumber);
  }

  /// Serial en hexadecimal sin ceros a la izquierda (BigInteger.toString(16)).
  string serialHex() const pure @safe {
    return toHexString(serialNumber);
  }

  /// Tiene el bit de KeyUsage indicado.
  bool hasKeyUsage(KeyUsageBit bit) const pure nothrow @safe @nogc {
    return keyUsage !is null && keyUsage[bit];
  }

  /// Es autofirmado (emisor y sujeto iguales).
  bool isSelfIssued() const pure @safe {
    return issuer.matches(subject);
  }

  /// Vigente en el instante dado.
  bool isValidAt(SysTime time) const pure @safe {
    return time >= notBefore && time <= notAfter;
  }

  /// Resumen del DER completo con el algoritmo pedido.
  ubyte[] digest(DigestAlgorithm algorithm) const pure @safe {
    return digestOf(algorithm, der);
  }

  /// DER en base64, como getB464Certificate de la versión Java.
  string base64() const pure @safe {
    return Base64.encode(der);
  }

  /// Nombre legible del titular para mensajes.
  override string toString() const pure @safe {
    return format("%s (serial %s)", subject.readableName, serialHex);
  }
}

/**
 * IssuerSerial DER (RFC 5035): el emisor como GeneralNames y el número de serie. Es el
 * IssuerSerialV2 de XAdES y el kid de JAdES.
 */
ubyte[] issuerSerialDer(const Certificate certificate) pure @safe {
  return derSequence(derSequence(derContextConstructed(4, certificate.issuer.der)), certificate.serialNumberDer);
}

/// Mismo certificado (mismo DER); sirve también con referencias const, donde == no es @safe.
bool sameCertificate(const Certificate first, const Certificate second) pure nothrow @safe @nogc {
  if (first is second) return true;
  return first !is null && second !is null && first.der == second.der;
}

/**
 * Certificado para firmar: de entidad final, con firma digital y no repudio (el filtro de
 * las credenciales que se ofrecen y de los firmantes que se informan en OOXML).
 */
bool isSigningCertificate(const Certificate certificate) pure nothrow @safe @nogc {
  return !certificate.isCa && certificate.hasKeyUsage(KeyUsageBit.digitalSignature)
    && certificate.hasKeyUsage(KeyUsageBit.nonRepudiation);
}

/// La lista contiene el certificado.
bool containsCertificate(const(Certificate)[] list, const Certificate certificate) pure nothrow @safe @nogc {
  foreach (candidate; list) if (sameCertificate(candidate, certificate)) return true;
  return false;
}

/**
 * Interpreta un certificado DER.
 *
 * Throws: Asn1Exception con el campo que falla si la estructura no es la de RFC 5280.
 */
Certificate parseCertificate(const(ubyte)[] der) pure @safe {
  auto root = parseDer(der);
  enforce!Asn1Exception(root.isSequence, "El certificado no es un SEQUENCE");
  auto certificateReader = root.reader();
  auto tbs = certificateReader.next("TBSCertificate");
  auto signatureAlgorithm = certificateReader.next("el algoritmo de firma del certificado");
  auto signatureValue = certificateReader.next("la firma del certificado");
  certificateReader.finish("el certificado");

  auto certificate = new Certificate;
  certificate.der = der.idup;
  certificate.tbsDer = tbs.raw.idup;
  certificate.signatureAlgorithm = parseAlgorithmIdentifier(signatureAlgorithm, "El algoritmo de firma del certificado");
  certificate.signatureValue = signatureValue.bitStringBytes.idup;

  auto reader = tbs.reader();
  DerElement versionElement;
  certificate.version_ = 1;
  if (reader.nextContext(0, versionElement)) {
    certificate.version_ = cast(int) parseDer(versionElement.content).smallIntegerValue + 1;
  }
  auto serial = reader.next("el serial");
  certificate.serialNumber = serial.integerValue;
  certificate.serialNumberDer = serial.raw.idup;
  reader.next("el algoritmo de firma de TBSCertificate");
  certificate.issuer = parseName(reader.next("el emisor"));
  auto validity = reader.next("la vigencia").reader();
  certificate.notBefore = validity.next("el inicio de vigencia").timeValue;
  certificate.notAfter = validity.next("el fin de vigencia").timeValue;
  certificate.subject = parseName(reader.next("el titular"));
  auto spki = reader.next("la clave pública");
  certificate.subjectPublicKeyInfoDer = spki.raw.idup;
  auto spkiReader = spki.reader();
  certificate.publicKeyAlgorithmOid = parseAlgorithmIdentifier(spkiReader.next("el algoritmo de la clave"),
    "El algoritmo de la clave pública").oid;
  certificate.publicKeyBits = spkiReader.next("los bits de la clave").bitStringBytes.idup;
  DerElement ignored;
  reader.nextContext(1, ignored);
  reader.nextContext(2, ignored);
  DerElement extensionsElement;
  if (reader.nextContext(3, extensionsElement)) {
    auto list = parseDer(extensionsElement.content);
    foreach (extensionElement; list.children()) {
      auto extensionReader = extensionElement.reader();
      Extension extension;
      extension.oid = extensionReader.next("el tipo de extensión").oidValue;
      DerElement criticalElement;
      if (extensionReader.nextUniversal(UniversalTag.boolean, criticalElement)) {
        extension.critical = criticalElement.booleanValue;
      }
      extension.value = extensionReader.next("el valor de la extensión").octetStringValue.idup;
      extensionReader.finish("la extensión");
      certificate.extensions ~= extension;
      applyExtension(certificate, extension);
    }
  }
  reader.finish("TBSCertificate");
  return certificate;
}

private void applyExtension(Certificate certificate, const Extension extension) pure @safe {
  auto value = parseDer(extension.value);
  switch (extension.oid) {
    case oidKeyUsage:
      bool[] bits = value.bitStringBits;
      while (bits.length < 9) bits ~= false;
      certificate.keyUsage = bits;
      break;
    case oidBasicConstraints:
      auto reader = value.reader();
      DerElement element;
      if (reader.nextUniversal(UniversalTag.boolean, element)) certificate.isCa = element.booleanValue;
      if (reader.nextUniversal(UniversalTag.integer, element)) certificate.pathLengthConstraint = cast(int) element.smallIntegerValue;
      break;
    case oidExtendedKeyUsage:
      foreach (purpose; value.children()) certificate.extendedKeyUsages ~= purpose.oidValue;
      break;
    case oidAuthorityInfoAccess:
      foreach (description; value.children()) {
        auto reader = description.reader();
        string method = reader.next("el método de acceso").oidValue;
        auto location = reader.next("la ubicación de acceso");
        if (!location.isContext(6)) break;
        string url = cast(string) location.content.idup;
        if (method == oidAccessOcsp) certificate.ocspUrls ~= url;
        else if (method == oidAccessCaIssuers) certificate.caIssuersUrls ~= url;
      }
      break;
    case oidCrlDistributionPoints:
      foreach (point; value.children()) {
        DerElement pointName;
        auto reader = point.reader();
        if (!reader.nextContext(0, pointName)) continue;
        foreach (choice; parseDerSequenceContent(pointName.content)) {
          if (!choice.isContext(0)) continue;
          foreach (generalName; parseDerSequenceContent(choice.content)) {
            if (generalName.isContext(6)) certificate.crlUrls ~= cast(string) generalName.content.idup;
          }
        }
      }
      break;
    case oidSubjectKeyIdentifier:
      certificate.subjectKeyIdentifier = value.octetStringValue.idup;
      break;
    case oidAuthorityKeyIdentifier:
      foreach (field; value.children()) {
        if (field.isContext(0)) certificate.authorityKeyIdentifier = field.content.idup;
      }
      break;
    case oidCertificatePolicies:
      foreach (policy; value.children()) {
        certificate.policyOids ~= policy.reader().next("el identificador de la política del certificado").oidValue;
      }
      break;
    case oidOcspNoCheck:
      certificate.ocspNoCheck = true;
      break;
    case oidSubjectAltName, oidCrlNumber, oidFreshestCrl:
      break;
    default:
      if (extension.critical) certificate.unknownCriticalExtensions ~= extension.oid;
      break;
  }
}

/**
 * Lee todos los certificados de un archivo DER o PEM (con o sin texto alrededor de los
 * bloques, como los de resources/certs).
 *
 * Throws: Exception si no hay ningún certificado o alguno está mal codificado.
 */
Certificate[] parseCertificates(const(ubyte)[] data) pure @safe {
  enum string beginMarker = "-----BEGIN CERTIFICATE-----";
  enum string endMarker = "-----END CERTIFICATE-----";
  string text = cast(string) data.idup;
  if (text.indexOf(beginMarker) < 0) return [parseCertificate(data)];
  Certificate[] certificates;
  size_t position = 0;
  while (true) {
    auto start = text[position .. $].indexOf(beginMarker);
    if (start < 0) break;
    size_t bodyStart = position + start + beginMarker.length;
    auto end = text[bodyStart .. $].indexOf(endMarker);
    enforce(end >= 0, "Bloque PEM de certificado sin cierre");
    string body = text[bodyStart .. bodyStart + end].replace("\r", "").replace("\n", "").replace(" ", "").strip;
    certificates ~= parseCertificate(Base64.decode(body));
    position = bodyStart + end + endMarker.length;
  }
  enforce(certificates.length > 0, "El archivo no contiene certificados");
  return certificates;
}

/// Certificado DER en PEM, con líneas de 64 caracteres (lo que espera libcurl como raíz TLS).
string certificatePem(const(ubyte)[] der) pure @safe {
  string encoded = encodeBase64(der);
  string pem = "-----BEGIN CERTIFICATE-----\n";
  for (size_t start = 0; start < encoded.length; start += 64) {
    pem ~= encoded[start .. start + 64 > encoded.length ? encoded.length : start + 64] ~ "\n";
  }
  return pem ~ "-----END CERTIFICATE-----\n";
}

/// Certificado incluido en el ejecutable (resources/certs), leído una sola vez.
Certificate bundledCertificate(string resource)() @trusted {
  static Certificate cached;
  if (cached is null) cached = parseCertificates(cast(const(ubyte)[]) import(resource))[0];
  return cached;
}

/// Certificados incluidos en el ejecutable para una lista de recursos conocida en compilación.
Certificate[] bundledCertificates(alias resources)() @safe {
  Certificate[] certificates;
  static foreach (resource; resources) certificates ~= bundledCertificate!resource();
  return certificates;
}

version (unittest) {
  import std.string : lineSplitter;
  import firmador.configuration : trustedRootCertificates, adjunctCertificates;
}

@("should round-trip a bundled certificate when encoding it as PEM")
unittest {
  auto root = bundledCertificate!"certs/CA RAIZ NACIONAL - COSTA RICA v2.crt"();
  string pem = certificatePem(root.der);
  assert(pem.lineSplitter.front == "-----BEGIN CERTIFICATE-----");
  foreach (line; pem.lineSplitter) assert(line.length <= 64);
  assert(parseCertificates(cast(const(ubyte)[]) pem)[0].der == root.der);
}

@("should read every bundled certificate of the national hierarchy")
unittest {
  auto roots = bundledCertificates!trustedRootCertificates();
  assert(roots.length == 2);
  foreach (root; roots) {
    assert(root.isCa && root.isSelfIssued);
    assert(root.hasKeyUsage(KeyUsageBit.keyCertSign));
    assert(root.subject.readableName.canFind("CA RAIZ NACIONAL"));
  }
  auto adjunct = bundledCertificates!adjunctCertificates();
  assert(adjunct.length == adjunctCertificates.length);
  foreach (certificate; adjunct) {
    assert(certificate.version_ == 3);
    assert(certificate.issuer.readableName.length > 0);
  }
}

@("should expose the time stamping purpose and CRL locations of the TSA certificate")
unittest {
  auto tsa = bundledCertificate!"certs/TSA SINPE v4.crt"();
  assert(!tsa.isCa);
  assert(tsa.extendedKeyUsages.canFind(oidEkuTimeStamping));
  assert(tsa.crlUrls.length > 0 || tsa.ocspUrls.length > 0);
  assert(tsa.authorityKeyIdentifier.length > 0);
}
