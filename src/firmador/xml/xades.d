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
 * Firmas XAdES (ETSI TS 101 903 v1.3.2 y 1.4.1) con la estructura que armaba DSS 6.4 en
 * la versión Java (FirmadorXAdES, en319132 = false): referencia al documento con la
 * transformación XPath not(ancestor-or-self::ds:Signature), SignedProperties con
 * SigningTime, SigningCertificate v1 y la política de Hacienda para comprobantes, y los
 * niveles T (SignatureTimeStamp), LT (CertificateValues y RevocationValues) y LTA
 * (xades141:ArchiveTimeStamp y TimeStampValidationData). La firma se arma en dos pasos:
 * prepareXadesSignature da lo que firma la tarjeta y completeXadesSignature pone el valor.
 */
module firmador.xml.xades;

import std.algorithm : canFind;
import std.array : appender;
import std.base64 : Base64;
import std.datetime.systime : SysTime;
import std.digest : LetterCase, toHexString;
import std.digest.md : md5Of;
import std.exception : enforce;
import std.format : format;
import std.logger : info;
import std.typecons : Nullable;

import firmador.cms.tsp : parseTimeStampToken, TimeStampToken, Timestamper;
import firmador.configuration : electronicReceiptTypes, haciendaPolicyDigestBase64, haciendaPolicyId;
import firmador.crypto.digest;
import firmador.crypto.openssl : RawSignatureEncoding, rawSignatureEncoding;
import firmador.util.datetime : toRfc3339Utc;
import firmador.util.base64 : encodeBase64;
import firmador.validation.certpath : missingFrom, ValidationData;
import firmador.validation.cmsverify : timestampSignerCertificate;
import firmador.validation.pool : CertificatePool;
import firmador.x509.certificate;
import firmador.xml.dom;
import firmador.xml.xmldsig;

/// Canonicalización de SignedInfo, SignedProperties y sellos (la predeterminada de DSS).
enum CanonicalizationMethod xadesCanonicalization = CanonicalizationMethod.exclusive;

/// Expresión de la transformación XPath que excluye las firmas del documento.
enum string envelopedXPath = "not(ancestor-or-self::ds:Signature)";

/// Espacio de nombres de las firmas de un contenedor ASiC (asic:XAdESSignatures).
enum string asicNamespace = "http://uri.etsi.org/02918/v1.2.1#";
/// Espacio de nombres de las firmas de un documento OpenDocument (document-signatures).
enum string openDocumentSignaturesNamespace = "urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0";

/// Política de firma explícita (SignaturePolicyId).
struct XadesPolicy {
  string identifier;
  DigestAlgorithm digest = DigestAlgorithm.sha256;
  immutable(ubyte)[] digestValue;
}

/// Política de Hacienda (configuration.haciendaPolicyId).
XadesPolicy haciendaPolicy() @safe {
  return XadesPolicy(haciendaPolicyId, DigestAlgorithm.sha256, Base64.decode(haciendaPolicyDigestBase64).idup);
}

/// El elemento raíz corresponde a un comprobante electrónico (configuration.electronicReceiptTypes).
bool isElectronicReceipt(string rootLocalName) pure nothrow @safe @nogc {
  foreach (name; electronicReceiptTypes) if (name == rootLocalName) return true;
  return false;
}

/// Empaquetado de la firma.
enum XadesPackaging {
  /// Dentro del documento XML firmado, como último hijo de su raíz.
  enveloped,
  /// En un documento aparte cuya referencia URI="" apunta al XML firmado (como la versión Java).
  detached,
  /// En el archivo de firmas de un contenedor, con una referencia por archivo (ASiC-E, OpenDocument).
  container,
}

/// Archivo de un contenedor que firma una firma de tipo container.
struct XadesFile {
  /// Ruta dentro del contenedor.
  string name;
  immutable(ubyte)[] content;
  string mimeType;
}

/// Lo que define una firma XAdES nueva.
struct XadesParameters {
  SysTime signingTime;
  Certificate signingCertificate;
  /// Certificados de ds:KeyInfo; el de firma si no se indican.
  Certificate[] keyInfoCertificates;
  bool rsa = true;
  XadesPackaging packaging = XadesPackaging.enveloped;
  /// Tipo MIME de xades:DataObjectFormat del documento firmado (enveloped y detached).
  string mimeType = "text/xml";
  /// Archivos firmados (container).
  XadesFile[] files;
  /// Elementos de EN 319 132 (SigningCertificateV2), como los contenedores ASiC de DSS.
  bool en319132;
  Nullable!XadesPolicy policy;
}

/// Firma preparada: el documento con ds:SignatureValue vacío y lo que se firma.
struct PreparedXades {
  immutable(ubyte)[] document;
  string signatureId;
  /// ds:SignedInfo canonicalizado.
  immutable(ubyte)[] dataToSign;
  RawSignatureEncoding signatureEncoding;
}

/**
 * Identificador de la firma como el de DSS (getDeterministicId): "id-" y el MD5 de la
 * fecha de firma en milisegundos y del identificador del certificado.
 */
string xadesDeterministicId(SysTime signingTime, const Certificate certificate) @safe {
  ubyte[] data;
  long milliseconds = (signingTime.toUnixTime!long) * 1000 + signingTime.fracSecs.total!"msecs";
  foreach_reverse (shift; 0 .. 8) data ~= cast(ubyte) (milliseconds >> (shift * 8));
  string tokenId = "C-" ~ toHexString!(LetterCase.upper)(certificate.digest(DigestAlgorithm.sha256)).idup;
  // DataOutputStream.writeChars: cada carácter en UTF-16 big endian.
  foreach (char character; tokenId) data ~= [cast(ubyte) 0, cast(ubyte) character];
  return "id-" ~ toHexString!(LetterCase.lower)(md5Of(data)).idup;
}

/**
 * URI de un archivo en una referencia, como DSSUtils.encodeURI (java.net.URI): se escapan
 * los caracteres ASCII que no pueden ir en una ruta; los no ASCII quedan igual.
 */
string encodeReferenceUri(string name) pure @safe {
  import std.ascii : isAlphaNum;
  auto output = appender!string;
  foreach (char character; name) {
    bool allowed = character >= 0x80 || isAlphaNum(character) || "-._~!$&'()*+,;=:@/".canFind(character);
    if (allowed) output ~= character;
    else output ~= format("%%%02X", cast(ubyte) character);
  }
  return output[];
}

/// Referencia de SignedInfo: su URI, si lleva la transformación XPath y el tipo MIME.
private struct ReferenceLine {
  string uri;
  bool envelopedTransform;
  string mimeType;
}

private ReferenceLine[] referenceLines(const XadesParameters parameters) @safe {
  if (parameters.packaging != XadesPackaging.container) return [ReferenceLine("", true, parameters.mimeType)];
  ReferenceLine[] lines;
  foreach (file; parameters.files) lines ~= ReferenceLine(encodeReferenceUri(file.name), false, file.mimeType);
  return lines;
}

/// Fragmento ds:Signature sin resúmenes ni valor, con sangría relativa de cuatro espacios.
private string signatureFragment(const XadesParameters parameters, string id) @safe {
  auto output = appender!string;
  void line(size_t depth, string text) {
    if (output[].length) output ~= "\n";
    foreach (_; 0 .. depth) output ~= "    ";
    output ~= text;
  }
  string sha256Uri = digestXmlUri(DigestAlgorithm.sha256);
  string c14n = canonicalizationUri(xadesCanonicalization);
  auto references = referenceLines(parameters);
  line(0, format(`<ds:Signature xmlns:ds="%s" Id="%s">`, xmldsigNamespace, id));
  line(1, `<ds:SignedInfo>`);
  line(2, format(`<ds:CanonicalizationMethod Algorithm="%s"/>`, c14n));
  line(2, format(`<ds:SignatureMethod Algorithm="%s"/>`, signatureMethodUri(parameters.rsa, DigestAlgorithm.sha256)));
  foreach (index, reference; references) {
    line(2, format(`<ds:Reference Id="r-%s-%d" URI="%s">`, id, index + 1, escapeXml(reference.uri)));
    if (reference.envelopedTransform) {
      line(3, `<ds:Transforms>`);
      line(4, format(`<ds:Transform Algorithm="%s">`, xpathTransformUri));
      line(5, format(`<ds:XPath>%s</ds:XPath>`, envelopedXPath));
      line(4, `</ds:Transform>`);
      line(3, `</ds:Transforms>`);
    }
    line(3, format(`<ds:DigestMethod Algorithm="%s"/>`, sha256Uri));
    line(3, `<ds:DigestValue></ds:DigestValue>`);
    line(2, `</ds:Reference>`);
  }
  line(2, format(`<ds:Reference Type="%s" URI="#xades-%s">`, signedPropertiesType, id));
  line(3, `<ds:Transforms>`);
  line(4, format(`<ds:Transform Algorithm="%s"/>`, c14n));
  line(3, `</ds:Transforms>`);
  line(3, format(`<ds:DigestMethod Algorithm="%s"/>`, sha256Uri));
  line(3, `<ds:DigestValue></ds:DigestValue>`);
  line(2, `</ds:Reference>`);
  line(1, `</ds:SignedInfo>`);
  line(1, format(`<ds:SignatureValue Id="value-%s"></ds:SignatureValue>`, id));
  line(1, `<ds:KeyInfo>`);
  line(2, `<ds:X509Data>`);
  auto keyInfo = parameters.keyInfoCertificates.length ? parameters.keyInfoCertificates
    : [cast(const Certificate) parameters.signingCertificate];
  foreach (certificate; keyInfo) line(3, format(`<ds:X509Certificate>%s</ds:X509Certificate>`, certificate.base64));
  line(2, `</ds:X509Data>`);
  line(1, `</ds:KeyInfo>`);
  line(1, `<ds:Object>`);
  line(2, format(`<xades:QualifyingProperties xmlns:xades="%s" Target="#%s">`, xadesNamespace, id));
  line(3, format(`<xades:SignedProperties Id="xades-%s">`, id));
  line(4, `<xades:SignedSignatureProperties>`);
  line(5, format(`<xades:SigningTime>%s</xades:SigningTime>`, toRfc3339Utc(cast(SysTime) parameters.signingTime)));
  line(5, parameters.en319132 ? `<xades:SigningCertificateV2>` : `<xades:SigningCertificate>`);
  line(6, `<xades:Cert>`);
  line(7, `<xades:CertDigest>`);
  line(8, format(`<ds:DigestMethod Algorithm="%s"/>`, sha256Uri));
  line(8, format(`<ds:DigestValue>%s</ds:DigestValue>`,
    encodeBase64(parameters.signingCertificate.digest(DigestAlgorithm.sha256))));
  line(7, `</xades:CertDigest>`);
  if (parameters.en319132) {
    line(7, format(`<xades:IssuerSerialV2>%s</xades:IssuerSerialV2>`, encodeBase64(issuerSerialDer(parameters.signingCertificate))));
  } else {
    line(7, `<xades:IssuerSerial>`);
    line(8, format(`<ds:X509IssuerName>%s</ds:X509IssuerName>`,
      escapeXml(parameters.signingCertificate.issuer.toRfc2253())));
    line(8, format(`<ds:X509SerialNumber>%s</ds:X509SerialNumber>`, parameters.signingCertificate.serialDecimal));
    line(7, `</xades:IssuerSerial>`);
  }
  line(6, `</xades:Cert>`);
  line(5, parameters.en319132 ? `</xades:SigningCertificateV2>` : `</xades:SigningCertificate>`);
  if (!parameters.policy.isNull) {
    auto policy = parameters.policy.get;
    line(5, `<xades:SignaturePolicyIdentifier>`);
    line(6, `<xades:SignaturePolicyId>`);
    line(7, `<xades:SigPolicyId>`);
    line(8, format(`<xades:Identifier>%s</xades:Identifier>`, escapeXml(policy.identifier)));
    line(7, `</xades:SigPolicyId>`);
    line(7, `<xades:SigPolicyHash>`);
    line(8, format(`<ds:DigestMethod Algorithm="%s"/>`, digestXmlUri(policy.digest)));
    line(8, format(`<ds:DigestValue>%s</ds:DigestValue>`, encodeBase64(policy.digestValue)));
    line(7, `</xades:SigPolicyHash>`);
    line(6, `</xades:SignaturePolicyId>`);
    line(5, `</xades:SignaturePolicyIdentifier>`);
  }
  line(4, `</xades:SignedSignatureProperties>`);
  line(4, `<xades:SignedDataObjectProperties>`);
  foreach (index, reference; references) {
    line(5, format(`<xades:DataObjectFormat ObjectReference="#r-%s-%d">`, id, index + 1));
    line(6, format(`<xades:MimeType>%s</xades:MimeType>`, escapeXml(reference.mimeType)));
    line(5, `</xades:DataObjectFormat>`);
  }
  line(4, `</xades:SignedDataObjectProperties>`);
  line(3, `</xades:SignedProperties>`);
  line(2, `</xades:QualifyingProperties>`);
  line(1, `</ds:Object>`);
  line(0, `</ds:Signature>`);
  return output[];
}

/**
 * Arma la firma sin su valor y devuelve el documento que la contiene con lo que hay que
 * firmar (ds:SignedInfo canonicalizado). `content` es, según el empaquetado, el XML
 * firmado (enveloped y detached) o el archivo de firmas existente del contenedor (null
 * para uno nuevo con la raíz `containerRoot`: asic:XAdESSignatures o document-signatures).
 *
 * Throws: XmlException si el contenido no es XML bien formado.
 */
PreparedXades prepareXadesSignature(immutable(ubyte)[] content, XadesParameters parameters,
    string containerRoot = null) @trusted {
  enforce!XmlException(parameters.signingCertificate !is null, "Falta el certificado de firma");
  enforce!XmlException(parameters.packaging != XadesPackaging.container || parameters.files.length,
    "Una firma de contenedor necesita archivos que firmar");
  PreparedXades prepared;
  prepared.signatureId = xadesDeterministicId(parameters.signingTime, parameters.signingCertificate);
  prepared.signatureEncoding = rawSignatureEncoding(parameters.rsa, parameters.signingCertificate);
  string fragment = signatureFragment(parameters, prepared.signatureId);

  XmlDocument signedXml;
  XmlDocument document;
  final switch (parameters.packaging) {
    case XadesPackaging.enveloped:
      signedXml = XmlDocument.parse(content);
      document = signedXml;
      document.appendFragment(document.root, fragment);
      break;
    case XadesPackaging.detached:
      signedXml = XmlDocument.parse(content);
      document = XmlDocument.parse(cast(const(ubyte)[]) fragment);
      break;
    case XadesPackaging.container:
      enforce!XmlException(content.length || containerRoot.length, "Falta la raíz del archivo de firmas");
      document = XmlDocument.parse(content.length ? content : cast(immutable(ubyte)[]) containerRoot);
      document.appendFragment(document.root, fragment);
      break;
  }
  scope (exit) {
    if (signedXml !is null) signedXml.close();
    if (document !is signedXml) document.close();
  }

  auto signature = parseDsSignature(document.elementById(prepared.signatureId));
  foreach (index, reference; signature.references[0 .. $ - 1]) {
    immutable(ubyte)[] octets = parameters.packaging == XadesPackaging.container ? parameters.files[index].content
      : processReference(signedXml, signature, reference, null);
    setDigestValue(reference.node, digestOf(DigestAlgorithm.sha256, octets));
  }
  auto propertiesReference = signature.references[$ - 1];
  auto propertiesOctets = processReference(document, signature, propertiesReference, null);
  setDigestValue(propertiesReference.node, digestOf(DigestAlgorithm.sha256, propertiesOctets));
  prepared.dataToSign = canonicalSignedInfo(document, signature);
  prepared.document = document.serialize();
  return prepared;
}

private void setDigestValue(XmlNode reference, const(ubyte)[] digest) @safe {
  auto value = reference.requiredChild(xmldsigNamespace, "DigestValue");
  value.appendText(encodeBase64(digest));
}

/**
 * Pone el valor de la firma (el que devolvió el dispositivo; en ECDSA, el DER) y devuelve
 * el documento firmado.
 *
 * Throws: XmlException si el documento preparado no contiene la firma.
 */
immutable(ubyte)[] completeXadesSignature(const PreparedXades prepared, const(ubyte)[] signatureValue) @trusted {
  auto document = XmlDocument.parse(prepared.document);
  scope (exit) document.close();
  auto valueElement = document.elementById("value-" ~ prepared.signatureId);
  enforce!XmlException(!valueElement.isNull, "El documento preparado no contiene la firma " ~ prepared.signatureId);
  valueElement.appendText(encodeBase64(prepared.signatureEncoding.encode(signatureValue)));
  return document.serialize();
}

/// Firma XAdES del documento con ese Id.
XmlNode signatureById(XmlDocument document, string signatureId) @safe {
  auto element = document.elementById(signatureId);
  enforce!XmlException(!element.isNull && element.isElement(xmldsigNamespace, "Signature"),
    format("El documento no contiene la firma %s", signatureId));
  return element;
}

/// Firmas XMLDSig del documento que no están dentro de otra firma, en orden de documento.
XmlNode[] topLevelSignatures(XmlDocument document) @safe {
  XmlNode[] result;
  foreach (signature; document.elements(xmldsigNamespace, "Signature")) {
    bool nested = false;
    for (auto parent = signature.parent; !parent.isNull; parent = parent.parent) {
      if (parent.isElement(xmldsigNamespace, "Signature")) nested = true;
    }
    if (!nested) result ~= signature;
  }
  return result;
}

/// xades:QualifyingProperties de la firma, o un nodo nulo si no es XAdES.
XmlNode qualifyingProperties(XmlNode signature) @safe {
  foreach (object; signature.childrenNamed(xmldsigNamespace, "Object")) {
    auto properties = object.child(xadesNamespace, "QualifyingProperties");
    if (!properties.isNull) return properties;
  }
  return XmlNode.init;
}

/// xades:UnsignedSignatureProperties de la firma, o un nodo nulo.
XmlNode unsignedSignatureProperties(XmlNode signature) @safe {
  auto properties = qualifyingProperties(signature);
  if (properties.isNull) return XmlNode.init;
  auto unsigned = properties.child(xadesNamespace, "UnsignedProperties");
  return unsigned.isNull ? XmlNode.init : unsigned.child(xadesNamespace, "UnsignedSignatureProperties");
}

private XmlNode ensureUnsignedSignatureProperties(XmlDocument document, XmlNode signature) @safe {
  auto existing = unsignedSignatureProperties(signature);
  if (!existing.isNull) return existing;
  auto properties = qualifyingProperties(signature);
  enforce!XmlException(!properties.isNull, "La firma no tiene QualifyingProperties: no es XAdES");
  auto unsigned = properties.child(xadesNamespace, "UnsignedProperties");
  if (unsigned.isNull) {
    unsigned = document.appendIndentedFragment(properties,
      format(`<xades:UnsignedProperties xmlns:xades="%s"></xades:UnsignedProperties>`, xadesNamespace));
  }
  return document.appendIndentedFragment(unsigned,
    format(`<xades:UnsignedSignatureProperties xmlns:xades="%s"></xades:UnsignedSignatureProperties>`, xadesNamespace));
}

/// Lo que sella un SignatureTimeStamp: ds:SignatureValue canonicalizado.
immutable(ubyte)[] signatureTimestampData(XmlDocument document, XmlNode signature,
    CanonicalizationMethod method = xadesCanonicalization) @safe {
  return document.canonicalize(signature.requiredChild(xmldsigNamespace, "SignatureValue"), method);
}

/**
 * Lo que sella un ArchiveTimeStamp de XAdES 1.4.1 (XAdESTimestampMessageDigestBuilder de
 * DSS): las referencias procesadas, SignedInfo, SignatureValue y KeyInfo, las propiedades
 * no firmadas anteriores a `until` (todas si es nulo) y los ds:Object sin las propiedades.
 *
 * Throws: XmlException si alguna referencia no se puede procesar.
 */
immutable(ubyte)[] archiveTimestampData(XmlDocument document, XmlNode signatureElement, XmlNode until,
    CanonicalizationMethod method, ExternalResolver resolver, XmlDocument emptyUriDocument = null) @trusted {
  auto signature = parseDsSignature(signatureElement);
  immutable(ubyte)[] data;
  foreach (reference; signature.references) {
    auto octets = processReference(document, signature, reference, resolver, emptyUriDocument);
    if (referenceOutputsNodeSet(reference)) {
      // Como Santuario: si lo referenciado es XML se vuelve a canonicalizar con el método del sello.
      try {
        auto parsed = XmlDocument.parse(octets);
        scope (exit) parsed.close();
        octets = parsed.canonicalizeDocumentExcluding(method, (element) => false);
      } catch (XmlException) {
        // No es XML: se sellan los bytes tal cual.
      }
    }
    data ~= octets;
  }
  data ~= document.canonicalize(cast(XmlNode) signature.signedInfo, method);
  data ~= document.canonicalize(cast(XmlNode) signature.signatureValueElement, method);
  if (!signature.keyInfo.isNull) data ~= document.canonicalize(cast(XmlNode) signature.keyInfo, method);
  auto unsigned = unsignedSignatureProperties(signatureElement);
  if (!unsigned.isNull) {
    foreach (property; unsigned.children()) {
      if (!until.isNull && property.node is until.node) break;
      data ~= document.canonicalize(property, method);
    }
  }
  foreach (object; signatureElement.childrenNamed(xmldsigNamespace, "Object")) {
    if (!object.child(xadesNamespace, "QualifyingProperties").isNull) continue;
    data ~= document.canonicalize(object, method);
  }
  return data;
}

private bool referenceOutputsNodeSet(const DsReference reference) pure @safe {
  bool nodeSet = reference.uri !is null && (reference.uri.length == 0 || reference.uri[0] == '#');
  foreach (transform; reference.transforms) {
    nodeSet = transform.algorithm == envelopedTransformUri || transform.algorithm == xpathTransformUri
      || transform.algorithm == xpathFilter2TransformUri;
  }
  return nodeSet;
}

private string timestampFragment(string elementName, string elementNamespace, const TimeStampToken token) @safe {
  string id = "ts-" ~ toHexString!(LetterCase.lower)(md5Of(token.der)).idup;
  string prefix = elementNamespace == xades141Namespace ? "xades141" : "xades";
  string xadesDeclaration = prefix == "xades" ? "" : format(` xmlns:xades="%s"`, xadesNamespace);
  return format(`<%s:%s xmlns:%s="%s" xmlns:ds="%s"%s Id="%s">`, prefix, elementName, prefix, elementNamespace,
      xmldsigNamespace, xadesDeclaration, id)
    ~ format("\n    <ds:CanonicalizationMethod Algorithm=\"%s\"/>", canonicalizationUri(xadesCanonicalization))
    ~ format("\n    <xades:EncapsulatedTimeStamp Id=\"e%s\">%s</xades:EncapsulatedTimeStamp>", id, encodeBase64(token.der))
    ~ format("\n</%s:%s>", prefix, elementName);
}

/**
 * Añade un xades:SignatureTimeStamp a la firma (nivel T).
 *
 * Throws: XmlException si la firma no está o no es XAdES; lo que lance el sellador.
 */
immutable(ubyte)[] addSignatureTimestamp(immutable(ubyte)[] xml, string signatureId, scope Timestamper stamp)
    @trusted {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  auto signature = signatureById(document, signatureId);
  auto token = stamp(digestOf(DigestAlgorithm.sha256, signatureTimestampData(document, signature)));
  auto unsigned = ensureUnsignedSignatureProperties(document, signature);
  document.appendIndentedFragment(unsigned, timestampFragment("SignatureTimeStamp", xadesNamespace, token));
  info("Sello de tiempo de firma añadido a ", signatureId);
  return document.serialize();
}

/**
 * Certificados y revocaciones que ya lleva la firma (KeyInfo, valores y
 * TimeStampValidationData); ignora los que no se pueden leer.
 */
ValidationData embeddedValidationData(XmlNode signatureElement) @trusted {
  ValidationData data;
  void addCertificate(string text) {
    try {
      data.addCertificate(parseCertificate(decodeXmlBase64(text)));
    } catch (Exception) {
      // Un valor ilegible no aporta a la validación.
    }
  }
  void addValues(XmlNode container) {
    foreach (values; container.childrenNamed(xadesNamespace, "CertificateValues")) {
      foreach (value; values.childrenNamed(xadesNamespace, "EncapsulatedX509Certificate")) addCertificate(value.text);
    }
    foreach (values; container.childrenNamed(xadesNamespace, "RevocationValues")) {
      foreach (crlValues; values.childrenNamed(xadesNamespace, "CRLValues")) {
        foreach (value; crlValues.childrenNamed(xadesNamespace, "EncapsulatedCRLValue")) {
          try data.crls ~= decodeXmlBase64(value.text); catch (Exception) {}
        }
      }
      foreach (ocspValues; values.childrenNamed(xadesNamespace, "OCSPValues")) {
        foreach (value; ocspValues.childrenNamed(xadesNamespace, "EncapsulatedOCSPValue")) {
          try data.ocspResponses ~= decodeXmlBase64(value.text); catch (Exception) {}
        }
      }
    }
  }
  auto keyInfo = signatureElement.child(xmldsigNamespace, "KeyInfo");
  if (!keyInfo.isNull) {
    foreach (x509Data; keyInfo.childrenNamed(xmldsigNamespace, "X509Data")) {
      foreach (certificate; x509Data.childrenNamed(xmldsigNamespace, "X509Certificate")) addCertificate(certificate.text);
    }
  }
  auto unsigned = unsignedSignatureProperties(signatureElement);
  if (!unsigned.isNull) {
    addValues(unsigned);
    foreach (validationData; unsigned.childrenNamed(xades141Namespace, "TimeStampValidationData")) addValues(validationData);
  }
  return data;
}

/// Sello de una propiedad XAdES y la canonicalización con que se sella lo que cubre.
struct XadesTimestamp {
  TimeStampToken token;
  CanonicalizationMethod method;
}

/**
 * Lee el sello de una propiedad XAdES (SignatureTimeStamp, ArchiveTimeStamp…): su
 * EncapsulatedTimeStamp y su CanonicalizationMethod (C14N 1.0 inclusiva si no lo trae).
 *
 * Throws: XmlException si falta el sello; Asn1Exception si no se puede leer.
 */
XadesTimestamp xadesTimestamp(XmlNode property) @safe {
  auto methodElement = property.child(xmldsigNamespace, "CanonicalizationMethod");
  auto method = methodElement.isNull ? CanonicalizationMethod.inclusive10
    : canonicalizationFromUri(methodElement.attribute("Algorithm"));
  auto token = parseTimeStampToken(decodeXmlBase64(property.requiredChild(xadesNamespace, "EncapsulatedTimeStamp").text));
  return XadesTimestamp(token, method);
}

/// Tokens de sello de la firma (de firma y de archivo), en orden de documento.
immutable(ubyte)[][] xadesTimestampTokens(XmlNode signatureElement) @trusted {
  immutable(ubyte)[][] tokens;
  auto unsigned = unsignedSignatureProperties(signatureElement);
  if (unsigned.isNull) return tokens;
  foreach (property; unsigned.children()) {
    bool stamp = property.isElement(xadesNamespace, "SignatureTimeStamp")
      || property.isElement(xades141Namespace, "ArchiveTimeStamp") || property.isElement(xadesNamespace, "ArchiveTimeStamp");
    if (!stamp) continue;
    auto encapsulated = property.child(xadesNamespace, "EncapsulatedTimeStamp");
    if (!encapsulated.isNull) tokens ~= decodeXmlBase64(encapsulated.text);
  }
  return tokens;
}

/// Referencia del certificado de firma en las propiedades firmadas (SigningCertificate o V2).
struct SigningCertificateReference {
  DigestAlgorithm digest;
  immutable(ubyte)[] digestValue;
  /// Número de serie de IssuerSerial (v1), vacío si no está.
  string serialDecimal;
  bool v2;
}

/// Referencias al certificado de firma, en orden; vacío si la firma no las tiene.
SigningCertificateReference[] signingCertificateReferences(XmlNode signatureElement) @trusted {
  SigningCertificateReference[] references;
  auto properties = qualifyingProperties(signatureElement);
  if (properties.isNull) return references;
  auto signedProperties = properties.child(xadesNamespace, "SignedProperties");
  if (signedProperties.isNull) return references;
  auto signatureProperties = signedProperties.child(xadesNamespace, "SignedSignatureProperties");
  if (signatureProperties.isNull) return references;
  foreach (name; ["SigningCertificate", "SigningCertificateV2"]) {
    foreach (container; signatureProperties.childrenNamed(xadesNamespace, name)) {
      foreach (cert; container.childrenNamed(xadesNamespace, "Cert")) {
        SigningCertificateReference reference;
        reference.v2 = name == "SigningCertificateV2";
        auto certDigest = cert.requiredChild(xadesNamespace, "CertDigest");
        reference.digest = digestFromXmlUri(certDigest.requiredChild(xmldsigNamespace, "DigestMethod").attribute("Algorithm"));
        reference.digestValue = decodeXmlBase64(certDigest.requiredChild(xmldsigNamespace, "DigestValue").text);
        import std.string : strip;
        auto issuerSerial = cert.child(xadesNamespace, "IssuerSerial");
        auto issuerSerialV2 = cert.child(xadesNamespace, "IssuerSerialV2");
        if (!issuerSerial.isNull) {
          reference.serialDecimal = issuerSerial.requiredChild(xmldsigNamespace, "X509SerialNumber").text.strip;
        } else if (!issuerSerialV2.isNull) {
          // IssuerSerial DER (RFC 5035): GeneralNames y el número de serie.
          import firmador.asn1.der : parseDer, toDecimalString;
          auto fields = parseDer(decodeXmlBase64(issuerSerialV2.text)).children();
          enforce!XmlException(fields.length >= 2, "IssuerSerialV2 mal formado");
          reference.serialDecimal = toDecimalString(fields[1].integerValue);
        }
        references ~= reference;
      }
    }
  }
  return references;
}

/// Primer certificado candidato cuyo resumen coincide con la primera referencia, o null.
Certificate matchSigningCertificate(const SigningCertificateReference[] references, const(Certificate)[] candidates)
    @trusted {
  if (references.length == 0) return null;
  foreach (candidate; candidates) {
    // Los certificados no se modifican después de leerlos.
    if (candidate.digest(references[0].digest) == references[0].digestValue) return cast(Certificate) candidate;
  }
  return null;
}

/**
 * Lo que necesita el nivel LT de la firma: en `certificates`, el de firma y los de las
 * autoridades de sellado (buscados también en `pool`); en las revocaciones, las que ya
 * incluye. Es lo que recibe SigningServices.validationData (firmador.signers.common).
 *
 * Throws: XmlException si la firma no identifica su certificado; Exception si el
 * certificado de la autoridad de un sello no está en el sello ni en `pool`.
 */
ValidationData xadesSigningMaterial(XmlNode signatureElement, CertificatePool pool) @trusted {
  auto embedded = embeddedValidationData(signatureElement);
  ValidationData material;
  material.ocspResponses = embedded.ocspResponses;
  material.crls = embedded.crls;
  auto signer = matchSigningCertificate(signingCertificateReferences(signatureElement), embedded.certificates);
  if (signer is null) {
    auto keyInfo = parseDsSignature(signatureElement).keyInfoCertificates;
    enforce!XmlException(keyInfo.length > 0, "La firma no incluye su certificado de firma");
    signer = keyInfo[0];
  }
  material.addCertificate(signer);
  foreach (der; xadesTimestampTokens(signatureElement)) {
    material.addCertificate(timestampSignerCertificate(parseTimeStampToken(der), pool));
  }
  return material;
}

/// La firma ya tiene un sello de archivo.
bool hasArchiveTimestamp(XmlNode signatureElement) @safe {
  auto unsigned = unsignedSignatureProperties(signatureElement);
  if (unsigned.isNull) return false;
  return !unsigned.child(xades141Namespace, "ArchiveTimeStamp").isNull
    || !unsigned.child(xadesNamespace, "ArchiveTimeStamp").isNull;
}

/// Bloques xades:CertificateValues y xades:RevocationValues (los que tengan algo), con sangría relativa.
private string[] valuesBlocks(const(Certificate)[] certificates, const(ubyte[])[] crls, const(ubyte[])[] ocsps) @safe {
  string[] blocks;
  if (certificates.length) {
    string block = format(`<xades:CertificateValues xmlns:xades="%s">`, xadesNamespace);
    foreach (certificate; certificates) {
      block ~= format("\n    <xades:EncapsulatedX509Certificate>%s</xades:EncapsulatedX509Certificate>", certificate.base64);
    }
    blocks ~= block ~ "\n</xades:CertificateValues>";
  }
  if (crls.length || ocsps.length) {
    string block = format(`<xades:RevocationValues xmlns:xades="%s">`, xadesNamespace);
    if (crls.length) {
      block ~= "\n    <xades:CRLValues>";
      foreach (crl; crls) block ~= format("\n        <xades:EncapsulatedCRLValue>%s</xades:EncapsulatedCRLValue>", encodeBase64(crl));
      block ~= "\n    </xades:CRLValues>";
    }
    if (ocsps.length) {
      block ~= "\n    <xades:OCSPValues>";
      foreach (ocsp; ocsps) {
        block ~= format("\n        <xades:EncapsulatedOCSPValue>%s</xades:EncapsulatedOCSPValue>", encodeBase64(ocsp));
      }
      block ~= "\n    </xades:OCSPValues>";
    }
    blocks ~= block ~ "\n</xades:RevocationValues>";
  }
  return blocks;
}

/**
 * Añade los datos de validación (nivel LT). Si la firma no tiene sello de archivo, se
 * reemplazan CertificateValues y RevocationValues por unos con todo lo que no esté en
 * KeyInfo; si ya lo tiene, lo nuevo va en un xades141:TimeStampValidationData, como DSS.
 *
 * Throws: XmlException si la firma no está o no es XAdES.
 */
immutable(ubyte)[] addXadesValidationData(immutable(ubyte)[] xml, string signatureId, const ValidationData data)
    @trusted {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  auto signature = signatureById(document, signatureId);
  auto unsigned = ensureUnsignedSignatureProperties(document, signature);
  bool archived = hasArchiveTimestamp(signature);
  // Los TimeStampValidationData del final se rehacen, como removeLastTimestampAndAnyValidationData.
  while (true) {
    auto children = unsigned.children();
    if (children.length == 0 || !children[$ - 1].isElement(xades141Namespace, "TimeStampValidationData")) break;
    document.removeIndented(children[$ - 1]);
  }
  if (!archived) {
    foreach (name; ["CertificateValues", "RevocationValues"]) {
      foreach (old; unsigned.childrenNamed(xadesNamespace, name)) document.removeIndented(old);
    }
  }
  auto missing = missingFrom(data, embeddedValidationData(signature));
  if (missing.empty) return document.serialize();
  auto blocks = valuesBlocks(missing.certificates, missing.crls, missing.ocspResponses);
  if (archived) {
    import std.array : replace;
    string id = "tsvd-" ~ toHexString!(LetterCase.lower)(md5Of(cast(const(ubyte)[]) xml)).idup;
    string wrapper = format(`<xades141:TimeStampValidationData xmlns:xades141="%s" Id="%s">`, xades141Namespace, id);
    foreach (block; blocks) wrapper ~= "\n    " ~ block.replace("\n", "\n    ");
    document.appendIndentedFragment(unsigned, wrapper ~ "\n</xades141:TimeStampValidationData>");
  } else {
    foreach (block; blocks) document.appendIndentedFragment(unsigned, block);
  }
  info("Datos de validación añadidos a ", signatureId);
  return document.serialize();
}

/**
 * Añade un xades141:ArchiveTimeStamp (nivel LTA) sobre todo lo que la firma ya tiene.
 *
 * Throws: XmlException si la firma no está, no es XAdES o sus referencias no se resuelven.
 */
immutable(ubyte)[] addArchiveTimestamp(immutable(ubyte)[] xml, string signatureId, scope Timestamper stamp,
    ExternalResolver resolver = null, immutable(ubyte)[] detachedContent = null) @trusted {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  XmlDocument detached = detachedContent.length ? XmlDocument.parse(detachedContent) : null;
  scope (exit) if (detached !is null) detached.close();
  auto signature = signatureById(document, signatureId);
  ensureUnsignedSignatureProperties(document, signature);
  auto data = archiveTimestampData(document, signature, XmlNode.init, xadesCanonicalization, resolver, detached);
  auto token = stamp(digestOf(DigestAlgorithm.sha256, data));
  document.appendIndentedFragment(unsignedSignatureProperties(signature),
    timestampFragment("ArchiveTimeStamp", xades141Namespace, token));
  info("Sello de archivo añadido a ", signatureId);
  return document.serialize();
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
  import std.datetime.date : DateTime;
  import std.datetime.timezone : UTC;
}

@("should build an enveloped XAdES whose references and signature verify with the signing certificate")
unittest {
  auto identity = makeTestIdentity("Firmante XAdES", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = cast(immutable(ubyte)[]) ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    ~ "<FacturaElectronica xmlns=\"https://cdn.comprobanteselectronicos.go.cr/xml-schemas/v4.3/facturaElectronica\">\n"
    ~ "  <Clave>506</Clave>\n</FacturaElectronica>\n");
  XadesParameters parameters;
  parameters.signingTime = SysTime(DateTime(2026, 9, 22, 15, 0, 0), UTC());
  parameters.signingCertificate = certificate;
  parameters.policy = haciendaPolicy();
  auto prepared = prepareXadesSignature(content, parameters);
  auto signed = completeXadesSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));

  auto document = XmlDocument.parse(signed);
  scope (exit) document.close();
  auto signatures = topLevelSignatures(document);
  assert(signatures.length == 1);
  auto signature = parseDsSignature(signatures[0]);
  assert(signature.id == prepared.signatureId);
  auto verification = verifyXmlSignature(document, signature, certificate, null);
  assert(verification.referencesValid && verification.signatureValid);
  string text = cast(string) signed;
  assert(text.canFind("<xades:SigningTime>2026-09-22T15:00:00Z</xades:SigningTime>"));
  assert(text.canFind(haciendaPolicyDigestBase64));
  assert(text.canFind("<xades:MimeType>text/xml</xades:MimeType>"));

  // Cambiar el contenido firmado rompe la referencia al documento.
  import std.array : replace;
  auto tampered = XmlDocument.parse(cast(const(ubyte)[]) text.replace("<Clave>506</Clave>", "<Clave>507</Clave>"));
  scope (exit) tampered.close();
  auto broken = verifyXmlSignature(tampered, parseDsSignature(topLevelSignatures(tampered)[0]), certificate, null);
  assert(!broken.referencesValid && broken.signatureValid);
}

@("should give the same deterministic id for the same signing time and certificate")
unittest {
  auto certificate = parseCertificate(makeTestIdentity("Id determinista", "x").certificateDer);
  auto time = SysTime(DateTime(2026, 1, 2, 3, 4, 5), UTC());
  string id = xadesDeterministicId(time, certificate);
  assert(id.length == 35 && id[0 .. 3] == "id-");
  assert(id == xadesDeterministicId(time, certificate));
  assert(id != xadesDeterministicId(time + 1.seconds, certificate));
}

version (unittest) import core.time : seconds;
