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
 * Firmas de paquetes OOXML (docx, xlsx, pptx) con la estructura de Apache POI 5.5 y las
 * facetas que usaba FirmadorOpenXmlFormat: manifiesto de las partes firmadas por sus
 * relaciones (OOXMLSignatureFacet), SignatureInfoV1 de Office, referencia enveloped,
 * XAdES 1.3.2 con SigningCertificate, política implícita y compromiso (XAdESSignatureFacet),
 * propiedades no firmadas vacías (Office2010SignatureFacet) y el nivel XAdES-X-L con sellos
 * y valores de validación (XAdESXLSignatureFacet). También añade las partes de firma al
 * paquete (origin.sigs y _xmlsignatures/sigN.xml).
 */
module firmador.ooxml.signature;

import std.algorithm : canFind, endsWith, filter, sort;
import std.array : appender, array, replace;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;
import std.regex : ctRegex, replaceFirst;
import std.string : lastIndexOf;

import firmador.asn1.der : toDecimalString;
import firmador.cms.ocsp : parseOcspResponse;
import firmador.cms.tsp : TimeStampToken, Timestamper;
import firmador.configuration : ooxmlSignatureDescription;
import firmador.crypto.digest;
import firmador.crypto.openssl : RawSignatureEncoding, rawSignatureEncoding;
import firmador.ooxml.opc;
import firmador.util.base64 : encodeBase64;
import firmador.util.datetime : toRfc3339Utc;
import firmador.validation.certpath : ValidationData;
import firmador.util.zip;
import firmador.x509.certificate;
import firmador.x509.crl : parseCrl;
import firmador.xml.dom;
import firmador.xml.xmldsig;

/// Espacio de nombres de las propiedades de firma de OPC (mdssi).
enum string mdssiNamespace = opcDigitalSignatureNamespace;
/// Espacio de nombres de SignatureInfoV1 de Office.
enum string officeSignatureNamespace = "http://schemas.microsoft.com/office/2006/digsig";
/// Id de la firma en la parte (SignatureConfig.packageSignatureId de POI).
enum string packageSignatureId = "idPackageSignature";
/// Compromiso que POI declara por omisión (SignatureConfig.commitmentType).
enum string defaultCommitmentType = "Created and approved this document";
/// Canonicalización de SignedInfo y de las referencias a objetos (inclusiva, como POI).
enum CanonicalizationMethod ooxmlCanonicalization = CanonicalizationMethod.inclusive10;
/// Canonicalización de los sellos XAdES (exclusiva, como POI).
enum CanonicalizationMethod ooxmlTimestampCanonicalization = CanonicalizationMethod.exclusive;

/// Tipos de relación cuyas partes se firman (OOXMLSignatureFacet.signed de POI).
private immutable string[] signedRelationshipTypes = [
  "activeXControlBinary", "aFChunk", "attachedTemplate", "attachedToolbars", "audio", "calcChain", "chart",
  "chartColorStyle", "chartLayout", "chartsheet", "chartStyle", "chartUserShapes", "classificationlabels",
  "commentAuthors", "comments", "connections", "connectorXml", "control", "ctrlProp", "customData", "customProperty",
  "customXml", "diagram", "diagramColors", "diagramColorsHeader", "diagramData", "diagramDrawing", "diagramLayout",
  "diagramLayoutHeader", "diagramQuickStyle", "diagramQuickStyleHeader", "dialogsheet", "dictionary", "documentParts",
  "downRev", "drawing", "endnotes", "externalLink", "externalLinkPath", "font", "fontTable", "footer", "footnotes",
  "functionPrototypes", "glossaryDocument", "graphicFrameDoc", "groupShapeXml", "handoutMaster", "hdphoto", "header",
  "hyperlink", "image", "ink", "inkXml", "keyMapCustomizations", "legacyDiagramText", "legacyDocTextInfo",
  "mailMergeHeaderSource", "mailMergeRecipientData", "mailMergeSource", "media", "notesMaster", "notesSlide",
  "numbering", "officeDocument", "oleObject", "package", "pictureXml", "pivotCacheDefinition", "pivotCacheRecords",
  "pivotTable", "powerPivotData", "presProps", "printerSettings", "queryTable", "recipientData", "settings", "shapeXml",
  "sharedStrings", "sheetMetadata", "slicer", "slicerCache", "slide", "slideLayout", "slideMaster", "slideUpdateInfo",
  "slideUpdateUrl", "smartTags", "styles", "stylesWithEffects", "table", "tableSingleCells", "tableStyles", "tags",
  "theme", "themeOverride", "timeline", "timelineCache", "transform", "ui/altText", "ui/buttonSize", "ui/controlID",
  "ui/description", "ui/enabled", "ui/extensibility", "ui/helperText", "ui/imageID", "ui/imageMso", "ui/keyTip",
  "ui/label", "ui/lcid", "ui/loud", "ui/pressed", "ui/progID", "ui/ribbonID", "ui/showImage", "ui/showLabel",
  "ui/supertip", "ui/target", "ui/text", "ui/title", "ui/tooltip", "ui/userCustomization", "ui/visible",
  "userXmlData", "vbaProject", "video", "viewProps", "vmlDrawing", "volatileDependencies", "webSettings", "wordVbaData",
  "worksheet", "wsSortMap", "xlBinaryIndex", "xlExternalLinkPath/xlAlternateStartup", "xlExternalLinkPath/xlLibrary",
  "xlExternalLinkPath/xlPathMissing", "xlExternalLinkPath/xlStartup", "xlIntlMacrosheet", "xlMacrosheet", "xmlMaps",
];

/// La relación apunta a una parte que se firma (isSignedRelationship de POI).
bool isSignedRelationship(string relationshipType) @safe {
  string shortType = relationshipType.replaceFirst(ctRegex!`.*/relationships/`, "");
  return signedRelationshipTypes.canFind(shortType) || shortType.endsWith("customXml");
}

/// Contenido de una parte *.rels como lo lee POI: sin saltos de línea (OOXMLURIDereferencer).
immutable(ubyte)[] relationshipsWithoutLineBreaks(immutable(ubyte)[] content) pure @safe {
  return content.filter!(character => character != '\n' && character != '\r').array.idup;
}

/// Referencia del manifiesto a una parte del paquete.
struct PackageReference {
  /// «/parte?ContentType=tipo».
  string uri;
  /// Relaciones elegidas (sólo en las partes *.rels, que llevan RelationshipTransform).
  string[] sourceIds;
  /// Resumen SHA-256 de la parte (o de sus relaciones elegidas).
  immutable(ubyte)[] digest;
}

/**
 * Referencias del manifiesto de una firma nueva (addManifestReferences de POI): cada
 * parte destino de una relación firmada, una vez, y cada parte de relaciones con las
 * relaciones firmadas o externas elegidas; ordenadas por URI.
 *
 * Throws: OpcException si falta [Content_Types].xml o una parte referenciada.
 */
PackageReference[] packageManifest(const ZipEntry[] entries) @safe {
  auto contentTypesXml = entryContent(entries, contentTypesName);
  enforce!OpcException(contentTypesXml !is null, "El paquete no tiene [Content_Types].xml");
  auto types = parseContentTypes(contentTypesXml);
  PackageReference[] references;
  string[] digestedParts;
  foreach (entry; entries) {
    string relsPart = partNameOf(entry.name);
    if (contentTypeOf(types, relsPart) != relationshipsContentType) continue;
    string source = relationshipsSource(relsPart);
    string[] sourceIds;
    foreach (relationship; parseRelationships(entry.content)) {
      // Los destinos externos no se firman, pero su relación sí.
      if (relationship.external) {
        sourceIds ~= relationship.id;
        continue;
      }
      if (!isSignedRelationship(relationship.type)) continue;
      sourceIds ~= relationship.id;
      string target = resolveTarget(source, relationship.target);
      if (digestedParts.canFind(target)) continue;
      digestedParts ~= target;
      auto content = partContent(entries, target);
      enforce!OpcException(content !is null, format("No se encontró la parte %s", target));
      string contentType = contentTypeOf(types, target);
      enforce!OpcException(contentType !is null, format("La parte %s no tiene tipo de contenido", target));
      if (relationship.type.endsWith("customXml") && contentType != "inkml+xml" && contentType != "text/xml") continue;
      references ~= PackageReference(target ~ "?ContentType=" ~ contentType, null, digestOf(DigestAlgorithm.sha256,
        content).idup);
    }
    if (sourceIds.length) {
      auto selected = selectRelationships(relationshipsWithoutLineBreaks(entry.content), sourceIds, null);
      references ~= PackageReference(relsPart ~ "?ContentType=" ~ relationshipsContentType, sourceIds,
        digestOf(DigestAlgorithm.sha256, selected).idup);
    }
  }
  references.sort!((a, b) => a.uri < b.uri);
  return references;
}

/// Lo que define una firma OOXML nueva.
struct OoxmlParameters {
  SysTime signingTime;
  Certificate signingCertificate;
  bool rsa = true;
  /// Texto de SignatureComments y del calificador del compromiso.
  string description = ooxmlSignatureDescription;
}

/// Firma preparada: la parte de firma sin valor y lo que se firma.
struct PreparedOoxml {
  immutable(ubyte)[] signatureXml;
  immutable(ubyte)[] dataToSign;
  RawSignatureEncoding signatureEncoding;
}

/// Nombre del emisor como el X500Principal.getName() con «, » de POI (setCertID).
private string poiIssuerName(const Certificate certificate) pure @safe {
  return certificate.issuer.toRfc2253().replace(",", ", ");
}

private string signatureFragment(const OoxmlParameters parameters, const PackageReference[] manifest) @safe {
  string sha256Uri = digestXmlUri(DigestAlgorithm.sha256);
  string digestMethod = format(`<DigestMethod Algorithm="%s"/>`, sha256Uri);
  string c14n = canonicalizationUri(ooxmlCanonicalization);
  auto output = appender!string;
  output ~= format(`<Signature xmlns="%s" Id="%s">`, xmldsigNamespace, packageSignatureId);
  output ~= `<SignedInfo>`;
  output ~= format(`<CanonicalizationMethod Algorithm="%s"/>`, c14n);
  output ~= format(`<SignatureMethod Algorithm="%s"/>`, signatureMethodUri(parameters.rsa, DigestAlgorithm.sha256));
  foreach (objectId; ["idPackageObject", "idOfficeObject"]) {
    output ~= format(`<Reference Type="%sObject" URI="#%s">%s<DigestValue></DigestValue></Reference>`, xmldsigNamespace,
      objectId, digestMethod);
  }
  output ~= format(`<Reference URI=""><Transforms><Transform Algorithm="%s"/><Transform Algorithm="%s"/></Transforms>`
    ~ `%s<DigestValue></DigestValue></Reference>`, envelopedTransformUri, canonicalizationUri(CanonicalizationMethod.exclusive),
    digestMethod);
  output ~= format(`<Reference Type="%s" URI="#idSignedProperties"><Transforms><Transform Algorithm="%s"/></Transforms>`
    ~ `%s<DigestValue></DigestValue></Reference>`, signedPropertiesType, c14n, digestMethod);
  output ~= `</SignedInfo>`;
  output ~= format(`<SignatureValue Id="%s-signature-value"></SignatureValue>`, packageSignatureId);
  output ~= format(`<KeyInfo><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>`,
    parameters.signingCertificate.base64);

  output ~= `<Object Id="idPackageObject"><Manifest>`;
  foreach (reference; manifest) {
    output ~= format(`<Reference URI="%s">`, escapeXml(reference.uri));
    if (reference.sourceIds.length) {
      output ~= format(`<Transforms><Transform Algorithm="%s">`, relationshipTransformUri);
      foreach (id; reference.sourceIds) {
        output ~= format(`<mdssi:RelationshipReference xmlns:mdssi="%s" SourceId="%s"/>`, mdssiNamespace, escapeXml(id));
      }
      output ~= format(`</Transform><Transform Algorithm="%s"/></Transforms>`, c14n);
    }
    output ~= format(`%s<DigestValue>%s</DigestValue></Reference>`, digestMethod, encodeBase64(reference.digest));
  }
  output ~= `</Manifest><SignatureProperties>`;
  output ~= format(`<SignatureProperty Id="idSignatureTime" Target="#%s"><mdssi:SignatureTime xmlns:mdssi="%s">`
    ~ `<mdssi:Format>YYYY-MM-DDThh:mm:ssTZD</mdssi:Format><mdssi:Value>%s</mdssi:Value></mdssi:SignatureTime>`
    ~ `</SignatureProperty>`, packageSignatureId, mdssiNamespace, toRfc3339Utc(cast(SysTime) parameters.signingTime));
  output ~= `</SignatureProperties></Object>`;

  output ~= `<Object Id="idOfficeObject"><SignatureProperties>`;
  output ~= format(`<SignatureProperty Id="idOfficeV1Details" Target="#%s"><SignatureInfoV1 xmlns="%s">`
    ~ `<SignatureComments>%s</SignatureComments><SignatureType>1</SignatureType>`
    ~ `<ManifestHashAlgorithm>%s</ManifestHashAlgorithm></SignatureInfoV1></SignatureProperty>`, packageSignatureId,
    officeSignatureNamespace, escapeXml(parameters.description), sha256Uri);
  output ~= `</SignatureProperties></Object>`;

  auto certificate = parameters.signingCertificate;
  output ~= format(`<Object><xd:QualifyingProperties xmlns:xd="%s" Target="#%s">`, xadesNamespace, packageSignatureId);
  output ~= `<xd:SignedProperties Id="idSignedProperties"><xd:SignedSignatureProperties>`;
  output ~= format(`<xd:SigningTime>%s</xd:SigningTime>`, toRfc3339Utc(cast(SysTime) parameters.signingTime));
  output ~= format(`<xd:SigningCertificate><xd:Cert><xd:CertDigest>%s<DigestValue>%s</DigestValue></xd:CertDigest>`
    ~ `<xd:IssuerSerial><X509IssuerName>%s</X509IssuerName><X509SerialNumber>%s</X509SerialNumber></xd:IssuerSerial>`
    ~ `</xd:Cert></xd:SigningCertificate>`, digestMethod, encodeBase64(certificate.digest(DigestAlgorithm.sha256)),
    escapeXml(poiIssuerName(certificate)), certificate.serialDecimal);
  output ~= `<xd:SignaturePolicyIdentifier><xd:SignaturePolicyImplied/></xd:SignaturePolicyIdentifier>`;
  output ~= `</xd:SignedSignatureProperties><xd:SignedDataObjectProperties><xd:CommitmentTypeIndication>`;
  output ~= format(`<xd:CommitmentTypeId><xd:Identifier>http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin</xd:Identifier>`
    ~ `<xd:Description>%s</xd:Description></xd:CommitmentTypeId><xd:AllSignedDataObjects/>`
    ~ `<xd:CommitmentTypeQualifiers><xd:CommitmentTypeQualifier>%s</xd:CommitmentTypeQualifier>`
    ~ `</xd:CommitmentTypeQualifiers>`, defaultCommitmentType, escapeXml(parameters.description));
  output ~= `</xd:CommitmentTypeIndication></xd:SignedDataObjectProperties></xd:SignedProperties>`;
  // Office2010SignatureFacet: propiedades no firmadas presentes aunque vacías.
  output ~= `<xd:UnsignedProperties><xd:UnsignedSignatureProperties/></xd:UnsignedProperties>`;
  output ~= `</xd:QualifyingProperties></Object>`;
  output ~= `</Signature>`;
  return output[];
}

/**
 * Arma la parte de firma del paquete sin el valor y devuelve lo que se firma
 * (SignedInfo canonicalizado).
 *
 * Throws: OpcException o XmlException si el paquete no se puede leer.
 */
PreparedOoxml prepareOoxmlSignature(const ZipEntry[] entries, const OoxmlParameters parameters) @trusted {
  enforce!OpcException(parameters.signingCertificate !is null, "Falta el certificado de firma");
  PreparedOoxml prepared;
  prepared.signatureEncoding = rawSignatureEncoding(parameters.rsa, parameters.signingCertificate);
  auto document = XmlDocument.parse(cast(const(ubyte)[]) signatureFragment(parameters, packageManifest(entries)));
  scope (exit) document.close();
  auto signature = parseDsSignature(document.root);
  foreach (reference; signature.references) {
    auto octets = processReference(document, signature, reference, null);
    reference.node.requiredChild(xmldsigNamespace, "DigestValue").appendText(encodeBase64(digestOf(DigestAlgorithm.sha256, octets)));
  }
  prepared.dataToSign = canonicalSignedInfo(document, signature);
  prepared.signatureXml = document.serialize();
  return prepared;
}

/// Parte de firma con el valor (el que dio el dispositivo; en ECDSA, el DER).
immutable(ubyte)[] completeOoxmlSignature(const PreparedOoxml prepared, const(ubyte)[] signatureValue) @trusted {
  auto document = XmlDocument.parse(prepared.signatureXml);
  scope (exit) document.close();
  document.root.requiredChild(xmldsigNamespace, "SignatureValue")
    .appendText(encodeBase64(prepared.signatureEncoding.encode(signatureValue)));
  return document.serialize();
}

private string certificateValues(const(Certificate)[] certificates) @safe {
  string values = `<xd:CertificateValues>`;
  foreach (certificate; certificates) {
    values ~= format(`<xd:EncapsulatedX509Certificate>%s</xd:EncapsulatedX509Certificate>`, certificate.base64);
  }
  return values ~ `</xd:CertificateValues>`;
}

private string revocationValues(const ValidationData data) @safe {
  string values = `<xd:RevocationValues>`;
  if (data.crls.length) {
    values ~= `<xd:CRLValues>`;
    foreach (crl; data.crls) values ~= format(`<xd:EncapsulatedCRLValue>%s</xd:EncapsulatedCRLValue>`, encodeBase64(crl));
    values ~= `</xd:CRLValues>`;
  }
  if (data.ocspResponses.length) {
    values ~= `<xd:OCSPValues>`;
    foreach (ocsp; data.ocspResponses) values ~= format(`<xd:EncapsulatedOCSPValue>%s</xd:EncapsulatedOCSPValue>`, encodeBase64(ocsp));
    values ~= `</xd:OCSPValues>`;
  }
  return values ~ `</xd:RevocationValues>`;
}

private string timestampElement(string name, const TimeStampToken token) @safe {
  return format(`<xd:%s><CanonicalizationMethod xmlns="%s" Algorithm="%s"/><xd:EncapsulatedTimeStamp>%s`
    ~ `</xd:EncapsulatedTimeStamp></xd:%s>`, name, xmldsigNamespace, canonicalizationUri(ooxmlTimestampCanonicalization),
    encodeBase64(token.der), name);
}

private string digestAlgAndValue(const(ubyte)[] data) @safe {
  return format(`<xd:DigestAlgAndValue><DigestMethod xmlns="%s" Algorithm="%s"/><DigestValue xmlns="%s">%s</DigestValue>`
    ~ `</xd:DigestAlgAndValue>`, xmldsigNamespace, digestXmlUri(DigestAlgorithm.sha256), xmldsigNamespace,
    encodeBase64(digestOf(DigestAlgorithm.sha256, data)));
}

/// CompleteRevocationRefs (addRevocationCRL y addRevocationOCSP de POI).
private string completeRevocationRefs(const ValidationData data) @safe {
  string refs = `<xd:CompleteRevocationRefs>`;
  if (data.crls.length) {
    refs ~= `<xd:CRLRefs>`;
    foreach (der; data.crls) {
      auto crl = parseCrl(der);
      string number = crl.number.isNull ? "" : format(`<xd:Number>%s</xd:Number>`, toDecimalString(crl.number.get));
      refs ~= format(`<xd:CRLRef>%s<xd:CRLIdentifier><xd:Issuer>%s</xd:Issuer><xd:IssueTime>%s</xd:IssueTime>%s`
        ~ `</xd:CRLIdentifier></xd:CRLRef>`, digestAlgAndValue(der), escapeXml(crl.issuer.toRfc2253().replace(",", ", ")),
        toRfc3339Utc(crl.thisUpdate), number);
    }
    refs ~= `</xd:CRLRefs>`;
  }
  if (data.ocspResponses.length) {
    refs ~= `<xd:OCSPRefs>`;
    foreach (der; data.ocspResponses) {
      auto ocsp = parseOcspResponse(der);
      string responder = ocsp.responderByKey ? format(`<xd:ByKey>%s</xd:ByKey>`, encodeBase64(ocsp.responderKeyHash))
        : format(`<xd:ByName>%s</xd:ByName>`, escapeXml(ocsp.responderName.toRfc2253()));
      refs ~= format(`<xd:OCSPRef><xd:OCSPIdentifier><xd:ResponderID>%s</xd:ResponderID><xd:ProducedAt>%s</xd:ProducedAt>`
        ~ `</xd:OCSPIdentifier>%s</xd:OCSPRef>`, responder, toRfc3339Utc(ocsp.producedAt), digestAlgAndValue(der));
    }
    refs ~= `</xd:OCSPRefs>`;
  }
  return refs ~ `</xd:CompleteRevocationRefs>`;
}

/// CompleteCertificateRefs de la cadena sin el firmante (setCertID sin invertir el emisor).
private string completeCertificateRefs(const(Certificate)[] chain) @safe {
  string refs = `<xd:CompleteCertificateRefs><xd:CertRefs>`;
  foreach (certificate; chain) {
    refs ~= format(`<xd:Cert><xd:CertDigest><DigestMethod xmlns="%s" Algorithm="%s"/><DigestValue xmlns="%s">%s`
      ~ `</DigestValue></xd:CertDigest><xd:IssuerSerial><X509IssuerName xmlns="%s">%s</X509IssuerName>`
      ~ `<X509SerialNumber xmlns="%s">%s</X509SerialNumber></xd:IssuerSerial></xd:Cert>`, xmldsigNamespace,
      digestXmlUri(DigestAlgorithm.sha256), xmldsigNamespace, encodeBase64(certificate.digest(DigestAlgorithm.sha256)),
      xmldsigNamespace, escapeXml(certificate.issuer.toDisplayString()), xmldsigNamespace, certificate.serialDecimal);
  }
  return refs ~ `</xd:CertRefs></xd:CompleteCertificateRefs>`;
}

/**
 * Añade las propiedades XAdES-X-L de POI: CertificateValues, SignatureTimeStamp (con los
 * datos de validación de su autoridad en TimeStampValidationData), las referencias
 * completas, RevocationValues y SigAndRefsTimeStamp. `signerData` y lo que devuelve
 * `timestampData` (RevocationData de POI) traen en `certificates` la cadena sin su primer
 * certificado (el firmante o la autoridad de sellado).
 *
 * Throws: XmlException si la parte no tiene la estructura esperada; lo que lancen los servicios.
 */
immutable(ubyte)[] addOoxmlXlProperties(immutable(ubyte)[] signatureXml, const ValidationData signerData,
    scope Timestamper stamp, scope ValidationData delegate(const TimeStampToken token) @safe timestampData)
    @trusted {
  auto document = XmlDocument.parse(signatureXml);
  scope (exit) document.close();
  auto unsigned = document.elements(xadesNamespace, "UnsignedSignatureProperties");
  enforce!XmlException(unsigned.length == 1, "La firma OOXML no tiene UnsignedSignatureProperties");
  auto properties = unsigned[0];
  auto signatureValue = document.root.requiredChild(xmldsigNamespace, "SignatureValue");
  string declaration = format(` xmlns:xd="%s"`, xadesNamespace);
  string withNamespace(string fragment) {
    // El prefijo xd se declara en cada fragmento para leerlo suelto; al insertarlo se quita.
    auto close = fragment.indexOfFirstTagEnd();
    return fragment[0 .. close] ~ declaration ~ fragment[close .. $];
  }
  if (signerData.certificates.length) document.appendFragment(properties, withNamespace(certificateValues(signerData.certificates)));

  auto signatureTimestamp = stamp(digestOf(DigestAlgorithm.sha256,
    document.canonicalize(signatureValue, ooxmlTimestampCanonicalization)));
  auto signatureTimestampElement = document.appendFragment(properties,
    withNamespace(timestampElement("SignatureTimeStamp", signatureTimestamp)));
  auto tsaData = timestampData(signatureTimestamp);
  if (tsaData.crls.length || tsaData.ocspResponses.length) {
    string validation = format(`<TimeStampValidationData xmlns="%s">`, xades141Namespace);
    if (tsaData.certificates.length) validation ~= withNamespace(certificateValues(tsaData.certificates));
    validation ~= withNamespace(revocationValues(tsaData)) ~ `</TimeStampValidationData>`;
    document.appendFragment(properties, validation);
  }
  auto certificateRefs = document.appendFragment(properties,
    withNamespace(completeCertificateRefs(signerData.certificates)));
  auto revocationRefs = document.appendFragment(properties, withNamespace(completeRevocationRefs(signerData)));
  document.appendFragment(properties, withNamespace(revocationValues(signerData)));
  immutable(ubyte)[] stamped;
  foreach (element; [signatureValue, signatureTimestampElement, certificateRefs, revocationRefs]) {
    stamped ~= document.canonicalize(element, ooxmlTimestampCanonicalization);
  }
  auto referencesTimestamp = stamp(digestOf(DigestAlgorithm.sha256, stamped));
  document.appendFragment(properties, withNamespace(timestampElement("SigAndRefsTimeStamp", referencesTimestamp)));
  return document.serialize();
}

/// Posición del final de la etiqueta de apertura del elemento raíz de un fragmento.
private size_t indexOfFirstTagEnd(string fragment) pure @safe {
  foreach (index, char character; fragment) {
    if (character == '>') return index > 0 && fragment[index - 1] == '/' ? index - 1 : index;
  }
  throw new XmlException("Fragmento XML sin etiqueta de apertura");
}

private string nextRelationshipId(const OpcRelationship[] relationships) @safe {
  int number = 1;
  while (relationships.canFind!(relationship => relationship.id == format("rId%d", number))) number++;
  return format("rId%d", number);
}

private immutable(ubyte)[] appendRelationship(immutable(ubyte)[] relsXml, string id, string type, string target) @trusted {
  auto document = XmlDocument.parse(relsXml);
  scope (exit) document.close();
  auto relationship = document.root.appendElement(opcRelationshipsNamespace, "", "Relationship");
  relationship.setAttribute("Id", id);
  relationship.setAttribute("Type", type);
  relationship.setAttribute("Target", target);
  return document.serialize();
}

private immutable(ubyte)[] ensureContentTypes(immutable(ubyte)[] xml, string signaturePart) @trusted {
  auto types = parseContentTypes(xml);
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  // ContentTypeManager.addContentType de POI: Default si la extensión está libre, si no Override.
  void add(string partName, string contentType) {
    string extension = partName[partName.lastIndexOf('.') + 1 .. $];
    bool defaultExists = types.defaults.values.canFind(contentType);
    if ((extension in types.defaults) !is null && !defaultExists) {
      auto element = document.root.appendElement(contentTypesNamespace, "", "Override");
      element.setAttribute("PartName", partName);
      element.setAttribute("ContentType", contentType);
      types.overrides[partName] = contentType;
    } else if (!defaultExists) {
      auto element = document.root.appendElement(contentTypesNamespace, "", "Default");
      element.setAttribute("Extension", extension);
      element.setAttribute("ContentType", contentType);
      types.defaults[extension] = contentType;
    }
  }
  if (contentTypeOf(types, originPartName) != originContentType) add(originPartName, originContentType);
  add(signaturePart, signatureContentType);
  return document.serialize();
}

/**
 * Añade la parte de firma al paquete con su relación desde origin.sigs, creando
 * origin.sigs (y su relación desde el paquete) si todavía no existe, como
 * SignatureInfo.writeDocument de POI.
 *
 * Throws: OpcException si el paquete no tiene [Content_Types].xml o _rels/.rels.
 */
ZipEntry[] addSignaturePart(const ZipEntry[] entries, immutable(ubyte)[] signatureXml) @safe {
  ZipEntry[] result = entries.dup;
  int index = nextSignatureIndex(entries);
  string signatureEntry = format("_xmlsignatures/sig%d.xml", index);
  enum originEntry = "_xmlsignatures/origin.sigs";
  enum originRelsEntry = "_xmlsignatures/_rels/origin.sigs.rels";
  enum packageRelsEntry = "_rels/.rels";
  void replace(string name, immutable(ubyte)[] content) {
    foreach (ref entry; result) {
      if (entry.name == name) {
        entry.content = content;
        return;
      }
    }
    result ~= ZipEntry(name, content, false);
  }
  auto contentTypesXml = entryContent(entries, contentTypesName);
  enforce!OpcException(contentTypesXml !is null, "El paquete no tiene [Content_Types].xml");
  replace(contentTypesName, ensureContentTypes(contentTypesXml, "/" ~ signatureEntry));
  if (entryContent(entries, originEntry) is null) {
    auto packageRels = entryContent(entries, packageRelsEntry);
    enforce!OpcException(packageRels !is null, "El paquete no tiene _rels/.rels");
    replace(originEntry, cast(immutable(ubyte)[]) "");
    replace(packageRelsEntry, appendRelationship(packageRels, nextRelationshipId(parseRelationships(packageRels)),
      originRelationshipType, originEntry));
  }
  auto originRels = entryContent(result, originRelsEntry);
  if (originRels is null) originRels = cast(immutable(ubyte)[]) (`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
    ~ `<Relationships xmlns="` ~ opcRelationshipsNamespace ~ `"/>`);
  replace(originRelsEntry, appendRelationship(originRels, nextRelationshipId(parseRelationships(originRels)),
    signatureRelationshipType, format("sig%d.xml", index)));
  replace(signatureEntry, signatureXml);
  return result;
}

/// Resuelve las referencias de una firma OOXML («/parte?ContentType=…») a las partes del paquete.
ExternalResolver packageResolver(const ZipEntry[] entries) @safe {
  auto copy = entries.dup;
  return (string uri) @safe {
    import std.string : indexOf;
    auto query = uri.indexOf('?');
    string partName = query >= 0 ? uri[0 .. query] : uri;
    if (partName.length == 0 || partName[0] != '/') return cast(immutable(ubyte)[]) null;
    auto content = partContent(copy, partName);
    if (content !is null && partName.endsWith(".rels")) return relationshipsWithoutLineBreaks(content);
    return content;
  };
}

/// Partes de firma del paquete, siguiendo las relaciones de origin.sigs (getSignatureParts de POI).
string[] signaturePartNames(const ZipEntry[] entries) @safe {
  string[] names;
  auto packageRels = entryContent(entries, "_rels/.rels");
  if (packageRels is null) return names;
  foreach (origin; parseRelationships(packageRels)) {
    if (origin.type != originRelationshipType || origin.external) continue;
    string originPart = resolveTarget("/", origin.target);
    string relsName = originPart[0 .. originPart.lastIndexOf('/')] ~ "/_rels" ~ originPart[originPart.lastIndexOf('/') .. $]
      ~ ".rels";
    auto originRels = partContent(entries, relsName);
    if (originRels is null) continue;
    foreach (signature; parseRelationships(originRels)) {
      if (signature.type == signatureRelationshipType && !signature.external) {
        names ~= resolveTarget(originPart, signature.target);
      }
    }
  }
  return names;
}

@("should select signed relationship types like POI")
unittest {
  assert(isSignedRelationship("http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"));
  assert(isSignedRelationship("http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"));
  assert(isSignedRelationship("http://schemas.openxmlformats.org/officeDocument/2006/relationships/customXml"));
  assert(!isSignedRelationship("http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"));
  assert(!isSignedRelationship(originRelationshipType));
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
  import std.datetime.systime : Clock;

  /// Paquete mínimo de Word para las pruebas.
  ZipEntry[] testPackage() @safe {
    enum contentTypes = `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="` ~ contentTypesNamespace ~ `">`
      ~ `<Default Extension="rels" ContentType="` ~ relationshipsContentType ~ `"/>`
      ~ `<Default Extension="xml" ContentType="application/xml"/>`
      ~ `<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.`
      ~ `wordprocessingml.document.main+xml"/></Types>`;
    enum packageRels = `<?xml version="1.0" encoding="UTF-8"?>` ~ "\r\n" ~ `<Relationships xmlns="`
      ~ opcRelationshipsNamespace ~ `"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/`
      ~ `2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.`
      ~ `openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>`
      ~ `</Relationships>`;
    enum documentRels = `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="` ~ opcRelationshipsNamespace
      ~ `"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" `
      ~ `Target="styles.xml"/><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/`
      ~ `relationships/hyperlink" Target="https://firmador.libre.cr" TargetMode="External"/></Relationships>`;
    return [
      ZipEntry(contentTypesName, cast(immutable(ubyte)[]) contentTypes),
      ZipEntry("_rels/.rels", cast(immutable(ubyte)[]) packageRels),
      ZipEntry("word/document.xml", cast(immutable(ubyte)[]) "<w:document xmlns:w=\"urn:w\"/>"),
      ZipEntry("word/_rels/document.xml.rels", cast(immutable(ubyte)[]) documentRels),
      ZipEntry("word/styles.xml", cast(immutable(ubyte)[]) "<w:styles xmlns:w=\"urn:w\"/>"),
      ZipEntry("docProps/core.xml", cast(immutable(ubyte)[]) "<cp:coreProperties xmlns:cp=\"urn:cp\"/>"),
    ];
  }
}

@("should build a manifest of the signed parts and relationships sorted by URI like POI")
unittest {
  auto manifest = packageManifest(testPackage());
  string[] uris;
  foreach (reference; manifest) uris ~= reference.uri;
  assert(uris == [
    "/_rels/.rels?ContentType=" ~ relationshipsContentType,
    "/word/_rels/document.xml.rels?ContentType=" ~ relationshipsContentType,
    "/word/document.xml?ContentType=application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "/word/styles.xml?ContentType=application/xml",
  ]);
  assert(manifest[0].sourceIds == ["rId1"]);
  assert(manifest[1].sourceIds == ["rId1", "rId9"]);
}

@("should sign a package whose SignedInfo and manifest references verify and register the signature part")
unittest {
  auto identity = makeTestIdentity("Firmante OOXML", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto entries = testPackage();
  OoxmlParameters parameters;
  parameters.signingTime = Clock.currTime;
  parameters.signingCertificate = certificate;
  auto prepared = prepareOoxmlSignature(entries, parameters);
  auto signatureXml = completeOoxmlSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));
  auto signedEntries = addSignaturePart(entries, signatureXml);
  assert(signaturePartNames(signedEntries) == ["/_xmlsignatures/sig1.xml"]);
  auto types = parseContentTypes(entryContent(signedEntries, contentTypesName));
  assert(contentTypeOf(types, "/_xmlsignatures/sig1.xml") == signatureContentType);
  assert(contentTypeOf(types, originPartName) == originContentType);

  auto document = XmlDocument.parse(entryContent(signedEntries, "_xmlsignatures/sig1.xml"));
  scope (exit) document.close();
  auto signature = parseDsSignature(document.root);
  auto resolver = packageResolver(signedEntries);
  auto verification = verifyXmlSignature(document, signature, certificate, resolver);
  assert(verification.referencesValid && verification.signatureValid);
  foreach (element; document.elements(xmldsigNamespace, "Manifest")[0].childrenNamed(xmldsigNamespace, "Reference")) {
    auto reference = parseReference(element);
    assert(digestOf(reference.digest, processReference(document, signature, reference, resolver)) == reference.digestValue,
      reference.uri);
  }
}
