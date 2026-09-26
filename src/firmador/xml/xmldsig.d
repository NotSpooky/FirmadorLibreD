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
 * Firmas XML (XMLDSig, W3C xmldsig-core1): lectura de ds:Signature, procesamiento de
 * referencias con sus transformaciones (enveloped-signature, XPath, XPath Filter 2.0,
 * canonicalizaciones y la RelationshipTransform de OOXML), verificación de los resúmenes
 * y del valor de la firma, y los nombres de algoritmo de XMLDSig. Las firmas XAdES se
 * arman en firmador.xml.xades.
 */
module firmador.xml.xmldsig;

import std.algorithm : canFind, startsWith, sort;
import std.array : split;
import std.base64 : Base64;
import std.exception : enforce;
import std.format : format;
import std.logger : trace, warning;
import std.string : strip, indexOf;
import std.uri : decodeComponent;

import clibxml;

import firmador.crypto.digest;
import firmador.crypto.openssl;
import firmador.x509.certificate;
import firmador.xml.dom;

/// Transformación enveloped-signature.
enum string envelopedTransformUri = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// Transformación XPath 1.0.
enum string xpathTransformUri = "http://www.w3.org/TR/1999/REC-xpath-19991116";
/// Transformación XPath Filter 2.0.
enum string xpathFilter2TransformUri = "http://www.w3.org/2002/06/xmldsig-filter2";
/// Transformación base64.
enum string base64TransformUri = "http://www.w3.org/2000/09/xmldsig#base64";
/// Transformación de relaciones de OPC (OOXML, ECMA-376 parte 2).
enum string relationshipTransformUri = "http://schemas.openxmlformats.org/package/2006/RelationshipTransform";
/// Tipo de referencia a las propiedades firmadas de XAdES.
enum string signedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";
/// Espacio de nombres de las relaciones de OPC.
enum string opcRelationshipsNamespace = "http://schemas.openxmlformats.org/package/2006/relationships";
/// Espacio de nombres de la firma digital de OPC.
enum string opcDigitalSignatureNamespace = "http://schemas.openxmlformats.org/package/2006/digital-signature";

/// URI XMLDSig del algoritmo de firma.
string signatureMethodUri(bool rsa, DigestAlgorithm digest) pure nothrow @safe @nogc {
  if (rsa) {
    final switch (digest) {
      case DigestAlgorithm.sha1: return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
      case DigestAlgorithm.sha224: return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
      case DigestAlgorithm.sha256: return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
      case DigestAlgorithm.sha384: return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
      case DigestAlgorithm.sha512: return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    }
  }
  final switch (digest) {
    case DigestAlgorithm.sha1: return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
    case DigestAlgorithm.sha224: return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
    case DigestAlgorithm.sha256: return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    case DigestAlgorithm.sha384: return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
    case DigestAlgorithm.sha512: return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
  }
}

/**
 * Algoritmo de firma de un URI de XMLDSig y si es ECDSA (cuyo valor va como r||s).
 *
 * Throws: XmlException si el algoritmo no se admite.
 */
SignatureAlgorithm signatureAlgorithmFromXmlUri(string uri, out bool ecdsa) pure @safe {
  SignatureAlgorithm algorithm;
  foreach (digest; [DigestAlgorithm.sha1, DigestAlgorithm.sha224, DigestAlgorithm.sha256, DigestAlgorithm.sha384,
      DigestAlgorithm.sha512]) {
    algorithm.digest = digest;
    if (signatureMethodUri(true, digest) == uri) {
      algorithm.kind = SignatureAlgorithm.Kind.rsaPkcs1;
      return algorithm;
    }
    if (signatureMethodUri(false, digest) == uri) {
      algorithm.kind = SignatureAlgorithm.Kind.ecdsa;
      ecdsa = true;
      return algorithm;
    }
    // RSASSA-PSS de RFC 6931 §2.3.10: MGF1 con el mismo resumen y sal de su longitud.
    if (uri == "http://www.w3.org/2007/05/xmldsig-more#" ~ digestJoseLikeName(digest) ~ "-rsa-MGF1") {
      algorithm.kind = SignatureAlgorithm.Kind.rsaPss;
      algorithm.mgfDigest = digest;
      algorithm.saltLength = cast(int) digestLength(digest);
      return algorithm;
    }
  }
  throw new XmlException(format("Algoritmo de firma XML no admitido: %s", uri));
}

private string digestJoseLikeName(DigestAlgorithm digest) pure nothrow @safe @nogc {
  final switch (digest) {
    case DigestAlgorithm.sha1: return "sha1";
    case DigestAlgorithm.sha224: return "sha224";
    case DigestAlgorithm.sha256: return "sha256";
    case DigestAlgorithm.sha384: return "sha384";
    case DigestAlgorithm.sha512: return "sha512";
  }
}

/// Transformación de una referencia.
struct DsTransform {
  string algorithm;
  XmlNode node;
}

/// Referencia de ds:SignedInfo.
struct DsReference {
  string id;
  string uri;
  string type;
  DsTransform[] transforms;
  DigestAlgorithm digest;
  immutable(ubyte)[] digestValue;
  XmlNode node;
}

/// ds:Signature ya interpretada.
struct DsSignature {
  string id;
  XmlNode element;
  XmlNode signedInfo;
  XmlNode signatureValueElement;
  XmlNode keyInfo;
  CanonicalizationMethod canonicalization;
  string signatureMethod;
  DsReference[] references;
  immutable(ubyte)[] signatureValue;
  /// Certificados de ds:KeyInfo/ds:X509Data.
  Certificate[] keyInfoCertificates;
}

/// Bytes decodificados de un base64 que puede traer espacios y saltos de línea.
immutable(ubyte)[] decodeXmlBase64(string text) pure @safe {
  import std.array : appender;
  auto cleaned = appender!string;
  foreach (char character; text) {
    if (character != ' ' && character != '\n' && character != '\r' && character != '\t') cleaned ~= character;
  }
  try {
    return Base64.decode(cleaned[]).idup;
  } catch (Exception) {
    throw new XmlException("Valor base64 no válido en la firma XML");
  }
}

/**
 * Interpreta un elemento ds:Signature.
 *
 * Throws: XmlException si le falta alguno de sus elementos obligatorios.
 */
DsSignature parseDsSignature(XmlNode element) @safe {
  enforce!XmlException(element.isElement(xmldsigNamespace, "Signature"), "El elemento no es un ds:Signature");
  DsSignature signature;
  signature.element = element;
  signature.id = element.attribute("Id");
  signature.signedInfo = element.requiredChild(xmldsigNamespace, "SignedInfo");
  auto c14n = signature.signedInfo.requiredChild(xmldsigNamespace, "CanonicalizationMethod");
  signature.canonicalization = canonicalizationFromUri(c14n.attribute("Algorithm"));
  signature.signatureMethod = signature.signedInfo.requiredChild(xmldsigNamespace, "SignatureMethod").attribute("Algorithm");
  foreach (referenceElement; signature.signedInfo.childrenNamed(xmldsigNamespace, "Reference")) {
    signature.references ~= parseReference(referenceElement);
  }
  enforce!XmlException(signature.references.length > 0, "La firma XML no tiene referencias");
  signature.signatureValueElement = element.requiredChild(xmldsigNamespace, "SignatureValue");
  signature.signatureValue = decodeXmlBase64(signature.signatureValueElement.text);
  signature.keyInfo = element.child(xmldsigNamespace, "KeyInfo");
  if (!signature.keyInfo.isNull) {
    foreach (data; signature.keyInfo.childrenNamed(xmldsigNamespace, "X509Data")) {
      foreach (certificate; data.childrenNamed(xmldsigNamespace, "X509Certificate")) {
        signature.keyInfoCertificates ~= parseCertificate(decodeXmlBase64(certificate.text));
      }
    }
  }
  return signature;
}

/**
 * Interpreta un ds:Reference (de SignedInfo o de un ds:Manifest).
 *
 * Throws: XmlException si le falta DigestMethod o DigestValue.
 */
DsReference parseReference(XmlNode referenceElement) @safe {
  DsReference reference;
  reference.node = referenceElement;
  reference.id = referenceElement.attribute("Id");
  reference.uri = referenceElement.attribute("URI");
  reference.type = referenceElement.attribute("Type");
  auto transforms = referenceElement.child(xmldsigNamespace, "Transforms");
  if (!transforms.isNull) {
    foreach (transform; transforms.childrenNamed(xmldsigNamespace, "Transform")) {
      reference.transforms ~= DsTransform(transform.attribute("Algorithm"), transform);
    }
  }
  reference.digest = digestFromXmlUri(referenceElement.requiredChild(xmldsigNamespace, "DigestMethod").attribute("Algorithm"));
  reference.digestValue = decodeXmlBase64(referenceElement.requiredChild(xmldsigNamespace, "DigestValue").text);
  return reference;
}

/// Contenido de una referencia externa (archivo de un contenedor), o null si no existe.
alias ExternalResolver = immutable(ubyte)[] delegate(string uri) @safe;

/// Conjunto de nodos sobre el que se aplican las transformaciones.
private struct NodeSet {
  XmlNode subtree;
  bool wholeDocument;
  bool withComments;
  XmlNode[] excludedSubtrees;
  string xpath;
  XmlNode xpathTransform;
}

/**
 * Bytes de la referencia tras sus transformaciones (lo que se resume).
 *
 * Throws: XmlException si la referencia no se puede resolver o usa una transformación
 * no admitida.
 */
immutable(ubyte)[] processReference(XmlDocument document, const DsSignature signature, const DsReference reference,
    ExternalResolver resolver, XmlDocument emptyUriDocument = null) @trusted {
  string uri = reference.uri;
  // En una firma separada, URI="" apunta al documento firmado y no al de la firma (como en DSS).
  if (uri !is null && uri.length == 0 && emptyUriDocument !is null) document = emptyUriDocument;
  bool sameDocument = uri !is null && (uri.length == 0 || uri.startsWith("#"));
  if (!sameDocument) {
    enforce!XmlException(resolver !is null, format("La referencia «%s» no se puede resolver", uri));
    auto content = resolver(decodeComponent(uri));
    enforce!XmlException(content !is null, format("No se encontró el objeto referenciado «%s»", uri));
    return applyOctetTransforms(content, reference);
  }
  NodeSet nodes;
  if (uri.length == 0) {
    nodes.wholeDocument = true;
  } else if (uri == "#xpointer(/)") {
    nodes.wholeDocument = true;
    nodes.withComments = true;
  } else {
    string id = uri[1 .. $];
    if (id.startsWith("xpointer(id('") && id.length > 16) id = id[13 .. $ - 3];
    nodes.subtree = document.elementById(id);
    enforce!XmlException(!nodes.subtree.isNull, format("No se encontró el elemento referenciado «%s»", uri));
  }
  bool canonicalized = false;
  immutable(ubyte)[] octets;
  foreach (transform; reference.transforms) {
    switch (transform.algorithm) {
      case envelopedTransformUri:
        nodes.excludedSubtrees ~= cast(XmlNode) signature.element;
        break;
      case xpathTransformUri:
        nodes.xpath = transform.node.requiredChild(xmldsigNamespace, "XPath").text.strip;
        nodes.xpathTransform = cast(XmlNode) transform.node;
        break;
      case xpathFilter2TransformUri:
        auto filters = transform.node.childrenNamed(xpathFilter2TransformUri, "XPath");
        enforce!XmlException(filters.length > 0, "Transformación XPath Filter 2.0 sin expresiones");
        foreach (filter; filters) {
          // La que usan DSS y los demás firmadores: restar todas las firmas del documento.
          string expression = filter.text.strip;
          enforce!XmlException(filter.attribute("Filter") == "subtract" && expression.startsWith("/descendant::")
            && isSignatureStep(filter, expression["/descendant::".length .. $]),
            format("Expresión XPath Filter 2.0 no admitida: %s", expression));
          nodes.excludedSubtrees ~= document.elements(xmldsigNamespace, "Signature");
        }
        break;
      case relationshipTransformUri:
        throw new XmlException("La transformación de relaciones sólo se admite sobre partes de un paquete OPC");
      default:
        auto method = canonicalizationFromUri(transform.algorithm);
        octets = canonicalizeNodes(document, nodes, method, inclusivePrefixes(transform.node));
        canonicalized = true;
        break;
    }
  }
  if (!canonicalized) {
    // Un conjunto de nodos que llega al resumen se convierte con C14N 1.0 (xmldsig-core §4.4.3.2).
    octets = canonicalizeNodes(document, nodes, nodes.withComments ? CanonicalizationMethod.inclusive10WithComments
      : CanonicalizationMethod.inclusive10, null);
  }
  return octets;
}

private string[] inclusivePrefixes(const XmlNode transform) @safe {
  auto inclusive = transform.child("http://www.w3.org/2001/10/xml-exc-c14n#", "InclusiveNamespaces");
  if (inclusive.isNull) return null;
  string list = inclusive.attribute("PrefixList");
  if (list is null) return null;
  string[] prefixes;
  foreach (prefix; list.split) if (prefix.length) prefixes ~= prefix == "#default" ? "" : prefix;
  return prefixes;
}

private immutable(ubyte)[] canonicalizeNodes(XmlDocument document, NodeSet nodes, CanonicalizationMethod method,
    const string[] prefixes) @trusted {
  auto commentsMethod = method;
  if (!nodes.withComments) {
    // Las referencias a un Id o al documento completo excluyen los comentarios.
    if (method == CanonicalizationMethod.inclusive10WithComments) commentsMethod = CanonicalizationMethod.inclusive10;
    if (method == CanonicalizationMethod.inclusive11WithComments) commentsMethod = CanonicalizationMethod.inclusive11;
    if (method == CanonicalizationMethod.exclusiveWithComments) commentsMethod = CanonicalizationMethod.exclusive;
  }
  bool[xmlNode*] xpathCache;
  bool excludedElement(XmlNode element) @trusted {
    foreach (excluded; nodes.excludedSubtrees) if (element.node is excluded.node) return true;
    if (nodes.xpath.length && !xpathKeeps(document, nodes, element, xpathCache)) return true;
    if (!nodes.subtree.isNull) {
      // Fuera del subárbol referenciado: sólo cuentan el elemento y sus descendientes.
      for (auto current = element.node; current !is null; current = current.parent) {
        if (current is nodes.subtree.node) return false;
      }
      return true;
    }
    return false;
  }
  if (!nodes.subtree.isNull && nodes.excludedSubtrees.length == 0 && nodes.xpath.length == 0) {
    return document.canonicalize(nodes.subtree, commentsMethod, prefixes);
  }
  return document.canonicalizeDocumentExcluding(commentsMethod, &excludedElement, prefixes);
}

/// Evalúa la expresión de la transformación XPath para el elemento (ancestros incluidos).
private bool xpathKeeps(XmlDocument document, ref NodeSet nodes, XmlNode element, ref bool[xmlNode*] cache) @trusted {
  if (auto cached = element.node in cache) return *cached;
  bool keep;
  string expression = nodes.xpath;
  // La expresión de los comprobantes de Hacienda y de DSS, con cualquier prefijo de XMLDSig.
  enum notPrefix = "not(ancestor-or-self::";
  if (expression.startsWith(notPrefix) && expression.length > notPrefix.length + 1 && expression[$ - 1] == ')'
      && isSignatureStep(nodes.xpathTransform.requiredChild(xmldsigNamespace, "XPath"),
        expression[notPrefix.length .. $ - 1])) {
    keep = true;
    for (auto current = element.node; current !is null; current = current.parent) {
      if (current.type == xmlElementType.XML_ELEMENT_NODE && XmlNode(current).isElement(xmldsigNamespace, "Signature")) {
        keep = false;
        break;
      }
    }
  } else {
    auto context = xmlXPathNewContext(document.document);
    enforce!XmlException(context !is null, "libxml2 no pudo crear el contexto XPath");
    scope (exit) xmlXPathFreeContext(context);
    // Los prefijos que usa la expresión se declaran en la propia transformación.
    for (auto ns = nodes.xpathTransform.node.nsDef; ns !is null; ns = ns.next) {
      if (ns.prefix !is null) xmlXPathRegisterNs(context, ns.prefix, ns.href);
    }
    for (auto parent = nodes.xpathTransform.node.parent; parent !is null; parent = parent.parent) {
      for (auto ns = parent.nsDef; ns !is null; ns = ns.next) {
        if (ns.prefix !is null) xmlXPathRegisterNs(context, ns.prefix, ns.href);
      }
    }
    context.node = element.node;
    auto result = xmlXPathEvalExpression(cast(const(ubyte)*) ("boolean(" ~ expression ~ ")\0").ptr, context);
    enforce!XmlException(result !is null, format("La expresión XPath de la firma no es válida: %s", expression));
    scope (exit) xmlXPathFreeObject(result);
    keep = result.boolval != 0;
  }
  cache[element.node] = keep;
  return keep;
}

/// `step` es «prefijo:Signature» con el prefijo de XMLDSig en el ámbito de `context`.
private bool isSignatureStep(const XmlNode context, string step) @safe {
  auto colon = step.indexOf(':');
  if (colon <= 0 || step[colon + 1 .. $] != "Signature") return false;
  return context.lookupNamespace(step[0 .. colon]) == xmldsigNamespace;
}

private immutable(ubyte)[] applyOctetTransforms(immutable(ubyte)[] content, const DsReference reference) @trusted {
  immutable(ubyte)[] octets = content;
  foreach (transform; reference.transforms) {
    switch (transform.algorithm) {
      case base64TransformUri:
        octets = decodeXmlBase64(cast(string) octets);
        break;
      case relationshipTransformUri:
        octets = relationshipTransform(octets, transform.node);
        break;
      default:
        auto method = canonicalizationFromUri(transform.algorithm);
        auto parsed = XmlDocument.parse(octets);
        scope (exit) parsed.close();
        octets = parsed.canonicalizeDocumentExcluding(method, (element) => false, inclusivePrefixes(transform.node));
        break;
    }
  }
  return octets;
}

/**
 * RelationshipTransform de OPC (ECMA-376 parte 2 §13.2.4.24): conserva sólo las
 * relaciones elegidas por Id o tipo, ordenadas por Id, con TargetMode explícito, y las
 * canonicaliza.
 */
immutable(ubyte)[] relationshipTransform(immutable(ubyte)[] relationships, const XmlNode transform) @trusted {
  string[] sourceIds;
  string[] sourceTypes;
  foreach (selector; transform.children()) {
    if (selector.localName == "RelationshipReference") sourceIds ~= selector.attribute("SourceId");
    else if (selector.localName == "RelationshipsGroupReference") sourceTypes ~= selector.attribute("SourceType");
  }
  return selectRelationships(relationships, sourceIds, sourceTypes);
}

/**
 * Parte de relaciones con sólo las elegidas por Id o tipo, ordenadas por Id, con
 * TargetMode explícito y canonicalizada (el resultado de la RelationshipTransform).
 *
 * Throws: XmlException si la parte no es XML bien formado.
 */
immutable(ubyte)[] selectRelationships(immutable(ubyte)[] relationships, const string[] sourceIds,
    const string[] sourceTypes) @trusted {
  auto parsed = XmlDocument.parse(relationships);
  scope (exit) parsed.close();
  struct Selected {
    string id;
    string type;
    string target;
    string targetMode;
  }
  Selected[] selected;
  foreach (relationship; parsed.root.childrenNamed(opcRelationshipsNamespace, "Relationship")) {
    string id = relationship.attribute("Id");
    string type = relationship.attribute("Type");
    if (!sourceIds.canFind(id) && !sourceTypes.canFind(type)) continue;
    string mode = relationship.attribute("TargetMode");
    selected ~= Selected(id, type, relationship.attribute("Target"), mode is null ? "Internal" : mode);
  }
  selected.sort!((a, b) => a.id < b.id);
  string rebuilt = `<Relationships xmlns="` ~ opcRelationshipsNamespace ~ `">`;
  foreach (relationship; selected) {
    rebuilt ~= format(`<Relationship Id="%s" Target="%s" TargetMode="%s" Type="%s"></Relationship>`,
      escapeXml(relationship.id), escapeXml(relationship.target), escapeXml(relationship.targetMode),
      escapeXml(relationship.type));
  }
  rebuilt ~= `</Relationships>`;
  auto canonical = XmlDocument.parse(cast(const(ubyte)[]) rebuilt);
  scope (exit) canonical.close();
  return canonical.canonicalize(canonical.root, CanonicalizationMethod.inclusive10);
}

/// ds:SignedInfo canonicalizado con su método (lo que se firma).
immutable(ubyte)[] canonicalSignedInfo(XmlDocument document, const DsSignature signature) @trusted {
  return document.canonicalize(cast(XmlNode) signature.signedInfo, signature.canonicalization);
}

/// Resultado de verificar una firma XML.
struct XmlSignatureVerification {
  bool referencesValid;
  bool signatureValid;
  /// Referencias cuyo resumen no coincide.
  string[] failedReferences;
  /// Referencias que no se pudieron resolver o procesar.
  string[] missingReferences;
  /// Por qué no se pudo verificar el valor de la firma (algoritmo no admitido…), o null.
  string signatureFailure;
}

/**
 * Verifica los resúmenes de todas las referencias y el valor de la firma con el
 * certificado dado.
 */
XmlSignatureVerification verifyXmlSignature(XmlDocument document, const DsSignature signature,
    const Certificate certificate, ExternalResolver resolver, XmlDocument emptyUriDocument = null) @trusted {
  XmlSignatureVerification result;
  result.referencesValid = true;
  foreach (reference; signature.references) {
    try {
      auto octets = processReference(document, signature, reference, resolver, emptyUriDocument);
      if (digestOf(reference.digest, octets) != reference.digestValue) {
        result.referencesValid = false;
        result.failedReferences ~= reference.uri;
        trace("Resumen distinto en la referencia «", reference.uri, "»");
      }
    } catch (Exception exception) {
      result.referencesValid = false;
      result.missingReferences ~= reference.uri;
      trace("No se pudo procesar la referencia «", reference.uri, "»: ", exception.msg);
    }
  }
  try {
    bool ecdsa;
    auto algorithm = signatureAlgorithmFromXmlUri(signature.signatureMethod, ecdsa);
    auto value = ecdsa ? ecdsaRawToDer(signature.signatureValue) : signature.signatureValue.dup;
    result.signatureValid = verifySignature(certificate.subjectPublicKeyInfoDer, algorithm,
      canonicalSignedInfo(document, signature), value);
  } catch (Exception exception) {
    warning("No se pudo verificar el valor de la firma XML: ", exception.msg);
    result.signatureValid = false;
    result.signatureFailure = exception.msg;
  }
  return result;
}

@("should select relationships by id and type and sort them when applying the OPC transform")
unittest {
  auto transformDocument = XmlDocument.parse(cast(const(ubyte)[]) (`<t xmlns:mdssi="` ~ opcDigitalSignatureNamespace
    ~ `"><mdssi:RelationshipReference SourceId="rId2"/><mdssi:RelationshipsGroupReference SourceType="urn:tipo"/></t>`));
  scope (exit) transformDocument.close();
  auto relationships = cast(immutable(ubyte)[]) (`<?xml version="1.0"?><Relationships xmlns="` ~ opcRelationshipsNamespace
    ~ `"><Relationship Id="rId3" Type="urn:tipo" Target="b.xml"/><Relationship Id="rId1" Type="urn:otro" Target="x.xml"/>`
    ~ `<Relationship Id="rId2" Type="urn:otro" Target="a.xml" TargetMode="External"/></Relationships>`);
  string result = cast(string) relationshipTransform(relationships, transformDocument.root);
  assert(result == `<Relationships xmlns="` ~ opcRelationshipsNamespace
    ~ `"><Relationship Id="rId2" Target="a.xml" TargetMode="External" Type="urn:otro"></Relationship>`
    ~ `<Relationship Id="rId3" Target="b.xml" TargetMode="Internal" Type="urn:tipo"></Relationship></Relationships>`);
}
