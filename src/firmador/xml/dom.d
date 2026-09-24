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
 * Documentos XML con libxml2 (cabeceras en src/c/clibxml.c): lectura segura (sin red ni
 * entidades externas), navegación, construcción de elementos con espacio de nombres,
 * serialización y canonicalización C14N 1.0, 1.1 y exclusiva sobre conjuntos de nodos
 * (lo que necesitan XMLDSig y XAdES en firmador.xml.xmldsig). También aplica la hoja XSLT
 * del reporte de validación.
 */
module firmador.xml.dom;

import core.stdc.string : strlen;
import std.exception : enforce;
import std.format : format;
import std.string : fromStringz, toStringz;

import clibxml;

/// Error de lectura o de estructura XML.
class XmlException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// Espacio de nombres de XMLDSig.
enum string xmldsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
/// Espacio de nombres de XAdES 1.3.2 (ETSI TS 101 903).
enum string xadesNamespace = "http://uri.etsi.org/01903/v1.3.2#";
/// Espacio de nombres de XAdES 1.4.1 (ArchiveTimeStamp, TimeStampValidationData).
enum string xades141Namespace = "http://uri.etsi.org/01903/v1.4.1#";

/// Métodos de canonicalización de XMLDSig.
enum CanonicalizationMethod {
  inclusive10,
  inclusive10WithComments,
  inclusive11,
  inclusive11WithComments,
  exclusive,
  exclusiveWithComments,
}

/// URI del método.
string canonicalizationUri(CanonicalizationMethod method) pure nothrow @safe @nogc {
  final switch (method) {
    case CanonicalizationMethod.inclusive10: return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    case CanonicalizationMethod.inclusive10WithComments:
      return "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
    case CanonicalizationMethod.inclusive11: return "http://www.w3.org/2006/12/xml-c14n11";
    case CanonicalizationMethod.inclusive11WithComments: return "http://www.w3.org/2006/12/xml-c14n11#WithComments";
    case CanonicalizationMethod.exclusive: return "http://www.w3.org/2001/10/xml-exc-c14n#";
    case CanonicalizationMethod.exclusiveWithComments: return "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
  }
}

/**
 * Método de un URI de canonicalización.
 *
 * Throws: XmlException si el URI no es uno de XMLDSig.
 */
CanonicalizationMethod canonicalizationFromUri(string uri) pure @safe {
  foreach (method; [CanonicalizationMethod.inclusive10, CanonicalizationMethod.inclusive10WithComments,
      CanonicalizationMethod.inclusive11, CanonicalizationMethod.inclusive11WithComments,
      CanonicalizationMethod.exclusive, CanonicalizationMethod.exclusiveWithComments]) {
    if (canonicalizationUri(method) == uri) return method;
  }
  throw new XmlException(format("Método de canonicalización no admitido: %s", uri));
}

/// Nodo de un documento; sólo es válido mientras viva su XmlDocument.
struct XmlNode {
  package xmlNode* node;

  bool isNull() const pure nothrow @safe @nogc {
    return node is null;
  }

  /// Es un elemento.
  bool isElement() const @trusted {
    return node !is null && node.type == xmlElementType.XML_ELEMENT_NODE;
  }

  /// Nombre local del elemento o atributo.
  string localName() const @trusted {
    return node is null || node.name is null ? null : fromStringz(cast(const(char)*) node.name).idup;
  }

  /// Espacio de nombres del elemento.
  string namespaceUri() const @trusted {
    if (node is null || node.ns is null || node.ns.href is null) return null;
    return fromStringz(cast(const(char)*) node.ns.href).idup;
  }

  /// Es el elemento `name` del espacio de nombres `uri`.
  bool isElement(string uri, string name) const @safe {
    return isElement() && localName == name && namespaceUri == uri;
  }

  /// Hijos que son elementos.
  XmlNode[] children() const @trusted {
    XmlNode[] result;
    if (node is null) return result;
    for (xmlNode* child = cast(xmlNode*) node.children; child !is null; child = child.next) {
      if (child.type == xmlElementType.XML_ELEMENT_NODE) result ~= XmlNode(child);
    }
    return result;
  }

  /// Primer hijo elemento con ese nombre y espacio de nombres, o un nodo nulo.
  XmlNode child(string uri, string name) const @safe {
    foreach (candidate; children()) if (candidate.isElement(uri, name)) return candidate;
    return XmlNode.init;
  }

  /// Hijos elemento con ese nombre y espacio de nombres.
  XmlNode[] childrenNamed(string uri, string name) const @safe {
    XmlNode[] result;
    foreach (candidate; children()) if (candidate.isElement(uri, name)) result ~= candidate;
    return result;
  }

  /// Primer hijo obligatorio.
  XmlNode requiredChild(string uri, string name) const @safe {
    auto found = child(uri, name);
    enforce!XmlException(!found.isNull, format("Falta el elemento %s dentro de %s", name, localName));
    return found;
  }

  XmlNode parent() const @trusted {
    return node is null || node.parent is null || node.parent.type != xmlElementType.XML_ELEMENT_NODE
      ? XmlNode.init : XmlNode(cast(xmlNode*) node.parent);
  }

  /// Texto de todos los descendientes.
  string text() const @trusted {
    if (node is null) return null;
    auto content = xmlNodeGetContent(cast(xmlNode*) node);
    if (content is null) return "";
    scope (exit) xmlFree(content);
    return fromStringz(cast(const(char)*) content).idup;
  }

  /// Valor de un atributo sin espacio de nombres, o null.
  string attribute(string name) const @trusted {
    if (node is null) return null;
    auto value = xmlGetNoNsProp(cast(xmlNode*) node, cast(const(ubyte)*) name.toStringz);
    if (value is null) return null;
    scope (exit) xmlFree(value);
    // Un atributo vacío (URI="") es "" y no null, que significa ausente.
    auto text = fromStringz(cast(const(char)*) value);
    return text.length ? text.idup : "";
  }

  /// Espacio de nombres del prefijo en el ámbito del elemento, o null si no está declarado.
  string lookupNamespace(string prefix) const @trusted {
    if (node is null) return null;
    auto ns = xmlSearchNs(cast(xmlDoc*) node.doc, cast(xmlNode*) node,
      prefix.length ? cast(const(ubyte)*) prefix.toStringz : null);
    return ns is null || ns.href is null ? null : fromStringz(cast(const(char)*) ns.href).idup;
  }

  /// Fija un atributo sin espacio de nombres.
  void setAttribute(string name, string value) @trusted {
    enforce!XmlException(node !is null, "Nodo XML nulo");
    xmlSetProp(node, cast(const(ubyte)*) name.toStringz, cast(const(ubyte)*) value.toStringz);
  }

  /// Añade un elemento hijo del espacio de nombres (con el prefijo si hay que declararlo).
  XmlNode appendElement(string uri, string prefix, string name) @trusted {
    enforce!XmlException(node !is null, "Nodo XML nulo");
    xmlNs* ns = xmlSearchNsByHref(node.doc, node, cast(const(ubyte)*) uri.toStringz);
    auto created = xmlNewDocNode(node.doc, ns, cast(const(ubyte)*) name.toStringz, null);
    enforce!XmlException(created !is null, "libxml2 no pudo crear el elemento " ~ name);
    xmlAddChild(node, created);
    if (ns is null) {
      ns = xmlNewNs(created, cast(const(ubyte)*) uri.toStringz, prefix.length ? cast(const(ubyte)*) prefix.toStringz : null);
      xmlSetNs(created, ns);
    }
    return XmlNode(created);
  }

  /// Añade texto al elemento.
  void appendText(string value) @trusted {
    enforce!XmlException(node !is null, "Nodo XML nulo");
    auto textNode = xmlNewDocTextLen(node.doc, cast(const(ubyte)*) value.ptr, cast(int) value.length);
    xmlAddChild(node, textNode);
  }

  /// Elimina el nodo del documento.
  void remove() @trusted {
    if (node is null) return;
    xmlUnlinkNode(node);
    xmlFreeNode(node);
    node = null;
  }
}

/// XML_DOM_RECONNS_REMOVEREDUND: libxml2 2.14 lo sacó de sus cabeceras públicas, pero lo sigue aceptando.
private enum int reconcileRemoveRedundant = 1;

/// Opciones de lectura: sin red, sin DTD externas ni sustitución de entidades.
private enum int safeParseOptions = XML_PARSE_NONET | XML_PARSE_NO_XXE | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;

private extern (C) void silenceErrors(void* context, const(xmlError)* error) nothrow @system {
  // Los errores se leen con xmlGetLastError; libxml2 no debe escribirlos en la salida de error.
}

/// Documento XML en memoria.
final class XmlDocument {
  package xmlDoc* document;

  private this(xmlDoc* document) @safe {
    this.document = document;
  }

  /**
   * Lee un documento.
   *
   * Throws: XmlException con el detalle de libxml2 si no es XML bien formado.
   */
  static XmlDocument parse(const(ubyte)[] bytes) @trusted {
    enforce!XmlException(bytes.length > 0 && bytes.length < int.max, "El documento XML está vacío o es demasiado grande");
    xmlSetStructuredErrorFunc(null, &silenceErrors);
    xmlResetLastError();
    auto parsed = xmlReadMemory(cast(const(char)*) bytes.ptr, cast(int) bytes.length, null, null, safeParseOptions);
    if (parsed is null) {
      auto error = xmlGetLastError();
      string detail = error !is null && error.message !is null ? fromStringz(error.message).idup : "sin detalle";
      throw new XmlException("El documento no es XML bien formado: " ~ detail);
    }
    return new XmlDocument(parsed);
  }

  /// Documento nuevo con un elemento raíz.
  static XmlDocument create(string uri, string prefix, string rootName) @trusted {
    auto created = xmlNewDoc(cast(const(ubyte)*) "1.0".ptr);
    auto root = xmlNewDocNode(created, null, cast(const(ubyte)*) rootName.toStringz, null);
    xmlDocSetRootElement(created, root);
    if (uri.length) {
      auto ns = xmlNewNs(root, cast(const(ubyte)*) uri.toStringz, prefix.length ? cast(const(ubyte)*) prefix.toStringz : null);
      xmlSetNs(root, ns);
    }
    return new XmlDocument(created);
  }

  /// Libera el documento.
  void close() @trusted {
    if (document !is null) {
      xmlFreeDoc(document);
      document = null;
    }
  }

  ~this() {
    if (document !is null) xmlFreeDoc(document);
  }

  XmlNode root() @trusted {
    enforce!XmlException(document !is null, "El documento XML ya fue cerrado");
    return XmlNode(xmlDocGetRootElement(document));
  }

  /// Serializa el documento completo (con la declaración XML y la codificación UTF-8).
  immutable(ubyte)[] serialize() @trusted {
    enforce!XmlException(document !is null, "El documento XML ya fue cerrado");
    ubyte* buffer;
    int length;
    xmlDocDumpMemoryEnc(document, &buffer, &length, "UTF-8");
    enforce!XmlException(buffer !is null, "libxml2 no pudo serializar el documento");
    scope (exit) xmlFree(buffer);
    return buffer[0 .. length].idup;
  }

  /// Elemento con atributo Id (o ID, id) igual a `id`, o un nodo nulo.
  XmlNode elementById(string id) @trusted {
    XmlNode found;
    void walk(xmlNode* current) {
      for (; current !is null && found.isNull; current = current.next) {
        if (current.type != xmlElementType.XML_ELEMENT_NODE) continue;
        auto wrapped = XmlNode(current);
        foreach (attributeName; ["Id", "ID", "id"]) {
          if (wrapped.attribute(attributeName) == id) {
            found = wrapped;
            return;
          }
        }
        walk(current.children);
      }
    }
    walk(document.children);
    return found;
  }

  /// Todos los elementos con ese nombre y espacio de nombres, en orden de documento.
  XmlNode[] elements(string uri, string name) @trusted {
    XmlNode[] result;
    void walk(xmlNode* current) {
      for (; current !is null; current = current.next) {
        if (current.type != xmlElementType.XML_ELEMENT_NODE) continue;
        auto wrapped = XmlNode(current);
        if (wrapped.isElement(uri, name)) result ~= wrapped;
        walk(current.children);
      }
    }
    walk(document.children);
    return result;
  }

  /**
   * Importa en el documento un fragmento XML como último hijo de `parent` y lo devuelve.
   * Las declaraciones de espacio de nombres que el fragmento repite de sus nuevos
   * ancestros se quitan.
   *
   * Throws: XmlException si el fragmento no es XML bien formado.
   */
  XmlNode appendFragment(XmlNode parent, string fragment) @trusted {
    auto copy = importFragment(fragment);
    xmlAddChild(parent.node, copy);
    xmlDOMWrapReconcileNamespaces(null, copy, reconcileRemoveRedundant);
    return XmlNode(copy);
  }

  /**
   * Como appendFragment, pero con sangría: el fragmento (con saltos de línea y sangría
   * relativa propia) queda en su propia línea, una unidad más adentro que `parent`, y la
   * etiqueta de cierre de `parent` conserva su sangría.
   */
  XmlNode appendIndentedFragment(XmlNode parent, string fragment, string unit = "    ") @trusted {
    string parentIndent;
    for (auto previous = parent.node.prev; previous !is null; previous = previous.prev) {
      if (previous.type != xmlElementType.XML_TEXT_NODE) break;
      string whitespace = XmlNode(previous).text;
      import std.string : lastIndexOf;
      auto newline = whitespace.lastIndexOf('\n');
      if (newline >= 0) parentIndent = whitespace[newline + 1 .. $];
      break;
    }
    string childIndent = parentIndent ~ unit;
    import std.array : replace;
    auto copy = importFragment(fragment.replace("\n", "\n" ~ childIndent));
    auto last = parent.node.last;
    if (last !is null && last.type == xmlElementType.XML_TEXT_NODE && isBlank(XmlNode(last).text)) {
      xmlAddPrevSibling(last, newText("\n" ~ childIndent));
      xmlAddPrevSibling(last, copy);
    } else {
      xmlAddChild(parent.node, newText("\n" ~ childIndent));
      xmlAddChild(parent.node, copy);
      xmlAddChild(parent.node, newText("\n" ~ parentIndent));
    }
    xmlDOMWrapReconcileNamespaces(null, copy, reconcileRemoveRedundant);
    return XmlNode(copy);
  }

  /// Quita el elemento y el espacio en blanco que lo precede (su sangría).
  void removeIndented(XmlNode element) @trusted {
    if (element.node is null) return;
    auto previous = element.node.prev;
    if (previous !is null && previous.type == xmlElementType.XML_TEXT_NODE && isBlank(XmlNode(previous).text)) {
      xmlUnlinkNode(previous);
      xmlFreeNode(previous);
    }
    element.remove();
  }

  private xmlNode* importFragment(string fragment) @trusted {
    auto parsed = XmlDocument.parse(cast(const(ubyte)[]) fragment);
    scope (exit) parsed.close();
    auto copy = xmlDocCopyNode(xmlDocGetRootElement(parsed.document), document, 1);
    enforce!XmlException(copy !is null, "libxml2 no pudo copiar el fragmento");
    return copy;
  }

  private xmlNode* newText(string value) @trusted {
    auto created = xmlNewDocTextLen(document, cast(const(ubyte)*) value.ptr, cast(int) value.length);
    enforce!XmlException(created !is null, "libxml2 no pudo crear un nodo de texto");
    return created;
  }

  /**
   * Canonicaliza el subárbol de `subject` (el elemento y sus descendientes).
   *
   * Throws: XmlException si libxml2 no puede canonicalizar.
   */
  immutable(ubyte)[] canonicalize(XmlNode subject, CanonicalizationMethod method, const string[] inclusivePrefixes = null)
      @trusted {
    return canonicalizeSelection(method, inclusivePrefixes, (xmlNode* node, xmlNode* parent) {
      return isInSubtree(node, parent, subject.node);
    });
  }

  /**
   * Canonicaliza todo el documento sin los comentarios y sin los elementos que
   * `excluded` marque, ni sus descendientes (transformación enveloped-signature o la
   * XPath not(ancestor-or-self::ds:Signature)).
   */
  immutable(ubyte)[] canonicalizeDocumentExcluding(CanonicalizationMethod method,
      scope bool delegate(XmlNode element) @safe excluded, const string[] inclusivePrefixes = null) @trusted {
    return canonicalizeSelection(method, inclusivePrefixes, (xmlNode* node, xmlNode* parent) {
      xmlNode* element = node.type == xmlElementType.XML_ELEMENT_NODE ? node : parent;
      for (auto current = element; current !is null; current = current.parent) {
        if (current.type == xmlElementType.XML_ELEMENT_NODE && excluded(XmlNode(current))) return false;
      }
      return true;
    });
  }

  private immutable(ubyte)[] canonicalizeSelection(CanonicalizationMethod method, const string[] inclusivePrefixes,
      scope bool delegate(xmlNode*, xmlNode*) visible) @trusted {
    enforce!XmlException(document !is null, "El documento XML ya fue cerrado");
    int mode;
    bool withComments;
    final switch (method) {
      case CanonicalizationMethod.inclusive10: mode = xmlC14NMode.XML_C14N_1_0; break;
      case CanonicalizationMethod.inclusive10WithComments: mode = xmlC14NMode.XML_C14N_1_0; withComments = true; break;
      case CanonicalizationMethod.inclusive11: mode = xmlC14NMode.XML_C14N_1_1; break;
      case CanonicalizationMethod.inclusive11WithComments: mode = xmlC14NMode.XML_C14N_1_1; withComments = true; break;
      case CanonicalizationMethod.exclusive: mode = xmlC14NMode.XML_C14N_EXCLUSIVE_1_0; break;
      case CanonicalizationMethod.exclusiveWithComments:
        mode = xmlC14NMode.XML_C14N_EXCLUSIVE_1_0;
        withComments = true;
        break;
    }
    ubyte*[] prefixes;
    foreach (prefix; inclusivePrefixes) prefixes ~= cast(ubyte*) (prefix ~ "\0").dup.ptr;
    prefixes ~= null;
    auto output = xmlAllocOutputBuffer(null);
    enforce!XmlException(output !is null, "libxml2 no pudo reservar la salida de la canonicalización");
    auto selection = Selection(visible);
    int result = xmlC14NExecute(document, &isVisible, &selection, mode,
      inclusivePrefixes.length ? prefixes.ptr : null, withComments ? 1 : 0, output);
    scope (exit) xmlOutputBufferClose(output);
    enforce!XmlException(result >= 0, "La canonicalización XML falló");
    auto content = xmlOutputBufferGetContent(output);
    size_t length = xmlOutputBufferGetSize(output);
    return content is null ? [] : content[0 .. length].idup;
  }
}

private bool isBlank(string text) pure nothrow @safe @nogc {
  foreach (char character; text) {
    if (character != ' ' && character != '\n' && character != '\r' && character != '\t') return false;
  }
  return true;
}

private struct Selection {
  bool delegate(xmlNode*, xmlNode*) visible;
}

private extern (C) int isVisible(void* userData, xmlNode* node, xmlNode* parent) nothrow @system {
  try {
    return (cast(Selection*) userData).visible(node, parent) ? 1 : 0;
  } catch (Exception) {
    return 0;
  }
}

private bool isInSubtree(xmlNode* node, xmlNode* parent, xmlNode* subject) @system {
  xmlNode* start = node.type == xmlElementType.XML_ELEMENT_NODE || node.type == xmlElementType.XML_TEXT_NODE
    || node.type == xmlElementType.XML_COMMENT_NODE || node.type == xmlElementType.XML_PI_NODE
    || node.type == xmlElementType.XML_CDATA_SECTION_NODE ? node : parent;
  for (auto current = start; current !is null; current = current.parent) {
    if (current is subject) return true;
  }
  return false;
}

/**
 * Aplica una hoja XSLT a un documento XML y devuelve el resultado serializado.
 *
 * Throws: XmlException si la hoja o el documento no son válidos.
 */
string applyStylesheet(const(ubyte)[] stylesheet, const(ubyte)[] input) @trusted {
  auto styleDocument = XmlDocument.parse(stylesheet);
  auto compiled = xsltParseStylesheetDoc(styleDocument.document);
  enforce!XmlException(compiled !is null, "La hoja XSLT no es válida");
  // xsltFreeStylesheet libera también el documento de la hoja.
  styleDocument.document = null;
  scope (exit) xsltFreeStylesheet(compiled);
  auto inputDocument = XmlDocument.parse(input);
  scope (exit) inputDocument.close();
  auto transformed = xsltApplyStylesheet(compiled, inputDocument.document, null);
  enforce!XmlException(transformed !is null, "No se pudo aplicar la hoja XSLT");
  scope (exit) xmlFreeDoc(transformed);
  ubyte* buffer;
  int length;
  enforce!XmlException(xsltSaveResultToString(&buffer, &length, transformed, compiled) == 0,
    "No se pudo serializar el resultado de la hoja XSLT");
  if (buffer is null) return "";
  scope (exit) xmlFree(buffer);
  return cast(string) buffer[0 .. length].idup;
}

/// Escapa texto para contenido o atributos XML.
string escapeXml(string text) pure @safe {
  import std.array : appender;
  auto output = appender!string;
  foreach (char character; text) {
    switch (character) {
      case '&': output ~= "&amp;"; break;
      case '<': output ~= "&lt;"; break;
      case '>': output ~= "&gt;"; break;
      case '"': output ~= "&quot;"; break;
      case '\'': output ~= "&apos;"; break;
      case '\r': output ~= "&#xD;"; break;
      default: output ~= character; break;
    }
  }
  return output[];
}

@("should canonicalize with and without the excluded subtree when applying enveloped transforms")
unittest {
  auto document = XmlDocument.parse(cast(const(ubyte)[])
    `<?xml version="1.0"?><a xmlns="urn:a" b="1"  ><!-- c --><x>t</x><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:y/></ds:Signature></a>`);
  scope (exit) document.close();
  auto whole = cast(string) document.canonicalizeDocumentExcluding(CanonicalizationMethod.inclusive10,
    (element) => element.isElement(xmldsigNamespace, "Signature"));
  assert(whole == `<a xmlns="urn:a" b="1"><x>t</x></a>`);
  auto subtree = cast(string) document.canonicalize(document.root.child("urn:a", "x"), CanonicalizationMethod.exclusive);
  assert(subtree == `<x xmlns="urn:a">t</x>`);
  auto inclusive = cast(string) document.canonicalize(document.root.child("urn:a", "x"), CanonicalizationMethod.inclusive10);
  assert(inclusive == `<x xmlns="urn:a">t</x>`);
}

@("should refuse external entities and malformed input when parsing untrusted XML")
unittest {
  import std.exception : assertThrown;
  auto withEntity = XmlDocument.parse(cast(const(ubyte)[])
    `<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>`);
  scope (exit) withEntity.close();
  import std.algorithm : canFind;
  assert(!withEntity.root.text.canFind("root:"));
  assertThrown!XmlException(XmlDocument.parse(cast(const(ubyte)[]) "<a><b></a>"));
}

@("should build namespaced elements and find them by Id when constructing signatures")
unittest {
  import std.algorithm : canFind;
  auto document = XmlDocument.create("urn:raiz", "r", "Raiz");
  scope (exit) document.close();
  auto signature = document.root.appendElement(xmldsigNamespace, "ds", "Signature");
  signature.setAttribute("Id", "firma-1");
  signature.appendElement(xmldsigNamespace, "ds", "SignatureValue").appendText("AB<C");
  assert(document.elementById("firma-1").localName == "Signature");
  string serialized = cast(string) document.serialize();
  assert(serialized.canFind(`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="firma-1">`));
  assert(serialized.canFind("AB&lt;C"));
  auto fragment = document.appendFragment(document.root, `<x:Hijo xmlns:x="urn:x">1</x:Hijo>`);
  assert(fragment.namespaceUri == "urn:x");
}

@("should indent appended fragments and drop repeated namespace declarations when extending signatures")
unittest {
  auto document = XmlDocument.parse(cast(const(ubyte)[])
    "<r:a xmlns:r=\"urn:r\">\n  <r:b>\n  </r:b>\n</r:a>");
  scope (exit) document.close();
  auto parent = document.root.child("urn:r", "b");
  document.appendIndentedFragment(parent, "<r:c xmlns:r=\"urn:r\">\n  <r:d/>\n</r:c>", "  ");
  string serialized = cast(string) document.serialize();
  import std.algorithm : canFind;
  assert(serialized.canFind("<r:b>\n    <r:c>\n      <r:d/>\n    </r:c>\n  </r:b>"), serialized);
  document.removeIndented(document.root.child("urn:r", "b").child("urn:r", "c"));
  assert((cast(string) document.serialize()).canFind("<r:b>\n  </r:b>"));
}
