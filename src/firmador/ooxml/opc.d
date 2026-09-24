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
 * Paquetes OPC (ECMA-376 parte 2) de los documentos OOXML: tipos de contenido de
 * [Content_Types].xml, relaciones de las partes *.rels, resolución de destinos relativos
 * y las partes de firma digital (origin.sigs y _xmlsignatures/sigN.xml) que añadía
 * Apache POI en la versión Java.
 */
module firmador.ooxml.opc;

import std.algorithm : canFind, endsWith, sort, startsWith;
import std.array : join, split;
import std.exception : enforce;
import std.format : format;
import std.string : lastIndexOf, toLower;
import std.uri : decodeComponent;

import firmador.util.zip;
import firmador.xml.dom;
import firmador.xml.xmldsig : opcRelationshipsNamespace;

/// Parte con los tipos de contenido.
enum string contentTypesName = "[Content_Types].xml";
/// Espacio de nombres de [Content_Types].xml.
enum string contentTypesNamespace = "http://schemas.openxmlformats.org/package/2006/content-types";
/// Tipo de contenido de las partes de relaciones.
enum string relationshipsContentType = "application/vnd.openxmlformats-package.relationships+xml";
/// Relación del paquete a origin.sigs.
enum string originRelationshipType = "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/origin";
/// Relación de origin.sigs a cada firma.
enum string signatureRelationshipType =
  "http://schemas.openxmlformats.org/package/2006/relationships/digital-signature/signature";
/// Tipo de contenido de origin.sigs.
enum string originContentType = "application/vnd.openxmlformats-package.digital-signature-origin";
/// Tipo de contenido de las partes de firma.
enum string signatureContentType = "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml";
/// Parte origin.sigs.
enum string originPartName = "/_xmlsignatures/origin.sigs";

/// Excepción de un paquete OPC mal formado.
class OpcException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// Tipos de contenido del paquete.
struct ContentTypes {
  /// Extensión en minúsculas → tipo.
  string[string] defaults;
  /// Nombre de parte (con «/» inicial) → tipo.
  string[string] overrides;
}

/**
 * Interpreta [Content_Types].xml.
 *
 * Throws: XmlException si no es XML bien formado.
 */
ContentTypes parseContentTypes(immutable(ubyte)[] xml) @trusted {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  ContentTypes types;
  foreach (element; document.root.childrenNamed(contentTypesNamespace, "Default")) {
    types.defaults[element.attribute("Extension").toLower] = element.attribute("ContentType");
  }
  foreach (element; document.root.childrenNamed(contentTypesNamespace, "Override")) {
    types.overrides[element.attribute("PartName")] = element.attribute("ContentType");
  }
  return types;
}

/// Tipo de contenido de una parte (con «/» inicial), o null si no tiene.
string contentTypeOf(const ContentTypes types, string partName) pure @safe {
  if (auto found = partName in types.overrides) return *found;
  // Los nombres de parte se comparan sin distinguir mayúsculas (OPC §9.1.1.1.2).
  foreach (name, type; types.overrides) if (name.toLower == partName.toLower) return type;
  auto dot = partName.lastIndexOf('.');
  auto slash = partName.lastIndexOf('/');
  if (dot <= slash) return null;
  if (auto found = partName[dot + 1 .. $].toLower in types.defaults) return *found;
  return null;
}

/// Relación de una parte *.rels.
struct OpcRelationship {
  string id;
  string type;
  string target;
  bool external;
}

/**
 * Relaciones de una parte *.rels, ordenadas por Id como las lee POI.
 *
 * Throws: XmlException si no es XML bien formado.
 */
OpcRelationship[] parseRelationships(immutable(ubyte)[] xml) @trusted {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  OpcRelationship[] relationships;
  foreach (element; document.root.childrenNamed(opcRelationshipsNamespace, "Relationship")) {
    relationships ~= OpcRelationship(element.attribute("Id"), element.attribute("Type"), element.attribute("Target"),
      element.attribute("TargetMode") == "External");
  }
  relationships.sort!((a, b) => a.id < b.id);
  return relationships;
}

/// Nombre de parte («/word/document.xml») de una entrada del ZIP.
string partNameOf(string entryName) pure @safe {
  return "/" ~ entryName;
}

/// Parte de origen de una parte de relaciones: «/_rels/.rels» → «/», «/a/_rels/b.xml.rels» → «/a/b.xml».
string relationshipsSource(string relsPartName) pure @safe {
  enum marker = "/_rels/";
  auto position = relsPartName.lastIndexOf(marker);
  enforce!OpcException(position >= 0 && relsPartName.endsWith(".rels"),
    format("«%s» no es una parte de relaciones", relsPartName));
  string directory = relsPartName[0 .. position];
  string source = relsPartName[position + marker.length .. $ - ".rels".length];
  return source.length ? directory ~ "/" ~ source : directory.length ? directory : "/";
}

/// Directorio base de una parte de relaciones como lo calcula POI («/word» o «»).
string relationshipsBase(string relsPartName) pure @safe {
  auto position = relsPartName.lastIndexOf("/_rels/");
  return position > 0 ? relsPartName[0 .. position] : "";
}

/**
 * Nombre de parte absoluto y normalizado del destino de una relación, relativo al
 * directorio de su parte de origen.
 *
 * Throws: OpcException si el destino sale del paquete.
 */
string resolveTarget(string sourcePart, string target) pure @safe {
  string path;
  if (target.startsWith("/")) {
    path = target;
  } else {
    auto slash = sourcePart.lastIndexOf('/');
    path = sourcePart[0 .. slash + 1] ~ target;
  }
  string[] parts;
  foreach (segment; path.split("/")) {
    if (segment.length == 0 || segment == ".") continue;
    if (segment == "..") {
      enforce!OpcException(parts.length, format("El destino «%s» sale del paquete", target));
      parts = parts[0 .. $ - 1];
    } else {
      parts ~= segment;
    }
  }
  return "/" ~ parts.join("/");
}

/// Contenido de la parte (nombre con «/» inicial, con o sin escapes), o null si no existe.
immutable(ubyte)[] partContent(const ZipEntry[] entries, string partName) @safe {
  enforce!OpcException(partName.startsWith("/"), format("Nombre de parte no válido: «%s»", partName));
  auto found = entryContent(entries, partName[1 .. $]);
  if (found !is null) return found;
  string decoded = decodeComponent(partName[1 .. $]);
  foreach (entry; entries) if (entry.name == decoded || entry.name.toLower == decoded.toLower) return entry.content;
  return null;
}

/// Primer índice libre de _xmlsignatures/sigN.xml (getUnusedPartIndex de POI).
int nextSignatureIndex(const ZipEntry[] entries) pure @safe {
  int index = 1;
  while (entries.canFind!(entry => entry.name == format("_xmlsignatures/sig%d.xml", index))) index++;
  return index;
}

@("should resolve relationship targets against their source part like OPC")
unittest {
  assert(relationshipsSource("/_rels/.rels") == "/");
  assert(relationshipsSource("/word/_rels/document.xml.rels") == "/word/document.xml");
  assert(relationshipsBase("/word/_rels/document.xml.rels") == "/word");
  assert(relationshipsBase("/_rels/.rels") == "");
  assert(resolveTarget("/", "word/document.xml") == "/word/document.xml");
  assert(resolveTarget("/word/document.xml", "styles.xml") == "/word/styles.xml");
  assert(resolveTarget("/word/document.xml", "../customXml/item1.xml") == "/customXml/item1.xml");
  assert(resolveTarget("/word/document.xml", "/docProps/app.xml") == "/docProps/app.xml");
  import std.exception : assertThrown;
  assertThrown!OpcException(resolveTarget("/", "../fuera.xml"));
}

@("should find content types by override first and then by extension")
unittest {
  auto types = parseContentTypes(cast(immutable(ubyte)[]) (`<Types xmlns="` ~ contentTypesNamespace ~ `">`
    ~ `<Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="`
    ~ relationshipsContentType ~ `"/><Override PartName="/word/document.xml" ContentType="application/vnd.main+xml"/>`
    ~ `</Types>`));
  assert(contentTypeOf(types, "/word/document.xml") == "application/vnd.main+xml");
  assert(contentTypeOf(types, "/word/styles.xml") == "application/xml");
  assert(contentTypeOf(types, "/_rels/.rels") == relationshipsContentType);
  assert(contentTypeOf(types, "/sin-extension") is null);
}
