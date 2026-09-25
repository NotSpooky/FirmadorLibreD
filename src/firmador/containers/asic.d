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
 * Contenedores ASiC (ETSI EN 319 162-1) y OpenDocument como los lee y escribe DSS 6.4:
 * clasificación de las entradas (documentos firmados, archivos de firma, manifiestos y
 * otros de META-INF), META-INF/manifest.xml de ASiC-E con XAdES, nombre del siguiente
 * archivo de firmas (signatures001.xml…), lo que firma una firma de OpenDocument y el
 * orden de escritura (mimetype primero y sin comprimir).
 */
module firmador.containers.asic;

import std.algorithm : canFind, endsWith, startsWith;
import std.array : appender;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;
import std.path : extension;
import std.string : toLower;

import firmador.documents.mimetype : detectMimeType, mimeTypeString;
import firmador.util.zip;
import firmador.xml.dom : escapeXml;
import firmador.xml.xades : XadesFile, asicNamespace, openDocumentSignaturesNamespace;
import firmador.xml.xmldsig : ExternalResolver;

/// Tipo MIME de un contenedor ASiC-E.
enum string asicEMimeType = "application/vnd.etsi.asic-e+zip";
/// Tipo MIME de un contenedor ASiC-S.
enum string asicSMimeType = "application/vnd.etsi.asic-s+zip";
/// Prefijo de los tipos MIME de OpenDocument.
enum string openDocumentMimePrefix = "application/vnd.oasis.opendocument";

/// Manifiesto de ASiC-E con XAdES.
enum string asicManifestName = "META-INF/manifest.xml";
/// Archivo de firmas de OpenDocument.
enum string openDocumentSignaturesName = "META-INF/documentsignatures.xml";
/// Plantilla del nombre del archivo de firmas XAdES de ASiC-E.
enum string asicXadesSignatureTemplate = "META-INF/signatures001.xml";

/// Raíz de un archivo de firmas ASiC nuevo.
enum string asicSignaturesRoot = `<asic:XAdESSignatures xmlns:asic="` ~ asicNamespace ~ `"/>`;
/// Raíz de un archivo de firmas OpenDocument nuevo.
enum string openDocumentSignaturesRoot = `<document-signatures xmlns="` ~ openDocumentSignaturesNamespace ~ `"/>`;

/// Entradas de un contenedor ya clasificadas (ASiCContent de DSS).
struct ContainerContent {
  /// mimetype, si lo tiene.
  ZipEntry mimetype;
  bool hasMimetype;
  /// Archivos fuera de META-INF: lo que firman las firmas ASiC.
  ZipEntry[] signedDocuments;
  /// META-INF/*signature*.xml (XAdES) o *.p7s (CAdES).
  ZipEntry[] signatureDocuments;
  /// META-INF/manifest.xml o META-INF/ASiCManifest*.xml.
  ZipEntry[] manifestDocuments;
  /// META-INF/timestamp*.tst (ASiC-S con sello).
  ZipEntry[] timestampDocuments;
  /// Otros archivos de META-INF.
  ZipEntry[] otherDocuments;

  /// Tipo MIME declarado en mimetype, o null.
  string mimeType() const pure @safe {
    return hasMimetype ? cast(string) mimetype.content : null;
  }

  bool isOpenDocument() const pure @safe {
    return mimeType.startsWith(openDocumentMimePrefix);
  }

  /// Todas las entradas en el orden en que DSS las escribe (ASiCContent.getAllDocuments).
  ZipEntry[] allEntries() const pure @safe {
    ZipEntry[] entries;
    if (hasMimetype) entries ~= mimetype;
    entries ~= signedDocuments.dup ~ signatureDocuments.dup ~ manifestDocuments.dup ~ timestampDocuments.dup
      ~ otherDocuments.dup;
    return entries;
  }
}

/// La entrada es un archivo de firma (ASiCUtils.isSignature: META-INF, «signature», sin «Manifest»).
bool isSignatureEntry(string name) pure @safe {
  return name.startsWith("META-INF/") && name.canFind("signature") && !name.canFind("Manifest");
}

/**
 * Clasifica las entradas como DSS: con `cades`, los archivos de firma son los .p7s y los
 * manifiestos los ASiCManifest*.xml; si no, los .xml y META-INF/manifest.xml.
 */
ContainerContent classifyContainer(const ZipEntry[] entries, bool cades = false) pure @safe {
  ContainerContent content;
  foreach (entry; entries) {
    string name = entry.name;
    if (name.endsWith("/")) continue;
    if (name.startsWith("META-INF/")) {
      bool signature = isSignatureEntry(name) && name.endsWith(cades ? ".p7s" : ".xml");
      bool manifest = cades ? name.startsWith("META-INF/ASiCManifest") && name.endsWith(".xml")
        : name == asicManifestName;
      if (signature) content.signatureDocuments ~= entry;
      else if (manifest) content.manifestDocuments ~= entry;
      else if (name.startsWith("META-INF/timestamp") && name.endsWith(".tst")) content.timestampDocuments ~= entry;
      else content.otherDocuments ~= entry;
    } else if (name == "mimetype") {
      content.mimetype = entry;
      content.hasMimetype = true;
    } else {
      content.signedDocuments ~= entry;
    }
  }
  return content;
}

/// Tipo MIME de un archivo por su nombre, como MimeType.fromFileName de DSS.
string mimeTypeForName(string name) pure @safe {
  switch (extension(name).toLower) {
    case ".txt": return "text/plain";
    case ".gif": return "image/gif";
    case ".svg": return "image/svg+xml";
    case ".html", ".htm": return "text/html";
    case ".odt": return "application/vnd.oasis.opendocument.text";
    case ".ods": return "application/vnd.oasis.opendocument.spreadsheet";
    case ".odp": return "application/vnd.oasis.opendocument.presentation";
    case ".odg": return "application/vnd.oasis.opendocument.graphics";
    default: return mimeTypeString(detectMimeType(name));
  }
}

/// META-INF/manifest.xml de ASiC-E con XAdES (ASiCEWithXAdESManifestBuilder).
string asicManifestXml(const ZipEntry[] documents) pure @safe {
  enum manifest = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";
  auto output = appender!string;
  output ~= `<?xml version="1.0" encoding="UTF-8" standalone="no"?>`;
  output ~= format(`<manifest:manifest xmlns:manifest="%s" manifest:version="1.2">`, manifest);
  output ~= format(`<manifest:file-entry manifest:full-path="/" manifest:media-type="%s"/>`, asicEMimeType);
  foreach (document; documents) {
    output ~= format(`<manifest:file-entry manifest:full-path="%s" manifest:media-type="%s"/>`,
      escapeXml(document.name), escapeXml(mimeTypeForName(document.name)));
  }
  output ~= `</manifest:manifest>`;
  return output[];
}

/**
 * Siguiente nombre libre a partir de la plantilla con «001» (getNextAvailableDocumentName
 * de DSS): empieza en la cantidad de archivos existentes más uno.
 */
string nextSignatureName(string template_, const string[] existing) pure @safe {
  import std.array : replace;
  size_t number = existing.length + 1;
  while (true) {
    string candidate = template_.replace("001", format("%03d", number));
    if (!existing.canFind(candidate)) return candidate;
    number++;
  }
}

/// Archivos que firma una firma nueva de ASiC: los documentos firmados, con su tipo MIME.
XadesFile[] asicSignedFiles(const ContainerContent content) pure @safe {
  XadesFile[] files;
  foreach (document; content.signedDocuments) files ~= XadesFile(document.name, document.content, mimeTypeForName(document.name));
  return files;
}

/**
 * Lo que firma una firma de OpenDocument (OpenDocumentSupportUtils.getOpenDocumentCoverage):
 * los documentos, manifiestos, sellos y otros archivos de META-INF y el mimetype, sin las
 * firmas ni external-data/.
 */
XadesFile[] openDocumentSignedFiles(const ContainerContent content) pure @safe {
  XadesFile[] files;
  const(ZipEntry)[] covered = content.signedDocuments ~ content.manifestDocuments ~ content.timestampDocuments
    ~ content.otherDocuments;
  if (content.hasMimetype) covered ~= content.mimetype;
  foreach (entry; covered) {
    if (entry.name.startsWith("external-data/")) continue;
    files ~= XadesFile(entry.name, entry.content, mimeTypeForName(entry.name));
  }
  return files;
}

/**
 * Contenedor ASiC-E nuevo para los documentos, sin firmas todavía: mimetype, documentos y
 * manifiesto.
 *
 * Throws: Exception si hay nombres repetidos o no hay documentos.
 */
ContainerContent newAsicEContainer(const ZipEntry[] documents) pure @safe {
  enforce(documents.length, "No hay documentos que poner en el contenedor ASiC");
  ContainerContent content;
  content.mimetype = ZipEntry("mimetype", cast(immutable(ubyte)[]) asicEMimeType, true);
  content.hasMimetype = true;
  string[] names;
  foreach (document; documents) {
    enforce(!names.canFind(document.name), format("Hay dos documentos con el nombre «%s»", document.name));
    enforce(isSafeEntryName(document.name) && !document.name.startsWith("META-INF/") && document.name != "mimetype",
      format("El nombre «%s» no puede ir en un contenedor ASiC", document.name));
    names ~= document.name;
    content.signedDocuments ~= ZipEntry(document.name, document.content, false);
  }
  content.manifestDocuments = [ZipEntry(asicManifestName, cast(immutable(ubyte)[]) asicManifestXml(documents), false)];
  return content;
}

/// El contenedor con el archivo de firma `name` reemplazado o añadido; `content` no cambia.
ContainerContent withSignatureDocument(ContainerContent content, string name, immutable(ubyte)[] signature)
    pure @safe {
  // La lista se copia: la del contenedor recibido la comparten sus otras copias.
  content.signatureDocuments = content.signatureDocuments.dup;
  foreach (ref existing; content.signatureDocuments) {
    if (existing.name == name) {
      existing.content = signature;
      return content;
    }
  }
  content.signatureDocuments ~= ZipEntry(name, signature, false);
  return content;
}

/// Resuelve las referencias de una firma del contenedor a sus archivos (URI con escapes).
ExternalResolver containerResolver(const ContainerContent content) pure @safe {
  auto entries = content.allEntries();
  return (string uri) @safe => entryContent(entries, uri);
}

/// Escribe el contenedor en el orden de DSS, con el mimetype sin comprimir.
immutable(ubyte)[] writeContainer(const ContainerContent content, SysTime time) @safe {
  auto entries = content.allEntries();
  foreach (ref entry; entries) entry.stored = entry.name == "mimetype";
  return writeZip(entries, time);
}

@("should classify container entries and number the next signature file like DSS")
unittest {
  ZipEntry[] entries = [
    ZipEntry("mimetype", cast(immutable(ubyte)[]) asicEMimeType, true),
    ZipEntry("contrato.pdf", cast(immutable(ubyte)[]) "pdf"),
    ZipEntry("META-INF/manifest.xml", cast(immutable(ubyte)[]) "<m/>"),
    ZipEntry("META-INF/signatures001.xml", cast(immutable(ubyte)[]) "<s/>"),
    ZipEntry("META-INF/signature001.p7s", cast(immutable(ubyte)[]) "p7s"),
  ];
  auto content = classifyContainer(entries);
  assert(content.mimeType == asicEMimeType && !content.isOpenDocument);
  assert(content.signedDocuments.length == 1 && content.signedDocuments[0].name == "contrato.pdf");
  assert(content.signatureDocuments.length == 1 && content.manifestDocuments.length == 1);
  assert(content.otherDocuments[0].name == "META-INF/signature001.p7s");
  assert(nextSignatureName(asicXadesSignatureTemplate, ["META-INF/signatures001.xml"]) == "META-INF/signatures002.xml");
  assert(nextSignatureName(asicXadesSignatureTemplate, []) == asicXadesSignatureTemplate);
  auto cades = classifyContainer(entries, true);
  assert(cades.signatureDocuments[0].name == "META-INF/signature001.p7s");
}

@("should build a new ASiC-E manifest listing each document with its media type")
unittest {
  auto content = newAsicEContainer([ZipEntry("a b.pdf", cast(immutable(ubyte)[]) "x")]);
  string manifest = cast(string) content.manifestDocuments[0].content;
  assert(manifest.canFind(`manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"`));
  assert(manifest.canFind(`manifest:full-path="a b.pdf" manifest:media-type="application/pdf"`));
  import std.datetime.systime : Clock;
  auto written = readZip(writeContainer(content, Clock.currTime));
  assert(written[0].name == "mimetype" && written[0].stored);
  assert(written[1].name == "a b.pdf" && written[2].name == asicManifestName);
}
