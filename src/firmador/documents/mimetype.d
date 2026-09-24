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
 * Tipos de documento que reconoce la aplicación (SupportedMimeTypeEnum y
 * MimeTypeDetector): por la extensión del nombre, como la versión Java, y por el tipo MIME
 * que envían las conexiones externas.
 */
module firmador.documents.mimetype;

import std.algorithm : canFind, endsWith;
import std.string : toLower;
import std.uni : icmp;

/// Tipo de documento; el nombre de cada valor es el que viaja en JSON (String.valueOf del enum).
enum SupportedMimeType {
  BINARY, XML, XMLA, ODT, ODS, ODP, ODG, PDF, DOCX, XLSX, PPTX, DOC, PPT, XLS, JSON, ASICE, ZIP, JPG, PNG,
}

private struct MimeInfo {
  SupportedMimeType type;
  string mimeType;
  string[] extensions;
}

private immutable MimeInfo[] mimeInfos = [
  MimeInfo(SupportedMimeType.BINARY, "application/octet-stream", []),
  MimeInfo(SupportedMimeType.XML, "text/xml", ["xml"]),
  MimeInfo(SupportedMimeType.XMLA, "application/xml", ["xml"]),
  MimeInfo(SupportedMimeType.ODT, "application/vnd.oasis.opendocument.text", ["odt"]),
  MimeInfo(SupportedMimeType.ODS, "application/vnd.oasis.opendocument.spreadsheet", ["ods"]),
  MimeInfo(SupportedMimeType.ODP, "application/vnd.oasis.opendocument.presentation", ["odp"]),
  MimeInfo(SupportedMimeType.ODG, "application/vnd.oasis.opendocument.graphics", ["odg"]),
  MimeInfo(SupportedMimeType.PDF, "application/pdf", ["pdf"]),
  MimeInfo(SupportedMimeType.DOCX, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ["docx"]),
  MimeInfo(SupportedMimeType.XLSX, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ["xlsx"]),
  MimeInfo(SupportedMimeType.PPTX, "application/vnd.openxmlformats-officedocument.presentationml.presentation", ["pptx"]),
  MimeInfo(SupportedMimeType.DOC, "application/msword", ["doc"]),
  MimeInfo(SupportedMimeType.PPT, "application/vnd.ms-powerpoint", ["ppt"]),
  MimeInfo(SupportedMimeType.XLS, "application/vnd.ms-excel", ["xls"]),
  MimeInfo(SupportedMimeType.JSON, "application/json", ["json"]),
  MimeInfo(SupportedMimeType.ASICE, "application/vnd.etsi.asic-e+zip", ["asice"]),
  MimeInfo(SupportedMimeType.ZIP, "application/zip", ["zip"]),
  MimeInfo(SupportedMimeType.JPG, "image/jpeg", ["jpg", "jpeg"]),
  MimeInfo(SupportedMimeType.PNG, "image/png", ["png"]),
];

private const(MimeInfo) infoFor(SupportedMimeType type) pure nothrow @safe @nogc {
  foreach (ref info; mimeInfos) if (info.type == type) return info;
  return mimeInfos[0];
}

/// Tipo MIME del tipo de documento.
string mimeTypeString(SupportedMimeType type) pure nothrow @safe @nogc {
  return infoFor(type).mimeType;
}

/// Extensión principal (sin punto), o null para BINARY.
string extensionOf(SupportedMimeType type) pure nothrow @safe @nogc {
  auto extensions = infoFor(type).extensions;
  return extensions.length ? extensions[0] : null;
}

/// Tipo según la extensión del nombre; BINARY si no se reconoce.
SupportedMimeType detectMimeType(string fileName) pure @safe {
  if (fileName is null) return SupportedMimeType.BINARY;
  string lower = fileName.toLower;
  foreach (info; mimeInfos) {
    foreach (extension; info.extensions) {
      if (lower.endsWith("." ~ extension)) return info.type;
    }
  }
  return SupportedMimeType.BINARY;
}

/// Tipo según su nombre MIME; BINARY si no coincide.
SupportedMimeType mimeTypeFromString(string mimeType) pure @safe {
  if (mimeType is null) return SupportedMimeType.BINARY;
  foreach (info; mimeInfos) if (icmp(info.mimeType, mimeType) == 0) return info.type;
  return SupportedMimeType.BINARY;
}

bool isPdf(SupportedMimeType type) pure nothrow @safe @nogc { return type == SupportedMimeType.PDF; }
bool isXml(SupportedMimeType type) pure nothrow @safe @nogc {
  return type == SupportedMimeType.XML || type == SupportedMimeType.XMLA;
}
bool isOpenDocument(SupportedMimeType type) pure nothrow @safe @nogc {
  return type == SupportedMimeType.ODT || type == SupportedMimeType.ODS || type == SupportedMimeType.ODP
    || type == SupportedMimeType.ODG;
}
bool isOpenXml(SupportedMimeType type) pure nothrow @safe @nogc {
  return type == SupportedMimeType.DOCX || type == SupportedMimeType.XLSX || type == SupportedMimeType.PPTX;
}
bool isOldOffice(SupportedMimeType type) pure nothrow @safe @nogc {
  return type == SupportedMimeType.DOC || type == SupportedMimeType.PPT || type == SupportedMimeType.XLS;
}
bool isAsic(SupportedMimeType type) pure nothrow @safe @nogc { return type == SupportedMimeType.ASICE; }
bool isJson(SupportedMimeType type) pure nothrow @safe @nogc { return type == SupportedMimeType.JSON; }
bool isZip(SupportedMimeType type) pure nothrow @safe @nogc { return type == SupportedMimeType.ZIP; }
bool isImage(SupportedMimeType type) pure nothrow @safe @nogc {
  return type == SupportedMimeType.JPG || type == SupportedMimeType.PNG;
}

/// No se previsualiza como documento: XML, OpenDocument, OOXML y Office antiguo (withoutVisualization).
bool withoutVisualization(SupportedMimeType type) pure nothrow @safe @nogc {
  return isXml(type) || isOpenDocument(type) || isOpenXml(type) || isOldOffice(type);
}

@("should detect the document type from the extension ignoring case")
unittest {
  assert(detectMimeType("Contrato.PDF") == SupportedMimeType.PDF);
  assert(detectMimeType("factura.xml") == SupportedMimeType.XML);
  assert(detectMimeType("foto.jpeg") == SupportedMimeType.JPG);
  assert(detectMimeType("sin-extension") == SupportedMimeType.BINARY);
  assert(mimeTypeFromString("APPLICATION/PDF") == SupportedMimeType.PDF);
  assert(extensionOf(SupportedMimeType.BINARY) is null);
  assert(withoutVisualization(SupportedMimeType.DOCX) && !withoutVisualization(SupportedMimeType.PDF));
}
