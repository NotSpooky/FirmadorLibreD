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
 * Vista previa de documentos (previewers de la versión Java): los PDF se muestran con
 * mupdf, los OpenDocument y OOXML convertidos a PDF con LibreOffice (soffice --headless
 * --convert-to pdf) si está instalado, y lo demás con resources/nonPreview.pdf.
 */
module firmador.previewers.previewer;

import std.array : array;
import std.exception : enforce;
import std.file : dirEntries, exists, mkdirRecurse, read, rmdirRecurse, SpanMode, tempDir, write;
import std.format : format;
import std.logger : error, info;
import std.path : buildPath, extension;
import std.process : Config, environment, execute;
import std.uuid : randomUUID;

import firmador.documents.mimetype;
import firmador.pdf.engine;
import firmador.settings : Settings;

/// De dónde sale el PDF de la vista previa.
enum PreviewKind {
  /// El documento es un PDF.
  pdf,
  /// Documento de oficina convertido a PDF con LibreOffice.
  office,
  /// Sin vista previa: la página de resources/nonPreview.pdf.
  none,
}

/// Vista previa de un documento: un PDF (el documento, su conversión o nonPreview.pdf) abierto con mupdf.
final class Previewer {
  private PreviewKind kind;
  private float scale;
  private string sofficePath;
  private PdfDocument document;

  /// `sofficePath` sólo se usa con PreviewKind.office.
  this(PreviewKind kind, float scale, string sofficePath = null) pure @safe {
    this.kind = kind;
    this.scale = scale;
    this.sofficePath = sofficePath;
  }

  /**
   * Prepara la vista previa del contenido.
   *
   * Throws: Exception si no se puede leer o convertir.
   */
  void load(immutable(ubyte)[] content, string name) @safe {
    close();
    immutable(ubyte)[] pdf;
    final switch (kind) {
      case PreviewKind.pdf: pdf = content; break;
      case PreviewKind.office: pdf = convertWithSoffice(sofficePath, content, name); break;
      case PreviewKind.none: pdf = cast(immutable(ubyte)[]) import("nonPreview.pdf"); break;
    }
    document = PdfDocument.open(pdf);
  }

  /// Páginas que se pueden mostrar.
  int pageCount() @safe {
    return document is null ? 0 : document.pageCount();
  }

  /// Página (desde 0) rasterizada con la escala de los ajustes.
  PageRaster renderPage(int index) @safe {
    return renderPage(index, scale);
  }

  /// Página (desde 0) rasterizada con otra escala (1 = 72 ppp), para el zoom de la ventana.
  PageRaster renderPage(int index, float pageScale) @safe {
    enforce(document !is null, "No hay documento cargado para la vista previa");
    return document.render(index, pageScale);
  }

  /// Tamaño y rotación de la página.
  PageGeometry pageGeometry(int index) @safe {
    enforce(document !is null, "No hay documento cargado para la vista previa");
    return document.pageGeometry(index);
  }

  /// Anotaciones del PDF (PdfDocument.annotations); ninguna si la vista previa no es el documento mismo.
  PdfAnnotation[] annotations() @safe {
    return kind == PreviewKind.pdf && document !is null ? document.annotations() : null;
  }

  /// Se puede ubicar la firma visible sobre la vista previa (showSignLabelPreview): sólo en los PDF.
  bool showsSignaturePosition() const pure nothrow @safe @nogc {
    return kind == PreviewKind.pdf;
  }

  /// Libera el documento.
  void close() @safe {
    if (document !is null) {
      document.close();
      document = null;
    }
  }
}

/**
 * Convierte un documento de oficina a PDF con LibreOffice (soffice --headless
 * --convert-to pdf) en un directorio temporal que se borra al terminar.
 *
 * Throws: Exception si LibreOffice no produjo el PDF.
 */
private immutable(ubyte)[] convertWithSoffice(string sofficePath, immutable(ubyte)[] content, string name) @trusted {
  auto type = detectMimeType(name);
  // Filtro de exportación según la aplicación de LibreOffice que abre el documento.
  string filter = "pdf:writer_pdf_Export";
  if (type == SupportedMimeType.XLSX || type == SupportedMimeType.ODS) filter = "pdf:calc_pdf_Export";
  if (type == SupportedMimeType.ODP || type == SupportedMimeType.PPTX) filter = "pdf:draw_pdf_Export";
  string workDirectory = buildPath(tempDir, "firmadorlibre-" ~ randomUUID().toString);
  mkdirRecurse(workDirectory);
  scope (exit) rmdirRecurse(workDirectory);
  string source = buildPath(workDirectory, "documento" ~ extension(name));
  write(source, content);
  string outputDirectory = buildPath(workDirectory, "pdf");
  mkdirRecurse(outputDirectory);
  info("Convirtiendo ", name, " a PDF con LibreOffice para la vista previa");
  auto result = execute([sofficePath, "--headless", "--convert-to", filter, "--outdir", outputDirectory, source],
    null, Config.none, size_t.max, workDirectory);
  info("LibreOffice terminó con el código ", result.status, ": ", result.output);
  auto converted = dirEntries(outputDirectory, "*.pdf", SpanMode.shallow).array;
  if (converted.length == 0) {
    error("No se encontró el PDF convertido por LibreOffice para ", name);
    throw new Exception(format("LibreOffice no pudo convertir «%s» a PDF", name));
  }
  return cast(immutable(ubyte)[]) read(converted[0].name);
}

/**
 * Ruta de soffice: la de los ajustes o, si está vacía, la habitual del sistema
 * (FLATPAKSOFFICEPATH dentro de flatpak), como Settings.getSofficePath.
 */
string resolveSofficePath(const Settings settings) @safe {
  if (settings.sofficePath.length) return settings.sofficePath;
  version (OSX) {
    return "/Applications/LibreOffice.app/Contents/MacOS/soffice";
  } else version (Windows) {
    return environment.get("SystemDrive", "C:") ~ `\Program Files\LibreOffice\program\soffice.exe`;
  } else {
    string flatpak = environment.get("FLATPAKSOFFICEPATH", "");
    return flatpak.length ? flatpak : "/usr/bin/soffice";
  }
}

/// Vista previa adecuada al tipo de documento (PreviewerManager.getPreviewManager).
Previewer previewerFor(SupportedMimeType type, const Settings settings) @safe {
  float scale = settings.pDFImgScaleFactor;
  if (isPdf(type)) return new Previewer(PreviewKind.pdf, scale);
  if (isOpenXml(type) || isOpenDocument(type)) {
    string soffice = resolveSofficePath(settings);
    if (exists(soffice)) return new Previewer(PreviewKind.office, scale, soffice);
  }
  return new Previewer(PreviewKind.none, scale);
}
