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

/// Vista previa de un documento.
interface Previewer {
  /**
   * Prepara la vista previa del contenido.
   *
   * Throws: Exception si no se puede leer o convertir.
   */
  void load(immutable(ubyte)[] content, string name) @safe;

  /// Páginas que se pueden mostrar.
  int pageCount() @safe;

  /// Página (desde 0) rasterizada con la escala de los ajustes.
  PageRaster renderPage(int index) @safe;

  /// Página (desde 0) rasterizada con otra escala (1 = 72 ppp), para el zoom de la ventana.
  PageRaster renderPage(int index, float scale) @safe;

  /// Tamaño y rotación de la página.
  PageGeometry pageGeometry(int index) @safe;

  /// Se puede ubicar la firma visible sobre la vista previa (showSignLabelPreview).
  bool showsSignaturePosition() const @safe;

  /// Libera el documento.
  void close() @safe;
}

/// Vista previa de un PDF.
class PdfPreviewer : Previewer {
  private PdfDocument document;
  private float scale;

  this(float scale) pure @safe {
    this.scale = scale;
  }

  void load(immutable(ubyte)[] content, string name) @safe {
    close();
    document = PdfDocument.open(content);
  }

  int pageCount() @safe {
    return document is null ? 0 : document.pageCount();
  }

  PageRaster renderPage(int index) @safe {
    return renderPage(index, scale);
  }

  PageRaster renderPage(int index, float pageScale) @safe {
    enforce(document !is null, "No hay documento cargado para la vista previa");
    return document.render(index, pageScale);
  }

  PageGeometry pageGeometry(int index) @safe {
    enforce(document !is null, "No hay documento cargado para la vista previa");
    return document.pageGeometry(index);
  }

  bool showsSignaturePosition() const @safe {
    return true;
  }

  void close() @safe {
    if (document !is null) {
      document.close();
      document = null;
    }
  }
}

/// Vista previa de documentos de oficina convertidos a PDF con LibreOffice.
final class SofficePreviewer : PdfPreviewer {
  private string sofficePath;

  this(float scale, string sofficePath) pure @safe {
    super(scale);
    this.sofficePath = sofficePath;
  }

  override void load(immutable(ubyte)[] content, string name) @trusted {
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
    super.load(cast(immutable(ubyte)[]) read(converted[0].name), name);
  }

  override bool showsSignaturePosition() const pure @safe {
    return false;
  }
}

/// Vista previa genérica: la página de resources/nonPreview.pdf.
final class NonPreviewer : PdfPreviewer {
  this(float scale) pure @safe {
    super(scale);
  }

  override void load(immutable(ubyte)[] content, string name) @safe {
    super.load(cast(immutable(ubyte)[]) import("nonPreview.pdf"), name);
  }

  override bool showsSignaturePosition() const pure @safe {
    return false;
  }
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
  if (isPdf(type)) return new PdfPreviewer(scale);
  if (isOpenXml(type) || isOpenDocument(type)) {
    string soffice = resolveSofficePath(settings);
    if (exists(soffice)) return new SofficePreviewer(scale, soffice);
  }
  return new NonPreviewer(scale);
}
