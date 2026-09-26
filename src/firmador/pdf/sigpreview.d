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
 * Vista previa de la firma visible (SignaturePreviewGenerator en la versión Java). En
 * lugar de imitar el dibujo, se prepara la firma de verdad (firmador.pdf.pades) sobre una
 * página en blanco del mismo tamaño y rotación que la de destino y se dibuja con fondo
 * transparente: la vista previa es exactamente la apariencia que quedará en el PDF.
 *
 * Las posiciones de la ventana son «visuales»: puntos desde la esquina superior izquierda
 * de la página tal como se ve (con /Rotate aplicado), que es como las interpreta la firma
 * visible (originX, originY).
 */
module firmador.pdf.sigpreview;

import std.array : appender;
import std.datetime.systime : Clock;
import std.format : format;
import std.math : ceil, floor;

import firmador.pdf.appearance : computeLayout;
import firmador.pdf.engine;
import firmador.pdf.pades;

/// Rectángulo en coordenadas visuales (puntos, origen arriba a la izquierda).
struct VisualRect {
  float left, top, width, height;
}

/**
 * Rectángulo del espacio de usuario del PDF (origen abajo a la izquierda) visto en la
 * página con esa caja y rotación (horaria, 0, 90, 180 o 270).
 */
VisualRect visualRect(PdfRect rect, PdfRect box, int rotation) pure nothrow @safe @nogc {
  float[2] map(float x, float y) {
    switch (rotation) {
      case 90: return [y - box.y0, x - box.x0];
      case 180: return [box.x1 - x, y - box.y0];
      case 270: return [box.y1 - y, box.x1 - x];
      default: return [x - box.x0, box.y1 - y];
    }
  }
  auto first = map(rect.x0, rect.y0);
  auto second = map(rect.x1, rect.y1);
  float left = first[0] < second[0] ? first[0] : second[0];
  float top = first[1] < second[1] ? first[1] : second[1];
  float right = first[0] > second[0] ? first[0] : second[0];
  float bottom = first[1] > second[1] ? first[1] : second[1];
  return VisualRect(left, top, right - left, bottom - top);
}

/// Tamaño visual (ancho y alto como se ve) de una caja con esa rotación.
float[2] visualSize(PdfRect box, int rotation) pure nothrow @safe @nogc {
  return rotation == 90 || rotation == 270 ? [box.height, box.width] : [box.width, box.height];
}

/**
 * PDF con esos objetos (el primero, 1 0 R, es el catálogo) y la tabla de referencias
 * correcta para que admita una actualización incremental.
 */
immutable(ubyte)[] minimalPdf(const string[] objects) pure @safe {
  auto output = appender!string;
  size_t[] offsets;
  output ~= "%PDF-1.7\n";
  foreach (body; objects) {
    offsets ~= output[].length;
    output ~= format("%d 0 obj\n%s\nendobj\n", offsets.length, body);
  }
  size_t xref = output[].length;
  output ~= format("xref\n0 %d\n0000000000 65535 f \n", offsets.length + 1);
  foreach (offset; offsets) output ~= format("%010d 00000 n \n", offset);
  output ~= format("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", offsets.length + 1, xref);
  return cast(immutable(ubyte)[]) output[];
}

/// PDF de una sola página en blanco con esa MediaBox y rotación (minimalPdf).
immutable(ubyte)[] blankPagePdf(PdfRect mediaBox, int rotation) pure @safe {
  return minimalPdf(["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    format("<< /Type /Page /Parent 2 0 R /MediaBox [%.3f %.3f %.3f %.3f] /Rotate %d /Resources << >> >>",
    mediaBox.x0, mediaBox.y0, mediaBox.x1, mediaBox.y1, rotation)]);
}

/// Apariencia de la firma dibujada, con su tamaño en puntos visuales.
struct SignaturePreview {
  PageRaster raster;
  float widthPoints;
  float heightPoints;
}

/**
 * Dibuja la apariencia de la firma visible como quedará en una página con esa geometría,
 * a la escala dada, con fondo transparente.
 *
 * Throws: PdfException si mupdf no puede preparar o dibujar la página.
 */
SignaturePreview renderSignaturePreview(VisibleSignature visible, const PageGeometry geometry, float scale) @trusted {
  visible.originX = 0;
  visible.originY = 0;
  PageGeometry blankGeometry = geometry;
  blankGeometry.cropBox = geometry.mediaBox;
  auto layout = computeLayout(layoutInput(visible, blankGeometry), encoderFor(visible));
  auto box = visualRect(layout.annotationRect, geometry.mediaBox, geometry.rotation);

  PadesSignatureParameters parameters;
  parameters.pageIndex = 0;
  parameters.visible = true;
  parameters.appearance = visible;
  parameters.signingTime = Clock.currTime;
  auto prepared = preparePadesSignature(blankPagePdf(geometry.mediaBox, geometry.rotation), parameters);
  auto document = PdfDocument.open(prepared.bytes);
  scope (exit) document.close();
  auto page = document.render(0, scale, true);

  int left = cast(int) floor(box.left * scale);
  int top = cast(int) floor(box.top * scale);
  int right = cast(int) ceil((box.left + box.width) * scale);
  int bottom = cast(int) ceil((box.top + box.height) * scale);
  left = left < 0 ? 0 : left;
  top = top < 0 ? 0 : top;
  right = right > page.width ? page.width : right;
  bottom = bottom > page.height ? page.height : bottom;
  SignaturePreview preview;
  preview.widthPoints = box.width;
  preview.heightPoints = box.height;
  preview.raster.width = right > left ? right - left : 1;
  preview.raster.height = bottom > top ? bottom - top : 1;
  preview.raster.rgb = new ubyte[cast(size_t) preview.raster.width * preview.raster.height * 3];
  preview.raster.alpha = new ubyte[cast(size_t) preview.raster.width * preview.raster.height];
  foreach (row; 0 .. bottom - top) {
    size_t source = cast(size_t) (top + row) * page.width + left;
    size_t target = cast(size_t) row * preview.raster.width;
    size_t count = right - left;
    preview.raster.rgb[target * 3 .. (target + count) * 3] = page.rgb[source * 3 .. (source + count) * 3];
    preview.raster.alpha[target .. target + count] = page.alpha[source .. source + count];
  }
  return preview;
}

@("should map user space corners to the visible page for every page rotation")
unittest {
  auto box = PdfRect(0, 0, 612, 792);
  auto rect = PdfRect(10, 700, 110, 750);
  assert(visualRect(rect, box, 0) == VisualRect(10, 42, 100, 50));
  assert(visualRect(rect, box, 90) == VisualRect(700, 10, 50, 100));
  assert(visualRect(rect, box, 180) == VisualRect(502, 700, 100, 50));
  assert(visualRect(rect, box, 270) == VisualRect(42, 502, 50, 100));
  assert(visualSize(box, 90) == [792f, 612f]);
}

@("should render a blank page PDF that mupdf opens with its size and rotation")
unittest {
  auto pdf = blankPagePdf(PdfRect(0, 0, 200, 100), 90);
  auto document = PdfDocument.open(pdf);
  scope (exit) document.close();
  assert(document.pageCount == 1);
  auto geometry = document.pageGeometry(0);
  assert(geometry.rotation == 90 && geometry.mediaBox.width == 200);
  auto raster = document.render(0, 1, true);
  assert(raster.width == 100 && raster.height == 200);
  assert(raster.alpha.length == 100 * 200 && raster.alpha[0] == 0);
}

@("should draw the visible signature appearance with opaque text pixels when previewing it")
unittest {
  VisibleSignature visible;
  visible.text = "FIRMA DE PRUEBA\nLínea 2";
  visible.fontSize = 10;
  PageGeometry geometry;
  geometry.mediaBox = PdfRect(0, 0, 612, 792);
  geometry.cropBox = geometry.mediaBox;
  auto preview = renderSignaturePreview(visible, geometry, 2);
  assert(preview.widthPoints > 60 && preview.heightPoints > 20);
  assert(preview.raster.width >= cast(int) (preview.widthPoints * 2) - 1);
  size_t opaque;
  foreach (value; preview.raster.alpha) if (value > 128) opaque++;
  assert(opaque > 50, "La vista previa de la firma no dibujó el texto");
}
