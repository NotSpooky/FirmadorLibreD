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
 * Diseño de la firma visible, sin E/S: la caja, la posición del texto y de la imagen y el
 * flujo de contenido de la apariencia. Reproduce SignatureFieldDimensionAndPositionBuilder
 * y NativePdfBoxVisibleSignatureDrawer de DSS 6.4 con los parámetros que usaba Firmador
 * (texto según la fuente, imagen estirada, relleno de 5 puntos, texto centrado en vertical
 * y alineado a la izquierda), para que las firmas y la previsualización
 * (firmador.gui.desktop.signpreview) queden donde quedaban. El origen es la esquina
 * superior izquierda de la página, como en DSS.
 */
module firmador.pdf.appearance;

import std.algorithm : map, splitter;
import std.array : appender, array;
import std.format : format;
import std.math : abs;
import std.string : indexOf;

import firmador.pdf.engine : PdfRect;
import firmador.settings : Rgba, SignerTextPosition, SignatureRotation, FontFamily, FontStyle;

/// Relleno alrededor del texto (DEFAULT_PADDING de DSS).
enum float textPadding = 5;

/// Resolución por omisión de una imagen sin metadatos (DEFAULT_DPI de ImageUtils).
enum int defaultImageDpi = 96;

/// Métricas de la fuente: ancho de cada código (milésimas de em) y alto de su caja.
struct FontMetrics {
  float[256] widths = 0;
  float boundingBoxHeight = 1156;
}

/// Tamaño y resolución de la imagen de la firma.
struct ImageSize {
  int width;
  int height;
  int dpiX = defaultImageDpi;
  int dpiY = defaultImageDpi;
}

/// Parámetros de la firma visible.
struct VisibleSignatureInput {
  /// Texto (líneas separadas por \n); vacío para una firma sólo con imagen.
  string text;
  SignerTextPosition position = SignerTextPosition.right;
  float fontSize = 7;
  FontMetrics metrics;
  Rgba textColor = Rgba(0, 0, 0, 255);
  Rgba backgroundColor = Rgba(255, 255, 255, 0);
  bool hasImage;
  ImageSize image;
  /// Origen del campo desde la esquina superior izquierda de la página, en puntos.
  float originX = 0;
  float originY = 0;
  SignatureRotation rotation = SignatureRotation.automatic;
  int pageRotation;
  /// Caja de la página (MediaBox, la que usa DSS).
  PdfRect pageBox;
}

/// Resultado del diseño, con los mismos campos que SignatureFieldDimensionAndPosition.
struct SignatureLayout {
  int globalRotation;
  float boxX = 0, boxY = 0, boxWidth = 0, boxHeight = 0;
  float textX = 0, textY = 0, textWidth = 0, textHeight = 0;
  float textBoxX = 0, textBoxY = 0, textBoxWidth = 0, textBoxHeight = 0;
  float imageX = 0, imageY = 0, imageWidth = 0, imageHeight = 0;
  float imageBoxX = 0, imageBoxY = 0, imageBoxWidth = 0, imageBoxHeight = 0;
  string[] lines;
  /// Rectángulo del campo en coordenadas de la página (/Rect).
  PdfRect annotationRect;
}

/// Rotación efectiva (ImageRotationUtils.getRotation): 0 si no se rota.
int globalRotation(SignatureRotation rotation, int pageRotation) pure nothrow @safe @nogc {
  int result = 360;
  final switch (rotation) {
    case SignatureRotation.none: result = 360; break;
    case SignatureRotation.automatic: result = 360 - pageRotation; break;
    case SignatureRotation.rotate90: result = 90; break;
    case SignatureRotation.rotate180: result = 180; break;
    case SignatureRotation.rotate270: result = 270; break;
  }
  return result % 360;
}

/// Líneas del texto como String.split("\\r?\\n") de Java, que descarta las vacías del final.
string[] javaLines(string text) pure @safe {
  auto parts = text.splitter('\n').map!(line => line.length && line[$ - 1] == '\r' ? line[0 .. $ - 1] : line).array;
  while (parts.length && parts[$ - 1].length == 0) parts = parts[0 .. $ - 1];
  return parts;
}

/// Ancho de una línea ya codificada en la fuente, con el tamaño dado.
float lineWidth(const FontMetrics metrics, const(ubyte)[] encoded, float fontSize) pure nothrow @safe @nogc {
  float total = 0;
  foreach (code; encoded) total += metrics.widths[code];
  return total / 1000 * fontSize;
}

/// Alto de línea (getHeight de PdfBoxDSSFontMetrics: la caja de la fuente escalada).
float lineHeight(const FontMetrics metrics, float fontSize) pure nothrow @safe @nogc {
  return metrics.boundingBoxHeight / 1000 * fontSize;
}

/**
 * Diseño completo del campo (build de SignatureFieldDimensionAndPositionBuilder).
 * `encode` convierte cada línea a los códigos de la fuente.
 */
SignatureLayout computeLayout(const VisibleSignatureInput input, scope ubyte[] delegate(string) pure @safe encode)
    pure @safe {
  SignatureLayout layout;
  layout.globalRotation = globalRotation(input.rotation, input.pageRotation);
  bool swap = layout.globalRotation == 90 || layout.globalRotation == 270;
  float pageWidth = input.pageBox.width;
  float pageHeight = input.pageBox.height;
  if (swap) {
    float temporary = pageWidth;
    pageWidth = pageHeight;
    pageHeight = temporary;
  }

  // assignImageBoundaryBox
  float imageWidth = 0, imageHeight = 0;
  if (input.hasImage) {
    layout.imageWidth = input.image.width;
    layout.imageHeight = input.image.height;
    imageWidth = input.image.width * (72f / input.image.dpiX);
    imageHeight = input.image.height * (72f / input.image.dpiY);
  }
  float width = imageWidth;
  float height = imageHeight;
  bool hasText = input.text.length > 0;
  if (hasText) {
    layout.lines = javaLines(input.text);
    float padding = textPadding;
    float textSize = input.fontSize;
    float longest = 0;
    foreach (line; layout.lines) {
      float measured = lineWidth(input.metrics, encode(line), textSize);
      if (measured > longest) longest = measured;
    }
    float textBoxHeight = lineHeight(input.metrics, textSize) * layout.lines.length + padding * 2;
    float textBoxWidth = longest + padding * 2;
    final switch (input.position) {
      case SignerTextPosition.left:
        width += input.hasImage || width == 0 ? textBoxWidth : 0;
        height = height > textBoxHeight ? height : textBoxHeight;
        layout.imageBoxX = width - imageWidth;
        layout.textBoxY = (height - textBoxHeight) / 2;
        layout.imageBoxY = (height - imageHeight) / 2;
        break;
      case SignerTextPosition.right:
        width += input.hasImage || width == 0 ? textBoxWidth : 0;
        height = height > textBoxHeight ? height : textBoxHeight;
        layout.textBoxX = width - textBoxWidth;
        layout.textBoxY = (height - textBoxHeight) / 2;
        layout.imageBoxY = (height - imageHeight) / 2;
        break;
      case SignerTextPosition.top:
        width = width > textBoxWidth ? width : textBoxWidth;
        height += input.hasImage || height == 0 ? textBoxHeight : 0;
        layout.textBoxY = height - textBoxHeight;
        layout.textBoxX = 0;
        layout.imageBoxX = 0;
        break;
      case SignerTextPosition.bottom:
        width = width > textBoxWidth ? width : textBoxWidth;
        height += input.hasImage || height == 0 ? textBoxHeight : 0;
        layout.imageBoxY = height - imageHeight;
        layout.textBoxX = 0;
        layout.imageBoxX = 0;
        break;
    }
    layout.textBoxWidth = textBoxWidth;
    layout.textBoxHeight = textBoxHeight;
    layout.textX = layout.textBoxX + padding;
    layout.textY = layout.textBoxY + padding;
    layout.textWidth = textBoxWidth - 2 * padding;
    layout.textHeight = textBoxHeight - 2 * padding;
  }
  if (swap) {
    float temporary = width;
    width = height;
    height = temporary;
  }
  layout.imageBoxWidth = imageWidth;
  layout.imageBoxHeight = imageHeight;
  layout.boxWidth = width;
  layout.boxHeight = height;

  // assignImagePosition con ImageScaling.STRETCH
  if (input.hasImage) {
    layout.imageX = layout.imageBoxX;
    layout.imageY = layout.imageBoxY;
    layout.imageWidth = layout.imageBoxWidth;
    layout.imageHeight = layout.imageBoxHeight;
  }

  // alignHorizontally / alignVertically con alineación NONE
  layout.boxX = input.originX;
  layout.boxY = input.originY;

  // rotateSignatureField
  switch (layout.globalRotation) {
    case 90:
      float boxX = layout.boxX;
      layout.boxX = pageHeight - layout.boxY - layout.boxWidth;
      layout.boxY = boxX;
      break;
    case 180:
      layout.boxX = pageWidth - layout.boxX - layout.boxWidth;
      layout.boxY = pageHeight - layout.boxY - layout.boxHeight;
      break;
    case 270:
      float boxX = layout.boxX;
      layout.boxX = layout.boxY;
      layout.boxY = pageWidth - boxX - layout.boxHeight;
      break;
    default:
      break;
  }

  // getAnnotationBox().toPdfPageCoordinates(pageBox), con la caja original de la página
  auto page = input.pageBox;
  layout.annotationRect = PdfRect(page.x0 + layout.boxX, page.y1 - (layout.boxY + layout.boxHeight),
    page.x0 + layout.boxX + layout.boxWidth, page.y1 - layout.boxY);
  return layout;
}

/// Tamaño natural (sin rotar) de la caja, en puntos (naturalBoxSizePt de la versión Java).
float[2] naturalBoxSize(const VisibleSignatureInput input, scope ubyte[] delegate(string) pure @safe encode)
    pure @safe {
  VisibleSignatureInput unrotated = input;
  unrotated.rotation = SignatureRotation.none;
  auto layout = computeLayout(unrotated, encode);
  return [layout.boxWidth, layout.boxHeight];
}

/// Flujo de contenido de la apariencia y los estados gráficos de opacidad que usa.
struct AppearanceContent {
  string content;
  string[] alphaNames;
  float[] alphaValues;
}

/**
 * Flujo de contenido de la apariencia (draw de NativePdfBoxVisibleSignatureDrawer):
 * rotación, fondo del texto, texto e imagen, en ese orden.
 */
AppearanceContent appearanceContent(const SignatureLayout layout, const VisibleSignatureInput input,
    scope ubyte[] delegate(string) pure @safe encode, string fontResource, string imageResource) pure @safe {
  AppearanceContent result;
  auto output = appender!string;
  float rectWidth = layout.annotationRect.width;
  float rectHeight = layout.annotationRect.height;
  switch (layout.globalRotation) {
    case 90:
      output ~= "0 -1 1 0 0 0 cm\n";
      output ~= format("1 0 0 1 %s 0 cm\n", number(-rectHeight));
      break;
    case 180:
      output ~= "-1 0 0 -1 0 0 cm\n";
      output ~= format("1 0 0 1 %s %s cm\n", number(-rectWidth), number(-rectHeight));
      break;
    case 270:
      output ~= "0 1 -1 0 0 0 cm\n";
      output ~= format("1 0 0 1 0 %s cm\n", number(-rectWidth));
      break;
    default:
      break;
  }
  string alphaState(ubyte alpha) {
    float value = alpha / 255f;
    foreach (index, existing; result.alphaValues) if (existing == value) return result.alphaNames[index];
    string stateName = format("GS%d", result.alphaNames.length + 1);
    result.alphaNames ~= stateName;
    result.alphaValues ~= value;
    return stateName;
  }
  if (layout.lines.length) {
    // setTextBackground
    auto background = input.backgroundColor;
    if (background.alpha < 255) output ~= format("/%s gs\n", alphaState(background.alpha));
    output ~= fillColor(background);
    output ~= format("%s %s %s %s re\nf\n", number(layout.textBoxX), number(layout.textBoxY),
      number(layout.textBoxWidth), number(layout.textBoxHeight));
    if (background.alpha < 255) output ~= format("/%s gs\n", alphaState(255));
    // setText
    output ~= "BT\n";
    output ~= format("/%s %s Tf\n", fontResource, number(input.fontSize));
    output ~= fillColor(input.textColor);
    if (input.textColor.alpha < 255) output ~= format("/%s gs\n", alphaState(input.textColor.alpha));
    output ~= format("%s TL\n", number(lineHeight(input.metrics, input.fontSize)));
    output ~= format("%s %s Td\n", number(layout.textX), number(layout.textHeight + layout.textY - input.fontSize));
    foreach (line; layout.lines) {
      output ~= "0 0 Td\n";
      output ~= literalString(encode(line));
      output ~= " Tj\nT*\n";
    }
    output ~= "ET\n";
    if (input.textColor.alpha < 255) output ~= format("/%s gs\n", alphaState(255));
  }
  if (input.hasImage) {
    output ~= format("q\n%s 0 0 %s %s %s cm\n/%s Do\nQ\n", number(layout.imageWidth), number(layout.imageHeight),
      number(layout.imageX), number(layout.imageY), imageResource);
  }
  result.content = output[];
  return result;
}

private string fillColor(Rgba color) pure @safe {
  if (color.red == color.green && color.green == color.blue) return format("%s g\n", number(color.red / 255f));
  return format("%s %s %s rg\n", number(color.red / 255f), number(color.green / 255f), number(color.blue / 255f));
}

/// Número PDF con hasta cuatro decimales y sin ceros sobrantes.
string number(float value) pure @safe {
  if (abs(value) < 0.00005f) return "0";
  string text = format("%.4f", value);
  while (text.length && text[$ - 1] == '0') text = text[0 .. $ - 1];
  if (text.length && text[$ - 1] == '.') text = text[0 .. $ - 1];
  return text;
}

/// Cadena literal PDF con los escapes de ( ) y \.
string literalString(const(ubyte)[] bytes) pure @safe {
  auto output = appender!string;
  output ~= '(';
  foreach (b; bytes) {
    if (b == '(' || b == ')' || b == '\\') {
      output ~= '\\';
      output ~= cast(char) b;
    } else if (b < 0x20 || b >= 0x7F) {
      output ~= format("\\%03o", b);
    } else {
      output ~= cast(char) b;
    }
  }
  output ~= ')';
  return output[];
}

/// Códigos 0x80-0x9F de WinAnsiEncoding que no coinciden con Latin-1.
private immutable dchar[32] winAnsiHigh = [
  '€', 0, '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹',
  'Œ', 0, 'Ž', 0, 0, '‘', '’', '“', '”', '•', '–', '—', '˜',
  '™', 'š', '›', 'œ', 0, 'ž', 'Ÿ',
];

/// Unicode de cada código WinAnsi (0 si no está definido).
dchar[256] winAnsiTable() pure nothrow @safe @nogc {
  dchar[256] table = 0;
  foreach (code; 32 .. 127) table[code] = cast(dchar) code;
  foreach (index, unicode; winAnsiHigh) table[0x80 + index] = unicode;
  foreach (code; 0xA0 .. 0x100) table[code] = cast(dchar) code;
  return table;
}

/**
 * Codifica texto en WinAnsiEncoding (fuentes estándar). Los caracteres que no existen en
 * ella se cambian por '?' y se cuentan en `replaced`.
 */
ubyte[] encodeWinAnsi(string text, ref size_t replaced) pure @safe {
  ubyte[] encoded;
  foreach (dchar character; text) {
    if (character == '\t') character = ' ';
    ubyte code = 0;
    if (character >= 32 && character < 127) {
      code = cast(ubyte) character;
    } else if (character >= 0xA0 && character <= 0xFF) {
      code = cast(ubyte) character;
    } else {
      foreach (index, unicode; winAnsiHigh) {
        if (unicode == character && unicode != 0) code = cast(ubyte) (0x80 + index);
      }
    }
    if (code == 0) {
      code = '?';
      replaced++;
    }
    encoded ~= code;
  }
  return encoded;
}

/// Codifica texto en Latin-1 (fuentes TrueType propias con PDF_SIMPLE_ENCODING_LATIN).
ubyte[] encodeLatin1(string text, ref size_t replaced) pure @safe {
  ubyte[] encoded;
  foreach (dchar character; text) {
    if (character == '\t') character = ' ';
    if (character >= 32 && character <= 0xFF && !(character >= 0x7F && character < 0xA0)) {
      encoded ~= cast(ubyte) character;
    } else {
      encoded ~= '?';
      replaced++;
    }
  }
  return encoded;
}

/// Nombre PostScript de la fuente estándar para la familia y el estilo (PdfBoxFontMapper).
string standardFontName(FontFamily family, FontStyle style) pure nothrow @safe @nogc {
  final switch (family) {
    case FontFamily.serif:
      if (style.bold && style.italic) return "Times-BoldItalic";
      if (style.bold) return "Times-Bold";
      if (style.italic) return "Times-Italic";
      return "Times-Roman";
    case FontFamily.monospaced:
      if (style.bold && style.italic) return "Courier-BoldOblique";
      if (style.bold) return "Courier-Bold";
      if (style.italic) return "Courier-Oblique";
      return "Courier";
    case FontFamily.sansSerif:
      if (style.bold && style.italic) return "Helvetica-BoldOblique";
      if (style.bold) return "Helvetica-Bold";
      if (style.italic) return "Helvetica-Oblique";
      return "Helvetica";
  }
}

/// Alto de FontBBox de las AFM de Adobe de cada fuente estándar (lo que da getBoundingBox en PDFBox).
float standardFontBoundingBoxHeight(string fontName) pure nothrow @safe @nogc {
  switch (fontName) {
    case "Courier", "Courier-Oblique": return 1055;
    case "Courier-Bold", "Courier-BoldOblique": return 1051;
    case "Helvetica", "Helvetica-Oblique": return 1156;
    case "Helvetica-Bold", "Helvetica-BoldOblique": return 1190;
    case "Times-Roman": return 1116;
    case "Times-Bold": return 1153;
    case "Times-Italic": return 1100;
    case "Times-BoldItalic": return 1139;
    default: return 1156;
  }
}

/**
 * Resolución de una imagen PNG (pHYs) o JPEG (densidad JFIF) y su tamaño en píxeles, como
 * ImageUtils de DSS: sin esos metadatos la resolución es 96 ppp.
 *
 * Throws: Exception si los bytes no son una imagen PNG o JPEG legible.
 */
ImageSize readImageSize(const(ubyte)[] bytes) pure @safe {
  import std.exception : enforce;
  ImageSize size;
  uint bigEndian32(size_t at) {
    enforce(at + 4 <= bytes.length, "Imagen truncada");
    return (cast(uint) bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3];
  }
  ushort bigEndian16(size_t at) {
    enforce(at + 2 <= bytes.length, "Imagen truncada");
    return cast(ushort) ((bytes[at] << 8) | bytes[at + 1]);
  }
  static immutable ubyte[8] pngSignature = [0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A];
  if (bytes.length > 8 && bytes[0 .. 8] == pngSignature) {
    size_t position = 8;
    while (position + 8 <= bytes.length) {
      uint length = bigEndian32(position);
      string type = cast(string) bytes[position + 4 .. position + 8].idup;
      size_t data = position + 8;
      enforce(data + length <= bytes.length, "Imagen PNG truncada");
      if (type == "IHDR") {
        size.width = cast(int) bigEndian32(data);
        size.height = cast(int) bigEndian32(data + 4);
      } else if (type == "pHYs" && length >= 9 && bytes[data + 8] == 1) {
        // Píxeles por metro: DSS los pasa a ppp con 25,4 / (1000 / ppm).
        uint perMeterX = bigEndian32(data);
        uint perMeterY = bigEndian32(data + 4);
        if (perMeterX > 0) size.dpiX = cast(int) (25.4 / (1000.0 / perMeterX));
        if (perMeterY > 0) size.dpiY = cast(int) (25.4 / (1000.0 / perMeterY));
      } else if (type == "IEND") {
        break;
      }
      position = data + length + 4;
    }
    enforce(size.width > 0 && size.height > 0, "La imagen PNG no indica su tamaño");
    return size;
  }
  enforce(bytes.length > 4 && bytes[0] == 0xFF && bytes[1] == 0xD8, "La imagen no es PNG ni JPEG");
  size_t position = 2;
  while (position + 4 <= bytes.length) {
    enforce(bytes[position] == 0xFF, "Imagen JPEG mal formada");
    ubyte marker = bytes[position + 1];
    if (marker == 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) {
      position += 2;
      continue;
    }
    ushort length = bigEndian16(position + 2);
    size_t data = position + 4;
    enforce(data + length - 2 <= bytes.length, "Imagen JPEG truncada");
    if (marker == 0xE0 && length >= 14 && bytes[data .. data + 5] == cast(const(ubyte)[]) "JFIF\0") {
      int densityX = bigEndian16(data + 8);
      int densityY = bigEndian16(data + 10);
      // DSS toma la densidad como ppp sin mirar sus unidades; una densidad nula queda en 96.
      if (densityX >= 1) size.dpiX = densityX;
      if (densityY >= 1) size.dpiY = densityY;
    } else if ((marker >= 0xC0 && marker <= 0xCF) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
      size.height = bigEndian16(data + 1);
      size.width = bigEndian16(data + 3);
      break;
    }
    position = data + length - 2;
  }
  enforce(size.width > 0 && size.height > 0, "La imagen JPEG no indica su tamaño");
  return size;
}

version (unittest) {
  private FontMetrics helveticaLike() pure @safe {
    FontMetrics metrics;
    metrics.widths[] = 500;
    metrics.boundingBoxHeight = 1156;
    return metrics;
  }

  private ubyte[] encodeForTest(string line) pure @safe {
    size_t replaced;
    return encodeWinAnsi(line, replaced);
  }
}

@("should place text to the right of the image and center them vertically when laying out a signature")
unittest {
  VisibleSignatureInput input;
  input.text = "LINEA UNO\nDOS\n";
  input.fontSize = 10;
  input.metrics = helveticaLike();
  input.hasImage = true;
  input.image = ImageSize(96, 48, 96, 96);
  input.originX = 100;
  input.originY = 50;
  input.pageBox = PdfRect(0, 0, 612, 792);
  input.rotation = SignatureRotation.automatic;
  auto layout = computeLayout(input, (line) => encodeForTest(line));
  assert(layout.lines == ["LINEA UNO", "DOS"]);
  // Texto: 9 caracteres a 500/1000 * 10 = 45 puntos más 10 de relleno.
  assert(layout.textBoxWidth == 55);
  assert(abs(layout.textBoxHeight - (11.56f * 2 + 10)) < 0.001);
  assert(layout.imageBoxWidth == 72 && layout.imageBoxHeight == 36);
  assert(layout.boxWidth == 72 + 55);
  assert(layout.textBoxX == 72);
  assert(abs(layout.imageBoxY - (layout.boxHeight - 36) / 2) < 0.001);
  assert(layout.annotationRect == PdfRect(100, 792 - 50 - layout.boxHeight, 100 + layout.boxWidth, 792 - 50));
}

@("should rotate the box around the page when the page itself is rotated")
unittest {
  VisibleSignatureInput input;
  input.text = "ABC";
  input.metrics = helveticaLike();
  input.pageBox = PdfRect(0, 0, 612, 792);
  input.pageRotation = 90;
  input.rotation = SignatureRotation.automatic;
  auto layout = computeLayout(input, (line) => encodeForTest(line));
  assert(layout.globalRotation == 270);
  // Con la página girada la caja intercambia alto y ancho.
  auto unrotated = naturalBoxSize(input, (line) => encodeForTest(line));
  assert(layout.boxWidth == unrotated[1] && layout.boxHeight == unrotated[0]);
  auto content = appearanceContent(layout, input, (line) => encodeForTest(line), "F1", "Img1");
  assert(content.content.indexOf("0 1 -1 0 0 0 cm") == 0);
  assert(content.alphaNames == ["GS1", "GS2"]);
}

@("should encode Spanish text in WinAnsi and escape PDF string delimiters")
unittest {
  size_t replaced;
  auto encoded = encodeWinAnsi("Año (€) \\ ☃", replaced);
  assert(encoded == [0x41, 0xF1, 0x6F, 0x20, 0x28, 0x80, 0x29, 0x20, 0x5C, 0x20, '?']);
  assert(replaced == 1);
  assert(literalString(encoded) == `(A\361o \(\200\) \\ ?)`);
  assert(number(1.5f) == "1.5" && number(-0.00001f) == "0" && number(3) == "3");
}

@("should read pixel size and resolution from PNG and JPEG headers like DSS")
unittest {
  import std.exception : assertThrown;
  ubyte[] chunk(string type, ubyte[] data) {
    uint length = cast(uint) data.length;
    return [cast(ubyte) (length >> 24), cast(ubyte) (length >> 16), cast(ubyte) (length >> 8), cast(ubyte) length]
      ~ cast(ubyte[]) type.dup ~ data ~ cast(ubyte[]) [0, 0, 0, 0];
  }
  ubyte[] png = [0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A];
  png ~= chunk("IHDR", [0, 0, 1, 0, 0, 0, 0, 50, 8, 6, 0, 0, 0]);
  // 11811 píxeles por metro son 299,99 ppp, que DSS trunca a 299.
  png ~= chunk("pHYs", [0, 0, 0x2E, 0x23, 0, 0, 0x2E, 0x23, 1]);
  png ~= chunk("IEND", []);
  auto size = readImageSize(png);
  assert(size.width == 256 && size.height == 50 && size.dpiX == 299 && size.dpiY == 299);
  ubyte[] jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0, 1, 1, 1, 0, 72, 0, 72, 0, 0,
    0xFF, 0xC0, 0x00, 0x11, 8, 0, 20, 0, 30, 3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1];
  auto jpegSize = readImageSize(jpeg);
  assert(jpegSize.width == 30 && jpegSize.height == 20 && jpegSize.dpiX == 72);
  assertThrown(readImageSize(cast(const(ubyte)[]) "GIF89a"));
}

@("should split lines like Java String.split with \\r?\\n when the text mixes line endings")
unittest {
  assert(javaLines("uno\r\ndos\ntres") == ["uno", "dos", "tres"]);
  // Un \r suelto no separa, y un \r antes de \r\n queda en la línea.
  assert(javaLines("a\rb\r\r\nc") == ["a\rb\r", "c"]);
  // Las vacías del medio se conservan; las del final se descartan.
  assert(javaLines("a\n\nb\n\n\r\n") == ["a", "", "b"]);
  assert(javaLines("").length == 0 && javaLines("\n\n").length == 0);
}
