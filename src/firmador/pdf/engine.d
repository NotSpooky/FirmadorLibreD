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
 * Acceso a PDF con mupdf (lo que en la versión Java hacían PDFBox y DSS): abrir, contar y
 * dibujar páginas, leer los diccionarios de firma y el DSS, y escribir actualizaciones
 * incrementales con un campo de firma o con datos de validación.
 *
 * mupdf avisa de sus errores con longjmp, así que cada operación corre dentro de fl_try
 * (src/shim/mupdfshim.c) mediante runInMupdf. El cuerpo sólo llama a mupdf y copia datos:
 * un longjmp lo abandona sin ejecutar nada más, así que no debe tener destructores
 * pendientes, scope(exit) ni cerrojos propios. Las excepciones de D que lance se atrapan
 * antes de volver a C y se relanzan después. Los objetos de mupdf que crea se anotan en
 * MupdfCleanup y se liberan al terminar, haya fallado o no. Un único contexto atiende a toda
 * la aplicación bajo un cerrojo.
 */
module firmador.pdf.engine;

import core.stdc.string : memcpy, strlen;
import core.sync.mutex : Mutex;
import std.exception : enforce;
import std.format : format;
import std.logger : info, trace, warning;
import std.string : fromStringz, toStringz;

import cmupdf;

/// Error de mupdf o de estructura del PDF.
class PdfException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }

  this(string message, Throwable cause, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line, cause);
  }
}

/// Objetos de mupdf que se liberan al terminar una operación.
struct MupdfCleanup {
  fz_buffer*[] buffers;
  fz_output*[] outputs;
  fz_font*[] fonts;
  fz_image*[] images;
  fz_pixmap*[] pixmaps;
  fz_stream*[] streams;
  pdf_obj*[] objects;
  fz_page*[] pages;
  pdf_document*[] documents;

  /// Anota un objeto para liberarlo y lo devuelve (para encadenar).
  T* keep(T)(T* value) nothrow @trusted {
    static if (is(T == fz_buffer)) buffers ~= value;
    else static if (is(T == fz_output)) outputs ~= value;
    else static if (is(T == fz_font)) fonts ~= value;
    else static if (is(T == fz_image)) images ~= value;
    else static if (is(T == fz_pixmap)) pixmaps ~= value;
    else static if (is(T == fz_stream)) streams ~= value;
    else static if (is(T == pdf_obj)) objects ~= value;
    else static if (is(T == fz_page)) pages ~= value;
    else static if (is(T == pdf_document)) documents ~= value;
    else static assert(false, "Tipo de mupdf sin liberación registrada");
    return value;
  }
}

/// Cuerpo de una operación con mupdf (ver runInMupdf).
alias MupdfBody = void delegate(fz_context*, ref MupdfCleanup);

private struct Invocation {
  MupdfBody body;
  MupdfCleanup cleanup;
  Throwable failure;
}

private extern (C) void runBody(fz_context* context, void* argument) nothrow @system {
  auto invocation = cast(Invocation*) argument;
  try {
    invocation.body(context, invocation.cleanup);
  } catch (Throwable failure) {
    // Una excepción de D no puede cruzar los marcos de C: se guarda y se relanza en runInMupdf.
    invocation.failure = failure;
  }
}

private extern (C) void runCleanup(fz_context* context, void* argument) nothrow @system {
  auto cleanup = cast(MupdfCleanup*) argument;
  try {
    foreach_reverse (output; cleanup.outputs) fz_drop_output(context, output);
    foreach_reverse (page; cleanup.pages) fz_drop_page(context, page);
    foreach_reverse (pixmap; cleanup.pixmaps) fz_drop_pixmap(context, pixmap);
    foreach_reverse (image; cleanup.images) fz_drop_image(context, image);
    foreach_reverse (font; cleanup.fonts) fz_drop_font(context, font);
    foreach_reverse (object; cleanup.objects) pdf_drop_obj(context, object);
    foreach_reverse (buffer; cleanup.buffers) fz_drop_buffer(context, buffer);
    foreach_reverse (stream; cleanup.streams) fz_drop_stream(context, stream);
    foreach_reverse (document; cleanup.documents) pdf_drop_document(context, document);
  } catch (Throwable) {
    // Las funciones de liberación de mupdf no lanzan excepciones de D; esto sólo satisface a nothrow.
  }
}

private __gshared fz_context* sharedContext;
private __gshared Mutex engineLock;

shared static this() {
  engineLock = new Mutex;
}

private extern (C) void logMupdfWarning(void* user, const(char)* text) nothrow @system {
  try {
    trace("mupdf: ", fromStringz(text));
  } catch (Exception) {
    // Una advertencia que no se pudo registrar no afecta a la operación.
  }
}

private extern (C) void logMupdfError(void* user, const(char)* text) nothrow @system {
  try {
    trace("mupdf (error): ", fromStringz(text));
  } catch (Exception) {
    // El error también llega a runInMupdf, que es quien lo informa.
  }
}

private fz_context* context() @trusted {
  if (sharedContext is null) {
    char[512] error;
    sharedContext = fl_new_context(error.ptr, error.length);
    enforce!PdfException(sharedContext !is null, "No se pudo iniciar mupdf: " ~ fromStringz(error.ptr).idup);
    // Las advertencias de mupdf van a la bitácora y no directamente a la salida de error.
    fz_set_warning_callback(sharedContext, &logMupdfWarning, null);
    fz_set_error_callback(sharedContext, &logMupdfError, null);
  }
  return sharedContext;
}

/**
 * Ejecuta `body` dentro de fz_try con el contexto compartido y libera lo anotado en su
 * MupdfCleanup.
 *
 * Throws: PdfException con `operation` y el mensaje de mupdf si falla.
 */
void runInMupdf(string operation, scope MupdfBody body) @trusted {
  engineLock.lock();
  scope (exit) engineLock.unlock();
  fz_context* ctx = context();
  char[1024] error;
  auto invocation = Invocation(body);
  int code = fl_try(ctx, &runBody, &invocation, error.ptr, error.length);
  string failure = code != 0 ? fromStringz(error.ptr).idup : null;
  char[256] cleanupError;
  fl_try(ctx, &runCleanup, &invocation.cleanup, cleanupError.ptr, cleanupError.length);
  if (code != 0) throw new PdfException(format("%s: %s", operation, failure));
  if (invocation.failure !is null) {
    if (auto exception = cast(Exception) invocation.failure) {
      throw new PdfException(format("%s: %s", operation, exception.msg), exception);
    }
    throw invocation.failure;
  }
}

/// Nombre PDF (los nombres conocidos por mupdf no reservan memoria).
package pdf_obj* name(fz_context* ctx, ref MupdfCleanup cleanup, string text) @trusted {
  char[128] buffer;
  size_t length = text.length < buffer.length - 1 ? text.length : buffer.length - 1;
  buffer[0 .. length] = text[0 .. length];
  buffer[length] = '\0';
  return cleanup.keep(pdf_new_name(ctx, buffer.ptr));
}

/// Texto de un objeto nombre o cadena, copiado a D.
package string nameText(fz_context* ctx, pdf_obj* object) @trusted {
  if (object is null) return null;
  if (pdf_is_name(ctx, object)) {
    auto text = pdf_to_name(ctx, object);
    return text is null ? null : text[0 .. strlen(text)].idup;
  }
  return null;
}

/// Bytes de una cadena PDF, copiados a D.
package immutable(ubyte)[] stringBytes(fz_context* ctx, pdf_obj* object) @trusted {
  if (object is null || !pdf_is_string(ctx, object)) return null;
  auto data = pdf_to_str_buf(ctx, object);
  size_t length = pdf_to_str_len(ctx, object);
  return (cast(const(ubyte)*) data)[0 .. length].idup;
}

/// Texto de una cadena de texto PDF (PDFDocEncoding o UTF-16) en UTF-8.
package string textString(fz_context* ctx, pdf_obj* object) @trusted {
  if (object is null || !pdf_is_string(ctx, object)) return null;
  auto text = pdf_to_text_string(ctx, object);
  return text is null ? null : text[0 .. strlen(text)].idup;
}

/// Valor de una clave de un diccionario (resuelve referencias).
package pdf_obj* get(fz_context* ctx, ref MupdfCleanup cleanup, pdf_obj* dictionary, string key) @trusted {
  if (dictionary is null) return null;
  return pdf_dict_get(ctx, dictionary, name(ctx, cleanup, key));
}

/// Rectángulo PDF [x0 y0 x1 y1].
struct PdfRect {
  float x0, y0, x1, y1;

  float width() const pure nothrow @safe @nogc { return x1 - x0; }
  float height() const pure nothrow @safe @nogc { return y1 - y0; }
}

/// Geometría de una página.
struct PageGeometry {
  PdfRect mediaBox;
  PdfRect cropBox;
  /// Rotación de la página normalizada a 0, 90, 180 o 270.
  int rotation;
  int objectNumber;
}

/// Imagen RGB de una página.
struct PageRaster {
  int width;
  int height;
  /// Píxeles RGB de 8 bits por fila, sin relleno.
  ubyte[] rgb;
  /// Opacidad de cada píxel (0 transparente), sólo si se dibujó con fondo transparente.
  ubyte[] alpha;
}

/// Diccionario de firma o de sello de documento encontrado en un campo del PDF.
struct PdfSignatureField {
  string fieldName;
  /// "Sig" o "DocTimeStamp".
  string type;
  string filter;
  string subFilter;
  long[] byteRange;
  /// Contenido de /Contents (CMS o TimeStampToken, con el relleno de ceros).
  immutable(ubyte)[] contents;
  string signingDate;
  string name;
  string reason;
  string location;
  string contactInfo;
  /// Página del widget (base 0) o -1 si no se pudo determinar.
  int pageIndex = -1;
  PdfRect rect;
  int dictionaryObject;
}

/// Contenido del diccionario DSS (datos de validación de PAdES LT).
struct PdfDss {
  immutable(ubyte)[][] certificates;
  immutable(ubyte)[][] ocsps;
  immutable(ubyte)[][] crls;
}

/// Anotación de una página, para detectar cambios después de firmar.
struct PdfAnnotation {
  int pageIndex;
  string subtype;
  string fieldType;
  PdfRect rect;
  string contents;
}

private PdfRect toRect(fz_context* ctx, pdf_obj* array) @trusted {
  fz_rect rect = pdf_to_rect(ctx, array);
  return PdfRect(rect.x0, rect.y0, rect.x1, rect.y1);
}

/// Documento PDF abierto sobre unos bytes en memoria.
final class PdfDocument {
  /// Bytes del documento; mupdf los lee sin copiarlos, así que viven lo que viva el documento.
  immutable(ubyte)[] bytes;
  private pdf_document* document;

  private this(immutable(ubyte)[] bytes) @safe {
    this.bytes = bytes;
  }

  /**
   * Abre un PDF.
   *
   * Throws: PdfException si mupdf no lo puede leer o está protegido con contraseña.
   */
  static PdfDocument open(immutable(ubyte)[] bytes) @trusted {
    enforce!PdfException(bytes.length > 0, "El PDF está vacío");
    auto opened = new PdfDocument(bytes);
    bool needsPassword;
    runInMupdf("No se pudo abrir el PDF", (ctx, ref cleanup) {
      auto stream = cleanup.keep(fz_open_memory(ctx, opened.bytes.ptr, opened.bytes.length));
      opened.document = pdf_open_document_with_stream(ctx, stream);
      needsPassword = pdf_needs_password(ctx, opened.document) != 0;
    });
    if (needsPassword) {
      opened.close();
      throw new PdfException("El PDF está protegido con contraseña");
    }
    return opened;
  }

  /// Libera el documento.
  void close() @trusted {
    if (document is null) return;
    auto toDrop = document;
    document = null;
    runInMupdf("No se pudo cerrar el PDF", (ctx, ref cleanup) {
      pdf_drop_document(ctx, toDrop);
    });
  }

  ~this() {
    // Sin cerrojo ni excepciones en un finalizador: sólo se avisa si quedó abierto.
    if (document !is null) {
      import core.stdc.stdio : fprintf, stderr;
      fprintf(stderr, "Advertencia: un PDF quedó abierto sin llamar a close()\n");
    }
  }

  private pdf_document* handle() @safe {
    enforce!PdfException(document !is null, "El PDF ya fue cerrado");
    return document;
  }

  /// Número de páginas.
  int pageCount() @trusted {
    auto doc = handle();
    int count;
    runInMupdf("No se pudieron contar las páginas", (ctx, ref cleanup) {
      count = pdf_count_pages(ctx, doc);
    });
    return count;
  }

  /// El documento está cifrado (tiene /Encrypt).
  bool isEncrypted() @trusted {
    auto doc = handle();
    bool encrypted;
    runInMupdf("No se pudo leer el tráiler", (ctx, ref cleanup) {
      encrypted = get(ctx, cleanup, pdf_trailer(ctx, doc), "Encrypt") !is null;
    });
    return encrypted;
  }

  /// Se puede añadir una actualización incremental sin reescribir el archivo.
  bool canSaveIncrementally() @trusted {
    auto doc = handle();
    bool possible;
    runInMupdf("No se pudo revisar el PDF", (ctx, ref cleanup) {
      possible = pdf_can_be_saved_incrementally(ctx, doc) != 0;
    });
    return possible;
  }

  /**
   * Geometría de la página `index` (base 0).
   *
   * Throws: PdfException si la página no existe.
   */
  PageGeometry pageGeometry(int index) @trusted {
    auto doc = handle();
    PageGeometry geometry;
    bool found;
    runInMupdf("No se pudo leer la página", (ctx, ref cleanup) {
      if (index < 0 || index >= pdf_count_pages(ctx, doc)) return;
      auto page = pdf_lookup_page_obj(ctx, doc, index);
      found = true;
      geometry.objectNumber = pdf_to_num(ctx, page);
      geometry.mediaBox = toRect(ctx, pdf_dict_get_inheritable(ctx, page, name(ctx, cleanup, "MediaBox")));
      auto crop = pdf_dict_get_inheritable(ctx, page, name(ctx, cleanup, "CropBox"));
      geometry.cropBox = crop is null ? geometry.mediaBox : toRect(ctx, crop);
      int rotation = pdf_to_int(ctx, pdf_dict_get_inheritable(ctx, page, name(ctx, cleanup, "Rotate")));
      rotation = ((rotation % 360) + 360) % 360;
      geometry.rotation = rotation % 90 == 0 ? rotation : 0;
    });
    enforce!PdfException(found, format("El PDF no tiene la página %d", index + 1));
    return geometry;
  }

  /**
   * Dibuja la página `index` (base 0) con la escala dada (1 = 72 ppp), con anotaciones. Con
   * `transparent` el fondo queda transparente y la opacidad va en `alpha`.
   *
   * Throws: PdfException si la página no existe o no se puede dibujar.
   */
  PageRaster render(int index, float scale, bool transparent = false) @trusted {
    auto doc = handle();
    PageRaster raster;
    runInMupdf("No se pudo dibujar la página", (ctx, ref cleanup) {
      auto pixmap = cleanup.keep(fz_new_pixmap_from_page_number(ctx, cast(fz_document*) doc, index,
        fz_scale(scale, scale), fz_device_rgb(ctx), transparent ? 1 : 0));
      raster.width = fz_pixmap_width(ctx, pixmap);
      raster.height = fz_pixmap_height(ctx, pixmap);
      int stride = fz_pixmap_stride(ctx, pixmap);
      int components = fz_pixmap_components(ctx, pixmap);
      auto samples = fz_pixmap_samples(ctx, pixmap);
      size_t pixels = cast(size_t) raster.width * raster.height;
      raster.rgb = new ubyte[pixels * 3];
      if (transparent) raster.alpha = new ubyte[pixels];
      foreach (row; 0 .. raster.height) {
        auto source = samples + cast(size_t) row * stride;
        auto target = raster.rgb.ptr + cast(size_t) row * raster.width * 3;
        if (components == 3) {
          memcpy(target, source, cast(size_t) raster.width * 3);
          continue;
        }
        foreach (column; 0 .. raster.width) {
          auto pixel = source + column * components;
          if (!transparent) {
            target[column * 3 .. column * 3 + 3] = pixel[0 .. 3];
            continue;
          }
          // mupdf entrega el color multiplicado por la opacidad.
          ubyte opacity = pixel[components - 1];
          raster.alpha[cast(size_t) row * raster.width + column] = opacity;
          foreach (channel; 0 .. 3) {
            uint value = opacity == 0 ? 0 : pixel[channel] * 255u / opacity;
            target[column * 3 + channel] = cast(ubyte) (value > 255 ? 255 : value);
          }
        }
      }
    });
    return raster;
  }

  /// Campos de firma con su diccionario, en el orden del formulario.
  PdfSignatureField[] signatureFields() @trusted {
    auto doc = handle();
    PdfSignatureField[] fields;
    runInMupdf("No se pudieron leer las firmas del PDF", (ctx, ref cleanup) {
      int[int] pageByObject;
      int pages = pdf_count_pages(ctx, doc);
      foreach (index; 0 .. pages) pageByObject[pdf_to_num(ctx, pdf_lookup_page_obj(ctx, doc, index))] = index;
      auto root = get(ctx, cleanup, pdf_trailer(ctx, doc), "Root");
      auto form = get(ctx, cleanup, root, "AcroForm");
      auto list = get(ctx, cleanup, form, "Fields");
      int[] visited;
      void walk(pdf_obj* field, string parentName, string inheritedType, int depth) {
        if (field is null || depth > 32) return;
        int number = pdf_to_num(ctx, field);
        if (number > 0) {
          foreach (seen; visited) if (seen == number) return;
          visited ~= number;
        }
        string partial = textString(ctx, get(ctx, cleanup, field, "T"));
        string fullName = parentName.length && partial.length ? parentName ~ "." ~ partial
          : partial.length ? partial : parentName;
        string fieldType = nameText(ctx, get(ctx, cleanup, field, "FT"));
        if (fieldType is null) fieldType = inheritedType;
        auto kids = get(ctx, cleanup, field, "Kids");
        if (kids !is null && pdf_is_array(ctx, kids)) {
          foreach (kid; 0 .. pdf_array_len(ctx, kids)) walk(pdf_array_get(ctx, kids, kid), fullName, fieldType, depth + 1);
        }
        if (fieldType != "Sig") return;
        auto value = get(ctx, cleanup, field, "V");
        if (value is null || !pdf_is_dict(ctx, value)) return;
        PdfSignatureField signature;
        signature.fieldName = fullName;
        signature.dictionaryObject = pdf_to_num(ctx, value);
        signature.type = nameText(ctx, get(ctx, cleanup, value, "Type"));
        signature.filter = nameText(ctx, get(ctx, cleanup, value, "Filter"));
        signature.subFilter = nameText(ctx, get(ctx, cleanup, value, "SubFilter"));
        auto range = get(ctx, cleanup, value, "ByteRange");
        if (range !is null && pdf_is_array(ctx, range)) {
          foreach (item; 0 .. pdf_array_len(ctx, range)) signature.byteRange ~= pdf_to_int64(ctx, pdf_array_get(ctx, range, item));
        }
        signature.contents = stringBytes(ctx, get(ctx, cleanup, value, "Contents"));
        signature.signingDate = textString(ctx, get(ctx, cleanup, value, "M"));
        signature.name = textString(ctx, get(ctx, cleanup, value, "Name"));
        signature.reason = textString(ctx, get(ctx, cleanup, value, "Reason"));
        signature.location = textString(ctx, get(ctx, cleanup, value, "Location"));
        signature.contactInfo = textString(ctx, get(ctx, cleanup, value, "ContactInfo"));
        auto pageReference = get(ctx, cleanup, field, "P");
        if (pageReference !is null) {
          if (auto page = pdf_to_num(ctx, pageReference) in pageByObject) signature.pageIndex = *page;
        }
        auto rect = get(ctx, cleanup, field, "Rect");
        if (rect !is null) signature.rect = toRect(ctx, rect);
        fields ~= signature;
      }
      if (list !is null && pdf_is_array(ctx, list)) {
        foreach (item; 0 .. pdf_array_len(ctx, list)) walk(pdf_array_get(ctx, list, item), null, null, 0);
      }
    });
    return fields;
  }

  /// Contenido del diccionario /DSS del catálogo.
  PdfDss dss() @trusted {
    auto doc = handle();
    PdfDss result;
    runInMupdf("No se pudo leer el diccionario DSS", (ctx, ref cleanup) {
      auto root = get(ctx, cleanup, pdf_trailer(ctx, doc), "Root");
      auto dss = get(ctx, cleanup, root, "DSS");
      if (dss is null) return;
      immutable(ubyte)[][] streams(string key) {
        immutable(ubyte)[][] found;
        auto array = get(ctx, cleanup, dss, key);
        if (array is null || !pdf_is_array(ctx, array)) return found;
        foreach (index; 0 .. pdf_array_len(ctx, array)) {
          auto item = pdf_array_get(ctx, array, index);
          if (!pdf_is_stream(ctx, item)) continue;
          auto buffer = cleanup.keep(pdf_load_stream(ctx, item));
          ubyte* data;
          size_t length = fz_buffer_storage(ctx, buffer, &data);
          found ~= data[0 .. length].idup;
        }
        return found;
      }
      result.certificates = streams("Certs");
      result.ocsps = streams("OCSPs");
      result.crls = streams("CRLs");
    });
    return result;
  }

  /// Anotaciones de todas las páginas.
  PdfAnnotation[] annotations() @trusted {
    auto doc = handle();
    PdfAnnotation[] result;
    runInMupdf("No se pudieron leer las anotaciones", (ctx, ref cleanup) {
      foreach (index; 0 .. pdf_count_pages(ctx, doc)) {
        auto page = pdf_lookup_page_obj(ctx, doc, index);
        auto annots = get(ctx, cleanup, page, "Annots");
        if (annots is null || !pdf_is_array(ctx, annots)) continue;
        foreach (item; 0 .. pdf_array_len(ctx, annots)) {
          auto annotation = pdf_array_get(ctx, annots, item);
          if (annotation is null || !pdf_is_dict(ctx, annotation)) continue;
          PdfAnnotation entry;
          entry.pageIndex = index;
          entry.subtype = nameText(ctx, get(ctx, cleanup, annotation, "Subtype"));
          string fieldType = nameText(ctx, get(ctx, cleanup, annotation, "FT"));
          if (fieldType is null) fieldType = nameText(ctx, get(ctx, cleanup, get(ctx, cleanup, annotation, "Parent"), "FT"));
          entry.fieldType = fieldType;
          auto rect = get(ctx, cleanup, annotation, "Rect");
          if (rect !is null) entry.rect = toRect(ctx, rect);
          entry.contents = textString(ctx, get(ctx, cleanup, annotation, "Contents"));
          result ~= entry;
        }
      }
    });
    return result;
  }

  /// Nombres de todos los campos del formulario (para elegir uno nuevo que no se repita).
  string[] fieldNames() @trusted {
    auto doc = handle();
    string[] names;
    runInMupdf("No se pudieron leer los campos del formulario", (ctx, ref cleanup) {
      auto root = get(ctx, cleanup, pdf_trailer(ctx, doc), "Root");
      auto list = get(ctx, cleanup, get(ctx, cleanup, root, "AcroForm"), "Fields");
      if (list is null || !pdf_is_array(ctx, list)) return;
      foreach (index; 0 .. pdf_array_len(ctx, list)) {
        string text = textString(ctx, get(ctx, cleanup, pdf_array_get(ctx, list, index), "T"));
        if (text !is null) names ~= text;
      }
    });
    return names;
  }

  /// Acceso directo al documento de mupdf para las operaciones de escritura (firmador.pdf.writer).
  package pdf_document* raw() @safe {
    return handle();
  }
}

/**
 * Anchos (en milésimas de em) de los caracteres WinAnsi 0-255 de una fuente estándar
 * (Helvetica, Times-Roman, Courier y sus variantes), según las fuentes base de mupdf, que
 * tienen las mismas métricas que las AFM de Adobe que usa PDFBox.
 *
 * Throws: PdfException si mupdf no incluye la fuente.
 */
float[256] standardFontWidths(string baseFont, const dchar[256] winAnsi) @trusted {
  float[256] widths = 0;
  runInMupdf("No se pudo cargar la fuente " ~ baseFont, (ctx, ref cleanup) {
    char[64] fontName;
    fontName[0 .. baseFont.length] = baseFont[];
    fontName[baseFont.length] = '\0';
    auto font = cleanup.keep(fz_new_base14_font(ctx, fontName.ptr));
    foreach (code; 0 .. 256) {
      dchar unicode = winAnsi[code];
      if (unicode == 0) continue;
      int glyph = fz_encode_character(ctx, font, cast(int) unicode);
      widths[code] = fz_advance_glyph(ctx, font, glyph, 0) * 1000;
    }
  });
  return widths;
}

/// Métricas de una fuente TrueType propia (Firmador Remoto): anchos Latin-1 y caja en milésimas de em.
struct CustomFontMetrics {
  float[256] widths;
  float boundingBoxHeight;
}

/**
 * Lee las métricas de una fuente TrueType u OpenType.
 *
 * Throws: PdfException si los bytes no son una fuente que mupdf entienda.
 */
CustomFontMetrics customFontMetrics(immutable(ubyte)[] fontBytes) @trusted {
  CustomFontMetrics metrics;
  metrics.widths = 0;
  runInMupdf("No se pudo leer la fuente", (ctx, ref cleanup) {
    auto font = cleanup.keep(fz_new_font_from_memory(ctx, null, fontBytes.ptr, cast(int) fontBytes.length, 0, 0));
    foreach (code; 32 .. 256) {
      int glyph = fz_encode_character(ctx, font, code);
      metrics.widths[code] = fz_advance_glyph(ctx, font, glyph, 0) * 1000;
    }
    fz_rect box = fz_font_bbox(ctx, font);
    metrics.boundingBoxHeight = (box.y1 - box.y0) * 1000;
  });
  return metrics;
}

@("should open a PDF, read its geometry and render its first page")
unittest {
  auto bytes = cast(immutable(ubyte)[]) import("nonPreview.pdf");
  auto document = PdfDocument.open(bytes);
  scope (exit) document.close();
  assert(document.pageCount() >= 1);
  auto geometry = document.pageGeometry(0);
  assert(geometry.mediaBox.width > 0 && geometry.mediaBox.height > 0);
  auto raster = document.render(0, 0.25);
  assert(raster.width > 0 && raster.rgb.length == cast(size_t) raster.width * raster.height * 3);
  assert(document.signatureFields().length == 0);
  import std.exception : assertThrown;
  assertThrown!PdfException(document.pageGeometry(99));
  assertThrown!PdfException(PdfDocument.open(cast(immutable(ubyte)[]) "no es un pdf"));
}
