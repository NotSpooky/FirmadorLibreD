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
 * Escritura de actualizaciones incrementales de PDF con mupdf (firmador.pdf.engine): el
 * campo de firma con su diccionario (/ByteRange y /Contents de reserva que se completan
 * después con completeSignature) y su apariencia, y el diccionario DSS con los datos de
 * validación. La parte de bytes (buscar las reservas, calcular /ByteRange y escribir el
 * CMS) no toca mupdf y se prueba por separado.
 */
module firmador.pdf.writer;

import std.exception : enforce;
import std.format : format;
import std.logger : info;
import std.string : indexOf, lastIndexOf;

import cmupdf;

import firmador.pdf.engine;

/// Valores de reserva de /ByteRange: diez cifras, que caben en cualquier archivo real.
private enum long placeholderLength1 = 1_111_111_111;
private enum long placeholderOffset2 = 2_222_222_222;
private enum long placeholderLength2 = 3_333_333_333;

/// Diccionario de firma que se va a escribir.
struct SignatureDictionaryPlan {
  /// Sello de tiempo de documento (/DocTimeStamp, ETSI.RFC3161) en lugar de firma.
  bool documentTimestamp;
  string subFilter = "ETSI.CAdES.detached";
  /// Bytes reservados para el CMS o el sello.
  size_t contentsSize;
  /// Fecha /M (no se usa en sellos de documento).
  string signingDate;
  string reason;
  string location;
  string contactInfo;
  /// Nombre de la aplicación en /Prop_Build /App /Name.
  string appName;
}

/// Recursos y contenido de la apariencia de una firma visible.
struct AppearancePlan {
  float width;
  float height;
  /// Flujo de contenido ya armado (firmador.pdf.appearance).
  string content;
  /// Fuente estándar (BaseFont) o, si hay bytes, una fuente TrueType que se incrusta.
  string standardFont;
  immutable(ubyte)[] customFont;
  string fontResource = "F1";
  /// Imagen PNG o JPEG que se incrusta como /Img1 (vacío si no hay).
  immutable(ubyte)[] image;
  string imageResource = "Img1";
  /// Estados gráficos con opacidad: nombre y valor ca/CA.
  string[] alphaNames;
  float[] alphaValues;
}

/// Campo de firma que se va a crear, o el campo de firma vacío que se va a ocupar.
struct FieldPlan {
  /// Nombre del campo nuevo (el que se ocupa conserva el suyo).
  string fieldName;
  int pageIndex;
  /// Rectángulo en la página; [0 0 0 0] para una firma invisible.
  PdfRect rect;
  bool visible;
  AppearancePlan appearance;
  /// Número de objeto del widget de un campo de firma vacío que se ocupa; 0 para crear uno.
  int existingWidget;
}

/// Documento con un campo de firma nuevo cuyo /Contents todavía es la reserva.
struct PreparedSignature {
  immutable(ubyte)[] bytes;
  /// Posición del '<' de /Contents y del byte siguiente al '>'.
  size_t contentsStart;
  size_t contentsEnd;
  /// Posición y longitud del texto de /ByteRange ("[...]").
  size_t byteRangeStart;
  size_t byteRangeLength;
  size_t contentsSize;
}

/// Tramos cubiertos por la firma: [0, contentsStart) y [contentsEnd, fin).
long[4] byteRangeFor(const PreparedSignature prepared) pure nothrow @safe @nogc {
  return [0, cast(long) prepared.contentsStart, cast(long) prepared.contentsEnd,
    cast(long) (prepared.bytes.length - prepared.contentsEnd)];
}

/// Bytes que cubre la firma según /ByteRange (lo que se resume para el CMS).
const(ubyte)[][] signedRanges(const(ubyte)[] bytes, const long[] byteRange) pure @safe {
  enforce!PdfException(byteRange.length == 4 && byteRange[0] >= 0 && byteRange[1] >= 0 && byteRange[2] >= 0
    && byteRange[3] >= 0, "/ByteRange no válido");
  enforce!PdfException(byteRange[0] + byteRange[1] <= byteRange[2]
    && byteRange[2] + byteRange[3] <= bytes.length, "/ByteRange fuera del archivo");
  return [bytes[cast(size_t) byteRange[0] .. cast(size_t) (byteRange[0] + byteRange[1])],
    bytes[cast(size_t) byteRange[2] .. cast(size_t) (byteRange[2] + byteRange[3])]];
}

/**
 * Localiza las reservas del último diccionario de firma escrito: /ByteRange con los
 * valores de reserva y el /Contents de ceros que le sigue.
 *
 * Throws: PdfException si no aparecen donde se esperan.
 */
PreparedSignature locatePlaceholders(immutable(ubyte)[] bytes, size_t contentsSize) pure @safe {
  string text = cast(string) bytes;
  string rangeMarker = format("%d %d %d", placeholderLength1, placeholderOffset2, placeholderLength2);
  auto rangeAt = text.lastIndexOf(rangeMarker);
  enforce!PdfException(rangeAt > 0, "No se encontró la reserva de /ByteRange en el PDF escrito");
  auto open = text[0 .. rangeAt].lastIndexOf('[');
  auto close = text[rangeAt .. $].indexOf(']');
  enforce!PdfException(open >= 0 && close >= 0, "La reserva de /ByteRange está mal formada");
  PreparedSignature prepared;
  prepared.bytes = bytes;
  prepared.contentsSize = contentsSize;
  prepared.byteRangeStart = open;
  prepared.byteRangeLength = rangeAt + close + 1 - open;

  // /Contents pertenece al mismo diccionario: se busca el más cercano a /ByteRange.
  auto contentsMarker = "/Contents";
  ptrdiff_t best = -1;
  ptrdiff_t search = 0;
  while (true) {
    auto found = text[search .. $].indexOf(contentsMarker);
    if (found < 0) break;
    size_t at = search + found;
    size_t cursor = at + contentsMarker.length;
    while (cursor < text.length && (text[cursor] == ' ' || text[cursor] == '\n' || text[cursor] == '\r')) cursor++;
    if (cursor < text.length && text[cursor] == '<' && cursor + 1 + contentsSize * 2 < text.length) {
      bool allZero = true;
      foreach (character; text[cursor + 1 .. cursor + 1 + contentsSize * 2]) {
        if (character != '0') {
          allZero = false;
          break;
        }
      }
      if (allZero && text[cursor + 1 + contentsSize * 2] == '>') {
        if (best < 0 || distance(cursor, open) < distance(best, open)) best = cursor;
      }
    }
    search = at + contentsMarker.length;
  }
  enforce!PdfException(best >= 0, "No se encontró la reserva de /Contents en el PDF escrito");
  prepared.contentsStart = best;
  prepared.contentsEnd = best + 2 + contentsSize * 2;
  return prepared;
}

private size_t distance(ptrdiff_t a, ptrdiff_t b) pure nothrow @safe @nogc {
  return a > b ? a - b : b - a;
}

/// El PDF con /ByteRange definitivo, listo para resumir los tramos firmados.
immutable(ubyte)[] withByteRange(const PreparedSignature prepared) pure @safe {
  long[4] range = byteRangeFor(prepared);
  string value = format("[%d %d %d %d", range[0], range[1], range[2], range[3]);
  enforce!PdfException(value.length + 1 <= prepared.byteRangeLength, "El /ByteRange no cabe en su reserva");
  while (value.length < prepared.byteRangeLength - 1) value ~= " ";
  value ~= "]";
  auto result = prepared.bytes.dup;
  result[prepared.byteRangeStart .. prepared.byteRangeStart + prepared.byteRangeLength] = cast(const(ubyte)[]) value;
  return result.idup;
}

/**
 * Escribe el CMS (o el sello) en hexadecimal dentro de /Contents, completando con ceros.
 *
 * Throws: PdfException si no cabe en el espacio reservado.
 */
immutable(ubyte)[] withContents(immutable(ubyte)[] withRange, const PreparedSignature prepared,
    const(ubyte)[] signature) pure @safe {
  enforce!PdfException(signature.length <= prepared.contentsSize, format(
    "La firma ocupa %d bytes y sólo se reservaron %d", signature.length, prepared.contentsSize));
  import std.ascii : upperHexDigits = hexDigits;
  auto result = withRange.dup;
  size_t cursor = prepared.contentsStart + 1;
  foreach (b; signature) {
    result[cursor++] = upperHexDigits[b >> 4];
    result[cursor++] = upperHexDigits[b & 0x0F];
  }
  return result.idup;
}

private pdf_obj* textObject(fz_context* ctx, ref MupdfCleanup cleanup, string text) @trusted {
  auto zeroTerminated = (text ~ "\0").dup;
  return cleanup.keep(pdf_new_text_string(ctx, zeroTerminated.ptr));
}

private void put(fz_context* ctx, ref MupdfCleanup cleanup, pdf_obj* dictionary, string key, pdf_obj* value) @trusted {
  pdf_dict_put(ctx, dictionary, name(ctx, cleanup, key), value);
}

private immutable(ubyte)[] saveIncremental(fz_context* ctx, ref MupdfCleanup cleanup, pdf_document* doc) @trusted {
  auto buffer = cleanup.keep(fz_new_buffer(ctx, 65536));
  auto output = cleanup.keep(fz_new_output_with_buffer(ctx, buffer));
  pdf_write_options options = pdf_default_write_options;
  options.do_incremental = 1;
  options.do_compress = 1;
  pdf_write_document(ctx, doc, output, &options);
  fz_close_output(ctx, output);
  ubyte* data;
  size_t length = fz_buffer_storage(ctx, buffer, &data);
  return data[0 .. length].idup;
}

/**
 * Añade el campo de firma (u ocupa el campo de firma vacío `field.existingWidget`), su
 * diccionario con las reservas y, si es visible, su apariencia, y devuelve el documento
 * resultante con las posiciones de las reservas.
 *
 * Throws: PdfException si el PDF está cifrado, no admite una actualización incremental o
 * la página no existe.
 */
PreparedSignature appendSignatureField(PdfDocument document, const SignatureDictionaryPlan plan,
    const FieldPlan field) @trusted {
  enforce!PdfException(!document.isEncrypted(),
    "El PDF está cifrado: no se puede añadir una firma sin alterar su /Contents");
  enforce!PdfException(document.canSaveIncrementally(),
    "El PDF está dañado y no admite una actualización incremental; ábralo y guárdelo de nuevo antes de firmar");
  enforce!PdfException(field.pageIndex >= 0 && field.pageIndex < document.pageCount(),
    format("El PDF no tiene la página %d", field.pageIndex + 1));
  auto doc = document.raw();
  immutable(ubyte)[] written;
  runInMupdf("No se pudo añadir el campo de firma", (ctx, ref cleanup) {
    auto root = get(ctx, cleanup, pdf_trailer(ctx, doc), "Root");
    auto page = pdf_lookup_page_obj(ctx, doc, field.pageIndex);

    auto signature = cleanup.keep(pdf_new_dict(ctx, doc, 12));
    put(ctx, cleanup, signature, "Type", name(ctx, cleanup, plan.documentTimestamp ? "DocTimeStamp" : "Sig"));
    put(ctx, cleanup, signature, "Filter", name(ctx, cleanup, "Adobe.PPKLite"));
    put(ctx, cleanup, signature, "SubFilter", name(ctx, cleanup, plan.subFilter));
    auto range = cleanup.keep(pdf_new_array(ctx, doc, 4));
    foreach (value; [0L, placeholderLength1, placeholderOffset2, placeholderLength2])
      pdf_array_push(ctx, range, cleanup.keep(pdf_new_int(ctx, value)));
    put(ctx, cleanup, signature, "ByteRange", range);
    auto zeros = new char[plan.contentsSize];
    zeros[] = '\0';
    put(ctx, cleanup, signature, "Contents", cleanup.keep(pdf_new_string(ctx, zeros.ptr, zeros.length)));
    if (!plan.documentTimestamp && plan.signingDate.length) put(ctx, cleanup, signature, "M", textObject(ctx, cleanup, plan.signingDate));
    if (plan.reason.length) put(ctx, cleanup, signature, "Reason", textObject(ctx, cleanup, plan.reason));
    if (plan.location.length) put(ctx, cleanup, signature, "Location", textObject(ctx, cleanup, plan.location));
    if (plan.contactInfo.length) put(ctx, cleanup, signature, "ContactInfo", textObject(ctx, cleanup, plan.contactInfo));
    if (plan.appName.length) {
      auto application = cleanup.keep(pdf_new_dict(ctx, doc, 1));
      put(ctx, cleanup, application, "Name", name(ctx, cleanup, plan.appName));
      auto build = cleanup.keep(pdf_new_dict(ctx, doc, 1));
      put(ctx, cleanup, build, "App", application);
      put(ctx, cleanup, signature, "Prop_Build", build);
    }
    auto signatureReference = cleanup.keep(pdf_add_object(ctx, doc, signature));

    bool filling = field.existingWidget != 0;
    pdf_obj* widget;
    if (filling) {
      widget = cleanup.keep(pdf_load_object(ctx, doc, field.existingWidget));
      enforce!PdfException(pdf_is_dict(ctx, widget), "El campo de firma vacío que se iba a ocupar no es un diccionario");
    } else {
      widget = cleanup.keep(pdf_new_dict(ctx, doc, 10));
      put(ctx, cleanup, widget, "Type", name(ctx, cleanup, "Annot"));
      put(ctx, cleanup, widget, "Subtype", name(ctx, cleanup, "Widget"));
      put(ctx, cleanup, widget, "FT", name(ctx, cleanup, "Sig"));
      put(ctx, cleanup, widget, "T", textObject(ctx, cleanup, field.fieldName));
    }
    put(ctx, cleanup, widget, "F", cleanup.keep(pdf_new_int(ctx, 132)));
    put(ctx, cleanup, widget, "P", page);
    fz_rect rect = fz_rect(field.rect.x0, field.rect.y0, field.rect.x1, field.rect.y1);
    put(ctx, cleanup, widget, "Rect", cleanup.keep(pdf_new_rect(ctx, doc, rect)));
    // El valor va en el campo: el widget mismo, o su padre si el widget no tiene nombre.
    auto parent = get(ctx, cleanup, widget, "Parent");
    bool valueInParent = filling && get(ctx, cleanup, widget, "T") is null && parent !is null;
    put(ctx, cleanup, valueInParent ? parent : widget, "V", signatureReference);
    if (field.visible) {
      auto appearance = field.appearance;
      auto resources = cleanup.keep(pdf_new_dict(ctx, doc, 3));
      if (appearance.standardFont.length || appearance.customFont.length) {
        pdf_obj* font;
        if (appearance.customFont.length) {
          auto fontData = cleanup.keep(fz_new_font_from_memory(ctx, null, appearance.customFont.ptr,
            cast(int) appearance.customFont.length, 0, 0));
          font = cleanup.keep(pdf_add_simple_font(ctx, doc, fontData, PDF_SIMPLE_ENCODING_LATIN));
        } else {
          auto fontDictionary = cleanup.keep(pdf_new_dict(ctx, doc, 4));
          put(ctx, cleanup, fontDictionary, "Type", name(ctx, cleanup, "Font"));
          put(ctx, cleanup, fontDictionary, "Subtype", name(ctx, cleanup, "Type1"));
          put(ctx, cleanup, fontDictionary, "BaseFont", name(ctx, cleanup, appearance.standardFont));
          put(ctx, cleanup, fontDictionary, "Encoding", name(ctx, cleanup, "WinAnsiEncoding"));
          font = cleanup.keep(pdf_add_object(ctx, doc, fontDictionary));
        }
        auto fonts = cleanup.keep(pdf_new_dict(ctx, doc, 1));
        put(ctx, cleanup, fonts, appearance.fontResource, font);
        put(ctx, cleanup, resources, "Font", fonts);
      }
      if (appearance.image.length) {
        auto imageBuffer = cleanup.keep(fz_new_buffer_from_copied_data(ctx, appearance.image.ptr, appearance.image.length));
        auto image = cleanup.keep(fz_new_image_from_buffer(ctx, imageBuffer));
        auto xobjects = cleanup.keep(pdf_new_dict(ctx, doc, 1));
        put(ctx, cleanup, xobjects, appearance.imageResource, cleanup.keep(pdf_add_image(ctx, doc, image)));
        put(ctx, cleanup, resources, "XObject", xobjects);
      }
      if (appearance.alphaNames.length) {
        auto states = cleanup.keep(pdf_new_dict(ctx, doc, cast(int) appearance.alphaNames.length));
        foreach (index, stateName; appearance.alphaNames) {
          auto state = cleanup.keep(pdf_new_dict(ctx, doc, 3));
          put(ctx, cleanup, state, "Type", name(ctx, cleanup, "ExtGState"));
          put(ctx, cleanup, state, "ca", cleanup.keep(pdf_new_real(ctx, appearance.alphaValues[index])));
          put(ctx, cleanup, state, "CA", cleanup.keep(pdf_new_real(ctx, appearance.alphaValues[index])));
          put(ctx, cleanup, states, stateName, state);
        }
        put(ctx, cleanup, resources, "ExtGState", states);
      }
      auto form = cleanup.keep(pdf_new_dict(ctx, doc, 5));
      put(ctx, cleanup, form, "Type", name(ctx, cleanup, "XObject"));
      put(ctx, cleanup, form, "Subtype", name(ctx, cleanup, "Form"));
      put(ctx, cleanup, form, "BBox", cleanup.keep(pdf_new_rect(ctx, doc, fz_rect(0, 0, appearance.width, appearance.height))));
      put(ctx, cleanup, form, "Resources", resources);
      auto content = cleanup.keep(fz_new_buffer_from_copied_data(ctx, cast(const(ubyte)*) appearance.content.ptr,
        appearance.content.length));
      auto stream = cleanup.keep(pdf_add_stream(ctx, doc, content, form, 1));
      auto normal = cleanup.keep(pdf_new_dict(ctx, doc, 1));
      put(ctx, cleanup, normal, "N", stream);
      put(ctx, cleanup, widget, "AP", normal);
    }
    auto form = get(ctx, cleanup, root, "AcroForm");
    if (form is null || !pdf_is_dict(ctx, form)) {
      form = cleanup.keep(pdf_new_dict(ctx, doc, 2));
      put(ctx, cleanup, root, "AcroForm", form);
    }
    // El campo que se ocupa ya está en la página y en el formulario.
    if (!filling) {
      auto widgetReference = cleanup.keep(pdf_add_object(ctx, doc, widget));
      auto annotations = get(ctx, cleanup, page, "Annots");
      if (annotations is null || !pdf_is_array(ctx, annotations)) {
        annotations = cleanup.keep(pdf_new_array(ctx, doc, 1));
        put(ctx, cleanup, page, "Annots", annotations);
      }
      pdf_array_push(ctx, annotations, widgetReference);
      auto fields = get(ctx, cleanup, form, "Fields");
      if (fields is null || !pdf_is_array(ctx, fields)) {
        fields = cleanup.keep(pdf_new_array(ctx, doc, 1));
        put(ctx, cleanup, form, "Fields", fields);
      }
      pdf_array_push(ctx, fields, widgetReference);
    }
    put(ctx, cleanup, form, "SigFlags", cleanup.keep(pdf_new_int(ctx, 3)));

    written = saveIncremental(ctx, cleanup, doc);
  });
  if (field.existingWidget != 0) {
    info(format("Firma añadida en el campo de firma vacío (objeto %d) de la página %d (%d bytes)",
      field.existingWidget, field.pageIndex + 1, written.length));
  } else {
    info(format("Campo de firma «%s» añadido en la página %d (%d bytes)", field.fieldName, field.pageIndex + 1,
      written.length));
  }
  return locatePlaceholders(written, plan.contentsSize);
}

/**
 * Añade (o completa) el diccionario /DSS del catálogo con certificados, respuestas OCSP y
 * CRL, sin repetir las que ya tiene.
 *
 * Throws: PdfException si el PDF está cifrado o no admite una actualización incremental.
 */
immutable(ubyte)[] appendDss(PdfDocument document, const(ubyte[])[] certificates, const(ubyte[])[] ocsps,
    const(ubyte[])[] crls) @trusted {
  enforce!PdfException(!document.isEncrypted(), "El PDF está cifrado: no se pueden añadir datos de validación");
  enforce!PdfException(document.canSaveIncrementally(), "El PDF no admite una actualización incremental");
  auto existing = document.dss();
  auto doc = document.raw();
  immutable(ubyte)[] written;
  runInMupdf("No se pudo añadir el diccionario DSS", (ctx, ref cleanup) {
    auto root = get(ctx, cleanup, pdf_trailer(ctx, doc), "Root");
    auto dss = get(ctx, cleanup, root, "DSS");
    if (dss is null || !pdf_is_dict(ctx, dss)) {
      auto created = cleanup.keep(pdf_new_dict(ctx, doc, 3));
      dss = cleanup.keep(pdf_add_object(ctx, doc, created));
      put(ctx, cleanup, root, "DSS", dss);
      dss = pdf_resolve_indirect(ctx, dss);
    }
    void addStreams(string key, const(ubyte[])[] items, const(immutable(ubyte)[])[] present) {
      auto array = get(ctx, cleanup, dss, key);
      if (array is null || !pdf_is_array(ctx, array)) {
        array = cleanup.keep(pdf_new_array(ctx, doc, cast(int) items.length));
        put(ctx, cleanup, dss, key, array);
      }
      const(ubyte)[][] added;
      foreach (item; items) {
        bool duplicate = false;
        foreach (old; present) if (old == item) duplicate = true;
        foreach (old; added) if (old == item) duplicate = true;
        if (duplicate) continue;
        added ~= item;
        auto buffer = cleanup.keep(fz_new_buffer_from_copied_data(ctx, item.ptr, item.length));
        auto streamDictionary = cleanup.keep(pdf_new_dict(ctx, doc, 1));
        pdf_array_push(ctx, array, cleanup.keep(pdf_add_stream(ctx, doc, buffer, streamDictionary, 1)));
      }
    }
    addStreams("Certs", certificates, existing.certificates);
    addStreams("OCSPs", ocsps, existing.ocsps);
    addStreams("CRLs", crls, existing.crls);
    written = saveIncremental(ctx, cleanup, doc);
  });
  info(format("Diccionario DSS actualizado con %d certificados, %d OCSP y %d CRL", certificates.length, ocsps.length,
    crls.length));
  return written;
}

@("should fill the byte range and contents placeholders without changing the file length")
unittest {
  enum size_t size = 4;
  string body = "%PDF-1.7\n1 0 obj\n<</ByteRange[0 1111111111 2222222222 3333333333]/Contents<00000000>>>\nendobj\n%%EOF\n";
  auto prepared = locatePlaceholders(cast(immutable(ubyte)[]) body, size);
  auto range = byteRangeFor(prepared);
  assert(range[1] == cast(long) body.indexOf("<00000000>"));
  assert(range[2] == range[1] + 10 && range[2] + range[3] == body.length);
  auto finished = withContents(withByteRange(prepared), prepared, [0xDE, 0xAD]);
  assert(finished.length == body.length);
  string text = cast(string) finished;
  assert(text.indexOf("<DEAD0000>") > 0);
  assert(text.indexOf(format("[0 %d %d %d", range[1], range[2], range[3])) > 0);
  auto parts = signedRanges(finished, range);
  assert(parts[0].length + parts[1].length + 10 == finished.length);
  import std.exception : assertThrown;
  assertThrown!PdfException(withContents(withByteRange(prepared), prepared, [1, 2, 3, 4, 5]));
  assertThrown!PdfException(signedRanges(finished, [0, 5, 3, 100]));
}

@("should append a signature field incrementally keeping the original bytes as prefix")
unittest {
  auto original = cast(immutable(ubyte)[]) import("nonPreview.pdf");
  auto document = PdfDocument.open(original);
  scope (exit) document.close();
  SignatureDictionaryPlan plan;
  plan.contentsSize = 64;
  plan.signingDate = "D:20260922140405-06'00'";
  plan.reason = "Prueba de razón";
  plan.appName = "Firmador prueba";
  FieldPlan field;
  field.fieldName = "Signature1";
  field.pageIndex = 0;
  field.rect = PdfRect(0, 0, 0, 0);
  auto prepared = appendSignatureField(document, plan, field);
  assert(prepared.bytes.length > original.length);
  assert(prepared.bytes[0 .. original.length] == original);
  auto finished = withContents(withByteRange(prepared), prepared, [1, 2, 3]);
  auto reopened = PdfDocument.open(finished);
  scope (exit) reopened.close();
  auto signatures = reopened.signatureFields();
  assert(signatures.length == 1);
  assert(signatures[0].fieldName == "Signature1" && signatures[0].reason == "Prueba de razón");
  assert(signatures[0].byteRange == byteRangeFor(prepared));
  assert(signatures[0].contents[0 .. 3] == [1, 2, 3]);
  assert(signatures[0].subFilter == "ETSI.CAdES.detached" && signatures[0].pageIndex == 0);
  auto withDss = appendDss(reopened, [[1, 2]], [[3]], []);
  auto dssDocument = PdfDocument.open(withDss);
  scope (exit) dssDocument.close();
  assert(dssDocument.dss().certificates == [[1, 2]]);
  assert(dssDocument.signatureFields().length == 1);
}
