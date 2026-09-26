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
 * Firmador PAdES (FirmadorPAdES): firma PDF en el nivel configurado con firma visible
 * opcional, los extiende a LTA y les añade sellos de tiempo de documento. La parte de PDF
 * y CMS está en firmador.pdf.pades; aquí están los pasos, los avisos y la configuración.
 */
module firmador.signers.pades;

import std.datetime.systime : Clock;
import std.exception : enforce;
import std.format : format;
import std.logger : error, info;
import std.math : round;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.configuration : maxSignatureScale, minSignatureScale, padesSignatureContentSize;
import firmador.gui.guiinterface;
import firmador.i18n : t;
import firmador.pdf.appearance;
import firmador.pdf.engine;
import firmador.pdf.pades;
import firmador.pdf.writer : PreparedSignature;
import firmador.settings;
import firmador.settingsmanager : currentSettings;
import firmador.signers.common;
import firmador.signers.documentsigner;
import firmador.signers.resources;
import firmador.util.datetime;

/// Resolución con que se interpreta el tamaño configurado de la imagen (IMAGE_DPI en Java).
enum int configuredImageDpi = 21;

/// Tamaño en píxeles de la imagen configurada: el natural, o el pedido en ajustes pasado a 96 ppp.
ImageSize configuredImageSize(immutable(ubyte)[] image, int configuredWidth, int configuredHeight) pure @safe {
  auto natural = readImageSize(image);
  if (configuredWidth == 0 || configuredHeight == 0) return natural;
  // La versión Java reescalaba la imagen a este tamaño y la guardaba como PNG sin
  // resolución, que DSS interpreta a 96 ppp.
  ImageSize scaled;
  scaled.width = cast(int) round(configuredWidth * 72.0 / configuredImageDpi);
  scaled.height = cast(int) round(configuredHeight * 72.0 / configuredImageDpi);
  scaled.dpiX = defaultImageDpi;
  scaled.dpiY = defaultImageDpi;
  return scaled;
}

/**
 * Firma visible según los ajustes de la aplicación (fuente, colores, posición del texto y
 * tamaño de imagen) y del documento (texto, imagen, origen, rotación y la escala elegida
 * en la vista previa), como appendVisibleSignature de la versión Java. `pageGeometry`
 * hace falta para corregir el origen con una rotación explícita.
 *
 * Throws: Exception si la escala del documento está fuera de los límites de configuration.d.
 */
VisibleSignature visibleSignatureFor(const Settings appSettings, const Settings documentSettings,
    string text, immutable(ubyte)[] image, const PageGeometry pageGeometry) @safe {
  float scale = documentSettings.signScale;
  // También rechaza NaN, que llegaría de un docSettings dañado.
  enforce(scale >= minSignatureScale && scale <= maxSignatureScale, format(
    "La escala de la firma visible (%s) debe estar entre %s y %s", scale, minSignatureScale, maxSignatureScale));
  VisibleSignature visible;
  visible.text = appSettings.isOnlyImageAlignment ? null : text;
  visible.font = resolveSignatureFont(documentSettings.font.length ? documentSettings.font : appSettings.font);
  visible.fontSize = appSettings.fontSize * scale;
  visible.textColor = appSettings.getFontColor();
  visible.backgroundColor = appSettings.getBackgroundColor();
  visible.position = appSettings.getFontAlignment();
  if (image.length) {
    visible.image = image;
    auto imageSize = configuredImageSize(image, appSettings.signImageWidth, appSettings.signImageHeight);
    imageSize.width = cast(int) round(imageSize.width * scale);
    imageSize.height = cast(int) round(imageSize.height * scale);
    visible.imageSize = imageSize;
  }
  float originX = documentSettings.signXf.isNull ? documentSettings.signX : documentSettings.signXf.get;
  float originY = documentSettings.signYf.isNull ? documentSettings.signY : documentSettings.signYf.get;
  visible.rotation = documentSettings.getSignRotation();
  int degrees = angleForRotation(documentSettings.signRotation);
  if (degrees != 0) {
    // naturalBoxSize mide la caja sin rotar, sea cual sea la rotación pedida.
    auto natural = naturalBoxSize(layoutInput(visible, pageGeometry), encoderFor(visible));
    auto corrected = correctedOrigin(originX, originY, degrees, natural, pageGeometry.mediaBox.width,
      pageGeometry.mediaBox.height);
    info(format("Firma rotada %d grados: origen corregido a %s, %s (caja natural %s x %s)", degrees, corrected[0],
      corrected[1], natural[0], natural[1]));
    originX = corrected[0];
    originY = corrected[1];
  }
  visible.originX = originX;
  visible.originY = originY;
  return visible;
}

/// Firma el PDF en el nivel configurado, con firma visible si se pide; null si no se pudo (ya avisado).
immutable(ubyte)[] signPades(GuiInterface gui, SigningServices services, const SigningInput input,
    CardSignInfo card) @trusted {
  auto appSettings = currentSettings();
  auto documentSettings = documentSettingsOf(input);
  return signWithCard(gui, card, (SigningKey key) @trusted {
    auto certificate = key.certificate;
    auto level = documentSettings.getPAdESLevel();
    PadesSignatureParameters parameters;
    parameters.signingTime = Clock.currTime;
    parameters.reason = documentSettings.reason;
    parameters.location = documentSettings.place;
    parameters.contactInfo = documentSettings.contact;
    auto document = PdfDocument.open(input.content);
    int pages = document.pageCount();
    int pageNumber = resolvePageNumber(documentSettings.pageNumber, pages);
    enforce(pageNumber >= 1 && pageNumber <= pages, format("El PDF no tiene la página %d", pageNumber));
    parameters.pageIndex = pageNumber - 1;
    if (documentSettings.isVisibleSignature) {
      auto geometry = document.pageGeometry(parameters.pageIndex);
      string text = signatureText(certificate, documentSettings, appSettings, parameters.signingTime);
      auto image = loadSignatureImage(documentSettings.image);
      parameters.visible = true;
      parameters.appearance = visibleSignatureFor(appSettings, documentSettings, text, image, geometry);
    }
    document.close();
    gui.nextStep(t("signers_adding_graphic_representation"));
    PreparedSignature prepared;
    try {
      prepared = preparePadesSignature(input.content, parameters, padesSignatureContentSize);
    } catch (SignatureOverlapException exception) {
      error("Error al firmar (traslape de firma): ", exception.msg);
      gui.showMessage(t("signers_signature_overlap"));
      throw new ReportedSigningFailure(exception.msg, exception);
    }
    auto attributes = padesSignedAttributes(preparedDigest(prepared), certificate).idup;
    auto chain = services.intermediateChain(certificate);
    bool rsa = key.key.rsa;
    immutable(ubyte)[] complete(const(ubyte)[] value, const(ubyte)[] signatureTimestamp) @safe {
      return completePadesSignature(prepared, padesCms(attributes, value, rsa, certificate, chain,
        signatureTimestamp));
    }
    SignatureAssembly assembly;
    assembly.dataToSign = attributes;
    assembly.baseline = (const(ubyte)[] value) @safe => complete(value, null);
    // El sello de firma va dentro del CMS: el nivel T se arma de nuevo con él.
    assembly.upgraded = (const(ubyte)[] value) @safe => raiseLevel(complete(value, null), level,
      (signed) => complete(value, services.timestamp(value).der), (pdf) => withPadesValidationData(services, pdf),
      (signed) => addDocumentTimestamp(signed, services.timestamper));
    return assembly;
  });
}

/// Añade al PDF los datos de validación de todos sus firmantes y sellos (nivel LT).
private immutable(ubyte)[] withPadesValidationData(SigningServices services, immutable(ubyte)[] pdf) @safe {
  return addPadesValidationData(pdf, services.validationData(padesSigningMaterial(pdf, services.pool)));
}

/// Extiende el PDF a LTA: datos de validación de todas las firmas y sello de documento.
immutable(ubyte)[] extendPades(GuiInterface gui, SigningServices services, const ExtensionInput input) @safe {
  return extendReporting(gui, () @safe => addDocumentTimestamp(withPadesValidationData(services, input.signed),
    services.timestamper));
}

/**
 * Sella el PDF con un sello de tiempo de documento independiente, visible en la primera
 * página si se pide (timestamp en la versión Java). Null si falla, avisado.
 */
immutable(ubyte)[] timestampPdf(GuiInterface gui, SigningServices services, immutable(ubyte)[] pdf,
    bool visibleTimestamp) @trusted {
  auto appSettings = currentSettings();
  try {
    VisibleSignature appearance;
    if (visibleTimestamp) {
      string date = formatJavaDate(appSettings.dateFormat, Clock.currTime.toOtherTZ(costaRicaTimeZone()),
        dateLanguageFor(appSettings.language));
      appearance.text = format(t("signers_info_timestamp_included"), date);
      appearance.font = resolveSignatureFont(appSettings.font);
      appearance.fontSize = appSettings.fontSize;
      appearance.textColor = appSettings.getFontColor();
      appearance.backgroundColor = appSettings.getBackgroundColor();
      appearance.position = SignerTextPosition.right;
      appearance.rotation = SignatureRotation.automatic;
    }
    return addDocumentTimestamp(pdf, services.timestamper, visibleTimestamp, appearance, 0);
  } catch (Exception exception) {
    error("Error al agregar un sello de tiempo independiente: ", exception.msg);
    gui.showError(exception);
    return null;
  }
}

@("should scale the configured image size to 96 dpi pixels like the Java resampling")
unittest {
  ubyte[] png = [0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, 'I', 'H', 'D', 'R',
    0, 0, 0, 200, 0, 0, 0, 100, 8, 6, 0, 0, 0, 0, 0, 0, 0];
  auto natural = configuredImageSize(png.idup, 0, 10);
  assert(natural.width == 200 && natural.height == 100);
  auto scaled = configuredImageSize(png.idup, 7, 14);
  assert(scaled.width == 24 && scaled.height == 48 && scaled.dpiX == 96);
}
