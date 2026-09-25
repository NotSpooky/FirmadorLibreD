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
 * Lo que reciben los firmadores de cada formato (firmador.signers.detector los elige): el
 * contenido, su nombre y tipo y los ajustes con que se firma. También los pasos que
 * comparten: firmar con la credencial (signWithCard), subir de nivel (raiseLevel) y
 * extender a LTA avisando (extendReporting). Los firmadores no conocen
 * firmador.documents.document; el documento los llama con un SigningInput.
 */
module firmador.signers.documentsigner;

import std.logger : error;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.documents.mimetype;
import firmador.gui.guiinterface;
import firmador.i18n : t;
import firmador.settings : Settings, SignatureLevel;
import firmador.settingsmanager : currentSettings;
import firmador.signers.common;
import firmador.validation.model : DetachedContent;

/// Lo que se firma.
struct SigningInput {
  immutable(ubyte)[] content;
  string name;
  SupportedMimeType mimeType;
  /// Ajustes del documento (razón, lugar, posición de la firma visible, niveles…).
  Settings settings;
  /// Otros archivos que van en el mismo contenedor ASiC (firma de varios documentos).
  DetachedContent[] additionalDocuments;
}

/// Contenido a extender a LTA, con los datos separados si la firma no los incluye.
struct ExtensionInput {
  immutable(ubyte)[] signed;
  string name;
  /// Documentos firmados por una firma separada (CAdES, XAdES o JAdES con archivos aparte).
  DetachedContent[] detached;

  /// El único documento separado, o null si no hay exactamente uno.
  immutable(ubyte)[] singleDetached() const pure nothrow @safe @nogc {
    return detached.length == 1 ? detached[0].content : null;
  }
}

/// Ajustes con que se firma: los del documento, o los vigentes si no trae.
const(Settings) documentSettingsOf(const SigningInput input) @safe {
  return input.settings is null ? currentSettings() : input.settings;
}

/// Paso de subida de nivel de un formato: recibe la firma y la devuelve con lo añadido.
alias LevelStep = immutable(ubyte)[] delegate(immutable(ubyte)[] signed) @safe;

/**
 * Sube una firma de nivel B hasta `level` con los pasos de su formato: sello de firma
 * (T), datos de validación (LT) y sello de archivo (LTA). Al extender a LTA una firma que
 * ya tiene su sello de firma, `alreadyTimestamped` salta el primero.
 */
immutable(ubyte)[] raiseLevel(immutable(ubyte)[] signed, SignatureLevel level, scope LevelStep addSignatureTimestamp,
    scope LevelStep addValidationData, scope LevelStep addArchiveTimestamp, bool alreadyTimestamped = false) @safe {
  if (level == SignatureLevel.b) return signed;
  if (!alreadyTimestamped) signed = addSignatureTimestamp(signed);
  if (level == SignatureLevel.t) return signed;
  signed = addValidationData(signed);
  if (level == SignatureLevel.lt) return signed;
  return addArchiveTimestamp(signed);
}

/// Cómo arma una firma cada formato a partir del valor que devuelve el dispositivo.
struct SignatureAssembly {
  /// Lo que firma el dispositivo (con SHA-256).
  immutable(ubyte)[] dataToSign;
  /// Documento firmado en nivel B.
  immutable(ubyte)[] delegate(const(ubyte)[] signatureValue) @safe baseline;
  /// Documento firmado en el nivel pedido; null si el formato sólo firma en nivel B.
  immutable(ubyte)[] delegate(const(ubyte)[] signatureValue) @safe upgraded;
}

/**
 * Pasos comunes de firma de todos los firmadores (los de la versión Java): abre la
 * credencial, comprueba el certificado, avisa cada paso, firma lo que arma `assemble` y
 * sube de nivel con respaldo a B. Devuelve null si no se pudo; el motivo ya se mostró.
 * `assemble` puede lanzar ReportedSigningFailure después de avisar por su cuenta.
 */
immutable(ubyte)[] signWithCard(GuiInterface gui, CardSignInfo card,
    scope SignatureAssembly delegate(SigningKey key) @safe assemble) @safe {
  gui.nextStep(t("signers_getting_verification_services"));
  return withSigningKey!(immutable(ubyte)[])(gui, card, "Error al solicitar firma al dispositivo", (signingKey) {
    gui.nextStep(t("signers_getting_card_certificates"));
    requireValidCertificate(gui, signingKey.certificate);
    gui.nextStep(t("signers_getting_tsp_services"));
    auto assembly = assemble(signingKey);
    gui.nextStep(t("signers_getting_data_structure"));
    auto signatureValue = signingKey.sign(assembly.dataToSign);
    gui.nextStep(t("signers_signing_data_structure"));
    immutable(ubyte)[] baseline() @safe {
      return assembly.baseline(signatureValue);
    }
    immutable(ubyte)[] upgraded() @safe {
      return assembly.upgraded is null ? baseline() : assembly.upgraded(signatureValue);
    }
    auto result = upgradeOrFallBack(gui, &upgraded, &baseline);
    if (result !is null) gui.nextStep(t("signers_document_sign_complete"));
    return result;
  });
}

/**
 * Pasos comunes de la extensión a LTA: avisa el inicio y el fin y, si falla, avisa con el
 * mensaje de sello adicional y devuelve null, como los extend de la versión Java.
 */
immutable(ubyte)[] extendReporting(GuiInterface gui, scope immutable(ubyte)[] delegate() @safe extension) @trusted {
  gui.nextStep(t("signers_extending_document_with_timestamp"));
  try {
    auto extended = extension();
    gui.nextStep(t("signers_additional_stamp_completed"));
    return extended;
  } catch (Exception exception) {
    error("Error al procesar información para al ampliar el nivel de firma avanzada a LTA (sello adicional): ",
      exception.msg);
    gui.showMessage(timestampFailureMessage("signers_not_possible_to_add_timestamp_extend", exception));
    // Como FirmadorPAdES: el paso se cierra también si falla, para que termine el progreso.
    gui.nextStep(t("signers_additional_stamp_completed"));
    return null;
  }
}

/**
 * Sube una firma ya hecha al nivel pedido y, si falla (típicamente sin Internet), avisa
 * con `messageKey` y se queda con el nivel B, como hacían los firmadores de la versión Java.
 */
immutable(ubyte)[] upgradeOrFallBack(GuiInterface gui, scope immutable(ubyte)[] delegate() @safe upgraded,
    scope immutable(ubyte)[] delegate() @safe baseline, string messageKey = "signers_not_possible_to_add_timestamp_sign")
    @safe {
  try {
    return upgraded();
  } catch (Exception exception) {
    error("Error al procesar información de firma avanzada: ", exception.msg);
    gui.showMessage(timestampFailureMessage(messageKey, exception));
    try {
      return baseline();
    } catch (Exception fallbackFailure) {
      error("Error al procesar información de firma avanzada en nivel de respaldo AdES-B: ", fallbackFailure.msg);
      gui.showError(fallbackFailure);
      return null;
    }
  }
}
