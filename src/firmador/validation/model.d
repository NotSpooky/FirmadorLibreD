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
 * Resultados de validación comunes a todos los formatos: indicación y subindicación de
 * ETSI EN 319 102-1 (las de los reportes de DSS), mensajes de los controles y el
 * resultado de cada firma y de cada sello de tiempo, que firmador.validation.report
 * convierte en el reporte simple.
 */
module firmador.validation.model;

import std.datetime.systime : SysTime;
import std.typecons : Nullable;

import firmador.i18n : validationMessage, t;
import firmador.x509.certificate : Certificate;

/// Indicación principal (EN 319 102-1 §5.1.3).
enum Indication { totalPassed, passed, indeterminate, failed, totalFailed }

/// Subindicación que explica una indicación distinta de aprobada.
enum SubIndication {
  none,
  formatFailure,
  hashFailure,
  sigCryptoFailure,
  revoked,
  sigConstraintsFailure,
  chainConstraintsFailure,
  certificateChainGeneralFailure,
  cryptoConstraintsFailure,
  expired,
  notYetValid,
  policyProcessingError,
  signaturePolicyNotAvailable,
  timestampOrderFailure,
  noSigningCertificateFound,
  noCertificateChainFound,
  revokedNoPoe,
  revokedCaNoPoe,
  outOfBoundsNoPoe,
  outOfBoundsNotRevoked,
  noPoe,
  tryLater,
  signedDataNotFound,
}

/// Nombre de la indicación en los reportes (TOTAL_PASSED…).
string indicationName(Indication indication) pure nothrow @safe @nogc {
  final switch (indication) {
    case Indication.totalPassed: return "TOTAL_PASSED";
    case Indication.passed: return "PASSED";
    case Indication.indeterminate: return "INDETERMINATE";
    case Indication.failed: return "FAILED";
    case Indication.totalFailed: return "TOTAL_FAILED";
  }
}

/// Nombre de la subindicación en los reportes (HASH_FAILURE…).
string subIndicationName(SubIndication sub) pure nothrow @safe @nogc {
  final switch (sub) {
    case SubIndication.none: return "";
    case SubIndication.formatFailure: return "FORMAT_FAILURE";
    case SubIndication.hashFailure: return "HASH_FAILURE";
    case SubIndication.sigCryptoFailure: return "SIG_CRYPTO_FAILURE";
    case SubIndication.revoked: return "REVOKED";
    case SubIndication.sigConstraintsFailure: return "SIG_CONSTRAINTS_FAILURE";
    case SubIndication.chainConstraintsFailure: return "CHAIN_CONSTRAINTS_FAILURE";
    case SubIndication.certificateChainGeneralFailure: return "CERTIFICATE_CHAIN_GENERAL_FAILURE";
    case SubIndication.cryptoConstraintsFailure: return "CRYPTO_CONSTRAINTS_FAILURE";
    case SubIndication.expired: return "EXPIRED";
    case SubIndication.notYetValid: return "NOT_YET_VALID";
    case SubIndication.policyProcessingError: return "POLICY_PROCESSING_ERROR";
    case SubIndication.signaturePolicyNotAvailable: return "SIGNATURE_POLICY_NOT_AVAILABLE";
    case SubIndication.timestampOrderFailure: return "TIMESTAMP_ORDER_FAILURE";
    case SubIndication.noSigningCertificateFound: return "NO_SIGNING_CERTIFICATE_FOUND";
    case SubIndication.noCertificateChainFound: return "NO_CERTIFICATE_CHAIN_FOUND";
    case SubIndication.revokedNoPoe: return "REVOKED_NO_POE";
    case SubIndication.revokedCaNoPoe: return "REVOKED_CA_NO_POE";
    case SubIndication.outOfBoundsNoPoe: return "OUT_OF_BOUNDS_NO_POE";
    case SubIndication.outOfBoundsNotRevoked: return "OUT_OF_BOUNDS_NOT_REVOKED";
    case SubIndication.noPoe: return "NO_POE";
    case SubIndication.tryLater: return "TRY_LATER";
    case SubIndication.signedDataNotFound: return "SIGNED_DATA_NOT_FOUND";
  }
}

/// Mensaje de un control de validación.
struct ValidationMessage {
  enum Level { error, warning, info }
  Level level;
  /// Clave del texto (dss-messages o messages).
  string key;
  string text;
}

/// Mensaje con el texto de DSS para la clave (o el de messages.properties si no está ahí).
ValidationMessage message(ValidationMessage.Level level, string key, string detail = null) @safe {
  string text = validationMessage(key);
  if (text is null) text = t(key);
  if (detail.length) text ~= " " ~ detail;
  return ValidationMessage(level, key, text);
}

/// Resultado de un paso: indicación, subindicación y mensajes acumulados.
struct Verdict {
  Indication indication = Indication.passed;
  SubIndication subIndication;
  ValidationMessage[] messages;

  bool isPassed() const pure nothrow @safe @nogc {
    return indication == Indication.passed || indication == Indication.totalPassed;
  }

  /// Rebaja la indicación si la nueva es peor, conservando la primera causa.
  void degrade(Indication worse, SubIndication cause, ValidationMessage why) pure @safe {
    messages ~= why;
    if (severity(worse) > severity(indication)) {
      indication = worse;
      subIndication = cause;
    }
  }

  void warn(ValidationMessage why) pure @safe {
    messages ~= why;
  }

  /// Incorpora el resultado de un paso: sus mensajes y su indicación, si es peor.
  void absorb(const Verdict step) pure @safe {
    absorbInto(this, step);
  }
}

/// Añade a `target` (Verdict o TimestampResult) los mensajes del paso y su indicación, si es peor.
private void absorbInto(T)(ref T target, const Verdict step) pure @safe {
  target.messages ~= step.messages;
  if (severity(step.indication) > severity(target.indication)) {
    target.indication = step.indication;
    target.subIndication = step.subIndication;
  }
}

private int severity(Indication indication) pure nothrow @safe @nogc {
  final switch (indication) {
    case Indication.totalPassed, Indication.passed: return 0;
    case Indication.indeterminate: return 1;
    case Indication.failed, Indication.totalFailed: return 2;
  }
}

/// Resultado de un sello de tiempo (de firma, de archivo o de documento).
struct TimestampResult {
  enum Kind { signature, archive, document, content }
  Kind kind;
  Indication indication;
  SubIndication subIndication;
  ValidationMessage[] messages;
  SysTime productionTime;
  Certificate[] certificateChain;
  string filename;

  /// Incorpora el resultado de una comprobación más: sus mensajes y su indicación, si es peor.
  void absorb(const Verdict step) pure @safe {
    absorbInto(this, step);
  }
}

/// Resultado de una firma.
struct SignatureResult {
  string id;
  /// Formato y nivel (PAdES-BASELINE-LTA…).
  string format;
  Indication indication;
  SubIndication subIndication;
  ValidationMessage[] messages;
  /// Fecha que declara la firma.
  Nullable!SysTime signingTime;
  /// Fecha mínima probada de existencia (la del primer sello válido o la de validación).
  Nullable!SysTime bestSignatureTime;
  /// Cadena del firmante, del certificado de firma a la raíz.
  Certificate[] certificateChain;
  TimestampResult[] timestamps;
  string filename;
  bool counterSignature;
  /// Hubo cambios en anotaciones de un PDF después de firmar.
  bool pdfAnnotationChanges;
}

/// Resultado de validar un documento.
struct DocumentValidationResult {
  string documentName;
  SysTime validationTime;
  SignatureResult[] signatures;
  /// Sellos de tiempo de documento que no pertenecen a una firma (PDF /DocTimeStamp).
  TimestampResult[] documentTimestamps;
}

/// Archivo que firma una firma separada, con el nombre con que la firma lo nombra.
struct DetachedContent {
  string name;
  immutable(ubyte)[] content;
}
