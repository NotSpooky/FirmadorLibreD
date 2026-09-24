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
 * Cierre común de la validación de una firma en todos los formatos (validators/*): hora
 * mínima probada por los sellos válidos, validación de la cadena del firmante a esa hora,
 * controles de la hora declarada con los niveles de la política por omisión de DSS
 * (constraint.xml: SigningTime y SigningTimeInCertRange en FAIL) y el resultado final.
 */
module firmador.validation.conclusion;

import std.datetime.systime : SysTime;
import std.logger : warning;
import std.typecons : Nullable;

import firmador.cms.tsp : TimeStampToken;
import firmador.validation.certpath;
import firmador.validation.cmsverify : validateTimestamp;
import firmador.validation.model;
import firmador.x509.certificate;

/**
 * Completa `signature` (con sus sellos ya validados) y devuelve el resultado con el
 * formato dado. `signer` puede ser null si no se identificó el certificado de firma.
 */
SignatureResult concludeSignature(SignatureResult signature, Verdict verdict, Certificate signer,
    PathContext baseContext, string format_) @safe {
  Nullable!SysTime bestTime;
  foreach (stamped; signature.timestamps) {
    if (stamped.indication == Indication.passed && (bestTime.isNull || stamped.productionTime < bestTime.get))
      bestTime = stamped.productionTime;
  }
  SysTime best = bestTime.isNull ? baseContext.validationTime : bestTime.get;
  signature.bestSignatureTime = best;
  if (signature.signingTime.isNull) {
    verdict.degrade(Indication.indeterminate, SubIndication.sigConstraintsFailure,
      message(ValidationMessage.Level.error, "BBB_SAV_ISQPSTP_ANS"));
  }
  if (signer !is null) {
    PathContext context = baseContext;
    context.bestSignatureTime = best;
    auto path = validatePath(signer, context);
    signature.certificateChain = path.path;
    verdict.absorb(path.verdict);
    if (!signature.signingTime.isNull && !signer.isValidAt(signature.signingTime.get)) {
      verdict.degrade(Indication.indeterminate, SubIndication.sigConstraintsFailure,
        message(ValidationMessage.Level.error, "BBB_SAV_ISQPSTWSCVR_ANS"));
    }
  }
  foreach (stamped; signature.timestamps) {
    if (stamped.indication != Indication.passed) {
      verdict.warn(message(ValidationMessage.Level.warning, "ADEST_ROTVPIIC_ANS"));
      break;
    }
  }
  return finishSignature(signature, verdict, format_);
}

/**
 * Cierra el resultado de una firma con su formato y el veredicto: TOTAL_PASSED si pasó
 * todo o, si no, la indicación, la subindicación y los mensajes del veredicto.
 */
SignatureResult finishSignature(SignatureResult signature, Verdict verdict, string format_) pure @safe {
  signature.format = format_;
  signature.indication = verdict.isPassed ? Indication.totalPassed : verdict.indication;
  signature.subIndication = verdict.subIndication;
  signature.messages = verdict.messages;
  return signature;
}

/// Archivo de firmas que no se pudo leer: falla por formato con el detalle.
SignatureResult unreadableSignature(string filename, string format_, string detail) @safe {
  SignatureResult unreadable;
  unreadable.filename = filename;
  Verdict verdict;
  verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
    message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", detail));
  return finishSignature(unreadable, verdict, format_);
}

/**
 * Lee y valida un sello de la firma. Si no se puede leer, o no se puede armar lo que
 * cubre, queda como sello ilegible con el motivo y la validación de la firma sigue.
 *
 * Params:
 *   kind = sello de firma, de archivo o de documento.
 *   owner = de qué firma es, para la bitácora.
 *   read = el sello tal como viene en la firma.
 *   stampedData = lo que el sello debe cubrir.
 *   context = contexto de la firma, para la cadena de la autoridad de sellado.
 */
TimestampResult readTimestamp(TimestampResult.Kind kind, string owner, scope TimeStampToken delegate() @safe read,
    scope const(ubyte)[] delegate(const TimeStampToken token) @safe stampedData, PathContext context) @safe {
  try {
    auto token = read();
    return validateTimestamp(token, stampedData(token), kind, context);
  } catch (Exception exception) {
    warning("Sello de tiempo ilegible en ", owner, ": ", exception.msg);
    return unreadableTimestamp(kind, exception.msg);
  }
}

/// Sello que no se pudo leer: falla por formato con el detalle.
TimestampResult unreadableTimestamp(TimestampResult.Kind kind, string detail) @safe {
  TimestampResult failed;
  failed.kind = kind;
  failed.indication = Indication.failed;
  failed.subIndication = SubIndication.formatFailure;
  failed.messages ~= message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", detail);
  return failed;
}

/// Nivel baseline (B, T, LT o LTA) según lo que tiene la firma.
string baselineLevel(bool signatureTimestamp, bool validationValues, bool archiveTimestamp) pure nothrow @safe @nogc {
  if (!signatureTimestamp) return "B";
  if (!validationValues) return "T";
  return archiveTimestamp ? "LTA" : "LT";
}
