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
import std.typecons : Nullable;

import firmador.validation.certpath;
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
  signature.format = format_;
  signature.indication = verdict.isPassed ? Indication.totalPassed : verdict.indication;
  signature.subIndication = verdict.subIndication;
  signature.messages = verdict.messages;
  return signature;
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
