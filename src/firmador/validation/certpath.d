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
 * Validación de la cadena de un certificado (bloque X.509 Certificate Validation de
 * EN 319 102-1): se arma la cadena hasta una raíz de confianza (descargando emisores por
 * AIA si hace falta), se comprueban firmas, restricciones de CA, vigencia y el estado de
 * revocación de cada certificado con la información incrustada o, si se permite, la de
 * los servicios en línea. También reúne los datos de validación que llevan los niveles LT.
 */
module firmador.validation.certpath;

import std.algorithm : canFind;
import std.datetime.systime : SysTime;
import std.format : format;
import std.logger : info, trace, warning;
import std.typecons : Nullable;

import firmador.asn1.oids;
import firmador.cms.ocsp;
import firmador.crypto.openssl : isSignedBy;
import firmador.util.datetime : toRfc3339Utc;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.revocation;
import firmador.validation.sources;
import firmador.x509.certificate;
import firmador.x509.crl;

/// Papel del certificado en la validación, para elegir los mensajes (firma o sello).
enum CertificateRole { signature, timestamp }

/// Contexto de una validación de cadena.
struct PathContext {
  CertificatePool pool;
  ValidationSource source;
  SysTime validationTime;
  /// Fecha mínima probada en que existía lo firmado (sello de tiempo), o la de validación.
  SysTime bestSignatureTime;
  /// Respuestas OCSP (OCSPResponse o BasicOCSPResponse) y CRL que trae el documento.
  const(ubyte[])[] embeddedOcsp;
  const(ubyte[])[] embeddedCrls;
  CertificateRole role = CertificateRole.signature;
}

/**
 * Contexto para validar las cadenas de un documento: `pool` (la jerarquía nacional si no
 * se da, más lo que se le añada), el servicio en línea (null sin conexión) y la hora
 * de validación, que es también la mejor hora probada hasta revisar los sellos
 * (firmador.validation.conclusion.concludeSignature).
 */
PathContext pathContext(ValidationSource source, SysTime validationTime,
    CertificatePool pool = CertificatePool.withNationalHierarchy()) pure @safe {
  PathContext context;
  context.pool = pool;
  context.source = source;
  context.validationTime = validationTime;
  context.bestSignatureTime = validationTime;
  return context;
}

/// Usa lo que trae la firma: suma sus certificados al conjunto y toma sus revocaciones.
void includeEmbedded(ref PathContext context, const ValidationData embedded) pure @safe {
  context.pool.addAll(embedded.certificates);
  context.embeddedOcsp = embedded.ocspResponses;
  context.embeddedCrls = embedded.crls;
}

/// Resultado de validar una cadena.
struct PathValidation {
  /// Del certificado validado a la raíz (hasta donde se pudo armar).
  Certificate[] path;
  bool trusted;
  Verdict verdict;
  /// Información de revocación usada, una por certificado que no es raíz.
  RevocationInfo[] revocations;
}

private string roleSuffix(CertificateRole role) pure @safe {
  final switch (role) {
    case CertificateRole.signature: return "_SIG";
    case CertificateRole.timestamp: return "_TSP";
  }
}

/**
 * Arma la cadena de `leaf` hasta una raíz de confianza con los certificados conocidos y,
 * si hay `source`, los emisores descargados por AIA.
 */
Certificate[] buildPath(Certificate leaf, CertificatePool pool, ValidationSource source, out bool trusted) @safe {
  Certificate[] path = [leaf];
  Certificate current = leaf;
  trusted = false;
  foreach (depth; 0 .. 10) {
    if (pool.isTrusted(current)) {
      trusted = true;
      return path;
    }
    Certificate issuer = findVerifiedIssuer(current, pool.issuerCandidates(current));
    if (issuer is null && source !is null) {
      foreach (downloaded; source.issuers(current)) pool.add(downloaded);
      issuer = findVerifiedIssuer(current, pool.issuerCandidates(current));
    }
    if (issuer is null || sameCertificate(issuer, current) || containsCertificate(path, issuer)) return path;
    path ~= issuer;
    current = issuer;
  }
  return path;
}

private Certificate findVerifiedIssuer(Certificate certificate, Certificate[] candidates) @safe {
  foreach (candidate; candidates) {
    try {
      if (isSignedBy(certificate, candidate)) return candidate;
    } catch (Exception exception) {
      trace("No se pudo comprobar la firma de ", certificate.toString, " con ", candidate.toString, ": ", exception.msg);
    }
  }
  return null;
}

/**
 * Valida la cadena del certificado: confianza, restricciones y vigencia
 * (chainConstraintsVerdict) y revocación (checkRevocation). Nunca da por buena una cadena
 * sin firmas verificadas hasta una raíz de confianza y sin prueba de no revocación de cada
 * certificado intermedio y final.
 */
PathValidation validatePath(Certificate leaf, PathContext context) @safe {
  PathValidation result;
  result.path = buildPath(leaf, context.pool, context.source, result.trusted);
  if (!result.trusted) {
    result.verdict.degrade(Indication.indeterminate, SubIndication.noCertificateChainFound,
      message(ValidationMessage.Level.error, "BBB_XCV_CCCBB" ~ roleSuffix(context.role) ~ "_ANS"));
    return result;
  }
  result.verdict = chainConstraintsVerdict(result.path, context.validationTime, context.bestSignatureTime);
  foreach (index; 0 .. result.path.length - 1) {
    checkRevocation(result.path[index], result.path[index + 1], index == 0, context, result);
  }
  return result;
}

/**
 * Reglas de una cadena ya armada, certificado por certificado: su emisor es una CA que
 * puede firmar certificados y respeta su pathLen, no tiene extensiones críticas
 * desconocidas y está vigente (checkValidity).
 *
 * Params:
 *   path = del certificado validado a la raíz (buildPath).
 *   validationTime = hora de la validación.
 *   bestSignatureTime = fecha mínima probada de la firma; un certificado vencido hoy pero
 *     vigente entonces sólo da una advertencia.
 * Returns: el veredicto, con un mensaje por regla que no se cumple.
 */
Verdict chainConstraintsVerdict(const(Certificate)[] path, SysTime validationTime, SysTime bestSignatureTime)
    pure @safe {
  import std.array : join;
  Verdict verdict;
  foreach (index, certificate; path) {
    if (index + 1 < path.length) {
      auto issuer = path[index + 1];
      if (!issuer.isCa || (issuer.keyUsage !is null && !issuer.hasKeyUsage(KeyUsageBit.keyCertSign))) {
        verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
          message(ValidationMessage.Level.error, "BBB_XCV_ICAC_ANS", issuer.subject.readableName));
      }
      if (issuer.pathLengthConstraint >= 0 && index > 0 && index - 1 > issuer.pathLengthConstraint) {
        verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
          message(ValidationMessage.Level.error, "BBB_XCV_ICPDV_ANS"));
      }
    }
    if (certificate.unknownCriticalExtensions.length) {
      verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
        message(ValidationMessage.Level.error, "BBB_XCV_DCCUCE_ANS", certificate.unknownCriticalExtensions.join(", ")));
    }
    checkValidity(certificate, index == 0, validationTime, bestSignatureTime, verdict);
  }
  return verdict;
}

private void checkValidity(const Certificate certificate, bool isLeaf, SysTime validationTime,
    SysTime bestSignatureTime, ref Verdict verdict) pure @safe {
  if (certificate.isValidAt(validationTime)) return;
  bool validWhenSigned = certificate.isValidAt(bestSignatureTime);
  if (validWhenSigned && bestSignatureTime < validationTime) {
    // Vencido hoy pero vigente cuando se probó la existencia de la firma (sello de tiempo).
    verdict.warn(message(ValidationMessage.Level.warning, isLeaf ? "BBB_XCV_ICTIVRSC_ANS" : "BBB_XCV_SUB_ANS",
      certificate.subject.readableName));
    return;
  }
  if (validationTime < certificate.notBefore) {
    verdict.degrade(Indication.indeterminate, SubIndication.notYetValid,
      message(ValidationMessage.Level.error, "BBB_XCV_ICTIVRSC_ANS", certificate.subject.readableName));
  } else {
    verdict.degrade(Indication.indeterminate, SubIndication.outOfBoundsNoPoe,
      message(ValidationMessage.Level.error, "BBB_XCV_ICTIVRSC_ANS", certificate.subject.readableName));
  }
}

private RevocationInfo[] embeddedRevocations(const Certificate certificate, const Certificate issuer,
    ref PathContext context) @safe {
  RevocationInfo[] found;
  foreach (der; context.embeddedOcsp) {
    try {
      found ~= verifyOcsp(parseOcspResponse(der), certificate, issuer, context.pool.all);
    } catch (Exception) {
      // La respuesta es de otro certificado o no es válida: se sigue con las demás.
    }
  }
  foreach (der; context.embeddedCrls) {
    try {
      auto crl = parseCrl(der);
      if (crl.issuer.matches(certificate.issuer)) found ~= verifyCrl(crl, certificate, issuer);
    } catch (Exception exception) {
      trace("Se descarta una CRL incrustada: ", exception.msg);
    }
  }
  return found;
}

private RevocationInfo[] onlineRevocations(const Certificate certificate, const Certificate issuer,
    ref PathContext context, out string failure) @safe {
  RevocationInfo[] found;
  if (context.source is null) {
    failure = "no se permiten consultas en línea";
    return found;
  }
  OcspResponse response;
  string ocspFailure;
  if (context.source.ocsp(certificate, issuer, response, ocspFailure)) {
    try {
      found ~= verifyOcsp(response, certificate, issuer, context.pool.all);
      return found;
    } catch (Exception exception) {
      ocspFailure = exception.msg;
      warning("Respuesta OCSP descartada para ", certificate.toString, ": ", exception.msg);
    }
  }
  // Alternativa a OCSP (setRevocationFallback en DSS): la CRL.
  CertificateRevocationList crl;
  string crlFailure;
  if (context.source.crl(certificate, crl, crlFailure)) {
    try {
      found ~= verifyCrl(crl, certificate, issuer);
      return found;
    } catch (Exception exception) {
      crlFailure = exception.msg;
      warning("CRL descartada para ", certificate.toString, ": ", exception.msg);
    }
  }
  failure = format("OCSP: %s; CRL: %s", ocspFailure, crlFailure);
  return found;
}

private void checkRevocation(const Certificate certificate, const Certificate issuer, bool isLeaf,
    ref PathContext context, ref PathValidation result) @trusted {
  RevocationInfo[] candidates = embeddedRevocations(certificate, issuer, context);
  RevocationInfo[] acceptable;
  foreach (candidate; candidates) {
    if (isAcceptable(candidate, context.bestSignatureTime, context.validationTime)) acceptable ~= candidate;
  }
  string failure;
  if (acceptable.length == 0) {
    foreach (candidate; onlineRevocations(certificate, issuer, context, failure)) {
      if (isAcceptable(candidate, context.bestSignatureTime, context.validationTime)) acceptable ~= candidate;
      else failure = "la información obtenida no es fresca";
    }
  }
  auto chosen = latest(acceptable);
  if (chosen.isNull) info("Sin información de revocación aceptable para ", certificate.toString, ": ", failure);
  else result.revocations ~= chosen.get;
  result.verdict.absorb(revocationVerdict(chosen, certificate, issuer, isLeaf, context.role,
    context.bestSignatureTime, context.validationTime));
}

/**
 * Veredicto del estado de revocación de un certificado de la cadena. Una revocación
 * posterior a la fecha probada de la firma sólo da una advertencia; antes, invalida la
 * firma si es el certificado final y la deja indeterminada si es una CA.
 *
 * Params:
 *   chosen = la revocación aceptable más reciente (latest), o nula si no hubo ninguna.
 *   certificate = el certificado revisado.
 *   issuer = su emisor, que puede firmar la revocación sin id-pkix-ocsp-nocheck.
 *   isLeaf = `certificate` es el certificado final de la cadena.
 *   role = papel de la cadena; sólo la del firmante da TOTAL_FAILED si está revocado.
 *   bestSignatureTime = fecha mínima probada de la firma.
 *   validationTime = hora de la validación.
 * Returns: el veredicto, aprobado si el estado es bueno.
 */
Verdict revocationVerdict(Nullable!RevocationInfo chosen, const Certificate certificate, const Certificate issuer,
    bool isLeaf, CertificateRole role, SysTime bestSignatureTime, SysTime validationTime) pure @safe {
  Verdict verdict;
  string name = certificate.subject.readableName;
  if (chosen.isNull) {
    verdict.degrade(Indication.indeterminate, SubIndication.tryLater,
      message(ValidationMessage.Level.error, isLeaf ? "BBB_XCV_IRDPFC_ANS" : "BBB_XCV_IARDPFC_ANS", name));
    return verdict;
  }
  auto revocation = chosen.get;
  final switch (revocation.status) {
    case CertificateStatus.good:
      break;
    case CertificateStatus.unknown:
      verdict.degrade(Indication.indeterminate, SubIndication.tryLater,
        message(ValidationMessage.Level.error, "BBB_XCV_ISCUKN_ANS", name));
      break;
    case CertificateStatus.revoked:
      bool revokedBeforeSigning = revocation.revocationTime <= bestSignatureTime;
      if (!revokedBeforeSigning && bestSignatureTime < validationTime) {
        // Revocado después de la fecha probada de la firma: no la invalida.
        verdict.warn(message(ValidationMessage.Level.warning, "BBB_XCV_ISCR_ANS",
          format("%s (%s)", name, toRfc3339Utc(revocation.revocationTime))));
        break;
      }
      if (isLeaf) {
        verdict.degrade(role == CertificateRole.signature ? Indication.totalFailed : Indication.failed,
          SubIndication.revoked, message(ValidationMessage.Level.error, "BBB_XCV_ISCR_ANS", name));
      } else {
        verdict.degrade(Indication.indeterminate, SubIndication.revokedCaNoPoe,
          message(ValidationMessage.Level.error, "BBB_XCV_ISCR_ANS", name));
      }
      break;
  }
  if (revocation.signer !is null && !sameCertificate(revocation.signer, issuer) && !revocation.signer.ocspNoCheck) {
    verdict.warn(message(ValidationMessage.Level.info, "BBB_XCV_OCSP_NO_CHECK_ANS"));
  }
  return verdict;
}

/// Datos de validación de nivel LT: certificados y revocaciones de una o varias cadenas.
struct ValidationData {
  Certificate[] certificates;
  immutable(ubyte)[][] ocspResponses;
  immutable(ubyte)[][] crls;

  /// Añade lo que usó una validación de cadena, sin repetir.
  void addPath(const PathValidation validation) pure @trusted {
    foreach (certificate; validation.path) addCertificate(certificate);
    foreach (revocation; validation.revocations) {
      if (revocation.kind == RevocationInfo.Kind.ocsp) {
        if (!ocspResponses.canFind(revocation.der)) ocspResponses ~= revocation.der;
        foreach (included; revocation.includedCertificates) addCertificate(included);
      } else if (!crls.canFind(revocation.der)) {
        crls ~= revocation.der;
      }
      if (revocation.signer !is null) addCertificate(revocation.signer);
    }
  }

  void addCertificate(const Certificate certificate) pure @trusted {
    if (!containsCertificate(certificates, certificate)) certificates ~= cast(Certificate) certificate;
  }

  /// No trae nada.
  bool empty() const pure nothrow @safe @nogc {
    return certificates.length == 0 && ocspResponses.length == 0 && crls.length == 0;
  }

}

/**
 * Lo de `wanted` que no está en `present`: lo que falta añadir a una firma que ya lleva
 * datos de validación (nivel LT de XAdES y JAdES).
 */
ValidationData missingFrom(const ValidationData wanted, const ValidationData present) pure @safe {
  ValidationData missing;
  foreach (certificate; wanted.certificates) {
    if (!containsCertificate(present.certificates, certificate)) missing.addCertificate(certificate);
  }
  foreach (ocsp; wanted.ocspResponses) if (!present.ocspResponses.canFind(ocsp)) missing.ocspResponses ~= ocsp;
  foreach (crl; wanted.crls) if (!present.crls.canFind(crl)) missing.crls ~= crl;
  return missing;
}

/**
 * Reúne la cadena y la información de revocación de los certificados dados, consultando
 * los servicios en línea, para incorporarlas a una firma de nivel LT. También valida la
 * cadena del firmante de cada respuesta OCSP delegada.
 *
 * Throws: Exception si falta la información de revocación de algún certificado, con el
 * certificado y el motivo: sin ella la firma no puede subir de nivel.
 */
ValidationData collectValidationData(Certificate[] certificates, CertificatePool pool, ValidationSource source,
    SysTime now, const(ubyte[])[] embeddedOcsp = null, const(ubyte[])[] embeddedCrls = null) @safe {
  ValidationData data;
  Certificate[] pending = certificates.dup;
  Certificate[] done;
  while (pending.length) {
    auto certificate = pending[0];
    pending = pending[1 .. $];
    if (containsCertificate(done, certificate)) continue;
    done ~= certificate;
    PathContext context;
    context.pool = pool;
    context.source = source;
    context.validationTime = now;
    context.bestSignatureTime = now;
    context.embeddedOcsp = embeddedOcsp;
    context.embeddedCrls = embeddedCrls;
    auto validation = validatePath(certificate, context);
    if (!validation.trusted) {
      throw new Exception(format("No se pudo armar la cadena de confianza de %s", certificate.toString));
    }
    foreach (message; validation.verdict.messages) {
      if (message.level == ValidationMessage.Level.error) {
        throw new Exception(format("No se pudo obtener la información de validación de %s: %s", certificate.toString,
          message.text));
      }
    }
    data.addPath(validation);
    foreach (revocation; validation.revocations) {
      if (revocation.signer !is null && !containsCertificate(done, revocation.signer) && !pool.isTrusted(revocation.signer)
          && !revocation.signer.ocspNoCheck && !containsCertificate(validation.path, revocation.signer)) {
        pending ~= revocation.signer;
      }
    }
  }
  return data;
}

@("should build the national hierarchy chain up to the trusted root without network access")
unittest {
  auto pool = CertificatePool.withNationalHierarchy();
  auto tsa = bundledCertificate!"certs/TSA SINPE v4.crt"();
  bool trusted;
  auto path = buildPath(tsa, pool, null, trusted);
  assert(trusted);
  assert(path.length == 3);
  assert(path[$ - 1].subject.readableName == "CA RAIZ NACIONAL - COSTA RICA v2");
}

@("should not pass a chain without revocation information when validating offline")
unittest {
  import std.datetime.systime : Clock;
  auto pool = CertificatePool.withNationalHierarchy();
  PathContext context;
  context.pool = pool;
  context.source = null;
  context.validationTime = Clock.currTime;
  context.bestSignatureTime = context.validationTime;
  context.role = CertificateRole.timestamp;
  auto result = validatePath(bundledCertificate!"certs/TSA SINPE v4.crt"(), context);
  assert(result.trusted);
  assert(result.verdict.indication == Indication.indeterminate);
  assert(result.verdict.subIndication == SubIndication.tryLater);
}

@("should not trust a self signed certificate that is not a bundled root")
unittest {
  import std.datetime.systime : Clock;
  import firmador.crypto.openssl : makeTestIdentity;
  auto foreign = parseCertificate(makeTestIdentity("Raíz ajena", "x").certificateDer);
  PathContext context;
  context.pool = CertificatePool.withNationalHierarchy();
  context.source = null;
  context.validationTime = Clock.currTime;
  context.bestSignatureTime = context.validationTime;
  auto result = validatePath(foreign, context);
  assert(!result.trusted);
  assert(result.verdict.subIndication == SubIndication.noCertificateChainFound);
}

@("should warn instead of failing when an expired certificate was valid at the proven signing time")
unittest {
  import core.time : dur;
  bool trusted;
  auto path = buildPath(bundledCertificate!"certs/TSA SINPE v4.crt"(), CertificatePool.withNationalHierarchy(),
    null, trusted);
  auto tsa = path[0];
  SysTime during = tsa.notBefore + dur!"days"(1);
  SysTime after = tsa.notAfter + dur!"days"(1);
  auto current = chainConstraintsVerdict(path, during, during);
  assert(current.isPassed && current.messages.length == 0);
  auto provenBefore = chainConstraintsVerdict(path, after, during);
  assert(provenBefore.isPassed && provenBefore.messages.length == 1
    && provenBefore.messages[0].level == ValidationMessage.Level.warning);
  assert(chainConstraintsVerdict(path, after, after).subIndication == SubIndication.outOfBoundsNoPoe);
  SysTime early = tsa.notBefore - dur!"days"(1);
  assert(chainConstraintsVerdict(path, early, early).subIndication == SubIndication.notYetValid);
}

@("should reject a chain when the issuer is not a certification authority")
unittest {
  import core.time : dur;
  bool trusted;
  auto path = buildPath(bundledCertificate!"certs/TSA SINPE v4.crt"(), CertificatePool.withNationalHierarchy(),
    null, trusted);
  SysTime during = path[0].notBefore + dur!"days"(1);
  auto issuedByLeaf = chainConstraintsVerdict([path[1], path[0]], during, during);
  assert(issuedByLeaf.subIndication == SubIndication.chainConstraintsFailure);
  assert(issuedByLeaf.messages[0].key == "BBB_XCV_ICAC_ANS");
}

@("should fail a revoked certificate only when it was revoked before the proven signing time")
unittest {
  import core.time : dur;
  import std.typecons : nullable;
  bool trusted;
  auto path = buildPath(bundledCertificate!"certs/TSA SINPE v4.crt"(), CertificatePool.withNationalHierarchy(),
    null, trusted);
  auto leaf = path[0], issuer = path[1];
  RevocationInfo revoked;
  revoked.status = CertificateStatus.revoked;
  revoked.revocationTime = leaf.notBefore + dur!"days"(10);
  revoked.signer = issuer;
  SysTime afterRevocation = revoked.revocationTime + dur!"days"(1);
  SysTime validation = revoked.revocationTime + dur!"days"(2);
  auto signer = revocationVerdict(nullable(revoked), leaf, issuer, true, CertificateRole.signature, afterRevocation,
    validation);
  assert(signer.indication == Indication.totalFailed && signer.subIndication == SubIndication.revoked);
  assert(revocationVerdict(nullable(revoked), leaf, issuer, true, CertificateRole.timestamp, afterRevocation,
    validation).indication == Indication.failed);
  assert(revocationVerdict(nullable(revoked), leaf, issuer, false, CertificateRole.signature, afterRevocation,
    validation).subIndication == SubIndication.revokedCaNoPoe);
  auto provenBefore = revocationVerdict(nullable(revoked), leaf, issuer, true, CertificateRole.signature,
    revoked.revocationTime - dur!"days"(1), validation);
  assert(provenBefore.isPassed && provenBefore.messages[0].level == ValidationMessage.Level.warning);
}

@("should ask to retry when there is no acceptable revocation and note a delegated responder without nocheck")
unittest {
  import core.time : dur;
  import std.typecons : Nullable, nullable;
  bool trusted;
  auto path = buildPath(bundledCertificate!"certs/TSA SINPE v4.crt"(), CertificatePool.withNationalHierarchy(),
    null, trusted);
  auto leaf = path[0], issuer = path[1];
  SysTime during = leaf.notBefore + dur!"days"(1);
  auto missingLeaf = revocationVerdict(Nullable!RevocationInfo.init, leaf, issuer, true, CertificateRole.signature,
    during, during);
  assert(missingLeaf.subIndication == SubIndication.tryLater && missingLeaf.messages[0].key == "BBB_XCV_IRDPFC_ANS");
  assert(revocationVerdict(Nullable!RevocationInfo.init, issuer, path[2], false, CertificateRole.signature, during,
    during).messages[0].key == "BBB_XCV_IARDPFC_ANS");
  RevocationInfo delegated;
  delegated.status = CertificateStatus.good;
  delegated.signer = leaf;
  auto good = revocationVerdict(nullable(delegated), leaf, issuer, true, CertificateRole.signature, during, during);
  assert(good.isPassed && good.messages.length == 1 && good.messages[0].key == "BBB_XCV_OCSP_NO_CHECK_ANS");
}
