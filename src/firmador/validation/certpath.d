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

import firmador.asn1.oids;
import firmador.cms.ocsp;
import firmador.crypto.openssl : isSignedBy;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.revocation;
import firmador.validation.sources;
import firmador.x509.certificate;
import firmador.x509.crl;

/// Papel del certificado en la validación, para elegir los mensajes (firma, sello o revocación).
enum CertificateRole { signature, timestamp, revocation }

/// Contexto de una validación de cadena.
struct PathContext {
  CertificatePool pool;
  ValidationDataSource source;
  /// Se pueden consultar servicios en línea (AIA, OCSP, CRL).
  bool allowOnline = true;
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
 * se da, más lo que se le añada), el servicio en línea, si se puede consultar, y la hora
 * de validación, que es también la mejor hora probada hasta revisar los sellos
 * (firmador.validation.conclusion.concludeSignature).
 */
PathContext pathContext(ValidationDataSource source, bool allowOnline, SysTime validationTime,
    CertificatePool pool = CertificatePool.withNationalHierarchy()) @safe {
  PathContext context;
  context.pool = pool;
  context.source = source;
  context.allowOnline = allowOnline;
  context.validationTime = validationTime;
  context.bestSignatureTime = validationTime;
  return context;
}

/// Usa lo que trae la firma: suma sus certificados al conjunto y toma sus revocaciones.
void includeEmbedded(ref PathContext context, const ValidationData embedded) @safe {
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
    case CertificateRole.revocation: return "_REV";
  }
}

/**
 * Arma la cadena de `leaf` hasta una raíz de confianza con los certificados conocidos y,
 * si se permite, los emisores descargados por AIA.
 */
Certificate[] buildPath(Certificate leaf, CertificatePool pool, ValidationDataSource source, bool allowOnline,
    out bool trusted) @safe {
  Certificate[] path = [leaf];
  Certificate current = leaf;
  trusted = false;
  foreach (depth; 0 .. 10) {
    if (pool.isTrusted(current)) {
      trusted = true;
      return path;
    }
    Certificate issuer = findVerifiedIssuer(current, pool.issuerCandidates(current));
    if (issuer is null && allowOnline && source !is null) {
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
 * Valida la cadena del certificado: confianza, restricciones, vigencia y revocación.
 * Nunca da por buena una cadena sin firmas verificadas hasta una raíz de confianza y sin
 * prueba de no revocación de cada certificado intermedio y final.
 */
PathValidation validatePath(Certificate leaf, PathContext context) @safe {
  PathValidation result;
  result.path = buildPath(leaf, context.pool, context.source, context.allowOnline, result.trusted);
  string suffix = roleSuffix(context.role);
  if (!result.trusted) {
    result.verdict.degrade(Indication.indeterminate, SubIndication.noCertificateChainFound,
      message(ValidationMessage.Level.error, "BBB_XCV_CCCBB" ~ suffix ~ "_ANS"));
    return result;
  }

  foreach (index, certificate; result.path) {
    bool isAnchor = index == result.path.length - 1;
    if (!isAnchor) {
      auto issuer = result.path[index + 1];
      if (!issuer.isCa || (issuer.keyUsage !is null && !issuer.hasKeyUsage(KeyUsageBit.keyCertSign))) {
        result.verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
          message(ValidationMessage.Level.error, "BBB_XCV_ICAC_ANS", issuer.subject.readableName));
      }
      if (issuer.pathLengthConstraint >= 0 && index > 0 && index - 1 > issuer.pathLengthConstraint) {
        result.verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
          message(ValidationMessage.Level.error, "BBB_XCV_ICPDV_ANS"));
      }
    }
    if (certificate.unknownCriticalExtensions.length) {
      import std.array : join;
      result.verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
        message(ValidationMessage.Level.error, "BBB_XCV_DCCUCE_ANS", certificate.unknownCriticalExtensions.join(", ")));
    }
    checkValidity(certificate, index == 0, context, result.verdict);
  }

  foreach (index; 0 .. result.path.length - 1) {
    auto certificate = result.path[index];
    auto issuer = result.path[index + 1];
    checkRevocation(certificate, issuer, index == 0, context, result);
  }
  return result;
}

private void checkValidity(const Certificate certificate, bool isLeaf, ref PathContext context, ref Verdict verdict)
    @safe {
  if (certificate.isValidAt(context.validationTime)) return;
  bool validWhenSigned = certificate.isValidAt(context.bestSignatureTime);
  if (validWhenSigned && context.bestSignatureTime < context.validationTime) {
    // Vencido hoy pero vigente cuando se probó la existencia de la firma (sello de tiempo).
    verdict.warn(message(ValidationMessage.Level.warning, isLeaf ? "BBB_XCV_ICTIVRSC_ANS" : "BBB_XCV_SUB_ANS",
      certificate.subject.readableName));
    return;
  }
  if (context.validationTime < certificate.notBefore) {
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
  if (!context.allowOnline || context.source is null) {
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
  if (chosen.isNull) {
    info("Sin información de revocación aceptable para ", certificate.toString, ": ", failure);
    result.verdict.degrade(Indication.indeterminate, SubIndication.tryLater,
      message(ValidationMessage.Level.error, isLeaf ? "BBB_XCV_IRDPFC_ANS" : "BBB_XCV_IARDPFC_ANS",
        certificate.subject.readableName));
    return;
  }
  auto revocation = chosen.get;
  result.revocations ~= revocation;
  final switch (revocation.status) {
    case CertificateStatus.good:
      break;
    case CertificateStatus.unknown:
      result.verdict.degrade(Indication.indeterminate, SubIndication.tryLater,
        message(ValidationMessage.Level.error, "BBB_XCV_ISCUKN_ANS", certificate.subject.readableName));
      break;
    case CertificateStatus.revoked:
      bool revokedBeforeSigning = revocation.revocationTime <= context.bestSignatureTime;
      if (!revokedBeforeSigning && context.bestSignatureTime < context.validationTime) {
        // Revocado después de la fecha probada de la firma: no la invalida.
        result.verdict.warn(message(ValidationMessage.Level.warning, "BBB_XCV_ISCR_ANS",
          format("%s (%s)", certificate.subject.readableName, revocation.revocationTime.toISOExtString)));
        break;
      }
      if (isLeaf) {
        result.verdict.degrade(context.role == CertificateRole.signature ? Indication.totalFailed : Indication.failed,
          SubIndication.revoked, message(ValidationMessage.Level.error, "BBB_XCV_ISCR_ANS",
          certificate.subject.readableName));
      } else {
        result.verdict.degrade(Indication.indeterminate, SubIndication.revokedCaNoPoe,
          message(ValidationMessage.Level.error, "BBB_XCV_ISCR_ANS", certificate.subject.readableName));
      }
      break;
  }
  if (revocation.signer !is null && !sameCertificate(revocation.signer, issuer) && !revocation.signer.ocspNoCheck) {
    result.verdict.warn(message(ValidationMessage.Level.info, "BBB_XCV_OCSP_NO_CHECK_ANS"));
  }
}

/// Datos de validación de nivel LT: certificados y revocaciones de una o varias cadenas.
struct ValidationData {
  Certificate[] certificates;
  immutable(ubyte)[][] ocspResponses;
  immutable(ubyte)[][] crls;

  /// Añade lo que usó una validación de cadena, sin repetir.
  void addPath(const PathValidation validation) @trusted {
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

  void addCertificate(const Certificate certificate) @trusted {
    if (!containsCertificate(certificates, certificate)) certificates ~= cast(Certificate) certificate;
  }

  /// No trae nada.
  bool empty() const pure nothrow @safe @nogc {
    return certificates.length == 0 && ocspResponses.length == 0 && crls.length == 0;
  }

  /// Une otros datos de validación a estos.
  void merge(const ValidationData other) @trusted {
    foreach (certificate; other.certificates) addCertificate(certificate);
    foreach (der; other.ocspResponses) if (!ocspResponses.canFind(der)) ocspResponses ~= der;
    foreach (der; other.crls) if (!crls.canFind(der)) crls ~= der;
  }
}

/**
 * Lo de `wanted` que no está en `present`: lo que falta añadir a una firma que ya lleva
 * datos de validación (nivel LT de XAdES y JAdES).
 */
ValidationData missingFrom(const ValidationData wanted, const ValidationData present) @safe {
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
ValidationData collectValidationData(Certificate[] certificates, CertificatePool pool, ValidationDataSource source,
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
  auto path = buildPath(tsa, pool, new OfflineValidationSource, false, trusted);
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
  context.source = new OfflineValidationSource;
  context.allowOnline = false;
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
  context.source = new OfflineValidationSource;
  context.allowOnline = false;
  context.validationTime = Clock.currTime;
  context.bestSignatureTime = context.validationTime;
  auto result = validatePath(foreign, context);
  assert(!result.trusted);
  assert(result.verdict.subIndication == SubIndication.noCertificateChainFound);
}
