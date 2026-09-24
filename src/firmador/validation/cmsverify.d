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
 * Verificación criptográfica de firmas CMS (identificación del certificado firmante,
 * atributo signing-certificate, message-digest y valor de la firma) y validación completa
 * de sellos de tiempo RFC 3161, que usan las firmas PAdES, CAdES, XAdES y JAdES.
 */
module firmador.validation.cmsverify;

import std.algorithm : canFind;
import std.exception : enforce;
import std.format : format;
import std.logger : warning;

import firmador.asn1.oids;
import firmador.cms.signeddata;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.crypto.openssl;
import firmador.validation.certpath;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.x509.certificate;

/// Resultado de la verificación criptográfica de un firmante CMS.
struct CmsSignerVerification {
  Certificate signingCertificate;
  Verdict verdict;
  bool hashValid;
  bool signatureValid;
  /// Por qué no se pudo verificar la firma (algoritmo no admitido…), o null.
  string signatureFailure;
}

/**
 * Certificado del firmante entre los del SignedData y los conocidos, o null.
 * El atributo signing-certificate(-v2), si está, debe coincidir con él.
 */
Certificate findSignerCertificate(const SignedData signedData, const SignerInfo signer, CertificatePool pool) @trusted {
  foreach (certificate; signedData.certificates) if (signer.identifies(certificate)) return cast(Certificate) certificate;
  foreach (certificate; pool.all) if (signer.identifies(certificate)) return cast(Certificate) certificate;
  return null;
}

/**
 * Certificado de la autoridad que firmó el sello (su único firmante), del propio sello o
 * de `pool`. Lo piden los niveles LT y LTA para incluir su cadena y su revocación.
 *
 * Throws: Exception con la fecha del sello si el certificado no está en ninguno de los dos:
 * sin él, los datos de validación de la firma quedarían incompletos.
 */
Certificate timestampSignerCertificate(const TimeStampToken token, CertificatePool pool) @safe {
  auto authority = findSignerCertificate(token.signedData, token.signedData.signerInfos[0], pool);
  enforce(authority !is null, format("El sello de tiempo del %s no incluye el certificado de la autoridad que lo "
    ~ "firmó, ni está entre los certificados conocidos", token.info.genTime.toISOExtString));
  return authority;
}

/**
 * Verifica un firmante CMS: certificado, signing-certificate, message-digest sobre
 * `contentDigest` (el resumen del contenido firmado con el algoritmo del firmante) y la
 * firma sobre los atributos firmados.
 */
CmsSignerVerification verifyCmsSigner(const SignedData signedData, const SignerInfo signer,
    const(ubyte)[] contentDigest, CertificatePool pool) @safe {
  CmsSignerVerification result;
  result.signingCertificate = findSignerCertificate(signedData, signer, pool);
  if (result.signingCertificate is null) {
    result.verdict.degrade(Indication.indeterminate, SubIndication.noSigningCertificateFound,
      message(ValidationMessage.Level.error, "BBB_ICS_ISCI_ANS"));
    return result;
  }
  // Niveles de la política por omisión de DSS: SigningCertificatePresent e IssuerSerialMatch
  // avisan; CertDigestMatch falla.
  auto references = signingCertificateReferences(signer);
  if (references.length == 0) {
    result.verdict.warn(message(ValidationMessage.Level.warning, "BBB_ICS_ISASCP_ANS"));
  } else if (result.signingCertificate.digest(references[0].digest) != references[0].certificateHash) {
    result.verdict.degrade(Indication.indeterminate, SubIndication.noSigningCertificateFound,
      message(ValidationMessage.Level.error, "BBB_ICS_ICDVV_ANS"));
  } else if (references[0].hasIssuerSerial && references[0].issuerSerial != result.signingCertificate.serialNumber) {
    result.verdict.warn(message(ValidationMessage.Level.warning, "BBB_ICS_AIDNASNE_ANS"));
  }

  if (signer.signedAttributesRaw.length == 0) {
    result.verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_SAV_ISQPMDOSPP_ANS"));
    return result;
  }
  try {
    result.hashValid = messageDigestOf(signer) == contentDigest;
  } catch (Exception exception) {
    result.verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_SAV_ISQPMDOSPP_ANS"));
    return result;
  }
  if (!result.hashValid) {
    result.verdict.degrade(Indication.totalFailed, SubIndication.hashFailure,
      message(ValidationMessage.Level.error, "BBB_CV_IRDOI_ANS"));
  }
  if (signer.signedAttribute(oidContentType) is null) {
    result.verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_SAV_ISQPCTP_ANS"));
  }
  try {
    auto algorithm = signatureAlgorithmFrom(signer.signatureAlgorithm, signer.digestAlgorithm);
    result.signatureValid = verifySignature(result.signingCertificate.subjectPublicKeyInfoDer, algorithm,
      signer.signedAttributesForSignature, signer.signature);
  } catch (Exception exception) {
    warning("No se pudo verificar la firma CMS: ", exception.msg);
    result.signatureValid = false;
    result.signatureFailure = exception.msg;
  }
  if (!result.signatureValid) {
    result.verdict.degrade(Indication.totalFailed, SubIndication.sigCryptoFailure,
      message(ValidationMessage.Level.error, "BBB_CV_ISI_ANS", result.signatureFailure));
  }
  return result;
}

/**
 * Valida un sello de tiempo sobre `stampedData`: resumen sellado, firma del sello,
 * certificado de la autoridad de sellado con uso id-kp-timeStamping, su cadena y su
 * revocación a la fecha del sello.
 */
TimestampResult validateTimestamp(const TimeStampToken token, const(ubyte)[] stampedData, TimestampResult.Kind kind,
    PathContext context) @trusted {
  TimestampResult result;
  result.kind = kind;
  result.productionTime = token.info.genTime;
  Verdict verdict;
  if (digestOf(token.info.imprintAlgorithm, stampedData) != token.info.imprint) {
    verdict.degrade(Indication.failed, SubIndication.hashFailure,
      message(ValidationMessage.Level.error, "BBB_CV_TSP_IRDOI_ANS"));
  }
  auto signer = token.signedData.signerInfos[0];
  auto cryptographic = verifyCmsSigner(token.signedData, signer,
    digestOf(signer.digestAlgorithm, token.signedData.eContent), context.pool);
  foreach (why; cryptographic.verdict.messages) {
    verdict.degrade(cryptographic.verdict.indication == Indication.totalFailed ? Indication.failed
      : cryptographic.verdict.indication, cryptographic.verdict.subIndication, why);
  }
  if (cryptographic.signingCertificate !is null) {
    auto tsa = cryptographic.signingCertificate;
    if (!tsa.extendedKeyUsages.canFind(oidEkuTimeStamping)) {
      verdict.degrade(Indication.indeterminate, SubIndication.chainConstraintsFailure,
        message(ValidationMessage.Level.error, "BBB_XCV_ISCGEKU_ANS", tsa.subject.readableName));
    }
    context.pool.addAll(token.signedData.certificates);
    PathContext timestampContext = context;
    timestampContext.role = CertificateRole.timestamp;
    timestampContext.bestSignatureTime = token.info.genTime;
    auto path = validatePath(tsa, timestampContext);
    result.certificateChain = path.path;
    foreach (why; path.verdict.messages) {
      if (why.level == ValidationMessage.Level.error) verdict.degrade(path.verdict.indication, path.verdict.subIndication, why);
      else verdict.warn(why);
    }
    if (!tsa.isValidAt(token.info.genTime)) {
      verdict.degrade(Indication.indeterminate, SubIndication.outOfBoundsNoPoe,
        message(ValidationMessage.Level.error, "BBB_XCV_ICTIVRSC_ANS", tsa.subject.readableName));
    }
  }
  result.indication = verdict.indication == Indication.totalPassed ? Indication.passed : verdict.indication;
  result.subIndication = verdict.subIndication;
  result.messages = verdict.messages;
  return result;
}

@("should verify a CMS signer built with the signing certificate and detect a changed content")
unittest {
  import firmador.crypto.openssl : makeTestIdentity;
  auto identity = makeTestIdentity("Firmante", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = cast(const(ubyte)[]) "contenido";
  SignedAttributesInput attributes = {
    contentDigest: digestOf(DigestAlgorithm.sha256, content),
    signingCertificate: certificate,
  };
  auto signedAttributes = buildSignedAttributes(attributes);
  SignedDataInput input = {
    signingCertificate: certificate,
    certificates: [certificate],
    signedAttributes: signedAttributes,
    signature: identity.key.sign(DigestAlgorithm.sha256, signedAttributes),
  };
  auto signedData = parseSignedData(buildSignedData(input));
  auto pool = new CertificatePool;
  auto good = verifyCmsSigner(signedData, signedData.signerInfos[0], digestOf(DigestAlgorithm.sha256, content), pool);
  assert(good.hashValid && good.signatureValid && good.verdict.isPassed);
  auto changed = verifyCmsSigner(signedData, signedData.signerInfos[0],
    digestOf(DigestAlgorithm.sha256, cast(const(ubyte)[]) "otro"), pool);
  assert(!changed.hashValid && changed.verdict.subIndication == SubIndication.hashFailure);
}
