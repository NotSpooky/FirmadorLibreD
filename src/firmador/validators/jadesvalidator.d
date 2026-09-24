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
 * Validación de firmas JAdES y JWS: para cada firma se comprueban el certificado de firma
 * (x5t#S256 o x5t#o), la firma sobre cabecera y contenido, los sellos sigTst y arcTst de
 * etsiU y la cadena y revocación del firmante con los valores incluidos.
 */
module firmador.validators.jadesvalidator;

import std.datetime.systime : Clock, SysTime;
import std.format : format;
import std.logger : warning;

import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.crypto.openssl : ecdsaRawToDer, verifySignature;
import firmador.jose.jades;
import firmador.util.datetime : parseRfc3339;
import firmador.util.json;
import firmador.validation.certpath;
import firmador.validation.cmsverify : validateTimestamp;
import firmador.validation.conclusion;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.x509.certificate;

/**
 * Valida las firmas del JWS. Si el contenido es separado (payload vacío), `detached[0]`
 * es lo firmado.
 *
 * Throws: JwsException o JsonShapeException si el documento no es un JWS.
 */
DocumentValidationResult validateJades(immutable(ubyte)[] document, string documentName, ValidationDataSource source,
    bool allowOnline = true, const DetachedContent[] detached = null) @trusted {
  DocumentValidationResult result;
  result.documentName = documentName;
  result.validationTime = Clock.currTime;
  auto jws = parseJws(document);
  const(ubyte)[] detachedContent = detached.length == 1 ? detached[0].content : null;
  foreach (index, signature; jws.signatures) {
    auto validated = validateJwsSignature(jws, signature, detachedContent,
      pathContext(source, allowOnline, result.validationTime));
    validated.id = format("S-%d", index + 1);
    validated.filename = jws.payload.length == 0 && detached.length == 1 ? detached[0].name : documentName;
    result.signatures ~= validated;
  }
  return result;
}

private SignatureResult validateJwsSignature(const Jws jws, const JwsSignature signature,
    const(ubyte)[] detachedContent, PathContext baseContext) @trusted {
  SignatureResult result;
  Verdict verdict;
  auto header = signature.header;
  bool etsi = !isAbsent(header, "x5t#S256") || !isAbsent(header, "x5t#o") || !isAbsent(header, "sigT")
    || signature.etsiU.length > 0;
  string family = etsi ? "JAdES-BASELINE" : "JWS";

  auto embedded = jadesEmbeddedData(signature);
  includeEmbedded(baseContext, embedded);

  try {
    string sigT = optionalString(header, "sigT", "La cabecera protegida");
    if (sigT !is null) result.signingTime = parseRfc3339(sigT);
    else if (!isAbsent(header, "iat")) {
      result.signingTime = SysTime.fromUnixTime(optionalLong(header, "iat", 0, "La cabecera protegida"));
    }
  } catch (Exception exception) {
    verdict.warn(message(ValidationMessage.Level.warning, "BBB_FC_IEFF_ANS", exception.msg));
  }

  // Certificado de firma: el que coincide con x5t#S256 (o x5t#o); si no hay, el primero de x5c.
  Certificate signer;
  const(Certificate)[] candidates = embedded.certificates ~ baseContext.pool.all;
  try {
    string thumbprint = optionalString(header, "x5t#S256", "La cabecera protegida");
    auto other = member(header, "x5t#o");
    if (thumbprint !is null) {
      auto expected = decodeBase64Url(thumbprint, "x5t#S256");
      foreach (candidate; candidates) {
        if (candidate.digest(DigestAlgorithm.sha256) == expected) signer = cast(Certificate) candidate;
      }
    } else if (other !is null) {
      auto algorithm = digestFromJoseName(requiredString(*other, "digAlg", "x5t#o"));
      auto expected = decodeBase64Url(requiredString(*other, "digVal", "x5t#o"), "x5t#o");
      foreach (candidate; candidates) if (candidate.digest(algorithm) == expected) signer = cast(Certificate) candidate;
    } else if (embedded.certificates.length) {
      // Sin referencia al certificado de firma DSS sólo avisa (SigningCertificatePresent).
      signer = embedded.certificates[0];
      if (etsi) verdict.warn(message(ValidationMessage.Level.warning, "BBB_ICS_ISASCP_ANS"));
    }
  } catch (Exception exception) {
    verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", exception.msg));
  }
  if (signer is null) {
    verdict.degrade(Indication.indeterminate, SubIndication.noSigningCertificateFound,
      message(ValidationMessage.Level.error, "BBB_ICS_ISCI_ANS"));
  }

  string payload = effectivePayload(jws, signature, detachedContent);
  bool hasSigD = !isAbsent(header, "sigD");
  if (payload.length == 0 || hasSigD) {
    // Sin contenido (o con sigD, que Firmador no genera) no se puede comprobar lo firmado.
    verdict.degrade(Indication.indeterminate, SubIndication.signedDataNotFound,
      message(ValidationMessage.Level.error, "BBB_CV_IRDOF_ANS"));
  } else if (signer !is null) {
    bool valid = false;
    try {
      bool ecdsa;
      auto algorithm = signatureAlgorithmFromJws(requiredString(header, "alg", "La cabecera protegida"), ecdsa);
      auto value = decodeBase64Url(signature.signature, "La firma");
      valid = verifySignature(signer.subjectPublicKeyInfoDer, algorithm, signingInput(signature, payload),
        ecdsa ? ecdsaRawToDer(value) : value.dup);
    } catch (Exception exception) {
      warning("No se pudo verificar la firma JWS: ", exception.msg);
    }
    if (!valid) {
      verdict.degrade(Indication.totalFailed, SubIndication.sigCryptoFailure,
        message(ValidationMessage.Level.error, "BBB_CV_ISI_ANS"));
    }
  }

  bool hasSignatureTimestamp, hasArchiveTimestamp, hasValues;
  foreach (index, component; signature.etsiU) {
    TimestampResult.Kind kind;
    if (component.name == "sigTst") {
      kind = TimestampResult.Kind.signature;
      hasSignatureTimestamp = true;
    } else if (component.name == "arcTst") {
      kind = TimestampResult.Kind.archive;
      hasArchiveTimestamp = true;
    } else {
      if (component.name == "xVals" || component.name == "rVals" || component.name == "tstVD") hasValues = true;
      continue;
    }
    const(ubyte)[] stampedData;
    immutable(ubyte)[][] tokens;
    try {
      stampedData = kind == TimestampResult.Kind.signature ? signatureTimestampData(signature)
        : archiveTimestampData(signature, payload, index);
      tokens = tstContainerTokens(component.value);
    } catch (Exception exception) {
      warning("Sello de tiempo ilegible en la firma JAdES: ", exception.msg);
      result.timestamps ~= unreadableTimestamp(kind, exception.msg);
      continue;
    }
    foreach (der; tokens) {
      result.timestamps ~= readTimestamp(kind, "la firma JAdES", () => parseTimeStampToken(der),
        (token) => stampedData, baseContext);
    }
  }
  return concludeSignature(result, verdict, signer, baseContext,
    etsi ? family ~ "-" ~ baselineLevel(hasSignatureTimestamp, hasValues, hasArchiveTimestamp) : family);
}

version (unittest) import firmador.crypto.openssl : makeTestIdentity;

@("should validate an enveloping JAdES and detect a changed payload")
unittest {
  auto identity = makeTestIdentity("Firmante JSON", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  JadesParameters parameters;
  parameters.signingTime = Clock.currTime;
  parameters.signingCertificate = certificate;
  parameters.mimeType = "application/json";
  auto prepared = prepareJadesSignature(cast(const(ubyte)[]) `{"a":1}`, parameters);
  auto signed = completeJadesSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));
  auto result = validateJades(signed, "datos.json", new OfflineValidationSource, false);
  assert(result.signatures.length == 1);
  assert(result.signatures[0].format == "JAdES-BASELINE-B");
  assert(result.signatures[0].subIndication == SubIndication.noCertificateChainFound);
  assert(!result.signatures[0].signingTime.isNull);

  auto jws = parseJws(signed);
  jws.payload = base64Url(cast(const(ubyte)[]) `{"a":2}`);
  auto changed = validateJades(serializeJws(jws), "datos.json", new OfflineValidationSource, false);
  assert(changed.signatures[0].subIndication == SubIndication.sigCryptoFailure);
}
