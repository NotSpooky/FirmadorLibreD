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
 * Validación de firmas CAdES y CMS (p7s, p7m y las de contenedores ASiC-CAdES): para cada
 * firmante se comprueban el resumen del contenido (el encapsulado o el archivo separado),
 * la firma, los sellos de firma y de archivo (v3, con su índice de resúmenes) y la cadena
 * y revocación del firmante con lo que trae el SignedData.
 */
module firmador.validators.cadesvalidator;

import std.datetime.systime : Clock, SysTime;
import std.logger : warning;

import firmador.asn1.oids;
import firmador.cms.cades;
import firmador.cms.signeddata;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.validation.certpath;
import firmador.validation.cmsverify;
import firmador.validation.conclusion;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.x509.certificate;

/**
 * Valida las firmas CMS. Una firma separada usa `detached[0]` como contenido; sin él, sus
 * firmantes quedan indeterminados por falta de lo firmado.
 *
 * Throws: Asn1Exception si los bytes no son un SignedData.
 */
DocumentValidationResult validateCades(immutable(ubyte)[] cms, string documentName, ValidationDataSource source,
    bool allowOnline = true, const DetachedContent[] detached = null) @trusted {
  DocumentValidationResult result;
  result.documentName = documentName;
  result.validationTime = Clock.currTime;
  auto data = parseSignedData(cms);
  const(ubyte)[] content;
  bool hasContent = data.hasEContent;
  if (hasContent) content = data.eContent;
  else if (detached.length == 1) {
    content = detached[0].content;
    hasContent = true;
  }
  foreach (index, signer; data.signerInfos) {
    auto context = pathContext(source, allowOnline, result.validationTime);
    context.pool.addAll(data.certificates);
    context.embeddedOcsp = data.ocspResponses;
    context.embeddedCrls = data.crls;
    auto signature = validateCadesSigner(data, signer, hasContent, content, context);
    import std.format : format;
    signature.id = format("S-%d", index + 1);
    signature.filename = hasContent && !data.hasEContent ? detached[0].name : documentName;
    result.signatures ~= signature;
  }
  return result;
}

/// Valida un firmante del SignedData.
private SignatureResult validateCadesSigner(const SignedData data, const SignerInfo signer, bool hasContent,
    const(ubyte)[] content, PathContext baseContext) @trusted {
  SignatureResult signature;
  Verdict verdict;
  SysTime signingTime;
  if (signingTimeOf(signer, signingTime)) signature.signingTime = signingTime;

  CmsSignerVerification cryptographic;
  if (hasContent) {
    cryptographic = verifyCmsSigner(data, signer, digestOf(signer.digestAlgorithm, content), baseContext.pool);
    verdict.absorb(cryptographic.verdict);
  } else {
    cryptographic.signingCertificate = findSignerCertificate(data, signer, baseContext.pool);
    verdict.degrade(Indication.indeterminate, SubIndication.signedDataNotFound,
      message(ValidationMessage.Level.error, "BBB_CV_IRDOF_ANS"));
  }

  bool hasSignatureTimestamp, hasArchiveTimestamp;
  foreach (attribute; signer.unsignedAttributesOf(oidSignatureTimeStampToken)) {
    hasSignatureTimestamp = true;
    signature.timestamps ~= readTimestamp(TimestampResult.Kind.signature, "la firma CAdES",
      () => parseTimeStampToken(attribute.values[0].raw), (token) => signer.signature, baseContext);
  }
  foreach (attribute; signer.unsignedAttributesOf(oidArchiveTimestampV3)) {
    hasArchiveTimestamp = true;
    bool completeIndex = true;
    auto stamped = readTimestamp(TimestampResult.Kind.archive, "la firma CAdES",
      () => parseTimeStampToken(attribute.values[0].raw), (token) {
        auto check = checkAtsHashIndex(data, signer, token);
        completeIndex = check.complete;
        auto contentDigest = hasContent ? digestOf(token.info.imprintAlgorithm, content) : null;
        return archiveTimestampV3Data(data, signer, contentDigest, check.hashIndex);
      }, baseContext);
    if (!completeIndex) stamped.messages ~= message(ValidationMessage.Level.warning, "validation_ats_hash_index_incomplete");
    signature.timestamps ~= stamped;
  }
  bool hasValues = data.crls.length || data.ocspResponses.length;
  return concludeSignature(signature, verdict, cryptographic.signingCertificate, baseContext,
    "CAdES-BASELINE-" ~ baselineLevel(hasSignatureTimestamp, hasValues, hasArchiveTimestamp));
}

version (unittest) import firmador.crypto.openssl : makeTestIdentity;

@("should validate a detached CAdES against its document and flag a missing or changed document")
unittest {
  auto identity = makeTestIdentity("Firmante p7s", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = cast(immutable(ubyte)[]) "contenido firmado";
  auto attributes = cadesSignedAttributes(digestOf(DigestAlgorithm.sha256, content), certificate, Clock.currTime);
  auto cms = cadesCms(attributes, identity.key.sign(DigestAlgorithm.sha256, attributes), true, certificate, []).idup;
  auto result = validateCades(cms, "firma.p7s", new OfflineValidationSource, false, [DetachedContent("doc.txt", content)]);
  assert(result.signatures.length == 1);
  assert(result.signatures[0].format == "CAdES-BASELINE-B");
  assert(result.signatures[0].subIndication == SubIndication.noCertificateChainFound);
  assert(result.signatures[0].filename == "doc.txt");
  auto changed = validateCades(cms, "firma.p7s", new OfflineValidationSource, false,
    [DetachedContent("doc.txt", cast(immutable(ubyte)[]) "otro contenido")]);
  assert(changed.signatures[0].subIndication == SubIndication.hashFailure);
  auto missing = validateCades(cms, "firma.p7s", new OfflineValidationSource, false);
  assert(missing.signatures[0].subIndication == SubIndication.signedDataNotFound);
}
