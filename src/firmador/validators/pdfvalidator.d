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
 * Validación de firmas PDF (PAdES y PKCS#7): para cada campo de firma se comprueban el
 * /ByteRange, el resumen, la firma CMS, los sellos de tiempo (el de la firma y los de
 * documento posteriores, que dan la fecha mínima probada), la cadena y la revocación del
 * firmante con los datos del DSS, y los cambios en anotaciones hechos después de firmar.
 * Los sellos de documento que no protegen ninguna firma se informan aparte.
 */
module firmador.validators.pdfvalidator;

import std.algorithm : canFind, sort;
import std.datetime.systime : Clock, SysTime;
import std.format : format;
import std.logger : info, trace, warning;

import firmador.asn1.oids;
import firmador.cms.signeddata;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.pdf.engine;
import firmador.pdf.pades : trimContents;
import firmador.pdf.writer : signedRanges;
import firmador.util.datetime : parsePdfDate;
import firmador.validation.certpath;
import firmador.validation.cmsverify;
import firmador.validation.conclusion;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.x509.certificate;

private struct PdfTimestamp {
  PdfSignatureField field;
  TimeStampToken token;
  TimestampResult result;
  long coveredEnd;
}

/// Fin (exclusivo) de lo que cubre un /ByteRange.
long coveredEnd(const long[] byteRange) pure nothrow @safe @nogc {
  return byteRange.length == 4 ? byteRange[2] + byteRange[3] : 0;
}

/**
 * Valida todas las firmas y sellos de documento del PDF.
 *
 * Throws: PdfException si el archivo no es un PDF legible.
 */
DocumentValidationResult validatePdf(immutable(ubyte)[] pdf, string documentName, ValidationDataSource source,
    bool allowOnline = true) @trusted {
  DocumentValidationResult result;
  result.documentName = documentName;
  result.validationTime = Clock.currTime;
  auto document = PdfDocument.open(pdf);
  scope (exit) document.close();
  auto fields = document.signatureFields();
  auto dss = document.dss();
  auto finalAnnotations = document.annotations();
  int finalPages = document.pageCount();

  auto pool = CertificatePool.withNationalHierarchy();
  foreach (der; dss.certificates) {
    try {
      pool.add(parseCertificate(der));
    } catch (Exception exception) {
      trace("Certificado ilegible en el DSS: ", exception.msg);
    }
  }

  PathContext baseContext;
  baseContext.pool = pool;
  baseContext.source = source;
  baseContext.allowOnline = allowOnline;
  baseContext.validationTime = result.validationTime;
  baseContext.bestSignatureTime = result.validationTime;
  const(ubyte[])[] embeddedOcsp = dss.ocsps.dup;
  const(ubyte[])[] embeddedCrls = dss.crls.dup;

  // Primero los sellos de documento: dan la fecha probada de lo que cubren.
  PdfTimestamp[] documentTimestamps;
  foreach (field; fields) {
    if (field.type != "DocTimeStamp" && field.subFilter != "ETSI.RFC3161") continue;
    PdfTimestamp timestamp;
    timestamp.field = field;
    timestamp.coveredEnd = coveredEnd(field.byteRange);
    timestamp.result.kind = TimestampResult.Kind.document;
    timestamp.result.filename = field.fieldName;
    try {
      timestamp.token = parseTimeStampToken(trimContents(field.contents));
      foreach (certificate; timestamp.token.signedData.certificates) pool.add(certificate);
      PathContext context = baseContext;
      context.embeddedOcsp = embeddedOcsp;
      context.embeddedCrls = embeddedCrls;
      auto covered = joinRanges(signedRanges(pdf, field.byteRange));
      timestamp.result = validateTimestamp(timestamp.token, covered, TimestampResult.Kind.document, context);
      timestamp.result.filename = field.fieldName;
      checkByteRange(field, pdf.length, fields, timestamp.result.messages);
    } catch (Exception exception) {
      warning("Sello de documento ilegible en ", field.fieldName, ": ", exception.msg);
      timestamp.result.indication = Indication.failed;
      timestamp.result.subIndication = SubIndication.formatFailure;
      timestamp.result.messages ~= message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", exception.msg);
    }
    documentTimestamps ~= timestamp;
  }

  long lastSignatureEnd = 0;
  foreach (field; fields) {
    if (field.type == "DocTimeStamp" || field.subFilter == "ETSI.RFC3161") continue;
    auto signature = validatePdfSignature(pdf, field, fields, documentTimestamps, pool, baseContext, embeddedOcsp,
      embeddedCrls, dss.certificates.length > 0);
    signature.pdfAnnotationChanges = annotationsChangedAfter(pdf, field, finalAnnotations, finalPages,
      signature.messages);
    long end = coveredEnd(field.byteRange);
    if (end > lastSignatureEnd) lastSignatureEnd = end;
    result.signatures ~= signature;
  }
  foreach (timestamp; documentTimestamps) {
    // Un sello que no protege ninguna firma se informa como sello independiente.
    if (lastSignatureEnd == 0 || timestamp.coveredEnd <= lastSignatureEnd) {
      if (result.signatures.length == 0) result.documentTimestamps ~= timestamp.result;
    }
  }
  return result;
}

private ubyte[] joinRanges(const(ubyte)[][] parts) pure @safe {
  ubyte[] joined;
  foreach (part; parts) joined ~= part;
  return joined;
}

private void checkByteRange(const PdfSignatureField field, size_t fileLength, const PdfSignatureField[] all,
    ref ValidationMessage[] messages) @safe {
  auto range = field.byteRange;
  if (range.length != 4 || range[0] != 0 || range[1] <= 0 || range[2] <= range[1]
      || range[2] + range[3] > fileLength) {
    messages ~= message(ValidationMessage.Level.error, "BBB_FC_DASTHVBR_ANS");
    return;
  }
  foreach (other; all) {
    if (other.fieldName == field.fieldName || other.byteRange.length != 4) continue;
    // Los huecos de /Contents de dos firmas nunca pueden cruzarse.
    if (other.byteRange[1] < range[2] && range[1] < other.byteRange[2] && other.byteRange[1] != range[1]) {
      messages ~= message(ValidationMessage.Level.error, "BBB_FC_DBTOOST_ANS");
    }
  }
}

private SignatureResult validatePdfSignature(immutable(ubyte)[] pdf, const PdfSignatureField field,
    const PdfSignatureField[] fields, PdfTimestamp[] documentTimestamps, CertificatePool pool, PathContext baseContext,
    const(ubyte[])[] embeddedOcsp, const(ubyte[])[] embeddedCrls, bool hasDss) @trusted {
  SignatureResult signature;
  signature.id = field.fieldName;
  signature.filename = field.fieldName;
  Verdict verdict;
  bool etsi = field.subFilter == "ETSI.CAdES.detached";
  string family = etsi ? "PAdES-BASELINE" : "PKCS7";

  if (field.signingDate.length) {
    try {
      signature.signingTime = parsePdfDate(field.signingDate);
    } catch (Exception exception) {
      trace("Fecha /M ilegible en ", field.fieldName, ": ", exception.msg);
    }
  }

  SignedData signedData;
  try {
    signedData = parseSignedData(trimContents(field.contents));
    if (signedData.signerInfos.length != 1) {
      verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
        message(ValidationMessage.Level.error, "BBB_FC_IOSIP_ANS"));
      // Sin firmante no queda nada que verificar.
      if (signedData.signerInfos.length == 0) return finish(signature, verdict, family ~ "-B");
    }
  } catch (Exception exception) {
    verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", exception.msg));
    return finish(signature, verdict, family ~ "-B");
  }
  checkByteRange(field, pdf.length, fields, verdict.messages);
  if (verdict.messages.length && verdict.messages[$ - 1].key.canFind("BBB_FC_D")) {
    verdict.degrade(Indication.totalFailed, SubIndication.formatFailure, verdict.messages[$ - 1]);
    return finish(signature, verdict, family ~ "-B");
  }
  if (coveredEnd(field.byteRange) != pdf.length) {
    // Hubo actualizaciones después de esta firma: se informa, no invalida la firma.
    verdict.warn(message(ValidationMessage.Level.info, "BBB_FC_ICFD_ANS"));
  }
  pool.addAll(signedData.certificates);
  auto signer = signedData.signerInfos[0];
  SysTime cmsSigningTime;
  if (signature.signingTime.isNull && signingTimeOf(signer, cmsSigningTime)) signature.signingTime = cmsSigningTime;

  auto covered = signedRanges(pdf, field.byteRange);
  auto cryptographic = verifyCmsSigner(signedData, signer, digestOfParts(signer.digestAlgorithm, covered), pool);
  verdict.absorb(cryptographic.verdict);

  // Sellos: el de la firma y los de documento que la cubren.
  PathContext timestampContext = baseContext;
  timestampContext.embeddedOcsp = embeddedOcsp ~ signedData.ocspResponses;
  timestampContext.embeddedCrls = embeddedCrls ~ signedData.crls;
  bool hasSignatureTimestamp;
  foreach (attribute; signer.unsignedAttributesOf(oidSignatureTimeStampToken)) {
    hasSignatureTimestamp = true;
    try {
      auto token = parseTimeStampToken(attribute.values[0].raw);
      signature.timestamps ~= validateTimestamp(token, signer.signature, TimestampResult.Kind.signature,
        timestampContext);
    } catch (Exception exception) {
      signature.timestamps ~= unreadableTimestamp(TimestampResult.Kind.signature, exception.msg);
    }
  }
  bool hasArchiveTimestamp;
  foreach (timestamp; documentTimestamps) {
    if (timestamp.coveredEnd <= coveredEnd(field.byteRange)) continue;
    hasArchiveTimestamp = true;
    auto archive = timestamp.result;
    archive.kind = TimestampResult.Kind.archive;
    signature.timestamps ~= archive;
  }

  PathContext context = baseContext;
  context.embeddedOcsp = timestampContext.embeddedOcsp;
  context.embeddedCrls = timestampContext.embeddedCrls;
  return concludeSignature(signature, verdict, cryptographic.signingCertificate, context,
    family ~ "-" ~ baselineLevel(hasSignatureTimestamp || hasArchiveTimestamp, hasDss, hasArchiveTimestamp));
}

private SignatureResult finish(SignatureResult signature, Verdict verdict, string format_) @safe {
  signature.format = format_;
  signature.indication = verdict.isPassed ? Indication.totalPassed : verdict.indication;
  signature.subIndication = verdict.subIndication;
  signature.messages = verdict.messages;
  return signature;
}

/**
 * Compara las anotaciones de la versión firmada con las del documento final (sin contar
 * los campos de firma, que se añaden al firmar de nuevo). Informa también si cambió el
 * número de páginas.
 */
private bool annotationsChangedAfter(immutable(ubyte)[] pdf, const PdfSignatureField field,
    const PdfAnnotation[] finalAnnotations, int finalPages, ref ValidationMessage[] messages) @trusted {
  long end = coveredEnd(field.byteRange);
  if (end <= 0 || end >= pdf.length) return false;
  PdfAnnotation[] signedAnnotations;
  int signedPages;
  try {
    auto revision = PdfDocument.open(pdf[0 .. cast(size_t) end]);
    scope (exit) revision.close();
    signedAnnotations = revision.annotations();
    signedPages = revision.pageCount();
  } catch (Exception exception) {
    trace("No se pudo abrir la versión firmada de ", field.fieldName, ": ", exception.msg);
    return false;
  }
  if (signedPages != finalPages) messages ~= message(ValidationMessage.Level.warning, "BBB_FC_DSFREAP_ANS");
  bool relevant(const PdfAnnotation annotation) {
    return !(annotation.subtype == "Widget" && annotation.fieldType == "Sig");
  }
  size_t signedCount, finalCount;
  foreach (annotation; signedAnnotations) if (relevant(annotation)) signedCount++;
  foreach (annotation; finalAnnotations) if (relevant(annotation)) finalCount++;
  if (signedCount != finalCount) return true;
  foreach (annotation; finalAnnotations) {
    if (!relevant(annotation)) continue;
    bool found = false;
    foreach (original; signedAnnotations) {
      if (original.pageIndex == annotation.pageIndex && original.subtype == annotation.subtype
          && original.rect == annotation.rect && original.contents == annotation.contents) {
        found = true;
        break;
      }
    }
    if (!found) return true;
  }
  return false;
}

@("should validate a PAdES signature cryptographically and flag the untrusted test chain")
unittest {
  import firmador.crypto.openssl : makeTestIdentity;
  import firmador.pdf.pades;
  auto identity = makeTestIdentity("Firmante validado", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  PadesSignatureParameters parameters;
  parameters.signingTime = Clock.currTime;
  auto pdf = cast(immutable(ubyte)[]) import("nonPreview.pdf");
  auto prepared = preparePadesSignature(pdf, parameters);
  auto attributes = padesSignedAttributes(preparedDigest(prepared), certificate);
  auto signed = completePadesSignature(prepared,
    padesCms(attributes, identity.key.sign(DigestAlgorithm.sha256, attributes), true, certificate, [], null));
  auto result = validatePdf(signed, "prueba.pdf", new OfflineValidationSource, false);
  assert(result.signatures.length == 1);
  auto signature = result.signatures[0];
  assert(signature.format == "PAdES-BASELINE-B");
  assert(signature.indication == Indication.indeterminate);
  assert(signature.subIndication == SubIndication.noCertificateChainFound);
  assert(!signature.signingTime.isNull);

  // Un byte cambiado dentro de lo firmado rompe el resumen.
  auto tampered = signed.dup;
  tampered[20] ^= 0x01;
  auto broken = validatePdf(tampered.idup, "alterado.pdf", new OfflineValidationSource, false);
  assert(broken.signatures[0].indication == Indication.totalFailed);
  assert(broken.signatures[0].subIndication == SubIndication.hashFailure);
}
