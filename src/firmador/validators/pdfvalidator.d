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

import std.algorithm : min;
import std.datetime.systime : Clock, SysTime;
import std.format : format;
import std.logger : trace, warning;

import firmador.asn1.der : joinBytes;
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

  auto baseContext = pathContext(source, allowOnline, result.validationTime, pool);
  baseContext.embeddedOcsp = dss.ocsps.dup;
  baseContext.embeddedCrls = dss.crls.dup;

  // Primero los sellos de documento: dan la fecha probada de lo que cubren.
  PdfTimestamp[] documentTimestamps;
  foreach (field; fields) {
    if (field.type != "DocTimeStamp" && field.subFilter != "ETSI.RFC3161") continue;
    PdfTimestamp timestamp;
    timestamp.field = field;
    timestamp.coveredEnd = coveredEnd(field.byteRange);
    timestamp.result = readTimestamp(TimestampResult.Kind.document, field.fieldName,
      () => parseTimeStampToken(trimContents(field.contents)),
      (token) => joinBytes(signedRanges(pdf, field.byteRange)), baseContext);
    timestamp.result.absorb(byteRangeVerdict(field, pdf.length, fields));
    timestamp.result.filename = field.fieldName;
    documentTimestamps ~= timestamp;
  }

  // Fin de lo que cubre la primera firma: un sello que termina antes no protege ninguna.
  long firstSignatureEnd = long.max;
  foreach (field; fields) {
    if (field.type == "DocTimeStamp" || field.subFilter == "ETSI.RFC3161") continue;
    auto signature = validatePdfSignature(pdf, field, fields, documentTimestamps, pool, baseContext,
      dss.certificates.length > 0);
    signature.pdfAnnotationChanges = annotationsChangedAfter(pdf, field, finalAnnotations, finalPages,
      signature.messages);
    firstSignatureEnd = min(firstSignatureEnd, coveredEnd(field.byteRange));
    result.signatures ~= signature;
  }
  // Un sello que no protege ninguna firma se informa como sello independiente; los demás van
  // como sellos de archivo de las firmas que cubren (validatePdfSignature).
  foreach (timestamp; documentTimestamps) {
    if (timestamp.coveredEnd <= firstSignatureEnd) result.documentTimestamps ~= timestamp.result;
  }
  return result;
}

/**
 * Comprueba el /ByteRange de una firma o sello: que empiece en 0, deje un solo hueco (el
 * de /Contents) y no pase del final del archivo, y que ese hueco no se cruce con el de
 * otro campo de `all`.
 *
 * Params:
 *   field = campo que se comprueba.
 *   fileLength = tamaño del PDF, en bytes.
 *   all = todos los campos de firma y sello del documento (puede incluir a `field`).
 * Returns: aprobado, o totalFailed/formatFailure con un mensaje por cada problema.
 */
private Verdict byteRangeVerdict(const PdfSignatureField field, size_t fileLength, const PdfSignatureField[] all)
    @safe {
  Verdict verdict;
  auto range = field.byteRange;
  if (range.length != 4 || range[0] != 0 || range[1] <= 0 || range[2] <= range[1] || range[3] < 0
      || range[2] + range[3] > fileLength) {
    verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_FC_DASTHVBR_ANS"));
    return verdict;
  }
  foreach (other; all) {
    if (other.fieldName == field.fieldName || other.byteRange.length != 4) continue;
    // Los huecos de /Contents de dos firmas nunca pueden cruzarse.
    if (other.byteRange[1] < range[2] && range[1] < other.byteRange[2] && other.byteRange[1] != range[1]) {
      verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
        message(ValidationMessage.Level.error, "BBB_FC_DBTOOST_ANS", other.fieldName));
    }
  }
  return verdict;
}

private SignatureResult validatePdfSignature(immutable(ubyte)[] pdf, const PdfSignatureField field,
    const PdfSignatureField[] fields, PdfTimestamp[] documentTimestamps, CertificatePool pool, PathContext baseContext,
    bool hasDss) @trusted {
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
      if (signedData.signerInfos.length == 0) return finishSignature(signature, verdict, family ~ "-B");
    }
  } catch (Exception exception) {
    verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", exception.msg));
    return finishSignature(signature, verdict, family ~ "-B");
  }
  auto byteRange = byteRangeVerdict(field, pdf.length, fields);
  verdict.absorb(byteRange);
  if (!byteRange.isPassed) return finishSignature(signature, verdict, family ~ "-B");
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

  // Sellos y cadena del firmante, con las revocaciones del DSS y las de la firma.
  PathContext context = baseContext;
  context.embeddedOcsp = baseContext.embeddedOcsp ~ signedData.ocspResponses;
  context.embeddedCrls = baseContext.embeddedCrls ~ signedData.crls;
  // Sellos: el de la firma y los de documento que la cubren.
  bool hasSignatureTimestamp;
  foreach (attribute; signer.unsignedAttributesOf(oidSignatureTimeStampToken)) {
    hasSignatureTimestamp = true;
    signature.timestamps ~= readTimestamp(TimestampResult.Kind.signature, field.fieldName,
      () => parseTimeStampToken(attribute.values[0].raw), (token) => signer.signature, context);
  }
  bool hasArchiveTimestamp;
  foreach (timestamp; documentTimestamps) {
    if (timestamp.coveredEnd <= coveredEnd(field.byteRange)) continue;
    hasArchiveTimestamp = true;
    auto archive = timestamp.result;
    archive.kind = TimestampResult.Kind.archive;
    signature.timestamps ~= archive;
  }

  return concludeSignature(signature, verdict, cryptographic.signingCertificate, context,
    family ~ "-" ~ baselineLevel(hasSignatureTimestamp || hasArchiveTimestamp, hasDss, hasArchiveTimestamp));
}

/**
 * Compara las anotaciones de la versión firmada con las del documento final (sin contar
 * los campos de firma, que se añaden al firmar de nuevo). Informa también si cambió el
 * número de páginas, y si la versión firmada no se pudo abrir para compararla (entonces
 * no se sabe si hubo cambios y devuelve false).
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
    warning("No se pudo abrir la versión firmada de ", field.fieldName, ": ", exception.msg);
    messages ~= message(ValidationMessage.Level.warning, "validation_signed_revision_unreadable", exception.msg);
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

@("should report only the document timestamps that protect no signature when timestamps precede and follow it")
unittest {
  import firmador.crypto.openssl : makeTestIdentity;
  import firmador.pdf.pades;
  // Un sello ilegible basta: se informa igual, como fallido.
  TimeStampToken fakeStamp(const(ubyte)[] digest) @safe {
    TimeStampToken token;
    token.der = [0x30, 0x03, 0x02, 0x01, 0x01];
    token.info.genTime = Clock.currTime;
    return token;
  }
  auto identity = makeTestIdentity("Firmante con sellos", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto stampedFirst = addDocumentTimestamp(cast(immutable(ubyte)[]) import("nonPreview.pdf"), &fakeStamp);
  PadesSignatureParameters parameters;
  parameters.signingTime = Clock.currTime;
  auto prepared = preparePadesSignature(stampedFirst, parameters);
  auto attributes = padesSignedAttributes(preparedDigest(prepared), certificate);
  auto signed = completePadesSignature(prepared,
    padesCms(attributes, identity.key.sign(DigestAlgorithm.sha256, attributes), true, certificate, [], null));
  auto archived = addDocumentTimestamp(signed, &fakeStamp);

  auto result = validatePdf(archived, "sellado.pdf", new OfflineValidationSource, false);
  assert(result.signatures.length == 1);
  assert(result.documentTimestamps.length == 1);
  assert(result.documentTimestamps[0].indication != Indication.passed);
  assert(result.signatures[0].timestamps.length == 1);
  assert(result.signatures[0].timestamps[0].kind == TimestampResult.Kind.archive);
}

@("should fail the byte range when it leaves the file or its gap crosses another field's gap")
unittest {
  PdfSignatureField field(string name, long[] range) {
    PdfSignatureField result;
    result.fieldName = name;
    result.byteRange = range;
    return result;
  }
  auto first = field("Firma1", [0, 100, 200, 300]);
  assert(byteRangeVerdict(first, 500, [first]).isPassed);
  assert(byteRangeVerdict(first, 499, [first]).indication == Indication.totalFailed);
  assert(byteRangeVerdict(field("Firma1", [0, 100, 100, 300]), 500, []).subIndication == SubIndication.formatFailure);
  // Un hueco dentro del de la primera firma, empezando en otro punto.
  auto crossing = field("Firma2", [0, 150, 180, 320]);
  auto verdict = byteRangeVerdict(first, 500, [first, crossing]);
  assert(verdict.indication == Indication.totalFailed && verdict.messages.length == 1);
  // Una firma posterior cubre la anterior entera, con su hueco más adelante.
  assert(byteRangeVerdict(first, 800, [first, field("Firma2", [0, 600, 700, 100])]).isPassed);
}
