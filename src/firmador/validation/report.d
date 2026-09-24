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
 * Reporte de validación (Report en la versión Java): el resultado se escribe como el
 * reporte simple de DSS (@contract simple-report-xml) y se le aplica la misma hoja
 * resources/xslt/html/simple-report.xslt, así que el HTML es el que veía el usuario.
 */
module firmador.validation.report;

import std.array : appender;
import std.datetime.systime : SysTime;
import std.format : format;

import firmador.i18n : t;
import firmador.util.datetime : toRfc3339Utc;
import firmador.validation.model;
import firmador.xml.dom : applyStylesheet, escapeXml;

private enum string simpleReportNamespace = "http://dss.esig.europa.eu/validation/simple-report";

/// Reporte simple en XML con los elementos que usa la hoja XSLT.
string simpleReportXml(const DocumentValidationResult result) @safe {
  auto output = appender!string;
  output ~= `<?xml version="1.0" encoding="UTF-8"?>`;
  output ~= format(`<SimpleReport xmlns="%s">`, simpleReportNamespace);
  output ~= format(`<ValidationTime>%s</ValidationTime>`, toRfc3339Utc(cast(SysTime) result.validationTime));
  output ~= format(`<DocumentName>%s</DocumentName>`, escapeXml(result.documentName));
  size_t valid;
  foreach (signature; result.signatures) if (signature.indication == Indication.totalPassed) valid++;
  output ~= format(`<ValidSignaturesCount>%d</ValidSignaturesCount>`, valid);
  output ~= format(`<SignaturesCount>%d</SignaturesCount>`, result.signatures.length);
  foreach (signature; result.signatures) {
    output ~= format(`<Signature Id="%s" SignatureFormat="%s"%s>`, escapeXml(signature.id), escapeXml(signature.format),
      signature.counterSignature ? ` CounterSignature="true"` : "");
    appendCommon(output, signature.certificateChain, signature.indication, signature.subIndication, signature.messages);
    if (!signature.signingTime.isNull)
      output ~= format(`<SigningTime>%s</SigningTime>`, toRfc3339Utc(cast(SysTime) signature.signingTime.get));
    if (!signature.bestSignatureTime.isNull)
      output ~= format(`<BestSignatureTime>%s</BestSignatureTime>`, toRfc3339Utc(cast(SysTime) signature.bestSignatureTime.get));
    if (signature.filename.length) output ~= format(`<Filename>%s</Filename>`, escapeXml(signature.filename));
    output ~= `</Signature>`;
  }
  foreach (timestamp; result.documentTimestamps) {
    output ~= `<Timestamp>`;
    appendCommon(output, timestamp.certificateChain, timestamp.indication, timestamp.subIndication, timestamp.messages);
    output ~= format(`<ProductionTime>%s</ProductionTime>`, toRfc3339Utc(cast(SysTime) timestamp.productionTime));
    if (timestamp.filename.length) output ~= format(`<Filename>%s</Filename>`, escapeXml(timestamp.filename));
    output ~= `</Timestamp>`;
  }
  output ~= `</SimpleReport>`;
  return output[];
}

private void appendCommon(A)(ref A output, const(Certificate)[] chain, Indication indication, SubIndication sub,
    const(ValidationMessage)[] messages) @safe {
  if (chain.length) {
    output ~= `<CertificateChain>`;
    foreach (certificate; chain) {
      output ~= format(`<Certificate><id>%s</id><QualifiedName>%s</QualifiedName></Certificate>`,
        escapeXml(certificate.serialHex), escapeXml(certificate.subject.readableName));
    }
    output ~= `</CertificateChain>`;
  }
  output ~= format(`<Indication>%s</Indication>`, indicationName(indication));
  if (sub != SubIndication.none) output ~= format(`<SubIndication>%s</SubIndication>`, subIndicationName(sub));
  if (messages.length) {
    output ~= `<AdESValidationDetails>`;
    foreach (level; [ValidationMessage.Level.error, ValidationMessage.Level.warning, ValidationMessage.Level.info]) {
      string tag = level == ValidationMessage.Level.error ? "Error"
        : level == ValidationMessage.Level.warning ? "Warning" : "Info";
      string[] seen;
      foreach (item; messages) {
        if (item.level != level) continue;
        bool repeated = false;
        foreach (text; seen) if (text == item.text) repeated = true;
        if (repeated) continue;
        seen ~= item.text;
        output ~= format(`<%s Key="%s">%s</%s>`, tag, escapeXml(item.key), escapeXml(item.text), tag);
      }
    }
    output ~= `</AdESValidationDetails>`;
  }
}

import firmador.x509.certificate : Certificate;

/**
 * Reporte HTML del resultado, con el aviso de anotaciones añadidas después de firmar
 * delante, como Report.getReport en la versión Java.
 *
 * Throws: XmlException si la hoja XSLT incluida no se puede aplicar.
 */
string reportHtml(const DocumentValidationResult result) @safe {
  string body = applyStylesheet(cast(const(ubyte)[]) import("xslt/html/simple-report.xslt"),
    cast(const(ubyte)[]) simpleReportXml(result));
  string annotationChanges;
  foreach (signature; result.signatures) {
    if (signature.pdfAnnotationChanges) annotationChanges = t("report_document_with_annotation");
  }
  return "<html>" ~ annotationChanges ~ body ~ "</html>";
}

@("should render the simple report HTML with the signer and indication texts of the stylesheet")
unittest {
  import std.algorithm : canFind;
  import std.datetime.systime : Clock;
  DocumentValidationResult result;
  result.documentName = "contrato.pdf";
  result.validationTime = Clock.currTime;
  SignatureResult signature;
  signature.id = "Signature1";
  signature.format = "PAdES-BASELINE-LTA";
  signature.indication = Indication.totalPassed;
  signature.signingTime = Clock.currTime;
  signature.messages = [message(ValidationMessage.Level.warning, "BBB_XCV_ISCR_ANS")];
  result.signatures = [signature];
  string html = reportHtml(result);
  assert(html.canFind("contrato.pdf"));
  assert(html.canFind("está firmado digitalmente"));
  assert(html.canFind("<b>válida</b>"));
  assert(html.canFind("PAdES-BASELINE-LTA"));
  assert(html.canFind("Advertencia"));
  result.signatures[0].indication = Indication.indeterminate;
  assert(reportHtml(result).canFind("se han encontrado"));
  result.signatures = null;
  assert(reportHtml(result).canFind("no está firmado digitalmente"));
}
