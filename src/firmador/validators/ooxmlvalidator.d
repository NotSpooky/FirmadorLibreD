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
 * Validación de firmas OOXML (OOXMLValidator): cada parte de firma del paquete se
 * verifica con sus referencias y las del manifiesto (como SignaturePart.validate de POI)
 * y se informa con el texto ooxmlvalidator_report. La garantía de validez en el tiempo
 * se da cuando el sello de la firma es válido y la cadena del firmante lo era a su hora.
 */
module firmador.validators.ooxmlvalidator;

import std.datetime.systime : Clock, SysTime;
import std.format : format;
import std.logger : warning;
import std.string : strip;
import std.typecons : Nullable;

import firmador.asn1.oids;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.i18n : t;
import firmador.ooxml.signature;
import firmador.settings : Settings;
import firmador.util.datetime : costaRicaDay, dateLanguageFor, formatJavaDate, parseRfc3339;
import firmador.util.zip;
import firmador.validation.certpath;
import firmador.validation.cmsverify : validateTimestamp;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.x509.certificate;
import firmador.xml.dom;
import firmador.xml.xades : embeddedValidationData, unsignedSignatureProperties, xadesTimestamp;
import firmador.xml.xmldsig;

/// Resultado de una parte de firma OOXML.
struct OoxmlSignatureCheck {
  string partName;
  Certificate signer;
  /// Referencias, manifiesto y valor de firma correctos.
  bool valid;
  Nullable!SysTime signingTime;
  /// Sello válido y cadena del firmante válida a la hora del sello.
  bool validOverTime;
}

/**
 * Verifica todas las firmas del paquete. Las partes que no se pueden leer se informan
 * como no válidas.
 *
 * Throws: ZipFormatException si no es un ZIP legible.
 */
OoxmlSignatureCheck[] checkOoxmlSignatures(immutable(ubyte)[] package_, ValidationDataSource source,
    bool allowOnline = true) @trusted {
  auto entries = readZip(package_);
  auto resolver = packageResolver(entries);
  OoxmlSignatureCheck[] checks;
  foreach (partName; signaturePartNames(entries)) {
    OoxmlSignatureCheck check;
    check.partName = partName;
    try {
      auto content = entryContent(entries, partName[1 .. $]);
      if (content is null) throw new XmlException("La parte de firma no existe");
      auto document = XmlDocument.parse(content);
      scope (exit) document.close();
      auto signature = parseDsSignature(document.root);
      if (signature.keyInfoCertificates.length == 0) throw new XmlException("La firma no incluye su certificado");
      // Como KeyInfoKeySelector de POI: el firmante es el primer certificado de KeyInfo.
      check.signer = signature.keyInfoCertificates[0];
      auto verification = verifyXmlSignature(document, signature, check.signer, resolver);
      bool manifestValid = true;
      foreach (manifest; document.elements(xmldsigNamespace, "Manifest")) {
        foreach (element; manifest.childrenNamed(xmldsigNamespace, "Reference")) {
          auto reference = parseReference(element);
          try {
            if (digestOf(reference.digest, processReference(document, signature, reference, resolver)) != reference.digestValue) {
              manifestValid = false;
            }
          } catch (Exception exception) {
            warning("Referencia del manifiesto sin resolver ", reference.uri, ": ", exception.msg);
            manifestValid = false;
          }
        }
      }
      check.valid = verification.referencesValid && verification.signatureValid && manifestValid;
      auto values = document.elements(opcDigitalSignatureNamespace, "Value");
      if (values.length) check.signingTime = parseRfc3339(values[0].text.strip);
      check.validOverTime = check.valid && validOverTime(document, signature, check.signer, source, allowOnline);
    } catch (Exception exception) {
      warning("Firma OOXML ilegible en ", partName, ": ", exception.msg);
    }
    checks ~= check;
  }
  return checks;
}

private bool validOverTime(XmlDocument document, const DsSignature signature, Certificate signer,
    ValidationDataSource source, bool allowOnline) @trusted {
  auto unsigned = unsignedSignatureProperties(cast(XmlNode) signature.element);
  if (unsigned.isNull) return false;
  auto timestampElement = unsigned.child(xadesNamespace, "SignatureTimeStamp");
  if (timestampElement.isNull) return false;
  auto context = pathContext(source, allowOnline, Clock.currTime);
  includeEmbedded(context, embeddedValidationData(cast(XmlNode) signature.element));
  auto stamp = xadesTimestamp(timestampElement);
  context.bestSignatureTime = stamp.token.info.genTime;
  auto stamped = validateTimestamp(stamp.token, document.canonicalize(cast(XmlNode) signature.signatureValueElement,
    stamp.method), TimestampResult.Kind.signature, context);
  if (stamped.indication != Indication.passed) return false;
  auto path = validatePath(signer, context);
  return path.trusted && path.verdict.isPassed;
}

/**
 * Reporte HTML de las firmas como OOXMLValidator.getStringReport: sólo firmantes de
 * certificados finales con firma digital y no repudio, con la fecha declarada en el
 * formato de los ajustes y la hora local.
 */
string ooxmlReport(const OoxmlSignatureCheck[] checks, const Settings settings) @safe {
  string report;
  int position = 0;
  foreach (check; checks) {
    position++;
    if (check.signer is null) continue;
    auto signer = check.signer;
    if (!isSigningCertificate(signer)) continue;
    string firstName = signer.subject.first(oidGivenName);
    string lastName = signer.subject.first(oidSurname);
    string name = firstName.length == 0 && lastName.length == 0 ? signer.subject.first(oidCommonName)
      : firstName ~ " " ~ lastName;
    string date = check.signingTime.isNull ? "" : formatJavaDate(settings.getDateFormat(),
      (cast(SysTime) check.signingTime.get).toLocalTime, dateLanguageFor(settings.language));
    report ~= format(t("ooxmlvalidator_report"), position, name, signer.subject.first(oidSerialNumber),
      signer.subject.first(oidOrganization), date, t(check.valid ? "ooxmlvalidator_valid" : "ooxmlvalidator_invalid"),
      costaRicaDay(signer.notAfter), t(check.validOverTime ? "ooxmlvalidator_valid" : "ooxmlvalidator_invalid"));
    report ~= "<br>";
  }
  return report;
}

version (unittest) import firmador.crypto.openssl : makeTestIdentity;

@("should verify a signed package and reject it after a signed part changes")
unittest {
  auto identity = makeTestIdentity("Firmante Word", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto entries = testPackage();
  OoxmlParameters parameters;
  parameters.signingTime = Clock.currTime;
  parameters.signingCertificate = certificate;
  auto prepared = prepareOoxmlSignature(entries, parameters);
  auto signatureXml = completeOoxmlSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));
  auto signedEntries = addSignaturePart(entries, signatureXml);
  auto checks = checkOoxmlSignatures(writeZip(signedEntries, Clock.currTime), new OfflineValidationSource, false);
  assert(checks.length == 1 && checks[0].valid && !checks[0].signingTime.isNull);
  assert(!checks[0].validOverTime);

  foreach (ref entry; signedEntries) {
    if (entry.name == "word/styles.xml") entry.content = cast(immutable(ubyte)[]) "<w:styles xmlns:w=\"urn:w\">x</w:styles>";
  }
  auto tampered = checkOoxmlSignatures(writeZip(signedEntries, Clock.currTime), new OfflineValidationSource, false);
  assert(!tampered[0].valid);
}
