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
 * Validación de contenedores ASiC (con XAdES o CAdES) y de documentos OpenDocument: las
 * firmas XAdES de META-INF se validan con sus referencias a los archivos del contenedor;
 * las CAdES de ASiC-S sobre el único documento y las de ASiC-E sobre su ASiCManifest, cuyos
 * resúmenes de archivos también se comprueban; los sellos .tst se informan como sellos de
 * documento.
 */
module firmador.validators.containervalidator;

import std.datetime.systime : Clock;
import std.exception : enforce;
import std.logger : trace, warning;

import firmador.cms.tsp;
import firmador.containers.asic;
import firmador.crypto.digest;
import firmador.util.base64 : encodeBase64;
import firmador.util.zip;
import firmador.validation.certpath;
import firmador.validation.cmsverify : validateTimestamp;
import firmador.validation.conclusion : finishSignature, unreadableSignature, unreadableTimestamp;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.validators.cadesvalidator;
import firmador.validators.xmlvalidator;
import firmador.xml.dom;
import firmador.xml.xades : asicNamespace;
import firmador.xml.xmldsig : decodeXmlBase64;

/// Referencia de un ASiCManifest a un archivo del contenedor.
struct ManifestReference {
  string uri;
  DigestAlgorithm digest;
  immutable(ubyte)[] digestValue;
}

/// ASiCManifest interpretado: el archivo que lo firma y los que referencia.
struct AsicManifest {
  string signatureUri;
  ManifestReference[] references;
}

/**
 * Interpreta un ASiCManifest (EN 319 162-1 §A.4).
 *
 * Throws: XmlException si no tiene la forma esperada.
 */
AsicManifest parseAsicManifest(immutable(ubyte)[] xml) @trusted {
  import std.uri : decodeComponent;
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  enforce!XmlException(document.root.isElement(asicNamespace, "ASiCManifest"), "El manifiesto no es un ASiCManifest");
  AsicManifest manifest;
  manifest.signatureUri = decodeComponent(document.root.requiredChild(asicNamespace, "SigReference").attribute("URI"));
  foreach (reference; document.root.childrenNamed(asicNamespace, "DataObjectReference")) {
    ManifestReference entry;
    entry.uri = decodeComponent(reference.attribute("URI"));
    entry.digest = digestFromXmlUri(reference.requiredChild(xmldsigNamespace, "DigestMethod").attribute("Algorithm"));
    entry.digestValue = decodeXmlBase64(reference.requiredChild(xmldsigNamespace, "DigestValue").text);
    manifest.references ~= entry;
  }
  return manifest;
}

/// Comprueba cada archivo que referencia el manifiesto contra el contenedor.
Verdict checkManifestReferences(const AsicManifest manifest, const ZipEntry[] entries) pure @safe {
  Verdict verdict;
  foreach (reference; manifest.references) {
    auto content = entryContent(entries, reference.uri);
    if (content is null) {
      verdict.degrade(Indication.indeterminate, SubIndication.signedDataNotFound,
        message(ValidationMessage.Level.error, "BBB_CV_IRDOF_ANS", reference.uri));
    } else if (digestOf(reference.digest, content) != reference.digestValue) {
      verdict.degrade(Indication.totalFailed, SubIndication.hashFailure,
        message(ValidationMessage.Level.error, "BBB_CV_IRDOI_ANS", reference.uri));
    }
  }
  return verdict;
}

private SignatureResult withVerdict(SignatureResult signature, const Verdict extra) pure @safe {
  if (extra.messages.length == 0) return signature;
  Verdict verdict;
  verdict.indication = signature.indication == Indication.totalPassed ? Indication.passed : signature.indication;
  verdict.subIndication = signature.subIndication;
  verdict.messages = signature.messages.dup;
  verdict.absorb(extra);
  return finishSignature(signature, verdict, signature.format);
}

/**
 * Valida todas las firmas y sellos del contenedor.
 *
 * Throws: ZipFormatException si no es un ZIP legible.
 */
DocumentValidationResult validateContainer(immutable(ubyte)[] container, string documentName,
    ValidationDataSource source, bool allowOnline = true) @trusted {
  DocumentValidationResult result;
  result.documentName = documentName;
  result.validationTime = Clock.currTime;
  auto entries = readZip(container);
  auto xadesContent = classifyContainer(entries);
  auto cadesContent = classifyContainer(entries, true);
  auto resolver = containerResolver(xadesContent);
  bool asicS = xadesContent.mimeType == asicSMimeType;

  foreach (signatureFile; xadesContent.signatureDocuments) {
    try {
      auto document = XmlDocument.parse(signatureFile.content);
      scope (exit) document.close();
      auto signatures = validateXmlSignatures(document, resolver, null, source, allowOnline, result.validationTime);
      foreach (ref signature; signatures) signature.filename = signatureFile.name;
      result.signatures ~= signatures;
    } catch (Exception exception) {
      warning("Archivo de firmas ilegible en el contenedor: ", signatureFile.name, ": ", exception.msg);
      result.signatures ~= unreadableSignature(signatureFile.name, "XAdES", exception.msg);
    }
  }

  // Lo que cubre una firma CAdES o un sello: su ASiCManifest (ASiC-E) o el único documento (ASiC-S).
  bool coveredData(string signatureName, out immutable(ubyte)[] covered, out Verdict manifestVerdict) {
    foreach (manifestFile; cadesContent.manifestDocuments) {
      try {
        auto manifest = parseAsicManifest(manifestFile.content);
        if (manifest.signatureUri != signatureName) continue;
        covered = manifestFile.content;
        manifestVerdict = checkManifestReferences(manifest, entries);
        return true;
      } catch (Exception exception) {
        trace("ASiCManifest ilegible ", manifestFile.name, ": ", exception.msg);
      }
    }
    if ((asicS || cadesContent.manifestDocuments.length == 0) && cadesContent.signedDocuments.length == 1) {
      covered = cadesContent.signedDocuments[0].content;
      return true;
    }
    return false;
  }

  foreach (signatureFile; cadesContent.signatureDocuments) {
    immutable(ubyte)[] covered;
    Verdict manifestVerdict;
    DetachedContent[] detached;
    if (coveredData(signatureFile.name, covered, manifestVerdict)) detached = [DetachedContent(signatureFile.name, covered)];
    try {
      auto validated = validateCades(signatureFile.content, signatureFile.name, source, allowOnline, detached);
      foreach (signature; validated.signatures) {
        signature.filename = signatureFile.name;
        result.signatures ~= withVerdict(signature, manifestVerdict);
      }
    } catch (Exception exception) {
      warning("Firma CAdES ilegible en el contenedor: ", signatureFile.name, ": ", exception.msg);
      result.signatures ~= unreadableSignature(signatureFile.name, "CAdES", exception.msg);
    }
  }

  foreach (timestampFile; cadesContent.timestampDocuments) {
    immutable(ubyte)[] covered;
    Verdict manifestVerdict;
    TimestampResult stamped;
    try {
      auto token = parseTimeStampToken(timestampFile.content);
      if (coveredData(timestampFile.name, covered, manifestVerdict)) {
        stamped = validateTimestamp(token, covered, TimestampResult.Kind.document,
          pathContext(source, allowOnline, result.validationTime));
        stamped.messages ~= manifestVerdict.messages;
        if (!manifestVerdict.isPassed) stamped.indication = Indication.failed;
      } else {
        stamped.indication = Indication.indeterminate;
        stamped.subIndication = SubIndication.signedDataNotFound;
        stamped.productionTime = token.info.genTime;
        stamped.messages ~= message(ValidationMessage.Level.error, "BBB_CV_IRDOF_ANS");
      }
    } catch (Exception exception) {
      warning("Sello de tiempo ilegible en el contenedor: ", timestampFile.name, ": ", exception.msg);
      stamped = unreadableTimestamp(TimestampResult.Kind.document, exception.msg);
    }
    stamped.filename = timestampFile.name;
    result.documentTimestamps ~= stamped;
  }
  return result;
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
  import firmador.x509.certificate : parseCertificate;
  import firmador.xml.xades;
}

@("should validate an ASiC-E XAdES signature against the container files and detect a changed file")
unittest {
  auto identity = makeTestIdentity("Firmante ASiC", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = newAsicEContainer([ZipEntry("a b.txt", cast(immutable(ubyte)[]) "hola")]);
  XadesParameters parameters;
  parameters.signingTime = Clock.currTime;
  parameters.signingCertificate = certificate;
  parameters.packaging = XadesPackaging.container;
  parameters.files = asicSignedFiles(content);
  parameters.en319132 = true;
  auto prepared = prepareXadesSignature(null, parameters, asicSignaturesRoot);
  content = withSignatureDocument(content, asicXadesSignatureTemplate,
    completeXadesSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign)));
  auto container = writeContainer(content, Clock.currTime);
  auto result = validateContainer(container, "c.asice", new OfflineValidationSource, false);
  assert(result.signatures.length == 1);
  assert(result.signatures[0].format == "XAdES-BASELINE-B");
  assert(result.signatures[0].subIndication == SubIndication.noCertificateChainFound);
  assert(result.signatures[0].filename == asicXadesSignatureTemplate);

  content.signedDocuments[0].content = cast(immutable(ubyte)[]) "adiós";
  auto tampered = validateContainer(writeContainer(content, Clock.currTime), "c.asice", new OfflineValidationSource,
    false);
  assert(tampered.signatures[0].subIndication == SubIndication.hashFailure);
}

@("should check each ASiCManifest reference digest against the container entries")
unittest {
  auto file = ZipEntry("doc.txt", cast(immutable(ubyte)[]) "texto");
  string manifestXml = `<asic:ASiCManifest xmlns:asic="` ~ asicNamespace ~ `" xmlns:ds="` ~ xmldsigNamespace ~ `">`
    ~ `<asic:SigReference URI="META-INF/signature001.p7s" MimeType="application/pkcs7-signature"/>`
    ~ `<asic:DataObjectReference URI="doc.txt"><ds:DigestMethod Algorithm="` ~ digestXmlUri(DigestAlgorithm.sha256)
    ~ `"/><ds:DigestValue>` ~ encodeBase64(digestOf(DigestAlgorithm.sha256, file.content))
    ~ `</ds:DigestValue></asic:DataObjectReference></asic:ASiCManifest>`;
  auto manifest = parseAsicManifest(cast(immutable(ubyte)[]) manifestXml);
  assert(manifest.signatureUri == "META-INF/signature001.p7s");
  assert(checkManifestReferences(manifest, [file]).isPassed);
  auto changed = checkManifestReferences(manifest, [ZipEntry("doc.txt", cast(immutable(ubyte)[]) "otro")]);
  assert(changed.subIndication == SubIndication.hashFailure);
  assert(checkManifestReferences(manifest, []).subIndication == SubIndication.signedDataNotFound);
}
