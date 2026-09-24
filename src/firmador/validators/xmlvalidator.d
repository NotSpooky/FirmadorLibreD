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
 * Validación de firmas XML (XAdES y XMLDSig): para cada ds:Signature que no está dentro
 * de otra se comprueban el certificado de firma (SigningCertificate), las referencias,
 * el valor de la firma, los sellos de firma y de archivo con sus datos sellados, y la
 * cadena y revocación del firmante con los valores incluidos. También la usa la
 * validación de contenedores ASiC, que pasa los archivos firmados.
 */
module firmador.validators.xmlvalidator;

import std.algorithm : canFind;
import std.datetime.systime : Clock, SysTime;
import std.logger : trace, warning;
import std.path : baseName;
import std.string : strip;

import firmador.cms.tsp;
import firmador.configuration : haciendaPolicyId, haciendaPolicyLegacyId, haciendaPolicyDocument;
import firmador.crypto.digest;
import firmador.util.datetime : parseRfc3339;
import firmador.validation.certpath;
import firmador.validation.cmsverify : validateTimestamp;
import firmador.validation.conclusion;
import firmador.validation.model;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.x509.certificate;
import firmador.xml.dom;
import firmador.xml.xades;
import firmador.xml.xmldsig;

/// Busca el archivo por nombre exacto o, si no hay, por nombre base.
ExternalResolver detachedResolver(const DetachedContent[] contents) @safe {
  return (string uri) @safe {
    foreach (item; contents) if (item.name == uri) return item.content;
    foreach (item; contents) if (baseName(item.name) == baseName(uri)) return item.content;
    return cast(immutable(ubyte)[]) null;
  };
}

/**
 * Valida las firmas del documento XML. Si el documento es una firma separada (su raíz es
 * ds:Signature), `detached` trae lo firmado; con un único archivo, URI="" lo designa.
 *
 * Throws: XmlException si el documento no es XML bien formado.
 */
DocumentValidationResult validateXml(immutable(ubyte)[] xml, string documentName, ValidationDataSource source,
    bool allowOnline = true, const DetachedContent[] detached = null) @trusted {
  DocumentValidationResult result;
  result.documentName = documentName;
  result.validationTime = Clock.currTime;
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  XmlDocument emptyUriDocument;
  if (document.root.isElement(xmldsigNamespace, "Signature") && detached.length == 1) {
    try {
      emptyUriDocument = XmlDocument.parse(detached[0].content);
    } catch (XmlException exception) {
      trace("El archivo separado no es XML: ", exception.msg);
    }
  }
  scope (exit) if (emptyUriDocument !is null) emptyUriDocument.close();
  result.signatures = validateXmlSignatures(document, detachedResolver(detached), emptyUriDocument, source,
    allowOnline, result.validationTime);
  foreach (ref signature; result.signatures) if (signature.filename.length == 0) signature.filename = documentName;
  return result;
}

/// Valida cada firma del documento que no está dentro de otra.
SignatureResult[] validateXmlSignatures(XmlDocument document, ExternalResolver resolver, XmlDocument emptyUriDocument,
    ValidationDataSource source, bool allowOnline, SysTime validationTime) @trusted {
  SignatureResult[] signatures;
  foreach (element; topLevelSignatures(document)) {
    auto pool = CertificatePool.withNationalHierarchy();
    PathContext context;
    context.pool = pool;
    context.source = source;
    context.allowOnline = allowOnline;
    context.validationTime = validationTime;
    context.bestSignatureTime = validationTime;
    signatures ~= validateXmlSignature(document, element, context, resolver, emptyUriDocument);
  }
  return signatures;
}

private SignatureResult validateXmlSignature(XmlDocument document, XmlNode element, PathContext baseContext,
    ExternalResolver resolver, XmlDocument emptyUriDocument) @trusted {
  SignatureResult signature;
  signature.id = element.attribute("Id");
  Verdict verdict;
  auto properties = qualifyingProperties(element);
  bool xades = !properties.isNull;
  string family = xades ? "XAdES-BASELINE" : "XML-NOT-ETSI";

  DsSignature parsed;
  try {
    parsed = parseDsSignature(element);
  } catch (Exception exception) {
    verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
      message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", exception.msg));
    return finish(signature, verdict, xades ? family ~ "-B" : family);
  }
  auto embedded = embeddedValidationData(element);
  baseContext.pool.addAll(embedded.certificates);
  baseContext.embeddedOcsp = embedded.ocspResponses;
  baseContext.embeddedCrls = embedded.crls;

  XmlNode signedProperties;
  if (xades) {
    signedProperties = properties.child(xadesNamespace, "SignedProperties");
    bool covered = false;
    foreach (reference; parsed.references) {
      if (!signedProperties.isNull && reference.uri.length > 1 && reference.uri[0] == '#'
          && signedProperties.attribute("Id") == reference.uri[1 .. $]) covered = true;
    }
    if (!covered) {
      verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
        message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS"));
    }
    auto signatureProperties = signedProperties.isNull ? XmlNode.init
      : signedProperties.child(xadesNamespace, "SignedSignatureProperties");
    auto signingTime = signatureProperties.isNull ? XmlNode.init : signatureProperties.child(xadesNamespace, "SigningTime");
    if (!signingTime.isNull) {
      try {
        signature.signingTime = parseRfc3339(signingTime.text.strip);
      } catch (Exception exception) {
        trace("SigningTime ilegible: ", exception.msg);
      }
    }
    auto policy = signatureProperties.isNull ? XmlNode.init
      : signatureProperties.child(xadesNamespace, "SignaturePolicyIdentifier");
    if (!policy.isNull) {
      try {
        verdict.absorb(checkSignaturePolicy(policy));
      } catch (Exception exception) {
        verdict.warn(message(ValidationMessage.Level.warning, "BBB_VCI_ISPM_ANS", exception.msg));
      }
    }
  }

  Certificate signer;
  if (xades) {
    SigningCertificateReference[] references;
    try {
      references = signingCertificateReferences(element);
    } catch (Exception exception) {
      verdict.degrade(Indication.totalFailed, SubIndication.formatFailure,
        message(ValidationMessage.Level.error, "BBB_FC_IEFF_ANS", exception.msg));
    }
    // Niveles de la política por omisión de DSS: SigningCertificatePresent e IssuerSerialMatch
    // avisan; CertDigestMatch falla.
    if (references.length == 0) {
      verdict.warn(message(ValidationMessage.Level.warning, "BBB_ICS_ISASCP_ANS"));
      if (parsed.keyInfoCertificates.length) signer = parsed.keyInfoCertificates[0];
    } else {
      signer = matchSigningCertificate(references, embedded.certificates ~ baseContext.pool.all);
      if (signer is null) {
        verdict.degrade(Indication.indeterminate, SubIndication.noSigningCertificateFound,
          message(ValidationMessage.Level.error, "BBB_ICS_ICDVV_ANS"));
      } else if (references[0].serialDecimal.length && references[0].serialDecimal != signer.serialDecimal) {
        verdict.warn(message(ValidationMessage.Level.warning, "BBB_ICS_AIDNASNE_ANS"));
      }
    }
  } else if (parsed.keyInfoCertificates.length) {
    signer = parsed.keyInfoCertificates[0];
  }
  if (signer is null && verdict.subIndication != SubIndication.noSigningCertificateFound) {
    verdict.degrade(Indication.indeterminate, SubIndication.noSigningCertificateFound,
      message(ValidationMessage.Level.error, "BBB_ICS_ISCI_ANS"));
  }

  if (signer !is null) {
    auto verification = verifyXmlSignature(document, parsed, signer, resolver, emptyUriDocument);
    if (verification.missingReferences.length) {
      verdict.degrade(Indication.indeterminate, SubIndication.signedDataNotFound,
        message(ValidationMessage.Level.error, "BBB_CV_IRDOF_ANS"));
    }
    if (verification.failedReferences.length) {
      verdict.degrade(Indication.totalFailed, SubIndication.hashFailure,
        message(ValidationMessage.Level.error, "BBB_CV_IRDOI_ANS"));
    }
    if (!verification.signatureValid) {
      verdict.degrade(Indication.totalFailed, SubIndication.sigCryptoFailure,
        message(ValidationMessage.Level.error, "BBB_CV_ISI_ANS"));
    }
  }

  // Sellos en el orden en que están: cada sello de archivo cubre lo anterior.
  bool hasSignatureTimestamp, hasArchiveTimestamp, hasValidationValues;
  auto unsigned = unsignedSignatureProperties(element);
  if (!unsigned.isNull) {
    foreach (property; unsigned.children()) {
      TimestampResult.Kind kind;
      if (property.isElement(xadesNamespace, "SignatureTimeStamp")) {
        kind = TimestampResult.Kind.signature;
        hasSignatureTimestamp = true;
      } else if (property.isElement(xades141Namespace, "ArchiveTimeStamp")
          || property.isElement(xadesNamespace, "ArchiveTimeStamp")) {
        kind = TimestampResult.Kind.archive;
        hasArchiveTimestamp = true;
      } else {
        if (property.isElement(xadesNamespace, "CertificateValues") || property.isElement(xadesNamespace, "RevocationValues")
            || property.isElement(xades141Namespace, "TimeStampValidationData")) hasValidationValues = true;
        continue;
      }
      try {
        auto methodElement = property.child(xmldsigNamespace, "CanonicalizationMethod");
        auto method = methodElement.isNull ? CanonicalizationMethod.inclusive10
          : canonicalizationFromUri(methodElement.attribute("Algorithm"));
        auto token = parseTimeStampToken(decodeXmlBase64(property.requiredChild(xadesNamespace, "EncapsulatedTimeStamp").text));
        baseContext.pool.addAll(token.signedData.certificates);
        auto stampedData = kind == TimestampResult.Kind.signature ? signatureTimestampData(document, element, method)
          : archiveTimestampData(document, element, property, method, resolver, emptyUriDocument);
        PathContext timestampContext = baseContext;
        signature.timestamps ~= validateTimestamp(token, stampedData, kind, timestampContext);
      } catch (Exception exception) {
        warning("Sello de tiempo ilegible en la firma ", signature.id, ": ", exception.msg);
        signature.timestamps ~= unreadableTimestamp(kind, exception.msg);
      }
    }
  }
  return concludeSignature(signature, verdict, signer, baseContext,
    xades ? family ~ "-" ~ baselineLevel(hasSignatureTimestamp, hasValidationValues, hasArchiveTimestamp) : family);
}

/**
 * Comprueba la política de firma explícita: las de Hacienda se comparan con la copia
 * incluida (configuration.haciendaPolicyDocument), como el SignaturePolicyProvider de la
 * versión Java; las demás no se descargan (PolicyAvailable informa, como en DSS).
 *
 * Throws: XmlException si SignaturePolicyId está mal formado.
 */
private Verdict checkSignaturePolicy(XmlNode policyIdentifier) @safe {
  Verdict verdict;
  auto policyId = policyIdentifier.child(xadesNamespace, "SignaturePolicyId");
  if (policyId.isNull) return verdict;
  string identifier = policyId.requiredChild(xadesNamespace, "SigPolicyId").requiredChild(xadesNamespace, "Identifier")
    .text.strip;
  if (identifier != haciendaPolicyId && identifier != haciendaPolicyLegacyId) {
    verdict.warn(message(ValidationMessage.Level.info, "BBB_VCI_ISPA_ANS"));
    return verdict;
  }
  auto hash = policyId.requiredChild(xadesNamespace, "SigPolicyHash");
  auto algorithm = digestFromXmlUri(hash.requiredChild(xmldsigNamespace, "DigestMethod").attribute("Algorithm"));
  auto expected = decodeXmlBase64(hash.requiredChild(xmldsigNamespace, "DigestValue").text);
  if (digestOf(algorithm, cast(const(ubyte)[]) import(haciendaPolicyDocument)) != expected) {
    verdict.warn(message(ValidationMessage.Level.warning, "BBB_VCI_ISPM_ANS"));
  }
  return verdict;
}

private SignatureResult finish(SignatureResult signature, Verdict verdict, string format_) @safe {
  signature.format = format_;
  signature.indication = verdict.isPassed ? Indication.totalPassed : verdict.indication;
  signature.subIndication = verdict.subIndication;
  signature.messages = verdict.messages;
  return signature;
}

version (unittest) import firmador.crypto.openssl : makeTestIdentity;

@("should validate an enveloped XAdES cryptographically and flag the untrusted test chain")
unittest {
  auto identity = makeTestIdentity("Firmante XML", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = cast(immutable(ubyte)[]) "<?xml version=\"1.0\"?><MensajeReceptor><Clave>1</Clave></MensajeReceptor>";
  XadesParameters parameters;
  parameters.signingTime = Clock.currTime;
  parameters.signingCertificate = certificate;
  parameters.policy = haciendaPolicy();
  auto prepared = prepareXadesSignature(content, parameters);
  auto signed = completeXadesSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));
  auto result = validateXml(signed, "mensaje.xml", new OfflineValidationSource, false);
  assert(result.signatures.length == 1);
  auto signature = result.signatures[0];
  assert(signature.format == "XAdES-BASELINE-B");
  assert(signature.indication == Indication.indeterminate);
  assert(signature.subIndication == SubIndication.noCertificateChainFound);
  assert(!signature.signingTime.isNull);

  import std.array : replace;
  auto tampered = cast(immutable(ubyte)[]) (cast(string) signed).replace("<Clave>1</Clave>", "<Clave>2</Clave>");
  auto broken = validateXml(tampered, "alterado.xml", new OfflineValidationSource, false);
  assert(broken.signatures[0].indication == Indication.totalFailed);
  assert(broken.signatures[0].subIndication == SubIndication.hashFailure);

  auto unsigned = validateXml(content, "sin-firma.xml", new OfflineValidationSource, false);
  assert(unsigned.signatures.length == 0);
}

@("should resolve URI empty references against the detached XML when validating a detached signature")
unittest {
  auto identity = makeTestIdentity("Firmante separado", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto content = cast(immutable(ubyte)[]) "<?xml version=\"1.0\"?><datos><a>1</a></datos>";
  XadesParameters parameters;
  parameters.signingTime = Clock.currTime;
  parameters.signingCertificate = certificate;
  parameters.packaging = XadesPackaging.detached;
  auto prepared = prepareXadesSignature(content, parameters);
  auto signed = completeXadesSignature(prepared, identity.key.sign(DigestAlgorithm.sha256, prepared.dataToSign));
  auto withContent = validateXml(signed, "firma.xml", new OfflineValidationSource, false,
    [DetachedContent("datos.xml", content)]);
  assert(withContent.signatures[0].subIndication == SubIndication.noCertificateChainFound);
  auto withoutContent = validateXml(signed, "firma.xml", new OfflineValidationSource, false);
  assert(withoutContent.signatures[0].indication == Indication.totalFailed);
}
