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
 * Firmas PAdES baseline (ETSI EN 319 142-1) sobre firmador.pdf.writer: la firma CAdES
 * separada dentro del PDF (niveles B y T), el diccionario DSS con los datos de validación
 * (LT) y el sello de tiempo de documento (LTA y el sellado independiente). La interacción
 * con el usuario está en firmador.signers.pades.
 */
module firmador.pdf.pades;

import core.sync.mutex : Mutex;
import std.algorithm : canFind;
import std.datetime.systime : Clock, SysTime;
import std.exception : basicExceptionCtors;
import std.format : format;
import std.logger : info, warning;

import firmador.asn1.oids;
import firmador.cms.signeddata;
import firmador.cms.tsp;
import firmador.configuration : appName, padesSignatureContentSize, padesTimestampContentSize;
import firmador.crypto.digest;
import firmador.pdf.appearance;
import firmador.pdf.engine;
import firmador.pdf.writer;
import firmador.settings : Rgba, SignerTextPosition, SignatureRotation;
import firmador.util.datetime : toPdfDate;
import firmador.validation.certpath : ValidationData;
import firmador.validation.cmsverify : findSignerCertificate, timestampSignerCertificate;
import firmador.validation.pool : CertificatePool;
import firmador.x509.certificate;

/// Fuente de la firma visible: una estándar o una TrueType incrustada.
struct SignatureFont {
  string standardName = "Helvetica";
  immutable(ubyte)[] trueType;
}

/// Firma visible que se va a dibujar.
struct VisibleSignature {
  string text;
  SignatureFont font;
  float fontSize = 7;
  Rgba textColor = Rgba(0, 0, 0, 255);
  Rgba backgroundColor = Rgba(255, 255, 255, 0);
  SignerTextPosition position = SignerTextPosition.right;
  /// Imagen original (PNG o JPEG) y el tamaño en píxeles con que se dibuja.
  immutable(ubyte)[] image;
  ImageSize imageSize;
  float originX = 0;
  float originY = 0;
  SignatureRotation rotation = SignatureRotation.automatic;
}

private __gshared FontMetrics[string] standardMetricsCache;
private __gshared Mutex metricsLock;

shared static this() {
  metricsLock = new Mutex;
}

/// Métricas de la fuente (las estándar se calculan una sola vez).
FontMetrics metricsFor(const SignatureFont font) @trusted {
  FontMetrics metrics;
  if (font.trueType.length) {
    auto custom = customFontMetrics(font.trueType);
    metrics.widths = custom.widths;
    metrics.boundingBoxHeight = custom.boundingBoxHeight;
    return metrics;
  }
  metricsLock.lock();
  scope (exit) metricsLock.unlock();
  if (auto cached = font.standardName in standardMetricsCache) return *cached;
  metrics.widths = standardFontWidths(font.standardName, winAnsiTable());
  metrics.boundingBoxHeight = standardFontBoundingBoxHeight(font.standardName);
  standardMetricsCache[font.standardName] = metrics;
  return metrics;
}

/**
 * Codificador de las líneas del texto para la fuente de la firma (WinAnsi para las
 * estándar, Latin-1 para las propias). Avisa en la bitácora si el texto tiene caracteres
 * que la fuente no tiene, que se dibujan como «?».
 */
ubyte[] delegate(string) pure @safe encoderFor(const VisibleSignature visible) @safe {
  auto encodeLine = visible.font.trueType.length ? &encodeLatin1 : &encodeWinAnsi;
  size_t missing;
  foreach (line; javaLines(visible.text)) encodeLine(line, missing);
  if (missing) warning(format("La fuente de la firma no tiene %d caracteres del texto; se cambiaron por «?»", missing));
  return (string line) pure @safe {
    size_t replaced;
    return encodeLine(line, replaced);
  };
}

/// Entrada del diseño para la firma visible en una página con esa geometría.
VisibleSignatureInput layoutInput(const VisibleSignature visible, const PageGeometry geometry) @safe {
  VisibleSignatureInput input;
  input.text = visible.text;
  input.position = visible.position;
  input.fontSize = visible.fontSize;
  input.metrics = metricsFor(visible.font);
  input.textColor = visible.textColor;
  input.backgroundColor = visible.backgroundColor;
  input.hasImage = visible.image.length > 0;
  input.image = visible.imageSize;
  input.originX = visible.originX;
  input.originY = visible.originY;
  input.rotation = visible.rotation;
  input.pageRotation = geometry.rotation;
  input.pageBox = geometry.mediaBox;
  return input;
}

/// El rectángulo se superpone con una anotación existente de la página (isOverlap de DSS).
bool overlapsAnnotation(const(PdfAnnotation)[] annotations, int pageIndex, PdfRect rect) pure nothrow @safe @nogc {
  foreach (annotation; annotations) {
    if (annotation.pageIndex != pageIndex) continue;
    auto other = annotation.rect;
    if (other.width <= 0 || other.height <= 0) continue;
    if (rect.x0 >= other.x1 || other.x0 >= rect.x1) continue;
    if (rect.y0 >= other.y1 || other.y0 >= rect.y1) continue;
    return true;
  }
  return false;
}

/// Primer nombre «SignatureN» que no usa ningún campo del formulario.
string nextFieldName(const string[] existing) pure @safe {
  foreach (number; 1 .. 10_000) {
    string candidate = format("Signature%d", number);
    if (!existing.canFind(candidate)) return candidate;
  }
  throw new PdfException("El formulario ya tiene demasiados campos de firma");
}

/// El campo de firma no se puede poner donde ya hay una anotación.
class SignatureOverlapException : PdfException {
  mixin basicExceptionCtors;
}

/// Parámetros de una firma PAdES.
struct PadesSignatureParameters {
  /// Página (base 0) donde va el campo.
  int pageIndex;
  bool visible;
  VisibleSignature appearance;
  string reason;
  string location;
  string contactInfo;
  SysTime signingTime;
}

/**
 * Añade el campo de firma al PDF y devuelve el documento preparado con el resumen SHA-256
 * de los tramos que cubrirá la firma.
 *
 * Throws: SignatureOverlapException si el campo visible se superpone con una anotación;
 * PdfException si el PDF no admite la firma.
 */
PreparedSignature preparePadesSignature(immutable(ubyte)[] pdf, const PadesSignatureParameters parameters,
    size_t contentsSize = padesSignatureContentSize) @trusted {
  auto document = PdfDocument.open(pdf);
  scope (exit) document.close();
  SignatureDictionaryPlan plan;
  plan.contentsSize = contentsSize;
  plan.signingDate = toPdfDate(parameters.signingTime);
  plan.reason = parameters.reason;
  plan.location = parameters.location;
  plan.contactInfo = parameters.contactInfo;
  plan.appName = appName;
  auto field = fieldPlan(document, parameters.pageIndex, parameters.visible, parameters.appearance);
  if (field.visible && overlapsAnnotation(document.annotations(), parameters.pageIndex, field.rect)) {
    throw new SignatureOverlapException("The new signature field position overlaps with an existing annotation!");
  }
  return appendSignatureField(document, plan, field);
}

/**
 * Campo nuevo de firma o de sello en la página: invisible, o con la apariencia dada
 * (diseño, contenido, fuente e imagen).
 */
private FieldPlan fieldPlan(PdfDocument document, int pageIndex, bool visible, const VisibleSignature appearance)
    @trusted {
  FieldPlan field;
  field.fieldName = nextFieldName(document.fieldNames());
  field.pageIndex = pageIndex;
  field.rect = PdfRect(0, 0, 0, 0);
  if (!visible) return field;
  auto input = layoutInput(appearance, document.pageGeometry(pageIndex));
  auto encode = encoderFor(appearance);
  auto layout = computeLayout(input, encode);
  auto content = appearanceContent(layout, input, encode, "F1", "Img1");
  field.visible = true;
  field.rect = layout.annotationRect;
  field.appearance.width = layout.annotationRect.width;
  field.appearance.height = layout.annotationRect.height;
  field.appearance.content = content.content;
  if (appearance.text.length) {
    field.appearance.standardFont = appearance.font.standardName;
    field.appearance.customFont = appearance.font.trueType;
  }
  field.appearance.image = appearance.image;
  field.appearance.alphaNames = content.alphaNames;
  field.appearance.alphaValues = content.alphaValues;
  return field;
}

/// Resumen SHA-256 de los tramos del documento preparado que cubre la firma.
ubyte[] preparedDigest(const PreparedSignature prepared) pure @safe {
  auto finalRange = withByteRange(prepared);
  return digestOfParts(DigestAlgorithm.sha256, signedRanges(finalRange, byteRangeFor(prepared)));
}

/// Atributos firmados de la firma PAdES (sin signing-time: la fecha va en /M).
ubyte[] padesSignedAttributes(const(ubyte)[] documentDigest, const Certificate signingCertificate) pure @safe {
  SignedAttributesInput input = {
    contentDigest: documentDigest,
    signingCertificate: signingCertificate,
    includeSigningTime: false,
  };
  return buildSignedAttributes(input);
}

/// CMS de la firma, con el sello de la firma si se pasa (nivel T).
ubyte[] padesCms(const(ubyte)[] signedAttributes, const(ubyte)[] signatureValue, bool rsa,
    const Certificate signingCertificate, const(Certificate)[] chain, const(ubyte)[] signatureTimestamp) pure @safe {
  const(Certificate)[] certificates = [signingCertificate];
  foreach (certificate; chain) {
    if (!certificate.isSelfIssued && !containsCertificate(certificates, certificate)) certificates ~= certificate;
  }
  SignedDataInput input = {
    rsa: rsa,
    signingCertificate: signingCertificate,
    certificates: certificates,
    signedAttributes: signedAttributes,
    signature: signatureValue,
  };
  if (signatureTimestamp.length) input.unsignedAttributes = [cmsAttribute(oidSignatureTimeStampToken, signatureTimestamp)];
  return buildSignedData(input);
}

/// PDF con la firma escrita en su /Contents.
immutable(ubyte)[] completePadesSignature(const PreparedSignature prepared, const(ubyte)[] cms) pure @safe {
  return withContents(withByteRange(prepared), prepared, cms);
}

/**
 * Lo que necesita el nivel LT del PDF: en `certificates`, los firmantes y las autoridades
 * de sellado de todas sus firmas y sellos (buscados también en `pool`); en las
 * revocaciones, las del DSS y las de las firmas. Es lo que recibe
 * validationData de firmador.signers.common. Las firmas ilegibles se omiten.
 *
 * Throws: Exception si el certificado de la autoridad de un sello no está en el sello ni en
 * `pool`.
 */
ValidationData padesSigningMaterial(immutable(ubyte)[] pdf, CertificatePool pool) @trusted {
  auto document = PdfDocument.open(pdf);
  scope (exit) document.close();
  ValidationData material;
  auto dss = document.dss();
  material.ocspResponses = dss.ocsps;
  material.crls = dss.crls;
  void add(Certificate certificate) {
    if (certificate !is null) material.addCertificate(certificate);
  }
  foreach (field; document.signatureFields()) {
    SignedData signedData;
    TimeStampToken[] timestamps;
    try {
      auto contents = trimContents(field.contents);
      signedData = parseSignedData(contents);
      foreach (signer; signedData.signerInfos) {
        foreach (attribute; signer.unsignedAttributesOf(oidSignatureTimeStampToken)) {
          timestamps ~= parseTimeStampToken(attribute.values[0].raw);
        }
      }
      if (signedData.eContentType == oidTstInfo) timestamps ~= parseTimeStampToken(contents);
    } catch (Exception exception) {
      warning("Se omite una firma ilegible del PDF (", field.fieldName, "): ", exception.msg);
      continue;
    }
    foreach (signer; signedData.signerInfos) add(findSignerCertificate(signedData, signer, pool));
    // Fuera del try: una autoridad que no se encuentra deja incompleto el nivel LT y se informa.
    foreach (timestamp; timestamps) material.addCertificate(timestampSignerCertificate(timestamp, pool));
    material.crls ~= signedData.crls;
    material.ocspResponses ~= signedData.ocspResponses;
  }
  return material;
}

/// Contenido de /Contents sin el relleno de ceros del final.
const(ubyte)[] trimContents(const(ubyte)[] contents) pure @safe {
  import firmador.asn1.der : parseDerElement;
  size_t consumed;
  parseDerElement(contents, consumed);
  return contents[0 .. consumed];
}

/// PDF con el diccionario DSS completado con los datos de validación dados (nivel LT).
immutable(ubyte)[] addPadesValidationData(immutable(ubyte)[] pdf, const ValidationData data) @trusted {
  auto document = PdfDocument.open(pdf);
  scope (exit) document.close();
  const(ubyte)[][] certificates;
  foreach (certificate; data.certificates) certificates ~= certificate.der;
  return appendDss(document, certificates, data.ocspResponses, data.crls);
}

/**
 * Añade un sello de tiempo de documento (/DocTimeStamp), invisible o con la apariencia
 * dada. `stamp` recibe el resumen SHA-256 de los tramos cubiertos y devuelve el sello.
 *
 * Throws: PdfException si el PDF no lo admite; lo que lance `stamp` si el servicio falla.
 */
immutable(ubyte)[] addDocumentTimestamp(immutable(ubyte)[] pdf, scope Timestamper stamp,
    bool visible = false, VisibleSignature appearance = VisibleSignature.init, int pageIndex = 0,
    size_t contentsSize = padesTimestampContentSize) @trusted {
  auto document = PdfDocument.open(pdf);
  scope (exit) document.close();
  SignatureDictionaryPlan plan;
  plan.documentTimestamp = true;
  plan.subFilter = "ETSI.RFC3161";
  plan.contentsSize = contentsSize;
  if (visible) plan.appName = appName;
  auto prepared = appendSignatureField(document, plan, fieldPlan(document, pageIndex, visible, appearance));
  auto token = stamp(preparedDigest(prepared));
  info("Sello de tiempo de documento añadido con fecha ", token.info.genTime.toISOExtString);
  return withContents(withByteRange(prepared), prepared, token.der);
}

/// Página de la firma según la configuración: positiva desde el principio; 0 o negativa desde el final.
int resolvePageNumber(int configured, int pages) pure nothrow @safe @nogc {
  if (configured > 0) return configured;
  if (configured == 0) return pages;
  if ((pages + 1) + configured <= 0) return pages;
  return (pages + 1) + configured;
}

/**
 * Origen corregido para una rotación explícita (appendVisibleSignature en la versión
 * Java): DSS reinterpreta el origen desde otra esquina según el ángulo, así que se invierte
 * esa fórmula para que la firma quede donde se arrastró.
 */
float[2] correctedOrigin(float originX, float originY, int degrees, float[2] naturalSize, float pageWidth,
    float pageHeight) pure nothrow @safe @nogc {
  float naturalWidth = naturalSize[0];
  float naturalHeight = naturalSize[1];
  switch (degrees) {
    case 90: return [originY, pageWidth - naturalHeight - originX];
    case 270: return [pageHeight - naturalWidth - originY, originX];
    case 180: return [pageWidth - naturalWidth - originX, pageHeight - naturalHeight - originY];
    default: return [originX, originY];
  }
}

@("should count pages from the end when the configured page is zero or negative")
unittest {
  assert(resolvePageNumber(2, 5) == 2);
  assert(resolvePageNumber(0, 5) == 5);
  assert(resolvePageNumber(-1, 5) == 5);
  assert(resolvePageNumber(-2, 5) == 4);
  assert(resolvePageNumber(-9, 5) == 5);
}

@("should detect overlapping annotations and choose unused field names")
unittest {
  PdfAnnotation existing;
  existing.pageIndex = 0;
  existing.rect = PdfRect(100, 100, 200, 150);
  assert(overlapsAnnotation([existing], 0, PdfRect(150, 120, 250, 170)));
  assert(!overlapsAnnotation([existing], 1, PdfRect(150, 120, 250, 170)));
  assert(!overlapsAnnotation([existing], 0, PdfRect(200, 100, 300, 150)));
  assert(nextFieldName(["Signature1", "Signature3"]) == "Signature2");
}

@("should produce a PAdES signature whose CMS covers the byte ranges when signing with a test key")
unittest {
  import firmador.crypto.openssl : makeTestIdentity, verifySignature, signatureAlgorithmFrom;
  auto identity = makeTestIdentity("Firmante PAdES", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  PadesSignatureParameters parameters;
  parameters.pageIndex = 0;
  parameters.visible = true;
  parameters.appearance.text = "Firmante PAdES\nPrueba de firma visible";
  parameters.appearance.originX = 198;
  parameters.appearance.originY = 0;
  parameters.reason = "Prueba";
  parameters.signingTime = Clock.currTime;
  auto pdf = cast(immutable(ubyte)[]) import("nonPreview.pdf");
  auto prepared = preparePadesSignature(pdf, parameters);
  auto digest = preparedDigest(prepared);
  auto attributes = padesSignedAttributes(digest, certificate);
  auto cms = padesCms(attributes, identity.key.sign(DigestAlgorithm.sha256, attributes), true, certificate, [], null);
  auto signed = completePadesSignature(prepared, cms);

  auto document = PdfDocument.open(signed);
  scope (exit) document.close();
  auto fields = document.signatureFields();
  assert(fields.length == 1 && fields[0].rect.width > 0);
  auto parsed = parseSignedData(trimContents(fields[0].contents));
  auto ranges = signedRanges(signed, fields[0].byteRange);
  assert(messageDigestOf(parsed.signerInfos[0]) == digestOfParts(DigestAlgorithm.sha256, ranges));
  auto algorithm = signatureAlgorithmFrom(parsed.signerInfos[0].signatureAlgorithm, DigestAlgorithm.sha256);
  assert(verifySignature(certificate.subjectPublicKeyInfoDer, algorithm,
    parsed.signerInfos[0].signedAttributesForSignature, parsed.signerInfos[0].signature));
  assert(document.render(0, 0.2).rgb.length > 0);
}
