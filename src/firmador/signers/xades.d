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
 * Firmador XAdES (FirmadorXAdES): firma XML dentro del documento (siempre en nivel B,
 * con la política de Hacienda si es un comprobante electrónico) o en un documento
 * separado en el nivel configurado, y extiende firmas XAdES a LTA. También da la subida
 * de nivel y la extensión que usan los contenedores ASiC y OpenDocument. La parte XML
 * está en firmador.xml.xades.
 */
module firmador.signers.xades;

import std.datetime.systime : Clock;
import std.exception : enforce;
import std.logger : info;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.crypto.digest;
import firmador.documents.mimetype : mimeTypeString;
import firmador.gui.guiinterface;
import firmador.settings;
import firmador.signers.common;
import firmador.signers.documentsigner;
import firmador.validation.certpath : ValidationData;
import firmador.validators.xmlvalidator : detachedResolver;
import firmador.xml.dom;
import firmador.xml.xades;
import firmador.xml.xmldsig : ExternalResolver;

/**
 * Firma XAdES: dentro del XML (`enveloped`, el caso normal) o en un documento aparte, como
 * cuando se elige XAdES en el diálogo de tipo de firma. Null si no se pudo (ya avisado).
 */
immutable(ubyte)[] signXades(GuiInterface gui, SigningServices services, const SigningInput input,
    CardSignInfo card, bool enveloped) @safe {
  auto documentSettings = documentSettingsOf(input);
  return signWithCard(gui, card, (SigningKey key) @safe {
    XadesParameters parameters;
    parameters.signingTime = Clock.currTime;
    parameters.signingCertificate = key.certificate;
    parameters.rsa = key.key.rsa;
    parameters.mimeType = mimeTypeString(input.mimeType);
    auto level = documentSettings.getXAdESLevel();
    if (enveloped) {
      // Como la versión Java: la firma dentro del XML queda en nivel B.
      parameters.packaging = XadesPackaging.enveloped;
      level = SignatureLevel.b;
      string root = xmlRootName(input.content);
      if (isElectronicReceipt(root)) {
        info("Comprobante electrónico ", root, ": se firma con la política de Hacienda");
        parameters.policy = haciendaPolicy();
      }
    } else {
      parameters.packaging = XadesPackaging.detached;
    }
    auto prepared = prepareXadesSignature(input.content, parameters);
    auto detachedContent = enveloped ? null : input.content;
    SignatureAssembly assembly;
    assembly.dataToSign = prepared.dataToSign;
    assembly.baseline = (const(ubyte)[] value) @safe => completeXadesSignature(prepared, value);
    assembly.upgraded = (const(ubyte)[] value) @safe => raiseXadesLevel(completeXadesSignature(prepared, value),
      prepared.signatureId, level, services, null, detachedContent);
    return assembly;
  });
}

/**
 * Extiende a LTA todas las firmas XAdES del documento (extendDocument de DSS con
 * XAdES_BASELINE_LTA). Una firma separada necesita el documento que firma.
 */
immutable(ubyte)[] extendXades(GuiInterface gui, SigningServices services, const ExtensionInput input) @safe {
  return extendReporting(gui, () @safe => extendXadesDocument(input.signed, services,
    detachedResolver(input.detached), input.singleDetached));
}

/**
 * Nombre local de la raíz de un XML.
 *
 * Throws: XmlException si no es XML bien formado.
 */
string xmlRootName(immutable(ubyte)[] xml) @trusted {
  auto parsed = XmlDocument.parse(xml);
  scope (exit) parsed.close();
  return parsed.root.localName;
}

/**
 * Sube la firma `signatureId` del XML desde B hasta `level` (raiseLevel): SignatureTimeStamp,
 * datos de validación y ArchiveTimeStamp. `resolver` y `detachedContent` resuelven las
 * referencias a archivos de la firma para el sello de archivo. `alreadyTimestamped` es
 * para extender a LTA una firma que ya tiene su sello de firma.
 */
immutable(ubyte)[] raiseXadesLevel(immutable(ubyte)[] xml, string signatureId, SignatureLevel level,
    SigningServices services, ExternalResolver resolver, immutable(ubyte)[] detachedContent,
    bool alreadyTimestamped = false) @safe {
  return raiseLevel(xml, level,
    (signed) => addSignatureTimestamp(signed, signatureId, services.timestamper),
    (signed) => withXadesValidationData(signed, signatureId, services),
    (signed) => addArchiveTimestamp(signed, signatureId, services.timestamper, resolver, detachedContent),
    alreadyTimestamped);
}

/// Añade los datos de validación del firmante y de los sellos de la firma (nivel LT).
private immutable(ubyte)[] withXadesValidationData(immutable(ubyte)[] xml, string signatureId,
    SigningServices services) @trusted {
  auto document = XmlDocument.parse(xml);
  ValidationData material;
  try {
    material = xadesSigningMaterial(signatureById(document, signatureId), services.pool);
  } finally {
    document.close();
  }
  return addXadesValidationData(xml, signatureId, services.validationData(material));
}

/**
 * Extiende a LTA todas las firmas XAdES del XML: sello de firma si falta, datos de
 * validación y sello de archivo.
 *
 * Throws: XmlException si no hay firmas XAdES o alguna no tiene Id; lo que fallen los servicios.
 */
immutable(ubyte)[] extendXadesDocument(immutable(ubyte)[] xml, SigningServices services, ExternalResolver resolver,
    immutable(ubyte)[] detachedContent) @trusted {
  immutable(ubyte)[] extended = xml;
  foreach (signatureId; xadesSignatureIds(extended)) {
    auto document = XmlDocument.parse(extended);
    bool timestamped;
    try {
      auto unsigned = unsignedSignatureProperties(signatureById(document, signatureId));
      timestamped = !unsigned.isNull && !unsigned.child(xadesNamespace, "SignatureTimeStamp").isNull;
    } finally {
      document.close();
    }
    extended = raiseXadesLevel(extended, signatureId, SignatureLevel.lta, services, resolver, detachedContent,
      timestamped);
  }
  info("Firmas XAdES extendidas a LTA");
  return extended;
}

/**
 * Ids de las firmas XAdES del documento que no están dentro de otra.
 *
 * Throws: XmlException si alguna no tiene Id (no se podría extender) o si no hay firmas.
 */
string[] xadesSignatureIds(immutable(ubyte)[] xml) @trusted {
  auto document = XmlDocument.parse(xml);
  scope (exit) document.close();
  string[] ids;
  foreach (signature; topLevelSignatures(document)) {
    if (qualifyingProperties(signature).isNull) continue;
    string id = signature.attribute("Id");
    enforce!XmlException(id.length, "Hay una firma XAdES sin atributo Id: no se puede extender");
    ids ~= id;
  }
  enforce!XmlException(ids.length, "El documento no tiene firmas XAdES que extender");
  return ids;
}
