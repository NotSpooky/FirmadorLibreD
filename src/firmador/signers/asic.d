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
 * Firmadores de contenedores con XAdES: ASiC-E (FirmadorASiC: uno o varios documentos, o
 * una firma más en un contenedor existente, en nivel B con los elementos de EN 319 132) y
 * OpenDocument (FirmadorOpenDocument: META-INF/documentsignatures.xml en el nivel
 * configurado). Los dos extienden a LTA todas las firmas XAdES del contenedor. La
 * estructura del contenedor está en firmador.containers.asic.
 */
module firmador.signers.asic;

import std.datetime.systime : Clock, SysTime;
import std.exception : enforce;
import std.format : format;
import std.logger : info;
import std.path : extension;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.containers.asic;
import firmador.documents.mimetype : isAsic;
import firmador.gui.guiinterface;
import firmador.settings;
import firmador.signers.common;
import firmador.signers.documentsigner;
import firmador.signers.xades : extendXadesDocument, raiseXadesLevel;
import firmador.util.zip;
import firmador.xml.xades;

/// Contenedor ASiC-E que se firma: el recibido o uno nuevo con el documento y los adicionales.
private ContainerContent asicContainerFor(const SigningInput input) @safe {
  if (isAsic(input.mimeType) || (looksLikeZip(input.content) && classifyContainer(readZip(input.content)).mimeType
      == asicEMimeType)) {
    auto content = classifyContainer(readZip(input.content));
    enforce(content.mimeType == asicEMimeType, "Sólo se pueden añadir firmas a contenedores ASiC-E");
    enforce(content.signedDocuments.length, "El contenedor ASiC no tiene documentos que firmar");
    return content;
  }
  ZipEntry[] documents = [ZipEntry(input.name, input.content)];
  foreach (additional; input.additionalDocuments) documents ~= ZipEntry(additional.name, additional.content);
  return newAsicEContainer(documents);
}

/// Firmador ASiC-E con XAdES.
final class AsicSigner : ServicedSigner {
  this(GuiInterface gui) @safe {
    super(gui);
  }

  string formatName() const @safe {
    return "ASiC-E";
  }

  string signedExtension(string originalName) const @safe {
    return ".asice";
  }

  immutable(ubyte)[] sign(const SigningInput input, CardSignInfo card) @safe {
    return signWithCard(gui, card, (SigningKey key) @safe {
      auto content = asicContainerFor(input);
      auto certificate = key.certificate;
      XadesParameters parameters;
      parameters.signingTime = Clock.currTime;
      parameters.signingCertificate = certificate;
      parameters.keyInfoCertificates = [certificate] ~ services.intermediateChain(certificate);
      parameters.rsa = key.key.rsa;
      parameters.packaging = XadesPackaging.container;
      parameters.files = asicSignedFiles(content);
      parameters.en319132 = true;
      string[] existing;
      foreach (signature; content.signatureDocuments) existing ~= signature.name;
      string signatureName = nextSignatureName(asicXadesSignatureTemplate, existing);
      auto prepared = prepareXadesSignature(null, parameters, asicSignaturesRoot);
      SysTime signingTime = parameters.signingTime;
      SignatureAssembly assembly;
      assembly.dataToSign = prepared.dataToSign;
      // Como la versión Java, la firma del contenedor queda en nivel B.
      assembly.baseline = (const(ubyte)[] value) @safe {
        auto signed = withSignatureDocument(content, signatureName, completeXadesSignature(prepared, value));
        info("Firma añadida al contenedor ASiC-E como ", signatureName);
        return writeContainer(signed, signingTime);
      };
      return assembly;
    });
  }

  immutable(ubyte)[] extend(const ExtensionInput input) @safe {
    return extendReporting(gui, () @safe => extendContainer(input.signed, services));
  }
}

/// Firmador de documentos OpenDocument.
final class OpenDocumentSigner : ServicedSigner {
  this(GuiInterface gui) @safe {
    super(gui);
  }

  string formatName() const @safe {
    return "OpenDocument";
  }

  string signedExtension(string originalName) const @safe {
    return extension(originalName);
  }

  immutable(ubyte)[] sign(const SigningInput input, CardSignInfo card) @safe {
    auto documentSettings = documentSettingsOf(input);
    return signWithCard(gui, card, (SigningKey key) @safe {
      auto content = classifyContainer(readZip(input.content));
      enforce(content.isOpenDocument, "El archivo no es un documento OpenDocument");
      // Como DSS: con más de un archivo de firmas no se sabe en cuál añadir la nueva.
      enforce(content.signatureDocuments.length <= 1, format("El documento tiene %d archivos de firmas; no se sabe en "
        ~ "cuál añadir la nueva", content.signatureDocuments.length));
      immutable(ubyte)[] existing = content.signatureDocuments.length ? content.signatureDocuments[0].content : null;
      XadesParameters parameters;
      parameters.signingTime = Clock.currTime;
      parameters.signingCertificate = key.certificate;
      parameters.rsa = key.key.rsa;
      parameters.packaging = XadesPackaging.container;
      parameters.files = openDocumentSignedFiles(content);
      auto level = documentSettings.getXAdESLevel();
      auto prepared = prepareXadesSignature(existing, parameters, openDocumentSignaturesRoot);
      SysTime signingTime = parameters.signingTime;
      auto resolver = containerResolver(content);
      immutable(ubyte)[] assemble(immutable(ubyte)[] signatures) @safe {
        return writeContainer(withSignatureDocument(content, openDocumentSignaturesName, signatures), signingTime);
      }
      SignatureAssembly assembly;
      assembly.dataToSign = prepared.dataToSign;
      assembly.baseline = (const(ubyte)[] value) @safe => assemble(completeXadesSignature(prepared, value));
      assembly.upgraded = (const(ubyte)[] value) @safe => assemble(raiseXadesLevel(completeXadesSignature(prepared,
        value), prepared.signatureId, level, services, resolver, null));
      return assembly;
    });
  }

  immutable(ubyte)[] extend(const ExtensionInput input) @safe {
    return extendReporting(gui, () @safe => extendContainer(input.signed, services));
  }
}

/**
 * Extiende a LTA todas las firmas XAdES de un contenedor ASiC u OpenDocument
 * (ASiCWithXAdESService.extendDocument), con sus archivos como contenido firmado.
 *
 * Throws: Exception si no es un contenedor con firmas XAdES; lo que fallen los servicios.
 */
immutable(ubyte)[] extendContainer(immutable(ubyte)[] container, SigningServices services) @safe {
  auto content = classifyContainer(readZip(container));
  enforce(content.hasMimetype, "El archivo no es un contenedor ASiC ni OpenDocument");
  enforce(content.signatureDocuments.length, "El contenedor no tiene firmas XAdES que extender");
  auto resolver = containerResolver(content);
  foreach (ref signature; content.signatureDocuments) {
    signature.content = extendXadesDocument(signature.content, services, resolver, null);
  }
  return writeContainer(content, Clock.currTime);
}
