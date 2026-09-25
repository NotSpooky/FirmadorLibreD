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
 * Firmador de un documento: su elección por tipo (DocumentSignerDetector), los formatos
 * que se pueden elegir a mano para cada tipo (SelectSignatureTypeDialog) y la firma y
 * extensión con el formato elegido, que llaman a firmador.signers.asic, cades, jades,
 * ooxml, pades y xades.
 */
module firmador.signers.detector;

import std.path : extension;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.documents.mimetype;
import firmador.gui.guiinterface;
import firmador.settings : Settings;
import firmador.signers.asic;
import firmador.signers.cades;
import firmador.signers.common : onlineSigningServices;
import firmador.signers.documentsigner;
import firmador.signers.jades;
import firmador.signers.ooxml;
import firmador.signers.pades;
import firmador.signers.xades;

/// Formatos de firma que se pueden elegir.
enum SignatureFormat { asic, pades, cades, xades, jades, openDocument, openXml }

/// Firmador de un documento: el formato y, en XAdES, si la firma va dentro del XML.
struct DocumentSigner {
  SignatureFormat format;
  /// XAdES dentro del XML (el caso normal); si no, en un documento aparte (elegido a mano).
  bool enveloped;
}

/// Firmador por omisión del tipo: CAdES si los ajustes lo fuerzan (forceCades).
DocumentSigner signerFor(const Settings settings, SupportedMimeType type) pure @safe {
  if (settings !is null && settings.forceCades) return DocumentSigner(SignatureFormat.cades);
  if (isPdf(type)) return DocumentSigner(SignatureFormat.pades);
  if (isOpenDocument(type)) return DocumentSigner(SignatureFormat.openDocument);
  if (isOpenXml(type)) return DocumentSigner(SignatureFormat.openXml);
  if (isXml(type)) return DocumentSigner(SignatureFormat.xades, true);
  if (isJson(type)) return DocumentSigner(SignatureFormat.jades);
  return DocumentSigner(SignatureFormat.asic);
}

/// Formatos que ofrece el diálogo de tipo de firma para el tipo de documento.
SignatureFormat[] selectableFormats(SupportedMimeType type) pure nothrow @safe {
  if (isPdf(type)) return [SignatureFormat.asic, SignatureFormat.pades];
  if (isOpenDocument(type)) return [SignatureFormat.asic, SignatureFormat.openDocument];
  if (isOpenXml(type)) return [SignatureFormat.openXml];
  if (isXml(type)) return [SignatureFormat.asic, SignatureFormat.xades, SignatureFormat.jades];
  return [SignatureFormat.asic, SignatureFormat.cades, SignatureFormat.jades];
}

/// Nombre del formato para la interfaz (PAdES, XAdES…).
string formatName(SignatureFormat format_) pure nothrow @safe @nogc {
  final switch (format_) {
    case SignatureFormat.asic: return "ASiC-E";
    case SignatureFormat.pades: return "PAdES";
    case SignatureFormat.cades: return "CAdES";
    case SignatureFormat.xades: return "XAdES";
    case SignatureFormat.jades: return "JAdES";
    case SignatureFormat.openDocument: return "OpenDocument";
    case SignatureFormat.openXml: return "OpenXML";
  }
}

/// Extensión (con punto) del archivo firmado a partir del nombre del original.
string signedExtension(DocumentSigner signer, string originalName) pure @safe {
  final switch (signer.format) {
    case SignatureFormat.asic: return ".asice";
    case SignatureFormat.pades: return ".pdf";
    case SignatureFormat.cades: return ".p7s";
    case SignatureFormat.xades: return ".xml";
    case SignatureFormat.jades: return ".json";
    case SignatureFormat.openDocument, SignatureFormat.openXml: return extension(originalName);
  }
}

/**
 * Firma el contenido con la credencial, con los servicios de sello y validación del BCCR.
 * Devuelve el documento firmado, o null si no se pudo; el motivo ya se le mostró al usuario.
 */
immutable(ubyte)[] sign(DocumentSigner signer, GuiInterface gui, const SigningInput input, CardSignInfo card) @safe {
  auto services = onlineSigningServices();
  final switch (signer.format) {
    case SignatureFormat.asic: return signAsic(gui, services, input, card);
    case SignatureFormat.pades: return signPades(gui, services, input, card);
    case SignatureFormat.cades: return signCades(gui, services, input, card);
    case SignatureFormat.xades: return signXades(gui, services, input, card, signer.enveloped);
    case SignatureFormat.jades: return signJades(gui, services, input, card);
    case SignatureFormat.openDocument: return signOpenDocument(gui, services, input, card);
    case SignatureFormat.openXml: return signOoxml(gui, services, input, card);
  }
}

/// Extiende la firma a LTA; null si no se pudo (también avisado).
immutable(ubyte)[] extend(DocumentSigner signer, GuiInterface gui, const ExtensionInput input) @safe {
  auto services = onlineSigningServices();
  final switch (signer.format) {
    case SignatureFormat.asic: return extendAsic(gui, services, input);
    case SignatureFormat.pades: return extendPades(gui, services, input);
    case SignatureFormat.cades: return extendCades(gui, services, input);
    case SignatureFormat.xades: return extendXades(gui, services, input);
    case SignatureFormat.jades: return extendJades(gui, services, input);
    case SignatureFormat.openDocument: return extendOpenDocument(gui, services, input);
    case SignatureFormat.openXml: return extendOoxml(gui, services, input);
  }
}
