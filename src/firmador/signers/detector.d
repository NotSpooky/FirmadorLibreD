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
 * Elección del firmador por tipo de documento (DocumentSignerDetector) y los formatos
 * que se pueden elegir a mano para cada tipo (SelectSignatureTypeDialog).
 */
module firmador.signers.detector;

import firmador.documents.mimetype;
import firmador.gui.guiinterface;
import firmador.settings : Settings;
import firmador.signers.asic;
import firmador.signers.cades;
import firmador.signers.documentsigner;
import firmador.signers.jades;
import firmador.signers.ooxml;
import firmador.signers.pades;
import firmador.signers.xades;

/// Formatos de firma que se pueden elegir.
enum SignatureFormat { asic, pades, cades, xades, jades, openDocument, openXml }

/// Firmador por omisión del tipo: CAdES si los ajustes lo fuerzan (forceCades).
DocumentSigner signerFor(GuiInterface gui, const Settings settings, SupportedMimeType type) @safe {
  if (settings !is null && settings.forceCades) return new CadesSigner(gui);
  if (isPdf(type)) return new PadesSigner(gui);
  if (isOpenDocument(type)) return new OpenDocumentSigner(gui);
  if (isOpenXml(type)) return new OoxmlSigner(gui);
  if (isXml(type)) return new XadesSigner(gui, true);
  if (isJson(type)) return new JadesSigner(gui);
  return new AsicSigner(gui);
}

/// Formatos que ofrece el diálogo de tipo de firma para el tipo de documento.
SignatureFormat[] selectableFormats(SupportedMimeType type) pure nothrow @safe {
  if (isPdf(type)) return [SignatureFormat.asic, SignatureFormat.pades];
  if (isOpenDocument(type)) return [SignatureFormat.asic, SignatureFormat.openDocument];
  if (isOpenXml(type)) return [SignatureFormat.openXml];
  if (isXml(type)) return [SignatureFormat.asic, SignatureFormat.xades, SignatureFormat.jades];
  return [SignatureFormat.asic, SignatureFormat.cades, SignatureFormat.jades];
}

/// Nombre del formato en el diálogo.
string formatLabel(SignatureFormat format_) pure nothrow @safe @nogc {
  final switch (format_) {
    case SignatureFormat.asic: return "ASIC-E";
    case SignatureFormat.pades: return "PAdES";
    case SignatureFormat.cades: return "CAdES";
    case SignatureFormat.xades: return "XAdES";
    case SignatureFormat.jades: return "JAdES";
    case SignatureFormat.openDocument: return "OpenDocument";
    case SignatureFormat.openXml: return "OpenXML";
  }
}

/// Firmador del formato elegido; XAdES elegido a mano firma separado, como la versión Java.
DocumentSigner signerForFormat(GuiInterface gui, SignatureFormat format_) @safe {
  final switch (format_) {
    case SignatureFormat.asic: return new AsicSigner(gui);
    case SignatureFormat.pades: return new PadesSigner(gui);
    case SignatureFormat.cades: return new CadesSigner(gui);
    case SignatureFormat.xades: return new XadesSigner(gui, false);
    case SignatureFormat.jades: return new JadesSigner(gui);
    case SignatureFormat.openDocument: return new OpenDocumentSigner(gui);
    case SignatureFormat.openXml: return new OoxmlSigner(gui);
  }
}

/// Formato de un firmador, para marcarlo en el diálogo.
SignatureFormat formatOf(const DocumentSigner signer) pure @safe {
  if (cast(const PadesSigner) signer) return SignatureFormat.pades;
  if (cast(const XadesSigner) signer) return SignatureFormat.xades;
  if (cast(const CadesSigner) signer) return SignatureFormat.cades;
  if (cast(const JadesSigner) signer) return SignatureFormat.jades;
  if (cast(const OoxmlSigner) signer) return SignatureFormat.openXml;
  if (cast(const OpenDocumentSigner) signer) return SignatureFormat.openDocument;
  return SignatureFormat.asic;
}
