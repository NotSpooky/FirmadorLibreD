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
 * Firmador JAdES (FirmadorJAdES): firma envolvente en serialización JSON en el nivel
 * configurado y extensión a LTA de todas las firmas del JWS. La parte JOSE está en
 * firmador.jose.jades.
 */
module firmador.signers.jades;

import std.datetime.systime : Clock;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.documents.mimetype : mimeTypeString;
import firmador.gui.guiinterface;
import firmador.jose.jades;
import firmador.settings;
import firmador.signers.common;
import firmador.signers.documentsigner;

/// Firma JAdES envolvente en el nivel configurado; null si no se pudo (ya avisado).
immutable(ubyte)[] signJades(GuiInterface gui, SigningServices services, const SigningInput input,
    CardSignInfo card) @safe {
  auto documentSettings = documentSettingsOf(input);
  return signWithCard(gui, card, (SigningKey key) @safe {
    JadesParameters parameters;
    parameters.signingTime = Clock.currTime;
    parameters.signingCertificate = key.certificate;
    parameters.rsa = key.key.rsa;
    parameters.mimeType = mimeTypeString(input.mimeType);
    auto level = documentSettings.getJAdESLevel();
    auto prepared = prepareJadesSignature(input.content, parameters);
    SignatureAssembly assembly;
    assembly.dataToSign = prepared.dataToSign;
    assembly.baseline = (const(ubyte)[] value) @safe => completeJadesSignature(prepared, value);
    assembly.upgraded = (const(ubyte)[] value) @safe => raiseJadesLevel(completeJadesSignature(prepared, value), 0,
      level, services);
    return assembly;
  });
}

/**
 * Extiende a LTA todas las firmas del JWS (extendDocument de DSS con
 * JAdES_BASELINE_LTA): sigTst si falta, datos de validación y arcTst.
 */
immutable(ubyte)[] extendJades(GuiInterface gui, SigningServices services, const ExtensionInput input) @safe {
  return extendReporting(gui, () @safe {
    immutable(ubyte)[] detachedContent = input.singleDetached;
    immutable(ubyte)[] extended = input.signed;
    auto count = parseJws(extended).signatures.length;
    foreach (index; 0 .. count) {
      bool timestamped = false;
      foreach (component; parseJws(extended).signatures[index].etsiU) if (component.name == "sigTst") timestamped = true;
      extended = raiseJadesLevel(extended, index, SignatureLevel.lta, services, detachedContent, timestamped);
    }
    return extended;
  });
}

/**
 * Sube la firma `index` del JWS desde B hasta `level` (raiseLevel): sigTst, datos de
 * validación y arcTst. `detachedContent` es el documento de una firma separada;
 * `alreadyTimestamped`, para extender a LTA una firma que ya tiene su sigTst.
 */
private immutable(ubyte)[] raiseJadesLevel(immutable(ubyte)[] document, size_t index, SignatureLevel level,
    SigningServices services, immutable(ubyte)[] detachedContent = null, bool alreadyTimestamped = false) @safe {
  return raiseLevel(document, level,
    (signed) => addJadesSignatureTimestamp(signed, index, services.timestamper),
    (signed) => addJadesValidationData(signed, index,
      services.validationData(jadesSigningMaterial(parseJws(signed).signatures[index], services.pool))),
    (signed) => addJadesArchiveTimestamp(signed, index, services.timestamper, detachedContent),
    alreadyTimestamped);
}
