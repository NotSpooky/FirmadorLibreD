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
 * Firmador CAdES (FirmadorCAdES): firma separada de cualquier archivo en el nivel
 * configurado y extensión a LTA de firmas CAdES con el documento que firman. La parte CMS
 * está en firmador.cms.cades.
 */
module firmador.signers.cades;

import std.datetime.systime : Clock;
import std.exception : enforce;

import firmador.asn1.oids;
import firmador.cards.cardinfo : CardSignInfo;
import firmador.cms.cades;
import firmador.cms.signeddata;
import firmador.crypto.digest;
import firmador.gui.guiinterface;
import firmador.settings;
import firmador.signers.common;
import firmador.signers.documentsigner;

/// Firma CAdES separada del contenido en el nivel configurado; null si no se pudo (ya avisado).
immutable(ubyte)[] signCades(GuiInterface gui, SigningServices services, const SigningInput input,
    CardSignInfo card) @safe {
  auto documentSettings = documentSettingsOf(input);
  return signWithCard(gui, card, (SigningKey key) @safe {
    auto certificate = key.certificate;
    auto level = documentSettings.getCAdESLevel();
    bool rsa = key.key.rsa;
    auto attributes = cadesSignedAttributes(digestOf(DigestAlgorithm.sha256, input.content), certificate,
      Clock.currTime).idup;
    SignatureAssembly assembly;
    assembly.dataToSign = attributes;
    assembly.baseline = (const(ubyte)[] value) @safe => cadesCms(attributes, value, rsa, certificate, null).idup;
    assembly.upgraded = (const(ubyte)[] value) @safe => raiseCadesLevel(
      cadesCms(attributes, value, rsa, certificate, null).idup, input.content, level, services);
    return assembly;
  });
}

/**
 * Extiende la firma a LTA (extendDocument de DSS con CAdES_BASELINE_LTA). Una firma
 * separada necesita el documento que firma.
 */
immutable(ubyte)[] extendCades(GuiInterface gui, SigningServices services, const ExtensionInput input) @safe {
  return extendReporting(gui, () @safe {
    auto data = parseSignedData(input.signed);
    enforce(data.hasEContent || input.singleDetached !is null,
      "Para ampliar una firma CAdES separada hace falta el documento que firma");
    // El sello de firma sólo se añade a una firma de un firmante que no lo tenga.
    bool timestamped = data.signerInfos.length != 1
      || data.signerInfos[0].unsignedAttributesOf(oidSignatureTimeStampToken).length > 0;
    return raiseCadesLevel(input.signed, data.hasEContent ? null : input.singleDetached, SignatureLevel.lta, services,
      timestamped);
  });
}

/**
 * Sube una firma CAdES de nivel B hasta `level` (raiseLevel); `content` es el documento
 * que firma, si no va dentro. `alreadyTimestamped` es para extender a LTA una firma que ya
 * tiene su sello de firma.
 */
immutable(ubyte)[] raiseCadesLevel(immutable(ubyte)[] cms, const(ubyte)[] content, SignatureLevel level,
    SigningServices services, bool alreadyTimestamped = false) @safe {
  return raiseLevel(cms, level,
    (signed) => addCadesSignatureTimestamp(signed, services.timestamper),
    (signed) => addCadesValidationData(signed, services.validationData(cadesSigningMaterial(signed, services.pool))),
    (signed) => addCadesArchiveTimestamp(signed, content, services.timestamper),
    alreadyTimestamped);
}
