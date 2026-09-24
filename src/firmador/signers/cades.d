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
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.gui.guiinterface;
import firmador.settings;
import firmador.settingsmanager : currentSettings;
import firmador.signers.common;
import firmador.signers.documentsigner;
import firmador.validation.cmsverify : findSignerCertificate;
import firmador.x509.certificate;

/// Firmador CAdES.
final class CadesSigner : DocumentSigner {
  private GuiInterface gui;
  private SigningServices services;

  this(GuiInterface gui, SigningServices services = null) @safe {
    this.gui = gui;
    this.services = services is null ? SigningServices.online() : services;
  }

  string formatName() const @safe {
    return "CAdES";
  }

  string signedExtension(string originalName) const @safe {
    return ".p7s";
  }

  immutable(ubyte)[] sign(const SigningInput input, CardSignInfo card) @trusted {
    auto documentSettings = input.settings is null ? currentSettings() : cast(Settings) input.settings;
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
  immutable(ubyte)[] extend(const ExtensionInput input) @trusted {
    return extendReporting(gui, () @safe {
      auto data = parseSignedData(input.signed);
      enforce(data.hasEContent || input.singleDetached !is null,
        "Para ampliar una firma CAdES separada hace falta el documento que firma");
      immutable(ubyte)[] extended = input.signed;
      if (data.signerInfos.length == 1 && data.signerInfos[0].unsignedAttributesOf(oidSignatureTimeStampToken).length == 0) {
        extended = addCadesSignatureTimestamp(extended, (digest) => services.timestampDigest(digest));
      }
      extended = withCadesValidationData(extended, services);
      return addCadesArchiveTimestamp(extended, data.hasEContent ? null : input.singleDetached,
        (digest) => services.timestampDigest(digest));
    });
  }
}

/// Sube una firma CAdES de nivel B hasta `level`; `content` es el documento que firma.
immutable(ubyte)[] raiseCadesLevel(immutable(ubyte)[] cms, const(ubyte)[] content, SignatureLevel level,
    SigningServices services) @safe {
  if (level == SignatureLevel.b) return cms;
  auto signed = addCadesSignatureTimestamp(cms, (digest) => services.timestampDigest(digest));
  if (level == SignatureLevel.t) return signed;
  signed = withCadesValidationData(signed, services);
  if (level == SignatureLevel.lt) return signed;
  return addCadesArchiveTimestamp(signed, content, (digest) => services.timestampDigest(digest));
}

/// Añade los datos de validación del firmante y de las autoridades de sellado (nivel LT).
private immutable(ubyte)[] withCadesValidationData(immutable(ubyte)[] cms, SigningServices services) @safe {
  auto material = cadesSigningMaterial(cms, services);
  auto data = services.validationData(material.certificates, material.embeddedOcsp, material.embeddedCrls);
  return addCadesValidationData(cms, data);
}

/// Certificados cuya validación necesita una firma CMS y la revocación que ya incluye.
struct CadesSigningMaterial {
  Certificate[] certificates;
  immutable(ubyte)[][] embeddedOcsp;
  immutable(ubyte)[][] embeddedCrls;
}

/**
 * Firmante y autoridades de sellado de la firma (sellos de firma y de archivo).
 *
 * Throws: Exception si el certificado del firmante no está en la firma ni en la jerarquía.
 */
CadesSigningMaterial cadesSigningMaterial(immutable(ubyte)[] cms, SigningServices services) @trusted {
  auto data = parseSignedData(cms);
  CadesSigningMaterial material;
  material.embeddedOcsp = data.ocspResponses;
  material.embeddedCrls = data.crls;
  void add(Certificate certificate) {
    if (certificate !is null && !containsCertificate(material.certificates, certificate)) material.certificates ~= certificate;
  }
  foreach (signer; data.signerInfos) {
    auto certificate = findSignerCertificate(data, signer, services.pool);
    enforce(certificate !is null, "La firma no incluye el certificado de su firmante");
    add(certificate);
    foreach (oid; [oidSignatureTimeStampToken, oidArchiveTimestampV3]) {
      foreach (attribute; signer.unsignedAttributesOf(oid)) {
        auto token = parseTimeStampToken(attribute.values[0].raw);
        add(findSignerCertificate(token.signedData, token.signedData.signerInfos[0], services.pool));
      }
    }
  }
  return material;
}
