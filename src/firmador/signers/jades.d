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
import std.exception : enforce;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.documents.mimetype : mimeTypeString;
import firmador.gui.guiinterface;
import firmador.jose.jades;
import firmador.settings;
import firmador.settingsmanager : currentSettings;
import firmador.signers.common;
import firmador.signers.documentsigner;
import firmador.validation.cmsverify : findSignerCertificate;
import firmador.x509.certificate;

/// Firmador JAdES.
final class JadesSigner : DocumentSigner {
  private GuiInterface gui;
  private SigningServices services;

  this(GuiInterface gui, SigningServices services = null) @safe {
    this.gui = gui;
    this.services = services is null ? SigningServices.online() : services;
  }

  string formatName() const @safe {
    return "JAdES";
  }

  string signedExtension(string originalName) const @safe {
    return ".json";
  }

  immutable(ubyte)[] sign(const SigningInput input, CardSignInfo card) @trusted {
    auto documentSettings = input.settings is null ? currentSettings() : cast(Settings) input.settings;
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
      assembly.upgraded = (const(ubyte)[] value) @safe {
        auto signed = completeJadesSignature(prepared, value);
        if (level == SignatureLevel.b) return signed;
        signed = addJadesSignatureTimestamp(signed, 0, (digest) => services.timestampDigest(digest));
        if (level == SignatureLevel.t) return signed;
        signed = withJadesValidationData(signed, 0, services);
        if (level == SignatureLevel.lt) return signed;
        return addJadesArchiveTimestamp(signed, 0, (digest) => services.timestampDigest(digest));
      };
      return assembly;
    });
  }

  /**
   * Extiende a LTA todas las firmas del JWS (extendDocument de DSS con
   * JAdES_BASELINE_LTA): sigTst si falta, datos de validación y arcTst.
   */
  immutable(ubyte)[] extend(const ExtensionInput input) @trusted {
    return extendReporting(gui, () @trusted {
      immutable(ubyte)[] detachedContent = input.singleDetached;
      immutable(ubyte)[] extended = input.signed;
      auto count = parseJws(extended).signatures.length;
      foreach (index; 0 .. count) {
        bool timestamped = false;
        foreach (component; parseJws(extended).signatures[index].etsiU) if (component.name == "sigTst") timestamped = true;
        if (!timestamped) extended = addJadesSignatureTimestamp(extended, index, (digest) => services.timestampDigest(digest));
        extended = withJadesValidationData(extended, index, services);
        extended = addJadesArchiveTimestamp(extended, index, (digest) => services.timestampDigest(digest), detachedContent);
      }
      return extended;
    });
  }
}

/// Añade los datos de validación del firmante y de las autoridades de sellado (nivel LT).
private immutable(ubyte)[] withJadesValidationData(immutable(ubyte)[] document, size_t index,
    SigningServices services) @trusted {
  auto jws = parseJws(document);
  auto signature = jws.signatures[index];
  auto embedded = jadesEmbeddedData(signature);
  Certificate[] certificates;
  string thumbprint = optionalThumbprint(signature);
  foreach (certificate; embedded.certificates) {
    if (thumbprint is null || base64Url(certificate.digest(DigestAlgorithm.sha256)) == thumbprint) {
      certificates ~= certificate;
      break;
    }
  }
  enforce(certificates.length, "La firma JAdES no incluye su certificado de firma");
  foreach (component; signature.etsiU) {
    if (component.name != "sigTst" && component.name != "arcTst") continue;
    foreach (der; tstContainerTokens(component.value)) {
      auto token = parseTimeStampToken(der);
      auto tsa = findSignerCertificate(token.signedData, token.signedData.signerInfos[0], services.pool);
      if (tsa !is null && !containsCertificate(certificates, tsa)) certificates ~= tsa;
    }
  }
  auto data = services.validationData(certificates, embedded.ocspResponses, embedded.crls);
  return addJadesValidationData(document, index, data);
}

private string optionalThumbprint(const JwsSignature signature) @safe {
  import firmador.util.json : optionalString;
  return optionalString(signature.header, "x5t#S256", "La cabecera protegida");
}
