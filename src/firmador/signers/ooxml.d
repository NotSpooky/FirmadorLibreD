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
 * Firmador de documentos OOXML (FirmadorOpenXmlFormat): firma de paquete de Office en
 * XAdES-X-L como la armaba Apache POI, o en XAdES-BES si no hay servicios de sello. Las
 * firmas OOXML no se extienden (la versión Java devolvía el documento igual). La
 * estructura está en firmador.ooxml.signature.
 */
module firmador.signers.ooxml;

import std.datetime.systime : Clock;
import std.logger : info;
import std.path : extension;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.cms.tsp : TimeStampToken;
import firmador.gui.guiinterface;
import firmador.ooxml.signature;
import firmador.signers.common;
import firmador.signers.documentsigner;
import firmador.util.zip;
import firmador.validation.certpath : ValidationData;
import firmador.validation.cmsverify : timestampSignerCertificate;
import firmador.x509.certificate;

/// Firmador OOXML.
final class OoxmlSigner : ServicedSigner {
  this(GuiInterface gui) @safe {
    super(gui);
  }

  string formatName() const @safe {
    return "OpenXML";
  }

  string signedExtension(string originalName) const @safe {
    return extension(originalName);
  }

  immutable(ubyte)[] sign(const SigningInput input, CardSignInfo card) @safe {
    return signWithCard(gui, card, (SigningKey key) @safe {
      auto entries = readZip(input.content);
      OoxmlParameters parameters;
      parameters.signingTime = Clock.currTime;
      parameters.signingCertificate = key.certificate;
      parameters.rsa = key.key.rsa;
      auto prepared = prepareOoxmlSignature(entries, parameters);
      auto signingTime = parameters.signingTime;
      auto certificate = key.certificate;
      immutable(ubyte)[] package_(immutable(ubyte)[] signatureXml) @safe {
        return writeZip(addSignaturePart(entries, signatureXml), signingTime);
      }
      SignatureAssembly assembly;
      assembly.dataToSign = prepared.dataToSign;
      assembly.baseline = (const(ubyte)[] value) @safe => package_(completeOoxmlSignature(prepared, value));
      assembly.upgraded = (const(ubyte)[] value) @safe {
        auto signatureXml = addOoxmlXlProperties(completeOoxmlSignature(prepared, value), revocationDataFor(certificate),
          &services.timestampDigest,
          (const TimeStampToken token) @safe => revocationDataFor(timestampSignerCertificate(token, services.pool)));
        info("Firma OOXML en nivel XAdES-X-L");
        return package_(signatureXml);
      };
      return assembly;
    });
  }

  /**
   * Cadena y revocación de un certificado con los servicios en línea (TimeStampServiceCR),
   * con la cadena sin él mismo, como la pide addOoxmlXlProperties.
   */
  private ValidationData revocationDataFor(Certificate certificate) @safe {
    auto data = services.validationData([certificate]);
    ValidationData revocation;
    foreach (chained; data.certificates) {
      if (!sameCertificate(chained, certificate)) revocation.certificates ~= chained;
    }
    revocation.crls = data.crls;
    revocation.ocspResponses = data.ocspResponses;
    return revocation;
  }

  /// Las firmas OOXML no se extienden: se devuelve el documento como está, como la versión Java.
  immutable(ubyte)[] extend(const ExtensionInput input) @safe {
    return input.signed;
  }
}
