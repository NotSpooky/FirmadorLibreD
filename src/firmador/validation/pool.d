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
 * Conjunto de certificados conocidos para armar cadenas (CertificateSource de DSS): las
 * raíces de confianza y las intermedias de la jerarquía nacional incluidas en el
 * ejecutable (firmador.configuration), más los que traen las firmas y los que se
 * descargan por AIA. Sólo las raíces incluidas son de confianza.
 */
module firmador.validation.pool;

import firmador.configuration : trustedRootCertificates, adjunctCertificates;
import firmador.x509.certificate;

/// Certificados disponibles para armar cadenas, con cuáles son de confianza.
final class CertificatePool {
  private Certificate[] trusted;
  private Certificate[] known;

  /// Conjunto con las raíces y las intermedias de la jerarquía nacional.
  static CertificatePool withNationalHierarchy() @safe {
    auto pool = new CertificatePool;
    foreach (root; bundledCertificates!trustedRootCertificates()) pool.addTrusted(root);
    foreach (certificate; bundledCertificates!adjunctCertificates()) pool.add(certificate);
    return pool;
  }

  /// Añade una raíz de confianza.
  void addTrusted(Certificate certificate) pure @safe {
    if (!containsCertificate(trusted, certificate)) trusted ~= certificate;
    add(certificate);
  }

  /// Añade un certificado conocido (no de confianza por sí mismo).
  void add(Certificate certificate) pure @safe {
    if (!containsCertificate(known, certificate)) known ~= certificate;
  }

  void addAll(const(Certificate)[] certificates) pure @trusted {
    foreach (certificate; certificates) add(cast(Certificate) certificate);
  }

  bool isTrusted(const Certificate certificate) const pure @safe {
    return containsCertificate(trusted, certificate);
  }

  /// Candidatos a emisor: mismo nombre y, si ambos lo declaran, mismo identificador de clave.
  Certificate[] issuerCandidates(const Certificate certificate) pure @safe {
    Certificate[] candidates;
    foreach (candidate; known) {
      if (!candidate.subject.matches(certificate.issuer)) continue;
      if (certificate.authorityKeyIdentifier.length && candidate.subjectKeyIdentifier.length
          && certificate.authorityKeyIdentifier != candidate.subjectKeyIdentifier) continue;
      candidates ~= candidate;
    }
    return candidates;
  }

  /// Todos los certificados conocidos.
  const(Certificate)[] all() const pure @safe {
    return known;
  }
}

@("should trust only the bundled roots and find issuers by name and key identifier")
unittest {
  auto pool = CertificatePool.withNationalHierarchy();
  auto root = bundledCertificate!"certs/CA RAIZ NACIONAL - COSTA RICA v2.crt"();
  auto policy = bundledCertificate!"certs/CA POLITICA SELLADO DE TIEMPO - COSTA RICA v2(1).crt"();
  auto tsa = bundledCertificate!"certs/TSA SINPE v4.crt"();
  assert(pool.isTrusted(root));
  assert(!pool.isTrusted(policy));
  auto issuers = pool.issuerCandidates(tsa);
  assert(issuers.length == 1 && sameCertificate(issuers[0], policy));
  assert(containsCertificate(pool.issuerCandidates(policy), root));
}
