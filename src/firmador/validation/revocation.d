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
 * Verificación de la información de revocación: que una respuesta OCSP la firme el
 * emisor o un respondedor autorizado por él (RFC 6960 §4.2.2.2) y que una CRL la firme el
 * emisor, y que ambas se refieran al certificado. También la regla de frescura de
 * EN 319 102-1 §5.2.5.4 y la elección de la mejor información disponible.
 */
module firmador.validation.revocation;

import core.time : dur, Duration;
import std.algorithm : canFind;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;
import std.typecons : Nullable;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.cms.ocsp;
import firmador.crypto.digest;
import firmador.crypto.openssl;
import firmador.x509.certificate;
import firmador.x509.crl;

/// Información de revocación verificada para un certificado.
struct RevocationInfo {
  enum Kind { ocsp, crl }
  Kind kind;
  /// OCSPResponse o CRL DER, lo que se guarda en los datos de validación.
  immutable(ubyte)[] der;
  CertificateStatus status;
  SysTime revocationTime;
  int revocationReason = -1;
  /// producedAt (OCSP) o thisUpdate (CRL).
  SysTime productionTime;
  SysTime thisUpdate;
  Nullable!SysTime nextUpdate;
  /// Certificado que firmó la respuesta (el emisor o el respondedor delegado).
  Certificate signer;
  /// Certificados que venían con la respuesta OCSP.
  Certificate[] includedCertificates;
}

/**
 * Verifica una respuesta OCSP para `certificate` emitido por `issuer`. `candidates` son
 * los certificados donde buscar un respondedor delegado además de los incluidos.
 *
 * Throws: Exception con el motivo si la respuesta no es válida para ese certificado.
 */
RevocationInfo verifyOcsp(const OcspResponse response, const Certificate certificate, const Certificate issuer,
    const(Certificate)[] candidates) @trusted {
  auto single = response.responseFor(certificate, issuer);
  enforce(single !is null, "La respuesta OCSP no se refiere al certificado consultado");
  Certificate signer;
  const(Certificate)[] possible = cast(const(Certificate)[]) response.certificates ~ candidates ~ [issuer];
  foreach (candidate; possible) {
    if (!response.isResponder(candidate)) continue;
    auto algorithm = signatureAlgorithmFrom(response.signatureAlgorithm, DigestAlgorithm.sha256);
    if (!verifySignature(candidate.subjectPublicKeyInfoDer, algorithm, response.tbsResponseData, response.signature))
      continue;
    if (sameCertificate(candidate, issuer)) {
      signer = cast(Certificate) candidate;
      break;
    }
    // Respondedor delegado: emitido por el mismo emisor y con el uso id-kp-OCSPSigning.
    if (candidate.issuer.matches(issuer.subject) && candidate.extendedKeyUsages.canFind(oidEkuOcspSigning)
        && isSignedBy(candidate, issuer)) {
      signer = cast(Certificate) candidate;
      break;
    }
  }
  enforce(signer !is null, "La respuesta OCSP no está firmada por el emisor ni por un respondedor que él autorice");
  RevocationInfo info;
  info.kind = RevocationInfo.Kind.ocsp;
  info.der = response.der;
  info.status = single.status;
  info.revocationTime = single.revocationTime;
  info.revocationReason = single.revocationReason;
  info.productionTime = response.producedAt;
  info.thisUpdate = single.thisUpdate;
  info.nextUpdate = single.nextUpdate;
  info.signer = signer;
  info.includedCertificates = cast(Certificate[]) response.certificates;
  return info;
}

/**
 * Verifica una CRL para `certificate` emitido por `issuer` y busca el certificado en ella.
 *
 * Throws: Exception con el motivo si la CRL no es del emisor o su firma no es válida.
 */
RevocationInfo verifyCrl(const CertificateRevocationList crl, const Certificate certificate, const Certificate issuer)
    @trusted {
  enforce(crl.issuer.matches(certificate.issuer), "La CRL no es del emisor del certificado");
  auto algorithm = signatureAlgorithmFrom(crl.signatureAlgorithm, DigestAlgorithm.sha256);
  enforce(verifySignature(issuer.subjectPublicKeyInfoDer, algorithm, crl.tbsDer, crl.signature),
    "La firma de la CRL no es válida");
  RevocationInfo info;
  info.kind = RevocationInfo.Kind.crl;
  info.der = crl.der;
  info.productionTime = crl.thisUpdate;
  info.thisUpdate = crl.thisUpdate;
  info.nextUpdate = crl.nextUpdate;
  info.signer = cast(Certificate) issuer;
  RevokedEntry entry;
  if (findRevocation(crl, certificate.serialNumber, entry)) {
    info.status = CertificateStatus.revoked;
    info.revocationTime = entry.revocationDate;
    info.revocationReason = entry.reason;
  } else {
    info.status = CertificateStatus.good;
  }
  return info;
}

/// Frescura máxima para una respuesta OCSP que no indica nextUpdate.
enum Duration ocspFreshnessWithoutNextUpdate = dur!"hours"(24);

/**
 * La información es fresca en `validationTime` (EN 319 102-1 §5.2.5.4): emitida después
 * de validationTime menos su propio intervalo de actualización.
 */
bool isFresh(const RevocationInfo info, SysTime validationTime) pure @safe {
  if (info.thisUpdate > validationTime + dur!"minutes"(5)) return false;
  Duration window = info.nextUpdate.isNull ? ocspFreshnessWithoutNextUpdate : info.nextUpdate.get - info.thisUpdate;
  return info.productionTime >= validationTime - window;
}

/**
 * La información sirve como prueba de no revocación para una firma que existía en
 * `bestSignatureTime`: emitida después de esa fecha, o fresca ahora.
 */
bool isAcceptable(const RevocationInfo info, SysTime bestSignatureTime, SysTime validationTime) pure @safe {
  return info.productionTime >= bestSignatureTime || isFresh(info, validationTime);
}

/// La más reciente de varias informaciones (la de mayor fecha de producción).
Nullable!RevocationInfo latest(const(RevocationInfo)[] infos) pure @trusted {
  Nullable!RevocationInfo best;
  foreach (info; infos) {
    if (best.isNull || info.productionTime > best.get.productionTime) best = cast(RevocationInfo) info;
  }
  return best;
}

version (unittest) {
  import std.datetime.date : DateTime;
  import std.datetime.timezone : UTC;
}

@("should consider revocation fresh inside its own update window when checking freshness")
unittest {
  RevocationInfo info;
  info.thisUpdate = SysTime(DateTime(2026, 9, 20, 0, 0, 0), UTC());
  info.productionTime = info.thisUpdate;
  info.nextUpdate = SysTime(DateTime(2026, 9, 27, 0, 0, 0), UTC());
  assert(isFresh(info, SysTime(DateTime(2026, 9, 22, 0, 0, 0), UTC())));
  assert(!isFresh(info, SysTime(DateTime(2026, 9, 28, 0, 0, 0), UTC())));
  RevocationInfo ocspWithoutNext;
  ocspWithoutNext.thisUpdate = SysTime(DateTime(2026, 9, 22, 10, 0, 0), UTC());
  ocspWithoutNext.productionTime = ocspWithoutNext.thisUpdate;
  assert(isFresh(ocspWithoutNext, SysTime(DateTime(2026, 9, 22, 20, 0, 0), UTC())));
  assert(!isFresh(ocspWithoutNext, SysTime(DateTime(2026, 9, 24, 0, 0, 0), UTC())));
  // Para una firma sellada antes, una respuesta posterior al sello sigue siendo prueba.
  assert(isAcceptable(info, SysTime(DateTime(2026, 9, 19, 0, 0, 0), UTC()), SysTime(DateTime(2030, 1, 1, 0, 0, 0), UTC())));
}

@("should verify a CRL signed by the issuer and reject one from another issuer")
unittest {
  // CRL real del BCCR guardada en la prueba sería frágil: se arma una firmada con una clave de prueba.
  import firmador.crypto.openssl : makeTestIdentity;
  import firmador.x509.name : encodeName;
  auto issuerIdentity = makeTestIdentity("Emisor de prueba", "x");
  auto issuer = parseCertificate(issuerIdentity.certificateDer);
  auto other = parseCertificate(makeTestIdentity("Otro emisor", "x").certificateDer);
  auto time = SysTime(DateTime(2026, 9, 1, 0, 0, 0), UTC());
  auto entries = derSequence(derSequence(issuer.serialNumberDer, derUtcTime(time)));
  auto tbs = derSequence(derInteger(1), derAlgorithm(oidSha256WithRsa), issuer.subject.der, derUtcTime(time),
    derUtcTime(time + dur!"days"(7)), entries);
  auto signature = issuerIdentity.key.sign(DigestAlgorithm.sha256, tbs);
  auto crl = parseCrl(derSequence(tbs, derAlgorithm(oidSha256WithRsa), derBitString(signature)));
  auto info = verifyCrl(crl, issuer, issuer);
  assert(info.status == CertificateStatus.revoked && info.revocationTime == time);
  import std.exception : assertThrown;
  assertThrown(verifyCrl(crl, issuer, other));
}
