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
 * Listas de revocación (CRL, RFC 5280 §5). Las de la jerarquía nacional son grandes, así
 * que las entradas no se interpretan todas: findRevocation las recorre buscando un serial.
 */
module firmador.x509.crl;

import std.bigint : BigInt;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.typecons : Nullable;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.x509.name;

/// CRL ya delimitada.
struct CertificateRevocationList {
  immutable(ubyte)[] der;
  immutable(ubyte)[] tbsDer;
  DistinguishedName issuer;
  SysTime thisUpdate;
  Nullable!SysTime nextUpdate;
  AlgorithmIdentifier signatureAlgorithm;
  immutable(ubyte)[] signature;
  /// Contenido del SEQUENCE de certificados revocados (vacío si no hay).
  immutable(ubyte)[] revokedContent;
  /// Extensión cRLNumber, si la tiene.
  Nullable!BigInt number;
}

/// Entrada de un certificado revocado.
struct RevokedEntry {
  SysTime revocationDate;
  int reason = -1;
}

/**
 * Interpreta una CRL DER.
 *
 * Throws: Asn1Exception si la estructura no es la de una CRL.
 */
CertificateRevocationList parseCrl(const(ubyte)[] der) pure @safe {
  CertificateRevocationList crl;
  crl.der = der.idup;
  auto reader = parseDer(der).reader();
  auto tbs = reader.next("TBSCertList");
  crl.tbsDer = tbs.raw.idup;
  crl.signatureAlgorithm = parseAlgorithmIdentifier(reader.next("el algoritmo de firma de la CRL"),
    "El algoritmo de firma de la CRL");
  crl.signature = reader.next("la firma de la CRL").bitStringBytes.idup;
  reader.finish("la CRL");

  auto tbsReader = tbs.reader();
  DerElement version_;
  tbsReader.nextUniversal(UniversalTag.integer, version_);
  tbsReader.next("el algoritmo de TBSCertList");
  crl.issuer = parseName(tbsReader.next("el emisor de la CRL"));
  crl.thisUpdate = tbsReader.next("thisUpdate").timeValue;
  if (!tbsReader.empty) {
    auto next = tbsReader.elements[tbsReader.position];
    if (next.isUniversal(UniversalTag.utcTime) || next.isUniversal(UniversalTag.generalizedTime)) {
      crl.nextUpdate = next.timeValue;
      tbsReader.position++;
    }
  }
  DerElement revoked;
  if (tbsReader.nextUniversal(UniversalTag.sequence, revoked)) crl.revokedContent = revoked.content.idup;
  DerElement extensions;
  if (tbsReader.nextContext(0, extensions)) {
    foreach (extension; parseDer(extensions.content).children()) {
      auto fields = extension.children();
      if (fields.length >= 2 && fields[0].oidValue == oidCrlNumber) {
        crl.number = parseDer(fields[$ - 1].octetStringValue).integerValue;
      }
    }
  }
  return crl;
}

/// Busca el serial entre los revocados.
bool findRevocation(const CertificateRevocationList crl, BigInt serial, out RevokedEntry entry) pure @safe {
  size_t position = 0;
  const(ubyte)[] content = crl.revokedContent;
  while (position < content.length) {
    size_t consumed;
    auto revokedEntry = parseDerElement(content[position .. $], consumed);
    position += consumed;
    auto reader = revokedEntry.reader();
    if (reader.next("el serial revocado").integerValue != serial) continue;
    entry.revocationDate = reader.next("la fecha de revocación").timeValue;
    DerElement extensions;
    if (reader.nextUniversal(UniversalTag.sequence, extensions)) {
      foreach (extension; extensions.children()) {
        auto extensionReader = extension.reader();
        if (extensionReader.next("el tipo de extensión").oidValue != oidCrlReason) continue;
        DerElement critical;
        extensionReader.nextUniversal(UniversalTag.boolean, critical);
        entry.reason = cast(int) parseDer(extensionReader.next("el motivo").octetStringValue).smallIntegerValue;
      }
    }
    return true;
  }
  return false;
}

@("should find a revoked serial and its reason when scanning a CRL")
unittest {
  import std.datetime.date : DateTime;
  import std.datetime.timezone : UTC;
  auto issuer = encodeName([[oidCountry, "CR"], [oidCommonName, "CA de prueba"]]);
  auto revokedDate = SysTime(DateTime(2026, 1, 2, 3, 4, 5), UTC());
  auto reasonExtension = derSequence(derOid(oidCrlReason), derOctetString(derTlv(0x0A, [1])));
  auto entries = derSequence(derSequence(derInteger(10), derUtcTime(revokedDate)),
    derSequence(derInteger(20), derUtcTime(revokedDate), derSequence(reasonExtension)));
  auto tbs = derSequence(derInteger(1), derAlgorithm(oidSha256WithRsa), issuer, derUtcTime(revokedDate),
    derUtcTime(revokedDate), entries);
  auto crl = parseCrl(derSequence(tbs, derAlgorithm(oidSha256WithRsa), derBitString([1, 2])));
  RevokedEntry entry;
  assert(findRevocation(crl, BigInt(20), entry) && entry.reason == 1 && entry.revocationDate == revokedDate);
  assert(findRevocation(crl, BigInt(10), entry) && entry.reason == -1);
  assert(!findRevocation(crl, BigInt(30), entry));
  assert(!crl.nextUpdate.isNull);
}
