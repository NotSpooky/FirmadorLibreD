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
 * Algoritmos de resumen (std.digest) y sus nombres en cada estándar: OID en ASN.1, URI en
 * XMLDSig, nombre corto en JOSE y el prefijo DigestInfo que firma RSA PKCS#1 v1.5.
 */
module firmador.crypto.digest;

import std.digest.sha : SHA1, SHA224, SHA256, SHA384, SHA512;
import std.exception : enforce;
import std.format : format;

import firmador.asn1.oids;

/// Algoritmos de resumen admitidos.
enum DigestAlgorithm { sha1, sha224, sha256, sha384, sha512 }

/// Resume `data` con el algoritmo dado.
ubyte[] digestOf(DigestAlgorithm algorithm, const(ubyte)[] data) pure @safe {
  return digestOfParts(algorithm, [data]);
}

/// Resume varias partes seguidas como si fueran una sola (rangos de bytes de un PDF, por ejemplo).
ubyte[] digestOfParts(DigestAlgorithm algorithm, const(ubyte[])[] parts) pure @safe {
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return runDigest!SHA1(parts);
    case DigestAlgorithm.sha224: return runDigest!SHA224(parts);
    case DigestAlgorithm.sha256: return runDigest!SHA256(parts);
    case DigestAlgorithm.sha384: return runDigest!SHA384(parts);
    case DigestAlgorithm.sha512: return runDigest!SHA512(parts);
  }
}

private ubyte[] runDigest(Hash)(const(ubyte[])[] parts) pure @safe {
  Hash hash;
  hash.start();
  foreach (part; parts) hash.put(part);
  return hash.finish()[].dup;
}

/// Longitud en bytes del resumen.
size_t digestLength(DigestAlgorithm algorithm) pure nothrow @safe @nogc {
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return 20;
    case DigestAlgorithm.sha224: return 28;
    case DigestAlgorithm.sha256: return 32;
    case DigestAlgorithm.sha384: return 48;
    case DigestAlgorithm.sha512: return 64;
  }
}

string digestOid(DigestAlgorithm algorithm) pure nothrow @safe @nogc {
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return oidSha1;
    case DigestAlgorithm.sha224: return oidSha224;
    case DigestAlgorithm.sha256: return oidSha256;
    case DigestAlgorithm.sha384: return oidSha384;
    case DigestAlgorithm.sha512: return oidSha512;
  }
}

/**
 * Algoritmo de un OID de resumen.
 *
 * Throws: Exception con el OID si no es uno admitido.
 */
DigestAlgorithm digestFromOid(string oid) pure @safe {
  switch (oid) {
    case oidSha1: return DigestAlgorithm.sha1;
    case oidSha224: return DigestAlgorithm.sha224;
    case oidSha256: return DigestAlgorithm.sha256;
    case oidSha384: return DigestAlgorithm.sha384;
    case oidSha512: return DigestAlgorithm.sha512;
    default: throw new Exception(format("Algoritmo de resumen no admitido: %s", oid));
  }
}

/// URI XMLDSig del algoritmo de resumen.
string digestXmlUri(DigestAlgorithm algorithm) pure nothrow @safe @nogc {
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return "http://www.w3.org/2000/09/xmldsig#sha1";
    case DigestAlgorithm.sha224: return "http://www.w3.org/2001/04/xmldsig-more#sha224";
    case DigestAlgorithm.sha256: return "http://www.w3.org/2001/04/xmlenc#sha256";
    case DigestAlgorithm.sha384: return "http://www.w3.org/2001/04/xmldsig-more#sha384";
    case DigestAlgorithm.sha512: return "http://www.w3.org/2001/04/xmlenc#sha512";
  }
}

/**
 * Algoritmo de un URI de resumen XMLDSig.
 *
 * Throws: Exception con el URI si no es uno admitido.
 */
DigestAlgorithm digestFromXmlUri(string uri) pure @safe {
  switch (uri) {
    case "http://www.w3.org/2000/09/xmldsig#sha1": return DigestAlgorithm.sha1;
    case "http://www.w3.org/2001/04/xmldsig-more#sha224": return DigestAlgorithm.sha224;
    case "http://www.w3.org/2001/04/xmlenc#sha256": return DigestAlgorithm.sha256;
    case "http://www.w3.org/2001/04/xmldsig-more#sha384": return DigestAlgorithm.sha384;
    case "http://www.w3.org/2001/04/xmlenc#sha512": return DigestAlgorithm.sha512;
    default: throw new Exception(format("Algoritmo de resumen XML no admitido: %s", uri));
  }
}

/// Nombre JOSE del resumen (S256…), el de las cabeceras x5t# y sigD de JAdES.
string digestJoseName(DigestAlgorithm algorithm) pure nothrow @safe @nogc {
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return "S1";
    case DigestAlgorithm.sha224: return "S224";
    case DigestAlgorithm.sha256: return "S256";
    case DigestAlgorithm.sha384: return "S384";
    case DigestAlgorithm.sha512: return "S512";
  }
}

/**
 * Resumen de un nombre JOSE (S256…) o, como también aceptan los validadores de JAdES, de
 * un URI de XMLDSig.
 *
 * Throws: Exception si el nombre no corresponde a un resumen admitido.
 */
DigestAlgorithm digestFromJoseName(string name) pure @safe {
  foreach (algorithm; [DigestAlgorithm.sha1, DigestAlgorithm.sha224, DigestAlgorithm.sha256, DigestAlgorithm.sha384,
      DigestAlgorithm.sha512]) {
    if (digestJoseName(algorithm) == name || digestXmlUri(algorithm) == name) return algorithm;
  }
  throw new Exception(format("Algoritmo de resumen JOSE no admitido: %s", name));
}

/// Nombre del resumen en DSS (SHA256…), el que aparece en los DTO remotos.
string digestDssName(DigestAlgorithm algorithm) pure nothrow @safe @nogc {
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return "SHA1";
    case DigestAlgorithm.sha224: return "SHA224";
    case DigestAlgorithm.sha256: return "SHA256";
    case DigestAlgorithm.sha384: return "SHA384";
    case DigestAlgorithm.sha512: return "SHA512";
  }
}

/// Prefijo DER de DigestInfo (RFC 8017 §9.2) que antecede al resumen en RSA PKCS#1 v1.5.
immutable(ubyte)[] digestInfoPrefix(DigestAlgorithm algorithm) pure nothrow @safe @nogc {
  static immutable ubyte[] sha1Prefix = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
    0x04, 0x14];
  static immutable ubyte[] sha224Prefix = [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c];
  static immutable ubyte[] sha256Prefix = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
  static immutable ubyte[] sha384Prefix = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30];
  static immutable ubyte[] sha512Prefix = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40];
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return sha1Prefix;
    case DigestAlgorithm.sha224: return sha224Prefix;
    case DigestAlgorithm.sha256: return sha256Prefix;
    case DigestAlgorithm.sha384: return sha384Prefix;
    case DigestAlgorithm.sha512: return sha512Prefix;
  }
}

@("should match the published SHA-256 test vector when hashing")
unittest {
  import std.digest : toHexString, LetterCase;
  assert(toHexString!(LetterCase.lower)(digestOf(DigestAlgorithm.sha256, cast(const(ubyte)[]) "abc"))
    == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert(digestOfParts(DigestAlgorithm.sha256, [cast(const(ubyte)[]) "a", cast(const(ubyte)[]) "bc"])
    == digestOf(DigestAlgorithm.sha256, cast(const(ubyte)[]) "abc"));
}

@("should build DigestInfo prefixes that parse as the matching AlgorithmIdentifier")
unittest {
  import firmador.asn1.der : parseDer;
  foreach (algorithm; [DigestAlgorithm.sha1, DigestAlgorithm.sha224, DigestAlgorithm.sha256, DigestAlgorithm.sha384,
      DigestAlgorithm.sha512]) {
    auto info = parseDer(digestInfoPrefix(algorithm) ~ digestOf(algorithm, [1, 2, 3]));
    auto children = info.children();
    assert(children[0].children()[0].oidValue == digestOid(algorithm));
    assert(children[1].content.length == digestLength(algorithm));
    assert(digestFromOid(digestOid(algorithm)) == algorithm);
    assert(digestFromXmlUri(digestXmlUri(algorithm)) == algorithm);
  }
}
