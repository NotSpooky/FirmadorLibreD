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
 * Dispositivos de firma (SignatureTokenConnection de DSS): la tarjeta por PKCS#11 y el
 * almacén PKCS#12. Entregan sus claves con el certificado y firman bytes; los formatos de
 * firma (firmador.signers) deciden qué se firma. El PIN se guarda en un SecretPin que se
 * borra de memoria al terminar.
 */
module firmador.tokens.token;

import core.stdc.config : c_ulong;
import std.exception : enforce;
import std.file : read;
import std.logger : info, trace, warning;
import std.sumtype : match, SumType;
import std.typecons : Nullable;

import firmador.asn1.oids : KeyUsageBit;
import firmador.crypto.digest;
import firmador.crypto.openssl;
import firmador.tokens.pkcs11;
import firmador.x509.certificate;

/// PIN o contraseña en memoria que se sobrescribe con ceros al destruirlo (PasswordProtection).
final class SecretPin {
  private char[] value;
  private bool destroyed;

  this(const(char)[] pin) pure @safe {
    value = pin.dup;
  }

  /// El PIN; falla si ya se destruyó.
  const(char)[] get() const pure @safe {
    enforce(!destroyed, "El PIN ya fue destruido");
    return value;
  }

  bool isEmpty() const pure @safe {
    return destroyed || value.length == 0;
  }

  /// Sobrescribe el PIN con ceros.
  void destroy() pure @safe {
    value[] = '\0';
    value = null;
    destroyed = true;
  }

  ~this() @safe {
    if (value !is null) value[] = '\0';
  }
}

/// Clave de firma del dispositivo con su certificado y, si lo trae, el resto de la cadena.
struct TokenKey {
  Certificate certificate;
  Certificate[] chain;
  bool rsa = true;
  package size_t index;
}

/// Dispositivo de firma abierto: la tarjeta (PKCS#11) o el almacén (PKCS#12).
alias SignatureToken = SumType!(Pkcs11SignatureToken, Pkcs12SignatureToken);

/// Claves disponibles.
TokenKey[] keys(SignatureToken token) pure @safe {
  return token.match!(opened => opened.keys());
}

/**
 * Firma `data` con la clave: RSA PKCS#1 v1.5, o ECDSA en DER.
 *
 * Throws: Exception si el dispositivo no firma.
 */
ubyte[] sign(SignatureToken token, const TokenKey key, DigestAlgorithm digest, const(ubyte)[] data) @safe {
  return token.match!(opened => opened.sign(key, digest, data));
}

/// Cierra el dispositivo, si se abrió; después no se puede usar.
void close(SignatureToken token) @safe {
  token.match!((opened) {
    if (opened !is null) opened.close();
  });
}

/**
 * Primera clave de no repudio, el criterio de CRSigner.getPrivateKey: las tarjetas de firma
 * digital de Costa Rica traen una sola. Null si ninguna tiene ese uso.
 */
Nullable!TokenKey selectNonRepudiationKey(TokenKey[] keys) pure @safe {
  foreach (key; keys) {
    if (key.certificate.hasKeyUsage(KeyUsageBit.nonRepudiation)) return Nullable!TokenKey(key);
  }
  return Nullable!TokenKey.init;
}

/// Tarjeta de firma por PKCS#11: una sesión con el usuario autenticado mientras esté abierta.
final class Pkcs11SignatureToken {
  private Pkcs11Module module_;
  private Pkcs11Session session;
  private SecretPin pin;
  private TokenCertificate[] tokenCertificates;
  private CK_OBJECT_HANDLE_t[] privateKeys;
  private TokenKey[] available;

  private alias CK_OBJECT_HANDLE_t = c_ulong;

  /**
   * Abre la tarjeta de la ranura (o la primera con tarjeta si `slot` es negativo) e inicia
   * sesión con el PIN.
   *
   * Throws: Pkcs11Exception (CKR_PIN_INCORRECT, CKR_TOKEN_NOT_RECOGNIZED…) o
   * Pkcs11LibraryException si la biblioteca no se puede usar.
   */
  this(string libraryPath, SecretPin pin, long slot) @trusted {
    this.pin = pin;
    module_ = Pkcs11Module.load(libraryPath);
    session = module_.openSession(module_.resolveSlot(slot));
    try {
      session.login(pin.get());
      foreach (tokenCertificate; session.certificates()) {
        Certificate certificate;
        try {
          certificate = parseCertificate(tokenCertificate.der);
        } catch (Exception exception) {
          warning("Se omite un certificado ilegible de la tarjeta (", tokenCertificate.label, "): ", exception.msg);
          continue;
        }
        CK_OBJECT_HANDLE_t privateKey;
        try {
          privateKey = session.privateKeyFor(tokenCertificate);
        } catch (Exception exception) {
          trace("El certificado «", tokenCertificate.label, "» no tiene clave privada: ", exception.msg);
          continue;
        }
        TokenKey key;
        key.certificate = certificate;
        key.rsa = session.isRsaKey(privateKey);
        key.index = available.length;
        available ~= key;
        tokenCertificates ~= tokenCertificate;
        privateKeys ~= privateKey;
      }
    } catch (Exception exception) {
      session.close();
      throw exception;
    }
  }

  TokenKey[] keys() pure @safe {
    return available.dup;
  }

  ubyte[] sign(const TokenKey key, DigestAlgorithm digest, const(ubyte)[] data) @trusted {
    enforce(key.index < privateKeys.length, "La clave no pertenece a esta tarjeta");
    ubyte[] signature = session.sign(privateKeys[key.index], digest, data, pin.get());
    if (!key.rsa) signature = ecdsaRawToDer(signature);
    return signature;
  }

  void close() @trusted {
    if (session is null) return;
    session.logout();
    session.close();
    session = null;
  }
}

/// Almacén PKCS#12 abierto con su contraseña.
final class Pkcs12SignatureToken {
  private Pkcs12Contents contents;
  private TokenKey key;

  /**
   * Abre el almacén.
   *
   * Throws: WrongPasswordException si la contraseña no es la correcta; Exception si el
   * archivo no existe o no es un PKCS#12 con clave.
   */
  this(string path, SecretPin password) @trusted {
    info("Abriendo el almacén PKCS#12 ", path);
    contents = openPkcs12(cast(const(ubyte)[]) read(path), password.get());
    key.certificate = parseCertificate(contents.certificateDer);
    foreach (der; contents.chainDer) key.chain ~= parseCertificate(der);
    key.rsa = contents.privateKey.isRsa;
    key.index = 0;
  }

  TokenKey[] keys() pure @safe {
    return [key];
  }

  ubyte[] sign(const TokenKey requested, DigestAlgorithm digest, const(ubyte)[] data) @trusted {
    enforce(requested.index == 0, "La clave no pertenece a este almacén");
    return contents.privateKey.sign(digest, data);
  }

  void close() @trusted {
    if (contents.privateKey !is null) {
      contents.privateKey.dispose();
      contents.privateKey = null;
    }
  }
}

@("should choose the first non repudiation key when a token offers several")
unittest {
  auto signing = makeTestIdentity("Firma", "x", true);
  auto authentication = makeTestIdentity("Autenticación", "x", false);
  TokenKey[] keys = [TokenKey(parseCertificate(authentication.certificateDer)),
    TokenKey(parseCertificate(signing.certificateDer))];
  auto chosen = selectNonRepudiationKey(keys);
  assert(!chosen.isNull && chosen.get.certificate.subject.readableName == "Firma");
  assert(selectNonRepudiationKey(keys[0 .. 1]).isNull);
}

@("should wipe the PIN when it is destroyed")
unittest {
  import std.exception : assertThrown;
  auto pin = new SecretPin("1234");
  assert(pin.get() == "1234");
  pin.destroy();
  assert(pin.isEmpty);
  assertThrown(pin.get());
}
