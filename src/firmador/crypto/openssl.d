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
 * Operaciones criptográficas con OpenSSL (libcrypto, cabeceras en src/c/copenssl.c):
 * verificación de firmas RSA PKCS#1 v1.5, RSA-PSS y ECDSA, lectura de almacenes PKCS#12
 * y firma con su clave, PBKDF2 y AES-256-GCM. Los datos estructurados (certificados, CMS)
 * se interpretan en D (firmador.asn1, firmador.x509); aquí sólo entran y salen bytes.
 */
module firmador.crypto.openssl;

import core.stdc.string : strlen;
import std.exception : enforce;
import std.format : format;
import std.string : toStringz;

import copenssl;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.crypto.digest;
import firmador.x509.certificate : Certificate;

/// Error de OpenSSL con el detalle de su cola de errores.
class CryptoException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

private __gshared bool providersLoaded;

/**
 * Carga los proveedores default y legacy de OpenSSL 3. legacy hace falta para los
 * almacenes PKCS#12 antiguos (RC2-40); si no está instalado se sigue sin él.
 */
void loadOpenSslProviders() @trusted {
  if (providersLoaded) return;
  enforce!CryptoException(OSSL_PROVIDER_load(null, "default") !is null,
    "No se pudo cargar el proveedor «default» de OpenSSL: " ~ openSslErrors());
  if (OSSL_PROVIDER_load(null, "legacy") is null) {
    import std.logger : warning;
    warning("OpenSSL no tiene el proveedor «legacy»; no se podrán abrir almacenes PKCS#12 con cifrado antiguo: ",
      openSslErrors());
  }
  providersLoaded = true;
}

/// Texto de los errores pendientes de OpenSSL, que quedan vaciados.
string openSslErrors() @trusted {
  char[256] buffer;
  string text;
  ulong code;
  while ((code = ERR_get_error()) != 0) {
    ERR_error_string_n(code, buffer.ptr, buffer.length);
    if (text.length) text ~= "; ";
    text ~= buffer[0 .. strlen(buffer.ptr)].idup;
  }
  return text.length ? text : "sin detalle";
}

private EVP_MD* evpDigest(DigestAlgorithm algorithm) @trusted {
  // ImportC declara sin const los parámetros const de OpenSSL; los resúmenes son estáticos.
  final switch (algorithm) {
    case DigestAlgorithm.sha1: return cast(EVP_MD*) EVP_sha1();
    case DigestAlgorithm.sha224: return cast(EVP_MD*) EVP_sha224();
    case DigestAlgorithm.sha256: return cast(EVP_MD*) EVP_sha256();
    case DigestAlgorithm.sha384: return cast(EVP_MD*) EVP_sha384();
    case DigestAlgorithm.sha512: return cast(EVP_MD*) EVP_sha512();
  }
}

/// Algoritmo de firma de un AlgorithmIdentifier: tipo de clave, resumen y parámetros PSS.
struct SignatureAlgorithm {
  enum Kind { rsaPkcs1, rsaPss, ecdsa }
  Kind kind;
  DigestAlgorithm digest;
  DigestAlgorithm mgfDigest;
  int saltLength = 20;
}

/**
 * Interpreta el algoritmo de firma a partir de su OID y, para RSA-PSS, sus parámetros DER.
 * `digestHint` es el resumen del firmante en CMS, donde el OID puede ser rsaEncryption.
 *
 * Throws: CryptoException si el algoritmo no se admite.
 */
SignatureAlgorithm signatureAlgorithmFrom(string oid, const(ubyte)[] parametersDer, DigestAlgorithm digestHint)
    @safe {
  SignatureAlgorithm algorithm;
  switch (oid) {
    case oidRsaEncryption:
      algorithm.kind = SignatureAlgorithm.Kind.rsaPkcs1;
      algorithm.digest = digestHint;
      break;
    case oidSha1WithRsa: algorithm.digest = DigestAlgorithm.sha1; break;
    case oidSha256WithRsa: algorithm.digest = DigestAlgorithm.sha256; break;
    case oidSha384WithRsa: algorithm.digest = DigestAlgorithm.sha384; break;
    case oidSha512WithRsa: algorithm.digest = DigestAlgorithm.sha512; break;
    case oidEcdsaWithSha1: algorithm.kind = SignatureAlgorithm.Kind.ecdsa; algorithm.digest = DigestAlgorithm.sha1; break;
    case oidEcdsaWithSha256: algorithm.kind = SignatureAlgorithm.Kind.ecdsa; algorithm.digest = DigestAlgorithm.sha256; break;
    case oidEcdsaWithSha384: algorithm.kind = SignatureAlgorithm.Kind.ecdsa; algorithm.digest = DigestAlgorithm.sha384; break;
    case oidEcdsaWithSha512: algorithm.kind = SignatureAlgorithm.Kind.ecdsa; algorithm.digest = DigestAlgorithm.sha512; break;
    case oidEcPublicKey:
      algorithm.kind = SignatureAlgorithm.Kind.ecdsa;
      algorithm.digest = digestHint;
      break;
    case oidRsaPss:
      algorithm.kind = SignatureAlgorithm.Kind.rsaPss;
      algorithm.digest = DigestAlgorithm.sha1;
      algorithm.mgfDigest = DigestAlgorithm.sha1;
      if (parametersDer.length) {
        // RSASSA-PSS-params: hashAlgorithm [0], maskGenAlgorithm [1], saltLength [2]
        foreach (field; parseDer(parametersDer).children()) {
          if (field.isContext(0)) {
            algorithm.digest = digestFromOid(parseAlgorithmIdentifier(parseDer(field.content),
              "El resumen de RSA-PSS").oid);
          } else if (field.isContext(1)) {
            auto mgf = parseAlgorithmIdentifier(parseDer(field.content), "La función MGF de RSA-PSS");
            enforce!CryptoException(mgf.oid == oidMgf1, "RSA-PSS con una función MGF distinta de MGF1");
            enforce!CryptoException(mgf.parameters.length > 0, "RSA-PSS con MGF1 sin su algoritmo de resumen");
            algorithm.mgfDigest = digestFromOid(parseAlgorithmIdentifier(parseDer(mgf.parameters),
              "El resumen de MGF1").oid);
          } else if (field.isContext(2)) {
            algorithm.saltLength = cast(int) parseDer(field.content).smallIntegerValue;
          }
        }
      }
      break;
    default:
      throw new CryptoException(format("Algoritmo de firma no admitido: %s", oid));
  }
  return algorithm;
}

private EVP_PKEY* publicKeyFromSpki(const(ubyte)[] spkiDer) @trusted {
  const(ubyte)* cursor = spkiDer.ptr;
  EVP_PKEY* key = d2i_PUBKEY(null, &cursor, cast(long) spkiDer.length);
  enforce!CryptoException(key !is null, "No se pudo leer la clave pública: " ~ openSslErrors());
  return key;
}

/**
 * Verifica una firma sobre `data` con la clave pública (SubjectPublicKeyInfo DER). Las
 * firmas ECDSA van en DER; para las de XMLDSig y JWS, convertir antes con ecdsaRawToDer.
 * Devuelve false si la firma no corresponde.
 *
 * Throws: CryptoException si la clave o el algoritmo no se pueden usar.
 */
bool verifySignature(const(ubyte)[] spkiDer, SignatureAlgorithm algorithm, const(ubyte)[] data,
    const(ubyte)[] signature) @trusted {
  loadOpenSslProviders();
  EVP_PKEY* key = publicKeyFromSpki(spkiDer);
  scope (exit) EVP_PKEY_free(key);
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  enforce!CryptoException(context !is null, "OpenSSL no pudo crear el contexto de verificación");
  scope (exit) EVP_MD_CTX_free(context);
  EVP_PKEY_CTX* keyContext;
  enforce!CryptoException(EVP_DigestVerifyInit(context, &keyContext, evpDigest(algorithm.digest), null, key) == 1,
    "No se pudo iniciar la verificación: " ~ openSslErrors());
  if (algorithm.kind == SignatureAlgorithm.Kind.rsaPss) {
    enforce!CryptoException(EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PSS_PADDING) == 1
      && EVP_PKEY_CTX_set_rsa_mgf1_md(keyContext, evpDigest(algorithm.mgfDigest)) == 1
      && EVP_PKEY_CTX_set_rsa_pss_saltlen(keyContext, algorithm.saltLength) == 1,
      "No se pudieron fijar los parámetros RSA-PSS: " ~ openSslErrors());
  }
  int result = EVP_DigestVerify(context, signature.ptr, signature.length, data.ptr, data.length);
  if (result != 1) ERR_clear_error();
  return result == 1;
}

/**
 * Comprueba que `certificate` esté firmado por la clave de `issuer`.
 *
 * Throws: CryptoException si el algoritmo no se admite.
 */
bool isSignedBy(const Certificate certificate, const Certificate issuer) @safe {
  auto parameters = parseAlgorithmIdentifier(parseDer(certificate.signatureAlgorithmDer),
    "El algoritmo de firma del certificado").parameters;
  auto algorithm = signatureAlgorithmFrom(certificate.signatureAlgorithmOid, parameters, DigestAlgorithm.sha256);
  return verifySignature(issuer.subjectPublicKeyInfoDer, algorithm, certificate.tbsDer, certificate.signatureValue);
}

/**
 * Longitud en bytes de cada mitad r y s de una firma ECDSA con la clave pública dada
 * (la del orden de la curva: 32 en P-256, 66 en P-521).
 *
 * Throws: CryptoException si la clave no se puede leer.
 */
size_t ecdsaComponentLength(const(ubyte)[] spkiDer) @trusted {
  EVP_PKEY* key = publicKeyFromSpki(spkiDer);
  scope (exit) EVP_PKEY_free(key);
  int bits = EVP_PKEY_get_bits(key);
  enforce!CryptoException(bits > 0, "No se pudo leer el tamaño de la clave: " ~ openSslErrors());
  return (cast(size_t) bits + 7) / 8;
}

/// Firma ECDSA r||s (XMLDSig, JWS) a DER (CMS), con la longitud en bytes de cada mitad.
ubyte[] ecdsaRawToDer(const(ubyte)[] raw) pure @safe {
  enforce!CryptoException(raw.length > 0 && raw.length % 2 == 0, "Firma ECDSA con longitud impar");
  size_t half = raw.length / 2;
  return derSequence(derIntegerUnsigned(raw[0 .. half]), derIntegerUnsigned(raw[half .. $]));
}

/// Firma ECDSA DER a r||s con cada mitad de `componentLength` bytes.
ubyte[] ecdsaDerToRaw(const(ubyte)[] der, size_t componentLength) pure @safe {
  auto reader = parseDer(der).reader();
  const(ubyte)[] r = reader.next("r").content;
  const(ubyte)[] s = reader.next("s").content;
  ubyte[] pad(const(ubyte)[] value) {
    while (value.length > componentLength && value[0] == 0) value = value[1 .. $];
    enforce!CryptoException(value.length <= componentLength, "Componente ECDSA más largo que la curva");
    return new ubyte[componentLength - value.length] ~ value;
  }
  return pad(r) ~ pad(s);
}

/// Clave privada en memoria (de un almacén PKCS#12); se libera con dispose().
final class OpenSslPrivateKey {
  private EVP_PKEY* key;

  private this(EVP_PKEY* key) @safe {
    this.key = key;
  }

  ~this() @trusted {
    dispose();
  }

  /// Libera la clave; después no se puede usar.
  void dispose() @trusted {
    if (key !is null) {
      EVP_PKEY_free(key);
      key = null;
    }
  }

  /// La clave es RSA (si no, EC).
  bool isRsa() @trusted {
    enforce!CryptoException(key !is null, "La clave privada ya fue liberada");
    return EVP_PKEY_get_base_id(key) == NID_rsaEncryption;
  }

  /**
   * Firma `data` con RSA PKCS#1 v1.5 o ECDSA (DER) y el resumen dado.
   *
   * Throws: CryptoException si OpenSSL no puede firmar.
   */
  ubyte[] sign(DigestAlgorithm digest, const(ubyte)[] data) @trusted {
    enforce!CryptoException(key !is null, "La clave privada ya fue liberada");
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    enforce!CryptoException(context !is null, "OpenSSL no pudo crear el contexto de firma");
    scope (exit) EVP_MD_CTX_free(context);
    enforce!CryptoException(EVP_DigestSignInit(context, null, evpDigest(digest), null, key) == 1,
      "No se pudo iniciar la firma: " ~ openSslErrors());
    size_t length;
    enforce!CryptoException(EVP_DigestSign(context, null, &length, data.ptr, data.length) == 1,
      "No se pudo calcular el tamaño de la firma: " ~ openSslErrors());
    auto signature = new ubyte[length];
    enforce!CryptoException(EVP_DigestSign(context, signature.ptr, &length, data.ptr, data.length) == 1,
      "No se pudo firmar: " ~ openSslErrors());
    return signature[0 .. length];
  }
}

/// Contenido de un almacén PKCS#12: la clave, su certificado y los demás certificados.
struct Pkcs12Contents {
  OpenSslPrivateKey privateKey;
  immutable(ubyte)[] certificateDer;
  immutable(ubyte)[][] chainDer;
}

/// La contraseña de un almacén PKCS#12 no es la correcta.
class WrongPasswordException : CryptoException {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

private immutable(ubyte)[] certificateToDer(X509* certificate) @trusted {
  ubyte* buffer = null;
  int length = i2d_X509(certificate, &buffer);
  enforce!CryptoException(length > 0, "No se pudo codificar el certificado del almacén: " ~ openSslErrors());
  scope (exit) CRYPTO_free(buffer, __FILE__.ptr, __LINE__);
  return buffer[0 .. length].idup;
}

/**
 * Abre un almacén PKCS#12 con su contraseña.
 *
 * Throws: WrongPasswordException si la contraseña no es la correcta; CryptoException si
 * el archivo no es un PKCS#12 o no trae clave y certificado.
 */
Pkcs12Contents openPkcs12(const(ubyte)[] data, const(char)[] password) @trusted {
  loadOpenSslProviders();
  const(ubyte)* cursor = data.ptr;
  PKCS12* store = d2i_PKCS12(null, &cursor, cast(long) data.length);
  enforce!CryptoException(store !is null, "El archivo no es un almacén PKCS#12: " ~ openSslErrors());
  scope (exit) PKCS12_free(store);
  auto passwordBuffer = new char[password.length + 1];
  passwordBuffer[0 .. password.length] = password[];
  passwordBuffer[$ - 1] = '\0';
  scope (exit) passwordBuffer[] = '\0';
  if (PKCS12_verify_mac(store, passwordBuffer.ptr, cast(int) password.length) != 1) {
    string detail = openSslErrors();
    throw new WrongPasswordException("La contraseña del almacén PKCS#12 no es la correcta (" ~ detail ~ ")");
  }
  EVP_PKEY* key;
  X509* certificate;
  stack_st_X509* chain;
  enforce!CryptoException(PKCS12_parse(store, passwordBuffer.ptr, &key, &certificate, &chain) == 1,
    "No se pudo leer el almacén PKCS#12: " ~ openSslErrors());
  scope (exit) {
    if (certificate !is null) X509_free(certificate);
    if (chain !is null) OPENSSL_sk_pop_free(cast(OPENSSL_STACK*) chain, cast(OPENSSL_sk_freefunc) &X509_free);
  }
  if (key is null || certificate is null) {
    if (key !is null) EVP_PKEY_free(key);
    throw new CryptoException("El almacén PKCS#12 no contiene una clave privada con su certificado");
  }
  Pkcs12Contents contents;
  contents.privateKey = new OpenSslPrivateKey(key);
  contents.certificateDer = certificateToDer(certificate);
  if (chain !is null) {
    int count = OPENSSL_sk_num(cast(OPENSSL_STACK*) chain);
    foreach (index; 0 .. count) {
      auto element = cast(X509*) OPENSSL_sk_value(cast(OPENSSL_STACK*) chain, index);
      contents.chainDer ~= certificateToDer(element);
    }
  }
  return contents;
}

/**
 * Deriva una clave con PBKDF2-HMAC-SHA256.
 *
 * Throws: CryptoException si OpenSSL falla.
 */
ubyte[] pbkdf2Sha256(const(char)[] password, const(ubyte)[] salt, int iterations, size_t length) @trusted {
  auto key = new ubyte[length];
  enforce!CryptoException(PKCS5_PBKDF2_HMAC(password.ptr, cast(int) password.length, salt.ptr, cast(int) salt.length,
    iterations, evpDigest(DigestAlgorithm.sha256), cast(int) length, key.ptr) == 1, "PBKDF2 falló: " ~ openSslErrors());
  return key;
}

/// Longitud del nonce de AES-GCM.
enum size_t gcmNonceLength = 12;
/// Longitud de la etiqueta de autenticación de AES-GCM.
enum size_t gcmTagLength = 16;

/**
 * Cifra con AES-256-GCM: devuelve nonce || texto cifrado || etiqueta.
 *
 * Throws: CryptoException si la clave no tiene 32 bytes o OpenSSL falla.
 */
ubyte[] aesGcmEncrypt(const(ubyte)[] key, const(ubyte)[] nonce, const(ubyte)[] plaintext, const(ubyte)[] associated)
    @trusted {
  enforce!CryptoException(key.length == 32 && nonce.length == gcmNonceLength, "Clave o nonce de AES-GCM no válidos");
  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  enforce!CryptoException(context !is null, "OpenSSL no pudo crear el contexto de cifrado");
  scope (exit) EVP_CIPHER_CTX_free(context);
  enforce!CryptoException(EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), null, key.ptr, nonce.ptr) == 1,
    "No se pudo iniciar AES-GCM: " ~ openSslErrors());
  int length;
  if (associated.length) {
    enforce!CryptoException(EVP_EncryptUpdate(context, null, &length, associated.ptr, cast(int) associated.length) == 1,
      "AES-GCM falló con los datos asociados: " ~ openSslErrors());
  }
  auto output = new ubyte[plaintext.length + 16];
  int written = 0;
  if (plaintext.length) {
    enforce!CryptoException(EVP_EncryptUpdate(context, output.ptr, &length, plaintext.ptr, cast(int) plaintext.length) == 1,
      "AES-GCM falló al cifrar: " ~ openSslErrors());
    written = length;
  }
  enforce!CryptoException(EVP_EncryptFinal_ex(context, output.ptr + written, &length) == 1,
    "AES-GCM falló al terminar: " ~ openSslErrors());
  written += length;
  auto tag = new ubyte[gcmTagLength];
  enforce!CryptoException(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, cast(int) gcmTagLength, tag.ptr) == 1,
    "AES-GCM no entregó la etiqueta: " ~ openSslErrors());
  return nonce.dup ~ output[0 .. written] ~ tag;
}

/**
 * Descifra lo que produjo aesGcmEncrypt.
 *
 * Throws: CryptoException si los datos fueron alterados o la clave no es la correcta.
 */
ubyte[] aesGcmDecrypt(const(ubyte)[] key, const(ubyte)[] sealed, const(ubyte)[] associated) @trusted {
  enforce!CryptoException(key.length == 32 && sealed.length >= gcmNonceLength + gcmTagLength,
    "Datos cifrados con AES-GCM incompletos");
  const(ubyte)[] nonce = sealed[0 .. gcmNonceLength];
  const(ubyte)[] ciphertext = sealed[gcmNonceLength .. $ - gcmTagLength];
  auto tag = sealed[$ - gcmTagLength .. $].dup;
  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  enforce!CryptoException(context !is null, "OpenSSL no pudo crear el contexto de descifrado");
  scope (exit) EVP_CIPHER_CTX_free(context);
  enforce!CryptoException(EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), null, key.ptr, nonce.ptr) == 1,
    "No se pudo iniciar AES-GCM: " ~ openSslErrors());
  int length;
  if (associated.length) {
    enforce!CryptoException(EVP_DecryptUpdate(context, null, &length, associated.ptr, cast(int) associated.length) == 1,
      "AES-GCM falló con los datos asociados: " ~ openSslErrors());
  }
  auto output = new ubyte[ciphertext.length + 16];
  int written = 0;
  if (ciphertext.length) {
    enforce!CryptoException(EVP_DecryptUpdate(context, output.ptr, &length, ciphertext.ptr, cast(int) ciphertext.length) == 1,
      "AES-GCM falló al descifrar: " ~ openSslErrors());
    written = length;
  }
  enforce!CryptoException(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, cast(int) gcmTagLength, tag.ptr) == 1,
    "AES-GCM no aceptó la etiqueta: " ~ openSslErrors());
  if (EVP_DecryptFinal_ex(context, output.ptr + written, &length) != 1) {
    ERR_clear_error();
    throw new CryptoException("Los datos cifrados fueron alterados o la clave no es la correcta");
  }
  written += length;
  return output[0 .. written];
}

version (unittest) {
  /// Genera una clave RSA de prueba y un certificado autofirmado con ella (sólo pruebas).
  struct TestIdentity {
    OpenSslPrivateKey key;
    immutable(ubyte)[] certificateDer;
    immutable(ubyte)[] pkcs12;
  }

  TestIdentity makeTestIdentity(string commonName, string password, bool nonRepudiation = true) @trusted {
    loadOpenSslProviders();
    EVP_PKEY* key = EVP_PKEY_Q_keygen(null, null, "RSA", cast(size_t) 2048);
    assert(key !is null, "No se pudo generar la clave RSA de prueba: " ~ openSslErrors());
    X509* certificate = X509_new();
    scope (exit) X509_free(certificate);
    X509_set_version(certificate, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(certificate), 4242);
    X509_gmtime_adj(X509_getm_notBefore(certificate), -3600);
    X509_gmtime_adj(X509_getm_notAfter(certificate), 3600L * 24 * 365);
    X509_set_pubkey(certificate, key);
    X509_NAME* name = X509_get_subject_name(certificate);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, cast(const(ubyte)*) "CR".ptr, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "serialNumber", MBSTRING_ASC, cast(const(ubyte)*) "CPF-01-0101-0101".ptr, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, cast(const(ubyte)*) commonName.toStringz, -1, -1, 0);
    X509_set_issuer_name(certificate, name);
    X509V3_CTX extensionContext;
    X509V3_set_ctx(&extensionContext, certificate, certificate, null, null, 0);
    string usage = nonRepudiation ? "critical,digitalSignature,nonRepudiation" : "critical,digitalSignature";
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(null, &extensionContext, NID_key_usage, usage.toStringz);
    X509_add_ext(certificate, extension, -1);
    X509_EXTENSION_free(extension);
    assert(X509_sign(certificate, key, evpDigest(DigestAlgorithm.sha256)) > 0, "No se pudo firmar el certificado de prueba");
    TestIdentity identity;
    identity.certificateDer = certificateToDer(certificate);
    PKCS12* store = PKCS12_create(password.toStringz, "prueba".ptr, key, certificate, null, 0, 0, 0, 0, 0);
    assert(store !is null, "No se pudo crear el PKCS#12 de prueba: " ~ openSslErrors());
    scope (exit) PKCS12_free(store);
    ubyte* buffer = null;
    int length = i2d_PKCS12(store, &buffer);
    identity.pkcs12 = buffer[0 .. length].idup;
    CRYPTO_free(buffer, __FILE__.ptr, __LINE__);
    identity.key = new OpenSslPrivateKey(key);
    return identity;
  }
}

@("should verify an RSA signature and reject a tampered one when checking with the certificate key")
unittest {
  import firmador.x509.certificate : parseCertificate;
  auto identity = makeTestIdentity("Firmante de Prueba", "clave");
  auto certificate = parseCertificate(identity.certificateDer);
  ubyte[] data = cast(ubyte[]) "datos a firmar".dup;
  auto signature = identity.key.sign(DigestAlgorithm.sha256, data);
  auto algorithm = signatureAlgorithmFrom(oidSha256WithRsa, null, DigestAlgorithm.sha256);
  assert(verifySignature(certificate.subjectPublicKeyInfoDer, algorithm, data, signature));
  data[0] ^= 1;
  assert(!verifySignature(certificate.subjectPublicKeyInfoDer, algorithm, data, signature));
  assert(isSignedBy(certificate, certificate));
}

@("should open a PKCS#12 store and tell a wrong password apart when reading it")
unittest {
  import std.exception : assertThrown;
  import firmador.x509.certificate : parseCertificate;
  auto identity = makeTestIdentity("Almacén", "correcta");
  auto contents = openPkcs12(identity.pkcs12, "correcta");
  assert(contents.certificateDer == identity.certificateDer);
  assert(contents.privateKey.isRsa);
  assertThrown!WrongPasswordException(openPkcs12(identity.pkcs12, "equivocada"));
  assertThrown!CryptoException(openPkcs12([1, 2, 3], "correcta"));
  assert(parseCertificate(contents.certificateDer).subject.readableName == "Almacén");
}

@("should decrypt what it encrypted and detect tampering when using AES-GCM")
unittest {
  import std.exception : assertThrown;
  import firmador.crypto.random : secureRandomBytes;
  auto key = secureRandomBytes(32);
  auto nonce = secureRandomBytes(gcmNonceLength);
  auto sealed = aesGcmEncrypt(key, nonce, cast(const(ubyte)[]) "token secreto", cast(const(ubyte)[]) "v1");
  assert(aesGcmDecrypt(key, sealed, cast(const(ubyte)[]) "v1") == cast(const(ubyte)[]) "token secreto");
  sealed[gcmNonceLength] ^= 1;
  assertThrown!CryptoException(aesGcmDecrypt(key, sealed, cast(const(ubyte)[]) "v1"));
}

@("should match the RFC 6070 style PBKDF2-HMAC-SHA256 vector when deriving keys")
unittest {
  import std.digest : toHexString, LetterCase;
  // Vector de RFC 7914 §11 para PBKDF2-HMAC-SHA256 ("passwd", "salt", 1 iteración, 64 bytes).
  auto derived = pbkdf2Sha256("passwd", cast(const(ubyte)[]) "salt", 1, 64);
  assert(toHexString!(LetterCase.lower)(derived)
    == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     ~ "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
}

@("should convert ECDSA signatures between DER and raw forms when round tripping")
unittest {
  ubyte[] raw = new ubyte[64];
  raw[0] = 0x80;
  raw[31] = 1;
  raw[63] = 2;
  auto der = ecdsaRawToDer(raw);
  assert(ecdsaDerToRaw(der, 32) == raw);
}
