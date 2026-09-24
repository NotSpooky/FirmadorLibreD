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
 * Almacén cifrado de los tokens de sesión de las conexiones externas (KeystoreManager
 * en la versión Java, que usaba keystore.p12): tokens de acceso, de renovación, de
 * identidad y el identificador del firmador que asigna cada servicio, bajo el alias
 * «identificación + servicio».
 *
 * tokens.store en el directorio de configuración: «FLTS», versión 1, sal de 16 bytes y
 * el JSON {alias.tipo: token} cifrado con AES-256-GCM (nonce y etiqueta incluidos, la
 * cabecera como datos asociados). La clave sale de PBKDF2-SHA256 sobre la contraseña del
 * almacén, que guarda el llavero del sistema o config.properties (ver
 * firmador.settingsmanager y firmador.connections.passwordprovider).
 */
module firmador.connections.tokenstore;

import core.sync.mutex : Mutex;
import std.datetime.systime : Clock;
import std.exception : enforce;
import std.file : exists, read, rename;
import std.format : format;
import std.json : JSONValue, toJSON;
import std.logger : error, info, warning;
import std.path : buildPath;

import firmador.crypto.openssl : aesGcmDecrypt, aesGcmEncrypt, CryptoException, gcmNonceLength, pbkdf2Sha256;
import firmador.crypto.random : secureRandomBytes;
import firmador.settingsmanager : configDirectory, currentSettings, writeFileAtomically;
import firmador.util.json;

/// Tipo de token guardado (el sufijo del alias en la versión Java).
enum TokenType : string {
  access = "access",
  refresh = "refresh",
  id = "id",
  firmadorId = "firmador_id",
}

/// Error del almacén de tokens (falta un token, archivo dañado o contraseña distinta).
class TokenStoreException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// Archivo del almacén dentro del directorio de configuración.
enum string tokenStoreFileName = "tokens.store";

private enum string storeMagic = "FLTS";
private enum ubyte storeVersion = 1;
private enum size_t saltLength = 16;
private enum size_t headerLength = storeMagic.length + 1 + saltLength;
/// La contraseña es aleatoria (generateKeyPassword); PBKDF2 protege además la que guarda config.properties.
private enum int kdfIterations = 100_000;

/// Alias de los tokens de una tarjeta en un servicio (identificación + servicio, como en Java).
string tokenAlias(string identification, string service) pure nothrow @safe {
  return identification ~ service;
}

/// Clave del mapa del almacén.
private string entryKey(string alias_, TokenType type) pure nothrow @safe {
  return alias_ ~ "." ~ type;
}

/**
 * Cifra las entradas con la sal y el nonce dados (en uso son aleatorios; recibirlos
 * permite comprobar el formato).
 *
 * Throws: CryptoException si OpenSSL falla.
 */
immutable(ubyte)[] sealTokenStore(const string[string] entries, const(char)[] password, const(ubyte)[] salt,
    const(ubyte)[] nonce) @safe {
  assert(salt.length == saltLength, format("La sal del almacén de tokens debe tener %d bytes, tiene %d", saltLength,
    salt.length));
  JSONValue json = JSONValue(string[string].init);
  foreach (key, value; entries) json[key] = value;
  ubyte[] header = cast(ubyte[]) storeMagic.dup ~ storeVersion ~ salt.dup;
  auto key = pbkdf2Sha256(password, salt, kdfIterations, 32);
  scope (exit) key[] = 0;
  auto plaintext = cast(ubyte[]) toJSON(json).dup;
  scope (exit) plaintext[] = 0;
  return (header ~ aesGcmEncrypt(key, nonce, plaintext, header)).idup;
}

/**
 * Descifra el almacén.
 *
 * Throws: TokenStoreException si el formato no es el esperado, el archivo fue alterado o
 * la contraseña no es la misma con que se cifró.
 */
string[string] openTokenStore(const(ubyte)[] sealed, const(char)[] password) @safe {
  enforce!TokenStoreException(sealed.length > headerLength && sealed[0 .. storeMagic.length] == storeMagic,
    "El almacén de tokens no tiene el formato esperado");
  enforce!TokenStoreException(sealed[storeMagic.length] == storeVersion,
    format("Versión %d del almacén de tokens no admitida", sealed[storeMagic.length]));
  const(ubyte)[] header = sealed[0 .. headerLength];
  auto key = pbkdf2Sha256(password, header[storeMagic.length + 1 .. $], kdfIterations, 32);
  scope (exit) key[] = 0;
  ubyte[] plaintext;
  try {
    plaintext = aesGcmDecrypt(key, sealed[headerLength .. $], header);
  } catch (CryptoException exception) {
    throw new TokenStoreException("No se pudo descifrar el almacén de tokens: la contraseña cambió o el archivo "
      ~ "está dañado (" ~ exception.msg ~ ")");
  }
  scope (exit) plaintext[] = 0;
  auto json = parseJsonText(cast(string) plaintext.idup, "El almacén de tokens");
  string[string] entries;
  foreach (key_; objectKeys(json, "El almacén de tokens")) entries[key_] = requiredString(json, key_, "El almacén de tokens");
  return entries;
}

/// Hay un token de ese tipo guardado para el alias en las entradas ya descifradas.
bool hasToken(const string[string] entries, string alias_, TokenType type) pure nothrow @safe {
  return (entryKey(alias_, type) in entries) !is null;
}

/**
 * Token de un alias en las entradas ya descifradas.
 *
 * Throws: TokenStoreException si no está (hay que volver a iniciar sesión).
 */
string tokenOf(const string[string] entries, string alias_, TokenType type) @safe {
  auto found = entryKey(alias_, type) in entries;
  enforce!TokenStoreException(found !is null, format("No hay un token «%s» guardado para %s; inicie sesión de nuevo",
    cast(string) type, alias_));
  return *found;
}

private __gshared Mutex storeLock;

shared static this() {
  storeLock = new Mutex;
}

/// Ruta del almacén.
string tokenStorePath() @safe {
  return buildPath(configDirectory(), tokenStoreFileName);
}

/// Contraseña del almacén (la del llavero o la de config.properties, ver readSettings).
private string storePassword() @safe {
  string password = currentSettings().keyPassword;
  enforce!TokenStoreException(password.length > 0, "No se pudo obtener la contraseña del almacén de tokens");
  return password;
}

/**
 * Lee y descifra todas las entradas (loadToken lee así los tres tokens de una petición
 * con una sola derivación de clave).
 *
 * Throws: TokenStoreException si no hay almacén o no se puede descifrar.
 */
string[string] readTokenStore() @trusted {
  storeLock.lock();
  scope (exit) storeLock.unlock();
  string path = tokenStorePath();
  enforce!TokenStoreException(exists(path), format("No existe el almacén de tokens en %s; inicie sesión en el servicio",
    path));
  info("Leyendo el almacén de tokens ", path);
  try {
    return openTokenStore(cast(const(ubyte)[]) read(path), storePassword());
  } catch (TokenStoreException exception) {
    error("No se pudo abrir el almacén de tokens ", path, ": ", exception.msg);
    throw exception;
  }
}

/**
 * Guarda un token (saveToken). Si el almacén existente no se puede descifrar con la
 * contraseña actual se aparta como tokens.store.backup.<milisegundos> y se empieza uno
 * nuevo, como hacía la versión Java con un keystore.p12 dañado.
 *
 * Throws: TokenStoreException o FileException si no se puede escribir.
 */
void saveToken(string alias_, TokenType type, string token) @trusted {
  enforce!TokenStoreException(token.length > 0, format("El servicio no entregó el token «%s» de %s",
    cast(string) type, alias_));
  storeLock.lock();
  scope (exit) storeLock.unlock();
  string path = tokenStorePath();
  string password = storePassword();
  string[string] entries;
  if (exists(path)) {
    try {
      entries = openTokenStore(cast(const(ubyte)[]) read(path), password);
    } catch (TokenStoreException exception) {
      string backup = format("%s.backup.%d", path, Clock.currTime.toUnixTime!long * 1000);
      error("El almacén de tokens no se puede abrir con la contraseña actual (", exception.msg,
        "); se aparta en ", backup, " y se crea uno nuevo");
      rename(path, backup);
    }
  }
  entries[entryKey(alias_, type)] = token;
  auto sealed = sealTokenStore(entries, password, secureRandomBytes(saltLength), secureRandomBytes(gcmNonceLength));
  writeFileAtomically(path, sealed);
  info("Token «", cast(string) type, "» de ", alias_, " guardado en ", path);
}

@("should decrypt the same entries when sealing and opening the token store")
unittest {
  auto salt = new ubyte[saltLength];
  auto nonce = new ubyte[gcmNonceLength];
  salt[] = 7;
  nonce[] = 9;
  string[string] entries = ["1234UCR.access": "acceso", "1234UCR.firmador_id": "abc"];
  auto sealed = sealTokenStore(entries, "contraseña", salt, nonce);
  assert(sealed[0 .. 4] == cast(const(ubyte)[]) "FLTS" && sealed[4] == 1);
  auto opened = openTokenStore(sealed, "contraseña");
  assert(opened == entries);
  assert(tokenOf(opened, tokenAlias("1234", "UCR"), TokenType.firmadorId) == "abc");
}

@("should refuse to open the store when the password differs or the header was altered")
unittest {
  import std.exception : assertThrown;
  auto salt = new ubyte[saltLength];
  auto nonce = new ubyte[gcmNonceLength];
  auto sealed = sealTokenStore(["a.access": "x"], "correcta", salt, nonce);
  assertThrown!TokenStoreException(openTokenStore(sealed, "otra"));
  auto altered = sealed.dup;
  altered[5] ^= 1;
  assertThrown!TokenStoreException(openTokenStore(altered, "correcta"));
  assertThrown!TokenStoreException(tokenOf(openTokenStore(sealed, "correcta"), "a", TokenType.refresh));
}

@("should never keep the tokens or the password in clear text when sealing the store")
unittest {
  import std.algorithm : canFind;
  auto salt = new ubyte[saltLength];
  auto nonce = new ubyte[gcmNonceLength];
  auto sealed = sealTokenStore(["alias.access": "token-secreto"], "clave-del-almacen", salt, nonce);
  assert(!(cast(string) sealed).canFind("token-secreto"));
  assert(!(cast(string) sealed).canFind("clave-del-almacen"));
  assert(!(cast(string) sealed).canFind("alias.access"));
}
