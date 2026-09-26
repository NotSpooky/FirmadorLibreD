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
 * Almacenes PKCS#12 registrados: la información pública del titular que se lee una sola
 * vez al darlos de alta (con la contraseña) y se guarda en pkcs12cards.json, junto a
 * config.properties, para reconstruir la credencial en cada arranque sin volver a pedirla
 * (Pkcs12CardMetadata, Pkcs12CertificateReader y Pkcs12CredentialStore en la versión
 * Java; el formato del archivo es el mismo, @contract pkcs12-store-json). La contraseña
 * no se guarda nunca.
 */
module firmador.cards.pkcs12store;

import core.sync.mutex : Mutex;
import std.algorithm : canFind;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.file : exists, getSize, read, readText, timeLastModified;
import std.format : format;
import std.json : JSONValue, JSONType, parseJSON;
import std.logger : info, warning;
import std.path : absolutePath, buildNormalizedPath, buildPath, baseName;

import firmador.cards.cardinfo;
import firmador.crypto.openssl : openPkcs12;
import firmador.logging : withContext;
import firmador.settingsmanager : configDirectory, writeFileAtomically;
import firmador.util.json;
import firmador.x509.certificate;

/// Nombre del archivo, junto a config.properties.
enum string pkcs12StoreFileName = "pkcs12cards.json";
private enum int storeVersion = 1;

/// Información del titular de un almacén, guardada al registrarlo.
struct Pkcs12CardMetadata {
  /// Ruta absoluta normalizada del .p12; es la llave de la entrada.
  string path;
  /// Alias del que se leyó el certificado. Sólo informativo.
  string alias_;
  string identification;
  string firstName;
  string lastName;
  string commonName;
  string organization;
  /// yyyy-MM-dd, igual que en las tarjetas PKCS#11.
  string expires;
  /// Serial del certificado en decimal, el mismo que publica la API remota.
  string certSerialNumber;
  /// Certificado DER en base64.
  string certificate;
  /// Tamaño y fecha (ms desde 1970) del archivo al registrarlo, para avisar si cambió.
  long fileSize;
  long fileLastModified;
}

/// Ruta absoluta normalizada, la llave de las entradas del almacén.
string normalizeStorePath(string path) pure @safe {
  return buildNormalizedPath(absolutePath(path));
}

/// JSON de una entrada, sin los campos nulos (@JsonInclude(NON_NULL) en Java).
JSONValue metadataToJson(const Pkcs12CardMetadata meta) pure @safe {
  JSONValue json = JSONValue(string[string].init);
  void put(string key, string value) {
    if (value !is null) json[key] = value;
  }
  put("path", meta.path);
  put("alias", meta.alias_);
  put("identification", meta.identification);
  put("firstName", meta.firstName);
  put("lastName", meta.lastName);
  put("commonName", meta.commonName);
  put("organization", meta.organization);
  put("expires", meta.expires);
  put("certSerialNumber", meta.certSerialNumber);
  put("certificate", meta.certificate);
  json["fileSize"] = meta.fileSize;
  json["fileLastModified"] = meta.fileLastModified;
  return json;
}

/// Entrada a partir de su JSON; los campos desconocidos se ignoran (@JsonIgnoreProperties).
Pkcs12CardMetadata metadataFromJson(const JSONValue json) pure @safe {
  enum string what = "Una entrada de pkcs12cards.json";
  enforce(isObject(json), what ~ " no es un objeto");
  Pkcs12CardMetadata meta;
  string text(string key) {
    return optionalString(json, key, what);
  }
  long number(string key) {
    return optionalLong(json, key, 0, what);
  }
  meta.path = text("path");
  meta.alias_ = text("alias");
  meta.identification = text("identification");
  meta.firstName = text("firstName");
  meta.lastName = text("lastName");
  meta.commonName = text("commonName");
  meta.organization = text("organization");
  meta.expires = text("expires");
  meta.certSerialNumber = text("certSerialNumber");
  meta.certificate = text("certificate");
  meta.fileSize = number("fileSize");
  meta.fileLastModified = number("fileLastModified");
  return meta;
}

/// Texto del archivo con todas las entradas.
string storeToJsonText(const Pkcs12CardMetadata[] cards) @safe {
  JSONValue root;
  root["version"] = storeVersion;
  JSONValue[] list;
  foreach (card; cards) list ~= metadataToJson(card);
  root["cards"] = JSONValue(list);
  return root.toPrettyString();
}

/**
 * Entradas de un archivo; las que no tienen ruta se descartan.
 *
 * Throws: Exception si el texto no es el JSON esperado.
 */
Pkcs12CardMetadata[] storeFromJsonText(string text) pure @safe {
  auto root = parseJsonText(text, "pkcs12cards.json");
  enforce(isObject(root), "pkcs12cards.json no es un objeto JSON");
  Pkcs12CardMetadata[] cards;
  if (auto list = member(root, "cards")) {
    foreach (entry; arrayItems(*list, "El campo «cards» de pkcs12cards.json")) {
      if (entry.type == JSONType.null_) continue;
      auto meta = metadataFromJson(entry);
      if (meta.path is null) continue;
      cards ~= meta;
    }
  }
  return cards;
}

/// Registro de almacenes en pkcs12cards.json; se relee cuando cambia la fecha del archivo.
final class Pkcs12CredentialStore {
  private immutable string storeFile;
  private Pkcs12CardMetadata[string] cards;
  private string[] order;
  private bool loaded;
  private long loadedAt = -1;
  private Mutex lock;

  this(string storeFile) @safe {
    this.storeFile = storeFile;
    lock = new Mutex;
  }

  /// Registro del directorio de configuración, compartido por toda la aplicación.
  static Pkcs12CredentialStore instance() @trusted {
    __gshared Pkcs12CredentialStore shared_;
    synchronized {
      if (shared_ is null) {
        string file;
        try {
          file = buildPath(configDirectory(), pkcs12StoreFileName);
        } catch (Exception exception) {
          // Sin directorio de configuración no hay nada que guardar, pero el detector
          // necesita un registro: se usa una ruta que simplemente no existe.
          warning("No se pudo determinar el directorio de configuración para ", pkcs12StoreFileName, ": ",
            exception.msg);
          file = pkcs12StoreFileName;
        }
        shared_ = new Pkcs12CredentialStore(file);
      }
      return shared_;
    }
  }

  /// Entrada de la ruta, o null si no está registrada.
  Pkcs12CardMetadata* get(string path) @trusted {
    if (path is null) return null;
    lock.lock();
    scope (exit) lock.unlock();
    loadIfNeeded();
    if (auto entry = normalizeStorePath(path) in cards) {
      auto copy = new Pkcs12CardMetadata;
      *copy = *entry;
      return copy;
    }
    return null;
  }

  void put(Pkcs12CardMetadata meta) @trusted {
    if (meta.path is null) return;
    lock.lock();
    scope (exit) lock.unlock();
    loadIfNeeded();
    string key = normalizeStorePath(meta.path);
    meta.path = key;
    if (key !in cards) order ~= key;
    cards[key] = meta;
  }

  /// Deja sólo las rutas indicadas (al guardar la configuración, para no acumular almacenes quitados).
  void retainOnly(const string[] paths) @trusted {
    lock.lock();
    scope (exit) lock.unlock();
    loadIfNeeded();
    string[] keep;
    foreach (path; paths) if (path !is null) keep ~= normalizeStorePath(path);
    string[] kept;
    foreach (key; order) {
      if (keep.canFind(key)) kept ~= key;
      else cards.remove(key);
    }
    order = kept;
  }

  /**
   * Escribe el archivo pasando por un temporal: un corte a medias no puede dejar un JSON
   * truncado que borre la identidad de todos los almacenes.
   */
  void save() @trusted {
    lock.lock();
    scope (exit) lock.unlock();
    Pkcs12CardMetadata[] list;
    foreach (key; order) list ~= cards[key];
    withContext("No se pudo guardar " ~ storeFile, {
      writeFileAtomically(storeFile, storeToJsonText(list));
      loaded = true;
      loadedAt = lastModified();
      info("Almacenes PKCS#12 registrados guardados en ", storeFile);
    });
  }

  private void loadIfNeeded() @trusted {
    long modified = lastModified();
    if (loaded && modified == loadedAt) return;
    cards = null;
    order = null;
    loaded = true;
    loadedAt = modified;
    if (modified < 0) return;
    try {
      foreach (meta; storeFromJsonText(readText(storeFile))) {
        string key = normalizeStorePath(meta.path);
        meta.path = key;
        if (key !in cards) order ~= key;
        cards[key] = meta;
      }
    } catch (Exception exception) {
      // Un archivo ilegible no puede tumbar el detector ni el arranque: se sigue sin
      // identidad y el próximo save() lo reescribe.
      warning("No se pudo leer ", storeFile, ", se continuará sin la información guardada: ", exception.msg);
    }
  }

  private long lastModified() @trusted {
    try {
      if (!exists(storeFile)) return -1;
      return fileLastModifiedMillis(storeFile);
    } catch (Exception) {
      return -1;
    }
  }
}

/// Fecha de modificación de un archivo en milisegundos desde 1970, como File.lastModified().
long fileLastModifiedMillis(string path) @trusted {
  SysTime modified = timeLastModified(path);
  return modified.toUnixTime * 1000 + modified.fracSecs.total!"msecs";
}

/**
 * Abre un almacén con la contraseña que da el usuario al registrarlo y extrae lo necesario
 * para reconstruir la credencial sin volver a pedirla (Pkcs12CertificateReader.read).
 *
 * Throws: WrongPasswordException si la contraseña no es la correcta; Exception si el
 * almacén no trae una clave con certificado.
 */
Pkcs12CardMetadata readPkcs12Metadata(string path, const(char)[] password) @trusted {
  info("Leyendo el titular del almacén PKCS#12 ", path);
  auto contents = openPkcs12(cast(const(ubyte)[]) read(path), password);
  scope (exit) contents.privateKey.dispose();
  auto certificate = parseCertificate(contents.certificateDer);
  auto subject = certificateSubject(certificate);
  Pkcs12CardMetadata meta;
  meta.path = path;
  meta.alias_ = baseName(path);
  meta.identification = subject.identification;
  meta.firstName = subject.firstName;
  meta.lastName = subject.lastName;
  meta.commonName = subject.commonName;
  meta.organization = subject.organization;
  meta.expires = subject.expires;
  meta.certSerialNumber = certificate.serialDecimal;
  meta.certificate = certificate.base64;
  meta.fileSize = cast(long) getSize(path);
  meta.fileLastModified = fileLastModifiedMillis(path);
  return meta;
}

/**
 * Credencial de un almacén configurado: con la identidad registrada si la hay, o sólo con
 * la ruta (se puede firmar con él, pero sin identidad) si nunca se registró.
 */
CardSignInfo pkcs12Card(string path, const Pkcs12CardMetadata* meta) @safe {
  if (meta is null || meta.certificate is null) return new CardSignInfo(path, baseName(path));
  try {
    import std.base64 : Base64;
    auto certificate = parseCertificate(Base64.decode(meta.certificate));
    CertificateSubject subject;
    subject.identification = meta.identification;
    subject.firstName = meta.firstName;
    subject.lastName = meta.lastName;
    subject.commonName = meta.commonName;
    subject.organization = meta.organization;
    subject.expires = meta.expires;
    return new CardSignInfo(CardType.pkcs12, subject, path, -1, certificate);
  } catch (Exception exception) {
    warning("No se pudo reconstruir el certificado guardado de ", path, ", se usará sólo la ruta: ", exception.msg);
    return new CardSignInfo(path, baseName(path));
  }
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
}

@("should keep the Java file format when writing and reading the registered stores")
unittest {
  Pkcs12CardMetadata meta;
  meta.path = "/home/u/almacen.p12";
  meta.identification = "CPF-01-0101-0101";
  meta.certSerialNumber = "4242";
  meta.fileSize = 2048;
  meta.fileLastModified = 1_700_000_000_000;
  string text = storeToJsonText([meta]);
  auto root = parseJSON(text);
  assert(root["version"].integer == 1);
  assert("organization" !in root["cards"][0].object);
  auto back = storeFromJsonText(text);
  assert(back.length == 1 && back[0] == meta);
  assert(storeFromJsonText(`{"version":2,"cards":[{"path":null},{"path":"/x.p12","extra":1}]}`).length == 1);
}

@("should rebuild the identity of a registered store and fall back to the file name otherwise")
unittest {
  auto identity = makeTestIdentity("Titular Almacén", "clave");
  import std.base64 : Base64;
  Pkcs12CardMetadata meta;
  meta.path = "/a/almacen.p12";
  meta.identification = "CPF-01-0101-0101";
  meta.firstName = "TITULAR";
  meta.certificate = Base64.encode(identity.certificateDer);
  auto registered = pkcs12Card("/a/almacen.p12", &meta);
  assert(registered.certificate !is null && registered.identification == "CPF-01-0101-0101");
  auto unregistered = pkcs12Card("/a/otro.p12", null);
  assert(unregistered.certificate is null && unregistered.identification == "otro.p12");
}

@("should read the holder from a PKCS#12 file and keep the store in sync with the disk")
unittest {
  import std.file : tempDir, write, remove, mkdirRecurse, rmdirRecurse;
  string directory = buildPath(tempDir, "firmador-prueba-pkcs12");
  if (exists(directory)) rmdirRecurse(directory);
  mkdirRecurse(directory);
  scope (exit) rmdirRecurse(directory);
  auto identity = makeTestIdentity("Persona Registrada", "clave");
  string p12 = buildPath(directory, "persona.p12");
  write(p12, identity.pkcs12);
  auto meta = readPkcs12Metadata(p12, "clave");
  assert(meta.commonName == "Persona Registrada" && meta.certSerialNumber == "4242");
  auto store = new Pkcs12CredentialStore(buildPath(directory, pkcs12StoreFileName));
  store.put(meta);
  store.save();
  auto other = new Pkcs12CredentialStore(buildPath(directory, pkcs12StoreFileName));
  assert(other.get(p12) !is null && other.get(p12).commonName == "Persona Registrada");
  other.retainOnly([]);
  assert(other.get(p12) is null);
}
