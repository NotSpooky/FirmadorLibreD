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
 * Lectura y escritura de la configuración (SettingsManager en la versión Java): el
 * directorio de configuración, config.properties, las configuraciones por documento
 * (docSettings/*.config) y la contraseña del almacén de tokens, que vive en el llavero
 * del sistema si lo hay (SecureCredentialStore, ver firmador.connections.passwordprovider)
 * y si no, ofuscada en config.properties. La conversión entre archivo y ajustes está en
 * firmador.settings.
 */
module firmador.settingsmanager;

import core.sync.mutex : Mutex;
import std.conv : to;
import std.datetime.systime : Clock;
import std.exception : enforce;
import std.file : exists, isDir, isFile, mkdirRecurse, readText, rename, write, remove;
import std.format : format;
import std.logger : error, info, warning;
import std.path : buildPath, dirName;
import std.process : environment;
import std.string : startsWith;

import firmador.configuration : configDirectoryName;
import firmador.crypto.random : secureRandomString;
import firmador.i18n : setMessagesLocale;
import firmador.logging : setLogLevel;
import firmador.settings;
import firmador.util.datetime : formatJavaDate, DateLanguage, costaRicaTimeZone;
import firmador.util.properties : parseProperties, formatProperties;

/// Llavero del sistema donde se guarda la contraseña del almacén de tokens.
interface SecureCredentialStore {
  /// El llavero está disponible y es seguro.
  bool isAvailable();
  /// Contraseña guardada, o null si no hay.
  string load();
  /// Guarda la contraseña; false si el llavero la rechazó.
  bool save(string password);
  /// Descripción del estado para las bitácoras (sin la contraseña).
  string storageInfo();
}

private __gshared SecureCredentialStore credentialStore;
private __gshared string overridePath;
private __gshared string[string] currentProperties;
private __gshared Settings cachedSettings;
private __gshared Mutex managerLock;

private enum string obfuscationPrefix = "OBF:";
private enum string keyPasswordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?";

shared static this() {
  managerLock = new Mutex;
}

/// Instala el llavero del sistema; sin él la contraseña se guarda ofuscada en config.properties.
void setSecureCredentialStore(SecureCredentialStore store) @trusted {
  credentialStore = store;
}

/// Llavero instalado (null si no hay).
SecureCredentialStore secureCredentialStore() @trusted {
  return credentialStore;
}

/**
 * Directorio de configuración (~/.config/firmadorlibre, %APPDATA%\firmadorlibre en
 * Windows), creado si falta y oculto en Windows.
 *
 * Throws: Exception si no se sabe cuál es el directorio personal o no se puede crear.
 */
string configDirectory() @trusted {
  version (Windows) {
    string base = environment.get("APPDATA");
    enforce(base.length, "No está definida la variable APPDATA para ubicar la configuración");
    string directory = buildPath(base, configDirectoryName);
  } else {
    string base = environment.get("HOME");
    enforce(base.length, "No está definida la variable HOME para ubicar la configuración");
    string directory = buildPath(base, ".config", configDirectoryName);
  }
  if (!exists(directory) || !isDir(directory)) {
    mkdirRecurse(directory);
    version (Windows) {
      import core.sys.windows.windows : SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN;
      import std.utf : toUTF16z;
      if (!SetFileAttributesW(directory.toUTF16z, FILE_ATTRIBUTE_HIDDEN))
        warning("No se pudo ocultar el directorio de configuración ", directory);
    }
  }
  return directory;
}

/// Fija la ruta de config.properties (pruebas y configuraciones alternativas).
void setConfigPath(string path) @trusted {
  managerLock.lock();
  scope (exit) managerLock.unlock();
  overridePath = path;
}

/// Ruta de config.properties (config-flatpak-properties dentro de flatpak).
string configFilePath() @trusted {
  managerLock.lock();
  string path = overridePath;
  managerLock.unlock();
  if (path.length) return path;
  bool inFlatpak = environment.get("FIRMADORINFLATPAK", "false") == "true";
  return buildPath(configDirectory(), inFlatpak ? "config-flatpak-properties" : "config.properties");
}

/// Línea de fecha que Properties.store añade tras el comentario.
private string storeTimestamp() @safe {
  return formatJavaDate("EEE MMM dd HH:mm:ss zzz yyyy", Clock.currTime.toOtherTZ(costaRicaTimeZone()),
    DateLanguage.english);
}

/// Escribe un archivo pasando por un temporal, para no dejarlo a medias si algo se corta.
void writeFileAtomically(string path, const(void)[] content) @trusted {
  string directory = dirName(path);
  if (directory.length && !exists(directory)) mkdirRecurse(directory);
  string temporary = path ~ ".tmp";
  write(temporary, content);
  rename(temporary, path);
}

/// Lee config.properties; null si todavía no existe.
private string[string] loadProperties(string path) @trusted {
  if (!exists(path)) return null;
  info("Leyendo la configuración de ", path);
  return parseProperties(readText(path));
}

/// Ofusca como Password.obfuscate de Jetty, que es lo que usaba la versión Java.
string obfuscate(string text) pure @safe {
  auto bytes = cast(const(byte)[]) text;
  string result = obfuscationPrefix;
  foreach (index, b1; bytes) {
    byte b2 = bytes[bytes.length - (index + 1)];
    int i1 = 127 + b1 + b2;
    int i2 = 127 + b1 - b2;
    int i0 = i1 * 256 + i2;
    string digits = toBase36(i0);
    while (digits.length < 4) digits = "0" ~ digits;
    result ~= digits;
  }
  return result;
}

/**
 * Deshace obfuscate.
 *
 * Throws: Exception si el texto no tiene grupos de cuatro cifras en base 36.
 */
string deobfuscate(string text) pure @safe {
  string body = text.startsWith(obfuscationPrefix) ? text[obfuscationPrefix.length .. $] : text;
  enforce(body.length % 4 == 0, "La contraseña ofuscada de config.properties está incompleta");
  ubyte[] bytes;
  for (size_t index = 0; index < body.length; index += 4) {
    int i0 = body[index .. index + 4].to!int(36);
    int i1 = i0 / 256;
    int i2 = i0 % 256;
    bytes ~= cast(ubyte) ((i1 + i2 - 254) / 2);
  }
  return cast(string) bytes.idup;
}

private string toBase36(int value) pure @safe {
  enum string digits = "0123456789abcdefghijklmnopqrstuvwxyz";
  if (value == 0) return "0";
  bool negative = value < 0;
  long remaining = negative ? -cast(long) value : value;
  string result;
  while (remaining > 0) {
    result = digits[cast(size_t) (remaining % 36)] ~ result;
    remaining /= 36;
  }
  return negative ? "-" ~ result : result;
}

/// Contraseña aleatoria de 32 caracteres para el almacén de tokens.
string generateKeyPassword() @safe {
  return secureRandomString(32, keyPasswordAlphabet);
}

/**
 * Lee config.properties y devuelve los ajustes (getSettings), con la contraseña del
 * almacén de tokens resuelta: la del llavero, la guardada en el archivo o una nueva.
 *
 * Throws: Exception si el archivo tiene un número que no se puede leer.
 */
Settings readSettings() @trusted {
  auto conf = new Settings();
  string path = configFilePath();
  auto props = loadProperties(path);
  if (props is null) return conf;
  applyProperties(conf, props);
  setLogLevel(conf.advancedLogs);
  managerLock.lock();
  currentProperties = props;
  managerLock.unlock();

  auto store = credentialStore;
  if (store !is null && store.isAvailable()) {
    string existing = store.load();
    if (existing.length) {
      conf.keyPassword = existing;
      info("Contraseña del almacén de tokens recuperada desde: ", store.storageInfo());
    } else {
      conf.keyPassword = generateKeyPassword();
      info("Generando nueva contraseña del almacén de tokens");
      if (!store.save(conf.keyPassword)) error("El llavero del sistema no aceptó la contraseña del almacén de tokens");
      else info("Nueva contraseña guardada en: ", store.storageInfo());
    }
  } else {
    info("Utilizando la contraseña del almacén de tokens guardada en la configuración");
    string stored = "keyPassword" in props ? props["keyPassword"] : null;
    if (stored.length == 0) {
      conf.keyPassword = generateKeyPassword();
      writeSettings(conf, true);
    } else {
      conf.keyPassword = deobfuscate(stored);
    }
  }
  return conf;
}

/**
 * Pasa los ajustes a config.properties y, con `save`, lo escribe (setSettings). La
 * contraseña del almacén sólo se guarda en el archivo si no hay llavero del sistema.
 */
void writeSettings(const Settings conf, bool save) @trusted {
  auto store = credentialStore;
  bool inKeyring = store !is null && store.isAvailable();
  managerLock.lock();
  currentProperties = settingsToProperties(conf, currentProperties, inKeyring ? null : obfuscate(conf.keyPassword));
  auto snapshot = currentProperties.dup;
  managerLock.unlock();
  if (!save) return;
  string path = configFilePath();
  try {
    writeFileAtomically(path, formatProperties(snapshot, "Firmador Libre settings", storeTimestamp()));
    info("Configuración guardada en ", path);
  } catch (Exception exception) {
    error("No se pudo guardar el archivo de configuración ", path, ": ", exception.msg);
    throw new Exception(format("No se pudo guardar la configuración en %s: %s", path, exception.msg), exception);
  }
}

/**
 * Ajustes vigentes de la aplicación (getAndCreateSettings): se leen una vez y se
 * comparten. Si el archivo no se puede interpretar se registra el error y se usan los
 * valores por omisión, que se guardan, como en la versión Java.
 */
Settings currentSettings() @trusted {
  managerLock.lock();
  auto cached = cachedSettings;
  string path = overridePath;
  managerLock.unlock();
  if (cached !is null) return cached;
  Settings loaded;
  if (path.length && !exists(path)) {
    error("No existe el archivo de configuración ", path);
    loaded = new Settings();
  } else {
    try {
      loaded = readSettings();
    } catch (Exception exception) {
      error("No se pudo cargar la configuración, se usarán los valores por omisión: ", exception.msg);
      loaded = new Settings();
      writeSettings(loaded, true);
    }
  }
  setLogLevel(loaded.advancedLogs);
  setMessagesLocale(loaded.language, loaded.country);
  managerLock.lock();
  scope (exit) managerLock.unlock();
  if (cachedSettings is null) cachedSettings = loaded;
  return cachedSettings;
}

/// Reemplaza los ajustes vigentes (al aplicar la configuración) y actualiza idioma y bitácora.
void replaceCurrentSettings(Settings settings) @trusted {
  managerLock.lock();
  cachedSettings = settings;
  managerLock.unlock();
  setLogLevel(settings.advancedLogs);
  setMessagesLocale(settings.language, settings.country);
}

/// Olvida los ajustes vigentes para volver a leerlos (nullifySettingsVariable).
void forgetCurrentSettings() @trusted {
  managerLock.lock();
  scope (exit) managerLock.unlock();
  cachedSettings = null;
}

/**
 * Guarda la configuración de un documento en docSettings/<nombre>.config y devuelve la ruta.
 *
 * Throws: Exception si no se puede escribir.
 */
string saveDocumentSettings(const Settings settings, string documentName) @trusted {
  string directory = buildPath(configDirectory(), "docSettings");
  string path = buildPath(directory, documentName ~ ".config");
  writeFileAtomically(path, formatProperties(documentSettingsToProperties(settings),
    "Firmador Libre settings for " ~ documentName, storeTimestamp()));
  info("Configuración del documento ", documentName, " guardada en ", path);
  return path;
}

/**
 * Lee la configuración de un documento: los campos guardados sobre una copia de los
 * ajustes vigentes.
 *
 * Throws: Exception si el archivo no existe o trae campos desconocidos o mal escritos.
 */
Settings loadDocumentSettings(string path) @trusted {
  enforce(exists(path) && isFile(path), format("No existe la configuración de documento %s", path));
  info("Leyendo la configuración de documento ", path);
  auto settings = new Settings(currentSettings());
  applyDocumentProperties(settings, parseProperties(readText(path)));
  return settings;
}

@("should reproduce the Jetty obfuscation when storing the key password")
unittest {
  // Valores producidos por SettingsManager.obfuscate de la versión Java.
  assert(obfuscate("secreto") == "OBF:1xtv1w1c1sot1y7z1sox1w261xtn");
  assert(obfuscate("A!z9{}") == "OBF:1qo31jxh1olc1ohq1k2h1qrf");
  assert(deobfuscate(obfuscate("secreto")) == "secreto");
  string generated = generateKeyPassword();
  assert(generated.length == 32);
  assert(deobfuscate(obfuscate(generated)) == generated);
}

@("should store and read settings in a temporary config file when writing and reading it")
unittest {
  import std.file : tempDir, rmdirRecurse;
  string directory = buildPath(tempDir, "firmador-prueba-configuracion");
  if (exists(directory)) rmdirRecurse(directory);
  mkdirRecurse(directory);
  scope (exit) rmdirRecurse(directory);
  setConfigPath(buildPath(directory, "config.properties"));
  scope (exit) setConfigPath(null);
  auto conf = new Settings();
  conf.reason = "Prueba";
  conf.keyPassword = "clave";
  writeSettings(conf, true);
  auto loaded = readSettings();
  assert(loaded.reason == "Prueba");
  assert(loaded.keyPassword == "clave");
}
