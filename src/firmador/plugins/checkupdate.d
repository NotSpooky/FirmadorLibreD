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
 * Aviso y descarga de actualizaciones (CheckUpdatePlugin). Las versiones publicadas se
 * comparan con version.txt; las de desarrollo («SNAPSHOT»), por la suma SHA-256 del
 * ejecutable. La descarga sólo se instala si su SHA-256 coincide con el archivo
 * «<artefacto>.sha256» publicado (@contract release-artifacts): en Linux reemplaza el
 * ejecutable, en Windows ejecuta el instalador en modo silencioso y en macOS reemplaza
 * el contenido del paquete Firmador.app. Dentro de flatpak no se instala nada: se avisa
 * y la actualización llega por flatpak. No consulta nada mientras
 * configuration.releaseCheckEnabled esté desactivado.
 */
module firmador.plugins.checkupdate;

import core.thread : Thread;
import std.algorithm : canFind, endsWith, startsWith;
import std.array : split;
import std.conv : octal;
import std.digest : toHexString, LetterCase;
import std.digest.sha : sha256Of;
import std.exception : enforce;
import std.file : isDir, mkdirRecurse, read, remove, rename, setAttributes, tempDir, thisExePath, write;
import std.format : format;
import std.logger : error, info;
import std.path : buildNormalizedPath, buildPath, dirName;
import std.process : Config, spawnProcess;
import std.string : indexOf, strip, toUpper;
import std.uni : isWhite;

import firmador.configuration;
import firmador.crypto.random : secureRandomString;
import firmador.gui.guiinterface : GuiInterface;
import firmador.i18n : t;
import firmador.net.http : httpGet, HttpOptions;
import firmador.util.desktop : insideFlatpak;
import firmador.util.zip : isSafeEntryName, readZip;

/// Tamaño máximo de un artefacto descargado.
private enum size_t maxArtifactBytes = 512 * 1024 * 1024;

/// Es una versión de desarrollo.
bool isSnapshot(string version_) pure nothrow @safe {
  return version_.canFind("SNAPSHOT");
}

/// Artefacto que corresponde a esta plataforma (getReleaseUrl).
string releaseArtifactUrl(bool snapshot) pure nothrow @safe {
  if (snapshot) return releaseSnapshotUrl;
  version (OSX) return releaseMacUrl;
  else version (Windows) return releaseWindowsUrl;
  else return releaseLinuxUrl;
}

/// Suma publicada de un artefacto (getChecksumUrl).
string checksumUrlOf(string artifactUrl) pure nothrow @safe {
  return artifactUrl ~ checksumSuffix;
}

/// La versión publicada (version.txt, sin espacios) es otra que la local.
bool isOtherVersion(string publishedVersion, string localVersion) pure @safe {
  string compact;
  foreach (character; publishedVersion) if (!isWhite(character)) compact ~= character;
  return compact.length > 0 && compact != localVersion;
}

/**
 * La suma publicada (formato de sha256sum: «<hex>  <archivo>», o sólo el hex) es la del
 * contenido.
 */
bool checksumMatches(string publishedChecksum, const(ubyte)[] content) pure @safe {
  auto words = publishedChecksum.strip.split;
  if (words.length == 0) return false;
  return words[0].toUpper == toHexString!(LetterCase.upper)(sha256Of(content)).idup;
}

/**
 * Ruta dentro de Firmador.app/Contents de una entrada del ZIP de macOS, o null si no
 * pertenece al paquete.
 */
string macBundleEntryPath(string entryName) pure @safe {
  enum marker = "Firmador.app/Contents/";
  auto position = entryName.indexOf(marker);
  if (position < 0 || entryName.endsWith("/")) return null;
  return entryName[position + marker.length .. $];
}

/// Avisa y, si el usuario acepta, instala la versión nueva.
struct CheckUpdatePlugin {
  enum string name = checkUpdatePluginName;
  private GuiInterface gui;

  this(GuiInterface gui) pure @safe {
    this.gui = gui;
  }

  void start() @trusted {
    if (!releaseCheckEnabled) {
      info("CheckUpdatePlugin desactivado (configuration.releaseCheckEnabled): no se buscan actualizaciones");
    } else {
      info("Starting CheckUpdatePlugin");
      // El hilo usa su propia copia: la del llamador puede dejar de existir.
      auto plugin = this;
      auto worker = new Thread({
        try {
          plugin.check();
        } catch (Exception exception) {
          error("Error al buscar actualizaciones: ", exception.msg);
        }
      });
      worker.isDaemon = true;
      worker.start();
    }
  }

  void stop() @safe {
    info("Stopping CheckUpdatePlugin");
  }

  private void check() @trusted {
    bool snapshot = isSnapshot(firmadorVersion);
    string artifact = releaseArtifactUrl(snapshot);
    bool outdated;
    if (snapshot) {
      info("Updating development version");
      string published = fetchText(checksumUrlOf(artifact));
      outdated = !checksumMatches(published, cast(const(ubyte)[]) read(thisExePath));
    } else {
      info("Updating release version");
      outdated = isOtherVersion(fetchText(releaseUrlCheck), firmadorVersion);
    }
    if (!outdated) return;
    string message = t("checkplugin_info") ~ baseUrl;
    if (!canInstall()) {
      gui.showMessage(message);
      return;
    }
    if (!gui.askConfirmation(t("checkplugin_download"), message)) return;
    try {
      install(artifact);
    } catch (Exception exception) {
      error(t("checkplugin_error_updating_jar"), ": ", exception.msg);
      gui.showError(exception);
    }
  }

  private string fetchText(string url) @safe {
    auto response = httpGet(url);
    enforce(response.status == 200, format("%s respondió %d", url, response.status));
    return response.text;
  }

  /// Se puede instalar sin permisos que no se tienen: fuera de flatpak y con el ejecutable escribible.
  private bool canInstall() @trusted {
    if (insideFlatpak()) return false;
    version (OSX) {
      return true;
    } else {
      import std.file : FileException;
      try {
        return isWritable(dirName(thisExePath)) && isWritable(thisExePath);
      } catch (FileException) {
        return false;
      }
    }
  }

  /// Descarga, verifica e instala el artefacto.
  private void install(string artifact) @trusted {
    info("Downloading from ", artifact);
    HttpOptions options;
    options.maxResponseBytes = maxArtifactBytes;
    options.operationTimeout = typeof(options.operationTimeout).zero;
    auto download = httpGet(artifact, null, options);
    enforce(download.status == 200, format("%s respondió %d", artifact, download.status));
    auto content = download.body;
    enforce(checksumMatches(fetchText(checksumUrlOf(artifact)), content),
      format("La suma SHA-256 de %s no coincide con la publicada: no se instala", artifact));
    info("Suma SHA-256 de la descarga verificada");
    version (Windows) {
      string installer = buildPath(tempDir, "firmador-" ~ secureRandomString(12, "abcdefghijklmnopqrstuvwxyz0123456789")
        ~ ".exe");
      write(installer, content);
      info("Ejecutando el instalador ", installer);
      spawnProcess([installer, "/S"], null, Config.detached);
      return;
    } else version (OSX) {
      // thisExePath: …/Firmador.app/Contents/MacOS/firmador
      string contents = buildNormalizedPath(dirName(thisExePath), "..");
      enforce(contents.endsWith("Contents"), format("Firmador no se está ejecutando desde un paquete .app: %s",
        thisExePath));
      extractMacBundle(content, contents);
    } else {
      string executable = thisExePath;
      string staged = executable ~ ".new";
      write(staged, content);
      setAttributes(staged, octal!755);
      rename(staged, executable);
      info("Ejecutable reemplazado: ", executable);
    }
    gui.showMessage("Nueva versión ha sido descargada con éxito, debe reiniciar la aplicación.");
  }
}

/// Se puede escribir en la ruta (permisos del usuario efectivo).
private bool isWritable(string path) @trusted {
  version (Posix) {
    import core.sys.posix.unistd : access, W_OK;
    import std.string : toStringz;
    return access(path.toStringz, W_OK) == 0;
  } else version (Windows) {
    // En Windows se prueba creando un archivo junto al ejecutable.
    string probe = (isDir(path) ? path : dirName(path)) ~ `\.firmador-escritura`;
    try {
      write(probe, "");
      remove(probe);
      return true;
    } catch (Exception) {
      return false;
    }
  }
}

/**
 * Copia en `contents` las entradas Firmador.app/Contents/… del ZIP descargado,
 * reemplazando las existentes.
 *
 * Throws: ZipFormatException si el ZIP está dañado; Exception si trae rutas inseguras o
 * no trae el paquete.
 */
private void extractMacBundle(immutable(ubyte)[] zip, string contents) @trusted {
  size_t copied;
  foreach (entry; readZip(zip)) {
    string relative = macBundleEntryPath(entry.name);
    if (relative is null) continue;
    enforce(isSafeEntryName(relative), format("El paquete descargado trae una ruta insegura: %s", entry.name));
    string destination = buildPath(contents, relative);
    mkdirRecurse(dirName(destination));
    string staged = destination ~ ".new";
    write(staged, entry.content);
    if (relative.startsWith("MacOS/") || relative.endsWith(".dylib")) setAttributes(staged, octal!755);
    rename(staged, destination);
    copied++;
  }
  enforce(copied > 0, "El paquete descargado no contiene Firmador.app");
  info("Paquete actualizado en ", contents, " (", copied, " archivos)");
}

@("should compare published versions and checksums like the update check expects")
unittest {
  assert(isOtherVersion(" 2.1.0\n", "2.0.9"));
  assert(!isOtherVersion("2.1.0\r\n", "2.1.0"));
  assert(!isOtherVersion("  ", "2.1.0"));
  auto content = cast(const(ubyte)[]) "firmador";
  string hex = toHexString!(LetterCase.lower)(sha256Of(content)).idup;
  assert(checksumMatches(hex ~ "  firmador-linux-x86_64\n", content));
  assert(!checksumMatches("", content));
  assert(!checksumMatches("00" ~ hex[2 .. $], content));
  assert(checksumUrlOf(releaseArtifactUrl(false)).endsWith(".sha256"));
}

@("should keep only the app bundle contents when unpacking the macOS update")
unittest {
  assert(macBundleEntryPath("dist/Firmador.app/Contents/MacOS/firmador") == "MacOS/firmador");
  assert(macBundleEntryPath("Firmador.app/Contents/Frameworks/libmupdf.dylib") == "Frameworks/libmupdf.dylib");
  assert(macBundleEntryPath("Firmador.app/Contents/Resources/") is null);
  assert(macBundleEntryPath("README.txt") is null);
}
