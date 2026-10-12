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
 * Actualización automática (CheckUpdatePlugin). Al abrir la ventana consulta la última versión
 * publicada en GitHub (configuration.latestReleaseApiUrl) y, si es más nueva que esta:
 * - en Windows, si Firmador se instaló con su instalador (packaging/windows/firmador.wxs, que
 *   deja la carpeta en el registro), pregunta, descarga el .msi y, cuando Firmador se cierra,
 *   lo ejecuta con msiexec, que reemplaza la versión instalada y vuelve a abrir Firmador;
 * - en macOS, dentro de Firmador.app, pregunta, descarga el ZIP, cambia el paquete por el
 *   nuevo y lo vuelve a abrir cuando Firmador se cierra;
 * - en lo demás (el ZIP de Windows, Linux, flatpak) avisa, con un enlace a la descarga.
 * Lo descargado sólo se instala si su SHA-256 coincide con el de SHA256SUMS de la misma
 * versión, y sólo se descarga de las versiones publicadas de este repositorio; los nombres de
 * los paquetes son los de la CI (@contract release-artifacts). Las versiones de desarrollo
 * (con sufijo, como 0.7.4-dev.abc1234) no se actualizan. No consulta nada con
 * configuration.releaseCheckEnabled desactivado ni sin el plugin activo.
 */
module firmador.plugins.checkupdate;

import core.thread : Thread;
import std.algorithm : all, endsWith, startsWith;
import std.array : replace, split;
import std.ascii : isDigit, isHexDigit;
import std.conv : ConvException, octal, to;
import std.digest : LetterCase, toHexString;
import std.digest.sha : sha256Of;
import std.exception : enforce;
import std.file : exists, mkdirRecurse, rename, rmdirRecurse, setAttributes, tempDir, thisExePath, write;
import std.format : format;
import std.logger : error, info;
import std.path : baseName, buildNormalizedPath, buildPath, dirName;
import std.process : Config, spawnProcess, thisProcessID;
import std.string : indexOf, lineSplitter, strip, toLower;
import std.uni : icmp;

import firmador.configuration;
import firmador.crypto.random : secureRandomString;
import firmador.gui.guiinterface : GuiInterface, NotificationType;
import firmador.i18n : t;
import firmador.net.http : httpGet, HttpOptions;
import firmador.signers.common : rootCause;
import firmador.util.desktop : insideFlatpak;
import firmador.util.json : arrayItems, isObject, JsonShapeException, member, parseJsonText, requiredString;
import firmador.util.zip : isSafeEntryName, readZip;

/// Tamaño máximo de un paquete descargado.
private enum size_t maxArtifactBytes = 512 * 1024 * 1024;

/// Tamaño máximo de la respuesta de la API de GitHub y de SHA256SUMS.
private enum size_t maxMetadataBytes = 1024 * 1024;

/// Plataforma para la que se busca el paquete.
enum UpdatePlatform {
  windows,
  macos,
  linux,
}

/// La de este ejecutable.
version (Windows) enum UpdatePlatform currentPlatform = UpdatePlatform.windows;
else version (OSX) enum UpdatePlatform currentPlatform = UpdatePlatform.macos;
else enum UpdatePlatform currentPlatform = UpdatePlatform.linux;

/// Números de una versión X.Y.Z[-sufijo].
struct VersionNumbers {
  uint major;
  uint minor;
  uint patch;
  /// Tiene sufijo («-dev.abc1234»): es de desarrollo.
  bool development;
}

/// Paquete de una versión publicada.
struct ReleaseAsset {
  string name;
  /// Dirección de descarga: siempre la de este nombre en la versión, bajo releaseDownloadPrefix.
  string url;
}

/// Última versión publicada, ya validada (parsePublishedRelease).
struct PublishedRelease {
  /// Versión X.Y.Z, que es la etiqueta.
  string version_;
  /// Página de la versión, con sus novedades y sus paquetes.
  string pageUrl;
  ReleaseAsset[] assets;
}

/**
 * Números de una versión: «0.7.4», o una de desarrollo como «0.7.4-dev.abc1234».
 * Params:
 *   text = la versión (version.txt o la etiqueta de una versión publicada).
 * Returns: sus números, y si tiene sufijo.
 * Throws: Exception si no es X.Y.Z[-sufijo].
 */
VersionNumbers parseVersion(string text) pure @safe {
  string invalid = format("«%s» no es una versión X.Y.Z[-sufijo]", text);
  auto dash = text.indexOf('-');
  string core = dash < 0 ? text : text[0 .. dash];
  string suffix = dash < 0 ? null : text[dash + 1 .. $];
  auto parts = core.split('.');
  enforce(parts.length == 3, invalid);
  foreach (part; parts) enforce(part.length > 0 && part.all!isDigit, invalid);
  enforce(dash < 0 || (suffix.length > 0 && suffix.all!(character => character.isDigit || (character >= 'a'
    && character <= 'z') || (character >= 'A' && character <= 'Z') || character == '.' || character == '-')), invalid);
  try {
    return VersionNumbers(parts[0].to!uint, parts[1].to!uint, parts[2].to!uint, dash >= 0);
  } catch (ConvException exception) {
    throw new Exception(invalid ~ ": un número es demasiado grande", exception);
  }
}

/// La versión publicada es más nueva que la local (se comparan X.Y.Z, sin el sufijo).
bool isNewerVersion(const VersionNumbers published, const VersionNumbers local) pure nothrow @safe @nogc {
  if (published.major != local.major) return published.major > local.major;
  if (published.minor != local.minor) return published.minor > local.minor;
  return published.patch > local.patch;
}

/**
 * Última versión publicada, de la respuesta de releases/latest de la API de GitHub. Se exige
 * una versión X.Y.Z, la página de las versiones de este repositorio y que cada paquete se
 * descargue de esa versión (releaseDownloadPrefix), así que no se baja nada de otro lugar.
 * Params:
 *   json = la respuesta de configuration.latestReleaseApiUrl.
 * Returns: la versión validada.
 * Throws: JsonShapeException o Exception, con el dato que falla, si la respuesta no es así.
 */
PublishedRelease parsePublishedRelease(string json) pure @safe {
  enum what = "La última versión publicada (API de GitHub)";
  auto root = parseJsonText(json, what);
  enforce!JsonShapeException(isObject(root), what ~ " debe ser un objeto JSON");
  PublishedRelease release;
  release.version_ = requiredString(root, "tag_name", what);
  enforce(!parseVersion(release.version_).development, format("%s: «%s» no es una versión X.Y.Z publicada", what,
    release.version_));
  release.pageUrl = requiredString(root, "html_url", what);
  enforce(release.pageUrl == releasesPageUrl ~ "/tag/" ~ release.version_, format(
    "%s: la página «%s» no es la de la versión %s en %s", what, release.pageUrl, release.version_, releasesPageUrl));
  auto assets = member(root, "assets");
  enforce!JsonShapeException(assets !is null, what ~ ": falta la lista «assets»");
  foreach (item; arrayItems(*assets, what ~ ": assets")) {
    ReleaseAsset asset;
    asset.name = requiredString(item, "name", what ~ ": paquete");
    asset.url = requiredString(item, "browser_download_url", what ~ ": paquete " ~ asset.name);
    enforce(asset.url == releaseDownloadPrefix ~ release.version_ ~ "/" ~ asset.name, format(
      "%s: el paquete %s se descarga de «%s», que no es de esta versión", what, asset.name, asset.url));
    release.assets ~= asset;
  }
  return release;
}

/**
 * Nombre del paquete de la versión `version_` que instala la actualización en `platform`
 * (@contract release-artifacts: los nombres de la CI, con v_X_Y_Z por la versión X.Y.Z).
 * Returns: el nombre, o null en Linux, donde la actualización sólo se avisa.
 */
string installableAssetName(string version_, UpdatePlatform platform) pure @safe {
  string label = "v_" ~ version_.replace(".", "_");
  final switch (platform) {
    case UpdatePlatform.windows:
      return "firmador_windows_" ~ label ~ ".msi";
    case UpdatePlatform.macos:
      return "firmador_macos_" ~ label ~ ".zip";
    case UpdatePlatform.linux:
      return null;
  }
}

/**
 * SHA-256 de `fileName` en un SHA256SUMS, con el formato de sha256sum: «<hex>  <archivo>» (o
 * «<hex> *<archivo>» en modo binario).
 * Returns: el SHA-256 en minúsculas, o null si el archivo no está.
 */
string publishedChecksum(string sums, string fileName) pure @safe {
  foreach (line; sums.lineSplitter) {
    string text = line.strip;
    if (text.length < 66 || text[64] != ' ' || !text[0 .. 64].all!isHexDigit) continue;
    string name = text[65 .. $];
    if (name.startsWith("*") || name.startsWith(" ")) name = name[1 .. $];
    if (name == fileName) return text[0 .. 64].toLower;
  }
  return null;
}

/// El SHA-256 del contenido es `expected` (en hexadecimal).
bool matchesChecksum(string expected, const(ubyte)[] content) pure @safe {
  return expected.toLower == toHexString!(LetterCase.lower)(sha256Of(content)).idup;
}

/// Dos rutas de Windows nombran la misma carpeta: sin distinguir mayúsculas ni la barra final.
bool sameWindowsFolder(string first, string second) pure @safe {
  string normalized(string path) {
    string result = path.replace("/", `\`);
    while (result.length > 3 && result.endsWith(`\`)) result = result[0 .. $ - 1];
    return result;
  }
  return icmp(normalized(first), normalized(second)) == 0;
}

/**
 * Orden de PowerShell que espera a que termine el proceso `processId` (este Firmador), instala
 * `installer` con `msiexec` (que vuelve a abrir Firmador) y lo borra. Las rutas van entre
 * comillas simples de PowerShell, con las que traigan duplicadas; la del instalador, además
 * entre comillas dobles para msiexec, por si tiene espacios (en Windows no puede tener «"»).
 */
string windowsUpdateCommand(uint processId, string msiexec, string installer) pure @safe {
  string quoted(string text) {
    return "'" ~ text.replace("'", "''") ~ "'";
  }
  return format("Wait-Process -Id %d -ErrorAction SilentlyContinue; Start-Process -FilePath %s -ArgumentList '/i', %s, "
    ~ "'/passive', 'LAUNCHFIRMADOR=1' -Wait; Remove-Item -LiteralPath %s -ErrorAction SilentlyContinue", processId,
    quoted(msiexec), quoted(`"` ~ installer ~ `"`), quoted(installer));
}

/// Orden de PowerShell para -EncodedCommand: su texto en UTF-16LE y Base64, sin problemas de comillas.
string encodedPowerShell(string command) pure @safe {
  import std.base64 : Base64;
  import std.utf : toUTF16;
  ubyte[] bytes;
  foreach (wchar unit; command.toUTF16) bytes ~= [cast(ubyte) (unit & 0xFF), cast(ubyte) (unit >> 8)];
  return Base64.encode(bytes).idup;
}

/**
 * Orden que vuelve a abrir `bundle` con open cuando termina el proceso `processId`: si se
 * abriera antes, la instancia nueva le pasaría los documentos a la vieja y se cerraría. La
 * ruta va como argumento del guion, no dentro de él.
 */
string[] macRelaunchCommand(uint processId, string bundle) pure @safe {
  return ["/bin/sh", "-c", format("while kill -0 %d 2>/dev/null; do sleep 0.5; done; exec /usr/bin/open -n \"$1\"",
    processId), "sh", bundle];
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

/// Avisa de las versiones nuevas y, si se puede y el usuario acepta, las instala.
struct CheckUpdatePlugin {
  enum string name = checkUpdatePluginName;
  private GuiInterface gui;

  this(GuiInterface gui) pure @safe {
    this.gui = gui;
  }

  void start() @trusted {
    if (!releaseCheckEnabled) {
      info("CheckUpdatePlugin desactivado (configuration.releaseCheckEnabled): no se buscan actualizaciones");
      return;
    }
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

  void stop() @safe {
    info("Stopping CheckUpdatePlugin");
  }

  private void check() @trusted {
    auto local = parseVersion(firmadorVersion);
    if (local.development) {
      info("Versión de desarrollo ", firmadorVersion, ": no se buscan actualizaciones");
      return;
    }
    info("Buscando actualizaciones en ", latestReleaseApiUrl);
    auto release = parsePublishedRelease(fetchText(latestReleaseApiUrl));
    if (!isNewerVersion(parseVersion(release.version_), local)) {
      info("Firmador está al día (", firmadorVersion, "; la última publicada es ", release.version_, ")");
      return;
    }
    info("Hay una versión nueva: ", release.version_, " (", release.pageUrl, ")");
    string assetName = installableAssetName(release.version_, currentPlatform);
    if (assetName is null || !canReplaceThisCopy()) {
      gui.showMessage(format(t("checkplugin_available"), release.version_, release.pageUrl));
      return;
    }
    if (!gui.askConfirmation(t("checkplugin_title"), format(t("checkplugin_install_question"), release.version_,
        release.pageUrl))) {
      info("Actualización a ", release.version_, " pospuesta por el usuario");
      return;
    }
    try {
      install(release, assetName);
    } catch (Exception exception) {
      error("No se pudo instalar la versión ", release.version_, ": ", exception.msg);
      gui.showErrorAlert(t("checkplugin_title"), format(t("checkplugin_install_error"), release.version_,
        release.pageUrl) ~ "<br>" ~ rootCause(exception).msg);
    }
  }

  /// Cabeceras de las consultas: la API de GitHub rechaza las que no dicen quién pregunta.
  private static string[string] requestHeaders() @safe {
    return ["User-Agent": "FirmadorLibreD/" ~ firmadorVersion, "Accept": "application/vnd.github+json"];
  }

  private string fetchText(string url) @safe {
    HttpOptions options;
    options.maxResponseBytes = maxMetadataBytes;
    auto response = httpGet(url, requestHeaders(), options);
    enforce(response.status == 200, format("%s respondió %d", url, response.status));
    return response.text;
  }

  /**
   * Esta copia de Firmador se puede reemplazar sola: en Windows, la del instalador; en macOS,
   * Firmador.app en una carpeta donde se puede escribir. Fuera de eso (o en flatpak) sólo se avisa.
   */
  private bool canReplaceThisCopy() @trusted {
    if (insideFlatpak()) return false;
    version (Windows) {
      import firmador.util.winregistry : RegistryRoot, registryText;
      string executableFolder = dirName(thisExePath);
      foreach (root; [RegistryRoot.currentUser, RegistryRoot.localMachine]) {
        string installed = registryText(root, `Software\Firmador Libre`, "InstallFolder");
        if (installed !is null && sameWindowsFolder(installed, executableFolder)) return true;
      }
      info("Firmador no corre desde la carpeta de su instalador (", executableFolder, "): sólo se avisa");
      return false;
    } else version (OSX) {
      import core.sys.posix.unistd : access, W_OK;
      import std.string : toStringz;
      string bundle = runningBundle();
      if (bundle is null || access(dirName(bundle).toStringz, W_OK) != 0) {
        info("Firmador no corre desde un Firmador.app que se pueda reemplazar (", thisExePath, "): sólo se avisa");
        return false;
      }
      return true;
    } else {
      return false;
    }
  }

  /// Descarga el paquete, lo verifica con SHA256SUMS, lo deja listo para cuando Firmador se cierre y lo cierra.
  private void install(const PublishedRelease release, string assetName) @trusted {
    string assetUrl = urlOf(release, assetName);
    string sumsUrl = urlOf(release, "SHA256SUMS");
    gui.showNotification(format(t("checkplugin_downloading"), release.version_), NotificationType.info);
    string expected = publishedChecksum(fetchText(sumsUrl), assetName);
    enforce(expected !is null, format("SHA256SUMS de la versión %s no trae la suma de %s", release.version_, assetName));
    info("Descargando ", assetUrl);
    HttpOptions options;
    options.maxResponseBytes = maxArtifactBytes;
    options.operationTimeout = typeof(options.operationTimeout).zero;
    auto download = httpGet(assetUrl, requestHeaders(), options);
    enforce(download.status == 200, format("%s respondió %d", assetUrl, download.status));
    enforce(matchesChecksum(expected, download.body), format(
      "La suma SHA-256 de %s no coincide con la de SHA256SUMS: no se instala", assetName));
    info("Suma SHA-256 de ", assetName, " verificada");
    version (Windows) {
      prepareWindowsInstaller(download.body);
    } else version (OSX) {
      replaceBundle(download.body);
    } else {
      assert(false, "En Linux la actualización sólo se avisa (canReplaceThisCopy)");
    }
    gui.closeApplication();
  }

  /// Dirección del paquete `assetName` de la versión.
  private static string urlOf(const PublishedRelease release, string assetName) @safe {
    foreach (asset; release.assets) if (asset.name == assetName) return asset.url;
    throw new Exception(format("La versión %s no publica %s", release.version_, assetName));
  }
}

version (Windows) {
  /**
   * Guarda el instalador en la carpeta temporal y deja esperando a PowerShell para que lo
   * ejecute con msiexec cuando Firmador termine (windowsUpdateCommand), sin archivos en uso.
   */
  private void prepareWindowsInstaller(const(ubyte)[] content) @trusted {
    import std.process : environment;
    string system = buildPath(environment.get("SystemRoot", `C:\Windows`), "System32");
    string installer = buildPath(tempDir, "firmador-" ~ secureRandomString(12, "abcdefghijklmnopqrstuvwxyz0123456789")
      ~ ".msi");
    write(installer, content);
    string command = windowsUpdateCommand(thisProcessID, buildPath(system, "msiexec.exe"), installer);
    info("Instalador guardado en ", installer, "; se ejecuta con msiexec al cerrar Firmador");
    spawnProcess([buildPath(system, `WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive",
      "-WindowStyle", "Hidden", "-EncodedCommand", encodedPowerShell(command)], null,
      Config.detached | Config.suppressConsole);
  }
}

version (OSX) {
  /// Firmador.app desde el que corre este ejecutable, o null si no corre desde un paquete.
  private string runningBundle() @trusted {
    // thisExePath: …/Firmador.app/Contents/MacOS/firmador
    string contents = buildNormalizedPath(dirName(thisExePath), "..");
    string bundle = dirName(contents);
    return baseName(contents) == "Contents" && bundle.endsWith(".app") ? bundle : null;
  }

  /**
   * Cambia Firmador.app por el del ZIP: lo arma al lado, cambia uno por otro (si falla, deja el
   * viejo) y deja esperando que Firmador termine para abrir el nuevo (macRelaunchCommand). Así
   * no quedan archivos que la versión nueva ya no trae, que romperían su firma.
   */
  private void replaceBundle(const(ubyte)[] zip) @trusted {
    string bundle = runningBundle();
    enforce(bundle !is null, format("Firmador no se está ejecutando desde un paquete .app: %s", thisExePath));
    string staged = bundle ~ ".nuevo";
    string previous = bundle ~ ".anterior";
    foreach (leftover; [staged, previous]) if (exists(leftover)) rmdirRecurse(leftover);
    extractMacBundle(zip, buildPath(staged, "Contents"));
    rename(bundle, previous);
    try {
      rename(staged, bundle);
    } catch (Exception exception) {
      rename(previous, bundle);
      throw new Exception(format("No se pudo poner la versión nueva en %s", bundle), exception);
    }
    rmdirRecurse(previous);
    info("Firmador.app reemplazado por la versión nueva: ", bundle);
    spawnProcess(macRelaunchCommand(thisProcessID, bundle), null, Config.detached);
  }

  /**
   * Copia en `contents` las entradas Firmador.app/Contents/… del ZIP descargado.
   *
   * Throws: ZipFormatException si el ZIP está dañado; Exception si trae rutas inseguras o
   * no trae el paquete.
   */
  private void extractMacBundle(const(ubyte)[] zip, string contents) @trusted {
    size_t copied;
    foreach (entry; readZip(zip)) {
      string relative = macBundleEntryPath(entry.name);
      if (relative is null) continue;
      enforce(isSafeEntryName(relative), format("El paquete descargado trae una ruta insegura: %s", entry.name));
      string destination = buildPath(contents, relative);
      mkdirRecurse(dirName(destination));
      write(destination, entry.content);
      if (relative.startsWith("MacOS/") || relative.endsWith(".dylib")) setAttributes(destination, octal!755);
      copied++;
    }
    enforce(copied > 0, "El paquete descargado no contiene Firmador.app");
    info("Paquete nuevo armado en ", contents, " (", copied, " archivos)");
  }
}

@("should read release and development versions and compare only their numbers")
unittest {
  import std.exception : assertThrown;
  assert(parseVersion("0.7.4") == VersionNumbers(0, 7, 4, false));
  assert(parseVersion("0.7.4-dev.abc1234") == VersionNumbers(0, 7, 4, true));
  foreach (invalid; ["0.7", "0.7.4.1", "v0.7.4", "0.7.x", "0.7.4-", "0.7.4-dev;rm", "", "99999999999.0.0"]) {
    assertThrown(parseVersion(invalid));
  }
  assert(isNewerVersion(parseVersion("0.10.0"), parseVersion("0.9.9")));
  assert(isNewerVersion(parseVersion("1.0.0"), parseVersion("0.99.99")));
  assert(!isNewerVersion(parseVersion("0.7.4"), parseVersion("0.7.4")));
  assert(!isNewerVersion(parseVersion("0.7.3"), parseVersion("0.7.4")));
  // Una de desarrollo de la 0.7.4 no se toma por anterior a la 0.7.4.
  assert(!isNewerVersion(parseVersion("0.7.4"), parseVersion("0.7.4-dev.abc1234")));
}

@("should accept the latest release only with this repository's tag page and download addresses")
unittest {
  import std.exception : assertThrown, collectExceptionMsg;
  import std.algorithm : canFind;
  string releaseJson(string tag, string page, string assetUrl) {
    return format(`{"tag_name": "%s", "html_url": "%s", "draft": false, "assets": [{"name": "SHA256SUMS",
      "browser_download_url": "%s"}]}`, tag, page, assetUrl);
  }
  string downloads = releaseDownloadPrefix ~ "0.8.0/";
  auto release = parsePublishedRelease(releaseJson("0.8.0", releasesPageUrl ~ "/tag/0.8.0", downloads ~ "SHA256SUMS"));
  assert(release.version_ == "0.8.0" && release.assets == [ReleaseAsset("SHA256SUMS", downloads ~ "SHA256SUMS")]);
  // Un paquete de otra versión o de otro lugar no se acepta.
  assert(collectExceptionMsg(parsePublishedRelease(releaseJson("0.8.0", releasesPageUrl ~ "/tag/0.8.0",
    "https://example.com/SHA256SUMS"))).canFind("no es de esta versión"));
  assertThrown(parsePublishedRelease(releaseJson("0.8.0", releasesPageUrl ~ "/tag/0.8.0",
    releaseDownloadPrefix ~ "0.7.0/SHA256SUMS")));
  assertThrown(parsePublishedRelease(releaseJson("0.8.0", "https://github.com/otro/repo/releases/tag/0.8.0",
    downloads ~ "SHA256SUMS")));
  assertThrown(parsePublishedRelease(releaseJson("0.8.0-beta", releasesPageUrl ~ "/tag/0.8.0-beta",
    releaseDownloadPrefix ~ "0.8.0-beta/SHA256SUMS")));
  assertThrown(parsePublishedRelease(`{"tag_name": "0.8.0"}`));
  assertThrown(parsePublishedRelease("<html>"));
}

@("should name the installable package like the CI and find its checksum in SHA256SUMS")
unittest {
  import std.string : toUpper;
  assert(installableAssetName("0.8.0", UpdatePlatform.windows) == "firmador_windows_v_0_8_0.msi");
  assert(installableAssetName("0.8.0", UpdatePlatform.macos) == "firmador_macos_v_0_8_0.zip");
  assert(installableAssetName("0.8.0", UpdatePlatform.linux) is null);
  auto content = cast(const(ubyte)[]) "instalador";
  string hex = toHexString!(LetterCase.lower)(sha256Of(content)).idup;
  string sums = "0000000000000000000000000000000000000000000000000000000000000000  firmador_macos_v_0_8_0.zip\n"
    ~ hex.toUpper ~ " *firmador_windows_v_0_8_0.msi\n";
  assert(publishedChecksum(sums, "firmador_windows_v_0_8_0.msi") == hex);
  assert(publishedChecksum(sums, "firmador_windows_v_0_8_0.zip") is null);
  assert(publishedChecksum("no es una suma  firmador_windows_v_0_8_0.msi", "firmador_windows_v_0_8_0.msi") is null);
  assert(matchesChecksum(publishedChecksum(sums, "firmador_windows_v_0_8_0.msi"), content));
  assert(!matchesChecksum(publishedChecksum(sums, "firmador_macos_v_0_8_0.zip"), content));
}

@("should recognize the installer folder whatever the case or the final backslash")
unittest {
  assert(sameWindowsFolder(`C:\Users\Ana\AppData\Local\Programs\Firmador Libre\`,
    `c:\users\ana\appdata\local\programs\firmador libre`));
  assert(sameWindowsFolder(`C:\Program Files\Firmador Libre`, `C:/Program Files/Firmador Libre/`));
  assert(!sameWindowsFolder(`C:\Program Files\Firmador Libre`, `C:\Descargas\firmador`));
}

@("should build update commands that keep paths with quotes and spaces intact")
unittest {
  import std.base64 : Base64;
  import std.algorithm : canFind;
  string command = windowsUpdateCommand(42, `C:\Windows\System32\msiexec.exe`, `C:\Users\O'Neil\AppData\Local\Temp\f.msi`);
  assert(command.canFind("Wait-Process -Id 42"));
  // La comilla del nombre va duplicada; la ruta, también entre comillas dobles para msiexec.
  assert(command.canFind(`'"C:\Users\O''Neil\AppData\Local\Temp\f.msi"'`));
  assert(command.canFind(`Remove-Item -LiteralPath 'C:\Users\O''Neil\AppData\Local\Temp\f.msi'`));
  // -EncodedCommand es UTF-16LE en Base64.
  assert(encodedPowerShell("Wait") == "VwBhAGkAdAA=");
  assert(cast(string) Base64.decode(encodedPowerShell("ñ")) == "\xF1\x00");
  auto relaunch = macRelaunchCommand(7, "/Applications/Firmador Libre.app");
  assert(relaunch[0] == "/bin/sh" && relaunch[$ - 1] == "/Applications/Firmador Libre.app");
  assert(relaunch[2].canFind("kill -0 7") && !relaunch[2].canFind("Firmador Libre.app"));
}

@("should keep only the app bundle contents when unpacking the macOS update")
unittest {
  assert(macBundleEntryPath("dist/Firmador.app/Contents/MacOS/firmador") == "MacOS/firmador");
  assert(macBundleEntryPath("Firmador.app/Contents/Frameworks/libmupdf.dylib") == "Frameworks/libmupdf.dylib");
  assert(macBundleEntryPath("Firmador.app/Contents/Resources/") is null);
  assert(macBundleEntryPath("README.txt") is null);
}
