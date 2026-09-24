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
 * Plugins (Plugin y PluginManager en la versión Java). Se activan por nombre en
 * config.properties (plugins=…|…) con los mismos nombres de clase de la versión Java,
 * para conservar la configuración: DummyPlugin (datos del sistema en la bitácora),
 * CheckUpdatePlugin (firmador.plugins.checkupdate), DocumentSignLogs (signlog.csv) e
 * InstallerPlugin (se desactiva a sí mismo tras la instalación).
 */
module firmador.plugins.plugin;

import std.algorithm : canFind, countUntil, remove;
import std.array : appender;
import std.datetime.systime : Clock;
import std.file : append;
import std.format : format;
import std.logger : error, info, warning;
import std.path : buildPath;
import std.string : join;
import std.system : endian, os;

import core.sync.mutex : Mutex;

import firmador.configuration;
import firmador.documents.document : Document;
import firmador.gui.guiinterface : GuiInterface;
import firmador.logging : withContext;
import firmador.plugins.checkupdate : CheckUpdatePlugin;
import firmador.settings : Settings;
import firmador.settingsmanager : configDirectory, currentSettings, writeSettings;
import firmador.util.datetime : costaRicaTimeZone, DateLanguage, formatJavaDate;

/// Plugin; los métodos que no le interesan quedan vacíos.
abstract class Plugin {
  /// Nombre con que se activa en la configuración.
  abstract string name() const @safe;
  /// Al cargar el plugin; los que trabajan en segundo plano arrancan aquí.
  void start() @safe {}
  /// Cuando la interfaz ya está armada y la bitácora lista.
  void startLogging() @safe {}
  /// Al cerrar la aplicación.
  void stop() @safe {}
  /// Terminó la firma de un documento en la ventana.
  void documentSigned(Document document) @safe {}
}

/// Nombres de todos los plugins que existen, para el panel de configuración.
immutable string[] knownPluginNames = [dummyPluginName, checkUpdatePluginName, documentSignLogsPluginName,
  installerPluginName];

/// Crea un plugin por su nombre; null si no existe.
Plugin createPlugin(string name, GuiInterface gui) @safe {
  switch (name) {
    case dummyPluginName: return new DummyPlugin;
    case checkUpdatePluginName: return new CheckUpdatePlugin(gui);
    case documentSignLogsPluginName: return new DocumentSignLogs;
    case installerPluginName: return new InstallerPlugin;
    default: return null;
  }
}

/// Plugins activos y su ciclo de vida (PluginManager).
final class PluginManager {
  private GuiInterface gui;
  private Plugin[] plugins_;

  this(GuiInterface gui) @safe {
    this.gui = gui;
  }

  /// Carga y arranca los plugins activos de la configuración; los desconocidos se registran como error.
  void load(const Settings settings) @trusted {
    foreach (name; settings.activePlugins.dup) {
      auto plugin = createPlugin(name, gui);
      if (plugin is null) {
        error("Error al cargar plugin (no existe): ", name);
        continue;
      }
      synchronized (this) plugins_ ~= plugin;
      try {
        plugin.start();
      } catch (Exception exception) {
        error("Error al iniciar el plugin ", name, ": ", exception.msg);
      }
    }
  }

  /// Plugins cargados.
  Plugin[] plugins() @trusted {
    synchronized (this) return plugins_.dup;
  }

  void startLogging() @safe {
    foreach (plugin; plugins()) plugin.startLogging();
  }

  void stop() @safe {
    foreach (plugin; plugins()) {
      try {
        plugin.stop();
      } catch (Exception exception) {
        error("Error al detener el plugin ", plugin.name, ": ", exception.msg);
      }
    }
  }

  /// Avisa a los plugins que terminó la firma de un documento (registerDocument + signDone).
  void documentSigned(Document document) @safe {
    foreach (plugin; plugins()) {
      try {
        plugin.documentSigned(document);
      } catch (Exception exception) {
        error("El plugin ", plugin.name, " falló al registrar la firma de ", document.name, ": ", exception.msg);
      }
    }
  }
}

/// Deja en la bitácora los datos del sistema y la versión (DummyPlugin).
final class DummyPlugin : Plugin {
  override string name() const @safe { return dummyPluginName; }

  override void start() @safe {
    info("Starting DummyPlugin");
  }

  override void startLogging() @safe {
    info(systemReport());
  }

  override void stop() @safe {
    info("Stopping DummyPlugin");
  }
}

/// Datos del sistema para la bitácora: sistema, arquitectura, compilador y versión.
string systemReport() @safe {
  import std.process : environment;
  auto output = appender!string;
  output ~= format("os.name - %s\n", os);
  output ~= format("os.arch - %s\n", size_t.sizeof == 8 ? "64" : "32");
  output ~= format("cpu.endian - %s\n", endian);
  output ~= format("user.language - %s\n", environment.get("LANG", ""));
  output ~= format("compiler - %s %d.%03d\n", __VENDOR__, __VERSION__ / 1000, __VERSION__ % 1000);
  output ~= format("firmador.libre.version - %s\n", firmadorVersion);
  return output[];
}

/// Quita el propio plugin de la configuración tras la instalación (InstallerPlugin).
final class InstallerPlugin : Plugin {
  override string name() const @safe { return installerPluginName; }

  override void start() @trusted {
    auto settings = currentSettings();
    settings.activePlugins = settings.activePlugins.remove!(entry => entry == installerPluginName);
    settings.availablePlugins = settings.availablePlugins.remove!(entry => entry == installerPluginName);
    writeSettings(settings, true);
  }
}

/// Campo CSV, entre comillas si lleva comas, comillas o saltos de línea (RFC 4180).
string csvField(string value) pure @safe {
  import std.array : replace;
  if (!value.canFind(',') && !value.canFind('"') && !value.canFind('\n') && !value.canFind('\r')) return value;
  return `"` ~ value.replace(`"`, `""`) ~ `"`;
}

/// Línea de signlog.csv: fecha, documento original, documento firmado y credencial.
string signLogLine(string date, string original, string signed, string card) pure @safe {
  return [csvField(date), csvField(original), csvField(signed), csvField(card)].join(",") ~ "\n";
}

/// Registra cada firma hecha en la ventana en signlog.csv (DocumentSignLogs).
final class DocumentSignLogs : Plugin {
  private static __gshared Mutex fileLock;

  shared static this() {
    fileLock = new Mutex;
  }

  override string name() const @safe { return documentSignLogsPluginName; }

  override void documentSigned(Document document) @trusted {
    auto card = document.usedCard();
    if (card is null || document.signedWithErrors()) return;
    auto settings = document.settings();
    string date = formatJavaDate(settings.dateFormat, Clock.currTime.toOtherTZ(costaRicaTimeZone()), DateLanguage.spanish);
    string line = signLogLine(date, document.pathname, document.pathToSave, card.displayInfo);
    string path = buildPath(configDirectory(), "signlog.csv");
    fileLock.lock();
    scope (exit) fileLock.unlock();
    withContext("No se pudo registrar la firma en " ~ path, {
      append(path, line);
      info("Firma de ", document.name, " registrada en ", path);
    });
  }
}

@("should quote only the CSV fields that need it when writing the sign log")
unittest {
  assert(signLogLine("01/02/2026 10:00:00 a. m.", "/tmp/a.pdf", "/tmp/a-firmado.pdf", "Ana (0101 vence 2027)")
    == "01/02/2026 10:00:00 a. m.,/tmp/a.pdf,/tmp/a-firmado.pdf,Ana (0101 vence 2027)\n");
  assert(signLogLine("d", `/tmp/a,"b".pdf`, "x", "y") == `d,"/tmp/a,""b"".pdf",x,y` ~ "\n");
}
