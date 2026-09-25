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

import std.algorithm : canFind, remove;
import std.array : appender;
import std.datetime.systime : Clock;
import std.file : append;
import std.format : format;
import std.logger : error, info, warning;
import std.meta : staticMap;
import std.path : buildPath;
import std.string : join;
import std.sumtype : match, SumType;
import std.system : endian, os;
import std.typecons : Nullable, nullable;

import core.sync.mutex : Mutex;

import firmador.configuration;
import firmador.documents.document : Document;
import firmador.gui.guiinterface : GuiInterface;
import firmador.logging : withContext;
import firmador.plugins.checkupdate : CheckUpdatePlugin;
import firmador.settings : Settings;
import firmador.settingsmanager : configDirectory, currentSettings, writeSettings;
import firmador.util.datetime : costaRicaTimeZone, DateLanguage, formatJavaDate;

/**
 * Plugin. Cada uno define `name` (con el que se activa en la configuración) y sólo los
 * ganchos que le interesan: start (al cargarlo; los que trabajan en segundo plano
 * arrancan aquí), startLogging (con la interfaz armada y la bitácora lista), stop (al
 * cerrar la aplicación) y documentSigned (terminó la firma de un documento en la ventana).
 */
alias Plugin = SumType!(DummyPlugin, CheckUpdatePlugin, DocumentSignLogs, InstallerPlugin);

/// Nombres de todos los plugins que existen, para el panel de configuración.
immutable string[] knownPluginNames = [staticMap!(nameOf, Plugin.Types)];

private enum nameOf(T) = T.name;

/// Nombre con que se activa el plugin.
string name(Plugin plugin) pure nothrow @safe @nogc {
  return plugin.match!(active => typeof(active).name);
}

/// Llama al gancho `hook` del plugin con `arguments`, si el plugin lo define.
void notify(string hook, Arguments...)(Plugin plugin, Arguments arguments) {
  plugin.match!((active) {
    static if (__traits(hasMember, typeof(active), hook)) __traits(getMember, active, hook)(arguments);
  });
}

/// Crea un plugin por su nombre; nulo si no existe. Los que avisan al usuario reciben `gui`.
Nullable!Plugin createPlugin(string name, GuiInterface gui) pure @safe {
  static foreach (Type; Plugin.Types) {
    if (name == Type.name) {
      static if (is(typeof(Type(gui)))) return nullable(Plugin(Type(gui)));
      else return nullable(Plugin(Type()));
    }
  }
  return Nullable!Plugin.init;
}

/// Plugins activos y su ciclo de vida (PluginManager).
final class PluginManager {
  private GuiInterface gui;
  private Plugin[] plugins_;

  this(GuiInterface gui) pure @safe {
    this.gui = gui;
  }

  /// Carga y arranca los plugins activos de la configuración; los desconocidos se registran como error.
  void load(const Settings settings) @trusted {
    foreach (name; settings.activePlugins.dup) {
      auto created = createPlugin(name, gui);
      if (created.isNull) {
        error("Error al cargar plugin (no existe): ", name);
        continue;
      }
      auto plugin = created.get;
      synchronized (this) plugins_ ~= plugin;
      try {
        plugin.notify!"start"();
      } catch (Exception exception) {
        error("Error al iniciar el plugin ", name, ": ", exception.msg);
      }
    }
  }

  /// Plugins cargados.
  Plugin[] plugins() pure @trusted {
    synchronized (this) return plugins_.dup;
  }

  void startLogging() @safe {
    foreach (plugin; plugins()) plugin.notify!"startLogging"();
  }

  void stop() @safe {
    foreach (plugin; plugins()) {
      try {
        plugin.notify!"stop"();
      } catch (Exception exception) {
        error("Error al detener el plugin ", plugin.name, ": ", exception.msg);
      }
    }
  }

  /// Avisa a los plugins que terminó la firma de un documento (registerDocument + signDone).
  void documentSigned(Document document) @safe {
    foreach (plugin; plugins()) {
      try {
        plugin.notify!"documentSigned"(document);
      } catch (Exception exception) {
        error("El plugin ", plugin.name, " falló al registrar la firma de ", document.name, ": ", exception.msg);
      }
    }
  }
}

/// Deja en la bitácora los datos del sistema y la versión (DummyPlugin).
struct DummyPlugin {
  enum string name = dummyPluginName;

  void start() @safe {
    info("Starting DummyPlugin");
  }

  void startLogging() @safe {
    info(systemReport());
  }

  void stop() @safe {
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
struct InstallerPlugin {
  enum string name = installerPluginName;

  void start() @trusted {
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
struct DocumentSignLogs {
  enum string name = documentSignLogsPluginName;
  private static __gshared Mutex fileLock;

  shared static this() {
    fileLock = new Mutex;
  }

  void documentSigned(Document document) @trusted {
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

@("should create every known plugin by the Java class name stored in config.properties")
unittest {
  assert(knownPluginNames == ["cr.libre.firmador.plugins.DummyPlugin", "cr.libre.firmador.plugins.CheckUpdatePlugin",
    "cr.libre.firmador.plugins.DocumentSignLogs", "cr.libre.firmador.plugins.InstallerPlugin"]);
  foreach (known; knownPluginNames) assert(createPlugin(known, null).get.name == known);
  assert(createPlugin("cr.libre.firmador.plugins.Otro", null).isNull);
}
