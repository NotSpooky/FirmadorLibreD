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
 * Punto de entrada (Firmador.java y GUISelector): separa las propiedades de lanzamiento
 * (firmador.launch), instala la bitácora y el llavero del sistema, lee la configuración y
 * elige la interfaz por «-dNOMBRE»: -dargs (firmador.gui.args) y -dshell
 * (firmador.gui.shell) corren en la consola sin iniciar la ventana, que es lo demás
 * (firmador.gui.desktop.window) con dlangui.
 *
 *   firmador [--background] [documento…]
 *   firmador -dargs [-slotN] [-timestamp|-visible-timestamp] <entrada> <salida> [almacen.p12]
 *   firmador -dshell
 */
module firmador.app;

import std.algorithm : filter, startsWith;
import std.array : array;
import std.logger : error, info, warning;

import firmador.cards.detector : SmartCardDetector;
import firmador.configuration : checkUpdatePluginName, firmadorVersion;
import firmador.connections.passwordprovider : systemCredentialStore;
import firmador.gui.args : localPathArgument, runArgsMode;
import firmador.gui.console : ConsoleInterface;
import firmador.gui.guiinterface : GuiInterface;
import firmador.gui.shell : runShellMode;
import firmador.launch : extractLaunchProperties, setLaunchProperties;
import firmador.logging : configureLogging;
import firmador.plugins.plugin : PluginManager;
import firmador.settings : Settings;
import firmador.settingsmanager : currentSettings, setSecureCredentialStore;

/// Interfaz pedida con «-dNOMBRE» (la última gana); «swing» o ninguna es la ventana.
string interfaceName(const string[] arguments) pure @safe {
  string name = "swing";
  foreach (argument; arguments) if (argument.startsWith("-d")) name = argument[2 .. $];
  return name;
}

/// Documentos pasados a la ventana: los argumentos que no son opciones (getFileArgs).
string[] windowFileArguments(const string[] arguments) pure @safe {
  string[] files;
  foreach (argument; arguments) if (!argument.startsWith("-")) files ~= localPathArgument(argument);
  return files;
}

/// Argumentos sin propiedades de lanzamiento, para la ventana (UIAppMain los recibe de dlangui).
private __gshared string[] windowArguments;

version (unittest) {
} else {
  int main(string[] arguments) {
    string[] remaining;
    setLaunchProperties(extractLaunchProperties(arguments.length ? arguments[1 .. $] : null, remaining));
    configureLogging("WARNING");
    info("Firmador ", firmadorVersion);
    setSecureCredentialStore(systemCredentialStore());
    auto settings = currentSettings();
    string mode = interfaceName(remaining);
    if (mode == "args" || mode == "shell") {
      attachParentConsole();
      auto detector = new SmartCardDetector;
      scope (exit) detector.shutdown();
      loadConsolePlugins(settings);
      return mode == "args" ? runArgsMode(remaining, detector) : runShellMode(detector);
    }
    if (mode != "swing") warning("Interfaz desconocida «", mode, "»: se usa la ventana");
    windowArguments = remaining;
    version (OSX) {
      // Antes de iniciar la ventana, para no perder el enlace con que se lanzó.
      import firmador.gui.desktop.macurl : installUrlHandler;
      installUrlHandler();
    }
    return startWindowToolkit(arguments);
  }
}

/**
 * Plugins en los modos de consola: los que no necesitan ventana (el aviso de
 * actualización pregunta al usuario, y en consola ensuciaría la salida de los scripts).
 */
private void loadConsolePlugins(Settings settings) {
  auto consoleSettings = new Settings(settings);
  consoleSettings.activePlugins = settings.activePlugins.filter!(name => name != checkUpdatePluginName).array;
  auto plugins = new PluginManager(new PluginConsole);
  plugins.load(consoleSettings);
  plugins.startLogging();
}

/// Interfaz mínima para los plugins de los modos de consola: todo va a la bitácora.
private final class PluginConsole : GuiInterface {
  mixin ConsoleInterface;

  import firmador.cards.cardinfo : CardSignInfo;

  void showError(Throwable failure) @safe {
    error(failure.msg);
  }

  void showMessage(string message) @safe {
    info(message);
  }

  void showErrorAlert(string title, string message) @safe {
    error(title, ": ", message);
  }

  CardSignInfo getPin() pure @safe {
    return null;
  }
}

/**
 * En Windows el ejecutable es de ventana (lflags-windows en dub.json): los modos de consola
 * se enganchan a la consola de quien los lanzó para leer el PIN y escribir el resultado.
 * Las entradas y salidas que ya vienen redirigidas (tuberías o archivos de otro programa)
 * se respetan; sólo las que no tienen destino pasan a la consola.
 *
 * Throws: Exception si no se puede abrir la consola para una de ellas.
 */
private void attachParentConsole() @trusted {
  version (Windows) {
    import core.stdc.stdio : freopen, stderr, stdin, stdout;
    import core.sys.windows.windows : AttachConsole, FILE_TYPE_UNKNOWN, GetFileType, GetStdHandle,
      STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE;
    import std.exception : enforce;
    import std.typecons : tuple;
    enum uint attachParentProcess = cast(uint) -1;
    auto streams = [
      tuple(STD_INPUT_HANDLE, "entrada", "CONIN$", "r", stdin),
      tuple(STD_OUTPUT_HANDLE, "salida", "CONOUT$", "w", stdout),
      tuple(STD_ERROR_HANDLE, "salida de errores", "CONOUT$", "w", stderr),
    ];
    auto redirected = new bool[streams.length];
    foreach (index, stream; streams) redirected[index] = GetFileType(GetStdHandle(stream[0])) != FILE_TYPE_UNKNOWN;
    if (!AttachConsole(attachParentProcess)) return;
    foreach (index, stream; streams) {
      if (redirected[index]) continue;
      enforce(freopen(stream[2].ptr, stream[3].ptr, stream[4]) !is null,
        "No se pudo conectar la " ~ stream[1] ~ " estándar a la consola (" ~ stream[2] ~ ")");
    }
  }
}

/// Inicia dlangui, que llama a UIAppMain cuando la plataforma está lista.
private int startWindowToolkit(string[] arguments) @trusted {
  version (Windows) {
    import core.sys.windows.windows : GetCommandLineA, GetModuleHandleW, SW_SHOWNORMAL;
    import dlangui.platforms.common.platform : DLANGUIWinMain;
    return DLANGUIWinMain(GetModuleHandleW(null), null, GetCommandLineA(), SW_SHOWNORMAL);
  } else {
    import dlangui.platforms.common.platform : DLANGUImain;
    return DLANGUImain(arguments);
  }
}

/// Ventana: la arma, carga los plugins y atiende sus eventos hasta que se cierre.
extern (C) int UIAppMain(string[] toolkitArguments) {
  import dlangui.core.logger : Log, ToolkitLogLevel = LogLevel;
  import dlangui.platforms.common.platform : Platform;
  import firmador.gui.desktop.uithread : reportUiFailure;
  import firmador.gui.desktop.window : DesktopInterface;
  // La bitácora de dlangui es muy detallada; sus avisos y errores siguen apareciendo.
  Log.setLogLevel(ToolkitLogLevel.Warn);
  bool background;
  foreach (argument; windowArguments) if (argument.startsWith("--background")) background = true;
  try {
    import firmador.gui.desktop.theme : applyTheme;
    auto settings = currentSettings();
    applyTheme(settings.themeMode, settings.uiFontSize);
  } catch (Exception exception) {
    error("No se pudo aplicar el tema de la ventana: ", exception.msg);
    return 1;
  }
  auto detector = new SmartCardDetector;
  auto desktop = new DesktopInterface(detector, null, background);
  auto plugins = new PluginManager(desktop);
  desktop.plugins = plugins;
  try {
    if (!desktop.open(windowFileArguments(windowArguments))) {
      info("Ya había una instancia de Firmador en ejecución; se le pasó el pedido");
      return 0;
    }
  } catch (Exception exception) {
    error("No se pudo abrir la ventana: ", exception.msg);
    return 1;
  }
  plugins.load(currentSettings());
  version (OSX) {
    import firmador.gui.desktop.macurl : setUrlTarget;
    setUrlTarget((string origin) => desktop.handleRemoteLaunch(origin));
  }
  // dlangui no atrapa los errores de los eventos (clics, teclas): uno sin atrapar sale del
  // ciclo de eventos, que se informa y se retoma. Los Error (fallos internos) sí lo cierran.
  int result;
  while (true) {
    try {
      result = Platform.instance.enterMessageLoop();
      break;
    } catch (Exception exception) {
      reportUiFailure("Error al atender un evento de la ventana", exception);
    }
  }
  // Lo que quedó sin referencias se libera ahora, mientras dlangui (y FreeType) siguen
  // activos: sus destructores no pueden correr después de que dlangui se cierre.
  import core.memory : GC;
  desktop = null;
  plugins = null;
  GC.collect();
  return result;
}

@("should pick the last -d interface and keep only document arguments for the window")
unittest {
  assert(interfaceName(["-dargs", "a.pdf", "b.pdf"]) == "args");
  assert(interfaceName(["a.pdf"]) == "swing");
  assert(interfaceName(["-dshell", "-dargs"]) == "args");
  assert(windowFileArguments(["--background", "file:///tmp/a%20b.pdf", "-dswing", "c.pdf"])
    == ["/tmp/a b.pdf", "c.pdf"]);
}
