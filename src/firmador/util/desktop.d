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
 * Abrir enlaces y archivos con el programa del escritorio (java.awt.Desktop en la
 * versión Java): xdg-open en Linux (también dentro de flatpak, por el portal), open en
 * macOS y ShellExecute en Windows. Los procesos se lanzan sin shell y desligados.
 */
module firmador.util.desktop;

import std.algorithm : startsWith;
import std.exception : enforce;
import std.format : format;
import std.logger : error, info;
import std.process : Config, ProcessException, spawnProcess;
import std.string : strip, toLower;

/// Error al abrir un enlace o un archivo.
class DesktopException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/**
 * Programa y argumentos con que se abre un enlace: el navegador preferido si está
 * configurado, si no el del sistema. Sólo se aceptan enlaces http(s), para que un
 * servicio no pueda hacer abrir archivos locales ni otros esquemas.
 *
 * Throws: DesktopException si el enlace no es http(s).
 */
string[] browserCommand(string url, string preferredBrowser) pure @safe {
  string lowered = url.toLower;
  enforce!DesktopException(lowered.startsWith("https://") || lowered.startsWith("http://"),
    format("Sólo se abren enlaces http(s), no «%s»", url));
  if (preferredBrowser.strip.length) return [preferredBrowser.strip, url];
  return systemOpener(url);
}

/// Programa del sistema que abre un enlace o archivo.
private string[] systemOpener(string target) pure nothrow @safe {
  version (OSX) return ["open", target];
  else version (Windows) return [target];
  else return ["xdg-open", target];
}

/**
 * Abre un enlace en el navegador (OpenBrowser).
 *
 * Throws: DesktopException si el enlace no es http(s) o no hay con qué abrirlo.
 */
void openUrl(string url, string preferredBrowser) @trusted {
  launch(browserCommand(url, preferredBrowser), url);
}

/**
 * Abre un archivo o carpeta con su programa asociado (Desktop.open).
 *
 * Throws: DesktopException si no hay con qué abrirlo.
 */
void openPath(string path) @trusted {
  launch(systemOpener(path), path);
}

/**
 * Aviso del escritorio (TrayIcon.displayMessage) cuando la ventana no está a la vista:
 * notify-send en Linux y el centro de notificaciones en macOS. Si no se puede mostrar se
 * registra y se sigue: el aviso también está en la ventana.
 */
void desktopNotification(string title, string message) @trusted {
  import firmador.i18n : htmlToText;
  import std.array : replace;
  string plain = htmlToText(message.replace("<br>", "\n"));
  version (OSX) {
    string escape(string text) { return text.replace("\\", "\\\\").replace("\"", "\\\""); }
    string[] command = ["osascript", "-e", `display notification "` ~ escape(plain) ~ `" with title "` ~ escape(title)
      ~ `"`];
  } else version (Windows) {
    info("Aviso sin ventana visible (Windows no tiene notify-send): ", plain);
    return;
  } else {
    string[] command = ["notify-send", "--app-name=Firmador", title, plain];
  }
  try {
    spawnProcess(command, null, Config.detached);
  } catch (ProcessException exception) {
    info("No se pudo mostrar el aviso del escritorio (", exception.msg, "): ", plain);
  }
}

private void launch(string[] command, string target) @trusted {
  info("Abriendo ", target);
  version (Windows) {
    if (command.length == 1) {
      import core.sys.windows.shellapi : ShellExecuteW;
      import core.sys.windows.winuser : SW_SHOWNORMAL;
      import std.utf : toUTF16z;
      // ShellExecute devuelve un valor mayor que 32 si pudo abrirlo.
      auto result = cast(size_t) ShellExecuteW(null, "open"w.ptr, command[0].toUTF16z, null, null, SW_SHOWNORMAL);
      if (result <= 32) {
        error("No se pudo abrir ", target, ": ShellExecute devolvió ", result);
        throw new DesktopException(format("No se pudo abrir «%s» (ShellExecute devolvió %d)", target, result));
      }
      return;
    }
  }
  try {
    spawnProcess(command, null, Config.detached);
  } catch (ProcessException exception) {
    error("No se pudo abrir ", target, " con ", command[0], ": ", exception.msg);
    throw new DesktopException(format("No se pudo abrir «%s» con %s: %s", target, command[0], exception.msg));
  }
}

@("should refuse non-web links and prefer the configured browser when opening URLs")
unittest {
  import std.exception : assertThrown;
  assert(browserCommand("https://ucr.ac.cr/login", " firefox ") == ["firefox", "https://ucr.ac.cr/login"]);
  assert(browserCommand("HTTPS://ucr.ac.cr", "")[$ - 1] == "HTTPS://ucr.ac.cr");
  assertThrown!DesktopException(browserCommand("file:///etc/passwd", ""));
  assertThrown!DesktopException(browserCommand("javascript:alert(1)", "firefox"));
}
