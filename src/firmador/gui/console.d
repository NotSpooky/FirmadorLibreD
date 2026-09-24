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
 * Lo común de los modos sin ventana (firmador.gui.args y firmador.gui.shell): no hay
 * vista previa, lista ni progreso que actualizar, las preguntas al usuario se responden
 * que no (no hay a quién preguntar) y Firmador Remoto no se atiende. También la lectura
 * de un PIN por la entrada estándar sin eco en la terminal.
 */
module firmador.gui.console;

import std.logger : error, info, trace, warning;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.documents.document : Document;
import firmador.gui.guiinterface;
import firmador.remote.slot : RemoteDocumentSlot;
import firmador.settings : Settings;
import firmador.settingsmanager : currentSettings;

/// Base de los modos de consola; cada modo decide cómo informar errores y mensajes.
abstract class ConsoleInterface : GuiInterface {
  /// Los pasos de una firma van a la bitácora (nunca a la salida estándar).
  void nextStep(string message) @safe {
    trace(message);
  }

  Settings currentDocumentSettings() @safe {
    return currentSettings();
  }

  void showNotification(string message, NotificationType type) @safe {
    if (type == NotificationType.error) error(message);
    else if (type == NotificationType.warning) warning(message);
    else info(message);
  }

  bool askConfirmation(string title, string message) @safe {
    info("Sin ventana para preguntar «", title, "»: se responde que no. ", message);
    return false;
  }

  // Sin vista previa, lista ni progreso: no hay nada que actualizar.
  void previewDone(Document document) @safe {}
  void validateDone(Document document) @safe {}
  void signDone(Document document) @safe {}
  void extendsDone(Document document) @safe {}
  void previewAllDone() @safe {}
  void validateAllDone() @safe {}
  void signAllDone() @safe {}
  void clearDone() @safe {}
  void progressStart(string title, string header) @safe {}
  void progressHeader(string header) @safe {}
  void progressUpdate(int percent, string note) @safe {}
  void progressEnd() @safe {}

  /// Firmador Remoto no se atiende sin ventana: las solicitudes se rechazan.
  bool requestRemotePin(CardSignInfo card, string description, immutable(ubyte)[] image) @safe {
    warning("Solicitud de firma remota rechazada: no hay ventana para pedir el PIN");
    return false;
  }

  HostAuthorization askHostAuthorization(string origin) @safe {
    warning("Origen ", origin, " no autorizado: no hay ventana para preguntar");
    return HostAuthorization.denied;
  }

  void loadRemoteDocument(RemoteDocumentSlot slot) @safe {
    warning("Documento remoto ", slot.name, " rechazado: no hay ventana para firmarlo");
    slot.reject();
  }

  void connectionErrors(string connection, string[] errors) @safe {
    error("Errores en la conexión ", connection, ": ", errors);
  }

  void originAuthorized(string origin) @safe {
    info("Origen autorizado: ", origin);
  }
}

/**
 * Lee una línea de la entrada estándar sin búfer, en `buffer`, sin el salto de línea
 * (\n o \r\n). Nada queda en un búfer de la biblioteca de C ni en una cadena inmutable
 * (que no se podrían borrar), ni se roban datos a otro lector de la entrada.
 *
 * Params:
 *   buffer = dónde se lee; si la línea trae un PIN, el llamador lo borra con ceros.
 *   length = cuántos caracteres de `buffer` ocupa la línea.
 * Returns: false si la entrada terminó sin traer nada.
 * Throws: Exception si la línea no cabe en `buffer`; el resto de ella se descarta y
 * `buffer` queda en ceros.
 */
bool readStandardInputLine(char[] buffer, out size_t length) @trusted {
  import std.format : format;
  char character;
  bool received;
  while (readStandardInputByte(character)) {
    received = true;
    if (character == '\n') break;
    if (length == buffer.length) {
      // Se descarta el resto para que no se lea como otra línea.
      while (readStandardInputByte(character) && character != '\n') {}
      buffer[] = '\0';
      length = 0;
      throw new Exception(format("La línea de la entrada estándar supera los %d caracteres", buffer.length));
    }
    buffer[length++] = character;
  }
  if (length && buffer[length - 1] == '\r') length--;
  return received;
}

/**
 * Lee un PIN de la entrada estándar sin búfer (readStandardInputLine), hasta el primer
 * salto de línea o el final de la entrada. Si la entrada es una terminal, pide el PIN
 * por la salida de error y no muestra lo que se escribe. El llamador debe borrar el
 * resultado con ceros.
 *
 * Throws: Exception si el PIN tiene más de `maxLength` caracteres.
 */
char[] readPinFromStandardInput(size_t maxLength) @trusted {
  auto buffer = new char[maxLength];
  scope (exit) buffer[] = '\0';
  size_t length;
  bool terminal = standardInputIsTerminal();
  if (terminal) {
    import std.stdio : stderr;
    stderr.write("PIN: ");
    stderr.flush();
  }
  auto restoreEcho = terminal ? disableEcho() : null;
  scope (exit) {
    if (restoreEcho !is null) {
      restoreEcho();
      import std.stdio : stderr;
      stderr.writeln();
    }
  }
  readStandardInputLine(buffer, length);
  return buffer[0 .. length].dup;
}

/// La entrada estándar es una terminal (System.console().isTerminal()).
private bool standardInputIsTerminal() @trusted {
  version (Posix) {
    import core.sys.posix.unistd : isatty, STDIN_FILENO;
    return isatty(STDIN_FILENO) == 1;
  } else version (Windows) {
    import core.sys.windows.windows : GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE;
    uint mode;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) != 0;
  }
}

/// Apaga el eco de la terminal; devuelve cómo restaurarlo (null si no se pudo).
private void delegate() @trusted disableEcho() @trusted {
  version (Posix) {
    import core.sys.posix.termios : ECHO, TCSANOW, tcgetattr, tcsetattr, termios;
    import core.sys.posix.unistd : STDIN_FILENO;
    termios original;
    if (tcgetattr(STDIN_FILENO, &original) != 0) return null;
    termios silent = original;
    silent.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &silent) != 0) return null;
    return () @trusted { tcsetattr(STDIN_FILENO, TCSANOW, &original); };
  } else version (Windows) {
    import core.sys.windows.windows : ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, SetConsoleMode,
      STD_INPUT_HANDLE;
    auto handle = GetStdHandle(STD_INPUT_HANDLE);
    uint original;
    if (!GetConsoleMode(handle, &original)) return null;
    if (!SetConsoleMode(handle, original & ~ENABLE_ECHO_INPUT)) return null;
    return () @trusted { SetConsoleMode(handle, original); };
  }
}

/// Lee un byte de la entrada estándar sin búfer; false al final de la entrada.
private bool readStandardInputByte(out char character) @trusted {
  version (Posix) {
    import core.sys.posix.unistd : read, STDIN_FILENO;
    return read(STDIN_FILENO, &character, 1) == 1;
  } else version (Windows) {
    import core.sys.windows.windows : GetStdHandle, ReadFile, STD_INPUT_HANDLE;
    uint count;
    return ReadFile(GetStdHandle(STD_INPUT_HANDLE), &character, 1, &count, null) != 0 && count == 1;
  }
}
