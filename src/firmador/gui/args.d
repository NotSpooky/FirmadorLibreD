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
 * Modo -dargs (GUIArgs): firma o sella un documento desde la línea de comandos y termina.
 *
 *   firmador -dargs [-slotN] [-timestamp|-visible-timestamp] <entrada> <salida> [almacen.p12]
 *
 * El PIN se lee de la entrada estándar (sin eco si es una terminal). Sale con 0 si todo
 * fue bien, 1 si hubo errores y 2 si los argumentos no son válidos; los mensajes van a la
 * salida estándar y los errores a la de error.
 */
module firmador.gui.args;

import std.algorithm : startsWith;
import std.conv : ConvException, to;
import std.file : read, write;
import std.format : format;
import std.logger : error, info, warning;
import std.path : absolutePath;
import std.stdio : stderr, stdout;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.cards.detector : createPinOnlyCard, SmartCardDetector;
import firmador.configuration : maxPinLength;
import firmador.documents.document : Document;
import firmador.gui.console;
import firmador.gui.guiinterface : GuiInterface;
import firmador.signers.common : onlineSigningServices, rootCause;
import firmador.signers.pades : timestampPdf;
import firmador.signers.resources : pathFromFileUri;
import firmador.tokens.token : SecretPin;

/// Uso del modo.
enum string argsUsage = "Uso: firmador -dargs [-slotN] [-timestamp|-visible-timestamp] <entrada> <salida> [almacen.p12]";

/// Códigos de salida.
enum ArgsExit : int { ok = 0, failure = 1, usage = 2 }

/// Opciones del modo ya interpretadas.
struct ArgsOptions {
  string input;
  string output;
  /// Almacén PKCS#12 con que firmar (null: la tarjeta).
  string pkcs12;
  /// Ranura PKCS#11 (-1: la de la tarjeta detectada).
  long slot = -1;
  /// Sello de tiempo independiente en lugar de firma (sin PIN).
  bool timestamp;
  bool visibleTimestamp;
  /// Argumentos posicionales que sobran (se ignoran con aviso).
  string[] ignored;
  /// No null si los argumentos no son válidos: el texto que se muestra.
  string usageError;
}

/// Ruta local de un argumento (los lanzadores .desktop con %U entregan URI file://).
string localPathArgument(string argument) pure @safe {
  import std.string : strip;
  string value = argument.strip;
  return value.startsWith("file:") ? pathFromFileUri(value) : value;
}

/**
 * Interpreta los argumentos (setArgs): los que empiezan con «-» son opciones, el resto
 * entrada, salida y almacén en ese orden.
 */
ArgsOptions parseArgsOptions(const string[] arguments) pure @safe {
  ArgsOptions options;
  string[] positional;
  foreach (argument; arguments) {
    if (!argument.startsWith("-")) {
      positional ~= localPathArgument(argument);
    } else if (argument == "-visible-timestamp") {
      options.timestamp = true;
      options.visibleTimestamp = true;
    } else if (argument == "-timestamp") {
      options.timestamp = true;
    } else if (argument.startsWith("-slot")) {
      import std.string : strip;
      try {
        options.slot = argument["-slot".length .. $].strip.to!long;
        if (options.slot < 0) throw new ConvException("negativo");
      } catch (ConvException) {
        options.usageError = "Slot inválido: " ~ argument ~ "\n" ~ argsUsage;
        return options;
      }
    }
  }
  if (positional.length < 2) {
    options.usageError = argsUsage;
    return options;
  }
  options.input = positional[0];
  options.output = positional[1];
  if (positional.length > 2) options.pkcs12 = positional[2];
  if (positional.length > 3) options.ignored = positional[3 .. $];
  return options;
}

/// Interfaz del modo: mensajes a la salida estándar, errores a la de error.
final class ArgsInterface : GuiInterface {
  mixin ConsoleInterface;

  private SmartCardDetector detector;
  private ArgsOptions options;
  private bool hadError;

  this(SmartCardDetector detector, ArgsOptions options) pure @safe {
    this.detector = detector;
    this.options = options;
  }

  void showError(Throwable failure) @trusted {
    hadError = true;
    auto cause = rootCause(failure);
    error("Error en modo -dargs: ", cause.msg);
    stderr.writeln("Excepción: ", typeid(cause).name);
    stderr.writeln("Mensaje: ", cause.msg);
  }

  void showMessage(string message) @trusted {
    stdout.writeln(message);
  }

  void showErrorAlert(string title, string message) @trusted {
    hadError = true;
    error(title, ": ", message);
    stderr.writeln("ERROR: ", title, " - ", message);
  }

  /**
   * Lee el PIN y elige la credencial: el almacén indicado, o el primer dispositivo
   * detectado, o la primera ranura PKCS#11 si no se detecta ninguno (hay tarjetas que no
   * muestran certificados sin iniciar sesión).
   */
  CardSignInfo getPin() @trusted {
    auto password = readPinFromStandardInput(maxPinLength);
    scope (exit) password[] = '\0';
    if (password.length == 0) {
      showError(new Exception("No se recibió ningún PIN por la entrada estándar"));
      return null;
    }
    CardSignInfo card;
    if (options.pkcs12 !is null) {
      auto cards = detector.readPkcs12Cards([options.pkcs12]);
      if (cards.length == 0) {
        showError(new Exception("No se encontró el almacén PKCS#12: " ~ options.pkcs12));
        return null;
      }
      card = cards[0];
    } else {
      CardSignInfo[] cards;
      try {
        cards = detector.readSaveListSmartCard();
      } catch (Exception exception) {
        warning("No se pudieron enumerar los dispositivos de firma: ", exception.msg);
      }
      auto choice = chooseCard(cards, null, true);
      if (choice.kind == CardChoice.Kind.pinOnly) {
        warning("No se detectaron dispositivos; se firmará con el primer slot PKCS#11 disponible");
        card = createPinOnlyCard(null);
      } else {
        card = cards[choice.matches[0]];
        if (cards.length > 1) {
          warning(format("Se detectaron %d dispositivos, se usa el primero: %s", cards.length, card.displayInfo));
        }
      }
    }
    card.pin = new SecretPin(password);
    if (options.slot >= 0) card.slotID = options.slot;
    return card;
  }

  /// Hubo errores informados durante la operación.
  bool failed() const pure @safe {
    return hadError;
  }
}

/**
 * Ejecuta el modo y devuelve el código de salida.
 *
 * Params:
 *   arguments = argumentos de la línea de comandos, sin el programa.
 *   detector = tarjetas (no se monitorean en este modo).
 */
int runArgsMode(const string[] arguments, SmartCardDetector detector) @trusted {
  auto options = parseArgsOptions(arguments);
  if (options.usageError !is null) {
    stderr.writeln(options.usageError);
    return ArgsExit.usage;
  }
  options.input = absolutePath(options.input);
  options.output = absolutePath(options.output);
  if (options.pkcs12 !is null) options.pkcs12 = absolutePath(options.pkcs12);
  if (options.ignored.length) warning("Se ignoran parámetros posicionales adicionales: ", options.ignored);
  auto gui = new ArgsInterface(detector, options);
  CardSignInfo card;
  scope (exit) if (card !is null) card.destroyPin();
  try {
    immutable(ubyte)[] result;
    if (options.timestamp) {
      // Sello de tiempo independiente: no se firma con la tarjeta ni se pide PIN.
      result = timestampPdf(gui, onlineSigningServices(), cast(immutable(ubyte)[]) read(options.input),
        options.visibleTimestamp);
    } else {
      card = gui.getPin();
      if (card is null) {
        stderr.writeln("ERROR: no hay ningún dispositivo de firma utilizable");
        return ArgsExit.failure;
      }
      result = signWith(new Document(gui, options.input), null, card).signedContent;
    }
    if (result is null) {
      stderr.writeln("ERROR: no se pudo procesar el documento ", options.input);
      return ArgsExit.failure;
    }
    write(options.output, result);
    info("Documento guardado en ", options.output);
    gui.showMessage("Documento guardado satisfactoriamente en " ~ options.output);
    return gui.failed ? ArgsExit.failure : ArgsExit.ok;
  } catch (Exception exception) {
    gui.showError(exception);
    return ArgsExit.failure;
  }
}

@("should read options, positional paths and usage errors like GUIArgs when parsing arguments")
unittest {
  auto options = parseArgsOptions(["-dargs", "-slot2", "-visible-timestamp", "file:///tmp/a%20b.pdf", "salida.pdf",
    "almacen.p12", "extra"]);
  assert(options.usageError is null);
  assert(options.slot == 2 && options.timestamp && options.visibleTimestamp);
  assert(options.input == "/tmp/a b.pdf" && options.output == "salida.pdf" && options.pkcs12 == "almacen.p12");
  assert(options.ignored == ["extra"]);
  assert(parseArgsOptions(["-dargs", "solo.pdf"]).usageError == argsUsage);
  assert(parseArgsOptions(["-slotx", "a", "b"]).usageError.startsWith("Slot inválido: -slotx"));
  assert(parseArgsOptions(["-slot-1", "a", "b"]).usageError !is null);
}
