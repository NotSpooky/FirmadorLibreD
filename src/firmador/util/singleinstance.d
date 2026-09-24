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
 * Una sola ventana por usuario (SingleInstanceManager, @contract instance-mailbox): la
 * primera instancia toma el candado .firmador.lock del directorio de configuración; las
 * siguientes dejan su pedido en .firmador.command y terminan. La primera lo lee cada dos
 * segundos: SHOW_WINDOW, OPEN_FILE:<ruta> (una línea por archivo), START_FIRMADOR_REMOTE
 * [:<origen>] y CLOSE_REQUEST (el instalador); a este último responde en
 * .firmador.response con REJECTED si el usuario no quiere cerrar.
 */
module firmador.util.singleinstance;

import core.atomic : atomicLoad, atomicStore;
import core.thread : Thread;
import core.time : dur;
import std.algorithm : map, startsWith;
import std.array : array, join, replace;
import std.file : exists, mkdirRecurse, readText, remove, write;
import std.logger : error, info, warning;
import std.path : buildPath;
import std.stdio : File, LockType;
import std.string : lineSplitter, strip;

import firmador.logging : withContext;

/// Pedido para mostrar la ventana.
enum string showWindowCommand = "SHOW_WINDOW";
/// Prefijo del pedido de abrir un archivo.
enum string openFileCommand = "OPEN_FILE:";
/// Pedido de atender un lanzamiento desde el navegador (CMD_START_REMOTE).
enum string startRemoteCommand = "START_FIRMADOR_REMOTE";
/// Pedido del instalador para cerrar la aplicación.
enum string closeRequestCommand = "CLOSE_REQUEST";

/// Pedido interpretado.
struct InstanceCommand {
  enum Kind { none, showWindow, openFile, startRemote, closeRequest }
  Kind kind;
  /// Ruta (openFile) u origen (startRemote, null si no lo trae).
  string argument;
}

/// Interpreta una línea del buzón.
InstanceCommand parseInstanceCommand(string line) pure @safe {
  string command = line.strip;
  if (command == showWindowCommand) return InstanceCommand(InstanceCommand.Kind.showWindow);
  if (command == closeRequestCommand) return InstanceCommand(InstanceCommand.Kind.closeRequest);
  if (command.startsWith(openFileCommand)) {
    string path = command[openFileCommand.length .. $].strip;
    return path.length ? InstanceCommand(InstanceCommand.Kind.openFile, path) : InstanceCommand.init;
  }
  if (command.startsWith(startRemoteCommand)) {
    string rest = command[startRemoteCommand.length .. $].strip;
    string origin = rest.startsWith(":") ? rest[1 .. $].strip : null;
    return InstanceCommand(InstanceCommand.Kind.startRemote, origin.length ? origin : null);
  }
  return InstanceCommand.init;
}

/**
 * Pedido con que arranca una instancia: abrir los archivos indicados, atender el origen
 * que la lanzó (en una sola línea) o mostrar la ventana.
 */
string initialInstanceCommand(const string[] files, string remoteOrigin) pure @safe {
  if (files.length) return files.map!(file => openFileCommand ~ file.replace("\n", " ")).join("\n");
  if (remoteOrigin !is null) return startRemoteCommand ~ ":" ~ remoteOrigin.replace("\n", " ").strip;
  return showWindowCommand;
}

/// Candado y buzón de la instancia.
final class SingleInstance {
  private string directory, lockPath, commandPath, responsePath;
  private File lockFile;
  private bool locked;
  private shared bool watching;

  /// `directory`: el del archivo de configuración.
  this(string directory) @safe {
    this.directory = directory;
    lockPath = buildPath(directory, ".firmador.lock");
    commandPath = buildPath(directory, ".firmador.command");
    responsePath = buildPath(directory, ".firmador.response");
  }

  /**
   * Toma el candado y empieza a leer el buzón, entregando cada pedido a `onCommand`
   * (desde otro hilo). Si otra instancia lo tiene, le deja `command` y devuelve false.
   */
  bool acquire(string command, void delegate(InstanceCommand) onCommand) @trusted {
    withContext("No se pudo tomar el candado de instancia " ~ lockPath, {
      mkdirRecurse(directory);
      lockFile = File(lockPath, "a+");
      locked = lockFile.tryLock(LockType.readWrite);
    });
    if (!locked) {
      info("Ya hay una instancia en ejecución; se le envía el pedido ", command);
      write(commandPath, command);
      return false;
    }
    atomicStore(watching, true);
    auto watcher = new Thread({
      while (atomicLoad(watching)) {
        try {
          if (exists(commandPath)) {
            string pending = readText(commandPath);
            remove(commandPath);
            foreach (line; pending.lineSplitter) {
              auto parsed = parseInstanceCommand(line);
              if (parsed.kind != InstanceCommand.Kind.none) onCommand(parsed);
              else if (line.strip.length) warning("Pedido de instancia desconocido: ", line);
            }
          }
        } catch (Exception exception) {
          warning("No se pudo leer el buzón de instancia: ", exception.msg);
        }
        Thread.sleep(dur!"seconds"(2));
      }
    });
    watcher.isDaemon = true;
    watcher.start();
    return true;
  }

  /// Le responde al instalador que el usuario no quiso cerrar.
  void signalCloseRejected() @trusted {
    try {
      write(responsePath, "REJECTED");
    } catch (Exception exception) {
      error("No se pudo responder al instalador: ", exception.msg);
    }
  }

  /// Suelta el candado y borra el buzón (al cerrar).
  void release() @trusted {
    atomicStore(watching, false);
    if (!locked) return;
    try {
      lockFile.unlock();
      lockFile.close();
      foreach (path; [lockPath, commandPath, responsePath]) if (exists(path)) remove(path);
    } catch (Exception exception) {
      warning("No se pudo soltar el candado de instancia: ", exception.msg);
    }
    locked = false;
  }
}

@("should read every mailbox command and build the startup command like the Java version")
unittest {
  assert(parseInstanceCommand(" SHOW_WINDOW ").kind == InstanceCommand.Kind.showWindow);
  assert(parseInstanceCommand("OPEN_FILE: /tmp/a b.pdf") == InstanceCommand(InstanceCommand.Kind.openFile,
    "/tmp/a b.pdf"));
  assert(parseInstanceCommand("START_FIRMADOR_REMOTE").argument is null);
  assert(parseInstanceCommand("START_FIRMADOR_REMOTE:https://sitio.cr#3517").argument == "https://sitio.cr#3517");
  assert(parseInstanceCommand("OTRA").kind == InstanceCommand.Kind.none);
  assert(initialInstanceCommand(["/a.pdf", "/b.pdf"], "x") == "OPEN_FILE:/a.pdf\nOPEN_FILE:/b.pdf");
  assert(initialInstanceCommand(null, "https://sitio.cr\n#3517") == "START_FIRMADOR_REMOTE:https://sitio.cr #3517");
  assert(initialInstanceCommand(null, null) == "SHOW_WINDOW");
}
