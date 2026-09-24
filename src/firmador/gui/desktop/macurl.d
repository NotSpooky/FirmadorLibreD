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
 * Enlaces firmador: en macOS (Desktop.setOpenURIHandler en la versión Java). macOS no
 * pasa el enlace como argumento: lo entrega como evento Apple «GURL» al proceso, esté
 * recién lanzado o ya abierto. El manejador se instala antes de iniciar la ventana, para
 * no perder el del lanzamiento; los enlaces que lleguen antes de que la ventana esté lista
 * se guardan y se entregan al registrarla. Requiere CFBundleURLTypes con el esquema
 * «firmador» en el Info.plist del paquete.
 */
module firmador.gui.desktop.macurl;

version (OSX):

import core.sync.mutex : Mutex;
import std.logger : error, info;

import firmador.launch : remoteOriginFromUrl;

private extern (C) nothrow @nogc {
  struct AEDesc {
    uint descriptorType;
    void* dataHandle;
  }

  alias AEEventHandler = short function(const(AEDesc)* event, AEDesc* reply, void* reference);
  short AEInstallEventHandler(uint eventClass, uint eventId, AEEventHandler handler, void* reference, ubyte system);
  short AEGetParamPtr(const(AEDesc)* event, uint keyword, uint desiredType, uint* actualType, void* data,
    long maximumSize, long* actualSize);
}

/// Código de cuatro letras de los eventos Apple ('GURL', '----', 'utf8').
private uint fourCharCode(string code) pure nothrow @safe @nogc {
  return (cast(uint) code[0] << 24) | (cast(uint) code[1] << 16) | (cast(uint) code[2] << 8) | code[3];
}

private __gshared Mutex handlerLock;
private __gshared void delegate(string origin) target;
private __gshared string[] pending;

shared static this() {
  handlerLock = new Mutex;
}

private extern (C) short handleGetUrl(const(AEDesc)* event, AEDesc* reply, void* reference) nothrow {
  try {
    char[4096] buffer;
    long length;
    uint actualType;
    short status = AEGetParamPtr(event, fourCharCode("----"), fourCharCode("utf8"), &actualType, buffer.ptr,
      buffer.length, &length);
    if (status != 0 || length <= 0 || length > buffer.length) {
      error("No se pudo leer el enlace firmador: recibido (código ", status, ")");
      return status != 0 ? status : -1;
    }
    string origin = remoteOriginFromUrl(buffer[0 .. cast(size_t) length].idup);
    info("Enlace firmador: recibido del sistema");
    void delegate(string) current;
    synchronized (handlerLock) {
      current = target;
      if (current is null) pending ~= origin;
    }
    if (current !is null) current(origin);
    return 0;
  } catch (Exception exception) {
    return -1;
  }
}

/// Instala el manejador de enlaces firmador: (antes de iniciar la ventana).
void installUrlHandler() @trusted {
  short status = AEInstallEventHandler(fourCharCode("GURL"), fourCharCode("GURL"), &handleGetUrl, null, 0);
  if (status != 0) error("No se pudo instalar el manejador de enlaces firmador: (código ", status, ")");
}

/// Registra a quién entregar los enlaces y le pasa los que llegaron antes.
void setUrlTarget(void delegate(string origin) receiver) @trusted {
  string[] waiting;
  synchronized (handlerLock) {
    target = receiver;
    waiting = pending;
    pending = null;
  }
  foreach (origin; waiting) receiver(origin);
}
