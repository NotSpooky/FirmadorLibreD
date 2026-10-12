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
 * Lectura de textos del registro de Windows. Sólo usa druntime, para poder revisarse fuera de
 * Windows con «ldc2 -mtriple=x86_64-pc-windows-msvc -o-».
 */
module firmador.util.winregistry;

version (Windows):

import core.sys.windows.windef : DWORD, HKEY;
import core.sys.windows.winerror : ERROR_FILE_NOT_FOUND, ERROR_SUCCESS;
import core.sys.windows.winnt : KEY_READ;
import core.sys.windows.winreg : HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, REG_SZ, RegCloseKey, RegOpenKeyExW,
  RegQueryValueExW;
import std.exception : enforce;
import std.format : format;
import std.utf : toUTF16z, toUTF8;

/// Rama del registro donde se busca.
enum RegistryRoot {
  /// HKEY_CURRENT_USER: lo que se instaló para el usuario.
  currentUser,
  /// HKEY_LOCAL_MACHINE: lo que se instaló para todos.
  localMachine,
}

/**
 * Valor de texto (REG_SZ) del registro, en la vista de 64 bits.
 * Params:
 *   root = rama del registro.
 *   key = clave, por ejemplo `Software\Firmador Libre`.
 *   name = nombre del valor.
 * Returns: el texto, o null si la clave o el valor no existen.
 * Throws: Exception si existen pero no se pueden leer o el valor no es texto.
 */
string registryText(RegistryRoot root, string key, string name) @trusted {
  HKEY rootKey = root == RegistryRoot.currentUser ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
  HKEY handle;
  auto opened = RegOpenKeyExW(rootKey, key.toUTF16z, 0, KEY_READ, &handle);
  if (opened == ERROR_FILE_NOT_FOUND) return null;
  enforce(opened == ERROR_SUCCESS, format("No se pudo abrir la clave %s del registro (%s, error %d)", key, root, opened));
  scope (exit) RegCloseKey(handle);
  DWORD type;
  DWORD size;
  auto queried = RegQueryValueExW(handle, name.toUTF16z, null, &type, null, &size);
  if (queried == ERROR_FILE_NOT_FOUND) return null;
  enforce(queried == ERROR_SUCCESS, format("No se pudo leer %s\\%s del registro (%s, error %d)", key, name, root, queried));
  enforce(type == REG_SZ, format("%s\\%s del registro (%s) no es texto, sino del tipo %d", key, name, root, type));
  // Puede no terminar en el carácter nulo: se reserva uno más.
  auto buffer = new wchar[size / wchar.sizeof + 1];
  DWORD bytes = cast(DWORD) (buffer.length * wchar.sizeof);
  queried = RegQueryValueExW(handle, name.toUTF16z, null, &type, buffer.ptr, &bytes);
  enforce(queried == ERROR_SUCCESS, format("No se pudo leer %s\\%s del registro (%s, error %d)", key, name, root, queried));
  size_t length = bytes / wchar.sizeof;
  while (length > 0 && buffer[length - 1] == '\0') length--;
  return toUTF8(buffer[0 .. length]);
}
