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

/// Texto Base64 (estándar, con relleno) de los bytes: el de XMLDSig, XAdES, JAdES y el JSON de Firmador Remoto.
module firmador.util.base64;

/// Los bytes en Base64 estándar con relleno.
string encodeBase64(const(ubyte)[] bytes) pure @safe {
  import std.base64 : Base64;
  return Base64.encode(bytes).idup;
}
