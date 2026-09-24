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

/// Números aleatorios criptográficamente seguros (RAND_bytes de OpenSSL).
module firmador.crypto.random;

import std.exception : enforce;

import copenssl : RAND_bytes;

/**
 * Llena `length` bytes con el generador seguro de OpenSSL.
 *
 * Throws: Exception si el generador no está sembrado o falla.
 */
ubyte[] secureRandomBytes(size_t length) @trusted {
  auto buffer = new ubyte[length];
  if (length == 0) return buffer;
  enforce(length <= int.max, "Se pidieron demasiados bytes aleatorios de una vez");
  enforce(RAND_bytes(buffer.ptr, cast(int) length) == 1, "El generador aleatorio de OpenSSL no está disponible");
  return buffer;
}

/// Índice aleatorio uniforme en [0, bound) sin sesgo de módulo.
size_t secureRandomIndex(size_t bound) @safe {
  enforce(bound > 0 && bound <= uint.max, "El rango del índice aleatorio debe estar entre 1 y 2^32");
  uint limit = cast(uint) (uint.max - (uint.max % bound));
  while (true) {
    ubyte[] bytes = secureRandomBytes(4);
    uint value = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (cast(uint) bytes[3] << 24);
    if (value < limit) return value % bound;
  }
}

/// Texto aleatorio con caracteres de `alphabet`.
string secureRandomString(size_t length, string alphabet) @safe {
  auto output = new char[length];
  foreach (ref character; output) character = alphabet[secureRandomIndex(alphabet.length)];
  return output.idup;
}

@("should produce values inside the requested bounds when drawing secure random indexes")
unittest {
  foreach (_; 0 .. 200) assert(secureRandomIndex(7) < 7);
  assert(secureRandomBytes(32).length == 32);
  string text = secureRandomString(40, "ab");
  foreach (character; text) assert(character == 'a' || character == 'b');
}
