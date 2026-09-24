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
 * Codificación PNG de las páginas rasterizadas (ImageIO.write en la versión Java): RGB de
 * 8 bits sin entrelazar, filas sin filtro y comprimidas con zlib (std.zlib). La usa la
 * vista previa del modo shell (firmador.gui.shell).
 */
module firmador.util.png;

import std.bitmanip : nativeToBigEndian;
import std.digest.crc : crc32Of;
import std.exception : enforce;
import std.format : format;
import std.zlib : compress;

import firmador.pdf.engine : PageRaster;

/**
 * PNG de una imagen RGB.
 *
 * Throws: Exception si las dimensiones no corresponden a los píxeles.
 */
immutable(ubyte)[] encodePng(const PageRaster raster) @trusted {
  enforce(raster.width > 0 && raster.height > 0, format("Dimensiones de imagen no válidas: %dx%d", raster.width,
    raster.height));
  size_t stride = cast(size_t) raster.width * 3;
  enforce(raster.rgb.length == stride * raster.height, format("La imagen de %dx%d trae %d bytes en lugar de %d",
    raster.width, raster.height, raster.rgb.length, stride * raster.height));
  auto scanlines = new ubyte[(stride + 1) * raster.height];
  foreach (row; 0 .. cast(size_t) raster.height) {
    // Byte de filtro 0 (ninguno) al inicio de cada fila.
    scanlines[row * (stride + 1)] = 0;
    scanlines[row * (stride + 1) + 1 .. (row + 1) * (stride + 1)] = raster.rgb[row * stride .. (row + 1) * stride];
  }
  ubyte[] header = nativeToBigEndian(cast(uint) raster.width) ~ nativeToBigEndian(cast(uint) raster.height)[]
    ~ cast(ubyte[]) [8, 2, 0, 0, 0];
  ubyte[] png = cast(ubyte[]) [0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A];
  png ~= chunk("IHDR", header);
  png ~= chunk("IDAT", compress(scanlines, 9));
  png ~= chunk("IEND", null);
  return png.idup;
}

/// Trozo PNG: longitud, tipo, datos y CRC-32 de tipo y datos.
private ubyte[] chunk(string type, const(ubyte)[] data) pure @safe {
  ubyte[] typed = cast(ubyte[]) type.dup ~ data;
  auto crc = crc32Of(typed);
  // crc32Of devuelve el CRC en orden little-endian; PNG lo guarda en big-endian.
  return nativeToBigEndian(cast(uint) data.length)[] ~ typed ~ [crc[3], crc[2], crc[1], crc[0]];
}

@("should produce a PNG that zlib and the chunk CRCs accept when encoding a raster")
unittest {
  import std.bitmanip : bigEndianToNative;
  import std.zlib : uncompress;
  auto raster = PageRaster(2, 1, [255, 0, 0, 0, 0, 255]);
  auto png = encodePng(raster);
  assert(png[0 .. 8] == [0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A]);
  size_t position = 8;
  string[] types;
  ubyte[] idat;
  while (position < png.length) {
    uint length = bigEndianToNative!uint(png[position .. position + 4][0 .. 4]);
    string type = cast(string) png[position + 4 .. position + 8];
    auto data = png[position + 8 .. position + 8 + length];
    auto crc = crc32Of(png[position + 4 .. position + 8 + length]);
    assert(png[position + 8 + length .. position + 12 + length] == [crc[3], crc[2], crc[1], crc[0]]);
    if (type == "IDAT") idat ~= data;
    types ~= type;
    position += 12 + length;
  }
  assert(types == ["IHDR", "IDAT", "IEND"]);
  assert(cast(ubyte[]) uncompress(idat) == [0, 255, 0, 0, 0, 0, 255]);
}
