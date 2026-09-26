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
 * Archivos ZIP en memoria para los contenedores ASiC, OpenDocument y OOXML. La lectura
 * usa el directorio de std.zip (que ya rechaza entradas superpuestas) pero descomprime con
 * zlib hasta el tamaño declarado, comprueba el CRC, rechaza nombres repetidos o con rutas
 * peligrosas y limita entradas y bytes (configuration.maxZipEntries y maxZipExpandedBytes).
 */
module firmador.util.zip;

import std.algorithm : canFind, sort;
import std.datetime.systime : SysTime;
import std.digest.crc : crc32Of;
import std.exception : basicExceptionCtors, enforce;
import std.format : format;
import std.zip : ArchiveMember, CompressionMethod, ZipArchive, ZipException;

import etc.c.zlib;

import firmador.configuration : maxZipEntries, maxZipExpandedBytes;

/// El ZIP no se puede leer o no cumple los límites.
class ZipFormatException : Exception {
  mixin basicExceptionCtors;
}

/// Entrada de un ZIP.
struct ZipEntry {
  string name;
  immutable(ubyte)[] content;
  /// Se guarda sin comprimir (el mimetype de ASiC y OpenDocument).
  bool stored;
}

/// El nombre es una ruta relativa segura dentro del archivo.
bool isSafeEntryName(string name) pure @safe {
  if (name.length == 0 || name[0] == '/' || name.canFind('\\') || name.canFind('\0')) return false;
  if (name.length > 1 && name[1] == ':') return false;
  foreach (part; splitPath(name)) if (part == "..") return false;
  return true;
}

private string[] splitPath(string name) pure @safe {
  import std.array : split;
  return name.split("/");
}

/**
 * Descomprime deflate crudo sin pasar de `expectedSize` bytes.
 *
 * Throws: ZipFormatException si los datos no son deflate o no miden lo declarado.
 */
private immutable(ubyte)[] inflateBounded(const(ubyte)[] compressed, size_t expectedSize, string name) @trusted {
  z_stream stream;
  enforce!ZipFormatException(inflateInit2(&stream, -15) == Z_OK, "zlib no pudo iniciar la descompresión");
  scope (exit) inflateEnd(&stream);
  // Un byte de más para detectar entradas que descomprimen más de lo que declaran.
  auto output = new ubyte[expectedSize + 1];
  stream.next_in = cast(ubyte*) compressed.ptr;
  stream.avail_in = cast(uint) compressed.length;
  stream.next_out = output.ptr;
  stream.avail_out = cast(uint) output.length;
  int status = inflate(&stream, Z_FINISH);
  enforce!ZipFormatException(status == Z_STREAM_END && stream.total_out == expectedSize,
    format("La entrada «%s» del ZIP está dañada o no mide lo que declara", name));
  return cast(immutable(ubyte)[]) output[0 .. expectedSize];
}

/**
 * Lee todas las entradas del ZIP en el orden del directorio central.
 *
 * Throws: ZipFormatException con el motivo si no es un ZIP válido, tiene nombres
 * repetidos o peligrosos, un CRC que no coincide o pasa los límites.
 */
ZipEntry[] readZip(const(ubyte)[] data) @trusted {
  ZipArchive archive;
  try {
    archive = new ZipArchive(cast(void[]) data.dup);
  } catch (ZipException exception) {
    throw new ZipFormatException("El archivo no es un ZIP válido: " ~ exception.msg);
  }
  ArchiveMember[] members = archive.directory.values;
  members.sort!((a, b) => a.index < b.index);
  enforce!ZipFormatException(members.length <= maxZipEntries,
    format("El ZIP tiene %d entradas; el máximo es %d", members.length, maxZipEntries));
  // std.zip indexa por nombre: si falta algún índice, dos entradas tenían el mismo nombre.
  foreach (position, member; members) {
    enforce!ZipFormatException(member.index == position, "El ZIP tiene entradas con el mismo nombre");
  }
  ZipEntry[] entries;
  size_t total;
  foreach (member; members) {
    enforce!ZipFormatException(isSafeEntryName(member.name), format("Nombre de entrada no permitido: «%s»", member.name));
    enforce!ZipFormatException((member.flags & 1) == 0, format("La entrada «%s» está cifrada", member.name));
    total += member.expandedSize;
    enforce!ZipFormatException(total <= maxZipExpandedBytes, "El ZIP descomprimido pasa el máximo permitido");
    ZipEntry entry;
    entry.name = member.name;
    auto compressed = cast(const(ubyte)[]) member.compressedData;
    switch (member.compressionMethod) {
      case CompressionMethod.none:
        enforce!ZipFormatException(compressed.length == member.expandedSize,
          format("La entrada «%s» no mide lo que declara", member.name));
        entry.content = compressed.idup;
        entry.stored = true;
        break;
      case CompressionMethod.deflate:
        entry.content = inflateBounded(compressed, member.expandedSize, member.name);
        break;
      default:
        throw new ZipFormatException(format("La entrada «%s» usa una compresión no admitida", member.name));
    }
    auto crc = crc32Of(entry.content);
    uint computed = crc[0] | (crc[1] << 8) | (crc[2] << 16) | (crc[3] << 24);
    enforce!ZipFormatException(computed == member.crc32, format("El CRC de la entrada «%s» no coincide", member.name));
    entries ~= entry;
  }
  return entries;
}

/// El contenido empieza como un ZIP (firma de cabecera local).
bool looksLikeZip(const(ubyte)[] data) pure nothrow @safe @nogc {
  return data.length >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4;
}

/**
 * Escribe un ZIP con las entradas en el orden dado, con la fecha `time`.
 *
 * Throws: ZipFormatException si hay nombres repetidos o no permitidos.
 */
immutable(ubyte)[] writeZip(const ZipEntry[] entries, SysTime time) @trusted {
  auto archive = new ZipArchive();
  string[] names;
  foreach (position, entry; entries) {
    enforce!ZipFormatException(isSafeEntryName(entry.name), format("Nombre de entrada no permitido: «%s»", entry.name));
    enforce!ZipFormatException(!names.canFind(entry.name), format("Entrada repetida en el ZIP: «%s»", entry.name));
    names ~= entry.name;
    auto member = new ArchiveMember();
    member.name = entry.name;
    member.expandedData(entry.content.dup);
    member.compressionMethod = entry.stored ? CompressionMethod.none : CompressionMethod.deflate;
    member.time(time);
    member.index = cast(uint) position;
    archive.addMember(member);
  }
  return cast(immutable(ubyte)[]) archive.build().idup;
}

/// Contenido de la entrada con ese nombre, o null.
immutable(ubyte)[] entryContent(const ZipEntry[] entries, string name) pure nothrow @safe @nogc {
  foreach (entry; entries) if (entry.name == name) return entry.content;
  return null;
}

@("should round-trip entries in order with the mimetype stored when writing and reading containers")
unittest {
  import std.datetime.systime : Clock;
  ZipEntry[] entries = [
    ZipEntry("mimetype", cast(immutable(ubyte)[]) "application/vnd.etsi.asic-e+zip", true),
    ZipEntry("documento.pdf", cast(immutable(ubyte)[]) "%PDF-1.7 contenido repetido contenido repetido"),
    ZipEntry("META-INF/manifest.xml", cast(immutable(ubyte)[]) "<manifest/>"),
  ];
  auto zip = writeZip(entries, Clock.currTime);
  assert(looksLikeZip(zip));
  // El mimetype va primero y sin comprimir, legible en el desplazamiento 30 (ASiC §A.1).
  assert(cast(string) zip[30 .. 38] == "mimetype");
  auto read = readZip(zip);
  assert(read.length == 3);
  assert(read[0].name == "mimetype" && read[0].stored);
  assert(read[1].content == entries[1].content && !read[1].stored);
  assert(entryContent(read, "META-INF/manifest.xml") == entries[2].content);
}

@("should reject path traversal and absolute names when reading untrusted archives")
unittest {
  assert(!isSafeEntryName("../fuera.txt"));
  assert(!isSafeEntryName("/etc/passwd"));
  assert(!isSafeEntryName("a/../../b"));
  assert(!isSafeEntryName("C:/Windows"));
  assert(isSafeEntryName("META-INF/signatures001.xml"));
  import std.exception : assertThrown;
  assertThrown!ZipFormatException(readZip(cast(const(ubyte)[]) "no es un zip"));
}
