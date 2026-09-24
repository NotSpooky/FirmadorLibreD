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
 * Codificación ASN.1: lectura de DER y BER (longitudes indefinidas incluidas, como las que
 * dejan algunos productores de CMS) y escritura de DER. Es la base de firmador.x509,
 * firmador.cms, firmador.cms.tsp y firmador.cms.ocsp.
 */
module firmador.asn1.der;

import std.algorithm : sort;
import std.array : appender, split;
import std.bigint : BigInt;
import std.conv : to, ConvException;
import std.datetime.date : DateTime;
import std.datetime.systime : SysTime;
import std.datetime.timezone : UTC;
import std.exception : enforce;
import std.format : format;
import std.string : indexOf;

/// Error de estructura en datos ASN.1 recibidos.
class Asn1Exception : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// Clase de una etiqueta ASN.1.
enum TagClass : ubyte { universal = 0, application = 1, contextSpecific = 2, privateUse = 3 }

/// Etiquetas universales que se usan en la aplicación.
enum UniversalTag : uint {
  endOfContents = 0,
  boolean = 1,
  integer = 2,
  bitString = 3,
  octetString = 4,
  null_ = 5,
  objectIdentifier = 6,
  enumerated = 10,
  utf8String = 12,
  sequence = 16,
  set = 17,
  numericString = 18,
  printableString = 19,
  t61String = 20,
  ia5String = 22,
  utcTime = 23,
  generalizedTime = 24,
  visibleString = 26,
  universalString = 28,
  bmpString = 30,
}

/// Elemento ASN.1 ya delimitado: `raw` es el TLV completo y `content` el valor.
struct DerElement {
  TagClass tagClass;
  bool constructed;
  uint tagNumber;
  const(ubyte)[] raw;
  const(ubyte)[] content;
  /// El elemento usaba longitud indefinida (BER).
  bool indefiniteLength;

  bool isUniversal(uint number) const pure nothrow @safe @nogc {
    return tagClass == TagClass.universal && tagNumber == number;
  }

  bool isContext(uint number) const pure nothrow @safe @nogc {
    return tagClass == TagClass.contextSpecific && tagNumber == number;
  }

  bool isSequence() const pure nothrow @safe @nogc {
    return isUniversal(UniversalTag.sequence) && constructed;
  }

  bool isSet() const pure nothrow @safe @nogc {
    return isUniversal(UniversalTag.set) && constructed;
  }

  /// Elementos contenidos en un elemento construido.
  DerElement[] children() const pure @safe {
    enforce!Asn1Exception(constructed, format("Se esperaba un elemento construido y llegó la etiqueta %s", describe));
    return parseDerSequenceContent(content);
  }

  /// Recorre los elementos contenidos con campos opcionales (ver DerReader).
  DerReader reader() const pure @safe {
    return DerReader(children());
  }

  /// Texto de la etiqueta para los mensajes de error.
  string describe() const pure @safe {
    string className = ["universal", "aplicación", "contexto", "privada"][tagClass];
    return format("[%s %d]", className, tagNumber);
  }

  /// Contenido de un OCTET STRING, uniendo los fragmentos si venía construido (BER).
  const(ubyte)[] octetStringValue() const pure @safe {
    enforce!Asn1Exception(isUniversal(UniversalTag.octetString) || tagClass != TagClass.universal,
      format("Se esperaba un OCTET STRING y llegó %s", describe));
    if (!constructed) return content;
    auto joined = appender!(ubyte[]);
    foreach (part; children()) joined ~= part.octetStringValue();
    return joined[];
  }

  /// Contenido de un BIT STRING sin el byte de bits sobrantes.
  const(ubyte)[] bitStringBytes() const pure @safe {
    enforce!Asn1Exception(isUniversal(UniversalTag.bitString) && !constructed,
      format("Se esperaba un BIT STRING y llegó %s", describe));
    enforce!Asn1Exception(content.length >= 1, "BIT STRING vacío");
    return content[1 .. $];
  }

  /// Bits de un BIT STRING, el primero en el índice 0 (como KeyUsage en Java).
  bool[] bitStringBits() const pure @safe {
    enforce!Asn1Exception(isUniversal(UniversalTag.bitString) && !constructed && content.length >= 1,
      format("Se esperaba un BIT STRING y llegó %s", describe));
    uint unused = content[0];
    enforce!Asn1Exception(unused < 8, "BIT STRING con bits sobrantes no válidos");
    bool[] bits;
    foreach (byteIndex, value; content[1 .. $]) {
      size_t usable = byteIndex == content.length - 2 ? 8 - unused : 8;
      foreach (bit; 0 .. usable) bits ~= ((value >> (7 - bit)) & 1) != 0;
    }
    return bits;
  }

  /// Valor de un INTEGER como entero grande (complemento a dos).
  BigInt integerValue() const pure @safe {
    enforce!Asn1Exception(isUniversal(UniversalTag.integer) || isUniversal(UniversalTag.enumerated)
      || tagClass == TagClass.contextSpecific, format("Se esperaba un INTEGER y llegó %s", describe));
    return bigIntFromTwosComplement(content);
  }

  /// Valor de un INTEGER pequeño.
  long smallIntegerValue() const pure @safe {
    enforce!Asn1Exception(content.length >= 1 && content.length <= 8,
      format("INTEGER de %d bytes fuera del rango esperado", content.length));
    return integerValue().toLong;
  }

  /// Valor de un BOOLEAN.
  bool booleanValue() const pure @safe {
    enforce!Asn1Exception(isUniversal(UniversalTag.boolean) && content.length == 1,
      format("Se esperaba un BOOLEAN y llegó %s", describe));
    return content[0] != 0;
  }

  /// Identificador de objeto en notación de puntos.
  string oidValue() const pure @safe {
    enforce!Asn1Exception(isUniversal(UniversalTag.objectIdentifier) && !constructed,
      format("Se esperaba un OBJECT IDENTIFIER y llegó %s", describe));
    return decodeOid(content);
  }

  /// Texto de las cadenas ASN.1 (UTF8, Printable, IA5, T61 como Latin-1, BMP, Universal…).
  string stringValue() const pure @safe {
    enforce!Asn1Exception(tagClass == TagClass.universal && !constructed,
      format("Se esperaba una cadena y llegó %s", describe));
    switch (tagNumber) {
      case UniversalTag.utf8String:
        import std.utf : validate;
        string text = cast(string) content.idup;
        validate(text);
        return text;
      case UniversalTag.printableString, UniversalTag.ia5String, UniversalTag.visibleString,
          UniversalTag.numericString:
        return cast(string) content.idup;
      case UniversalTag.t61String:
        return latin1ToUtf8(content);
      case UniversalTag.bmpString:
        return utf16BigEndianToUtf8(content);
      case UniversalTag.universalString:
        return utf32BigEndianToUtf8(content);
      default:
        throw new Asn1Exception(format("La etiqueta %s no es una cadena de texto", describe));
    }
  }

  /// Fecha de un UTCTime o GeneralizedTime.
  SysTime timeValue() const @safe {
    if (isUniversal(UniversalTag.utcTime)) return parseUtcTime(cast(string) content.idup);
    if (isUniversal(UniversalTag.generalizedTime)) return parseGeneralizedTime(cast(string) content.idup);
    throw new Asn1Exception(format("Se esperaba una fecha y llegó %s", describe));
  }
}

/// Recorrido de los hijos de un SEQUENCE con campos opcionales.
struct DerReader {
  DerElement[] elements;
  size_t position;

  bool empty() const pure nothrow @safe @nogc {
    return position >= elements.length;
  }

  /// Siguiente elemento, obligatorio.
  DerElement next(string what) pure @safe {
    enforce!Asn1Exception(!empty, format("Falta %s en la estructura ASN.1", what));
    return elements[position++];
  }

  /// Siguiente elemento si tiene esa etiqueta de contexto (campo OPTIONAL [n]).
  bool nextContext(uint number, out DerElement element) pure @safe {
    if (!empty && elements[position].isContext(number)) {
      element = elements[position++];
      return true;
    }
    return false;
  }

  /// Siguiente elemento si tiene esa etiqueta universal.
  bool nextUniversal(uint number, out DerElement element) pure @safe {
    if (!empty && elements[position].isUniversal(number)) {
      element = elements[position++];
      return true;
    }
    return false;
  }

  /// Comprueba que no queden elementos sin interpretar.
  void finish(string what) const pure @safe {
    enforce!Asn1Exception(empty, format("Sobran elementos al final de %s", what));
  }
}

/// AlgorithmIdentifier (RFC 5280): el OID y, si no son un NULL, los parámetros codificados.
struct AlgorithmIdentifier {
  string oid;
  immutable(ubyte)[] parameters;
}

/**
 * Lee un AlgorithmIdentifier de un documento que no es de confianza.
 *
 * Params:
 *   element = la SEQUENCE del algoritmo.
 *   what = qué algoritmo es, para el mensaje de error.
 * Returns: el OID y los parámetros (vacíos si faltan o son un NULL).
 * Throws: Asn1Exception si no trae el OID o trae campos de más.
 */
AlgorithmIdentifier parseAlgorithmIdentifier(const DerElement element, string what) pure @safe {
  auto fields = element.children();
  enforce!Asn1Exception(fields.length == 1 || fields.length == 2,
    format("%s no es un AlgorithmIdentifier válido: tiene %d campos", what, fields.length));
  AlgorithmIdentifier algorithm;
  algorithm.oid = fields[0].oidValue;
  if (fields.length == 2 && !fields[1].isUniversal(UniversalTag.null_)) algorithm.parameters = fields[1].raw.idup;
  return algorithm;
}

/**
 * Lee un elemento al principio de `data` y devuelve cuántos bytes ocupa.
 *
 * Throws: Asn1Exception si la etiqueta, la longitud o el contenido están truncados o
 * mal codificados.
 */
DerElement parseDerElement(const(ubyte)[] data, out size_t consumed, size_t depth = 0) pure @safe {
  enforce!Asn1Exception(depth < 64, "Anidamiento ASN.1 demasiado profundo");
  enforce!Asn1Exception(data.length >= 2, "Elemento ASN.1 truncado");
  DerElement element;
  size_t position = 0;
  ubyte first = data[position++];
  element.tagClass = cast(TagClass) (first >> 6);
  element.constructed = (first & 0x20) != 0;
  uint number = first & 0x1F;
  if (number == 0x1F) {
    number = 0;
    ubyte part;
    size_t count = 0;
    do {
      enforce!Asn1Exception(position < data.length, "Etiqueta ASN.1 truncada");
      part = data[position++];
      enforce!Asn1Exception(++count <= 4, "Etiqueta ASN.1 demasiado grande");
      number = (number << 7) | (part & 0x7F);
    } while (part & 0x80);
  }
  element.tagNumber = number;
  enforce!Asn1Exception(position < data.length, "Longitud ASN.1 truncada");
  ubyte lengthByte = data[position++];
  if (lengthByte == 0x80) {
    enforce!Asn1Exception(element.constructed, "Longitud indefinida en un elemento primitivo");
    element.indefiniteLength = true;
    size_t contentStart = position;
    while (true) {
      enforce!Asn1Exception(position + 2 <= data.length, "Falta el fin de contenido de una longitud indefinida");
      if (data[position] == 0 && data[position + 1] == 0) break;
      size_t childLength;
      parseDerElement(data[position .. $], childLength, depth + 1);
      position += childLength;
    }
    element.content = data[contentStart .. position];
    position += 2;
  } else {
    size_t length;
    if (lengthByte & 0x80) {
      size_t lengthBytes = lengthByte & 0x7F;
      enforce!Asn1Exception(lengthBytes <= 4, "Longitud ASN.1 demasiado grande");
      enforce!Asn1Exception(position + lengthBytes <= data.length, "Longitud ASN.1 truncada");
      length = 0;
      foreach (index; 0 .. lengthBytes) length = (length << 8) | data[position++];
    } else {
      length = lengthByte;
    }
    enforce!Asn1Exception(length <= data.length - position,
      format("El contenido ASN.1 %s declara %d bytes y sólo quedan %d", element.describe, length, data.length - position));
    element.content = data[position .. position + length];
    position += length;
  }
  element.raw = data[0 .. position];
  consumed = position;
  return element;
}

/**
 * Lee un único elemento que debe ocupar todos los bytes.
 *
 * Throws: Asn1Exception si no es así.
 */
DerElement parseDer(const(ubyte)[] data) pure @safe {
  size_t consumed;
  auto element = parseDerElement(data, consumed);
  enforce!Asn1Exception(consumed == data.length,
    format("Sobran %d bytes después del elemento ASN.1", data.length - consumed));
  return element;
}

/// Lee los elementos seguidos que forman el contenido de un SEQUENCE o SET.
DerElement[] parseDerSequenceContent(const(ubyte)[] content) pure @safe {
  DerElement[] elements;
  size_t position = 0;
  while (position < content.length) {
    size_t consumed;
    elements ~= parseDerElement(content[position .. $], consumed);
    position += consumed;
  }
  return elements;
}

/// Entero grande a partir de su complemento a dos en big endian.
BigInt bigIntFromTwosComplement(const(ubyte)[] bytes) pure @safe {
  enforce!Asn1Exception(bytes.length > 0, "INTEGER vacío");
  BigInt value = 0;
  foreach (b; bytes) value = value * 256 + b;
  if (bytes[0] & 0x80) value -= BigInt(1) << (8 * bytes.length);
  return value;
}

/// Bytes sin signo de un entero no negativo, sin ceros a la izquierda.
ubyte[] unsignedBytes(BigInt value) pure @safe {
  enforce!Asn1Exception(value >= 0, "Se esperaba un entero no negativo");
  if (value == 0) return [0];
  ubyte[] reversed;
  BigInt remaining = value;
  while (remaining > 0) {
    reversed ~= cast(ubyte) (remaining % 256);
    remaining /= 256;
  }
  ubyte[] bytes;
  foreach_reverse (b; reversed) bytes ~= b;
  return bytes;
}

/// Hexadecimal en minúsculas de un entero no negativo (como BigInteger.toString(16)).
string toHexString(BigInt value) pure @safe {
  if (value < 0) return "-" ~ toHexString(-value);
  import std.ascii : lowerHexDigits;
  if (value == 0) return "0";
  string text;
  BigInt remaining = value;
  while (remaining > 0) {
    text = lowerHexDigits[cast(size_t) (remaining % 16)] ~ text;
    remaining /= 16;
  }
  return text;
}

/// Decimal de un entero grande (como BigInteger.toString()).
string toDecimalString(BigInt value) pure @safe {
  static import std.bigint;
  return std.bigint.toDecimalString(value);
}

/// Notación de puntos de los bytes de un OBJECT IDENTIFIER.
string decodeOid(const(ubyte)[] bytes) pure @safe {
  enforce!Asn1Exception(bytes.length > 0, "OBJECT IDENTIFIER vacío");
  ulong[] arcs;
  ulong value = 0;
  size_t bitsUsed = 0;
  foreach (index, b; bytes) {
    enforce!Asn1Exception(bitsUsed < 56, "Arco de OBJECT IDENTIFIER demasiado grande");
    value = (value << 7) | (b & 0x7F);
    bitsUsed += 7;
    if (!(b & 0x80)) {
      arcs ~= value;
      value = 0;
      bitsUsed = 0;
    } else {
      enforce!Asn1Exception(index + 1 < bytes.length, "OBJECT IDENTIFIER truncado");
    }
  }
  ulong first = arcs[0];
  ulong root = first < 40 ? 0 : first < 80 ? 1 : 2;
  auto text = appender!string;
  text ~= root.to!string;
  text ~= ".";
  text ~= (first - root * 40).to!string;
  foreach (arc; arcs[1 .. $]) {
    text ~= ".";
    text ~= arc.to!string;
  }
  return text[];
}

/// Bytes de un OBJECT IDENTIFIER en notación de puntos.
ubyte[] encodeOidContent(string dotted) pure @safe {
  string[] parts = dotted.split(".");
  enforce!Asn1Exception(parts.length >= 2, format("OID «%s» no válido", dotted));
  ulong[] arcs;
  try {
    foreach (part; parts) arcs ~= part.to!ulong;
  } catch (ConvException) {
    throw new Asn1Exception(format("OID «%s» no válido", dotted));
  }
  enforce!Asn1Exception(arcs[0] <= 2 && (arcs[0] == 2 || arcs[1] < 40), format("OID «%s» no válido", dotted));
  ulong[] values = [arcs[0] * 40 + arcs[1]] ~ arcs[2 .. $];
  ubyte[] bytes;
  foreach (value; values) {
    ubyte[] group = [cast(ubyte) (value & 0x7F)];
    value >>= 7;
    while (value > 0) {
      group = [cast(ubyte) ((value & 0x7F) | 0x80)] ~ group;
      value >>= 7;
    }
    bytes ~= group;
  }
  return bytes;
}

/// UTCTime (AAMMDDHHmm[SS]Z): los años 50-99 son del siglo XX, como indica RFC 5280.
SysTime parseUtcTime(string text) @safe {
  enforce!Asn1Exception((text.length == 13 || text.length == 11) && text[$ - 1] == 'Z',
    format("UTCTime no válido: «%s»", text));
  try {
    int year = text[0 .. 2].to!int;
    year += year < 50 ? 2000 : 1900;
    int second = text.length == 13 ? text[10 .. 12].to!int : 0;
    return SysTime(DateTime(year, text[2 .. 4].to!int, text[4 .. 6].to!int, text[6 .. 8].to!int,
      text[8 .. 10].to!int, second), UTC());
  } catch (Exception exception) {
    throw new Asn1Exception(format("UTCTime no válido: «%s»", text));
  }
}

/// GeneralizedTime (AAAAMMDDHHmmSS[.fff]Z), la forma que exigen RFC 5280 y RFC 3161.
SysTime parseGeneralizedTime(string text) @safe {
  import core.time : dur;
  enforce!Asn1Exception(text.length >= 15 && text[$ - 1] == 'Z', format("GeneralizedTime no válido: «%s»", text));
  try {
    auto base = SysTime(DateTime(text[0 .. 4].to!int, text[4 .. 6].to!int, text[6 .. 8].to!int,
      text[8 .. 10].to!int, text[10 .. 12].to!int, text[12 .. 14].to!int), UTC());
    if (text.length > 15) {
      enforce!Asn1Exception(text[14] == '.' && text.length > 16, format("GeneralizedTime no válido: «%s»", text));
      string fraction = text[15 .. $ - 1];
      foreach (digit; fraction) enforce!Asn1Exception(digit >= '0' && digit <= '9', "Fracción de segundo no válida");
      string micros = (fraction ~ "000000")[0 .. 6];
      base += dur!"usecs"(micros.to!long);
    }
    return base;
  } catch (Asn1Exception exception) {
    throw exception;
  } catch (Exception exception) {
    throw new Asn1Exception(format("GeneralizedTime no válido: «%s»", text));
  }
}

private string latin1ToUtf8(const(ubyte)[] bytes) pure @safe {
  auto text = appender!string;
  foreach (b; bytes) text ~= cast(dchar) b;
  return text[];
}

private string utf16BigEndianToUtf8(const(ubyte)[] bytes) pure @safe {
  import std.utf : toUTF8;
  enforce!Asn1Exception(bytes.length % 2 == 0, "BMPString con longitud impar");
  wchar[] units;
  for (size_t index = 0; index < bytes.length; index += 2) units ~= cast(wchar) ((bytes[index] << 8) | bytes[index + 1]);
  return toUTF8(units);
}

private string utf32BigEndianToUtf8(const(ubyte)[] bytes) pure @safe {
  import std.utf : toUTF8;
  enforce!Asn1Exception(bytes.length % 4 == 0, "UniversalString con longitud no múltiplo de 4");
  dchar[] units;
  for (size_t index = 0; index < bytes.length; index += 4)
    units ~= cast(dchar) ((bytes[index] << 24) | (bytes[index + 1] << 16) | (bytes[index + 2] << 8) | bytes[index + 3]);
  return toUTF8(units);
}

// ---------------------------------------------------------------------------------------
// Escritura DER

/// Bytes de la longitud DER.
ubyte[] encodeLength(size_t length) pure @safe {
  if (length < 0x80) return [cast(ubyte) length];
  ubyte[] bytes;
  size_t remaining = length;
  while (remaining > 0) {
    bytes = [cast(ubyte) (remaining & 0xFF)] ~ bytes;
    remaining >>= 8;
  }
  return [cast(ubyte) (0x80 | bytes.length)] ~ bytes;
}

/// Primer byte de una etiqueta de número pequeño.
ubyte tagByte(TagClass tagClass, bool constructed, uint number) pure @safe {
  enforce!Asn1Exception(number < 31, "Etiquetas de número alto no se escriben");
  return cast(ubyte) ((tagClass << 6) | (constructed ? 0x20 : 0) | number);
}

/// TLV con la etiqueta y el contenido dados.
ubyte[] derTlv(ubyte tag, const(ubyte)[] content) pure @safe {
  return [tag] ~ encodeLength(content.length) ~ content;
}

ubyte[] derSequence(const(ubyte[])[] elements...) pure @safe {
  return derTlv(0x30, joinBytes(elements));
}

/// SET con los elementos en el orden dado (para SET con un solo miembro o ya ordenados).
ubyte[] derSet(const(ubyte[])[] elements...) pure @safe {
  return derTlv(0x31, joinBytes(elements));
}

/// SET OF en DER: los miembros ordenados por su codificación (X.690 11.6).
ubyte[] derSetOf(const(ubyte[])[] elements) pure @safe {
  ubyte[][] sorted;
  foreach (element; elements) sorted ~= element.dup;
  sorted.sort!((a, b) => compareBytes(a, b) < 0);
  return derTlv(0x31, joinBytes(sorted));
}

/// Contenido de un elemento [n] construido (etiquetado explícito o IMPLICIT de un SEQUENCE).
ubyte[] derContextConstructed(uint number, const(ubyte[])[] elements...) pure @safe {
  return derTlv(tagByte(TagClass.contextSpecific, true, number), joinBytes(elements));
}

/// Elemento [n] primitivo (IMPLICIT de un tipo primitivo).
ubyte[] derContextPrimitive(uint number, const(ubyte)[] content) pure @safe {
  return derTlv(tagByte(TagClass.contextSpecific, false, number), content);
}

/// Cambia la etiqueta de un elemento ya codificado (IMPLICIT), conservando si es construido.
ubyte[] derRetag(const(ubyte)[] encoded, TagClass tagClass, uint number) pure @safe {
  auto element = parseDer(encoded);
  return derTlv(tagByte(tagClass, element.constructed, number), element.content);
}

ubyte[] derInteger(long value) pure @safe {
  return derIntegerBig(BigInt(value));
}

ubyte[] derIntegerBig(BigInt value) pure @safe {
  ubyte[] bytes;
  if (value >= 0) {
    bytes = unsignedBytes(value);
    if (bytes[0] & 0x80) bytes = [cast(ubyte) 0] ~ bytes;
  } else {
    size_t length = 1;
    while (-(BigInt(1) << (8 * length - 1)) > value) length++;
    BigInt twos = (BigInt(1) << (8 * length)) + value;
    bytes = unsignedBytes(twos);
    while (bytes.length < length) bytes = [cast(ubyte) 0xFF] ~ bytes;
  }
  return derTlv(0x02, bytes);
}

/// INTEGER a partir de los bytes sin signo de un número (serial de un certificado, por ejemplo).
ubyte[] derIntegerUnsigned(const(ubyte)[] magnitude) pure @safe {
  size_t start = 0;
  while (start + 1 < magnitude.length && magnitude[start] == 0) start++;
  const(ubyte)[] bytes = magnitude.length ? magnitude[start .. $] : [cast(ubyte) 0];
  if (bytes[0] & 0x80) return derTlv(0x02, [cast(ubyte) 0] ~ bytes);
  return derTlv(0x02, bytes);
}

ubyte[] derBoolean(bool value) pure @safe {
  return derTlv(0x01, [value ? cast(ubyte) 0xFF : cast(ubyte) 0]);
}

ubyte[] derNull() pure @safe {
  return [cast(ubyte) 0x05, 0x00];
}

ubyte[] derOid(string dotted) pure @safe {
  return derTlv(0x06, encodeOidContent(dotted));
}

ubyte[] derOctetString(const(ubyte)[] content) pure @safe {
  return derTlv(0x04, content);
}

ubyte[] derBitString(const(ubyte)[] content, ubyte unusedBits = 0) pure @safe {
  return derTlv(0x03, [unusedBits] ~ content);
}

ubyte[] derUtf8String(string text) pure @safe {
  return derTlv(0x0C, cast(const(ubyte)[]) text);
}

ubyte[] derIa5String(string text) pure @safe {
  foreach (character; text) enforce!Asn1Exception(character < 0x80, "IA5String con caracteres fuera de ASCII");
  return derTlv(0x16, cast(const(ubyte)[]) text);
}

ubyte[] derGeneralizedTime(SysTime time) @safe {
  DateTime utc = cast(DateTime) time.toUTC;
  string text = format("%04d%02d%02d%02d%02d%02dZ", utc.year, cast(int) utc.month, utc.day, utc.hour, utc.minute,
    utc.second);
  return derTlv(0x18, cast(const(ubyte)[]) text);
}

/// UTCTime para fechas entre 1950 y 2049, como exige RFC 5652 para signing-time.
ubyte[] derUtcTime(SysTime time) @safe {
  DateTime utc = cast(DateTime) time.toUTC;
  enforce!Asn1Exception(utc.year >= 1950 && utc.year < 2050, "UTCTime sólo representa años de 1950 a 2049");
  string text = format("%02d%02d%02d%02d%02d%02dZ", utc.year % 100, cast(int) utc.month, utc.day, utc.hour,
    utc.minute, utc.second);
  return derTlv(0x17, cast(const(ubyte)[]) text);
}

/// Fecha en UTCTime hasta 2049 y en GeneralizedTime después (Time de RFC 5280).
ubyte[] derTime(SysTime time) @safe {
  DateTime utc = cast(DateTime) time.toUTC;
  return utc.year >= 1950 && utc.year < 2050 ? derUtcTime(time) : derGeneralizedTime(time);
}

/// Identificador de algoritmo (AlgorithmIdentifier) con parámetros NULL o sin parámetros.
ubyte[] derAlgorithm(string oid, bool nullParameters = true) pure @safe {
  return nullParameters ? derSequence(derOid(oid), derNull()) : derSequence(derOid(oid));
}

/// Une varios fragmentos de bytes.
ubyte[] joinBytes(const(ubyte[])[] parts) pure @safe {
  auto joined = appender!(ubyte[]);
  foreach (part; parts) joined ~= part;
  return joined[];
}

/// Orden lexicográfico de bytes (el más corto primero si es prefijo).
int compareBytes(const(ubyte)[] a, const(ubyte)[] b) pure nothrow @safe @nogc {
  size_t common = a.length < b.length ? a.length : b.length;
  foreach (index; 0 .. common) {
    if (a[index] != b[index]) return a[index] < b[index] ? -1 : 1;
  }
  if (a.length == b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

@("should encode and decode object identifiers when converting dotted notation")
unittest {
  assert(encodeOidContent("1.2.840.113549.1.1.11") == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]);
  assert(decodeOid([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]) == "1.2.840.113549.1.1.11");
  assert(decodeOid(encodeOidContent("2.999.3")) == "2.999.3");
  import std.exception : assertThrown;
  assertThrown!Asn1Exception(encodeOidContent("1"));
  assertThrown!Asn1Exception(decodeOid([0x86]));
}

@("should keep sign and magnitude when encoding and decoding integers")
unittest {
  foreach (value; [0L, 1, 127, 128, 255, 256, -1, -128, -129, 65535, -65536, long.max, long.min + 1]) {
    auto element = parseDer(derInteger(value));
    assert(element.integerValue() == BigInt(value));
  }
  assert(derInteger(128) == [0x02, 0x02, 0x00, 0x80]);
  assert(derInteger(-129) == [0x02, 0x02, 0xFF, 0x7F]);
  assert(derIntegerUnsigned([0x00, 0x00, 0xFF]) == [0x02, 0x02, 0x00, 0xFF]);
  assert(toHexString(BigInt("255")) == "ff");
}

@("should read nested structures including BER indefinite lengths when parsing")
unittest {
  // SEQUENCE (indefinida) { INTEGER 5, OCTET STRING construido (indefinida) { "ab", "c" } }
  ubyte[] ber = [0x30, 0x80, 0x02, 0x01, 0x05, 0x24, 0x80, 0x04, 0x02, 'a', 'b', 0x04, 0x01, 'c', 0x00, 0x00, 0x00, 0x00];
  auto element = parseDer(ber);
  assert(element.indefiniteLength && element.isSequence);
  auto reader = element.reader();
  assert(reader.next("entero").smallIntegerValue == 5);
  assert(reader.next("octetos").octetStringValue == cast(const(ubyte)[]) "abc");
  reader.finish("la prueba");
}

@("should reject truncated and oversized encodings when parsing untrusted data")
unittest {
  import std.exception : assertThrown;
  assertThrown!Asn1Exception(parseDer([0x30, 0x05, 0x02, 0x01]));
  assertThrown!Asn1Exception(parseDer([0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00]));
  assertThrown!Asn1Exception(parseDer([0x02, 0x01, 0x05, 0x00]));
  assertThrown!Asn1Exception(parseDer([0x04, 0x80, 0x00, 0x00]));
}

@("should sort SET OF members by their encoding when writing DER")
unittest {
  auto set = derSetOf([derInteger(300), derOctetString([1]), derInteger(2)]);
  auto members = parseDer(set).children();
  assert(members[0].isUniversal(UniversalTag.integer) && members[0].smallIntegerValue == 2);
  assert(members[1].smallIntegerValue == 300);
  assert(members[2].isUniversal(UniversalTag.octetString));
}

@("should read UTC and generalized times with RFC 5280 century rules")
unittest {
  assert(parseUtcTime("491231235959Z").toUTC.year == 2049);
  assert(parseUtcTime("500101000000Z").toUTC.year == 1950);
  auto withFraction = parseGeneralizedTime("20260922200405.125Z");
  assert(withFraction.fracSecs.total!"msecs" == 125);
  assert(parseDer(derGeneralizedTime(withFraction)).timeValue.toUnixTime == withFraction.toUnixTime);
  import std.exception : assertThrown;
  assertThrown!Asn1Exception(parseGeneralizedTime("2026092220Z"));
}

@("should decode the text of every ASN.1 string type used in certificates")
unittest {
  assert(parseDer([0x0C, 0x02, 0xC3, 0xA1]).stringValue == "á");
  assert(parseDer([0x1E, 0x02, 0x00, 0xE1]).stringValue == "á");
  assert(parseDer([0x14, 0x01, 0xE1]).stringValue == "á");
  assert(parseDer([0x03, 0x02, 0x05, 0xA0]).bitStringBits == [true, false, true]);
}

@("should reject an empty algorithm and drop NULL parameters when reading an AlgorithmIdentifier")
unittest {
  import std.exception : assertThrown;
  // 30 00: SEQUENCE vacía, como la de un certificado manipulado.
  assertThrown!Asn1Exception(parseAlgorithmIdentifier(parseDer([0x30, 0x00]), "El algoritmo"));
  // sha256WithRSAEncryption con parámetros NULL.
  immutable ubyte[] withNull = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
    0x00];
  auto algorithm = parseAlgorithmIdentifier(parseDer(withNull), "El algoritmo");
  assert(algorithm.oid == "1.2.840.113549.1.1.11" && algorithm.parameters.length == 0);
}
