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
 * Fechas: la zona horaria de Costa Rica, el formato de fecha configurable (patrones de
 * java.text.SimpleDateFormat, que es lo que el usuario escribe en «Formato de fecha» y lo
 * que guardó la versión Java) y los formatos de fecha de los estándares (RFC 3339, ASN.1
 * GeneralizedTime y el de las fechas PDF).
 */
module firmador.util.datetime;

import core.time : dur, Duration;
import std.array : appender;
import std.conv : to;
import std.datetime.date : Date, DateTime, DayOfWeek, Month;
import std.datetime.systime : SysTime;
import std.datetime.timezone : SimpleTimeZone, UTC;
import std.exception : enforce;
import std.format : format;
import std.string : rightJustify;

import firmador.configuration : costaRicaUtcOffsetHours;

/// Zona horaria de Costa Rica (UTC-6 fijo, sin horario de verano desde 1992).
immutable(SimpleTimeZone) costaRicaTimeZone() pure @safe {
  return new immutable SimpleTimeZone(costaRicaOffset, "CST");
}

/// Desplazamiento de Costa Rica respecto de UTC.
private enum Duration costaRicaOffset = dur!"hours"(costaRicaUtcOffsetHours);

/// Origen de SysTime.stdTime (1 de enero del año 1, en UTC).
private enum DateTime stdTimeEpoch = DateTime(1, 1, 1);

/**
 * Instante de una fecha y hora en UTC. Equivale a `SysTime(utc, UTC())`, que no es `pure`
 * porque convierte por medio de TimeZone.
 */
SysTime utcTime(DateTime utc) pure nothrow @safe {
  return SysTime((utc - stdTimeEpoch).total!"hnsecs", UTC());
}

/**
 * Fecha y hora en UTC de un instante, sin fracciones de segundo. Equivale a
 * `cast(DateTime) time.toUTC`, que no es `pure` porque convierte por medio de TimeZone.
 */
DateTime utcDateTime(SysTime time) pure nothrow @safe {
  return stdTimeEpoch + dur!"seconds"(time.stdTime / dur!"seconds"(1).total!"hnsecs");
}

/// Fecha y hora de un instante en la zona de Costa Rica, sin fracciones de segundo.
private DateTime costaRicaDateTime(SysTime time) pure nothrow @safe {
  return utcDateTime(time) + costaRicaOffset;
}

/// Idioma de los nombres de mes, día y a. m./p. m. en fechas con formato.
enum DateLanguage { spanish, english }

/// Idioma de fechas que corresponde al idioma configurado ("es", "en").
DateLanguage dateLanguageFor(string language) pure nothrow @safe @nogc {
  return language == "en" ? DateLanguage.english : DateLanguage.spanish;
}

private immutable string[12] spanishMonths = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio",
  "agosto", "septiembre", "octubre", "noviembre", "diciembre"];
private immutable string[12] spanishShortMonths = ["ene.", "feb.", "mar.", "abr.", "may.", "jun.", "jul.",
  "ago.", "sept.", "oct.", "nov.", "dic."];
private immutable string[12] englishMonths = ["January", "February", "March", "April", "May", "June", "July",
  "August", "September", "October", "November", "December"];
private immutable string[12] englishShortMonths = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug",
  "Sep", "Oct", "Nov", "Dec"];
private immutable string[7] spanishDays = ["domingo", "lunes", "martes", "miércoles", "jueves", "viernes", "sábado"];
private immutable string[7] spanishShortDays = ["dom.", "lun.", "mar.", "mié.", "jue.", "vie.", "sáb."];
private immutable string[7] englishDays = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
private immutable string[7] englishShortDays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/**
 * Da formato a `time`, ya convertido a la zona que corresponda, con un patrón de
 * SimpleDateFormat: G y M L d D E u a H k K h m s S z Z X F W w y sus repeticiones, texto
 * entre comillas simples y '' para una comilla.
 *
 * Throws: Exception con el carácter y el patrón si el patrón no es válido, como
 * IllegalArgumentException en Java.
 */
string formatJavaDate(string pattern, SysTime time, DateLanguage language) @safe {
  auto output = appender!string;
  DateTime local = cast(DateTime) time;
  Duration offset = time.utcOffset;
  size_t index = 0;
  while (index < pattern.length) {
    char current = pattern[index];
    if (current == '\'') {
      if (index + 1 < pattern.length && pattern[index + 1] == '\'') {
        output ~= '\'';
        index += 2;
        continue;
      }
      size_t end = index + 1;
      while (true) {
        enforce(end < pattern.length, format("Falta cerrar una comilla en el formato de fecha «%s»", pattern));
        if (pattern[end] == '\'') {
          if (end + 1 < pattern.length && pattern[end + 1] == '\'') {
            output ~= '\'';
            end += 2;
            continue;
          }
          break;
        }
        output ~= pattern[end];
        end++;
      }
      index = end + 1;
      continue;
    }
    if (!((current >= 'a' && current <= 'z') || (current >= 'A' && current <= 'Z'))) {
      output ~= current;
      index++;
      continue;
    }
    size_t count = 1;
    while (index + count < pattern.length && pattern[index + count] == current) count++;
    output ~= formatField(current, count, local, time.fracSecs.total!"msecs", offset, language, pattern);
    index += count;
  }
  return output[];
}

private string formatField(char letter, size_t count, DateTime local, long milliseconds, Duration offset,
    DateLanguage language, string pattern) pure @safe {
  bool spanish = language == DateLanguage.spanish;
  int hour = local.hour;
  switch (letter) {
    case 'G': return spanish ? "d. C." : "AD";
    case 'y', 'Y', 'u':
      if (letter == 'u') return padded(dayOfWeekNumber(local.dayOfWeek), count);
      if (count == 2) return padded(local.year % 100, 2);
      return padded(local.year, count);
    case 'M', 'L':
      int monthIndex = cast(int) local.month - 1;
      if (count >= 4) return spanish ? spanishMonths[monthIndex] : englishMonths[monthIndex];
      if (count == 3) return spanish ? spanishShortMonths[monthIndex] : englishShortMonths[monthIndex];
      return padded(monthIndex + 1, count);
    case 'd': return padded(local.day, count);
    case 'D': return padded(local.dayOfYear, count);
    case 'F': return padded((local.day - 1) / 7 + 1, count);
    case 'W': return padded(weekOfMonth(local), count);
    case 'w': return padded(local.isoWeek, count);
    case 'E':
      int dayIndex = cast(int) local.dayOfWeek;
      if (count >= 4) return spanish ? spanishDays[dayIndex] : englishDays[dayIndex];
      return spanish ? spanishShortDays[dayIndex] : englishShortDays[dayIndex];
    case 'a': return hour < 12 ? (spanish ? "a. m." : "AM") : (spanish ? "p. m." : "PM");
    case 'H': return padded(hour, count);
    case 'k': return padded(hour == 0 ? 24 : hour, count);
    case 'K': return padded(hour % 12, count);
    case 'h': return padded(hour % 12 == 0 ? 12 : hour % 12, count);
    case 'm': return padded(local.minute, count);
    case 's': return padded(local.second, count);
    case 'S': return padded(milliseconds, count);
    case 'z':
      if (count >= 4) return spanish ? "hora estándar central" : "Central Standard Time";
      return offsetName(offset);
    case 'Z': return offsetText(offset, false, true);
    case 'X':
      if (offset == Duration.zero) return "Z";
      if (count == 1) return offsetText(offset, false, false);
      return offsetText(offset, count >= 3, true);
    default:
      throw new Exception(format("Carácter «%s» no válido en el formato de fecha «%s»", letter, pattern));
  }
}

private string padded(long value, size_t count) pure @safe {
  string text = value.to!string;
  return count > text.length ? text.rightJustify(count, '0') : text;
}

private int dayOfWeekNumber(DayOfWeek day) pure nothrow @safe @nogc {
  return day == DayOfWeek.sun ? 7 : cast(int) day;
}

private int weekOfMonth(DateTime local) pure @safe {
  int firstDay = cast(int) Date(local.year, local.month, 1).dayOfWeek;
  return (local.day + firstDay - 1) / 7 + 1;
}

private string offsetText(Duration offset, bool withColon, bool withMinutes) pure @safe {
  long totalMinutes = offset.total!"minutes";
  char sign = totalMinutes < 0 ? '-' : '+';
  if (totalMinutes < 0) totalMinutes = -totalMinutes;
  string hours = padded(totalMinutes / 60, 2);
  if (!withMinutes) return sign ~ hours;
  return sign ~ hours ~ (withColon ? ":" : "") ~ padded(totalMinutes % 60, 2);
}

private string offsetName(Duration offset) pure @safe {
  if (offset == costaRicaOffset) return "CST";
  if (offset == Duration.zero) return "UTC";
  return "GMT" ~ offsetText(offset, true, true);
}

/// Fecha en UTC como en RFC 3339 con zona «Z» (xsd:dateTime), sin fracciones de segundo.
string toRfc3339Utc(SysTime time) pure @safe {
  DateTime utc = utcDateTime(time);
  return format("%04d-%02d-%02dT%02d:%02d:%02dZ", utc.year, cast(int) utc.month, utc.day, utc.hour, utc.minute,
    utc.second);
}

/// Día (yyyy-MM-dd) en que cae `time` en la zona de Costa Rica, como se muestran los vencimientos.
string costaRicaDay(SysTime time) pure @safe {
  DateTime local = costaRicaDateTime(time);
  return format("%04d-%02d-%02d", local.year, cast(int) local.month, local.day);
}

/// Fecha en la zona de Costa Rica con su desplazamiento, como en RFC 3339 (-06:00).
string toRfc3339CostaRica(SysTime time) pure @safe {
  DateTime fields = costaRicaDateTime(time);
  return format("%04d-%02d-%02dT%02d:%02d:%02d%s", fields.year, cast(int) fields.month, fields.day, fields.hour,
    fields.minute, fields.second, offsetText(costaRicaOffset, true, true));
}

/// Fecha de un diccionario PDF («D:AAAAMMDDHHmmSS+HH'mm'»), en la zona de Costa Rica.
string toPdfDate(SysTime time) pure @safe {
  DateTime fields = costaRicaDateTime(time);
  long totalMinutes = costaRicaOffset.total!"minutes";
  char sign = totalMinutes < 0 ? '-' : '+';
  if (totalMinutes < 0) totalMinutes = -totalMinutes;
  return format("D:%04d%02d%02d%02d%02d%02d%s%02d'%02d'", fields.year, cast(int) fields.month, fields.day,
    fields.hour, fields.minute, fields.second, sign, totalMinutes / 60, totalMinutes % 60);
}

/**
 * Interpreta una fecha xsd:dateTime / RFC 3339 («2026-09-22T20:04:05Z», con fracción o
 * desplazamiento opcionales).
 *
 * Throws: Exception con el texto recibido si no tiene ese formato.
 */
SysTime parseRfc3339(string text) @safe {
  import std.regex : ctRegex, matchFirst;
  auto match = matchFirst(text, ctRegex!`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$`);
  enforce(!match.empty, format("Fecha RFC 3339 no válida: «%s»", text));
  auto local = DateTime(match[1].to!int, match[2].to!int, match[3].to!int, match[4].to!int, match[5].to!int,
    match[6].to!int);
  string zone = match[8];
  if (zone.length == 0 || zone == "Z") return SysTime(local, UTC());
  int sign = zone[0] == '-' ? -1 : 1;
  auto offset = dur!"minutes"(sign * (zone[1 .. 3].to!int * 60 + zone[4 .. 6].to!int));
  return SysTime(local, new immutable SimpleTimeZone(offset));
}

/**
 * Interpreta una fecha de diccionario PDF (D:AAAA[MM[DD[HH[mm[SS[Z|+HH'mm']]]]]]).
 *
 * Throws: Exception con el texto recibido si no tiene ese formato.
 */
SysTime parsePdfDate(string text) @safe {
  import std.regex : ctRegex, matchFirst;
  auto match = matchFirst(text,
    ctRegex!`^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(Z|[+-]\d{2}'?(?:\d{2}'?)?)?`);
  enforce(!match.empty, format("Fecha PDF no válida: «%s»", text));
  int field(size_t group, int fallback) {
    return match[group].length ? match[group].to!int : fallback;
  }
  auto local = DateTime(field(1, 1), field(2, 1), field(3, 1), field(4, 0), field(5, 0), field(6, 0));
  string zone = match[7];
  if (zone.length == 0 || zone[0] == 'Z') return SysTime(local, UTC());
  int sign = zone[0] == '-' ? -1 : 1;
  import std.array : replace;
  string digits = zone[1 .. $].replace("'", "");
  int minutes = digits[0 .. 2].to!int * 60 + (digits.length >= 4 ? digits[2 .. 4].to!int : 0);
  return SysTime(local, new immutable SimpleTimeZone(dur!"minutes"(sign * minutes)));
}

/// Fecha ASN.1 GeneralizedTime en UTC (AAAAMMDDHHmmSSZ) de DER.
string toGeneralizedTime(SysTime time) pure @safe {
  DateTime utc = utcDateTime(time);
  return format("%04d%02d%02d%02d%02d%02dZ", utc.year, cast(int) utc.month, utc.day, utc.hour, utc.minute, utc.second);
}

@("should format the default signature date format in Spanish when the Java pattern is used")
unittest {
  auto time = SysTime(DateTime(2026, 9, 22, 20, 4, 5), UTC()).toOtherTZ(costaRicaTimeZone());
  assert(formatJavaDate("dd/MM/yyyy hh:mm:ss a", time, DateLanguage.spanish) == "22/09/2026 02:04:05 p. m.");
  assert(formatJavaDate("MM/dd/yyyy hh:mm:ss a", time, DateLanguage.english) == "09/22/2026 02:04:05 PM");
}

@("should format names, quotes and zones when the pattern uses text fields")
unittest {
  auto time = SysTime(DateTime(2026, 1, 4, 0, 30, 0), UTC()).toOtherTZ(costaRicaTimeZone());
  assert(formatJavaDate("EEEE d 'de' MMMM 'de' yyyy, HH:mm z", time, DateLanguage.spanish)
    == "sábado 3 de enero de 2026, 18:30 CST");
  assert(formatJavaDate("yy-MMM-dd'T'kk Z XXX ''", time, DateLanguage.english) == "26-Jan-03T18 -0600 -06:00 '");
}

@("should reject unknown letters and unclosed quotes when validating a Java date pattern")
unittest {
  import std.exception : assertThrown;
  auto time = SysTime(DateTime(2026, 1, 4, 0, 30, 0), UTC());
  assertThrown(formatJavaDate("dd/MM/yyyy q", time, DateLanguage.spanish));
  assertThrown(formatJavaDate("dd 'de", time, DateLanguage.spanish));
}

@("should convert between SysTime and RFC 3339, PDF and GeneralizedTime dates when round tripping")
unittest {
  auto time = SysTime(DateTime(2026, 9, 22, 20, 4, 5), UTC());
  assert(toRfc3339Utc(time) == "2026-09-22T20:04:05Z");
  assert(toRfc3339CostaRica(time) == "2026-09-22T14:04:05-06:00");
  assert(toPdfDate(time) == "D:20260922140405-06'00'");
  assert(toGeneralizedTime(time) == "20260922200405Z");
  assert(parseRfc3339("2026-09-22T14:04:05-06:00") == time);
  assert(parseRfc3339("2026-09-22T20:04:05.123Z").toUnixTime == time.toUnixTime);
  assert(parsePdfDate("D:20260922140405-06'00'") == time);
  assert(parsePdfDate("D:20260922200405Z") == time);
}

@("should give the Costa Rica calendar day when a UTC time is past local midnight")
unittest {
  import std.datetime.timezone : UTC;
  assert(costaRicaDay(SysTime(DateTime(2027, 1, 1, 3, 0, 0), UTC())) == "2026-12-31");
  assert(costaRicaDay(SysTime(DateTime(2027, 1, 1, 6, 0, 0), UTC())) == "2027-01-01");
}

@("should match the TimeZone conversions of Phobos when converting between UTC fields and instants")
unittest {
  auto fields = DateTime(2026, 9, 22, 20, 4, 5);
  assert(utcTime(fields) == SysTime(fields, UTC()));
  auto withFraction = SysTime(fields, dur!"msecs"(900), costaRicaTimeZone());
  assert(utcDateTime(withFraction) == cast(DateTime) withFraction.toUTC);
  assert(utcDateTime(utcTime(DateTime(1950, 1, 1, 0, 0, 0))) == DateTime(1950, 1, 1, 0, 0, 0));
}
