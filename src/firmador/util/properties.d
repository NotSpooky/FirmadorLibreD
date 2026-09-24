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
 * Lectura y escritura del formato .properties de Java, el de config.properties, las
 * configuraciones por documento (docSettings) y los paquetes de mensajes
 * (resources/messages*.properties). Se conserva el formato para que la configuración que
 * dejó la versión Java siga valiendo.
 */
module firmador.util.properties;

import std.array : appender;
import std.algorithm : sort;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.utf : decode, encode;

/**
 * Interpreta el texto de un .properties: comentarios # y !, separadores = : o espacio,
 * líneas continuadas con \ y los escapes \t \n \f \r \uXXXX. Una clave repetida se queda
 * con el último valor, igual que java.util.Properties.
 *
 * Throws: Exception si un escape \u está incompleto o no es hexadecimal.
 */
string[string] parseProperties(string text) pure @safe {
  string[string] result;
  foreach (logicalLine; logicalLines(text)) {
    size_t position = 0;
    while (position < logicalLine.length && isPropertiesWhitespace(logicalLine[position])) position++;
    if (position >= logicalLine.length) continue;
    if (logicalLine[position] == '#' || logicalLine[position] == '!') continue;

    size_t keyStart = position;
    bool escaped = false;
    while (position < logicalLine.length) {
      char current = logicalLine[position];
      if (escaped) {
        escaped = false;
      } else if (current == '\\') {
        escaped = true;
      } else if (current == '=' || current == ':' || isPropertiesWhitespace(current)) {
        break;
      }
      position++;
    }
    string rawKey = logicalLine[keyStart .. position];
    while (position < logicalLine.length && isPropertiesWhitespace(logicalLine[position])) position++;
    if (position < logicalLine.length && (logicalLine[position] == '=' || logicalLine[position] == ':')) {
      position++;
      while (position < logicalLine.length && isPropertiesWhitespace(logicalLine[position])) position++;
    }
    result[unescapeProperty(rawKey)] = unescapeProperty(logicalLine[position .. $]);
  }
  return result;
}

/**
 * Escribe las entradas ordenadas por clave con el mismo escape que
 * Properties.store(Writer): los caracteres fuera de ASCII quedan tal cual (el archivo va
 * en UTF-8) y se escapan \ = : # ! los controles y los espacios que se perderían al leer.
 * `timestamp` es la línea de fecha que Java añade tras el comentario.
 */
string formatProperties(const string[string] entries, string comment, string timestamp) pure @safe {
  auto output = appender!string;
  if (comment.length) {
    output ~= "#";
    output ~= escapeComment(comment);
    output ~= "\n";
  }
  if (timestamp.length) {
    output ~= "#";
    output ~= timestamp;
    output ~= "\n";
  }
  string[] keys = entries.keys;
  keys.sort();
  foreach (key; keys) {
    output ~= escapeProperty(key, true);
    output ~= "=";
    output ~= escapeProperty(entries[key], false);
    output ~= "\n";
  }
  return output[];
}

private bool isPropertiesWhitespace(char character) pure nothrow @safe @nogc {
  return character == ' ' || character == '\t' || character == '\f';
}

/// Une las líneas físicas continuadas con una barra final impar y quita la sangría de la continuación.
private string[] logicalLines(string text) pure @safe {
  string[] lines;
  auto current = appender!string;
  bool continuing = false;
  size_t start = 0;
  void takeLine(string physical) {
    size_t begin = 0;
    if (continuing) {
      while (begin < physical.length && isPropertiesWhitespace(physical[begin])) begin++;
    }
    string content = physical[begin .. $];
    if (!continuing) {
      size_t firstVisible = 0;
      while (firstVisible < content.length && isPropertiesWhitespace(content[firstVisible])) firstVisible++;
      if (firstVisible < content.length && (content[firstVisible] == '#' || content[firstVisible] == '!')) {
        lines ~= content;
        return;
      }
    }
    size_t trailingBackslashes = 0;
    while (trailingBackslashes < content.length && content[$ - 1 - trailingBackslashes] == '\\') trailingBackslashes++;
    if (trailingBackslashes % 2 == 1) {
      current ~= content[0 .. $ - 1];
      continuing = true;
    } else {
      current ~= content;
      lines ~= current[];
      current = appender!string;
      continuing = false;
    }
  }
  for (size_t index = 0; index < text.length; index++) {
    if (text[index] == '\n' || text[index] == '\r') {
      takeLine(text[start .. index]);
      if (text[index] == '\r' && index + 1 < text.length && text[index + 1] == '\n') index++;
      start = index + 1;
    }
  }
  if (start < text.length) takeLine(text[start .. $]);
  if (continuing) lines ~= current[];
  return lines;
}

private string unescapeProperty(string raw) pure @safe {
  auto output = appender!string;
  for (size_t index = 0; index < raw.length; index++) {
    char current = raw[index];
    if (current != '\\') {
      output ~= current;
      continue;
    }
    index++;
    if (index >= raw.length) break;
    char escapeCharacter = raw[index];
    switch (escapeCharacter) {
      case 't': output ~= '\t'; break;
      case 'n': output ~= '\n'; break;
      case 'r': output ~= '\r'; break;
      case 'f': output ~= '\f'; break;
      case 'u':
        enforce(index + 4 < raw.length, format("Escape \\u incompleto en «%s»", raw));
        string hex = raw[index + 1 .. index + 5];
        foreach (digit; hex) {
          enforce((digit >= '0' && digit <= '9') || (digit >= 'a' && digit <= 'f') || (digit >= 'A' && digit <= 'F'),
            format("Escape \\u%s no es hexadecimal en «%s»", hex, raw));
        }
        dchar unit = cast(dchar) hex.to!uint(16);
        index += 4;
        // Un par sustituto de UTF-16 escrito como dos \u se recompone en un solo carácter.
        if (unit >= 0xD800 && unit <= 0xDBFF && index + 6 < raw.length && raw[index + 1] == '\\' && raw[index + 2] == 'u') {
          string lowHex = raw[index + 3 .. index + 7];
          uint low = lowHex.to!uint(16);
          if (low >= 0xDC00 && low <= 0xDFFF) {
            unit = cast(dchar) (0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
            index += 6;
          }
        }
        char[4] buffer;
        size_t length = encode(buffer, unit);
        output ~= buffer[0 .. length].idup;
        break;
      default:
        output ~= escapeCharacter;
        break;
    }
  }
  return output[];
}

private string escapeProperty(string value, bool isKey) pure @safe {
  auto output = appender!string;
  foreach (index, char current; value) {
    switch (current) {
      case ' ':
        if (index == 0 || isKey) output ~= '\\';
        output ~= ' ';
        break;
      case '\t': output ~= `\t`; break;
      case '\n': output ~= `\n`; break;
      case '\r': output ~= `\r`; break;
      case '\f': output ~= `\f`; break;
      case '=', ':', '#', '!', '\\':
        output ~= '\\';
        output ~= current;
        break;
      default:
        output ~= current;
        break;
    }
  }
  return output[];
}

/// Los saltos de línea de un comentario se convierten en nuevas líneas de comentario.
private string escapeComment(string comment) pure @safe {
  auto output = appender!string;
  foreach (char current; comment) {
    if (current == '\n') output ~= "\n#";
    else if (current != '\r') output ~= current;
  }
  return output[];
}

@("should read keys and values with every separator and skip comments when parsing properties")
unittest {
  auto parsed = parseProperties("# comentario\n! otro\nuno=1\ndos : 2\ntres 3\n  cuatro=\n");
  assert(parsed == ["uno": "1", "dos": "2", "tres": "3", "cuatro": ""]);
}

@("should join continued lines and decode escapes when parsing properties")
unittest {
  auto parsed = parseProperties("mensaje=Primera\\nlínea \\\n    y seguida\nclave\\ con\\ espacio=\\u00e1\\u00E9\nruta=C\\:\\\\dir\n");
  assert(parsed["mensaje"] == "Primera\nlínea y seguida");
  assert(parsed["clave con espacio"] == "áé");
  assert(parsed["ruta"] == `C:\dir`);
}

@("should reproduce every value when formatting and parsing properties again")
unittest {
  string[string] original = [
    "reason": " espacio inicial", "place": "San José: sede #1 = !", "defaultsignmessage": "Línea 1\nLínea 2\tfin",
    "clave rara": `barra \ final\`,
  ];
  string text = formatProperties(original, "Firmador Libre settings", "Tue Sep 22 20:04:00 CST 2026");
  assert(text.length > 0 && text[0] == '#');
  assert(parseProperties(text) == original);
}

@("should reject a malformed unicode escape when parsing properties")
unittest {
  import std.exception : assertThrown;
  assertThrown(parseProperties("clave=\\u12"));
  assertThrown(parseProperties("clave=\\u12zz"));
}
