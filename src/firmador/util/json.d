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
 * Lectura validada de JSON externo (peticiones de Firmador Remoto, comandos del shell,
 * mensajes de las conexiones): cada acceso comprueba el tipo y, si no es el esperado,
 * falla con el campo y lo que se esperaba. Envuelve los accesos @system de std.json.
 */
module firmador.util.json;

import std.base64 : Base64, Base64Exception;
import std.exception : enforce;
import std.format : format;
import std.json : JSONValue, JSONType, parseJSON, JSONException;

/// El JSON recibido no tiene la forma esperada.
class JsonShapeException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/**
 * Interpreta un texto JSON.
 *
 * Throws: JsonShapeException con `what` y el motivo si el texto no es JSON.
 */
JSONValue parseJsonText(string text, string what) pure @safe {
  try {
    return parseJSON(text);
  } catch (JSONException exception) {
    throw new JsonShapeException(format("%s no es JSON válido: %s", what, exception.msg));
  }
}

/// El valor es un objeto.
bool isObject(const JSONValue value) pure nothrow @safe @nogc {
  return value.type == JSONType.object;
}

/// Miembro de un objeto, o null si falta o el valor no es un objeto.
const(JSONValue)* member(const JSONValue value, string key) pure @trusted {
  if (value.type != JSONType.object) return null;
  return key in value.object;
}

/// Claves de un objeto.
string[] objectKeys(const JSONValue value, string what) pure @trusted {
  enforce!JsonShapeException(value.type == JSONType.object, format("%s debe ser un objeto JSON", what));
  return value.object.keys;
}

/// Elementos de una lista.
const(JSONValue)[] arrayItems(const JSONValue value, string what) pure @trusted {
  enforce!JsonShapeException(value.type == JSONType.array, format("%s debe ser una lista JSON", what));
  return value.array;
}

/// El miembro no existe o es null.
bool isAbsent(const JSONValue value, string key) pure @safe {
  auto found = member(value, key);
  return found is null || found.type == JSONType.null_;
}

/// Texto obligatorio.
string requiredString(const JSONValue value, string key, string what) pure @safe {
  auto found = member(value, key);
  enforce!JsonShapeException(found !is null && found.type == JSONType.string,
    format("%s: falta el texto «%s»", what, key));
  return found.str;
}

/// Texto opcional (null si falta o es null).
string optionalString(const JSONValue value, string key, string what) pure @safe {
  auto found = member(value, key);
  if (found is null || found.type == JSONType.null_) return null;
  enforce!JsonShapeException(found.type == JSONType.string, format("%s: «%s» debe ser texto", what, key));
  return found.str;
}

/// Entero opcional.
long optionalLong(const JSONValue value, string key, long fallback, string what) pure @safe {
  auto found = member(value, key);
  if (found is null || found.type == JSONType.null_) return fallback;
  if (found.type == JSONType.integer) return found.integer;
  if (found.type == JSONType.uinteger) {
    enforce!JsonShapeException(found.uinteger <= long.max, format("%s: «%s» es demasiado grande", what, key));
    return cast(long) found.uinteger;
  }
  if (found.type == JSONType.float_) {
    double number = found.floating;
    enforce!JsonShapeException(number == cast(long) number, format("%s: «%s» debe ser un entero", what, key));
    return cast(long) number;
  }
  if (found.type == JSONType.string) {
    import std.conv : to, ConvException;
    try {
      return found.str.to!long;
    } catch (ConvException) {
      throw new JsonShapeException(format("%s: «%s» debe ser un entero", what, key));
    }
  }
  throw new JsonShapeException(format("%s: «%s» debe ser un entero", what, key));
}

/// Decimal opcional.
double optionalDouble(const JSONValue value, string key, double fallback, string what) pure @safe {
  auto found = member(value, key);
  if (found is null || found.type == JSONType.null_) return fallback;
  switch (found.type) {
    case JSONType.integer: return found.integer;
    case JSONType.uinteger: return found.uinteger;
    case JSONType.float_: return found.floating;
    default: throw new JsonShapeException(format("%s: «%s» debe ser un número", what, key));
  }
}

/// Booleano opcional (acepta también "true"/"false" como texto, como Jackson).
bool optionalBool(const JSONValue value, string key, bool fallback, string what) pure @safe {
  auto found = member(value, key);
  if (found is null || found.type == JSONType.null_) return fallback;
  if (found.type == JSONType.true_) return true;
  if (found.type == JSONType.false_) return false;
  if (found.type == JSONType.string && (found.str == "true" || found.str == "false")) return found.str == "true";
  throw new JsonShapeException(format("%s: «%s» debe ser verdadero o falso", what, key));
}

/**
 * Bytes codificados en base64 (la forma en que Jackson serializa byte[]).
 *
 * Throws: JsonShapeException si el texto no es base64.
 */
ubyte[] decodeBase64Field(string text, string what) pure @safe {
  try {
    import std.array : replace;
    return Base64.decode(text.replace("\n", "").replace("\r", ""));
  } catch (Base64Exception) {
    throw new JsonShapeException(format("%s no está codificado en base64", what));
  }
}

/// Bytes base64 obligatorios de un miembro.
ubyte[] requiredBase64(const JSONValue value, string key, string what) pure @safe {
  return decodeBase64Field(requiredString(value, key, what), format("%s: «%s»", what, key));
}

/// Lista de textos opcional.
string[] optionalStringList(const JSONValue value, string key, string what) pure @safe {
  auto found = member(value, key);
  if (found is null || found.type == JSONType.null_) return null;
  string[] result;
  foreach (item; arrayItems(*found, format("%s: «%s»", what, key))) {
    enforce!JsonShapeException(item.type == JSONType.string, format("%s: «%s» debe contener textos", what, key));
    result ~= item.str;
  }
  return result;
}

@("should report the field and the expected type when external JSON has the wrong shape")
unittest {
  import std.exception : collectExceptionMsg;
  import std.algorithm : canFind;
  auto value = parseJsonText(`{"nombre":"x","numero":"12","lista":[1],"b":"true","datos":"AAEC"}`, "la prueba");
  assert(requiredString(value, "nombre", "la prueba") == "x");
  assert(optionalLong(value, "numero", 0, "la prueba") == 12);
  assert(optionalBool(value, "b", false, "la prueba"));
  assert(requiredBase64(value, "datos", "la prueba") == [0, 1, 2]);
  assert(collectExceptionMsg(requiredString(value, "falta", "la prueba")).canFind("«falta»"));
  assert(collectExceptionMsg(optionalStringList(value, "lista", "la prueba")).canFind("textos"));
  assert(collectExceptionMsg(parseJsonText("{", "el cuerpo")).canFind("el cuerpo"));
  assert(collectExceptionMsg(decodeBase64Field("%%%", "el documento")).canFind("base64"));
}
