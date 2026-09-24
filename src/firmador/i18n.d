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
 * Textos traducidos de la interfaz (MessageUtils en la versión Java). Los paquetes
 * resources/messages*.properties van incrustados en el ejecutable y se buscan como
 * ResourceBundle: primero idioma y país, luego idioma y por último el paquete base. El
 * idioma lo fija firmador.settings al cargar o cambiar la configuración.
 *
 * resources/dss-messages_es.properties trae los textos de los controles de validación,
 * con las mismas claves que DSS (BBB_*), que usa firmador.validation.report.
 */
module firmador.i18n;

import core.sync.mutex : Mutex;
import std.exception : enforce;
import std.format : format;
import std.regex : ctRegex, replaceAll;

import firmador.util.properties : parseProperties;

private struct Bundle {
  string suffix;
  string text;
}

private immutable Bundle[] embeddedBundles = [
  Bundle("", import("messages.properties")),
  Bundle("_es_CR", import("messages_es_CR.properties")),
  Bundle("_en_US", import("messages_en_US.properties")),
];

private __gshared string[string][string] parsedBundles;
private __gshared string[string] parsedValidationMessages;
private __gshared string currentLanguage = "es";
private __gshared string currentCountry = "CR";
private __gshared Mutex bundleLock;

shared static this() {
  bundleLock = new Mutex;
}

/// Idioma y país con el que se buscan los textos a partir de ahora.
void setMessagesLocale(string language, string country) @trusted {
  bundleLock.lock();
  scope (exit) bundleLock.unlock();
  currentLanguage = language;
  currentCountry = country;
}

/// Paquete ya interpretado para el sufijo pedido (null si no existe).
private const(string[string])* bundleFor(string suffix) @trusted {
  if (auto cached = suffix in parsedBundles) return cached;
  foreach (bundle; embeddedBundles) {
    if (bundle.suffix == suffix) {
      parsedBundles[suffix] = parseProperties(bundle.text);
      return suffix in parsedBundles;
    }
  }
  return null;
}

/**
 * Texto traducido de la clave para el idioma actual.
 *
 * Throws: Exception con la clave y el idioma si no está en ningún paquete, igual que
 * MissingResourceException: una clave ausente es un error de programación.
 */
string t(string key) @trusted {
  bundleLock.lock();
  string language = currentLanguage;
  string country = currentCountry;
  bundleLock.unlock();
  return translate(key, language, country);
}

/// Como t, pero para un idioma y país concretos (el mensaje de firma por omisión va siempre en es_CR).
string translate(string key, string language, string country) @trusted {
  bundleLock.lock();
  scope (exit) bundleLock.unlock();
  foreach (suffix; ["_" ~ language ~ "_" ~ country, "_" ~ language, ""]) {
    auto bundle = bundleFor(suffix);
    if (bundle is null) continue;
    if (auto value = key in *bundle) return *value;
  }
  throw new Exception(format("No existe el texto «%s» para el idioma %s_%s", key, language, country));
}

/**
 * Texto de un control de validación de DSS (claves BBB_*), o null si no está: los
 * controles propios de Firmador que no tienen equivalente en DSS usan claves de
 * messages.properties.
 */
string validationMessage(string key) @trusted {
  bundleLock.lock();
  scope (exit) bundleLock.unlock();
  if (parsedValidationMessages is null) parsedValidationMessages = parseProperties(import("dss-messages_es.properties"));
  if (auto value = key in parsedValidationMessages) return *value;
  return null;
}

/// Sustituye {0}, {1}… de un texto traducido por los argumentos (MessageFormat.format).
string formatText(string pattern, const string[] arguments...) pure @safe {
  import std.array : appender;
  import std.conv : to;
  auto output = appender!string;
  size_t position = 0;
  while (position < pattern.length) {
    if (pattern[position] == '{') {
      size_t close = position + 1;
      while (close < pattern.length && pattern[close] >= '0' && pattern[close] <= '9') close++;
      if (close > position + 1 && close < pattern.length && pattern[close] == '}') {
        size_t index = pattern[position + 1 .. close].to!size_t;
        enforce(index < arguments.length, format("El texto «%s» usa {%d} pero sólo recibió %d argumentos", pattern,
          index, arguments.length));
        output ~= arguments[index];
        position = close + 1;
        continue;
      }
    }
    output ~= pattern[position];
    position++;
  }
  return output[];
}

/// Quita las etiquetas HTML de un texto (MessageUtils.html2txt).
string htmlToText(string text) @safe {
  return replaceAll(text, ctRegex!`<[^>]*>`, "");
}

@("should find Spanish texts and fall back to the base bundle when English lacks a key")
unittest {
  setMessagesLocale("es", "CR");
  assert(t("configpanel_save") == "Guardar");
  setMessagesLocale("en", "US");
  assert(t("configpanel_save") != "Guardar");
  assert(t("connection_panel_error_token").length > 0);
  setMessagesLocale("es", "CR");
}

@("should throw with the key when a text does not exist")
unittest {
  import std.exception : collectExceptionMsg;
  import std.algorithm : canFind;
  assert(collectExceptionMsg(t("clave_que_no_existe")).canFind("clave_que_no_existe"));
}

@("should read the Spanish validation messages when the resource was converted to UTF-8")
unittest {
  assert(validationMessage("BBB_FC_IEFF") == "¿El formato de la firma corresponde a un formato esperado?");
  assert(validationMessage("NO_EXISTE") is null);
  assert(htmlToText("<p>Hola <b>mundo</b></p>") == "Hola mundo");
}

@("should substitute numbered placeholders when formatting a translated text")
unittest {
  import std.exception : assertThrown;
  assert(formatText("La sesión de {0} ha terminado.", "UCR") == "La sesión de UCR ha terminado.");
  assert(formatText("{1} y {0} {x}", "a", "b") == "b y a {x}");
  assertThrown(formatText("{2}", "a"));
}
