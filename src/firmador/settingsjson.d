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
 * Ajustes en JSON (@contract settings-json): el objeto «settings» que reciben Firmador
 * Remoto (/signDocument) y el modo shell, y el que se envía a las conexiones al pedir la
 * firma de documentos virtuales. Los nombres son los campos públicos de Settings (los de
 * Jackson en la versión Java). Al leer se aceptan también las propiedades derivadas que
 * escribía Jackson (se ignoran), nunca se lee ni se escribe keyPassword, y cualquier otro
 * nombre es un error, como en Jackson.
 */
module firmador.settingsjson;

import std.algorithm : canFind;
import std.array : join;
import std.format : format;
import std.json : JSONType, JSONValue;
import std.traits : isFloatingPoint, isIntegral;
import std.typecons : Nullable;

import firmador.settings : Settings;
import firmador.util.json;

/// Campos que no viajan en JSON (@JsonIgnore en Java, o secretos locales).
private enum string[] localOnlyFields = ["extraPKCS11Lib", "signXf", "signYf", "signScale", "portNumber",
  "pKCS12File", "activePlugins", "availablePlugins", "keyPassword", "listeners"];

/**
 * Ajustes de la aplicación que un documento no puede cambiar ni necesita enviar: rutas de
 * programas que Firmador ejecuta, orígenes autorizados y preferencias de la ventana. Al
 * leerlos se conserva el valor local.
 */
private immutable string[] applicationFields = ["sofficePath", "registeredAllowedOrigins", "tempAllowedHosts",
  "noAuthorizedHosts", "allowOriginPort", "startFimadorRemote", "preferredBrowser", "showLogs", "advancedLogs",
  "showTrayNotifications", "themeMode", "startwindowstate", "max_number_process_doc", "simplified_mode",
  "previewZoom", "pDFImgScaleFactor"];

/**
 * Propiedades que Jackson escribía a partir de getters, y campos que ya no existen (el ancho
 * y el alto de la firma); al leerlas se ignoran.
 */
private immutable string[] derivedProperties = ["allowedHosts", "formattedAllowedPorts", "translatedDefaultSignMessage",
  "remote", "remoteOrigin", "origin", "remotePort", "startFirmadorRemote", "minimizeGui", "version", "releaseUrl",
  "releaseCheckUrl", "checksumUrl", "extendedState", "simplifiedMode", "padESLevel", "xadESLevel", "cadESLevel",
  "jadESLevel", "sofficePath", "defaultDevelopmentVersion", "keyPassword", "signWidth", "signHeight"];

/// Nombres de los campos que viajan en JSON.
enum string[] settingsJsonFields = jsonFieldNames();

private string[] jsonFieldNames() pure @safe {
  string[] names;
  static foreach (field; Settings.tupleof) {{
    enum name = __traits(identifier, field);
    static if (!localOnlyFields.canFind(name)) names ~= name;
  }}
  return names;
}

/// Ajustes en JSON, sin los campos locales ni la contraseña del almacén.
JSONValue settingsToJson(const Settings settings) @trusted {
  JSONValue json = JSONValue(string[string].init);
  static foreach (index, field; Settings.tupleof) {{
    enum name = __traits(identifier, field);
    static if (!localOnlyFields.canFind(name) && !applicationFields.canFind(name)) {
      auto value = settings.tupleof[index];
      alias Type = typeof(value);
      static if (is(Type : Nullable!T, T)) {
        json[name] = value.isNull ? JSONValue(null) : JSONValue(value.get);
      } else static if (is(Type == string)) {
        json[name] = value is null ? JSONValue(null) : JSONValue(value);
      } else {
        json[name] = JSONValue(value);
      }
    }
  }}
  return json;
}

/**
 * Ajustes de `base` con los campos que trae `json` (treeToValue en la versión Java).
 *
 * Throws: JsonShapeException con el campo y lo esperado si algún valor no tiene el tipo del
 * campo o si trae un nombre desconocido.
 */
Settings settingsFromJson(const JSONValue json, const Settings base) @trusted {
  enum what = "Los ajustes";
  auto settings = new Settings(base);
  // El constructor de copia no copia todo: los campos que viajan se copian aquí.
  static foreach (index, field; Settings.tupleof) {{
    enum name = __traits(identifier, field);
    static if (!localOnlyFields.canFind(name)) settings.tupleof[index] = base.tupleof[index];
  }}
  foreach (key; objectKeys(json, what)) {
    if (derivedProperties.canFind(key) && !settingsJsonFields.canFind(key)) continue;
    if (applicationFields.canFind(key)) continue;
    bool known = false;
    static foreach (index, field; Settings.tupleof) {{
      enum name = __traits(identifier, field);
      static if (!localOnlyFields.canFind(name)) {
        if (key == name) {
          known = true;
          alias Type = typeof(settings.tupleof[index]);
          static if (is(Type == bool)) {
            settings.tupleof[index] = optionalBool(json, name, settings.tupleof[index], what);
          } else static if (isIntegral!Type) {
            long number = optionalLong(json, name, settings.tupleof[index], what);
            if (number < Type.min || number > Type.max) {
              throw new JsonShapeException(format("%s: «%s» está fuera de rango", what, name));
            }
            settings.tupleof[index] = cast(Type) number;
          } else static if (isFloatingPoint!Type) {
            settings.tupleof[index] = cast(Type) optionalDouble(json, name, settings.tupleof[index], what);
          } else static if (is(Type == string)) {
            // noAuthorizedHosts llegaba como lista desde el getter de Jackson.
            auto found = member(json, name);
            if (found !is null && found.type == JSONType.array) {
              settings.tupleof[index] = optionalStringList(json, name, what).join("\n");
            } else {
              settings.tupleof[index] = optionalString(json, name, what);
            }
          } else static if (is(Type : Nullable!bool)) {
            if (isAbsent(json, name)) settings.tupleof[index].nullify();
            else settings.tupleof[index] = optionalBool(json, name, false, what);
          } else {
            static assert(false, "Tipo de ajuste sin conversión JSON: " ~ name);
          }
        }
      }
    }}
    if (!known) throw new JsonShapeException(format("%s: el campo «%s» no existe", what, key));
  }
  return settings;
}

@("should round-trip the travelling settings and never carry the key password")
unittest {
  auto settings = new Settings();
  settings.reason = "Aprobación";
  settings.signX = 40;
  settings.fontSize = 9;
  settings.keyPassword = "secreto-local";
  settings.extraPKCS11Lib = "/opt/lib.so";
  auto json = settingsToJson(settings);
  import std.json : toJSON;
  string text = toJSON(json);
  import std.algorithm : canFind;
  assert(!text.canFind("secreto-local") && !text.canFind("keyPassword"));
  assert(!text.canFind("extraPKCS11Lib"));
  auto base = new Settings();
  auto restored = settingsFromJson(json, base);
  assert(restored.reason == "Aprobación" && restored.signX == 40 && restored.fontSize == 9);
  assert(restored.keyPassword == base.keyPassword);
}

@("should ignore Jackson derived properties and reject unknown or mistyped fields")
unittest {
  import std.exception : collectExceptionMsg;
  auto base = new Settings();
  auto derived = parseJsonText(`{"version":"1.0","allowedHosts":["https://a.cr"],"keyPassword":"x","reason":"R",`
    ~ `"noAuthorizedHosts":["https://b.cr"],"sofficePath":"/tmp/programa","signWidth":"150"}`, "prueba");
  auto settings = settingsFromJson(derived, base);
  assert(settings.reason == "R");
  assert(settings.keyPassword == base.keyPassword);
  // Un documento no cambia lo que es de la aplicación.
  assert(settings.sofficePath == base.sofficePath && settings.noAuthorizedHosts == base.noAuthorizedHosts);
  import std.algorithm : canFind;
  assert(collectExceptionMsg(settingsFromJson(parseJsonText(`{"inventado":1}`, "p"), base)).canFind("inventado"));
  assert(collectExceptionMsg(settingsFromJson(parseJsonText(`{"fontSize":true}`, "p"), base)).canFind("fontSize"));
}
