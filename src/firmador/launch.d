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
 * Propiedades de lanzamiento: lo que la versión Java recibía como propiedades del
 * sistema (-Djnlp.remoteOrigin=…, -Djnlp.signatureImage=…, -Djnlp.hideSignatureAdvice=…).
 * Se siguen aceptando con la misma sintaxis, porque así las registró el instalador de
 * Windows para el esquema firmador:, y además un argumento «firmador:<origen>» tal cual lo
 * entrega el navegador. Se fijan una sola vez al arrancar (firmador.app) y se leen desde
 * cualquier hilo.
 */
module firmador.launch;

import core.sync.mutex : Mutex;
import std.algorithm : startsWith;
import std.array : replace;

import firmador.configuration : remoteUrlScheme;

/// Propiedad con el origen de la página que lanzó Firmador Remoto.
enum string remoteOriginProperty = "jnlp.remoteOrigin";
/// Propiedad con la imagen de firma que impone quien lanza la aplicación.
enum string signatureImageProperty = "jnlp.signatureImage";
/// Propiedad que oculta el aviso de representación gráfica en la firma visible.
enum string hideSignatureAdviceProperty = "jnlp.hideSignatureAdvice";

private __gshared string[string] properties;
private __gshared Mutex propertiesLock;

shared static this() {
  propertiesLock = new Mutex;
}

/**
 * Separa las propiedades de lanzamiento de los demás argumentos. Devuelve las propiedades
 * encontradas y deja en `remaining` el resto, en el mismo orden.
 */
string[string] extractLaunchProperties(const string[] arguments, out string[] remaining) pure @safe {
  string[string] found;
  foreach (argument; arguments) {
    if (argument.startsWith("-D")) {
      string assignment = argument[2 .. $];
      import std.string : indexOf;
      auto separator = assignment.indexOf('=');
      if (separator > 0) {
        found[assignment[0 .. separator]] = assignment[separator + 1 .. $];
        continue;
      }
    }
    if (argument.startsWith(remoteUrlScheme)) {
      found[remoteOriginProperty] = remoteOriginFromUrl(argument);
      continue;
    }
    remaining ~= argument;
  }
  return found;
}

/// Origen de un enlace firmador:, con el # que el navegador escapa como %23.
string remoteOriginFromUrl(string url) pure @safe {
  string origin = url.startsWith(remoteUrlScheme) ? url[remoteUrlScheme.length .. $] : url;
  return origin.replace("%23", "#");
}

/// Fija o reemplaza propiedades de lanzamiento (al arrancar, o al recibir un enlace en macOS).
void setLaunchProperties(const string[string] values) @trusted {
  synchronized (propertiesLock) foreach (key, value; values) properties[key] = value;
}

/// Valor de una propiedad de lanzamiento, o null si no se indicó.
string launchProperty(string key) @trusted {
  propertiesLock.lock();
  scope (exit) propertiesLock.unlock();
  if (auto value = key in properties) return *value;
  return null;
}

/// Como Boolean.getBoolean: verdadero sólo si la propiedad existe y vale "true" sin distinguir mayúsculas.
bool launchFlag(string key) @safe {
  import std.uni : icmp;
  string value = launchProperty(key);
  return value !is null && icmp(value, "true") == 0;
}

@("should separate -D properties and firmador: links from the other arguments")
unittest {
  string[] remaining;
  auto found = extractLaunchProperties(
    ["-dshell", "-Djnlp.remoteOrigin=http://localhost:8000#3517#True", "documento.pdf", "-Djnlp.hideSignatureAdvice=true"],
    remaining);
  assert(remaining == ["-dshell", "documento.pdf"]);
  assert(found[remoteOriginProperty] == "http://localhost:8000#3517#True");
  assert(found[hideSignatureAdviceProperty] == "true");
  auto fromLink = extractLaunchProperties(["firmador:https://sitio.example%233518"], remaining);
  assert(fromLink[remoteOriginProperty] == "https://sitio.example#3518");
  assert(remaining.length == 0);
}
