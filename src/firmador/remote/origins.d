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
 * Decide si un origen puede hablar con Firmador y, si hace falta, se lo pregunta al
 * usuario (OriginAuthorizer). Lo consultan el servidor de Firmador Remoto, el panel de
 * conexiones y el traspaso entre instancias; las preguntas en curso se comparten, de modo
 * que varias solicitudes del mismo origen abren una sola ventana.
 */
module firmador.remote.origins;

import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import std.algorithm : canFind, map;
import std.array : array;
import std.logger : info;
import std.string : strip, toLower;
import std.typecons : Nullable;

import firmador.gui.guiinterface;
import firmador.settings : Settings;
import firmador.settingsmanager : writeSettings;

/// Origen en minúsculas, sin espacios ni barra final (normalize).
string normalizeOrigin(string origin) pure @safe {
  string normalized = origin.toLower.strip;
  while (normalized.length && normalized[$ - 1] == '/') normalized = normalized[0 .. $ - 1];
  return normalized.strip;
}

/// El origen está entre los autorizados (permanentes o de esta sesión).
bool isOriginAllowed(const Settings settings, string origin) pure @trusted {
  string normalized = normalizeOrigin(origin);
  if (normalized.length == 0) return false;
  synchronized (cast(Settings) settings) {
    return settings.getAllowedHosts().map!normalizeOrigin.array.canFind(normalized);
  }
}

private __gshared Mutex pendingLock;
private __gshared Condition pendingAnswered;
private __gshared bool[string] asking;
private __gshared HostAuthorization[string] answers;

shared static this() {
  pendingLock = new Mutex;
  pendingAnswered = new Condition(pendingLock);
}

/**
 * Si ya hay una pregunta abierta por ese origen, espera su respuesta y devuelve si quedó
 * autorizado; nulo si nadie pregunta por él (awaitPending).
 */
Nullable!bool awaitPendingAuthorization(string origin) @trusted {
  synchronized (pendingLock) {
    if ((origin in asking) is null) return Nullable!bool.init;
    return Nullable!bool(answerOfPending(origin) != HostAuthorization.denied);
  }
}

/// Espera a que termine la pregunta en curso por el origen y da su respuesta; se llama con pendingLock tomado.
private HostAuthorization answerOfPending(string origin) @trusted {
  while ((origin in asking) !is null) pendingAnswered.wait();
  auto answer = origin in answers;
  return answer is null ? HostAuthorization.denied : *answer;
}

/// Pregunta una sola vez por origen aunque lleguen varias solicitudes a la vez (ask).
private HostAuthorization ask(GuiInterface gui, string origin) @trusted {
  synchronized (pendingLock) {
    if ((origin in asking) !is null) return answerOfPending(origin);
    asking[origin] = true;
    answers.remove(origin);
  }
  HostAuthorization answer = HostAuthorization.denied;
  scope (exit) {
    synchronized (pendingLock) {
      asking.remove(origin);
      answers[origin] = answer;
      pendingAnswered.notifyAll();
    }
  }
  answer = gui.askHostAuthorization(origin);
  return answer;
}

/**
 * Autoriza el origen preguntándole al usuario si no lo estaba (authorize). Una respuesta
 * «siempre» se guarda en la configuración; «esta vez» sólo dura la sesión.
 */
bool authorizeOrigin(GuiInterface gui, Settings settings, string origin) @trusted {
  if (isOriginAllowed(settings, origin)) return true;
  auto answer = ask(gui, origin);
  synchronized (settings) {
    final switch (answer) {
      case HostAuthorization.always:
        settings.registerAllowedOrigin(origin);
        writeSettings(settings, true);
        break;
      case HostAuthorization.once:
        settings.addTempAllowedHost(origin);
        break;
      case HostAuthorization.denied:
        return false;
    }
    settings.removeNoAuthorizedHost(origin);
  }
  info("Origen autorizado: ", origin);
  gui.originAuthorized(origin);
  return true;
}

@("should compare origins without case, spaces or a trailing slash")
unittest {
  assert(normalizeOrigin(" HTTPS://Tramites.CR/ ") == "https://tramites.cr");
  auto settings = new Settings();
  settings.setRegisteredAllowedOrigins(["https://tramites.cr/"]);
  assert(isOriginAllowed(settings, "https://TRAMITES.cr"));
  assert(!isOriginAllowed(settings, "https://otro.cr"));
  assert(!isOriginAllowed(settings, ""));
}
