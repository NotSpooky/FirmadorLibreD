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
 * Avisa cuando cambia el estado de los lectores (se mete o se saca una tarjeta) por PC/SC,
 * para que firmador.cards.detector vuelva a leer sin sondear la biblioteca PKCS#11
 * (CardTerminalWatcher). Es opcional: sin pcscd o sin lector, awaitChange se limita a
 * esperar y el detector sigue por sondeo.
 */
module firmador.cards.terminalwatcher;

import core.thread : Thread;
import core.time : dur;
import std.logger : info, trace;
import std.string : fromStringz, toStringz;

import cpcsc;

private enum LONG success = cast(LONG) 0x00000000;
private enum LONG timeoutError = cast(LONG) 0x8010000A;
private enum LONG cancelledError = cast(LONG) 0x80100002;
private enum LONG noReadersError = cast(LONG) 0x8010002E;
private enum DWORD stateUnaware = 0x0000;
private enum DWORD stateChanged = 0x0002;
private enum DWORD stateIgnore = 0x0001;
private enum DWORD scopeSystem = 0x0002;
private enum string plugAndPlayReader = `\\?PnP?\Notification`;

/// Observador de lectores PC/SC.
final class CardTerminalWatcher {
  private SCARDCONTEXT context;
  private bool contextOpen;
  private bool failureLogged;
  private SCARD_READERSTATE[] states;
  private string[] readerNames;

  /// Crea el observador, o null si PC/SC no está disponible en esta máquina.
  static CardTerminalWatcher create() @trusted {
    auto watcher = new CardTerminalWatcher;
    if (!watcher.establish()) {
      info("Sin eventos de lector (PC/SC no disponible), se sondeará periódicamente");
      return null;
    }
    return watcher;
  }

  private bool establish() @trusted {
    LONG result = SCardEstablishContext(scopeSystem, null, null, &context);
    contextOpen = result == success;
    return contextOpen;
  }

  /// Libera el contexto de PC/SC.
  void close() @trusted {
    if (contextOpen) {
      SCardReleaseContext(context);
      contextOpen = false;
    }
  }

  /// Interrumpe una espera en curso desde otro hilo.
  void cancel() @trusted {
    if (contextOpen) SCardCancel(context);
  }

  private string[] listReaders() @trusted {
    DWORD length;
    LONG result = SCardListReaders(context, null, null, &length);
    if (result == noReadersError || length == 0) return [];
    if (result != success) throw new Exception("SCardListReaders falló");
    auto buffer = new char[length];
    result = SCardListReaders(context, null, buffer.ptr, &length);
    if (result == noReadersError) return [];
    if (result != success) throw new Exception("SCardListReaders falló");
    string[] names;
    size_t start = 0;
    foreach (index; 0 .. length) {
      if (buffer[index] == '\0') {
        if (index > start) names ~= buffer[start .. index].idup;
        start = index + 1;
      }
    }
    return names;
  }

  /**
   * Espera a que cambie el estado de algún lector, a lo sumo `timeoutMilliseconds`.
   * Devuelve true si hubo inserción, extracción o un lector nuevo.
   */
  bool awaitChange(long timeoutMilliseconds) @trusted {
    try {
      if (!contextOpen && !establish()) {
        Thread.sleep(dur!"msecs"(timeoutMilliseconds));
        return false;
      }
      string[] names = listReaders();
      if (names != readerNames) {
        bool hadReaders = readerNames.length > 0;
        readerNames = names;
        states = new SCARD_READERSTATE[names.length + 1];
        foreach (index, name; names) {
          states[index].szReader = name.toStringz;
          states[index].dwCurrentState = stateUnaware;
        }
        states[$ - 1].szReader = plugAndPlayReader.toStringz;
        states[$ - 1].dwCurrentState = stateUnaware;
        // La primera lectura sólo fija el estado actual; un lector que aparece es un cambio.
        SCardGetStatusChange(context, 0, states.ptr, cast(DWORD) states.length);
        foreach (ref state; states) state.dwCurrentState = state.dwEventState & ~stateChanged;
        if (hadReaders || names.length > 0) return hadReaders;
      }
      LONG result = SCardGetStatusChange(context, cast(DWORD) timeoutMilliseconds, states.ptr, cast(DWORD) states.length);
      if (result == timeoutError || result == cancelledError) return false;
      if (result != success) throw new Exception("SCardGetStatusChange falló");
      bool changed = false;
      foreach (ref state; states) {
        if (state.dwEventState & stateChanged) changed = true;
        state.dwCurrentState = state.dwEventState & ~stateChanged;
      }
      failureLogged = false;
      return changed;
    } catch (Exception exception) {
      if (!failureLogged) {
        trace("No se pudo esperar cambios en los lectores, se seguirá por sondeo: ", exception.msg);
        failureLogged = true;
      }
      // Se rehace el contexto: un lector conectado después no aparecería en la lista vieja.
      close();
      readerNames = null;
      Thread.sleep(dur!"msecs"(timeoutMilliseconds));
      return false;
    }
  }
}
