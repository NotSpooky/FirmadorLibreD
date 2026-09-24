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
 * Hilo de la ventana (SwingUtilities.invokeLater en la versión Java). dlangui sólo se
 * puede tocar desde el hilo que atiende los eventos: los demás hilos le pasan trabajo con
 * runOnUi, y los que necesitan una respuesta del usuario (PIN, autorizaciones) esperan
 * con waitOnUi a que el diálogo termine. Al cerrar la aplicación las esperas pendientes
 * se liberan como canceladas. Los errores que no tienen a quién devolverse (trabajo en
 * segundo plano, acciones pasadas al hilo de la ventana, eventos de la ventana) se
 * registran y se le muestran al usuario con reportUiFailure.
 */
module firmador.gui.desktop.uithread;

import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import core.thread : Thread;
import std.exception : enforce;
import std.logger : error;

import dlangui.platforms.common.platform : Window;

private __gshared Window uiWindow;
private __gshared Thread uiThread;
private __gshared Mutex bridgeLock;
private __gshared Condition bridgeSignal;
private __gshared bool shuttingDown;
private __gshared void delegate(Exception) uiErrorReporter;

shared static this() {
  bridgeLock = new Mutex;
  bridgeSignal = new Condition(bridgeLock);
}

/// Registra la ventana principal; se llama desde el hilo de la ventana al crearla.
void registerUiWindow(Window window) @trusted {
  synchronized (bridgeLock) {
    uiWindow = window;
    uiThread = Thread.getThis();
  }
}

/// Se está en el hilo de la ventana.
bool onUiThread() @trusted {
  synchronized (bridgeLock) return uiThread !is null && Thread.getThis() is uiThread;
}

/**
 * Registra cómo se le muestra al usuario un error que no tiene a quién devolverse
 * (DesktopInterface.showError en firmador.gui.desktop.window).
 */
void setUiErrorReporter(void delegate(Exception) reporter) @trusted {
  synchronized (bridgeLock) uiErrorReporter = reporter;
}

/**
 * Registra un error que no tiene a quién devolverse, con lo que se estaba haciendo, y se
 * lo muestra al usuario. Si mostrarlo también falla, queda sólo en la bitácora.
 *
 * Params:
 *   context = qué se estaba haciendo, para la bitácora.
 *   failure = el error; se muestra tal cual para que firmador.gui.errors lo traduzca.
 */
void reportUiFailure(string context, Exception failure) @trusted {
  error(context, ": ", failure.msg);
  void delegate(Exception) reporter;
  synchronized (bridgeLock) reporter = uiErrorReporter;
  if (reporter is null) return;
  try {
    reporter(failure);
  } catch (Exception reportFailure) {
    error("No se pudo mostrar el error al usuario: ", reportFailure.msg);
  }
}

/**
 * Ejecuta en el hilo de la ventana: en el acto si ya se está en él, si no en cuanto la
 * ventana atienda sus eventos. Un error se informa con reportUiFailure: no hay a quién
 * devolverlo.
 */
void runOnUi(void delegate() action) @trusted {
  Window window;
  synchronized (bridgeLock) {
    if (shuttingDown) return;
    window = uiWindow;
  }
  enforce(window !is null, "La ventana todavía no está creada");
  auto guarded = () {
    try {
      action();
    } catch (Exception exception) {
      reportUiFailure("Error en el hilo de la ventana", exception);
    }
  };
  if (onUiThread()) guarded();
  else window.executeInUiThread(guarded);
}

/**
 * Hace `work` en un hilo aparte que no retiene el cierre de la aplicación. Si falla, el
 * error se informa con reportUiFailure y `onFailure` deshace en el hilo de la ventana lo
 * que quedó a medias (avisos de espera, botones desactivados).
 *
 * Params:
 *   context = qué se hace, para la bitácora si falla.
 *   work = el trabajo; lo que muestre al terminar lo pasa con runOnUi.
 *   onFailure = qué hacer en la ventana si `work` lanza un error; puede ser null.
 */
void runInBackground(string context, void delegate() work, void delegate() onFailure = null) @trusted {
  auto worker = new Thread({
    try {
      work();
    } catch (Exception exception) {
      if (onFailure !is null) runOnUi(onFailure);
      reportUiFailure(context, exception);
    }
  });
  worker.isDaemon = true;
  worker.start();
}

/**
 * Inicia en el hilo de la ventana algo que termina más tarde (un diálogo) y espera su
 * resultado. `start` recibe la función con que se entrega el resultado. Si la aplicación
 * se cierra antes, devuelve `cancelled`.
 *
 * No se puede llamar desde el hilo de la ventana: se bloquearía esperando a sí mismo.
 */
T waitOnUi(T)(void delegate(void delegate(T) complete) start, T cancelled) @trusted {
  enforce(!onUiThread(), "waitOnUi no se puede usar desde el hilo de la ventana");
  bool done;
  T result = cancelled;
  runOnUi(() {
    start((T value) {
      synchronized (bridgeLock) {
        if (done) return;
        result = value;
        done = true;
        bridgeSignal.notifyAll();
      }
    });
  });
  synchronized (bridgeLock) {
    while (!done && !shuttingDown) bridgeSignal.wait();
    return done ? result : cancelled;
  }
}

/// Libera las esperas pendientes y deja de aceptar trabajo (al cerrar la aplicación).
void shutdownUi() @trusted {
  synchronized (bridgeLock) {
    shuttingDown = true;
    bridgeSignal.notifyAll();
  }
}
