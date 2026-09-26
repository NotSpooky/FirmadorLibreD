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
 * Pestaña de bitácoras (LoggingFrame y LogHandler). LogBuffer recibe cada línea de la
 * bitácora (firmador.logging.addLogSink) desde que se abre la ventana y conserva las
 * últimas 5000, se vea o no la pestaña; LogPanel las muestra mientras la pestaña está
 * abierta. La pestaña se crea al mostrarla y dlangui la destruye al quitarla, así que el
 * búfer nunca guarda una referencia a un panel destruido.
 */
module firmador.gui.desktop.logpanel;

import core.sync.mutex : Mutex;
import std.array : join;
import std.logger : LogLevel;
import std.utf : toUTF32;

import dlangui.core.types;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.widget;

import firmador.gui.desktop.common;
import firmador.gui.desktop.uithread : runOnUi;
import firmador.logging : addLogSink;

/// Líneas que se conservan.
enum size_t maxLogLines = 5000;

/// Últimas líneas de la bitácora y el panel que las muestra (si la pestaña está abierta).
final class LogBuffer {
  private Mutex lock;
  private string[] lines;
  private LogPanel panel;

  /// Se registra en la bitácora; se crea una vez, con la ventana.
  this() @trusted {
    lock = new Mutex;
    addLogSink((LogLevel level, string line) nothrow {
      try {
        synchronized (lock) {
          lines ~= line;
          if (lines.length > maxLogLines) lines = lines[$ - maxLogLines .. $];
        }
        runOnUi(() => showLine(line));
      } catch (Exception) {
        // Antes de crear la ventana, o al cerrarla, la línea queda en el búfer y en la salida de error.
      }
    });
  }

  /// Líneas conservadas, una por renglón.
  string text() pure @trusted {
    synchronized (lock) return lines.join("\n") ~ (lines.length ? "\n" : "");
  }

  /// Vacía el búfer.
  void clear() pure @trusted {
    synchronized (lock) lines = null;
  }

  private void showLine(string line) {
    if (panel !is null) panel.append(line);
  }

  private void attach(LogPanel shown) pure {
    panel = shown;
  }

  private void detach(LogPanel shown) pure {
    if (panel is shown) panel = null;
  }
}

/// Pestaña de bitácoras; se crea al mostrarla y dlangui la destruye al quitarla.
final class LogPanel : VerticalLayout {
  private LogBuffer buffer;
  private LogWidget lines;

  this(LogBuffer buffer) @trusted {
    super("bitacoras");
    this.buffer = buffer;
    fillParent();
    lines = new LogWidget("lineas");
    lines.fillParent();
    lines.maxLines = cast(int) maxLogLines;
    lines.text = buffer.text.toUTF32;
    addChild(lines);
    auto clear = new Button("vaciar-bitacora", dt("connection_panel_clear"));
    clear.click = (Widget source) {
      buffer.clear();
      lines.text = ""d;
      return true;
    };
    addChild(clear);
    buffer.attach(this);
  }

  ~this() {
    buffer.detach(this);
  }

  private void append(string line) {
    lines.appendText((line ~ "\n").toUTF32);
  }
}
