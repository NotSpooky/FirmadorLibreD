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
 * Pestaña de bitácoras (LoggingFrame y LogHandler): recibe cada línea de la bitácora
 * (firmador.logging.addLogSink) y la muestra, conservando las últimas 5000 líneas.
 */
module firmador.gui.desktop.logpanel;

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

/// Pestaña de bitácoras.
final class LogPanel : VerticalLayout {
  private LogWidget lines;

  this() @trusted {
    super("bitacoras");
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;
    lines = new LogWidget("lineas");
    lines.layoutWidth = FILL_PARENT;
    lines.layoutHeight = FILL_PARENT;
    lines.maxLines = 5000;
    addChild(lines);
    auto clear = new Button("vaciar-bitacora", dt("connection_panel_clear"));
    clear.click = (Widget source) { lines.text = ""d; return true; };
    addChild(clear);
    addLogSink((LogLevel level, string line) nothrow {
      try {
        runOnUi(() { lines.appendText((line ~ "\n").toUTF32); });
      } catch (Exception) {
        // Antes de crear la ventana, o al cerrarla, la línea sólo queda en la salida de error.
      }
    });
  }
}
