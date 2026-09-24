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
 * Piezas comunes de los paneles de la ventana: textos traducidos para dlangui, botones
 * con su ayuda, selectores de archivos y carpetas, el nombre que se propone al guardar
 * (showSaveDialog) y el selector de página que admite negativos (desde el final).
 */
module firmador.gui.desktop.common;

import std.algorithm : endsWith;
import std.array : replace;
import std.conv : ConvException, to;
import std.file : exists, isDir;
import std.path : baseName, dirName, extension, stripExtension;
import std.string : strip, toLower;
import std.utf : toUTF32, toUTF8;

import dlangui.core.events;
import dlangui.core.stdaction;
import dlangui.core.types;
import dlangui.dialogs.dialog;
import dlangui.dialogs.filedlg;
import dlangui.platforms.common.platform : Window;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.scrollbar;
import dlangui.widgets.widget;

import firmador.i18n : htmlToText, t;

/**
 * Área con desplazamiento vertical que ajusta el contenido al ancho visible: el texto se
 * parte en líneas en lugar de pedir desplazamiento horizontal (ScrollWidget mide su
 * contenido con ancho ilimitado).
 */
final class VerticalScroll : ScrollWidget {
  this(string id) @trusted {
    // Auto y no Invisible: dlangui (0.10.8) usa la barra horizontal aunque no la cree con
    // Invisible y se cae. Como el contenido se ajusta al ancho visible, sólo aparece si algo
    // no cabe de ninguna manera.
    super(id, ScrollBarMode.Auto, ScrollBarMode.Auto);
  }

  override Point fullContentSize() {
    Point size;
    if (_contentWidget !is null) {
      _contentWidget.measure(_clientRect.width, SIZE_UNSPECIFIED);
      size.x = _contentWidget.measuredWidth > _clientRect.width ? _contentWidget.measuredWidth : _clientRect.width;
      size.y = _contentWidget.measuredHeight;
    }
    _fullScrollableArea.right = size.x;
    _fullScrollableArea.bottom = size.y;
    return size;
  }
}

/// Texto traducido para dlangui.
dstring dt(string key) @trusted {
  return t(key).toUTF32;
}

/// Ayuda emergente de un texto traducido que puede traer HTML sencillo.
dstring tip(string key) @trusted {
  return htmlToText(t(key).replace("<br>", "\n")).strip.toUTF32;
}

/// Botón con texto, ayuda y acción.
Button makeButton(string id, string labelKey, string tooltipKey, bool delegate() action) @trusted {
  auto button = new Button(id, dt(labelKey));
  if (tooltipKey.length) button.tooltipText = tip(tooltipKey);
  button.click = (Widget source) => action();
  return button;
}

/**
 * Nombre que se propone al guardar un documento (showSaveDialogInternal): el del
 * original con el sufijo y la extensión de salida. El sufijo sobra cuando la extensión
 * de salida ya distingue el archivo del original.
 */
string proposedSaveName(string original, string suffix, string outputExtension) pure @safe {
  string sourceExtension = extension(original);
  string chosenExtension = outputExtension.length ? outputExtension : sourceExtension;
  if (outputExtension.length && outputExtension.toLower != sourceExtension.toLower) suffix = "";
  return stripExtension(baseName(original)) ~ suffix ~ chosenExtension;
}

/// Añade la extensión de salida si el nombre elegido no trae ninguna.
string withOutputExtension(string chosen, string outputExtension) pure @safe {
  return outputExtension.length && extension(chosen).length == 0 ? chosen ~ outputExtension : chosen;
}

/// Elige archivos para abrir; entrega las rutas (vacío si se cancela).
void chooseFiles(Window parent, string title, bool multiple, string directory, void delegate(string[] paths) done)
    @trusted {
  auto dialog = new FileDialog(UIString.fromRaw(title.toUTF32), parent, null,
    DialogFlag.Modal | DialogFlag.Resizable | FileDialogFlag.FileMustExist);
  dialog.allowMultipleFiles = multiple;
  if (directory.length && exists(directory) && isDir(directory)) dialog.path = directory;
  dialog.dialogResult = (Dialog source, const Action result) {
    if (result is null || result.id != StandardAction.Open) return done(null);
    string[] paths = multiple ? dialog.filenames : null;
    if (paths.length == 0 && dialog.filename.length) paths = [dialog.filename];
    done(paths);
  };
  dialog.show();
}

/// Elige una carpeta; entrega la ruta (null si se cancela).
void chooseDirectory(Window parent, string title, string directory, void delegate(string path) done) @trusted {
  auto dialog = new FileDialog(UIString.fromRaw(title.toUTF32), parent, null,
    DialogFlag.Modal | DialogFlag.Resizable | FileDialogFlag.SelectDirectory);
  if (directory.length && exists(directory) && isDir(directory)) dialog.path = directory;
  dialog.dialogResult = (Dialog source, const Action result) {
    if (result is null || result.id != StandardAction.OpenDirectory) return done(null);
    string chosen = dialog.filename;
    while (chosen.length > 1 && (chosen.endsWith("/") || chosen.endsWith("\\"))) chosen = chosen[0 .. $ - 1];
    done(chosen.length ? chosen : dialog.path);
  };
  dialog.show();
}

/// Elige dónde guardar, proponiendo carpeta y nombre; entrega la ruta (null si se cancela).
void chooseSaveFile(Window parent, string title, string directory, string proposedName,
    void delegate(string path) done) @trusted {
  auto dialog = new FileDialog(UIString.fromRaw(title.toUTF32), parent, null,
    DialogFlag.Modal | DialogFlag.Resizable | FileDialogFlag.Save);
  if (directory.length && exists(directory) && isDir(directory)) dialog.path = directory;
  dialog.filename = proposedName;
  dialog.dialogResult = (Dialog source, const Action result) {
    if (result is null || result.id != StandardAction.Save) return done(null);
    done(result.stringParam.length ? result.stringParam : dialog.filename);
  };
  dialog.show();
}

/**
 * Número de página del selector (pageSpinner): positivo desde el principio, negativo
 * desde el final; el cero se salta en la dirección en que se venía.
 */
int nextPageValue(int current, int requested, int pages) pure nothrow @safe @nogc {
  if (pages <= 0) return 1;
  if (requested > pages) requested = pages;
  if (requested < -pages) requested = -pages;
  if (requested == 0) return current > 0 ? -1 : 1;
  return requested;
}

/// Índice (desde 0) de la página del selector.
int pageIndexFor(int value, int pages) pure nothrow @safe @nogc {
  if (pages <= 0) return 0;
  int index = value > 0 ? value - 1 : pages + value;
  return index < 0 ? 0 : index >= pages ? pages - 1 : index;
}

/// Selector de página con botones y negativos (página desde el final).
final class PageSelector : HorizontalLayout {
  /// Se llama cuando el usuario cambia la página.
  void delegate(int value) onChange;
  private EditLine field;
  private int pages;
  private int value_ = 1;

  this(string id) @trusted {
    super(id);
    auto previous = new Button(null, "−"d);
    previous.click = (Widget source) { set(value_ - 1, true); return true; };
    field = new EditLine(id ~ "-valor", "1"d);
    field.minWidth = 56;
    field.enterKey = (EditWidgetBase source) { parseField(); return true; };
    field.focusChange = (Widget source, bool focused) { if (!focused) parseField(); return true; };
    auto next = new Button(null, "+"d);
    next.click = (Widget source) { set(value_ + 1, true); return true; };
    addChild(previous);
    addChild(field);
    addChild(next);
  }

  /// Cantidad de páginas del documento.
  void setPages(int count) @trusted {
    pages = count;
    set(value_, false);
  }

  int value() const @safe {
    return value_;
  }

  /// Cambia el valor; con `notify` avisa a onChange.
  void set(int requested, bool notify) @trusted {
    value_ = nextPageValue(value_, requested, pages);
    field.text = value_.to!dstring;
    if (notify && onChange !is null) onChange(value_);
  }

  private void parseField() {
    try {
      set(field.text.toUTF8.strip.to!int, true);
    } catch (ConvException) {
      field.text = value_.to!dstring;
    }
  }
}

@("should propose the save name with the output extension and drop the suffix when it already differs")
unittest {
  assert(proposedSaveName("/home/a/contrato.pdf", "-firmado", ".pdf") == "contrato-firmado.pdf");
  assert(proposedSaveName("/home/a/contrato.pdf", "-firmado", ".asice") == "contrato.asice");
  assert(proposedSaveName("/home/a/datos.odt", "-firmado", "") == "datos-firmado.odt");
  assert(withOutputExtension("/tmp/salida", ".pdf") == "/tmp/salida.pdf");
  assert(withOutputExtension("/tmp/salida.PDF", ".pdf") == "/tmp/salida.PDF");
}

@("should skip page zero and count negative pages from the end when moving the page selector")
unittest {
  assert(nextPageValue(1, 0, 5) == -1);
  assert(nextPageValue(-1, 0, 5) == 1);
  assert(nextPageValue(3, 9, 5) == 5);
  assert(nextPageValue(3, -9, 5) == -5);
  assert(pageIndexFor(-1, 5) == 4 && pageIndexFor(2, 5) == 1 && pageIndexFor(1, 0) == 0);
}
