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
 * con su ayuda, títulos, filas elegibles, desplazamiento vertical, selectores de
 * archivos y carpetas (los del sistema: firmador.gui.desktop.filepicker), dónde guardar
 * el documento firmado (showSaveDialog), las
 * posiciones de los selectores y el selector de página.
 */
module firmador.gui.desktop.common;

import std.algorithm : countUntil;
import std.array : replace;
import std.conv : ConvException, to;
import std.file : exists;
import std.format : format;
import std.path : baseName, dirName, extension, stripExtension;
import std.string : strip, toLower;
import std.utf : toUTF32, toUTF8;

import dlangui.core.events;
import dlangui.core.stdaction;
import dlangui.core.types;
import dlangui.dialogs.dialog;
import dlangui.platforms.common.platform : Window;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.scrollbar;
import dlangui.widgets.widget;

import firmador.documents.document : Document;
import firmador.gui.desktop.dialogs : showConfirmDialog;
import firmador.gui.desktop.filepicker : nearestExistingDirectory, pickPaths, PickKind, PickRequest, usableDirectory;
import firmador.gui.desktop.theme : ThemeColor, themeColor;
import firmador.gui.desktop.uithread : reportUiFailure;
import firmador.i18n : htmlToText, t;
import firmador.settings : Settings;
import firmador.settingsmanager : lastDirectory, rememberDirectory;
import firmador.xml.dom : escapeXml;

/**
 * Área con desplazamiento vertical que ajusta el contenido al ancho visible: el texto se
 * parte en líneas en lugar de pedir desplazamiento horizontal (ScrollWidget mide su
 * contenido con ancho ilimitado).
 */
final class VerticalScroll : ScrollWidget {
  /// Ocupa todo el espacio de su contenedor y muestra `content`.
  this(string id, Widget content) @trusted {
    // Auto y no Invisible: dlangui (0.10.8) usa la barra horizontal aunque no la cree con
    // Invisible y se cae. Como el contenido se ajusta al ancho visible, sólo aparece si algo
    // no cabe de ninguna manera.
    super(id, ScrollBarMode.Auto, ScrollBarMode.Auto);
    contentWidget = content;
    fillParent();
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

/// Título de sección en negrita con un texto traducido.
TextWidget boldTitle(string key) @trusted {
  auto title = new TextWidget(null, dt(key));
  title.fontWeight = 800;
  return title;
}

/// Fila de una lista en la que se elige un elemento: de ancho completo, resaltada si es la elegida.
HorizontalLayout selectableRow(bool selected, int horizontalPadding = 6) @trusted {
  auto row = new HorizontalLayout;
  row.layoutWidth = FILL_PARENT;
  row.padding = Rect(horizontalPadding, 6, horizontalPadding, 6);
  row.margins = Rect(0, 0, 0, 4);
  row.backgroundColor = themeColor(selected ? ThemeColor.rowSelected : ThemeColor.row);
  return row;
}

/// Posición de `value` en los valores de un selector, o `fallback` si no está.
int indexIn(const string[] values, string value, int fallback = 0) pure @safe {
  auto index = values.countUntil(value);
  return index < 0 ? fallback : cast(int) index;
}

/// Valor de la posición elegida en un selector, o el de `fallback` si no hay ninguna elegida.
string valueAt(const string[] values, int index, int fallback = 0) pure @safe {
  int chosen = index < 0 ? fallback : index;
  assert(chosen < values.length, "El selector tiene más opciones que valores");
  return values[chosen];
}

/// Ayuda emergente de un texto traducido que puede traer HTML sencillo.
dstring tip(string key) @trusted {
  return htmlToText(t(key).replace("<br>", "\n")).strip.toUTF32;
}

/**
 * Deja que las ayudas emergentes ocupen varias líneas. tip convierte los <br> en saltos
 * de línea, que el estilo de una sola línea del tema de dlangui dibuja como un carácter
 * sin glifo. Se llama una vez, al crear la ventana (firmador.gui.desktop.window).
 *
 * Throws: Exception si el tema no define el estilo de las ayudas emergentes.
 */
void allowMultilineTooltips() @trusted {
  import std.exception : enforce;
  import dlangui.widgets.styles : currentTheme, STYLE_TOOLTIP;
  // Sin el estilo, get devuelve el del tema entero, que no se debe cambiar.
  auto style = currentTheme.get(STYLE_TOOLTIP);
  enforce(style.id == STYLE_TOOLTIP, "El tema de dlangui no define el estilo de las ayudas emergentes");
  style.maxLines = 0;
}

/// Botón con texto, ayuda y acción.
Button makeButton(string id, string labelKey, string tooltipKey, void delegate() action) @trusted {
  auto button = new Button(id, dt(labelKey));
  if (tooltipKey.length) button.tooltipText = tip(tooltipKey);
  button.click = (Widget source) {
    action();
    return true;
  };
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

/**
 * Pedido al selector (firmador.gui.desktop.filepicker) que empieza en `directory` o, sin
 * él, en la última carpeta usada (firmador.settingsmanager.lastDirectory); si esa carpeta
 * ya no existe, en la más cercana de sus superiores que sí exista, y si no queda ninguna,
 * donde el selector decida.
 */
private PickRequest pickRequest(PickKind kind, string title, string directory) @trusted {
  return PickRequest(kind, title, nearestExistingDirectory!usableDirectory(directory.length ? directory : lastDirectory()));
}

/// Elige archivos para abrir, desde `directory` o la última carpeta usada; entrega las rutas (vacío si se cancela).
void chooseFiles(Window parent, string title, bool multiple, string directory, void delegate(string[] paths) done)
    @trusted {
  auto request = pickRequest(PickKind.open, title, directory);
  request.multiple = multiple;
  pickPaths(parent, request, (string[] paths) {
    if (paths.length) rememberChosenDirectory(dirName(paths[0]));
    done(paths);
  });
}

/// Elige una carpeta, desde `directory` o la última usada; entrega la ruta (null si se cancela).
void chooseDirectory(Window parent, string title, string directory, void delegate(string path) done) @trusted {
  pickPaths(parent, pickRequest(PickKind.directory, title, directory), (string[] paths) {
    if (paths.length == 0) return done(null);
    rememberChosenDirectory(paths[0]);
    done(paths[0]);
  });
}

/**
 * Elige dónde guardar, proponiendo carpeta (o la última usada), nombre y extensión de
 * salida (con punto, o vacía); entrega la ruta tal como se eligió (null si se cancela).
 */
void chooseSaveFile(Window parent, string title, string directory, string proposedName, string outputExtension,
    void delegate(string path) done) @trusted {
  auto request = pickRequest(PickKind.save, title, directory);
  request.proposedName = proposedName;
  request.defaultExtension = outputExtension;
  pickPaths(parent, request, (string[] paths) {
    if (paths.length == 0) return done(null);
    rememberChosenDirectory(dirName(paths[0]));
    done(paths[0]);
  });
}

/**
 * Recuerda la carpeta para el próximo selector de archivos (la de lo último que se eligió
 * o se abrió); si no se puede guardar, se avisa al usuario y se sigue.
 */
void rememberChosenDirectory(string directory) @trusted {
  if (directory.length == 0) return;
  try {
    rememberDirectory(directory);
  } catch (Exception failure) {
    reportUiFailure("No se pudo recordar la última carpeta usada", failure);
  }
}

/**
 * Pregunta dónde guardar el documento firmado (showSaveDialogInternal): propone el nombre
 * del original con «-firmado» (salvo que se sobrescriba) y la extensión de salida, y deja
 * la ruta en el documento. `chosen` se llama sólo si se eligió una.
 */
void chooseSignedOutput(Window parent, Document document, const Settings settings, void delegate() chosen) @trusted {
  string suffix = settings.overwriteSourceFile ? "" : "-firmado";
  string outputExtension = document.signedExtension;
  chooseSaveFile(parent, t("guiswing_dialog_document_save"), dirName(document.pathname),
    proposedSaveName(document.pathname, suffix, outputExtension), outputExtension, (string path) {
    if (path is null) return;
    string target = withOutputExtension(path, outputExtension);
    void accept() {
      document.setPathToSave(target);
      chosen();
    }
    // El selector ya preguntó por el nombre que se escribió, no por el que queda al añadirle la extensión.
    if (target == path || !exists(target)) return accept();
    showConfirmDialog(parent, t("file_overwrite_title"), format(t("file_overwrite_confirm"), escapeXml(baseName(target))),
      (bool replace) {
      if (replace) accept();
    });
  });
}

/**
 * Número de página del selector, siempre entre 1 y `pages`; lo que queda fuera da la
 * vuelta (módulo). Los negativos cuentan desde el final, como en la versión Java (-1 es
 * la última), y el 0, al que se llega con «−» desde la primera, también es la última.
 */
int nextPageValue(int requested, int pages) pure nothrow @safe @nogc {
  if (pages <= 0) return 1;
  long index = requested > 0 ? cast(long) requested - 1 : requested == 0 ? pages - 1 : cast(long) pages + requested;
  long wrapped = index % pages;
  return cast(int) (wrapped < 0 ? wrapped + pages : wrapped) + 1;
}

/// Índice (desde 0) de la página del selector.
int pageIndexFor(int value, int pages) pure nothrow @safe @nogc {
  if (pages <= 0) return 0;
  int index = value > 0 ? value - 1 : pages + value;
  return index < 0 ? 0 : index >= pages ? pages - 1 : index;
}

/// Selector de página con botones; da la vuelta al pasar de la primera o de la última.
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

  int value() const pure @safe {
    return value_;
  }

  /// Cambia el valor; con `notify` avisa a onChange.
  void set(int requested, bool notify) @trusted {
    value_ = nextPageValue(requested, pages);
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

@("should wrap around to the last or first page when the page selector goes past either end")
unittest {
  assert(nextPageValue(0, 5) == 5 && nextPageValue(-1, 5) == 5);
  assert(nextPageValue(6, 5) == 1 && nextPageValue(3, 5) == 3);
  assert(nextPageValue(-5, 5) == 1 && nextPageValue(-6, 5) == 5 && nextPageValue(9, 5) == 4);
  assert(nextPageValue(int.min, 3) >= 1 && nextPageValue(1, 0) == 1);
  assert(pageIndexFor(-1, 5) == 4 && pageIndexFor(2, 5) == 1 && pageIndexFor(1, 0) == 0);
  // Página configurada: 0 es la última y una fuera de rango queda en la más cercana.
  assert(pageIndexFor(0, 5) == 4 && pageIndexFor(9, 5) == 4 && pageIndexFor(-9, 5) == 0);
}
