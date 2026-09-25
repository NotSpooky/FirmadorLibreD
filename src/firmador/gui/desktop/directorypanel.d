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
 * Pestaña de carpetas del modo completo (DirectoryPanel): firma todos los archivos de una
 * carpeta y sus subcarpetas. Los firmados van a «<carpeta>-firmado» con la misma
 * estructura (sufijo de carpeta), junto a cada original con «-Firmado» (sufijo de
 * archivo), a otra carpeta elegida, o todos en un solo contenedor ASiC-E
 * «<carpeta>.asice». Si dos archivos quedarían con el mismo nombre, al segundo se le
 * añade «(1)», al tercero «(2)», etc.
 */
module firmador.gui.desktop.directorypanel;

import std.algorithm : canFind, filter, map, remove, sort;
import std.array : array;
import std.file : dirEntries, exists, isDir, isFile, mkdirRecurse, read, SpanMode;
import std.format : format;
import std.logger : error, info;
import std.path : absolutePath, baseName, buildPath, dirName, extension, relativePath, stripExtension;
import std.string : toLower;
import std.utf : toUTF32;

import dlangui.core.types;
import dlangui.widgets.controls;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.widget;

import firmador.documents.document : Document;
import firmador.gui.desktop.common;
import firmador.gui.desktop.window : DesktopInterface;
import firmador.gui.guiinterface : NotificationType;
import firmador.i18n : t;
import firmador.signers.detector : DocumentSigner, SignatureFormat;
import firmador.validation.model : DetachedContent;

/// Archivo de una carpeta que se va a firmar.
struct DirectoryFile {
  /// Ruta relativa a la carpeta, con «/».
  string relative;
  /// Extensión del formato con que se firma (con punto).
  string signedExtension;
}

/// Dónde se guardan los firmados de una carpeta.
enum DirectoryOutput {
  /// En la carpeta de destino, con la misma estructura.
  destination,
  /// Junto a cada original, con «-Firmado».
  besideOriginal,
}

/**
 * Rutas de salida de los archivos de una carpeta (processFiles), con «(n)» cuando dos
 * coincidirían (sin distinguir mayúsculas).
 */
string[] directoryOutputPaths(string source, const DirectoryFile[] files, string destination, DirectoryOutput output)
    pure @safe {
  string[] paths;
  string[] firstChoices;
  foreach (file; files) {
    string relativeDirectory = dirName(file.relative);
    string stem = stripExtension(baseName(file.relative));
    string name = stem ~ (output == DirectoryOutput.besideOriginal ? "-Firmado" : "") ~ file.signedExtension;
    string directory = output == DirectoryOutput.besideOriginal
      ? (relativeDirectory == "." ? source : buildPath(source, relativeDirectory))
      : (relativeDirectory == "." ? destination : buildPath(destination, relativeDirectory));
    string chosen = buildPath(directory, name);
    size_t repeated;
    foreach (previous; firstChoices) if (previous.toLower == chosen.toLower) repeated++;
    firstChoices ~= chosen;
    if (repeated) chosen = buildPath(directory, format("%s(%d)%s", stripExtension(name), repeated, extension(name)));
    paths ~= chosen;
  }
  return paths;
}

/// Carpeta hermana con «-firmado» donde van los firmados.
string signedDirectoryFor(string directory) pure @safe {
  return buildPath(dirName(directory), baseName(directory) ~ "-firmado");
}

/// Pestaña de carpetas.
final class DirectoryPanel : HorizontalLayout {
  private DesktopInterface host;
  private string[] directories;
  private string selectedDirectory;
  private VerticalLayout list;
  private VerticalLayout detail;

  this(DesktopInterface host) @trusted {
    super("carpetas");
    this.host = host;
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;
    auto left = new VerticalLayout;
    left.layoutWidth = FILL_PARENT;
    left.layoutHeight = FILL_PARENT;
    auto buttons = new HorizontalLayout;
    buttons.addChild(makeButton("elegir-carpeta", "directory_panel_select_directory", null, () {
      chooseDirectory(window, t("directory_panel_select_directory"), null, (string directory) {
        if (directory !is null) addDirectories([directory]);
      });
      return true;
    }));
    buttons.addChild(makeButton("vaciar", "directoty_empty_action", null, () {
      directories = null;
      selectedDirectory = null;
      reloadView();
      host.showNotification(t("directoty_empty_action_done"), NotificationType.success);
      return true;
    }));
    left.addChild(buttons);
    left.addChild(boldTitle("directory_list_panel"));
    list = new VerticalLayout("lista-carpetas");
    list.layoutWidth = FILL_PARENT;
    left.addChild(new VerticalScroll("lista-carpetas-scroll", list));
    addChild(left);
    detail = new VerticalLayout("detalle-carpeta");
    detail.layoutWidth = FILL_PARENT;
    detail.layoutHeight = FILL_PARENT;
    detail.padding = Rect(12, 0, 0, 0);
    addChild(detail);
  }

  /// Añade carpetas que no estén ya (addFiles).
  void addDirectories(string[] paths) @trusted {
    bool added;
    foreach (path; paths) {
      string absolute = absolutePath(path);
      if (!exists(absolute) || !isDir(absolute) || directories.canFind(absolute)) continue;
      directories ~= absolute;
      added = true;
    }
    reloadView();
    host.showNotification(t(added ? "directory_add_directory_done" : "directory_add_directory_error"),
      added ? NotificationType.success : NotificationType.warning);
  }

  private void reloadView() {
    list.removeAllChildren();
    foreach (directory; directories) list.addChild(directoryRow(directory));
  }

  private void showDetail(string directory) {
    detail.removeAllChildren();
    void add(string id, string key, bool delegate() action) {
      auto button = makeButton(id, key, null, action);
      button.layoutWidth = FILL_PARENT;
      button.margins = Rect(0, 0, 0, 5);
      detail.addChild(button);
    }
    add("firmar-carpeta", "directory_panel_sign", () {
      signDirectory(directory, signedDirectoryFor(directory), DirectoryOutput.destination);
      return true;
    });
    add("firmar-archivo", "directory_panel_sign_document", () {
      signDirectory(directory, null, DirectoryOutput.besideOriginal);
      return true;
    });
    add("firmar-asic", "directory_panel_sign_asic", () {
      signAsAsic(directory);
      return true;
    });
    add("guardar-en", "directory_panel_save_as", () {
      chooseDirectory(window, t("directory_panel_save_as"), null, (string destination) {
        if (destination !is null) signDirectory(directory, destination, DirectoryOutput.destination);
      });
      return true;
    });
    add("guardar-en-archivo", "directory_panel_save_as_name", () {
      chooseDirectory(window, t("directory_panel_save_as_name"), null, (string destination) {
        if (destination !is null) signDirectory(directory, destination, DirectoryOutput.besideOriginal);
      });
      return true;
    });
    detail.addChild(new TextWidget(null, directory.toUTF32));
    size_t files, subdirectories;
    string[] subdirectoryLines;
    try {
      foreach (entry; dirEntries(directory, SpanMode.shallow)) {
        if (entry.isDir) {
          subdirectories++;
          size_t inside;
          foreach (child; dirEntries(entry.name, SpanMode.shallow)) if (child.isFile) inside++;
          subdirectoryLines ~= format("%s - %d %s", baseName(entry.name), inside, t("directory_archives_label"));
        } else {
          files++;
        }
      }
    } catch (Exception exception) {
      error("No se pudo leer la carpeta ", directory, ": ", exception.msg);
    }
    detail.addChild(new TextWidget(null, format(t("directory_info_label"), files, subdirectories).toUTF32));
    foreach (line; subdirectoryLines) detail.addChild(new TextWidget(null, line.toUTF32));
  }

  /// Archivos de la carpeta y sus subcarpetas, ordenados; avisa y devuelve vacío si no hay.
  private string[] filesOf(string directory) {
    if (!exists(directory) || !isDir(directory)) {
      host.showMessage("El directorio no existe o no es válido: " ~ directory);
      return null;
    }
    string[] files;
    try {
      foreach (entry; dirEntries(directory, SpanMode.depth)) if (entry.isFile) files ~= entry.name;
    } catch (Exception exception) {
      error("Error al recorrer el directorio ", directory, ": ", exception.msg);
      host.showMessage("Error al procesar el directorio.");
      return null;
    }
    files.sort();
    if (files.length == 0) host.showMessage("No se encontraron documentos en el directorio.");
    return files;
  }

  /// Documentos de los archivos con extensión; avisa de los que no la tienen.
  /// Firma cada archivo de la carpeta con su formato (processDirectory).
  private void signDirectory(string directory, string destination, DirectoryOutput output) {
    auto documents = host.openDocuments(filesOf(directory));
    if (documents.length == 0) return;
    DirectoryFile[] files;
    foreach (document; documents) {
      files ~= DirectoryFile(relativePath(document.pathname, directory), document.signedExtension);
    }
    auto outputs = directoryOutputPaths(directory, files, destination, output);
    try {
      foreach (index, document; documents) {
        mkdirRecurse(dirName(outputs[index]));
        document.setPathToSave(outputs[index]);
      }
    } catch (Exception exception) {
      error("No se pudo preparar la carpeta de destino: ", exception.msg);
      host.showError(exception);
      return;
    }
    info("Firmando ", documents.length, " documentos de ", directory);
    host.signDocuments(documents);
  }

  /// Firma toda la carpeta en un solo contenedor ASiC-E (signWithAsic).
  private void signAsAsic(string directory) {
    auto files = filesOf(directory);
    if (files.length == 0) return;
    Document container;
    try {
      container = new Document(host, files[0]);
      foreach (file; files[1 .. $]) {
        container.additionalDocuments ~= DetachedContent(relativePath(file, directory),
          cast(immutable(ubyte)[]) read(file));
      }
    } catch (Exception exception) {
      error("No se pudieron leer los archivos de ", directory, ": ", exception.msg);
      host.showError(exception);
      return;
    }
    container.setSigner(DocumentSigner(SignatureFormat.asic));
    container.setPathToSave(buildPath(dirName(directory), baseName(directory) ~ ".asice"));
    host.signDocuments([container]);
  }

  /// Fila de una carpeta (función aparte: los cierres de un bucle comparten sus variables).
  private Widget directoryRow(string directory) {
    auto row = selectableRow(directory == selectedDirectory);
    auto name = new Button(null, (baseName(directory) ~ "  (" ~ directory ~ ")").toUTF32);
    name.layoutWidth = FILL_PARENT;
    name.click = (Widget source) {
      selectedDirectory = directory;
      showDetail(directory);
      reloadView();
      return true;
    };
    row.addChild(name);
    auto remove_ = new Button(null, "X"d);
    remove_.click = (Widget source) {
      directories = directories.remove!(existing => existing == directory);
      if (selectedDirectory == directory) {
        selectedDirectory = null;
        detail.removeAllChildren();
      }
      reloadView();
      return true;
    };
    row.addChild(remove_);

    return row;
  }

}

@("should mirror the folder structure and number repeated names when signing a directory")
unittest {
  auto files = [DirectoryFile("a.pdf", ".pdf"), DirectoryFile("sub/b.xml", ".xml"), DirectoryFile("A.pdf", ".pdf"),
    DirectoryFile("c.docx", ".docx")];
  assert(directoryOutputPaths("/doc", files, "/doc-firmado", DirectoryOutput.destination)
    == ["/doc-firmado/a.pdf", "/doc-firmado/sub/b.xml", "/doc-firmado/A(1).pdf", "/doc-firmado/c.docx"]);
  assert(directoryOutputPaths("/doc", files[0 .. 2], null, DirectoryOutput.besideOriginal)
    == ["/doc/a-Firmado.pdf", "/doc/sub/b-Firmado.xml"]);
  assert(signedDirectoryFor("/home/ana/contratos") == "/home/ana/contratos-firmado");
}
