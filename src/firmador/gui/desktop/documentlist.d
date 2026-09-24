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
 * Pestaña de documentos del modo completo (ListDocumentPanel, ButtonActionsController y
 * ListDocumentPanelService en la versión Java): la lista de documentos locales o
 * virtuales con sus acciones (firmar, ir a la vista previa, cambiar dónde se guarda,
 * cambiar el formato, quitar), y a la derecha el reporte del documento elegido o las
 * acciones sobre la lista (firmar todos o los elegidos, preparar todos, cambiar la
 * carpeta de salida, aplicar la configuración, guardar y cargar la lista, ordenar y
 * pedir documentos virtuales a los servicios).
 *
 * La lista guardada es document_list.csv junto a la configuración (@contract
 * document-list-csv): nombre, ruta, ruta de salida y archivo de configuración del
 * documento en docSettings.
 */
module firmador.gui.desktop.documentlist;

import std.algorithm : canFind, countUntil, filter, map, remove, sort, startsWith;
import std.array : array, join;
import std.conv : to;
import std.datetime.date : Date, DateTimeException;
import std.file : exists, isDir, readText, rmdirRecurse;
import std.format : format;
import std.logger : error, info;
import std.path : baseName, buildPath, dirName;
import std.string : indexOf, lineSplitter, strip, toLower;
import std.utf : toUTF32, toUTF8;
import std.uuid : UUID;

import dlangui.core.events;
import dlangui.core.types;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.widget;

import firmador.connections.config : ConnectionKind;
import firmador.connections.connection : Connection;
import firmador.connections.external : deleteVirtualDocument, reloadVirtualDocuments;
import firmador.documents.document : Document;
import firmador.gui.desktop.common;
import firmador.gui.desktop.dialogs;
import firmador.gui.desktop.richtext : RichText;
import firmador.gui.desktop.uithread : runOnUi;
import firmador.gui.desktop.window : DesktopInterface;
import firmador.gui.guiinterface : NotificationType;
import firmador.i18n : t;
import firmador.plugins.plugin : csvField;
import firmador.settingsmanager : configDirectory, configFilePath, loadDocumentSettings, saveDocumentSettings,
  writeFileAtomically;
import firmador.signers.detector : formatOf, selectableFormats, SignatureFormat, signerForFormat;

/// Fila de document_list.csv.
struct SavedDocument {
  string name;
  string pathName;
  string pathToSave;
  string settingsPath;
}

/// Campos de una línea CSV (RFC 4180: comillas dobles y comillas escapadas).
string[] parseCsvLine(string line) pure @safe {
  string[] fields;
  string field;
  bool quoted;
  for (size_t index = 0; index < line.length; index++) {
    char character = line[index];
    if (quoted) {
      if (character == '"' && index + 1 < line.length && line[index + 1] == '"') {
        field ~= '"';
        index++;
      } else if (character == '"') {
        quoted = false;
      } else {
        field ~= character;
      }
    } else if (character == '"') {
      quoted = true;
    } else if (character == ',') {
      fields ~= field;
      field = null;
    } else {
      field ~= character;
    }
  }
  return fields ~ field;
}

/// document_list.csv con su cabecera.
string formatDocumentList(const SavedDocument[] documents) pure @safe {
  string csv = `"name","pathName","pathToSave","settingsPath"` ~ "\n";
  foreach (document; documents) {
    csv ~= [document.name, document.pathName, document.pathToSave, document.settingsPath].map!csvField.join(",")
      ~ "\n";
  }
  return csv;
}

/**
 * Filas de document_list.csv, sin la cabecera.
 *
 * Throws: Exception si una fila no trae los cuatro campos.
 */
SavedDocument[] parseDocumentList(string csv) pure @safe {
  import std.exception : enforce;
  SavedDocument[] documents;
  bool header = true;
  foreach (line; csv.lineSplitter) {
    if (header) {
      header = false;
      continue;
    }
    if (line.strip.length == 0) continue;
    auto fields = parseCsvLine(line);
    enforce(fields.length >= 4, format("La lista de documentos tiene una fila incompleta: %s", line));
    documents ~= SavedDocument(fields[0], fields[1], fields[2], fields[3]);
  }
  return documents;
}

/// Orden de búsqueda: primero los que empiezan con el texto, luego los que lo contienen.
int searchRank(string name, string query) pure @safe {
  string lowered = name.toLower;
  string wanted = query.toLower;
  if (lowered.startsWith(wanted)) return 0;
  if (lowered.canFind(wanted)) return 1;
  return 2;
}

/// Fecha dd/MM/yyyy de los documentos virtuales, o `fallback` si no se puede leer.
Date parseListDate(string text, Date fallback) pure @safe {
  auto parts = text.strip.length >= 10 ? [text[0 .. 2], text[3 .. 5], text[6 .. 10]] : null;
  if (parts is null) return fallback;
  try {
    return Date(parts[2].to!int, parts[1].to!int, parts[0].to!int);
  } catch (Exception) {
    return fallback;
  }
}

/// Pestaña de documentos.
final class DocumentListPanel : HorizontalLayout {
  private DesktopInterface host;
  private Document[] allDocuments;
  private Document[] selected;
  private Document current;
  private bool onlyVirtual;
  private string lastAction = "na";
  private bool[string] ascending;
  private VerticalLayout rows;
  private Button localButton, virtualButton;
  private RichText report;
  private VerticalScroll reportScroll;
  private VerticalLayout actions;
  private VerticalLayout connectionButtons;
  private Button selectAllButton;
  private Widget[] localOnlyButtons;

  this(DesktopInterface host) @trusted {
    super("documentos");
    this.host = host;
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;

    auto left = new VerticalLayout;
    left.layoutWidth = FILL_PARENT;
    left.layoutHeight = FILL_PARENT;
    left.layoutWeight = 3;
    auto search = new HorizontalLayout;
    auto searchField = new EditLine("buscar");
    searchField.minWidth = 220;
    searchField.tooltipText = tip("list_document_search_field_tooltip");
    auto runSearch = () {
      string query = searchField.text.toUTF8;
      auto sorted = visibleDocuments.dup;
      sorted.sort!((a, b) => searchRank(a.name, query) < searchRank(b.name, query)
        || (searchRank(a.name, query) == searchRank(b.name, query) && a.pathname < b.pathname));
      reorder(sorted);
      return true;
    };
    searchField.enterKey = (EditWidgetBase source) => runSearch();
    search.addChild(searchField);
    search.addChild(makeButton("buscar-boton", "list_document_search_button", "list_document_search_button",
      () => runSearch()));
    search.addChild(makeButton("propiedades", "list_document_properties", "list_document_properties", () {
      showActions();
      return true;
    }));
    localButton = makeButton("locales", "list_document_button_local", null, () {
      showLocalDocuments();
      return true;
    });
    virtualButton = makeButton("virtuales", "list_document_button_virtual", null, () {
      onlyVirtual = true;
      refreshModeButtons();
      reloadView();
      return true;
    });
    search.addChild(localButton);
    search.addChild(virtualButton);
    left.addChild(search);
    rows = new VerticalLayout("filas");
    rows.layoutWidth = FILL_PARENT;
    auto rowsScroll = new VerticalScroll("lista");
    rowsScroll.contentWidget = rows;
    rowsScroll.layoutWidth = FILL_PARENT;
    rowsScroll.layoutHeight = FILL_PARENT;
    left.addChild(rowsScroll);
    addChild(left);

    auto right = new VerticalLayout;
    right.layoutWidth = FILL_PARENT;
    right.layoutHeight = FILL_PARENT;
    right.layoutWeight = 2;
    report = new RichText("reporte");
    report.padding = Rect(8, 8, 8, 8);
    report.onLink = (string link) { openMessageLink(link); };
    reportScroll = new VerticalScroll("reporte-scroll");
    reportScroll.contentWidget = report;
    reportScroll.layoutWidth = FILL_PARENT;
    reportScroll.layoutHeight = FILL_PARENT;
    right.addChild(reportScroll);
    actions = buildActions();
    right.addChild(actions);
    addChild(right);
    showActions();
    refreshModeButtons();
  }

  private VerticalLayout buildActions() {
    auto panel = new VerticalLayout("acciones-lista");
    panel.layoutWidth = FILL_PARENT;
    panel.layoutHeight = FILL_PARENT;
    auto title = new TextWidget(null, dt("list_document_actions"));
    title.fontWeight = 800;
    panel.addChild(title);
    Button add(string id, string key, bool delegate() action) {
      auto button = makeButton(id, key, null, action);
      button.layoutWidth = FILL_PARENT;
      panel.addChild(button);
      return button;
    }
    add("firmar-todos", "list_document_signall", () {
      if (visibleDocuments.length == 0) return notifyEmpty("list_document_no_documents_to_sign");
      host.signDocuments(visibleDocuments);
      return true;
    });
    add("firmar-elegidos", "list_document_signall_selected", () {
      if (selectedVisible.length == 0) return notifyEmpty("list_document_no_documents_to_sign");
      host.signDocuments(selectedVisible);
      return true;
    });
    add("limpiar", "list_document_clear", () {
      // Se quitan los de la vista actual y se conservan los del otro tipo.
      allDocuments = allDocuments.filter!(document => document.isVirtual != onlyVirtual).array;
      selected = selected.filter!(document => document.isVirtual != onlyVirtual).array;
      host.showNotification(t("list_document_clear_documents"), NotificationType.success);
      host.clearDone();
      reloadView();
      return true;
    });
    localOnlyButtons ~= add("guardar-lista", "list_document_save_list", () {
      saveDocumentList();
      return true;
    });
    localOnlyButtons ~= add("cargar-lista", "list_document_load_list", () {
      loadDocumentList();
      return true;
    });
    add("preparar-todos", "list_document_previewall", () {
      if (visibleDocuments.length == 0) return notifyEmpty("list_document_previewall_empty_action");
      if (onlyVirtual) {
        foreach (document; visibleDocuments) host.validateVirtual(document, null);
      } else {
        host.showLoading(t("loadprogressdialogworker_analyzing_docs"));
        host.manager.processDocuments(visibleDocuments, 0);
      }
      return true;
    });
    localOnlyButtons ~= add("carpeta-salida", "list_document_changefolder", () {
      changeOutputFolder();
      return true;
    });
    add("configurar-todos", "list_document_setconfigureall", () {
      if (onlyVirtual) return notifyEmpty("list_document_no_virtual_documents_to_config");
      if (visibleDocuments.length == 0) return notifyEmpty("list_document_no_documents_to_sign");
      foreach (document; visibleDocuments) document.setSettings(host.currentDocumentSettings());
      host.showNotification(t("list_document_setconfigureall_success"), NotificationType.success);
      return true;
    });
    selectAllButton = add("elegir-todos", "list_document_selectall", () {
      if (visibleDocuments.length == 0) return notifyEmpty("list_document_no_documents_to_sign");
      if (selectedVisible.length == visibleDocuments.length) {
        selected = selected.filter!(document => document.isVirtual != onlyVirtual).array;
      } else {
        foreach (document; visibleDocuments) if (!selected.canFind(document)) selected ~= document;
      }
      reloadView();
      return true;
    });
    add("orden-nombre", "list_document_order_by_name", () => sortBy("nombre"));
    add("orden-firmas", "list_document_order_by_number_of_signatures", () => sortBy("firmas"));
    add("orden-paginas", "list_document_order_by_number_of_pages", () => sortBy("paginas"));
    add("orden-fecha", "list_document_order_by_date", () => sortBy("fecha"));
    add("orden-vencimiento", "list_document_order_by_expiration_date", () => sortBy("vencimiento"));
    connectionButtons = new VerticalLayout("pedir-documentos");
    connectionButtons.layoutWidth = FILL_PARENT;
    panel.addChild(connectionButtons);
    return panel;
  }

  private bool notifyEmpty(string key) {
    host.showNotification(t(key), NotificationType.info);
    return true;
  }

  // Documentos -------------------------------------------------------------------

  /// Documentos de la vista actual (locales o virtuales).
  Document[] visibleDocuments() @safe {
    return allDocuments.filter!(document => document.isVirtual == onlyVirtual).array;
  }

  /// Todos los documentos de la lista, locales y virtuales.
  Document[] allOpenDocuments() @safe {
    return allDocuments.dup;
  }

  /// Documentos locales, en el orden de la lista.
  Document[] documents() @safe {
    return allDocuments.filter!(document => !document.isVirtual).array;
  }

  private Document[] selectedVisible() {
    return selected.filter!(document => document.isVirtual == onlyVirtual).array;
  }

  void addDocuments(Document[] added) @trusted {
    foreach (document; added) if (!allDocuments.canFind(document)) allDocuments ~= document;
    reloadView();
  }

  /// Añade los documentos virtuales que todavía no estén (loadVirtualDocuments).
  void addVirtualDocuments(Document[] loaded) @trusted {
    foreach (document; loaded) {
      if (!allDocuments.canFind!(existing => existing.isVirtual && existing.id == document.id)) {
        allDocuments ~= document;
      }
    }
    reloadView();
  }

  Document findVirtual(UUID id) @safe {
    foreach (document; allDocuments) if (document.isVirtual && document.id == id) return document;
    return null;
  }

  void removeDocument(Document document) @trusted {
    allDocuments = allDocuments.remove!(existing => existing is document);
    selected = selected.remove!(existing => existing is document);
    if (current is document) current = null;
    reloadView();
  }

  /// Vuelve a la vista de documentos locales (toggleToLocals).
  void showLocalDocuments() @trusted {
    onlyVirtual = false;
    refreshModeButtons();
    reloadView();
  }

  private void reorder(Document[] ordered) {
    allDocuments = ordered ~ allDocuments.filter!(document => document.isVirtual != onlyVirtual).array;
    reloadView();
  }

  private bool sortBy(string criterion) {
    auto shown = visibleDocuments;
    if (shown.length == 0) return notifyEmpty("list_document_no_documents_to_sign");
    bool up = ascending.get(criterion, true);
    ascending[criterion] = !up;
    Date early = Date(1970, 1, 1), late = Date(9999, 12, 31);
    switch (criterion) {
      case "nombre": shown.sort!((a, b) => up ? a.name < b.name : a.name > b.name); break;
      case "firmas": shown.sort!((a, b) => up ? a.signatureCount < b.signatureCount : a.signatureCount > b.signatureCount); break;
      case "paginas":
        shown.sort!((a, b) => up ? pagesOf(a) < pagesOf(b) : pagesOf(a) > pagesOf(b));
        break;
      case "fecha":
        shown.sort!((a, b) => up ? parseListDate(a.createdAt, early) < parseListDate(b.createdAt, early)
          : parseListDate(a.createdAt, early) > parseListDate(b.createdAt, early));
        break;
      default:
        shown.sort!((a, b) => up ? parseListDate(a.expirationDate, late) < parseListDate(b.expirationDate, late)
          : parseListDate(a.expirationDate, late) > parseListDate(b.expirationDate, late));
        break;
    }
    reorder(shown);
    return true;
  }

  private static int pagesOf(Document document) @trusted {
    if (document.isVirtual) return document.pages;
    try {
      return document.previewLoaded ? document.previewPageCount : 0;
    } catch (Exception) {
      return 0;
    }
  }

  // Reporte y acciones ---------------------------------------------------------

  /// Muestra el reporte de un documento.
  void showReport(Document document) @trusted {
    current = document;
    report.setHtml(document.report);
    reportScroll.visibility = Visibility.Visible;
    actions.visibility = Visibility.Gone;
  }

  /// Muestra un aviso en lugar del reporte.
  void showReportMessage(string html) @trusted {
    report.setHtml(html);
    reportScroll.visibility = Visibility.Visible;
    actions.visibility = Visibility.Gone;
  }

  private void showActions() {
    reportScroll.visibility = Visibility.Gone;
    actions.visibility = Visibility.Visible;
    refreshConnectionButtons();
  }

  /// Botones para pedir documentos a cada servicio con sesión (sólo en la vista de virtuales).
  private void refreshConnectionButtons() {
    connectionButtons.removeAllChildren();
    if (!onlyVirtual || host.connections is null) return;
    foreach (connection; host.connections.connections) addConnectionButton(connection);
  }

  /// Los botones de locales y virtuales sólo se ven con un servicio externo conectado.
  private void refreshModeButtons() {
    bool external;
    if (host.connections !is null) {
      foreach (connection; host.connections.connections) {
        if (connection.kind == ConnectionKind.external && connection.isRunning()) external = true;
      }
    }
    localButton.visibility = external ? Visibility.Visible : Visibility.Gone;
    virtualButton.visibility = external ? Visibility.Visible : Visibility.Gone;
    localButton.enabled = onlyVirtual;
    virtualButton.enabled = !onlyVirtual;
    foreach (button; localOnlyButtons) button.visibility = onlyVirtual ? Visibility.Gone : Visibility.Visible;
    refreshConnectionButtons();
  }

  // Filas ------------------------------------------------------------------------

  /// Rehace la lista (reloadView).
  void reloadView() @trusted {
    refreshModeButtons();
    rows.removeAllChildren();
    foreach (document; visibleDocuments) rows.addChild(rowFor(document));
    selectAllButton.text = dt(selectedVisible.length && selectedVisible.length == visibleDocuments.length
      ? "list_document_deselectall" : "list_document_selectall");
  }

  private Widget rowFor(Document document) {
    auto row = new HorizontalLayout;
    row.layoutWidth = FILL_PARENT;
    row.padding = Rect(6, 6, 6, 6);
    row.margins = Rect(0, 0, 0, 4);
    row.backgroundColor = document is current ? 0xDCE8F7 : 0xF4F4F4;
    row.focusable = true;
    row.tooltipText = (t("list_document_docPanel_accessible") ~ document.name).toUTF32;
    auto check = new CheckBox(null, ""d);
    check.checked = selected.canFind(document);
    check.tooltipText = tip("list_document_checkbox_accessible");
    check.checkChange = (Widget source, bool checked) {
      if (checked && !selected.canFind(document)) selected ~= document;
      else if (!checked) selected = selected.remove!(existing => existing is document);
      return true;
    };
    row.addChild(check);

    auto info = new VerticalLayout;
    info.layoutWidth = FILL_PARENT;
    auto name = new TextWidget(null, document.name.toUTF32);
    name.fontWeight = 800;
    name.fontSize = 16;
    info.addChild(name);
    if (document.isVirtual) {
      info.addChild(new TextWidget(null, (t("list_document_panel_origin") ~ document.origin).toUTF32));
    } else {
      auto output = new Button(null, (t("list_document_panel_exit_path") ~ document.pathToSave).toUTF32);
      output.tooltipText = tip("list_document_save_button_accessible_description_local");
      output.click = (Widget source) { chooseOutput(document); return true; };
      info.addChild(output);
    }
    auto counts = new HorizontalLayout;
    counts.addChild(new TextWidget(null, (t("list_document_panel_sign") ~ document.signatureCount.to!string)
      .toUTF32));
    auto sign = new Button(null, dt("list_document_panel_sign_action"));
    sign.click = (Widget source) { signOne(document); return true; };
    counts.addChild(sign);
    counts.addChild(new TextWidget(null, ("   " ~ t("list_document_panel_pages") ~ pagesOf(document).to!string)
      .toUTF32));
    auto preview = new Button(null, dt("list_document_panel_page_action"));
    preview.click = (Widget source) { goToSign(document); return true; };
    counts.addChild(preview);
    if (!document.isVirtual && !document.isRemote) {
      auto formatButton = new Button(null, (t("list_document_format") ~ " " ~ document.signer.formatName).toUTF32);
      formatButton.click = (Widget source) { changeFormat(document); return true; };
      counts.addChild(formatButton);
    }
    info.addChild(counts);
    row.addChild(info);

    auto side = new VerticalLayout;
    auto remove_ = new Button(null, "X"d);
    remove_.tooltipText = (t("list_document_delete_button_accessible") ~ document.name).toUTF32;
    remove_.click = (Widget source) { removeWithConfirmation(document); return true; };
    side.addChild(remove_);
    if (document.isVirtual) {
      if (document.expirationDate.length && document.expirationDate != "null") {
        auto expiration = new TextWidget(null, (t("list_document_panel_expiration") ~ " " ~ document.expirationDate)
          .toUTF32);
        expiration.fontSize = 11;
        expiration.textColor = 0x707070;
        side.addChild(expiration);
      }
    } else if (document.validated) {
      auto validated = new TextWidget(null, dt("list_document_panel_validated"));
      validated.textColor = 0x2E7D32;
      side.addChild(validated);
    }
    row.addChild(side);
    row.click = (Widget source) { goToReport(document); return true; };
    row.keyEvent = (Widget source, KeyEvent event) {
      if (event.action == KeyAction.KeyDown && (event.keyCode == KeyCode.RETURN || event.keyCode == KeyCode.SPACE)) {
        goToReport(document);
        return true;
      }
      return false;
    };
    return row;
  }

  private void goToReport(Document document) {
    current = document;
    lastAction = "validate";
    host.showDocumentReport(document, !document.validated);
    reloadView();
  }

  /// Firma un documento; si todavía no se validó, primero lo valida (SignActionListener).
  private void signOne(Document document) {
    current = document;
    if (!document.validated && !document.isVirtual) {
      lastAction = "sign";
      host.showDocumentReport(document, true);
      return;
    }
    lastAction = "na";
    host.signDocument(document);
  }

  /// Va a la vista previa; si todavía no se validó, primero lo valida (goToSignActionListener).
  private void goToSign(Document document) {
    current = document;
    if (!document.validated && !document.isVirtual) {
      lastAction = "preview";
      host.showDocumentReport(document, true);
      return;
    }
    lastAction = "na";
    if (!document.isReady && !document.isVirtual) host.doPreview(document);
    host.loadActiveDocument(document);
  }

  /**
   * Terminó de prepararse un documento: se completa la acción que esperaba la
   * validación (previewAllDone en la versión Java).
   */
  void documentValidated(Document document) @trusted {
    if (document !is current || !document.isReady) return;
    string pending = lastAction;
    lastAction = "na";
    if (pending == "preview") goToSign(document);
    else if (pending == "sign") host.signDocument(document);
    if (pending != "na" && pending != "validate") host.showDocumentReport(document, false);
  }

  private void chooseOutput(Document document) {
    if (document.isRemote) return;
    current = document;
    auto settings = host.currentDocumentSettings();
    string suffix = settings.overwriteSourceFile ? "" : "-firmado";
    string outputExtension = document.signedExtension;
    chooseSaveFile(window, t("guiswing_dialog_document_save"), dirName(document.pathname),
      proposedSaveName(document.pathname, suffix, outputExtension), (string path) {
      if (path is null) return;
      document.setPathToSave(withOutputExtension(path, outputExtension));
      reloadView();
    });
  }

  private void changeFormat(Document document) {
    current = document;
    showSignatureTypeDialog(window, selectableFormats(document.mimeType), formatOf(document.signer),
      (bool changed, SignatureFormat chosen) {
      if (!changed) return;
      document.setSigner(signerForFormat(host, chosen));
      reloadView();
    });
  }

  private void removeWithConfirmation(Document document) {
    if (!document.isVirtual) {
      removeDocument(document);
      host.clearDone();
      return;
    }
    showConfirmDialog(window, t("list_document_panel_confirm_delete_title"), t("list_document_panel_confirm_delete"),
      (bool accepted) {
      if (!accepted) return;
      if (!host.connections.requireSession(document.service, "guiswing_show_error_not_logged4")) return;
      import core.thread : Thread;
      auto worker = new Thread({
        bool deleted = deleteVirtualDocument(host.connections, document);
        runOnUi(() {
          if (deleted) {
            removeDocument(document);
            host.showNotification(t("list_document_delete_document"), NotificationType.success);
          } else {
            host.showNotification(t("list_document_panel_delete_error"), NotificationType.error);
          }
          host.clearDone();
        });
      });
      worker.isDaemon = true;
      worker.start();
    });
  }

  private void changeOutputFolder() {
    if (onlyVirtual) {
      notifyEmpty("list_document_no_virtual_documents_to_save");
      return;
    }
    auto shown = visibleDocuments;
    if (shown.length == 0) {
      notifyEmpty("list_document_no_documents_to_sign");
      return;
    }
    chooseDirectory(window, t("list_document_changefolder"), null, (string directory) {
      // Cancelar no cambia nada.
      if (directory is null) return;
      if (!exists(directory) || !isDir(directory)) {
        host.showNotification(t("list_document_changefolder_notfound"), NotificationType.error);
        return;
      }
      foreach (document; shown) document.setPathToSave(buildPath(directory, document.name));
      host.showNotification(t("list_document_save_done") ~ " " ~ directory, NotificationType.success);
      reloadView();
    });
  }

  /// Ruta de document_list.csv (junto a la configuración).
  private static string documentListPath() @safe {
    return buildPath(dirName(configFilePath()), "document_list.csv");
  }

  /// Guarda la lista (los elegidos, o todos) con la configuración de cada documento.
  private void saveDocumentList() {
    if (onlyVirtual) {
      notifyEmpty("list_document_no_virtual_documents_to_save");
      return;
    }
    auto toSave = selectedVisible.length ? selectedVisible : visibleDocuments;
    if (toSave.length == 0) {
      notifyEmpty("list_document_no_documents_to_save");
      return;
    }
    string path = documentListPath();
    try {
      string settingsDirectory = buildPath(configDirectory(), "docSettings");
      if (exists(settingsDirectory)) rmdirRecurse(settingsDirectory);
      SavedDocument[] rows;
      foreach (document; toSave) {
        rows ~= SavedDocument(document.name, document.pathname, document.pathToSave,
          saveDocumentSettings(document.settings, document.name));
      }
      writeFileAtomically(path, formatDocumentList(rows));
      info("Lista de documentos guardada en ", path);
      host.showNotification(t("list_document_save_done") ~ " " ~ path, NotificationType.success);
    } catch (Exception exception) {
      error("No se pudo guardar la lista de documentos en ", path, ": ", exception.msg);
      host.showNotification(t("list_document_error_during_save"), NotificationType.error);
    }
  }

  /// Carga la lista guardada, con la configuración y la ruta de salida de cada documento.
  private void loadDocumentList() {
    string path = documentListPath();
    if (!exists(path)) {
      notifyEmpty("list_document_no_file_to_load");
      return;
    }
    try {
      auto saved = parseDocumentList(readText(path));
      allDocuments = allDocuments.filter!(document => document.isVirtual).array;
      selected = null;
      string[] missing;
      foreach (row; saved) {
        if (!exists(row.pathName)) {
          missing ~= row.pathName;
          continue;
        }
        auto opened = host.addFiles([row.pathName], false);
        if (opened.length == 0) continue;
        opened[0].setSettings(loadDocumentSettings(row.settingsPath));
        opened[0].setPathToSave(row.pathToSave);
      }
      reloadView();
      if (missing.length) {
        host.showNotification(t("list_document_files_not_found_on_load") ~ " " ~ missing.join(", "),
          NotificationType.error);
      } else {
        host.showNotification(t("list_document_files_success"), NotificationType.success);
      }
    } catch (Exception exception) {
      error("Error cargando la lista de documentos ", path, ": ", exception.msg);
      host.showNotification(t("list_document_error_during_load"), NotificationType.error);
    }
  }

  /// Botón para pedir los documentos de un servicio (función aparte: los cierres de un bucle comparten sus variables).
  private void addConnectionButton(Connection connection) {
    if (connection.kind != ConnectionKind.external) return;
    auto button = new Button(null, connection.name.toUTF32);
    button.layoutWidth = FILL_PARENT;
    button.click = (Widget source) {
      if (!connection.isLogged) {
        host.showNotification(t("guiswing_show_error_not_logged"), NotificationType.error);
        return true;
      }
      source.enabled = false;
      import core.thread : Thread;
      auto worker = new Thread({
        bool requested = reloadVirtualDocuments(host.connections, connection);
        runOnUi(() {
          source.enabled = true;
          host.showNotification(t(requested ? "connection_panel_success_get_virtual_documents"
            : "connection_panel_error_get_virtual_documents"), requested ? NotificationType.success
            : NotificationType.error);
        });
      });
      worker.isDaemon = true;
      worker.start();
      return true;
    };
    connectionButtons.addChild(button);

  }

}

@("should write and read back the saved document list with quoted fields")
unittest {
  auto rows = [SavedDocument("a,b.pdf", `/tmp/a,"b".pdf`, "/tmp/a-firmado.pdf", "/c/docSettings/a.config")];
  auto csv = formatDocumentList(rows);
  assert(parseDocumentList(csv) == rows);
  // El archivo que escribía opencsv (todo entre comillas) también se lee.
  assert(parseDocumentList("\"name\",\"pathName\",\"pathToSave\",\"settingsPath\"\n\"x.pdf\",\"/x.pdf\",\"/y.pdf\",\"/z\"\n")
    == [SavedDocument("x.pdf", "/x.pdf", "/y.pdf", "/z")]);
}

@("should rank names that start with the query before names that contain it")
unittest {
  assert(searchRank("Contrato.pdf", "con") == 0);
  assert(searchRank("MiContrato.pdf", "con") == 1);
  assert(searchRank("Factura.pdf", "con") == 2);
  assert(parseListDate("05/03/2026", Date(1970, 1, 1)) == Date(2026, 3, 5));
  assert(parseListDate("mal", Date(1970, 1, 1)) == Date(1970, 1, 1));
}
