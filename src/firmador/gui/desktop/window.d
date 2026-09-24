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
 * Ventana de Firmador con dlangui (GUISwing, SwingMainWindowFrame,
 * DocumentSelectionGroupLayout, DocumentService y ConnectionService en la versión Java).
 * Implementa GuiInterface para firmadores, validadores, documentos y Firmador Remoto, y
 * ConnectionView para las conexiones. Todo lo que toca la ventana ocurre en su hilo
 * (firmador.gui.desktop.uithread): los avisos de otros hilos se pasan con runOnUi y lo que
 * necesita una respuesta del usuario espera con waitOnUi.
 *
 * Modo completo: documentos, carpetas, firma, conexiones, configuración, acerca de y,
 * si se pide, bitácoras. Modo simplificado: firma, validación, conexiones, configuración y
 * acerca de; varios documentos soltados a la vez se firman de una sin vista previa.
 */
module firmador.gui.desktop.window;

import core.thread : Thread;
import std.algorithm : canFind, countUntil, filter, remove;
import std.array : array, replace;
import std.conv : ConvException, to;
import std.file : exists, isDir, isFile, dirEntries, SpanMode;
import std.format : format;
import std.logger : error, info, warning;
import std.path : absolutePath, baseName, dirName, extension;
import std.regex : ctRegex, matchFirst, replaceAll;
import std.string : strip;
import std.utf : toUTF32;
import std.uuid : UUID;

import dlangui.core.events;
import dlangui.core.stdaction;
import dlangui.core.types;
import dlangui.platforms.common.platform : Platform, Window, WindowFlag, WindowState;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.tabs;
import dlangui.widgets.widget;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.cards.detector : SmartCardDetector;
import firmador.configuration : defaultRemotePort, firmadorVersion;
import firmador.connections.config : firmadorRemotoService;
import firmador.connections.connection;
import firmador.connections.external;
import firmador.connections.gaudi : startGaudi;
import firmador.documents.document : Document;
import firmador.documents.manager : DocumentManager;
import firmador.gui.desktop.aboutpanel : AboutPanel;
import firmador.gui.desktop.common;
import firmador.gui.desktop.configpanel : ConfigPanel;
import firmador.gui.desktop.connectionpanel : ConnectionPanel;
import firmador.gui.desktop.dialogs;
import firmador.gui.desktop.directorypanel : DirectoryPanel;
import firmador.gui.desktop.documentlist : DocumentListPanel;
import firmador.gui.desktop.logpanel : LogPanel;
import firmador.gui.desktop.richtext : RichText;
import firmador.gui.desktop.signpanel : SignPanel;
import firmador.gui.desktop.uithread;
import firmador.gui.errors : userErrorFor;
import firmador.gui.guiinterface;
import firmador.i18n : t;
import firmador.launch : launchProperty, remoteOriginProperty;
import firmador.plugins.plugin : PluginManager;
import firmador.remote.dto : RemoteSignRequest;
import firmador.remote.origins : authorizeOrigin, isOriginAllowed;
import firmador.remote.slot : RemoteDocumentSlot;
import firmador.settings : processOrigin, resolveOriginPort, Settings;
import firmador.settingsmanager : configFilePath, currentSettings, writeSettings;
import firmador.util.desktop : desktopNotification;
import firmador.util.singleinstance;

/**
 * Reporte de un documento virtual que envía el servicio, en HTML (notifyReportDocument):
 * sin la línea del nombre temporal del documento y sin líneas en blanco repetidas; si no
 * tiene firmas, el aviso de que no las tiene. `signatures` recibe la cantidad declarada.
 */
string virtualReportHtml(string report, out size_t signatures) @safe {
  import firmador.xml.dom : escapeXml;
  signatures = 0;
  auto count = matchFirst(report, ctRegex!`Contiene\s+(\d+)\s+firma`);
  if (!count.empty) {
    try {
      signatures = count[1].to!size_t;
    } catch (ConvException) {
      signatures = 0;
    }
  }
  if (signatures == 0) return "<html>Este documento no tiene ninguna firma digital.</html>";
  string cleaned = replaceAll(report, ctRegex!`El documento doc_[0-9]+\.pdf[^\n]*`, "").strip;
  cleaned = replaceAll(cleaned, ctRegex!`(\n\s*){2,}`, "\n");
  return "<html>" ~ escapeXml(cleaned).replace("\n", "<br>") ~ "</html>";
}

/// Barra de avisos breves al pie de la ventana (showNotification).
private final class NotificationBar : VerticalLayout {
  private RichText message;
  private ulong hideTimer;

  this() @trusted {
    super("avisos");
    layoutWidth = FILL_PARENT;
    padding = Rect(10, 8, 10, 8);
    message = new RichText("aviso");
    message.fontWeight = 800;
    message.alignment = Align.Center;
    addChild(message);
    visibility = Visibility.Gone;
  }

  void show(string html, NotificationType type) @trusted {
    uint background, foreground;
    final switch (type) {
      case NotificationType.success: background = 0xD4EDDA; foreground = 0x155724; break;
      case NotificationType.error: background = 0xF8D7DA; foreground = 0x721C24; break;
      case NotificationType.warning: background = 0xFFF3CD; foreground = 0x856404; break;
      case NotificationType.info: background = 0xD9EDF7; foreground = 0x0C5460; break;
    }
    backgroundColor = background;
    message.textColor = foreground;
    message.setHtml(html);
    visibility = Visibility.Visible;
    if (hideTimer != 0) cancelTimer(hideTimer);
    hideTimer = setTimer(5000);
  }

  override bool onTimer(ulong id) {
    if (id != hideTimer) return super.onTimer(id);
    hideTimer = 0;
    visibility = Visibility.Gone;
    return false;
  }
}

/// Ventana de Firmador.
final class DesktopInterface : GuiInterface, ConnectionView {
  /// Ventana de dlangui.
  Window window;
  SmartCardDetector detector;
  PluginManager plugins;
  DocumentManager manager;
  ConnectionManager connections;

  private bool background;
  private bool simplified;
  private SingleInstance instance;
  private TabWidget tabs;
  private EditLine fileField;
  private NotificationBar notifications;
  private SignPanel signPanel;
  private RichText validateView;
  private VerticalScroll validateScroll;
  private DocumentListPanel documentList;
  private DirectoryPanel directoryPanel;
  private ConnectionPanel connectionPanel;
  private ConfigPanel configPanel;
  private AboutPanel aboutPanel;
  private LogPanel logPanel;
  private ProgressDialog progress;
  private ProgressDialog loading;
  private Document simplifiedDocument;
  private Document[] simplifiedQueue;
  private bool simplifiedBatch;
  private bool needNavigateToPreview;
  private bool forcePreview;
  private Document remoteDocument;
  private RemoteDocumentSlot remoteSlot;
  private Document[] virtualDocumentsToSign;
  private string lastDirectory;
  private bool closing;

  /**
   * Params:
   *   detector = tarjetas; la ventana las monitorea.
   *   plugins = plugins ya cargados.
   *   background = arrancar oculta (--background): se muestra con otra instancia.
   */
  this(SmartCardDetector detector, PluginManager plugins, bool background) @trusted {
    this.detector = detector;
    this.plugins = plugins;
    this.background = background;
  }

  /**
   * Arma la ventana (loadGUI). Devuelve false si ya había otra instancia, a la que se le
   * pasaron los archivos o el lanzamiento.
   */
  bool open(string[] fileArguments) @trusted {
    auto settings = currentSettings();
    string remoteOrigin = launchProperty(remoteOriginProperty);
    instance = new SingleInstance(dirName(configFilePath()));
    if (!instance.acquire(initialInstanceCommand(fileArguments, remoteOrigin), (InstanceCommand command) {
        runOnUi(() => handleInstanceCommand(command));
      })) {
      return false;
    }
    window = Platform.instance.createWindow((remoteOrigin !is null ? "Firmador remoto" : "Firmador").toUTF32, null,
      WindowFlag.Resizable, 1100, 800);
    registerUiWindow(window);
    if (settings.simplified_mode.isNull && remoteOrigin is null) {
      // La primera vez se pregunta el modo antes de armar las pestañas.
      window.mainWidget = new TextWidget(null, ""d);
      window.show();
      showSelectModeDialog(window, (bool chosen) {
        settings.simplified_mode = chosen;
        try {
          writeSettings(settings, true);
        } catch (Exception exception) {
          error("No se pudo guardar el modo elegido: ", exception.msg);
        }
        build(fileArguments, remoteOrigin);
      });
    } else {
      build(fileArguments, remoteOrigin);
      if (background) window.setWindowState(WindowState.minimized);
      else window.show();
    }
    return true;
  }

  private void build(string[] fileArguments, string remoteOrigin) {
    auto settings = currentSettings();
    simplified = settings.isSimplifiedMode();
    connections = new ConnectionManager(this, this, detector, &startGaudi, &startExternal);
    connections.load();
    manager = new DocumentManager(this);

    auto root = new VerticalLayout("raiz");
    root.layoutWidth = FILL_PARENT;
    root.layoutHeight = FILL_PARENT;
    root.padding = Rect(6, 6, 6, 6);
    auto selection = new HorizontalLayout("seleccion");
    selection.layoutWidth = FILL_PARENT;
    selection.addChild(new TextWidget(null, dt("document_selection_label")));
    fileField = new EditLine("archivo", dt("document_selection_filefield"));
    fileField.readOnly = true;
    fileField.layoutWidth = FILL_PARENT;
    fileField.tooltipText = tip("document_selection_filefield_tooltip");
    selection.addChild(fileField);
    selection.addChild(makeButton("elegir", "document_selection_btn", "document_selection_btn_tooltip", () {
      chooseFiles(window, t("document_selection_filedialog_title"), true, lastDirectory, (string[] paths) {
        if (paths.length == 0) return;
        lastDirectory = dirName(paths[0]);
        addFiles(paths, true);
      });
      return true;
    }));
    root.addChild(selection);

    tabs = new TabWidget("pestanas");
    tabs.layoutWidth = FILL_PARENT;
    tabs.layoutHeight = FILL_PARENT;
    signPanel = new SignPanel(this);
    connectionPanel = new ConnectionPanel(this);
    configPanel = new ConfigPanel(this);
    aboutPanel = new AboutPanel(this);
    if (simplified) {
      tabs.addTab(signPanel, dt("guiswing_tab_sign"), null, false, tip("guiswing_tab_sign_tooltip"));
      validateView = new RichText("reporte", t("guiswing_dialog_document_not_signed"));
      validateView.padding = Rect(12, 12, 12, 12);
      validateView.onLink = (string link) { openMessageLink(link); };
      validateScroll = new VerticalScroll("validar");
      validateScroll.contentWidget = validateView;
      validateScroll.layoutWidth = FILL_PARENT;
      validateScroll.layoutHeight = FILL_PARENT;
      tabs.addTab(validateScroll, dt("guiswing_tab_validate"), null, false, tip("guiswing_tab_validate_tooltip"));
    } else {
      documentList = new DocumentListPanel(this);
      directoryPanel = new DirectoryPanel(this);
      tabs.addTab(documentList, dt("guiswing_tab_documents"), null, false, tip("guiswing_tab_documents_tooltip"));
      tabs.addTab(directoryPanel, dt("guiswing_tab_directories"), null, false,
        tip("guiswing_tab_directories_tooltip"));
      tabs.addTab(signPanel, dt("guiswing_tab_sign"), null, false, tip("guiswing_tab_sign_tooltip"));
    }
    tabs.addTab(connectionPanel, dt("guiswing_tab_connection"), null, false, tip("guiswing_tab_connection_tooltip"));
    tabs.addTab(configPanel, dt("guiswing_tab_settings"), null, false, tip("guiswing_tab_settings_tooltip"));
    tabs.addTab(aboutPanel, dt("guiswing_tab_about"), null, false, tip("guiswing_tab_about_tooltip"));
    logPanel = new LogPanel;
    if (settings.showLogs) tabs.addTab(logPanel, dt("guiswing_tab_logs"), null, false, tip("guiswing_tab_logs_tooltip"));
    root.addChild(tabs);
    notifications = new NotificationBar;
    root.addChild(notifications);
    window.mainWidget = root;
    tabs.selectTab(0, true);
    connectionPanel.refreshAll();

    window.onFilesDropped = (string[] paths) { processDroppedFiles(paths); };
    window.onCanClose = () {
      if (background && !closing) {
        window.setWindowState(WindowState.minimized);
        return false;
      }
      return true;
    };
    window.onClose = () { shutdown(); };

    detector.addListener((const(CardSignInfo)[] cards) {
      runOnUi(() => signPanel.cardsChanged(cards));
    });
    detector.start();
    plugins.startLogging();

    // Una página que lanzó Firmador pide atender Firmador Remoto; la configuración también.
    if (remoteOrigin !is null) startRemoteForOrigin(remoteOrigin);
    else if (settings.startFimadorRemote) connections.startRemote(cast(ushort) settings.portNumber);
    Thread autoStart = new Thread({ connections.autoStart(); });
    autoStart.isDaemon = true;
    autoStart.start();

    string[] existing;
    foreach (path; fileArguments) {
      if (exists(path) && isFile(path)) {
        existing ~= path;
      } else {
        warning("No se encontró el documento indicado por argumento: ", path);
        showNotification(t("guiswing_document_arg_not_found") ~ " " ~ path, NotificationType.error);
      }
    }
    if (existing.length) addFiles(existing, true);
  }

  /// Cierra todo lo que la ventana puso en marcha (al cerrarla).
  private void shutdown() {
    if (closing) return;
    closing = true;
    info("Cerrando Firmador");
    shutdownUi();
    signPanel.pageView.stopRendering();
    plugins.stop();
    manager.stop();
    closeDocuments();
    connections.stopAll();
    detector.shutdown();
    instance.release();
  }

  /// Cierra las vistas previas de los documentos abiertos (liberan el PDF de mupdf).
  private void closeDocuments() {
    Document[] open = [signPanel.document, remoteDocument, simplifiedDocument];
    if (documentList !is null) open ~= documentList.allOpenDocuments;
    open ~= simplifiedQueue;
    Document[] closed;
    foreach (document; open) {
      if (document is null || document.isVirtual || closed.canFind!(done => done is document)) continue;
      closed ~= document;
      try {
        document.preview.close();
      } catch (Exception exception) {
        warning("No se pudo cerrar la vista previa de ", document.name, ": ", exception.msg);
      }
    }
  }

  /// Cierra la aplicación aunque esté en segundo plano.
  void closeApplication() @trusted {
    closing = true;
    window.close();
  }

  // Pestañas y avisos -----------------------------------------------------------

  /// Muestra la pestaña de una función: sign, validate, document, directory o connection.
  void displayFunctionality(string functionality) @trusted {
    Widget target;
    switch (functionality) {
      case "sign": target = signPanel; break;
      case "validate": target = validateScroll; break;
      case "document": target = documentList; break;
      case "directory": target = directoryPanel; break;
      case "connection": target = connectionPanel; break;
      default: break;
    }
    if (target !is null) tabs.selectTab(target.id);
  }

  /// Muestra u oculta la pestaña de bitácoras según la configuración (updateConfig).
  void applySettings() @trusted {
    auto settings = currentSettings();
    bool shown = tabs.tabControl.tabIndex(logPanel.id) >= 0;
    if (settings.showLogs && !shown) {
      tabs.addTab(logPanel, dt("guiswing_tab_logs"), null, false, tip("guiswing_tab_logs_tooltip"));
    } else if (!settings.showLogs && shown) {
      tabs.removeTab(logPanel.id);
    }
    signPanel.updateConfig();
    if (documentList !is null) documentList.reloadView();
  }

  /// Trae la ventana al frente (bringToFront).
  void bringToFront() @trusted {
    if (window is null) return;
    window.show();
    window.setWindowState(WindowState.normal, true);
    window.activateWindow();
  }

  private bool windowHidden() {
    return window is null || window.windowState == WindowState.minimized || window.windowState == WindowState.hidden;
  }

  void showNotification(string message, NotificationType type) @trusted {
    runOnUi(() {
      if (notifications is null) return;
      notifications.show(message, type);
      if (windowHidden() && currentSettings().showTrayNotifications) desktopNotification("Firmador", message);
    });
  }

  // GuiInterface ----------------------------------------------------------------

  void showError(Throwable failure) @trusted {
    auto shown = userErrorFor(failure);
    error(t("guiswing_show_error_logmessage"), shown.message);
    runOnUi(() => showMessageDialog(window, t("guiswing_show_error_dialog_title"), shown.message));
  }

  void showMessage(string message) @trusted {
    runOnUi(() => showMessageDialog(window, t("guiswing_show_error_dialog_title"), message));
  }

  void showErrorAlert(string title, string message) @trusted {
    error(title, ": ", message);
    runOnUi(() => showMessageDialog(window, title, message));
  }

  bool askConfirmation(string title, string message) @trusted {
    if (onUiThread()) {
      error("No se puede esperar una confirmación en el hilo de la ventana: ", title);
      return false;
    }
    return waitOnUi!bool((void delegate(bool) done) => showConfirmDialog(window, title, message, done), false);
  }

  void nextStep(string message) @trusted {
    runOnUi(() {
      if (progress !is null) progress.setProgress(0, message);
    });
  }

  /**
   * Credencial y PIN para firmar (getPin). Sin credenciales detectadas avisa y devuelve
   * null. Se llama desde el hilo de firma.
   */
  CardSignInfo getPin() @trusted {
    try {
      if (detector.listCardInfo().length == 0) detector.readSaveListSmartCard();
      if (detector.listCardInfo().length == 0) {
        error("No se detectaron tarjetas conectadas");
        showErrorAlert(t("guiswing_log_closefile"), t("guiswing_show_error_providerexception"));
        return null;
      }
      detector.restoreSessions();
    } catch (Exception exception) {
      error("Error al leer las tarjetas: ", exception.msg);
      showError(exception);
      return null;
    }
    return waitOnUi!CardSignInfo((void delegate(CardSignInfo) done) {
      new PinDialog(window, detector).open(done);
    }, null);
  }

  Settings currentDocumentSettings() @trusted {
    if (onUiThread()) return signPanel.collectSettings();
    return waitOnUi!Settings((void delegate(Settings) done) => done(signPanel.collectSettings()), currentSettings());
  }

  void previewDone(Document document) @trusted {
    runOnUi(() {
      showNotification(t("guiswing_success_preview_document"), NotificationType.success);
      if (document.showPreview) {
        setActiveDocument(document);
        if (document.isReady) loadActiveDocument(document);
        if (forcePreview) {
          forcePreview = false;
          hideLoading();
          displayFunctionality("sign");
        }
      }
      if (documentList !is null) documentList.reloadView();
    });
  }

  void previewAllDone() @trusted {
    runOnUi(() {
      showNotification(t("guiswing_success_preview_documents"), NotificationType.success);
      if (needNavigateToPreview) {
        Document document = simplified ? simplifiedDocument
          : (documentList.documents.length ? documentList.documents[0] : null);
        if (document !is null) {
          if (!document.isReady) doPreview(document);
          loadActiveDocument(document);
          displayFunctionality("sign");
        }
        needNavigateToPreview = false;
      }
      hideLoading();
      if (documentList !is null) documentList.reloadView();
    });
  }

  void validateDone(Document document) @trusted {
    runOnUi(() {
      setActiveDocument(document);
      showNotification(t("guiswing_success_validate_document"), NotificationType.success);
      if (document.isReady) {
        loadActiveDocument(document);
        hideLoading();
      }
      if (documentList !is null) {
        documentList.reloadView();
        documentList.documentValidated(document);
      }
    });
  }

  void validateAllDone() @trusted {
    showNotification(t("guiswing_success_validate_documents"), NotificationType.success);
  }

  void signDone(Document document) @trusted {
    plugins.documentSigned(document);
    runOnUi(() {
      info("Firma terminada: ", document.name);
      showNotification(t(document.signedWithErrors ? "guiswing_success_sing_document_error"
        : "guiswing_success_sing_document"), document.signedWithErrors ? NotificationType.error
        : NotificationType.success);
      if (document is remoteDocument && remoteSlot !is null) {
        auto signed = document.signedContent;
        if (signed !is null && !document.signedWithErrors) remoteSlot.complete(signed);
        else remoteSlot.reject();
        remoteSlot = null;
        remoteDocument = null;
        // El firmado ya volvió al navegador y no queda en la lista.
        resetPreview();
      }
      if (simplified && !document.isRemote) {
        simplifiedQueue = simplifiedQueue.remove!(queued => queued is document);
        if (simplifiedQueue.length == 0) {
          if (simplifiedBatch) {
            simplifiedBatch = false;
          } else if (!document.signedWithErrors && exists(document.pathToSave)) {
            simplifiedDocument = null;
            addFiles([document.pathToSave], false);
            showLoading(t("loadprogressdialogworker_analyzing_docs"));
          }
        }
      }
      // En la lista, el documento firmado reemplaza al original.
      if (documentList !is null && !document.isRemote && !document.signedWithErrors
          && documentList.documents.canFind(document) && exists(document.pathToSave)) {
        documentList.removeDocument(document);
        addFiles([document.pathToSave], false);
        showLoading(t("loadprogressdialogworker_analyzing_docs"));
      }
      if (documentList !is null) documentList.reloadView();
    });
  }

  void extendsDone(Document document) @trusted {
    runOnUi(() => setActiveDocument(document));
  }

  void signAllDone() @trusted {}

  void clearDone() @trusted {
    runOnUi(() => resetPreview());
  }

  void progressStart(string title, string header) @trusted {
    runOnUi(() {
      if (progress !is null) progress.finish();
      progress = new ProgressDialog(window, t("progress_dialog_title_default"), header);
      progress.display();
      progress.setHeader(title ~ " - " ~ header);
    });
  }

  void progressHeader(string header) @trusted {
    runOnUi(() {
      if (progress !is null) progress.setHeader(header);
    });
  }

  void progressUpdate(int percent, string note) @trusted {
    runOnUi(() {
      if (progress !is null) progress.setProgress(percent, note);
    });
  }

  void progressEnd() @trusted {
    runOnUi(() {
      if (progress !is null) progress.finish();
      progress = null;
    });
  }

  bool requestRemotePin(CardSignInfo card, string description, immutable(ubyte)[] image) @trusted {
    runOnUi(() => bringToFront());
    return waitOnUi!bool((void delegate(bool) done) => showRemotePinDialog(window, card, description, image, done),
      false);
  }

  HostAuthorization askHostAuthorization(string origin) @trusted {
    runOnUi(() => bringToFront());
    return waitOnUi!HostAuthorization((void delegate(HostAuthorization) done) =>
      showHostAuthorizationDialog(window, origin, done), HostAuthorization.denied);
  }

  /**
   * Llegó un documento por Firmador Remoto: se prepara su vista previa en este hilo (el
   * del servidor) y se muestra para firmarlo. Sólo se aceptan PDF.
   */
  void loadRemoteDocument(RemoteDocumentSlot slot) @trusted {
    import firmador.documents.mimetype : detectMimeType, isPdf;
    if (!isPdf(detectMimeType(slot.name))) {
      warning("El documento remoto ", slot.name, " llegó con un tipo que no se previsualiza");
      showNotification(t("guiswing_remote_document_unsupported_type") ~ " " ~ slot.name, NotificationType.error);
      slot.reject();
      return;
    }
    auto document = new Document(this, slot.content, slot.name);
    document.loadPreviewOf(slot.content);
    runOnUi(() {
      if (remoteSlot !is null && remoteSlot !is slot) remoteSlot.reject();
      remoteSlot = slot;
      remoteDocument = document;
      displayFunctionality("sign");
      signPanel.setDocument(document);
      fileField.text = document.name.toUTF32;
      string ready = t("guiswing_remote_document_ready_to_sign") ~ " " ~ document.name;
      if (windowHidden() && currentSettings().showTrayNotifications) desktopNotification("Firmador", ready);
      bringToFront();
      showNotification(ready, NotificationType.info);
    });
  }

  void connectionErrors(string connectionName, string[] errors) @trusted {
    runOnUi(() {
      auto connection = connections.find(connectionName);
      if (connection !is null) connections.reportErrors(connection, errors);
      else error("Errores de la conexión ", connectionName, ": ", errors);
    });
  }

  void originAuthorized(string origin) @trusted {
    runOnUi(() {
      configPanel.reload();
      connectionPanel.refreshAll();
    });
  }

  // ConnectionView --------------------------------------------------------------

  void connectionChanged(Connection connection) @trusted {
    runOnUi(() {
      connectionPanel.refresh(connection);
      if (documentList !is null) documentList.reloadView();
    });
  }

  PinAndCode requestPinAndCode(immutable(ubyte)[] logo, string entityName, string summary, string errorMessage)
      @trusted {
    runOnUi(() => bringToFront());
    return waitOnUi!PinAndCode((void delegate(PinAndCode) done) =>
      showPinAndCodeDialog(window, logo, entityName, summary, errorMessage, done), PinAndCode(false, null, null));
  }

  void virtualDocumentsLoaded(Document[] loaded) @trusted {
    runOnUi(() {
      if (documentList is null) {
        warning("El modo simplificado no tiene lista donde mostrar los documentos virtuales");
        return;
      }
      documentList.addVirtualDocuments(loaded);
    });
  }

  void signRequestsReceived(RemoteSignRequest[] requests, string service) @trusted {
    runOnUi(() => showLoading(t("guiswing_completing_documents")));
    auto worker = new Thread({
      bool signed;
      try {
        signed = completeSignRequests(connections, requests, service);
      } catch (Exception exception) {
        error("Error al completar la firma de los documentos virtuales: ", exception.msg);
        showError(exception);
      }
      runOnUi(() {
        hideLoading();
        if (signed && documentList !is null) {
          foreach (document; virtualDocumentsToSign) documentList.removeDocument(document);
        }
      });
    });
    worker.isDaemon = true;
    worker.start();
  }

  void virtualReport(UUID documentId, string report) @trusted {
    runOnUi(() {
      if (documentList is null) return;
      auto document = documentList.findVirtual(documentId);
      if (document is null) {
        error("No se encontró el documento virtual con ID: ", documentId);
        return;
      }
      size_t signatures;
      document.setValidating(false);
      document.setReport(virtualReportHtml(report, signatures));
      document.setSignatureCount(signatures);
      documentList.showReport(document);
      documentList.reloadView();
    });
  }

  void virtualCancelled(UUID documentId) @trusted {
    runOnUi(() {
      if (documentList is null) return;
      auto document = documentList.findVirtual(documentId);
      if (document !is null) documentList.removeDocument(document);
    });
  }

  void virtualExpired(string documentKey) @trusted {
    runOnUi(() {
      auto index = virtualDocumentsToSign.countUntil!(document => document.id.toString == documentKey);
      if (index < 0) {
        error("No se encontró el documento virtual vencido ", documentKey);
        return;
      }
      auto document = virtualDocumentsToSign[index];
      virtualDocumentsToSign = virtualDocumentsToSign.remove(index);
      if (virtualDocumentsToSign.length == 0) hideLoading();
      showNotification(t("guiswing_show_error_expire_document") ~ " " ~ document.name, NotificationType.error);
      if (documentList !is null) documentList.removeDocument(document);
    });
  }

  void virtualBatchFinished() @trusted {
    runOnUi(() { virtualDocumentsToSign = null; });
  }

  void loadingFinished() @trusted {
    runOnUi(() => hideLoading());
  }

  // Documentos --------------------------------------------------------------------

  /// Espera de una operación larga (LoadProgressDialogWorker).
  void showLoading(string title) @trusted {
    if (loading !is null) return;
    loading = new ProgressDialog(window, t("progress_dialog_title_default"), title);
    loading.display();
  }

  void hideLoading() @trusted {
    if (loading is null) return;
    loading.finish();
    loading = null;
  }

  /// Archivos y carpetas soltados sobre la ventana (processFiles).
  private void processDroppedFiles(string[] dropped) {
    string[] directories = dropped.filter!(path => exists(path) && isDir(path)).array;
    if (directories.length == dropped.length && directories.length > 1) {
      if (!simplified) addDirectories(directories);
      return;
    }
    string[] files;
    foreach (path; dropped) {
      if (exists(path) && isDir(path)) {
        foreach (entry; dirEntries(path, SpanMode.shallow)) if (entry.isFile) files ~= entry.name;
      } else if (exists(path)) {
        files ~= path;
      }
    }
    if (files.length) addFiles(files, true);
  }

  /**
   * Abre documentos (DocumentService.addDocuments): los que no tienen extensión se
   * rechazan con aviso.
   */
  Document[] addFiles(string[] paths, bool preview) @trusted {
    Document[] documents;
    foreach (path; paths) {
      string absolute = absolutePath(path);
      if (extension(absolute).length == 0) {
        showMessage(t("guiswing_dialog_document_not_valid_extension") ~ absolute ~ " "
          ~ t("guiswing_dialog_document_not_valid_extension2"));
        continue;
      }
      try {
        documents ~= new Document(this, absolute);
      } catch (Exception exception) {
        error(t("guiswing_error_loading_documents"), ": ", exception.msg);
        showMessage(t("guiswing_error_loading_documents") ~ ": " ~ exception.msg);
      }
    }
    if (documents.length) loadDocuments(documents, preview);
    return documents;
  }

  /// Carga documentos abiertos (loadDocuments).
  void loadDocuments(Document[] documents, bool preview) @trusted {
    auto settings = currentSettings();
    if (simplified && documents.length > 1) {
      // Varios documentos en modo simplificado: se firman todos de una sin vista previa.
      simplifiedQueue = documents;
      simplifiedBatch = true;
      showNotification(format("%d %s", documents.length, t("guiswing_simplified_batch_loaded")),
        NotificationType.info);
      hideLoading();
      signQueuedDocuments();
      return;
    }
    manager.processDocuments(documents, settings.max_number_process_doc);
    if (simplified) {
      simplifiedDocument = documents[0];
      simplifiedQueue = documents;
      simplifiedBatch = false;
      needNavigateToPreview = true;
    } else {
      needNavigateToPreview = documents.length == 1 && preview;
      if (documents.length > 1) displayFunctionality("document");
      documentList.showLocalDocuments();
      documentList.addDocuments(documents);
    }
  }

  /// Firma sin firma visible el lote soltado en modo simplificado (signQueuedDocuments).
  private void signQueuedDocuments() {
    if (!validateConnectedCard()) return;
    auto batchSettings = currentDocumentSettings();
    batchSettings.isVisibleSignature = false;
    foreach (document; simplifiedQueue) document.setSettings(new Settings(batchSettings));
    manager.scheduleSigning(simplifiedQueue);
  }

  /// Vuelve a preparar la vista previa de un documento y lo muestra al terminar (doPreview).
  void doPreview(Document document) @trusted {
    forcePreview = true;
    manager.schedulePreview(document);
  }

  /// Valida y prepara la vista previa de un documento (processDocument).
  void processDocument(Document document) @trusted {
    showLoading(t("loadprogressdialogworker_analyzing_docs"));
    manager.processDocuments([document], 0);
  }

  private void setActiveDocument(Document document) {
    if (document is null || document.isVirtual) return;
    fileField.text = document.name.toUTF32;
    if (document.pathname.length) lastDirectory = dirName(document.pathname);
  }

  /// Muestra el documento en la pestaña de firma (loadActiveDocument).
  void loadActiveDocument(Document document) @trusted {
    try {
      if (document.isSigned) showDocumentReportText(document);
      else if (simplified) validateView.setHtml(t("guiswing_dialog_document_not_signed"));
      displayFunctionality("sign");
      signPanel.setDocument(document);
      setActiveDocument(document);
    } catch (Exception exception) {
      error(t("guiswing_error_loading_documents_with_mimetype"), ": ", exception.msg);
      showError(exception);
    }
  }

  private void showDocumentReportText(Document document) {
    if (simplified) validateView.setHtml(document.report);
    else documentList.showReport(document);
  }

  /**
   * Muestra las firmas del documento (loadReportDocument): su reporte, o lo valida si
   * todavía no se validó y `needProcess`.
   */
  void showDocumentReport(Document document, bool needProcess = false) @trusted {
    displayFunctionality(simplified ? "validate" : "document");
    if (document.isSigned) {
      if (document.report.length) showDocumentReportText(document);
      else if (!simplified) documentList.showReportMessage(t("guiswing_dialog_document_not_signed_analyzed"));
      return;
    }
    if (!needProcess) {
      if (simplified) validateView.setHtml(t("guiswing_dialog_document_not_signed"));
      else documentList.showReportMessage(t("guiswing_dialog_document_not_signed"));
      return;
    }
    if (!simplified) documentList.showReportMessage(t("guiswing_dialog_document_not_signed_analyzed"));
    if (!document.isVirtual) {
      processDocument(document);
    } else if (document.report.length) {
      showDocumentReportText(document);
    } else {
      validateVirtual(document, null);
    }
  }

  /// Pide al servicio el reporte de un documento virtual (validateVirtualDocument).
  void validateVirtual(Document document, void delegate() onComplete) @trusted {
    if (!connections.requireSession(document.service, "guiswing_show_error_not_logged6")) {
      if (onComplete !is null) onComplete();
      return;
    }
    if (document.validating) {
      if (onComplete !is null) onComplete();
      return;
    }
    document.setValidating(true);
    auto worker = new Thread({
      bool requested = validateVirtualDocument(connections, document);
      runOnUi(() {
        showNotification(t(requested ? "guiswing_success_validate_document" : "guiswing_error_validate_document"),
          requested ? NotificationType.success : NotificationType.error);
        if (!requested) document.setValidating(false);
        if (onComplete !is null) onComplete();
      });
    });
    worker.isDaemon = true;
    worker.start();
  }

  /// Imagen de una página de un documento virtual (getPageImageFromApi), desde un hilo de fondo.
  immutable(ubyte)[] virtualPage(Document document, int page) @trusted {
    auto connection = connections.find(document.service);
    if (connection is null || !connection.isLogged() || !connection.isRunning()) return null;
    return virtualPagePreview(connections, document, page);
  }

  /// Hay alguna credencial para firmar (validateConnectedCard).
  bool validateConnectedCard() @trusted {
    try {
      detector.invalidateCache();
      if (detector.readSaveListSmartCard().length > 0) return true;
      warning(t("guiswing_show_error_providerexception"));
      showErrorAlert(t("guiswing_log_closefile"), t("guiswing_show_error_providerexception"));
      hideLoading();
      return false;
    } catch (Exception exception) {
      showError(exception);
      return false;
    }
  }

  /// Firma un documento (signDocument): los virtuales se preparan en su servicio.
  void signDocument(Document document) @trusted {
    if (!validateConnectedCard()) return;
    if (!document.isVirtual) {
      manager.scheduleSigning(document);
      return;
    }
    signVirtual([document], document.settings);
    signPanel.clean();
    displayFunctionality("document");
  }

  /**
   * Firma varios documentos (signAllDocuments y signSelectedDocuments): los locales en un
   * solo lote; los virtuales, los de conexiones con sesión, en sus servicios.
   */
  void signDocuments(Document[] documents) @trusted {
    if (documents.length == 0) return;
    if (!validateConnectedCard()) return;
    if (!documents[0].isVirtual) {
      manager.scheduleSigning(documents);
      return;
    }
    string[] invalid;
    Document[] valid;
    foreach (document; documents) {
      auto connection = connections.find(document.service);
      if (connection is null || !connection.isLogged() || !connection.isRunning()) {
        if (!invalid.canFind(document.service)) invalid ~= document.service;
      } else {
        valid ~= document;
      }
    }
    if (invalid.length) {
      import std.string : join;
      showErrorAlert(t("guiswing_show_error_not_logged_title"), t("guiswing_show_error_not_logged") ~ " "
        ~ invalid.join(", ") ~ " " ~ t("guiswing_show_error_not_logged3"));
    }
    if (valid.length) signVirtual(valid, null);
  }

  private void signVirtual(Document[] documents, Settings settings) {
    if (!connections.requireSession(documents[0].service, "guiswing_show_error_not_logged3")) return;
    virtualDocumentsToSign ~= documents;
    showLoading(t("guiswing_obtaining_data_documents"));
    auto worker = new Thread({
      bool requested;
      try {
        requested = requestHashesToSign(connections, documents, settings);
      } catch (Exception exception) {
        error("Error al pedir los resúmenes a firmar: ", exception.msg);
      }
      if (!requested) {
        runOnUi(() => hideLoading());
        showNotification(t("guiswing_show_error_getHashToSign_title"), NotificationType.warning);
      }
    });
    worker.isDaemon = true;
    worker.start();
  }

  /// Rechaza el documento de Firmador Remoto y se lo comunica al navegador.
  void cancelRemoteDocument() @trusted {
    if (remoteSlot !is null) {
      remoteSlot.reject();
      remoteSlot = null;
      remoteDocument = null;
    }
    resetPreview();
    showNotification(t("guiswing_remote_document_cancelled"), NotificationType.warning);
  }

  /// Deja la vista previa sin documento (resetPreview).
  private void resetPreview() {
    signPanel.clean();
    if (validateView !is null) validateView.setHtml("");
    fileField.text = ""d;
  }

  /// Añade carpetas a la pestaña de carpetas (addDirectories).
  void addDirectories(string[] paths) @trusted {
    if (directoryPanel is null) return;
    directoryPanel.addDirectories(paths);
    displayFunctionality("directory");
  }

  // Lanzamientos --------------------------------------------------------------------

  private void handleInstanceCommand(InstanceCommand command) {
    final switch (command.kind) {
      case InstanceCommand.Kind.none:
        break;
      case InstanceCommand.Kind.showWindow:
        bringToFront();
        break;
      case InstanceCommand.Kind.openFile:
        import firmador.gui.args : localPathArgument;
        bringToFront();
        addFiles([localPathArgument(command.argument)], true);
        break;
      case InstanceCommand.Kind.startRemote:
        startRemoteForOrigin(command.argument);
        break;
      case InstanceCommand.Kind.closeRequest:
        if (windowHidden()) {
          closeApplication();
          break;
        }
        showConfirmDialog(window, "Firmador",
          "El instalador de Firmador necesita cerrar la aplicación para continuar. ¿Desea cerrarla ahora?",
          (bool accepted) {
          if (accepted) closeApplication();
          else instance.signalCloseRejected();
        });
        break;
    }
  }

  /**
   * Atiende el lanzamiento desde una página: autoriza su origen si hace falta y atiende el
   * puerto que pidió (startRemoteForOrigin).
   */
  private void startRemoteForOrigin(string rawOrigin) {
    auto settings = currentSettings();
    bool outOfRange;
    int port = resolveOriginPort(rawOrigin, settings.allowOriginPort, outOfRange);
    if (outOfRange) warning("El origen ", rawOrigin, " pidió un puerto fuera del rango; se usa ", port);
    auto metadata = processOrigin(rawOrigin, defaultRemotePort);
    if (!metadata.minimized) bringToFront();
    string origin = metadata.url;
    if (rawOrigin !is null && !isOriginAllowed(settings, origin)) {
      auto worker = new Thread({
        bool authorized;
        try {
          authorized = authorizeOrigin(this, settings, origin);
        } catch (Exception exception) {
          error("Error autorizando el origen ", origin, ": ", exception.msg);
        }
        runOnUi(() {
          if (authorized) showRemoteConnection(cast(ushort) port);
          else showNotification(t("remote_http_worker_error_origin_not_allowed") ~ " " ~ origin, NotificationType.error);
        });
      });
      worker.isDaemon = true;
      worker.start();
      return;
    }
    showRemoteConnection(cast(ushort) port);
  }

  /// Lanzamiento desde el navegador recibido con la ventana abierta (macOS entrega el enlace a la instancia).
  void handleRemoteLaunch(string origin) @trusted {
    runOnUi(() => startRemoteForOrigin(origin));
  }

  private void showRemoteConnection(ushort port) {
    if (connections.startRemote(port)) displayFunctionality("connection");
  }
}

@("should keep the declared signature count and drop the temporary name line when showing a virtual report")
unittest {
  size_t signatures;
  string html = virtualReportHtml("El documento doc_123.pdf está firmado\n\n\nContiene 2 firmas <válidas>", signatures);
  assert(signatures == 2);
  assert(html == "<html>Contiene 2 firmas &lt;válidas&gt;</html>");
  assert(virtualReportHtml("Sin firmas", signatures) == "<html>Este documento no tiene ninguna firma digital.</html>");
  assert(signatures == 0);
}
