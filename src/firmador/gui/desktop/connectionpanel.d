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
 * Pestaña de conexiones (ConnectionPanel y ConnectionPanelService): la lista de
 * conexiones, el detalle de la elegida (estado, usuario, iniciar al arrancar, puertos de
 * Firmador Remoto, orígenes autorizados y no autorizados), conectar y desconectar, pedir
 * documentos virtuales, dar de alta servicios con un .firmadorconn y el registro de
 * errores de todas las conexiones.
 *
 * Un .firmadorconn firmado se valida y se muestra quién lo firmó y a qué servidor apunta
 * antes de aceptarlo; uno sin firma se advierte. La firma avala a quien lo firmó, no los
 * datos: el usuario debe confirmar que el servidor es el esperado.
 */
module firmador.gui.desktop.connectionpanel;

import std.algorithm : endsWith;
import std.file : readText;
import std.format : format;
import std.logger : error, info, warning;
import std.string : toLower;
import std.utf : toUTF32;

import dlangui.core.types;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.widget;

import firmador.connections.config;
import firmador.connections.connection;
import firmador.gui.desktop.common;
import firmador.gui.desktop.dialogs;
import firmador.gui.desktop.uithread : runInBackground, runOnUi;
import firmador.gui.desktop.window : DesktopInterface;
import firmador.gui.guiinterface : NotificationType;
import firmador.i18n : t;
import firmador.remote.origins : authorizeOrigin;
import firmador.settingsmanager : currentSettings, writeSettings;
import firmador.util.json : parseJsonText;
import firmador.xml.dom : escapeXml;

/// Pestaña de conexiones.
final class ConnectionPanel : VerticalLayout {
  private DesktopInterface host;
  private VerticalLayout list;
  private VerticalLayout details;
  private LogWidget log;
  private Connection selected;
  private size_t[Connection] loggedErrors;

  this(DesktopInterface host) @trusted {
    super("conexiones");
    this.host = host;
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;
    auto split = new HorizontalLayout;
    split.layoutWidth = FILL_PARENT;
    split.layoutHeight = FILL_PARENT;

    auto left = new VerticalLayout;
    left.layoutWidth = FILL_PARENT;
    left.layoutHeight = FILL_PARENT;
    left.layoutWeight = 1;
    auto leftTitle = new TextWidget(null, dt("connection_panel_connections"));
    leftTitle.fontWeight = 800;
    left.addChild(leftTitle);
    auto add = makeButton("agregar-conexion", "connection_panel_add", "connection_panel_add_button_accessible_description",
      () { importConnections(); return true; });
    left.addChild(add);
    list = new VerticalLayout("lista-conexiones");
    list.layoutWidth = FILL_PARENT;
    auto listScroll = new VerticalScroll("lista-conexiones-scroll");
    listScroll.contentWidget = list;
    listScroll.layoutWidth = FILL_PARENT;
    listScroll.layoutHeight = FILL_PARENT;
    left.addChild(listScroll);
    split.addChild(left);

    auto right = new VerticalLayout;
    right.layoutWidth = FILL_PARENT;
    right.layoutHeight = FILL_PARENT;
    right.layoutWeight = 2;
    right.padding = Rect(12, 0, 0, 0);
    auto rightTitle = new TextWidget(null, dt("connection_panel_info"));
    rightTitle.fontWeight = 800;
    right.addChild(rightTitle);
    details = new VerticalLayout("detalle-conexion");
    details.layoutWidth = FILL_PARENT;
    auto detailScroll = new VerticalScroll("detalle-conexion-scroll");
    detailScroll.contentWidget = details;
    detailScroll.layoutWidth = FILL_PARENT;
    detailScroll.layoutHeight = FILL_PARENT;
    right.addChild(detailScroll);
    split.addChild(right);
    addChild(split);

    auto logHeader = new HorizontalLayout;
    logHeader.layoutWidth = FILL_PARENT;
    auto logTitle = new TextWidget(null, dt("connection_panel_log"));
    logTitle.fontWeight = 800;
    logTitle.layoutWidth = FILL_PARENT;
    logHeader.addChild(logTitle);
    logHeader.addChild(makeButton("vaciar-registro", "connection_panel_clear", "connection_panel_clear_description", () {
      log.text = ""d;
      foreach (connection; host.connections.connections) {
        connection.clearErrors();
        loggedErrors[connection] = 0;
      }
      refreshAll();
      return true;
    }));
    addChild(logHeader);
    log = new LogWidget("registro");
    log.layoutWidth = FILL_PARENT;
    log.minHeight = 90;
    log.maxHeight = 140;
    addChild(log);
  }

  /// Repinta la lista y el detalle.
  void refreshAll() @trusted {
    if (host.connections is null) return;
    list.removeAllChildren();
    foreach (connection; host.connections.connections) {
      appendNewErrors(connection);
      list.addChild(rowFor(connection));
    }
    showDetails(selected);
  }

  /// Cambió una conexión: su estado, sesión o errores.
  void refresh(Connection connection) @trusted {
    if (selected is null) selected = connection;
    refreshAll();
  }

  /// Escribe en el registro los errores nuevos de la conexión.
  private void appendNewErrors(Connection connection) {
    auto errors = connection.errors();
    size_t already = loggedErrors.get(connection, 0);
    if (already > errors.length) already = 0;
    foreach (message; errors[already .. $]) appendLog(connection.name, message);
    loggedErrors[connection] = errors.length;
  }

  private void appendLog(string source, string message) {
    import std.string : strip;
    if (message.strip.length == 0) return;
    log.appendText(format("[%s] %s\n", source, message.strip).toUTF32);
  }

  private Widget rowFor(Connection connection) {
    auto row = new HorizontalLayout;
    row.layoutWidth = FILL_PARENT;
    row.padding = Rect(8, 6, 8, 6);
    row.margins = Rect(0, 0, 0, 4);
    row.backgroundColor = connection is selected ? 0xDCE8F7 : 0xF4F4F4;
    auto name = new Button(null, format("%s  %s", connection.isRunning() ? "●" : "○", connection.name).toUTF32);
    name.layoutWidth = FILL_PARENT;
    name.click = (Widget source) {
      selected = connection;
      refreshAll();
      return true;
    };
    row.addChild(name);
    if (connection.kind == ConnectionKind.external) {
      auto remove_ = new Button(null, "X"d);
      remove_.tooltipText = dt("connection_panel_delete");
      remove_.click = (Widget source) { removeConnection(connection); return true; };
      row.addChild(remove_);
    }
    return row;
  }

  private void showDetails(Connection connection) {
    details.removeAllChildren();
    if (connection is null) return;
    auto settings = currentSettings();
    auto title = new TextWidget(null, connection.name.toUTF32);
    title.fontWeight = 800;
    title.fontSize = 18;
    details.addChild(title);
    if (connection.userLogged().length) {
      details.addChild(new TextWidget(null, dt("connection_panel_logged_user")));
      details.addChild(new TextWidget(null, connection.userLogged().toUTF32));
    }
    auto startOn = new CheckBox("iniciar-al-arrancar", dt("connection_panel_start_on"));
    bool remote = connection.kind == ConnectionKind.firmadorRemoto;
    // Firmador Remoto arranca por el ajuste de la aplicación (el mismo de Configuración).
    startOn.checked = remote ? settings.startFimadorRemote : connection.startOn;
    startOn.checkChange = (Widget source, bool checked) {
      try {
        if (remote) {
          settings.startFimadorRemote = checked;
          writeSettings(settings, true);
        } else {
          connection.setStartOn(checked);
          host.connections.save();
        }
      } catch (Exception exception) {
        error("No se pudo guardar la opción de inicio de ", connection.name, ": ", exception.msg);
        host.showError(exception);
      }
      return true;
    };
    details.addChild(startOn);
    if (remote) details.addChild(listenersFor(connection));
    string state = connection.kind == ConnectionKind.external && !connection.isLogged()
      ? (connection.isRunning() ? "connection_panel_connect_external" : "connection_panel_disconnected")
      : (connection.isRunning() ? "connection_panel_connected" : "connection_panel_disconnected");
    auto stateLabel = new TextWidget("estado", dt(state));
    stateLabel.margins = Rect(0, 8, 0, 4);
    details.addChild(stateLabel);
    auto connect = makeButton("conectar", connection.isRunning() ? "connection_panel_disconnect"
      : "connection_panel_connect", "connection_panel_connection_button_des", () {
      toggleConnection(connection);
      return true;
    });
    details.addChild(connect);
    if (connection.kind == ConnectionKind.external && connection.isLogged()) {
      auto request = makeButton("pedir-documentos", "connection_panel_get_documents_title",
        "coonection_panel_get_documents", () { host.requestVirtualDocuments(connection); return true; });
      details.addChild(request);
    }
    if (remote) {
      auto allowedTitle = new TextWidget(null, dt("connection_panel_authorized_domains"));
      allowedTitle.margins = Rect(0, 12, 0, 4);
      allowedTitle.fontWeight = 800;
      details.addChild(allowedTitle);
      foreach (origin; settings.getAllowedHosts()) details.addChild(allowedOriginRow(origin));
      auto denied = settings.getNoAuthorizedHosts();
      if (denied.length) {
        auto deniedTitle = new TextWidget(null, dt("connection_panel_no_authorized_domains"));
        deniedTitle.margins = Rect(0, 12, 0, 4);
        deniedTitle.fontWeight = 800;
        details.addChild(deniedTitle);
        foreach (origin; denied) details.addChild(deniedOriginRow(origin));
      }
    }
  }

  private Widget listenersFor(Connection connection) {
    auto panel = new VerticalLayout;
    auto title = new TextWidget(null, dt("connection_panel_listeners"));
    title.fontWeight = 800;
    title.margins = Rect(0, 8, 0, 4);
    panel.addChild(title);
    auto ports = connection.runningPorts();
    if (ports.length == 0) {
      panel.addChild(new TextWidget(null, dt("connection_panel_no_listeners")));
      return panel;
    }
    foreach (port; ports) panel.addChild(listenerRow(connection, port));
    return panel;
  }

  // Las filas van en funciones aparte: los cierres creados en un bucle comparten sus variables.

  private Widget listenerRow(Connection connection, ushort port) {
    auto row = new HorizontalLayout;
    row.addChild(new TextWidget(null, format("%s %d", t("connection_panel_port"), port).toUTF32));
    auto stop = makeButton(null, "connection_panel_stop_listener", "connection_panel_stop_listener_description", () {
      host.connections.stopRemote(port);
      appendLog(connection.name, format("%s %d", t("connection_panel_connection_end"), port));
      refreshAll();
      return true;
    });
    stop.margins = Rect(8, 0, 0, 0);
    row.addChild(stop);
    return row;
  }

  private Widget allowedOriginRow(string origin) {
    return originRow(origin, "connection_panel_delete", () {
      confirmRemoveOrigin(origin);
      return true;
    });
  }

  private Widget deniedOriginRow(string origin) {
    return originRow(origin, "connection_panel_authorize", () {
      runInBackground("Error autorizando el origen " ~ origin, {
        // Si el servidor ya está preguntando por este origen, se espera su respuesta.
        authorizeOrigin(host, currentSettings(), origin);
        runOnUi(() => refreshAll());
      }, () => refreshAll());
      return true;
    });
  }

  private Widget originRow(string origin, string buttonKey, bool delegate() action) {
    auto row = new HorizontalLayout;
    row.layoutWidth = FILL_PARENT;
    auto text = new TextWidget(null, origin.toUTF32);
    text.layoutWidth = FILL_PARENT;
    row.addChild(text);
    row.addChild(makeButton(null, buttonKey, null, action));
    return row;
  }

  private void confirmRemoveOrigin(string origin) {
    showConfirmDialog(window, t("connection_panel_confirm_delete_title"),
      t("connection_panel_confirm_delete_host") ~ "<br><b>" ~ escapeXml(origin) ~ "</b>?", (bool accepted) {
      if (!accepted) return;
      auto settings = currentSettings();
      settings.removeAllowedHost(origin);
      try {
        writeSettings(settings, true);
      } catch (Exception exception) {
        host.showError(exception);
        return;
      }
      host.showNotification(t("connection_panel_delete_connection_done"), NotificationType.success);
      refreshAll();
    });
  }

  /// Conecta o desconecta en segundo plano (puede esperar la red).
  private void toggleConnection(Connection connection) {
    bool running = connection.isRunning();
    selected = connection;
    appendLog(connection.name, t(running ? "connection_panel_disconnecting" : "connection_panel_connecting"));
    runInBackground("Error en la conexión " ~ connection.name, {
      bool started;
      try {
        if (running) {
          host.connections.stop(connection);
        } else {
          connection.clearErrors();
          started = host.connections.start(connection);
        }
      } catch (Exception exception) {
        error("Error en la conexión ", connection.name, ": ", exception.msg);
        connection.addErrors([exception.msg]);
      }
      runOnUi(() {
        if (running) {
          host.showNotification(t("connection_panel_connection_end"), NotificationType.success);
        } else {
          host.showNotification(t(started ? "connection_panel_connection_done" : "connection_panel_connection_failed"),
            started ? NotificationType.success : NotificationType.error);
        }
        refreshAll();
      });
    }, () => refreshAll());
  }

  private void removeConnection(Connection connection) {
    if (connection.isRunning()) {
      host.showNotification(t("connection_panel_delete_error"), NotificationType.error);
      return;
    }
    showConfirmDialog(window, t("connection_panel_confirm_delete_title"), t("connection_panel_confirm_delete")
      ~ " «" ~ escapeXml(connection.name) ~ "»?", (bool accepted) {
      if (!accepted) return;
      try {
        host.connections.remove(connection);
      } catch (Exception exception) {
        host.showError(exception);
        return;
      }
      if (selected is connection) selected = null;
      host.showNotification(t("connection_panel_delete_connection_done"), NotificationType.success);
      refreshAll();
    });
  }

  // Alta de servicios -----------------------------------------------------------------

  private void importConnections() {
    chooseFiles(window, t("document_selection_filedialog_title"), true, null, (string[] paths) {
      foreach (path; paths) {
        if (!path.toLower.endsWith(".firmadorconn")) {
          host.showNotification(t("connection_panel_error_add_connection") ~ ": " ~ path, NotificationType.error);
          continue;
        }
        importConnection(path);
      }
    });
  }

  private void importConnection(string path) {
    ConnectionFile file;
    ConnectionConfig config;
    try {
      file = parseConnectionFile(readText(path));
      config = connectionFromJson(parseJsonText(file.json, "El archivo de conexión"));
    } catch (Exception exception) {
      error("Error leyendo el archivo de conexión ", path, ": ", exception.msg);
      host.showNotification(t("connection_panel_error_add_connection") ~ ": " ~ exception.msg, NotificationType.error);
      return;
    }
    foreach (existing; host.connections.connections) {
      if (existing.name == config.service || existing.service == config.service) {
        host.showNotification(t("connection_panel_add_existing"), NotificationType.warning);
        return;
      }
    }
    string description = "<b>" ~ escapeXml(config.name) ~ "</b><br>" ~ escapeXml(config.baseUrl);
    if (file.signedXml is null) {
      confirmUnsigned(config, description);
      return;
    }
    runInBackground("Error al revisar la firma del archivo de conexión", {
      ConnectionSignature signature;
      bool readable = true;
      try {
        signature = checkConnectionSignature(file.signedXml);
      } catch (Exception exception) {
        warning("La firma del archivo de conexión no se reconoce, se trata como sin firma: ", exception.msg);
        readable = false;
      }
      runOnUi(() {
        if (!readable) {
          confirmUnsigned(config, description);
        } else if (!signature.valid) {
          host.showNotification(t("connection_panel_authorization_error") ~ " (" ~ signature.indication ~ ")",
            NotificationType.error);
        } else {
          showChoiceDialog(window, t("connection_panel_register_new_connection_title"), escapeXml(signature.signerName)
            ~ " " ~ t("connection_panel_register_new_connection") ~ "<br>" ~ description ~ "<br>"
            ~ t("connection_panel_accept_new_connection"), [t("connection_panel_accept"), t("connection_panel_reject")],
            0, true, (int choice) {
            if (choice == 0) addConnection(config);
            else host.showNotification(t("connection_panel_error_add_connection"), NotificationType.error);
          });
        }
      });
    });
  }

  private void confirmUnsigned(ConnectionConfig config, string description) {
    showChoiceDialog(window, t("connection_panel_warning"), t("connection_panel_no_signature_warning") ~ "<br>"
      ~ description, [t("connection_panel_accept"), t("connection_panel_reject")], 1, true, (int choice) {
      if (choice == 0) addConnection(config);
    });
  }

  private void addConnection(ConnectionConfig config) {
    try {
      if (host.connections.add(config)) {
        info("Conexión ", config.name, " agregada desde un archivo");
        host.showNotification(t("connection_panel_add_connection_done"), NotificationType.success);
      } else {
        host.showNotification(t("connection_panel_add_existing"), NotificationType.warning);
      }
    } catch (Exception exception) {
      error("No se pudo agregar la conexión ", config.name, ": ", exception.msg);
      host.showNotification(t("connection_panel_error_add_connection") ~ ": " ~ exception.msg, NotificationType.error);
    }
    refreshAll();
  }
}
