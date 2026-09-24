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
 * Conexiones en marcha (Connection y la gestión que hacían ConnectionPanel y
 * ConnectionService en la versión Java): Firmador Remoto en uno o varios puertos
 * (firmador.remote.server), el hub del BCCR (firmador.connections.gaudi) y los servicios
 * externos con documentos virtuales (firmador.connections.external). Los datos que se
 * guardan están en firmador.connections.config; lo que la ventana debe ofrecer a las
 * conexiones, en ConnectionView.
 */
module firmador.connections.connection;

import core.thread : Thread;
import core.time : dur;
import std.algorithm : countUntil, remove, sort;
import std.format : format;
import std.logger : error, info, warning;
import std.uuid : UUID;

import firmador.cards.detector : SmartCardDetector;
import firmador.configuration : defaultRemotePort;
import firmador.connections.config;
import firmador.documents.document : Document;
import firmador.gui.guiinterface : GuiInterface, NotificationType;
import firmador.i18n : t;
import firmador.remote.dto : RemoteSignRequest;
import firmador.remote.server : RemoteServer;
import firmador.tokens.token : SecretPin;

/// PIN y código de verificación que pide una solicitud del BCCR (RequestPinAndCodeWindow).
struct PinAndCode {
  /// El usuario aceptó; si no, `pin` es null.
  bool accepted;
  SecretPin pin;
  string code;
}

/**
 * Lo que la ventana ofrece a las conexiones (los métodos de GUISwing y ConnectionPanel
 * que llamaban). Se puede llamar desde cualquier hilo.
 */
interface ConnectionView {
  /// Cambió el estado, la sesión o los errores de la conexión: repintar su detalle.
  void connectionChanged(Connection connection) @safe;
  /**
   * Pide PIN y código para una solicitud del BCCR mostrando el logo, la entidad y el
   * resumen; `errorMessage` no vacío si se repite por un PIN incorrecto.
   */
  PinAndCode requestPinAndCode(immutable(ubyte)[] logo, string entityName, string summary, string errorMessage) @safe;
  /// Documentos virtuales publicados por un servicio (loadVirtualDocument).
  void virtualDocumentsLoaded(Document[] documents) @safe;
  /// Resúmenes preparados por un servicio para firmarlos con la tarjeta (loadRemoteDocumentInList).
  void signRequestsReceived(RemoteSignRequest[] requests, string service) @safe;
  /// Llegó el reporte de validación de un documento virtual (notifyReportDocument).
  void virtualReport(UUID documentId, string report) @safe;
  /// El servicio canceló un documento virtual (cancelDocument).
  void virtualCancelled(UUID documentId) @safe;
  /// Venció un documento virtual que se estaba firmando (showErrorVirtual).
  void virtualExpired(string documentId) @safe;
  /// El servicio terminó el lote que se estaba firmando (cleanVirtualDocumentsInList).
  void virtualBatchFinished() @safe;
  /// Termina la espera de una operación con un servicio (desativateLoadDialog).
  void loadingFinished() @safe;
}

/// Hilo de una integración (Gaudi o servicio externo).
interface ConnectionWorker {
  /// Sigue conectado o intentando conectarse.
  bool isRunning() @safe;
  /**
   * Pide terminar y cierra la sesión si corresponde. Puede esperar la red (no llamarlo
   * desde el hilo de la ventana), pero no espera a que el hilo acabe.
   */
  void stop() @safe;
}

/// Una conexión con su estado en marcha.
final class Connection {
  private ConnectionConfig config_;
  private string[] errors_;
  private bool logged_;
  private string userLogged_;
  private RemoteServer[ushort] remoteServers;
  private ConnectionWorker worker;

  this(ConnectionConfig config) @safe {
    config_ = config;
  }

  /// Datos guardados de la conexión.
  ConnectionConfig config() @trusted {
    synchronized (this) return config_;
  }

  string name() @safe { return config.name; }
  string service() @safe { return config.service; }
  ConnectionKind kind() @safe { return connectionKind(config.service); }

  /**
   * URL completa de una ruta del servicio.
   *
   * Throws: ConnectionConfigException si falta la ruta o cambia de servidor.
   */
  string url(string relative, string what) @safe {
    return serviceUrl(config, relative, what);
  }

  /// Se inicia al abrir la aplicación.
  bool startOn() @safe { return config.startOn; }

  void setStartOn(bool value) @trusted {
    synchronized (this) config_.startOn = value;
  }

  /// Hay una sesión iniciada en el servicio externo.
  bool isLogged() @trusted {
    synchronized (this) return logged_;
  }

  /// Usuario con sesión iniciada (vacío si no hay).
  string userLogged() @trusted {
    synchronized (this) return userLogged_;
  }

  /// Marca la sesión iniciada o cerrada.
  void setLogged(bool logged, string user) @trusted {
    synchronized (this) {
      logged_ = logged;
      userLogged_ = logged ? user : "";
    }
  }

  /// Errores acumulados para mostrarlos en el detalle.
  string[] errors() @trusted {
    synchronized (this) return errors_.dup;
  }

  void addErrors(const string[] errors) @trusted {
    synchronized (this) errors_ ~= errors;
  }

  void clearErrors() @trusted {
    synchronized (this) errors_ = null;
  }

  /// Está conectada: algún puerto de Firmador Remoto atendiendo, o su integración en marcha.
  bool isRunning() @trusted {
    if (kind == ConnectionKind.firmadorRemoto) return runningPorts().length > 0;
    ConnectionWorker current;
    synchronized (this) current = worker;
    return current !is null && current.isRunning();
  }

  /// Puertos que Firmador Remoto atiende; descarta los servidores que se detuvieron.
  ushort[] runningPorts() @trusted {
    synchronized (this) {
      foreach (port; remoteServers.keys) if (!remoteServers[port].isRunning()) remoteServers.remove(port);
      auto ports = remoteServers.keys;
      ports.sort();
      return ports;
    }
  }
}

/**
 * Inicia el hilo de una integración (Gaudi o servicio externo) para una conexión; lo
 * reciben aquí para que este módulo no dependa de las integraciones, que usan el gestor.
 */
alias WorkerFactory = ConnectionWorker function(ConnectionManager manager, Connection connection) @safe;

/**
 * Lista de conexiones y su ciclo de vida (lo que hacía ConnectionPanel fuera del
 * dibujo): carga, alta y baja, inicio, parada, reinicio y cierre por sesión vencida.
 */
final class ConnectionManager {
  private GuiInterface gui;
  private ConnectionView view;
  private SmartCardDetector detector;
  private WorkerFactory gaudiFactory;
  private WorkerFactory externalFactory;
  private Connection[] connections_;

  /**
   * Params:
   *   gui = interfaz para avisos y para Firmador Remoto.
   *   view = ventana que recibe los eventos de las conexiones.
   *   detector = tarjetas compartidas con el resto de la aplicación.
   *   gaudiFactory = crea la integración con el BCCR (firmador.connections.gaudi).
   *   externalFactory = crea la integración con un servicio externo (firmador.connections.external).
   */
  this(GuiInterface gui, ConnectionView view, SmartCardDetector detector, WorkerFactory gaudiFactory,
      WorkerFactory externalFactory) @safe {
    this.gui = gui;
    this.view = view;
    this.detector = detector;
    this.gaudiFactory = gaudiFactory;
    this.externalFactory = externalFactory;
  }

  /**
   * Carga servicesUrls.xml con las conexiones por omisión que falten. Si el archivo no
   * se puede leer se informa y se usan sólo las por omisión, sin sobrescribirlo.
   */
  void load() @trusted {
    ConnectionConfig[] loaded;
    try {
      loaded = loadConnections();
    } catch (Exception exception) {
      gui.showNotification(t("connection_panel_error_add_connection") ~ ": " ~ exception.msg, NotificationType.error);
    }
    Connection[] created;
    foreach (config; withDefaultConnections(loaded)) created ~= new Connection(config);
    synchronized (this) connections_ = created;
  }

  /// Conexiones en el orden en que se muestran.
  Connection[] connections() @trusted {
    synchronized (this) return connections_.dup;
  }

  /// Conexión de ese servicio, o null.
  Connection find(string service) @safe {
    foreach (connection; connections()) if (connection.service == service) return connection;
    return null;
  }

  /**
   * Guarda la lista.
   *
   * Throws: Exception con la ruta si no se puede escribir.
   */
  void save() @safe {
    ConnectionConfig[] configs;
    foreach (connection; connections()) configs ~= connection.config;
    saveConnections(configs);
  }

  /**
   * Da de alta una conexión externa y guarda la lista. Devuelve false si ya existe una
   * con ese servicio o con ese nombre de servicio.
   *
   * Throws: ConnectionConfigException si no es válida; Exception si no se puede guardar.
   */
  bool add(ConnectionConfig config) @trusted {
    validateExternalConfig(config);
    synchronized (this) {
      foreach (existing; connections_) {
        if (existing.name == config.service || existing.service == config.service) return false;
      }
      connections_ ~= new Connection(config);
    }
    save();
    info("Conexión ", config.name, " agregada");
    return true;
  }

  /**
   * Quita una conexión detenida y guarda la lista. Devuelve false si está en marcha.
   *
   * Throws: Exception si no se puede guardar.
   */
  bool remove(Connection connection) @trusted {
    if (connection.isRunning()) return false;
    synchronized (this) {
      auto index = connections_.countUntil(connection);
      if (index < 0) return false;
      connections_ = connections_.remove(index);
    }
    save();
    info("Conexión ", connection.name, " eliminada");
    return true;
  }

  /**
   * Inicia una conexión (Connection.start): Firmador Remoto en su puerto (o el
   * oficial), o la integración. Devuelve si quedó en marcha.
   */
  bool start(Connection connection) @trusted {
    connection.setLogged(false, "");
    final switch (connection.kind) {
      case ConnectionKind.firmadorRemoto:
        ushort port = connection.config.port != 0 ? connection.config.port : defaultRemotePort;
        startRemotePort(connection, port);
        break;
      case ConnectionKind.gaudi:
      case ConnectionKind.external:
        if (connection.isRunning()) return true;
        auto created = connection.kind == ConnectionKind.gaudi ? gaudiFactory(this, connection)
          : externalFactory(this, connection);
        synchronized (connection) connection.worker = created;
        break;
    }
    view.connectionChanged(connection);
    return connection.isRunning();
  }

  /**
   * Atiende Firmador Remoto también en ese puerto (una página puede pedir el suyo).
   * Devuelve false si no hay conexión de Firmador Remoto configurada.
   */
  bool startRemote(ushort port) @safe {
    auto connection = find(firmadorRemotoService);
    if (connection is null) {
      error(t("connection_panel_remote_connection_missing"));
      return false;
    }
    startRemotePort(connection, port);
    view.connectionChanged(connection);
    return true;
  }

  /// Levanta un servidor en el puerto si no hay uno atendiéndolo; false si ya lo había o no se pudo.
  private bool startRemotePort(Connection connection, ushort port) @trusted {
    connection.setLogged(false, "");
    if (connection.runningPorts().countUntil(port) >= 0) return false;
    auto server = new RemoteServer(gui, detector, port);
    if (!server.start()) return false;
    synchronized (connection) connection.remoteServers[port] = server;
    return true;
  }

  /// Deja de atender un solo puerto de Firmador Remoto.
  void stopRemote(ushort port) @trusted {
    auto connection = find(firmadorRemotoService);
    if (connection is null) return;
    RemoteServer server;
    synchronized (connection) {
      if (auto found = port in connection.remoteServers) {
        server = *found;
        connection.remoteServers.remove(port);
      }
    }
    if (server !is null) server.stop();
    view.connectionChanged(connection);
  }

  /**
   * Detiene una conexión (Connection.stop): todos los puertos o la integración, cerrando
   * la sesión del servicio. Puede esperar la red: no llamarlo desde el hilo de la ventana.
   */
  void stop(Connection connection) @trusted {
    connection.setLogged(false, "");
    RemoteServer[] servers;
    ConnectionWorker current;
    synchronized (connection) {
      servers = connection.remoteServers.values;
      connection.remoteServers = null;
      current = connection.worker;
      connection.worker = null;
    }
    foreach (server; servers) server.stop();
    if (current !is null) current.stop();
    view.connectionChanged(connection);
  }

  /**
   * Reinicia una conexión en segundo plano (restartConnection): la detiene y la vuelve a
   * iniciar hasta diez veces, esperando tres segundos entre intentos.
   */
  void restart(Connection connection) @trusted {
    info("Reiniciando la conexión ", connection.name);
    auto restarter = new Thread({
      try {
        stop(connection);
        foreach (attempt; 0 .. 10) {
          if (start(connection)) break;
          warning("La conexión ", connection.name, " no inició (intento ", attempt + 1, " de 10); se reintentará");
          Thread.sleep(dur!"seconds"(3));
          connection.clearErrors();
        }
        connection.clearErrors();
        view.connectionChanged(connection);
      } catch (Exception exception) {
        error("No se pudo reiniciar la conexión ", connection.name, ": ", exception.msg);
        connection.addErrors([exception.msg]);
        view.connectionChanged(connection);
      }
    });
    restarter.isDaemon = true;
    restarter.start();
  }

  /// Inicia las conexiones marcadas para iniciarse con la aplicación, una tras otra.
  void autoStart() @safe {
    foreach (connection; connections()) {
      if (!connection.startOn) continue;
      info("Iniciando al arrancar la conexión ", connection.name);
      if (!start(connection)) warning("La conexión ", connection.name, " no inició al arrancar");
    }
  }

  /// Detiene todas (al cerrar la aplicación).
  void stopAll() @safe {
    foreach (connection; connections()) {
      if (connection.isRunning()) stop(connection);
    }
  }

  /// Anota errores en la conexión y los muestra (updateErrors).
  void reportErrors(Connection connection, const string[] errors) @safe {
    if (errors.length == 0) return;
    error(t("connection_panel_errors_found"), ": ", connection.name, ": ", errors);
    connection.addErrors(errors);
    view.connectionChanged(connection);
  }

  /**
   * El servicio respondió 403: la sesión venció. Se avisa y se detiene la conexión
   * (ConnectionService.disconnect y GUISwing.disconnect).
   */
  void forbidden(string service) @safe {
    auto connection = find(service);
    string name = connection is null ? service : connection.name;
    gui.showErrorAlert(t("guiswing_show_403_title"), t("guiswing_show_403") ~ " " ~ name);
    if (connection !is null) stop(connection);
    gui.showNotification(formatLostConnection(name), NotificationType.info);
    view.loadingFinished();
  }

  /**
   * La conexión de ese servicio tiene sesión y está en marcha (validateConnection); si no,
   * avisa con el texto que corresponde a `suffixKey`.
   */
  bool requireSession(string service, string suffixKey) @safe {
    auto connection = find(service);
    if (connection !is null && connection.isLogged() && connection.isRunning()) return true;
    gui.showErrorAlert(t("guiswing_show_error_not_logged_title"),
      t("guiswing_show_error_not_logged") ~ " " ~ service ~ " " ~ t(suffixKey));
    return false;
  }

  /// Interfaz y tarjetas compartidas, para las integraciones.
  GuiInterface interface_() @safe { return gui; }
  ConnectionView connectionView() @safe { return view; }
  SmartCardDetector cards() @safe { return detector; }
}

/// Aviso de sesión terminada de una conexión (ucr_integration_lost_connection).
string formatLostConnection(string name) @safe {
  import firmador.i18n : formatText;
  return formatText(t("ucr_integration_lost_connection"), name);
}
