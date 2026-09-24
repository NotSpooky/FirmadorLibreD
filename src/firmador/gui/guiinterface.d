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
 * Lo que los firmadores, validadores y documentos necesitan de la interfaz que esté
 * activa (GUIInterface en la versión Java): la ventana (firmador.gui.desktop.window), el
 * modo de argumentos (firmador.gui.args) o el shell (firmador.gui.shell). Los métodos se
 * pueden llamar desde cualquier hilo; cada interfaz se encarga de pasar al suyo.
 */
module firmador.gui.guiinterface;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.documents.document : Document;
import firmador.remote.slot : RemoteDocumentSlot;
import firmador.settings : Settings;

/// Tipo de aviso breve de la ventana.
enum NotificationType { success, error, warning, info }

/// Respuesta a la pregunta de autorizar un origen (RequestHostAuthorizationRemote).
enum HostAuthorization { always = 1, once = 2, denied = 3 }

/// Interfaz activa.
interface GuiInterface {
  /// Muestra un error ocurrido durante una operación (showError).
  void showError(Throwable error) @safe;

  /// Muestra un mensaje informativo; puede llevar HTML sencillo (<br>, <b>, <a>).
  void showMessage(string message) @safe;

  /// Muestra un error con título.
  void showErrorAlert(string title, string message) @safe;

  /**
   * Pregunta sí o no (JOptionPane.showConfirmDialog); el mensaje puede llevar HTML
   * sencillo. Los modos sin ventana responden que no.
   */
  bool askConfirmation(string title, string message) @safe;

  /// Informa el paso en curso de una firma.
  void nextStep(string message) @safe;

  /// Pide el PIN y la credencial con que firmar; null si el usuario cancela.
  CardSignInfo getPin() @safe;

  /// Ajustes con que se firma lo que muestra la interfaz (getCurrentSettings).
  Settings currentDocumentSettings() @safe;

  /// Aviso breve (en los modos de consola va a la bitácora).
  void showNotification(string message, NotificationType type) @safe;

  /// Terminó la vista previa del documento.
  void previewDone(Document document) @safe;
  /// Terminó la validación del documento.
  void validateDone(Document document) @safe;
  /// Terminó la firma del documento (con o sin errores).
  void signDone(Document document) @safe;
  /// Terminó la extensión a LTA del documento.
  void extendsDone(Document document) @safe;
  /// No quedan vistas previas en curso.
  void previewAllDone() @safe;
  /// No quedan validaciones en curso.
  void validateAllDone() @safe;
  /// No quedan firmas en curso.
  void signAllDone() @safe;
  /// Se quitaron los documentos.
  void clearDone() @safe;

  /// Empieza el progreso de un lote de firmas (SignProgressDialogWorker).
  void progressStart(string title, string header) @safe;
  /// Cambia el encabezado del progreso.
  void progressHeader(string header) @safe;
  /// Avance del progreso (0 a 100) con la nota del paso.
  void progressUpdate(int percent, string note) @safe;
  /// Termina el progreso.
  void progressEnd() @safe;

  /**
   * Pide el PIN de la credencial para una solicitud de Firmador Remoto o de una conexión
   * (RequestPinWindowRemote), mostrando la descripción (HTML sencillo) y la imagen que la
   * acompaña. Devuelve false si el usuario cancela; si acepta, el PIN queda en la credencial.
   */
  bool requestRemotePin(CardSignInfo card, string description, immutable(ubyte)[] image) @safe;

  /// Pregunta si el origen puede usar Firmador; bloquea hasta que el usuario responde.
  HostAuthorization askHostAuthorization(string origin) @safe;

  /// Llegó un documento a Firmador Remoto para firmarlo en la interfaz.
  void loadRemoteDocument(RemoteDocumentSlot slot) @safe;

  /// Errores de una conexión (Firmador Remoto u otras) para mostrarlos en su panel.
  void connectionErrors(string connection, string[] errors) @safe;

  /// Se autorizó un origen: la interfaz recarga la configuración y lo anota.
  void originAuthorized(string origin) @safe;
}
