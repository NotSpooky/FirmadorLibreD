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
 * Diálogos de la ventana (JOptionPane, RequestPinWindow, RequestPinWindowRemote,
 * RequestPinAndCodeWindow, RequestHostAuthorizationRemote, SelectSignatureTypeDialog,
 * SelectSimpleModePanel y ProgressDialog en la versión Java). Todos son asíncronos: se
 * abren en el hilo de la ventana y entregan el resultado a una función; quien necesita
 * esperarlo desde otro hilo usa firmador.gui.desktop.uithread.waitOnUi.
 *
 * FirmadorDialog corrige dos comportamientos de dlangui: Escape cierra con la acción de
 * cancelar (dlangui la cambiaba por la acción por omisión) y cerrar la ventana cuenta
 * como cancelar, para que nadie quede esperando una respuesta que no llegará.
 */
module firmador.gui.desktop.dialogs;

import core.time : dur;
import std.algorithm : all, canFind, map;
import std.array : array;
import std.ascii : isDigit;
import std.conv : to;
import std.format : format;
import std.logger : error, info, warning;
import std.uni : toUpper;
import std.utf : toUTF32, toUTF8;

import dlangui.core.events;
import dlangui.core.signals;
import dlangui.core.stdaction;
import dlangui.core.types;
import dlangui.dialogs.dialog;
import dlangui.graphics.drawbuf;
import dlangui.graphics.images : loadImage;
import dlangui.graphics.resources;
import dlangui.platforms.common.platform : Platform, Window;
import dlangui.widgets.combobox;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.progressbar;
import dlangui.widgets.widget;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.cards.detector : SmartCardDetector, UnsupportedArchitectureException;
import firmador.connections.connection : PinAndCode;
import firmador.gui.desktop.richtext : RichText;
import firmador.gui.guiinterface : HostAuthorization;
import firmador.i18n : t;
import firmador.signers.detector : formatLabel, SignatureFormat;
import firmador.tokens.token : SecretPin;
import firmador.util.desktop : openPath, openUrl;

/// Identificadores de las acciones de los diálogos propios (más allá de las estándar).
private enum int firstChoiceAction = 10_000;

/// Botón de un diálogo con el texto traducido.
Action dialogAction(int id, string labelKey) @trusted {
  return new Action(id, t(labelKey).toUTF32);
}

/// Abre un enlace de un mensaje: archivos locales con su programa, lo demás en el navegador.
void openMessageLink(string link) @trusted {
  import firmador.settingsmanager : currentSettings;
  import firmador.signers.resources : pathFromFileUri;
  import std.algorithm : startsWith;
  try {
    if (link.startsWith("file:")) openPath(pathFromFileUri(link));
    else openUrl(link, currentSettings().preferredBrowser);
  } catch (Exception exception) {
    error("No se pudo abrir el enlace ", link, ": ", exception.msg);
  }
}

/// Imagen decodificada (PNG, JPEG, GIF, BMP) reducida para caber en `maxSide`, o null si no se puede leer.
DrawableRef imageDrawable(immutable(ubyte)[] bytes, int maxSide) @trusted {
  if (bytes.length == 0) return DrawableRef.init;
  ColorDrawBuf decoded;
  try {
    decoded = loadImage(bytes, "imagen");
  } catch (Exception exception) {
    warning("No se pudo leer la imagen: ", exception.msg);
    return DrawableRef.init;
  }
  if (decoded is null) return DrawableRef.init;
  int width = decoded.width, height = decoded.height;
  if (width > maxSide || height > maxSide) {
    float scale = cast(float) maxSide / (width > height ? width : height);
    int scaledWidth = cast(int) (width * scale) > 0 ? cast(int) (width * scale) : 1;
    int scaledHeight = cast(int) (height * scale) > 0 ? cast(int) (height * scale) : 1;
    auto scaled = new ColorDrawBuf(scaledWidth, scaledHeight);
    scaled.fill(0xFFFFFFFF);
    scaled.drawRescaled(Rect(0, 0, scaledWidth, scaledHeight), decoded, Rect(0, 0, width, height));
    decoded = scaled;
  }
  DrawBufRef reference = decoded;
  return DrawableRef(new ImageDrawable(reference));
}

/// Base de los diálogos: Escape cancela y cerrar la ventana también.
class FirmadorDialog : Dialog {
  private bool finished;
  private void delegate(const Action result) resultHandler;
  protected Action cancelAction;

  this(string title, Window parent, uint flags = DialogFlag.Modal) @trusted {
    super(UIString.fromRaw(title.toUTF32), parent, flags);
    padding = Rect(12, 12, 12, 12);
  }

  /// Muestra el diálogo; `handler` recibe la acción elegida, o null si se cerró la ventana.
  void open(void delegate(const Action result) handler) @trusted {
    resultHandler = handler;
    show();
    if (_window !is null) {
      _window.onClose = () {
        if (!finished) deliver(null);
      };
    }
  }

  private void deliver(const Action action) {
    if (finished) return;
    finished = true;
    if (resultHandler !is null) resultHandler(action);
  }

  override void close(const Action action) {
    if (action !is null && !accepts(action)) return;
    deliver(action);
    super.close(null);
  }

  /// Si el diálogo puede cerrarse con esa acción (validaciones de los campos).
  protected bool accepts(const Action action) {
    return true;
  }

  override bool onKeyEvent(KeyEvent event) {
    if (event.action == KeyAction.KeyDown && event.keyCode == KeyCode.ESCAPE && event.noModifiers) {
      close(cancelAction);
      return true;
    }
    return super.onKeyEvent(event);
  }

  /// Añade los botones; el primero es el que se activa con Intro.
  void addButtons(Action[] actions, int defaultIndex, Action cancel) {
    cancelAction = cancel;
    addChild(createButtonsPanel(cast(const(Action)[]) actions, defaultIndex, 0));
  }

  /// Añade Aceptar (el de Intro) y Cancelar (el de Escape).
  void addOkCancel() @trusted {
    auto cancel = dialogAction(StandardAction.Cancel, "dialog_cancel");
    addButtons([dialogAction(StandardAction.Ok, "dialog_accept"), cancel], 0, cancel);
  }
}

/// Añade a la fila la imagen, si se puede mostrar, con su margen a la derecha.
private void addImage(HorizontalLayout row, string id, immutable(ubyte)[] image, int size) @trusted {
  auto drawable = imageDrawable(image, size);
  if (drawable.isNull) return;
  auto picture = new ImageWidget(id);
  picture.drawable = drawable;
  picture.margins = Rect(0, 0, 16, 0);
  row.addChild(picture);
}

/// Mensaje con texto con formato y botones propios.
private final class MessageDialog : FirmadorDialog {
  this(string title, string html, Window parent, Action[] actions, int defaultIndex, Action cancel) @trusted {
    super(title, parent);
    auto body = new RichText(null, html);
    body.maxWidth = 560;
    body.onLink = (string link) { openMessageLink(link); };
    body.margins = Rect(0, 0, 0, 12);
    addChild(body);
    addButtons(actions, defaultIndex, cancel);
  }
}

/// Muestra un mensaje (JOptionPane.showMessageDialog) y avisa cuando se cierra.
void showMessageDialog(Window parent, string title, string html, void delegate() done = null) @trusted {
  auto ok = dialogAction(StandardAction.Ok, "dialog_accept");
  auto dialog = new MessageDialog(title, html, parent, [ok], 0, ok);
  dialog.open((const Action result) {
    if (done !is null) done();
  });
}

/// Pregunta sí o no (showConfirmDialog); cerrar la ventana es no.
void showConfirmDialog(Window parent, string title, string html, void delegate(bool accepted) done) @trusted {
  auto yes = dialogAction(StandardAction.Yes, "dialog_yes");
  auto no = dialogAction(StandardAction.No, "dialog_no");
  auto dialog = new MessageDialog(title, html, parent, [yes, no], 0, no);
  dialog.open((const Action result) { done(result !is null && result.id == StandardAction.Yes); });
}

/**
 * Pregunta entre varias opciones (showOptionDialog); entrega el índice elegido, o -1 si
 * se cerró o se canceló (la última opción es la de cancelar si `lastCancels`).
 */
void showChoiceDialog(Window parent, string title, string html, string[] options, int defaultIndex,
    bool lastCancels, void delegate(int choice) done) @trusted {
  Action[] actions;
  foreach (index, option; options) actions ~= new Action(firstChoiceAction + cast(int) index, option.toUTF32);
  auto dialog = new MessageDialog(title, html, parent, actions, defaultIndex, lastCancels ? actions[$ - 1] : null);
  dialog.open((const Action result) {
    done(result is null ? -1 : result.id - firstChoiceAction);
  });
}

/// Autorización de un origen para Firmador Remoto (RequestHostAuthorizationRemote).
void showHostAuthorizationDialog(Window parent, string origin, void delegate(HostAuthorization) done) @trusted {
  import firmador.xml.dom : escapeXml;
  showChoiceDialog(parent, t("host_authorization_title"), t("host_authorization_message") ~ "<br><b>"
    ~ escapeXml(origin) ~ "</b>", [t("host_authorization_always"), t("host_authorization_once"),
    t("dialog_cancel")], 2, true, (int choice) {
    done(choice == 0 ? HostAuthorization.always : choice == 1 ? HostAuthorization.once : HostAuthorization.denied);
  });
}

/// Campo de PIN: oculta lo que se escribe.
private EditLine pinField() @trusted {
  auto field = new EditLine("pin");
  field.passwordChar = '•';
  field.minWidth = 220;
  return field;
}

/// Texto de un campo de PIN como SecretPin, borrando el campo.
private SecretPin takePin(EditLine field) @trusted {
  auto characters = field.text.toUTF8.dup;
  field.text = ""d;
  auto pin = new SecretPin(characters);
  characters[] = '\0';
  return pin;
}

/**
 * Credencial y PIN para firmar (RequestPinWindow): lista las credenciales detectadas, se
 * puede refrescar la lista, y exige credencial y PIN antes de aceptar.
 */
final class PinDialog : FirmadorDialog {
  private SmartCardDetector detector;
  private CardSignInfo[] cards;
  private ComboBox cardList;
  private EditLine pin;
  private TextWidget info;

  this(Window parent, SmartCardDetector detector) @trusted {
    super(t("pin_dialog_title"), parent);
    this.detector = detector;
    auto table = new TableLayout;
    table.colCount = 3;
    table.addChild(new TextWidget(null, t("pin_dialog_request_certificate").toUTF32));
    cardList = new ComboBox("cards", cast(dstring[]) []);
    cardList.minWidth = 360;
    cardList.itemClick = (Widget source, int index) { updateSelected(); return true; };
    table.addChild(cardList);
    auto refresh = new Button("refresh", t("pin_dialog_reload_cards").toUTF32);
    refresh.tooltipText = t("pin_dialog_reload_cards_accesible").toUTF32;
    refresh.click = (Widget source) { reloadCards(); return true; };
    table.addChild(refresh);
    table.addChild(new TextWidget(null, t("pin_dialog_requestpin").toUTF32));
    pin = pinField();
    pin.enterKey = (EditWidgetBase source) { close(new Action(StandardAction.Ok)); return true; };
    table.addChild(pin);
    table.addChild(new TextWidget(null, ""d));
    addChild(table);
    info = new TextWidget("info", ""d);
    info.margins = Rect(0, 8, 0, 8);
    addChild(info);
    addOkCancel();
  }

  /// Muestra las credenciales detectadas.
  void showCards(CardSignInfo[] detected) @trusted {
    cards = detected;
    cardList.items = cards.map!(card => card.displayInfo.toUTF32).array;
    if (cards.length) cardList.selectedItemIndex = 0;
    updateSelected();
  }

  private void updateSelected() {
    int index = cardList.selectedItemIndex;
    info.text = index >= 0 && index < cards.length ? cards[index].displayInfo.toUTF32
      : t("pin_dialog_warning_card").toUTF32;
  }

  private void reloadCards() {
    try {
      showCards(detector.readSaveListSmartCard());
    } catch (UnsupportedArchitectureException exception) {
      showMessageDialog(window, t("pin_dialog_warning_arm_title"), t("pin_dialog_warning_arm"));
    } catch (Exception exception) {
      error(t("pin_error_reading_cards"), ": ", exception.msg);
    }
  }

  protected override bool accepts(const Action action) {
    if (action.id != StandardAction.Ok) return true;
    if (pin.text.length > 0 && cardList.selectedItemIndex >= 0 && cardList.selectedItemIndex < cards.length) {
      return true;
    }
    showMessageDialog(window, t("pin_dialog_error_context"), t("pin_dialog_error_title"));
    return false;
  }

  /// Credencial elegida con su PIN, o null si se canceló.
  void open(void delegate(CardSignInfo card) done) @trusted {
    reloadCards();
    super.open((const Action result) {
      if (result is null || result.id != StandardAction.Ok) {
        pin.text = ""d;
        done(null);
        return;
      }
      auto card = cards[cardList.selectedItemIndex];
      card.pin = takePin(pin);
      done(card);
    });
    pin.setFocus();
  }
}

/**
 * PIN para una solicitud de Firmador Remoto o de un servicio (RequestPinWindowRemote):
 * la credencial ya está elegida; se muestran la descripción y la imagen de la solicitud.
 */
void showRemotePinDialog(Window parent, CardSignInfo card, string description, immutable(ubyte)[] image,
    void delegate(bool accepted) done) @trusted {
  auto dialog = new RemotePinDialog(parent, card, description, image);
  dialog.open((const Action result) {
    bool accepted = result !is null && result.id == StandardAction.Ok;
    if (accepted) card.pin = takePin(dialog.pin);
    else dialog.pin.text = ""d;
    done(accepted);
  });
  dialog.pin.setFocus();
}

private final class RemotePinDialog : FirmadorDialog {
  EditLine pin;

  this(Window parent, CardSignInfo card, string description, immutable(ubyte)[] image) @trusted {
    super(t("pin_dialog_title"), parent);
    auto row = new HorizontalLayout;
    addImage(row, "imagen", image, 128);
    auto column = new VerticalLayout;
    auto table = new TableLayout;
    table.colCount = 2;
    table.addChild(new TextWidget(null, t("pin_dialog_remote_certificate").toUTF32));
    table.addChild(new TextWidget("certificado", card.displayInfo.toUTF32));
    table.addChild(new TextWidget(null, t("pin_dialog_requestpin").toUTF32));
    pin = pinField();
    pin.enterKey = (EditWidgetBase source) { close(new Action(StandardAction.Ok)); return true; };
    table.addChild(pin);
    column.addChild(table);
    import firmador.xml.dom : escapeXml;
    auto info = new RichText("descripcion", t("pin_dialog_info_remote") ~ " " ~ (description is null ? ""
      : description));
    info.maxWidth = 480;
    info.margins = Rect(0, 8, 0, 8);
    column.addChild(info);
    row.addChild(column);
    addChild(row);
    addOkCancel();
  }

  protected override bool accepts(const Action action) {
    if (action.id != StandardAction.Ok || pin.text.length > 0) return true;
    showMessageDialog(window, t("pin_dialog_error_context"), t("pin_dialog_error_title"));
    return false;
  }
}

/// El PIN sólo admite dígitos.
bool isValidPinText(dstring text) pure nothrow @safe {
  return text.all!(character => character >= '0' && character <= '9');
}

/// Segundos que da el BCCR para responder una solicitud (RequestPinAndCodeWindow).
enum int pinAndCodeSeconds = 120;

/// Texto del tiempo restante: «Tiempo restante: 1:05».
string remainingTimeText(int seconds) @safe {
  return format(t("pin_code_time_left"), seconds / 60, seconds % 60);
}

/**
 * PIN y código de verificación de una solicitud del BCCR (RequestPinAndCodeWindow): el
 * PIN sólo admite dígitos, el código se pasa a mayúsculas y la solicitud vence a los dos
 * minutos.
 */
void showPinAndCodeDialog(Window parent, immutable(ubyte)[] logo, string entityName, string summary,
    string errorMessage, void delegate(PinAndCode result) done) @trusted {
  auto dialog = new PinAndCodeDialog(parent, logo, entityName, summary, errorMessage);
  dialog.open((const Action result) {
    dialog.stopTimer();
    if (result is null || result.id != StandardAction.Ok) {
      dialog.pin.text = ""d;
      if (dialog.expired) showMessageDialog(parent, t("pin_code_expired_title"), t("pin_code_expired"));
      done(PinAndCode(false, null, null));
      return;
    }
    string code = dialog.code.text.toUTF8.toUpper;
    done(PinAndCode(true, takePin(dialog.pin), code));
  });
  dialog.pin.setFocus();
}

private final class PinAndCodeDialog : FirmadorDialog {
  EditLine pin;
  EditLine code;
  bool expired;
  private TextWidget timerLabel;
  private int remaining = pinAndCodeSeconds;
  private ulong timerId;

  this(Window parent, immutable(ubyte)[] logo, string entityName, string summary, string errorMessage) @trusted {
    super(t("pin_code_title"), parent);
    auto summaryText = new RichText("resumen", summary);
    summaryText.maxWidth = 380;
    summaryText.margins = Rect(0, 0, 0, 12);
    addChild(summaryText);
    auto row = new HorizontalLayout;
    addImage(row, "logo", logo, 96);
    auto table = new TableLayout;
    table.colCount = 2;
    table.addChild(new TextWidget(null, t("pin_code_pin_label").toUTF32));
    pin = pinField();
    pin.contentChange = (EditableContent content) {
      dstring value = pin.text;
      if (!isValidPinText(value)) {
        dstring digits;
        foreach (character; value) if (character >= '0' && character <= '9') digits ~= character;
        pin.text = digits;
      }
    };
    table.addChild(pin);
    table.addChild(new TextWidget(null, t("pin_code_code_label").toUTF32));
    code = new EditLine("codigo");
    code.minWidth = 220;
    code.contentChange = (EditableContent content) {
      dstring value = code.text;
      dstring upper = value.toUpper;
      if (upper != value) code.text = upper;
    };
    code.enterKey = (EditWidgetBase source) { close(new Action(StandardAction.Ok)); return true; };
    table.addChild(code);
    row.addChild(table);
    addChild(row);
    if (errorMessage.length) {
      auto errorText = new RichText("error", "<b>" ~ errorMessage ~ "</b>");
      errorText.textColor = 0xB00020;
      errorText.margins = Rect(0, 8, 0, 0);
      addChild(errorText);
    }
    timerLabel = new TextWidget("tiempo", remainingTimeText(remaining).toUTF32);
    timerLabel.fontWeight = 800;
    timerLabel.alignment = Align.Center;
    timerLabel.layoutWidth = FILL_PARENT;
    timerLabel.margins = Rect(0, 12, 0, 4);
    addChild(timerLabel);
    auto entity = new TextWidget("entidad", entityName.toUTF32);
    entity.fontWeight = 800;
    entity.margins = Rect(0, 0, 0, 12);
    addChild(entity);
    addOkCancel();
  }

  override void onShow() {
    super.onShow();
    timerId = setTimer(1000);
  }

  override bool onTimer(ulong id) {
    if (id != timerId) return super.onTimer(id);
    remaining--;
    timerLabel.text = remainingTimeText(remaining).toUTF32;
    if (remaining > 0) return true;
    expired = true;
    close(cancelAction);
    return false;
  }

  void stopTimer() {
    if (timerId != 0) cancelTimer(timerId);
    timerId = 0;
  }

  protected override bool accepts(const Action action) {
    if (action.id != StandardAction.Ok || (pin.text.length > 0 && code.text.length > 0)) return true;
    showMessageDialog(window, t("pin_code_required_title"), t("pin_code_required"));
    return false;
  }
}

/**
 * Tipo de firma para un documento (SelectSignatureTypeDialog): entrega el formato
 * elegido, o `current` si se canceló.
 */
void showSignatureTypeDialog(Window parent, SignatureFormat[] formats, SignatureFormat current,
    void delegate(bool changed, SignatureFormat chosen) done) @trusted {
  auto dialog = new FirmadorDialog(t("signature_type_title"), parent);
  dialog.addChild(new TextWidget(null, t("signature_type_prompt").toUTF32));
  RadioButton[] buttons;
  foreach (format_; formats) {
    auto button = new RadioButton(null, formatLabel(format_).toUTF32);
    button.checked = format_ == current;
    buttons ~= button;
    dialog.addChild(button);
  }
  dialog.addOkCancel();
  dialog.open((const Action result) {
    if (result is null || result.id != StandardAction.Ok) return done(false, current);
    foreach (index, button; buttons) if (button.checked) return done(true, formats[index]);
    done(false, current);
  });
}

/// Modo simplificado o completo al primer arranque (SelectSimpleModePanel); cancelar es simplificado.
void showSelectModeDialog(Window parent, void delegate(bool simplified) done) @trusted {
  auto dialog = new FirmadorDialog(t("select_mode_title"), parent);
  auto question = new TextWidget(null, t("select_mode_question").toUTF32);
  question.fontWeight = 800;
  dialog.addChild(question);
  auto simplified = new RadioButton("simplificado", t("select_mode_yes").toUTF32);
  simplified.checked = true;
  simplified.margins = Rect(16, 12, 0, 4);
  auto complete = new RadioButton("completo", t("select_mode_no").toUTF32);
  complete.margins = Rect(16, 4, 0, 4);
  dialog.addChild(simplified);
  dialog.addChild(complete);
  auto note = new TextWidget(null, t("select_mode_info").toUTF32);
  note.fontItalic = true;
  note.textColor = 0x707070;
  note.margins = Rect(0, 16, 0, 12);
  dialog.addChild(note);
  dialog.addOkCancel();
  dialog.open((const Action result) {
    done(result is null || result.id != StandardAction.Ok || simplified.checked);
  });
}

/**
 * Progreso de un lote de firmas (ProgressDialog): título, nota del paso y barra. Cerrarlo
 * sólo lo oculta; la firma sigue.
 */
final class ProgressDialog : FirmadorDialog {
  private TextWidget header;
  private TextWidget note;
  private ProgressBarWidget bar;
  private bool closed;

  this(Window parent, string title, string headerText) @trusted {
    super(title, parent, DialogFlag.Popup);
    minWidth = 460;
    header = new TextWidget("encabezado", headerText.toUTF32);
    header.fontWeight = 800;
    header.alignment = Align.Center;
    header.layoutWidth = FILL_PARENT;
    addChild(header);
    note = new TextWidget("nota", ""d);
    note.margins = Rect(0, 8, 0, 8);
    note.layoutWidth = FILL_PARENT;
    addChild(note);
    bar = new ProgressBarWidget("progreso", PROGRESS_INDETERMINATE);
    bar.layoutWidth = FILL_PARENT;
    bar.animationInterval = 50;
    addChild(bar);
    auto close_ = dialogAction(StandardAction.Close, "progress_dialog_btn_close");
    addButtons([close_], 0, close_);
  }

  /// Muestra el diálogo.
  void display() @trusted {
    open((const Action result) { closed = true; });
  }

  void setHeader(string text) @trusted {
    if (!closed) header.text = text.toUTF32;
  }

  void setProgress(int percent, string text) @trusted {
    if (closed) return;
    bar.progress = percent <= 0 ? PROGRESS_INDETERMINATE : percent * PROGRESS_MAX / 100;
    note.text = text.toUTF32;
  }

  /// Cierra el diálogo si sigue abierto.
  void finish() @trusted {
    if (!closed) close(cancelAction);
  }
}

@("should accept only digits in a PIN and format the remaining time like the BCCR window")
unittest {
  import firmador.i18n : setMessagesLocale;
  setMessagesLocale("es", "CR");
  assert(isValidPinText("0123"d) && isValidPinText(""d));
  assert(!isValidPinText("12a"d));
  assert(remainingTimeText(65) == "Tiempo restante: 1:05");
  assert(remainingTimeText(120) == "Tiempo restante: 2:00");
}
