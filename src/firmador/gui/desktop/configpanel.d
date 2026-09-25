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
 * Pestaña de configuración (ConfigPanel, Pkcs12ConfigPanel y PluginManagerPlugin): las
 * opciones básicas (modo, firma visible, datos y apariencia de la firma, idioma) y las
 * avanzadas (niveles AdES, biblioteca PKCS#11, almacenes PKCS#12, Firmador Remoto,
 * vista previa y programas externos, bitácoras y plugins). Guardar escribe
 * config.properties; aplicar sin guardar sólo cambia la sesión; restaurar vuelve a los
 * valores por omisión.
 *
 * Los valores se validan al guardar: un número o un color que no se puede leer se informa
 * con el campo y no se aplica nada.
 */
module firmador.gui.desktop.configpanel;

import std.algorithm : canFind, countUntil, map, remove;
import std.array : array, join, replace, split;
import std.conv : ConvException, to;
import std.exception : enforce;
import std.format : format;
import std.logger : error, info;
import std.path : baseName;
import std.string : strip;
import std.utf : toUTF32, toUTF8;

import dlangui.core.events : Action;
import dlangui.core.stdaction : StandardAction;
import dlangui.core.types;
import dlangui.widgets.combobox;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.scroll;
import dlangui.widgets.widget;

import firmador.cards.pkcs12store : normalizeStorePath, Pkcs12CredentialStore, readPkcs12Metadata;
import firmador.crypto.openssl : WrongPasswordException;
import firmador.gui.desktop.common;
import firmador.gui.desktop.dialogs;
import firmador.gui.desktop.secretfield : SecretField;
import firmador.gui.desktop.pageview : zoomAt, zoomIndexFor, zoomSettingValues;
import firmador.gui.desktop.signpanel : rotationLabels, rotationValues, zoomLabels;
import firmador.gui.desktop.window : DesktopInterface;
import firmador.gui.guiinterface : NotificationType;
import firmador.i18n : t;
import firmador.plugins.plugin : knownPluginNames;
import firmador.settings : parseColor, Settings, splitHosts, transparentColorName;
import firmador.settingsmanager : currentSettings, replaceCurrentSettings, writeSettings;
import firmador.signers.common : rootCause;

/// Opciones de los selectores (las mismas listas de la versión Java).
immutable string[] logLevels = ["OFF", "SEVERE", "WARNING", "INFO", "CONFIG", "FINE", "FINER", "FINEST", "ALL"];
immutable string[] fontPositions = ["RIGHT", "LEFT", "BOTTOM", "TOP", "ONLY IMAGE"];
immutable string[] signatureLevels = ["T", "LT", "LTA"];
immutable string[] languages = ["es", "en"];
immutable string[] windowStates = ["NORMAL", "MAXIMIZED_BOTH", "MAXIMIZED_HORIZ", "MAXIMIZED_VERT"];
immutable string[] themeModes = ["system", "light", "dark"];

/// País de cada idioma (countryByLanguage).
string countryFor(string language) pure nothrow @safe {
  return language == "en" ? "US" : "CR";
}

/// Fuentes que se ofrecen para la firma visible en esta plataforma.
immutable(string)[] signatureFonts() pure nothrow @safe {
  version (OSX) {
    return ["Helvetica Regular", "Helvetica Oblique", "Helvetica Bold", "Helvetica Bold Oblique",
      "Times New Roman Regular", "Times New Roman Italic", "Times New Roman Bold", "Times New Roman Bold Italic",
      "Courier New Regular", "Courier New Italic", "Courier New Bold", "Courier New Bold Italic"];
  } else version (Windows) {
    return ["Arial Regular", "Arial Italic", "Arial Bold", "Arial Bold Italic", "Times New Roman Regular",
      "Times New Roman Italic", "Times New Roman Bold", "Times New Roman Bold Italic", "Courier New Regular",
      "Courier New Italic", "Courier New Bold", "Courier New Bold Italic"];
  } else {
    return ["Nimbus Sans Regular", "Nimbus Sans Italic", "Nimbus Sans Bold", "Nimbus Sans Bold Italic",
      "Nimbus Roman Regular", "Nimbus Roman Italic", "Nimbus Roman Bold", "Nimbus Roman Bold Italic",
      "Nimbus Mono PS Regular", "Nimbus Mono PS Italic", "Nimbus Mono PS Bold", "Nimbus Mono PS Bold Italic"];
  }
}

/**
 * Número entero de un campo.
 *
 * Throws: Exception con el nombre del campo si no es un entero.
 */
int integerField(string text, string fieldName) pure @safe {
  try {
    return text.strip.to!int;
  } catch (ConvException) {
    throw new Exception(format("«%s» debe ser un número entero, no «%s»", fieldName, text));
  }
}

/**
 * Número decimal de un campo (acepta coma decimal).
 *
 * Throws: Exception con el nombre del campo si no es un número positivo.
 */
float scaleField(string text, string fieldName) pure @safe {
  try {
    float value = text.strip.replace(",", ".").to!float;
    enforce(value > 0, format("«%s» debe ser mayor que cero", fieldName));
    return value;
  } catch (ConvException) {
    throw new Exception(format("«%s» debe ser un número, no «%s»", fieldName, text));
  }
}

/// Pestaña de configuración.
final class ConfigPanel : VerticalLayout {
  private DesktopInterface host;
  private VerticalScroll scroll;
  private VerticalLayout basic, advanced;
  private bool showingAdvanced;
  private Button switchButton;

  private CheckBox simplifiedMode, withoutVisibleSign, showLogs, overwriteSourceFile, startRemote,
    startRemoteBasic, allowOriginPort, showTrayNotifications;
  private EditLine reason, place, contact, dateFormat, pageNumber, signX, signY, fontSize,
    fontColor, backgroundColor, imagePath, imageWidth, imageHeight, sofficePath, preferredBrowser, scaleFactor,
    pkcs11Library;
  private EditBox defaultSignMessage, allowedOrigins;
  private ComboBox font, fontPosition, rotation, zoom, language, windowState, themeMode, logLevel, padesLevel,
    xadesLevel, cadesLevel, jadesLevel;
  private string[] pkcs12Files;
  private VerticalLayout pkcs12List;
  private CheckBox[string] pluginChecks;

  this(DesktopInterface host) @trusted {
    super("configuracion");
    this.host = host;
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;
    auto top = new HorizontalLayout;
    switchButton = makeButton("cambiar-vista", "configpanel_advanced_options", null, () {
      showingAdvanced = !showingAdvanced;
      showView();
      return true;
    });
    top.addChild(switchButton);
    addChild(top);
    basic = buildBasic();
    advanced = buildAdvanced();
    auto content = new VerticalLayout;
    content.layoutWidth = FILL_PARENT;
    content.addChild(basic);
    content.addChild(advanced);
    scroll = new VerticalScroll("configuracion-scroll", content);
    addChild(scroll);
    auto buttons = new HorizontalLayout;
    buttons.addChild(makeButton("restaurar", "configpanel_restore", null, () {
      load(new Settings());
      host.showNotification(t("configpanel_restore_done"), NotificationType.success);
      return true;
    }));
    buttons.addChild(makeButton("aplicar", "configpanel_apply_without_saving", null, () {
      apply(false);
      return true;
    }));
    buttons.addChild(makeButton("guardar", "configpanel_save", null, () {
      apply(true);
      return true;
    }));
    addChild(buttons);
    load(currentSettings());
    showView();
  }

  private void showView() {
    basic.visibility = showingAdvanced ? Visibility.Gone : Visibility.Visible;
    advanced.visibility = showingAdvanced ? Visibility.Visible : Visibility.Gone;
    switchButton.text = dt(showingAdvanced ? "configpanel_basic_options" : "configpanel_advanced_options");
  }

  /// Vuelve a leer la configuración vigente (tras autorizar un origen, por ejemplo).
  void reload() @trusted {
    load(currentSettings());
  }

  // Armado --------------------------------------------------------------------------

  private TableLayout form(VerticalLayout parent) {
    auto table = new TableLayout;
    table.colCount = 2;
    table.layoutWidth = FILL_PARENT;
    parent.addChild(table);
    return table;
  }

  private T row(T : Widget)(TableLayout table, string label, T widget) {
    auto text = new TextWidget(null, label.toUTF32);
    text.minWidth = 220;
    table.addChild(text);
    widget.layoutWidth = FILL_PARENT;
    table.addChild(widget);
    return widget;
  }

  private EditLine field(TableLayout table, string labelKey) {
    return row(table, t(labelKey), new EditLine);
  }

  private ComboBox combo(TableLayout table, string label, const(dstring)[] items) {
    return row(table, label, new ComboBox(null, items.dup));
  }

  private static dstring[] plain(const string[] items) pure @trusted {
    return items.map!(item => item.toUTF32).array;
  }

  private void section(VerticalLayout parent, string titleKey) {
    auto title = boldTitle(titleKey);
    title.margins = Rect(0, 16, 0, 6);
    parent.addChild(title);
  }

  /// Campo de ruta con botón para elegir un archivo.
  private EditLine pathField(TableLayout table, string label, string dialogKey) {
    auto rowLayout = new HorizontalLayout;
    auto edit = new EditLine;
    edit.layoutWidth = FILL_PARENT;
    rowLayout.addChild(edit);
    rowLayout.addChild(makeButton(null, "configpanel_choose", null, () {
      chooseFiles(window, t(dialogKey), false, null, (string[] paths) {
        if (paths.length) edit.text = paths[0].toUTF32;
      });
      return true;
    }));
    row(table, label, rowLayout);
    return edit;
  }

  private VerticalLayout buildBasic() {
    auto panel = new VerticalLayout("basica");
    panel.layoutWidth = FILL_PARENT;
    panel.padding = Rect(10, 10, 10, 10);
    auto checks = new HorizontalLayout;
    simplifiedMode = new CheckBox("modo-simplificado", dt("configpanel_simplified_mode"));
    withoutVisibleSign = new CheckBox("sin-firma-visible-config", dt("configpanel_without_visible_signature"));
    showLogs = new CheckBox("ver-bitacoras", dt("configpanel_view_logs"));
    startRemoteBasic = new CheckBox("iniciar-remoto-basico", dt("configpanel_start_fimador_remote"));
    startRemoteBasic.tooltipText = tip("configpanel_start_fimador_remote_tooltip");
    foreach (check; [simplifiedMode, withoutVisibleSign, showLogs, startRemoteBasic]) {
      check.margins = Rect(0, 0, 16, 0);
      checks.addChild(check);
    }
    panel.addChild(checks);
    auto checksDown = new HorizontalLayout;
    overwriteSourceFile = new CheckBox("sobrescribir", dt("configpanel_rewrite_original_file"));
    showTrayNotifications = new CheckBox("notificaciones", dt("configpanel_show_tray_notifications"));
    showTrayNotifications.tooltipText = tip("configpanel_show_tray_notifications_tooltip");
    foreach (check; [overwriteSourceFile, showTrayNotifications]) {
      check.margins = Rect(0, 4, 16, 0);
      checksDown.addChild(check);
    }
    panel.addChild(checksDown);
    auto table = form(panel);
    reason = field(table, "configpanel_reason");
    place = field(table, "configpanel_place");
    contact = field(table, "configpanel_contact");
    dateFormat = field(table, "configpanel_date_format");
    dateFormat.tooltipText = tip("configpanel_must_be_compatible_with_java_date_formats");
    defaultSignMessage = row(table, t("configpanel_signature_message"), new EditBox);
    defaultSignMessage.minHeight = 70;
    defaultSignMessage.tooltipText = tip("configpanel_default_sign_message_help");
    pageNumber = field(table, "configpanel_initial_page");
    signX = field(table, "configpanel_initial_position_x");
    signY = field(table, "configpanel_initial_position_y");
    fontSize = field(table, "configpanel_font_size");
    font = combo(table, t("configpanel_font"), plain(signatureFonts()));
    fontPosition = combo(table, t("configpanel_font_position"), plain(fontPositions));
    fontColor = field(table, "configpanel_font_color");
    fontColor.tooltipText = tip("configpanel_use_the_word_transparent_if_you_do_not_want_a_color");
    backgroundColor = field(table, "configpanel_background_color");
    backgroundColor.tooltipText = tip("configpanel_use_the_word_transparent_if_you_do_not_want_a_background_color");
    imagePath = pathField(table, t("configpanel_signature_image"), "configpanel_select_an_image");
    imageWidth = field(table, "configpanel_signature_image_width");
    imageHeight = field(table, "configpanel_signature_image_height");
    rotation = combo(table, t("configpanel_sign_rotation"), rotationLabels());
    zoom = combo(table, t("configpanel_preview_zoom"), zoomLabels());
    language = combo(table, t("configpanel_language"), plain(languages));
    windowState = combo(table, t("configpanel_windowstate"), plain(windowStates));
    themeMode = combo(table, t("configpanel_theme_mode"), plain(themeModes));
    return panel;
  }

  private VerticalLayout buildAdvanced() {
    auto panel = new VerticalLayout("avanzada");
    panel.layoutWidth = FILL_PARENT;
    panel.padding = Rect(10, 10, 10, 10);
    section(panel, "configpanel_section_signature_levels");
    auto levels = form(panel);
    padesLevel = combo(levels, t("configpanel_level") ~ " PAdES:", plain(signatureLevels));
    xadesLevel = combo(levels, t("configpanel_level") ~ " XAdES:", plain(signatureLevels));
    cadesLevel = combo(levels, t("configpanel_level") ~ " CAdES:", plain(signatureLevels));
    jadesLevel = combo(levels, t("configpanel_level") ~ " JAdES:", plain(signatureLevels));

    section(panel, "configpanel_section_pkcs11");
    auto pkcs11 = form(panel);
    pkcs11Library = pathField(pkcs11, t("configpanel_file") ~ " PKCS11", "configpanel_select_a_file");
    panel.addChild(new TextWidget(null, (t("configpanel_the_file") ~ " PKCS11 " ~ t("configpanel_is_automatically_detected")
      ~ ", " ~ t("configpanel_but_could_be_write_using_the_previous_field")).toUTF32));

    section(panel, "configpanel_section_pkcs12");
    auto pkcs12Buttons = new HorizontalLayout;
    pkcs12Buttons.addChild(new TextWidget(null, dt("pkcs12_config_label")));
    auto addPkcs12 = new Button(null, "+"d);
    addPkcs12.tooltipText = dt("pkcs12_config_select_file");
    addPkcs12.click = (Widget source) { choosePkcs12(); return true; };
    pkcs12Buttons.addChild(addPkcs12);
    panel.addChild(pkcs12Buttons);
    pkcs12List = new VerticalLayout("almacenes");
    pkcs12List.layoutWidth = FILL_PARENT;
    panel.addChild(pkcs12List);

    section(panel, "configpanel_section_remote");
    startRemote = new CheckBox("iniciar-remoto", dt("configpanel_start_fimador_remote"));
    startRemote.tooltipText = tip("configpanel_start_fimador_remote_tooltip");
    // Es la misma opción que la casilla de la vista básica.
    startRemote.checkChange = (Widget source, bool checked) { startRemoteBasic.checked = checked; return true; };
    startRemoteBasic.checkChange = (Widget source, bool checked) { startRemote.checked = checked; return true; };
    panel.addChild(startRemote);
    allowOriginPort = new CheckBox("puerto-del-sitio", dt("configpanel_allow_origin_port"));
    allowOriginPort.tooltipText = tip("configpanel_allow_origin_port_tooltip");
    panel.addChild(allowOriginPort);
    auto remote = form(panel);
    allowedOrigins = row(remote, t("configpanel_allowed_hosts"), new EditBox);
    allowedOrigins.minHeight = 90;

    section(panel, "configpanel_section_preview_apps");
    auto apps = form(panel);
    scaleFactor = field(apps, "configpanel_pdf_preview_scale");
    scaleFactor.tooltipText = tip("configpanel_scale_factor_to_present_the_pdf_page_preview");
    sofficePath = pathField(apps, t("configpanel_libreoffice_route") ~ ":", "configpanel_select_a_file");
    preferredBrowser = pathField(apps, t("configpanel_preferred_browser") ~ ":", "configpanel_select_browser");

    section(panel, "configpanel_section_logs");
    auto logs = form(panel);
    logLevel = combo(logs, t("configpanel_section_logs"), plain(logLevels));

    section(panel, "configpanel_section_plugins");
    foreach (name; knownPluginNames) {
      auto check = new CheckBox(null, baseName(name.replace(".", "/")).toUTF32);
      check.tooltipText = name.toUTF32;
      pluginChecks[name] = check;
      panel.addChild(check);
    }
    return panel;
  }

  // Almacenes PKCS#12 --------------------------------------------------------------------

  private void refreshPkcs12() {
    pkcs12List.removeAllChildren();
    foreach (path; pkcs12Files) pkcs12List.addChild(pkcs12Row(path));
  }

  private void choosePkcs12() {
    chooseFiles(window, t("pkcs12_config_select_file"), false, null, (string[] paths) {
      if (paths.length == 0) return;
      string path = normalizeStorePath(paths[0]);
      if (pkcs12Files.canFind(path)) {
        host.showNotification(t("pkcs12_config_already_added"), NotificationType.info);
        return;
      }
      askPkcs12Password(path);
    });
  }

  /**
   * Pide la contraseña y registra la identidad del almacén: es el único momento en que se
   * tiene, así que aquí se lee y se guarda el certificado. La contraseña no se guarda.
   */
  private void askPkcs12Password(string path) {
    auto dialog = new FirmadorDialog(t("pkcs12_config_password_title"), window);
    dialog.addChild(new TextWidget(null, format(t("pkcs12_config_password_prompt"), baseName(path)).toUTF32));
    auto password = new SecretField("contrasena");
    password.minWidth = 260;
    password.onEnter = () { dialog.close(new Action(StandardAction.Ok)); };
    dialog.addChild(password);
    dialog.addOkCancel();
    dialog.open((const Action result) {
      auto characters = password.take();
      scope (exit) characters[] = '\0';
      if (result is null || result.id != StandardAction.Ok) return;
      try {
        auto meta = readPkcs12Metadata(path, characters);
        auto store = Pkcs12CredentialStore.instance();
        store.put(meta);
        // Se guarda ya: después no habría forma de volver a leer el almacén sin la contraseña.
        store.save();
        pkcs12Files ~= path;
        refreshPkcs12();
        showMessageDialog(window, t("pkcs12_config_label"), format(t("pkcs12_config_added_ok"),
          meta.commonName.length ? meta.commonName : baseName(path)));
      } catch (WrongPasswordException exception) {
        showMessageDialog(window, t("pkcs12_config_password_title"), t("pkcs12_config_wrong_password"), () {
          askPkcs12Password(path);
        });
      } catch (Exception exception) {
        error("No se pudo leer el almacén PKCS#12 ", path, ": ", exception.msg);
        showMessageDialog(window, t("pkcs12_config_label"), t("pkcs12_config_read_error") ~ "<br>"
          ~ rootCause(exception).msg);
      }
    });
    password.setFocus();
  }

  // Carga y aplicación ------------------------------------------------------------------

  private static void select(ComboBox box, const string[] values, string value) @trusted {
    box.selectedItemIndex = indexIn(values, value);
  }

  /// Pone en los campos los valores de unos ajustes.
  private void load(const Settings settings) {
    simplifiedMode.checked = settings.isSimplifiedMode();
    withoutVisibleSign.checked = settings.withoutVisibleSign;
    showLogs.checked = settings.showLogs;
    overwriteSourceFile.checked = settings.overwriteSourceFile;
    startRemote.checked = settings.startFimadorRemote;
    startRemoteBasic.checked = settings.startFimadorRemote;
    allowOriginPort.checked = settings.allowOriginPort;
    showTrayNotifications.checked = settings.showTrayNotifications;
    reason.text = settings.reason.toUTF32;
    place.text = settings.place.toUTF32;
    contact.text = settings.contact.toUTF32;
    dateFormat.text = settings.dateFormat.toUTF32;
    defaultSignMessage.text = settings.defaultSignMessage.toUTF32;
    pageNumber.text = settings.pageNumber.to!dstring;
    signX.text = settings.signX.to!dstring;
    signY.text = settings.signY.to!dstring;
    fontSize.text = settings.fontSize.to!dstring;
    select(font, signatureFonts(), settings.font);
    select(fontPosition, fontPositions, settings.fontAlignment);
    fontColor.text = settings.fontColor.toUTF32;
    backgroundColor.text = settings.backgroundColor.toUTF32;
    imagePath.text = settings.image.toUTF32;
    imageWidth.text = settings.signImageWidth.to!dstring;
    imageHeight.text = settings.signImageHeight.to!dstring;
    select(rotation, rotationValues, settings.signRotation);
    zoom.selectedItemIndex = zoomIndexFor(settings.previewZoom);
    select(language, languages, settings.language);
    select(windowState, windowStates, settings.startwindowstate);
    select(themeMode, themeModes, settings.themeMode);
    select(padesLevel, signatureLevels, settings.pAdESLevel);
    select(xadesLevel, signatureLevels, settings.xAdESLevel);
    select(cadesLevel, signatureLevels, settings.cAdESLevel);
    select(jadesLevel, signatureLevels, settings.jAdESLevel);
    pkcs11Library.text = settings.extraPKCS11Lib.toUTF32;
    pkcs12Files = settings.pKCS12File.dup;
    refreshPkcs12();
    allowedOrigins.text = settings.getRegisteredAllowedOrigins().join("\n").toUTF32;
    scaleFactor.text = format("%g", settings.pDFImgScaleFactor).toUTF32;
    sofficePath.text = settings.sofficePath.toUTF32;
    preferredBrowser.text = settings.preferredBrowser.toUTF32;
    select(logLevel, logLevels, settings.advancedLogs);
    foreach (name, check; pluginChecks) check.checked = settings.activePlugins.canFind(name);
  }

  /**
   * Pasa los campos a la configuración vigente (chargeSettings) y, con `save`, la escribe.
   * Si algún valor no se puede leer o no se puede guardar, se informa y no se cambia nada.
   */
  private void apply(bool save) {
    auto settings = currentSettings();
    string previousLanguage = settings.language;
    string previousTheme = settings.themeMode;
    // Los campos se leen y se guardan desde una copia completa; sólo si todo sale bien se
    // cambian los ajustes vigentes, que comparten los documentos abiertos.
    auto candidate = new Settings();
    synchronized (settings) candidate.assign(settings);
    try {
      fill(candidate);
    } catch (Exception exception) {
      showMessageDialog(window, t("guiswing_show_error_dialog_title"), exception.msg);
      return;
    }
    try {
      writeSettings(candidate, save);
    } catch (Exception exception) {
      host.showError(exception);
      return;
    }
    synchronized (settings) settings.assign(candidate);
    replaceCurrentSettings(settings);
    auto store = Pkcs12CredentialStore.instance();
    store.retainOnly(settings.pKCS12File);
    try {
      store.save();
    } catch (Exception exception) {
      // Los ajustes ya están guardados; el almacén conserva en el archivo los que se quitaron.
      host.showError(exception);
    }
    settings.updateConfig();
    host.applySettings();
    bool restartNeeded = previousLanguage != settings.language || previousTheme != settings.themeMode;
    if (restartNeeded) {
      showMessageDialog(window, t("guiswing_show_error_dialog_title"), t(save ? "configpanel_language_applied_on_restart"
        : "configpanel_language_not_applied_save_and_restart"));
    }
    host.showNotification(t(save ? "configpanel_save_done" : "configpanel_applywithoutsave"), NotificationType.success);
    info(save ? "Configuración guardada desde la ventana" : "Configuración aplicada sin guardar");
  }

  /// Lee los campos en `settings`, validando números y colores.
  private void fill(Settings settings) {
    settings.simplified_mode = simplifiedMode.checked;
    settings.withoutVisibleSign = withoutVisibleSign.checked;
    settings.showLogs = showLogs.checked;
    settings.overwriteSourceFile = overwriteSourceFile.checked;
    settings.startFimadorRemote = startRemote.checked;
    settings.allowOriginPort = allowOriginPort.checked;
    settings.showTrayNotifications = showTrayNotifications.checked;
    settings.reason = reason.text.toUTF8;
    settings.place = place.text.toUTF8;
    settings.contact = contact.text.toUTF8;
    settings.dateFormat = dateFormat.text.toUTF8;
    settings.defaultSignMessage = defaultSignMessage.text.toUTF8;
    settings.pageNumber = integerField(pageNumber.text.toUTF8, t("configpanel_initial_page"));
    settings.signX = integerField(signX.text.toUTF8, t("configpanel_initial_position_x"));
    settings.signY = integerField(signY.text.toUTF8, t("configpanel_initial_position_y"));
    settings.signXf.nullify();
    settings.signYf.nullify();
    settings.fontSize = integerField(fontSize.text.toUTF8, t("configpanel_font_size"));
    settings.signImageWidth = integerField(imageWidth.text.toUTF8, t("configpanel_signature_image_width"));
    settings.signImageHeight = integerField(imageHeight.text.toUTF8, t("configpanel_signature_image_height"));
    settings.font = valueAt(signatureFonts(), font.selectedItemIndex);
    settings.fontAlignment = valueAt(fontPositions, fontPosition.selectedItemIndex);
    string textColor = fontColor.text.toUTF8.strip;
    string fillColor = backgroundColor.text.toUTF8.strip;
    try {
      parseColor(textColor);
    } catch (Exception exception) {
      throw new Exception(t("configpanel_font_color_change_error") ~ ": " ~ textColor);
    }
    try {
      parseColor(fillColor);
    } catch (Exception exception) {
      throw new Exception(t("configpanel_background_color_change_error") ~ ": " ~ fillColor);
    }
    settings.fontColor = textColor;
    settings.backgroundColor = fillColor;
    string image = imagePath.text.toUTF8.strip;
    settings.image = image.length ? image : null;
    settings.signRotation = valueAt(rotationValues, rotation.selectedItemIndex);
    settings.previewZoom = valueAt(zoomSettingValues(), zoom.selectedItemIndex);
    settings.language = valueAt(languages, language.selectedItemIndex);
    settings.country = countryFor(settings.language);
    settings.startwindowstate = valueAt(windowStates, windowState.selectedItemIndex);
    settings.themeMode = valueAt(themeModes, themeMode.selectedItemIndex);
    settings.pAdESLevel = valueAt(signatureLevels, padesLevel.selectedItemIndex, 2);
    settings.xAdESLevel = valueAt(signatureLevels, xadesLevel.selectedItemIndex, 2);
    settings.cAdESLevel = valueAt(signatureLevels, cadesLevel.selectedItemIndex, 2);
    settings.jAdESLevel = valueAt(signatureLevels, jadesLevel.selectedItemIndex, 2);
    string library = pkcs11Library.text.toUTF8.strip;
    settings.extraPKCS11Lib = library.length ? library : null;
    settings.pKCS12File = pkcs12Files.dup;
    settings.setRegisteredAllowedOrigins(splitHosts(allowedOrigins.text.toUTF8));
    settings.pDFImgScaleFactor = scaleField(scaleFactor.text.toUTF8, t("configpanel_pdf_preview_scale"));
    settings.sofficePath = sofficePath.text.toUTF8.strip;
    settings.preferredBrowser = preferredBrowser.text.toUTF8.strip;
    settings.advancedLogs = logLevels[logLevel.selectedItemIndex < 0 ? 2 : logLevel.selectedItemIndex];
    string[] active;
    foreach (name; knownPluginNames) if (pluginChecks[name].checked) active ~= name;
    settings.activePlugins = active;
    foreach (name; active) if (!settings.availablePlugins.canFind(name)) settings.availablePlugins ~= name;
  }


  /// Fila de un almacén (función aparte: los cierres de un bucle comparten sus variables).
  private Widget pkcs12Row(string path) {
    auto rowLayout = new HorizontalLayout;
    rowLayout.layoutWidth = FILL_PARENT;
    auto meta = Pkcs12CredentialStore.instance().get(path);
    string text = meta is null || meta.certificate.length == 0 ? path ~ " " ~ t("pkcs12_config_list_no_metadata")
      : format("%s%s — %s", meta.commonName.length ? meta.commonName : baseName(path),
        meta.identification.length ? " (" ~ meta.identification ~ ")" : "", baseName(path));
    auto label = new TextWidget(null, text.toUTF32);
    label.layoutWidth = FILL_PARENT;
    rowLayout.addChild(label);
    auto remove_ = new Button(null, "−"d);
    remove_.click = (Widget source) {
      pkcs12Files = pkcs12Files.remove!(existing => existing == path);
      refreshPkcs12();
      return true;
    };
    rowLayout.addChild(remove_);

    return rowLayout;
  }

}

@("should read integers, decimal scales with comma and report the field name when invalid")
unittest {
  import std.exception : collectExceptionMsg;
  import std.algorithm : canFind;
  assert(integerField(" 12 ", "Ancho") == 12);
  assert(collectExceptionMsg(integerField("doce", "Ancho")).canFind("«Ancho»"));
  assert(scaleField("1,5", "Escala") == 1.5f);
  assert(collectExceptionMsg(scaleField("0", "Escala")).canFind("mayor que cero"));
  assert(countryFor("en") == "US" && countryFor("es") == "CR");
}
