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
 * Pestaña de firma (SignPanel): la vista previa del documento con el recuadro de la
 * firma visible, y los datos y opciones con que se firma. Arriba van página, escala,
 * rotación, posición y tamaño de la firma; abajo la razón, el lugar y el contacto, el formato (documentos que
 * no son PDF), la firma visible, el nivel (opciones avanzadas), ver las firmas, guardar la
 * configuración del documento y firmar (o rechazar un documento de Firmador Remoto).
 *
 * El recuadro muestra la apariencia real de la firma (firmador.pdf.sigpreview) con los
 * datos de la credencial conectada o, si hay varias sin elegir, con los de ejemplo. Su
 * tamaño se cambia con los botones de tamaño o arrastrando su esquina (PageView), y queda
 * en la escala del documento (Settings.signScale).
 */
module firmador.gui.desktop.signpanel;

import std.algorithm : canFind, countUntil, map;
import std.array : array, replace;
import std.datetime.systime : Clock;
import std.format : format;
import std.path : dirName;
import std.string : strip;
import std.utf : toUTF32, toUTF8;

import dlangui.core.events;
import dlangui.core.stdaction;
import dlangui.core.types;
import dlangui.graphics.drawbuf;
import dlangui.widgets.combobox;
import dlangui.widgets.controls;
import dlangui.widgets.editors;
import dlangui.widgets.layouts;
import dlangui.widgets.widget;

import firmador.cards.cardinfo : CardSignInfo, CardType;
import firmador.configuration : signatureScaleStep;
import firmador.documents.document : Document;
import firmador.documents.mimetype;
import firmador.gui.desktop.common;
import firmador.gui.desktop.dialogs;
import firmador.gui.desktop.pageview;
import firmador.gui.desktop.uithread : runInBackground, runOnUi;
import firmador.gui.desktop.window : DesktopInterface;
import firmador.gui.guiinterface : NotificationType;
import firmador.i18n : t;
import firmador.launch : hideSignatureAdviceProperty, launchFlag, launchProperty, signatureImageProperty;
import firmador.pdf.engine : PageGeometry;
import firmador.pdf.sigpreview : renderSignaturePreview;
import firmador.settings : Settings;
import firmador.settingsmanager : currentSettings;
import firmador.signers.asic : AsicSigner;
import firmador.signers.cades : CadesSigner;
import firmador.signers.common : signatureTextFor;
import firmador.signers.jades : JadesSigner;
import firmador.signers.pades : visibleSignatureFor;
import firmador.signers.resources : loadSignatureImage;
import firmador.signers.xades : XadesSigner;

/// Valores de rotación de la firma, en el orden del selector (ROTATION_VALUES).
immutable string[] rotationValues = ["AUTOMATIC", "NONE", "ROTATE_90", "ROTATE_180", "ROTATE_270"];

/// Rótulos del selector de rotación (también los usa la configuración).
dstring[] rotationLabels() @trusted {
  return [dt("signpanel_rotation_automatic"), dt("signpanel_rotation_none"), "90°"d, "180°"d, "270°"d];
}

/// Rótulos del selector de escala (también los usa la configuración).
dstring[] zoomLabels() @trusted {
  dstring[] labels = [dt("signpanel_zoom_auto_width"), dt("signpanel_zoom_full_page")];
  foreach (percent; zoomPercents) labels ~= format("%d%%", percent).toUTF32;
  return labels;
}

/**
 * Escala del paso siguiente de los botones de tamaño: el múltiplo de signatureScaleStep
 * siguiente (`direction` > 0) o anterior, aunque la escala actual venga de arrastrar la
 * esquina y no sea un múltiplo. Los límites los pone PageView.scaleSignature.
 */
float steppedSignatureScale(float current, int direction) pure nothrow @safe @nogc {
  import std.math : ceil, floor;
  // El margen evita que 1,1 guardado como 1,0999… cuente como un paso menos.
  float steps = current / signatureScaleStep;
  float next = direction > 0 ? floor(steps + 1e-3f) + 1 : ceil(steps - 1e-3f) - 1;
  return next * signatureScaleStep;
}

/// Nivel de firma de los ajustes que corresponde al tipo de documento (PAdES, XAdES, JAdES o CAdES).
private ref string levelFor(Settings settings, SupportedMimeType mimeType) @safe {
  if (isPdf(mimeType)) return settings.pAdESLevel;
  if (isXml(mimeType)) return settings.xAdESLevel;
  if (isJson(mimeType)) return settings.jAdESLevel;
  return settings.cAdESLevel;
}

/// La credencial puede anunciar un titular: una tarjeta, o un PKCS#12 registrado con su certificado.
bool hasIdentity(const CardSignInfo card) @safe {
  return card !is null && (card.cardType == CardType.pkcs11 || (card.cardType == CardType.pkcs12
    && card.certificate !is null));
}

/// Identidad estable de una credencial entre escaneos: el serial del certificado o la identificación.
string identityKey(const CardSignInfo card) @safe {
  if (card is null) return null;
  return card.certificate !is null ? card.certificate.serialDecimal : card.identification;
}

/**
 * Credencial que se anuncia en el recuadro (previewCard): la única que tenga titular, o
 * la elegida si hay varias; ninguna si hay varias sin elegir o la elegida ya no está.
 */
const(CardSignInfo) previewCard(const(CardSignInfo)[] cards, string preferredKey) @safe {
  const(CardSignInfo)[] identities;
  foreach (card; cards) if (hasIdentity(card)) identities ~= card;
  if (identities.length == 1) return identities[0];
  if (identities.length < 2 || preferredKey is null) return null;
  foreach (card; identities) if (identityKey(card) == preferredKey) return card;
  return null;
}

/// Pestaña de firma.
final class SignPanel : VerticalLayout {
  private DesktopInterface host;
  private Document current;
  private PageView pages;
  private PageSelector pageSelector;
  private ComboBox zoomBox;
  private ComboBox rotationBox;
  private Button positionButton;
  private HorizontalLayout sizeGroup;
  private TextWidget sizeLabel;
  /// Escala de la firma del documento (Settings.signScale), elegida en la vista previa.
  private float signScale = 1;
  private HorizontalLayout topBar;
  private EditLine reasonField, locationField, contactField;
  private TableLayout fieldsColumn;
  private CheckBox withoutVisible;
  private HorizontalLayout formatGroup;
  private RadioButton cadesButton, xadesButton, jadesButton, asicButton;
  private Button validateButton, advancedButton, saveButton, signButton, cancelButton, collapseButton;
  private HorizontalLayout secondaryActions;
  private VerticalLayout bottomBar;
  private bool footerCollapsed;
  private string levelOverride;
  private const(CardSignInfo)[] cards;
  private string preferredCardKey;
  private bool askingPreferredCard;
  private int previewGeneration;
  private ulong previewTimer;

  this(DesktopInterface host) @trusted {
    super("firma");
    this.host = host;
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;
    auto settings = currentSettings();

    topBar = new HorizontalLayout("barra-superior");
    topBar.padding = Rect(4, 4, 4, 4);
    topBar.addChild(new TextWidget(null, dt("signpanel_page")));
    pageSelector = new PageSelector("pagina");
    pageSelector.tooltipText = tip("signpanel_page_tooltip");
    pageSelector.onChange = (int value) {
      int index = pageIndexFor(value, pages.pageCount);
      pages.moveSignature(index, pages.signaturePlacement.x, pages.signaturePlacement.y);
      pages.scrollToPage(index);
    };
    topBar.addChild(pageSelector);
    topBar.addChild(new TextWidget(null, dt("signpanel_zoom"))).margins = Rect(12, 0, 0, 0);
    zoomBox = new ComboBox("escala", zoomLabels());
    zoomBox.tooltipText = tip("signpanel_zoom_tooltip");
    zoomBox.selectedItemIndex = zoomIndexFor(settings.previewZoom);
    zoomBox.itemClick = (Widget source, int index) {
      pages.setZoom(zoomAt(index));
      scheduleSignaturePreview();
      return true;
    };
    topBar.addChild(zoomBox);
    topBar.addChild(new TextWidget(null, dt("signpanel_rotation"))).margins = Rect(12, 0, 0, 0);
    rotationBox = new ComboBox("rotacion", rotationLabels());
    rotationBox.tooltipText = tip("signpanel_rotation_tooltip");
    rotationBox.selectedItemIndex = indexIn(rotationValues, settings.signRotation);
    rotationBox.itemClick = (Widget source, int index) {
      scheduleSignaturePreview();
      return true;
    };
    topBar.addChild(rotationBox);
    positionButton = makeButton("posicion", "signpanel_sign_position", "signpanel_sign_position", () {
      showPositionDialog();
      return true;
    });
    positionButton.margins = Rect(12, 0, 0, 0);
    topBar.addChild(positionButton);
    sizeGroup = new HorizontalLayout("tamano-firma");
    sizeGroup.margins = Rect(12, 0, 0, 0);
    sizeGroup.tooltipText = tip("signpanel_signature_size_tooltip");
    sizeGroup.addChild(new TextWidget(null, dt("signpanel_signature_size")));
    auto smaller = new Button("firma-menor", "−"d);
    smaller.tooltipText = tip("signpanel_signature_smaller");
    smaller.click = (Widget source) {
      pages.scaleSignature(steppedSignatureScale(signScale, -1));
      return true;
    };
    sizeGroup.addChild(smaller);
    sizeLabel = new TextWidget("firma-escala", ""d);
    sizeLabel.minWidth = 48;
    sizeLabel.alignment = Align.Center;
    sizeGroup.addChild(sizeLabel);
    auto larger = new Button("firma-mayor", "+"d);
    larger.tooltipText = tip("signpanel_signature_larger");
    larger.click = (Widget source) {
      pages.scaleSignature(steppedSignatureScale(signScale, 1));
      return true;
    };
    sizeGroup.addChild(larger);
    topBar.addChild(sizeGroup);
    updateSizeLabel();
    addChild(topBar);

    pages = new PageView("paginas");
    pages.layoutWidth = FILL_PARENT;
    pages.layoutHeight = FILL_PARENT;
    pages.setZoom(zoomAt(zoomBox.selectedItemIndex));
    pages.onSignatureResized = (float scale) {
      signScale = scale;
      updateSizeLabel();
      // Una apariencia que se estaba dibujando con la escala anterior ya no sirve.
      previewGeneration++;
      scheduleSignaturePreview();
    };
    pages.onSignatureMoved = (SignaturePlacement placement) {
      positionButton.text = format("X: %d - Y: %d", cast(int) placement.x, cast(int) placement.y).toUTF32;
      if (pageIndexFor(pageSelector.value, pages.pageCount) != placement.page) {
        pageSelector.set(placement.page + 1, false);
      }
    };
    addChild(pages);

    bottomBar = new VerticalLayout("barra-inferior");
    bottomBar.layoutWidth = FILL_PARENT;
    bottomBar.padding = Rect(4, 4, 4, 4);
    auto mainRow = new HorizontalLayout;
    mainRow.layoutWidth = FILL_PARENT;
    fieldsColumn = new TableLayout("campos");
    fieldsColumn.colCount = 2;
    fieldsColumn.layoutWidth = FILL_PARENT;
    reasonField = addField("razon", "signpanel_reason", "signpanel_reason_tooltip", settings.reason);
    locationField = addField("lugar", "signpanel_place", "signpanel_place_tooltip", settings.place);
    contactField = addField("contacto", "signpanel_contact", "signpanel_contact_tooltip", settings.contact);
    mainRow.addChild(fieldsColumn);
    auto signRow = new HorizontalLayout;
    signRow.margins = Rect(12, 0, 0, 0);
    cancelButton = makeButton("rechazar", "signpanel_cancel_btn", "signpanel_cancel_tooltip", () {
      confirmCancel();
      return true;
    });
    signButton = makeButton("firmar", "signpanel_sign_btn", "signpanel_sign_tooltip", () {
      requestSign();
      return true;
    });
    signButton.fontWeight = 800;
    signButton.minWidth = 140;
    collapseButton = makeButton("plegar", "signpanel_collapse_footer", "signpanel_collapse_footer", () {
      applyFooterState(!footerCollapsed);
      return true;
    });
    signRow.addChild(cancelButton);
    signRow.addChild(signButton);
    signRow.addChild(collapseButton);
    mainRow.addChild(signRow);
    bottomBar.addChild(mainRow);

    secondaryActions = new HorizontalLayout("acciones");
    secondaryActions.margins = Rect(0, 4, 0, 0);
    withoutVisible = new CheckBox("sin-firma-visible", dt("signpanel_visible_checkbox"));
    withoutVisible.tooltipText = tip("signpanel_visible_checkbox_tooltip");
    withoutVisible.checked = settings.withoutVisibleSign;
    withoutVisible.checkChange = (Widget source, bool checked) {
      pages.showSignature(!checked);
      return true;
    };
    secondaryActions.addChild(withoutVisible);
    formatGroup = new HorizontalLayout("formato");
    formatGroup.addChild(new TextWidget(null, dt("signpanel_formato_ades")));
    cadesButton = new RadioButton("cades", "CAdES"d);
    xadesButton = new RadioButton("xades", "XAdES"d);
    jadesButton = new RadioButton("jades", "JAdES"d);
    asicButton = new RadioButton("asic", "ASiC-E"d);
    foreach (button; [cadesButton, xadesButton, jadesButton, asicButton]) formatGroup.addChild(button);
    formatGroup.margins = Rect(12, 0, 0, 0);
    secondaryActions.addChild(formatGroup);
    validateButton = makeButton("ver-firmas", "signpanel_validate_btn", "signpanel_validate_tooltip", () {
      if (current !is null) host.showDocumentReport(current);
      return true;
    });
    advancedButton = makeButton("avanzadas", "signpanel_advanced_options_btn", "signpanel_advanced_options_tooltip",
      () { showAdvancedOptions(); return true; });
    saveButton = makeButton("guardar-configuracion", "signpanel_save_btn", "signpanel_save_tooltip", () {
      if (current is null) return true;
      current.setSettings(collectSettings());
      host.showMessage(t("signpanel_dialog_save_configuration"));
      return true;
    });
    foreach (button; [validateButton, advancedButton, saveButton]) {
      button.margins = Rect(8, 0, 0, 0);
      secondaryActions.addChild(button);
    }
    bottomBar.addChild(secondaryActions);
    addChild(bottomBar);

    foreach (field; [reasonField, locationField, contactField]) {
      field.contentChange = (EditableContent content) { scheduleSignaturePreview(); };
    }
    hideControls();
  }

  private EditLine addField(string id, string labelKey, string tooltipKey, string value) {
    fieldsColumn.addChild(new TextWidget(null, dt(labelKey)));
    auto field = new EditLine(id, value.toUTF32);
    field.tooltipText = tip(tooltipKey);
    field.layoutWidth = FILL_PARENT;
    field.minWidth = 240;
    fieldsColumn.addChild(field);
    return field;
  }

  /// Documento que se está mostrando (null si ninguno).
  Document document() @safe {
    return current;
  }

  /// La vista de páginas, para detener su hilo al cerrar.
  PageView pageView() @safe {
    return pages;
  }

  // Visibilidad de los controles ---------------------------------------------

  private void hideControls() {
    signButton.enabled = false;
    foreach (widget; [cast(Widget) topBar, sizeGroup, fieldsColumn, withoutVisible, formatGroup, validateButton,
        advancedButton, saveButton, collapseButton, cancelButton]) {
      widget.visibility = Visibility.Gone;
    }
  }

  private void showPreviewControls() {
    topBar.visibility = Visibility.Visible;
    advancedButton.visibility = Visibility.Visible;
    collapseButton.visibility = Visibility.Visible;
    bool simplified = currentSettings().isSimplifiedMode();
    validateButton.visibility = simplified ? Visibility.Gone : Visibility.Visible;
    refreshSignatureCount();
  }

  private void showPdfControls() {
    showPreviewControls();
    // Los documentos virtuales los firma su servicio, que no recibe la escala.
    sizeGroup.visibility = current.isVirtual ? Visibility.Gone : Visibility.Visible;
    withoutVisible.visibility = Visibility.Visible;
    fieldsColumn.visibility = Visibility.Visible;
    saveButton.visibility = currentSettings().isSimplifiedMode() ? Visibility.Gone : Visibility.Visible;
    signButton.enabled = true;
  }

  private void showOtherFormatControls() {
    bool simplified = currentSettings().isSimplifiedMode();
    formatGroup.visibility = Visibility.Visible;
    advancedButton.visibility = Visibility.Visible;
    collapseButton.visibility = Visibility.Visible;
    saveButton.visibility = simplified ? Visibility.Gone : Visibility.Visible;
    validateButton.visibility = simplified ? Visibility.Gone : Visibility.Visible;
    signButton.enabled = true;
    auto signer = current.signer;
    cadesButton.visibility = Visibility.Visible;
    xadesButton.visibility = cast(XadesSigner) signer ? Visibility.Visible : Visibility.Gone;
    jadesButton.visibility = cast(JadesSigner) signer ? Visibility.Visible : Visibility.Gone;
    asicButton.visibility = Visibility.Visible;
    if (cast(CadesSigner) signer) cadesButton.checked = true;
    else if (cast(XadesSigner) signer) xadesButton.checked = true;
    else if (cast(JadesSigner) signer) jadesButton.checked = true;
    else asicButton.checked = true;
    refreshSignatureCount();
  }

  private void applyFooterState(bool collapsed) {
    footerCollapsed = collapsed;
    collapseButton.text = dt(collapsed ? "signpanel_expand_footer" : "signpanel_collapse_footer");
    collapseButton.tooltipText = tip(collapsed ? "signpanel_expand_footer" : "signpanel_collapse_footer");
    secondaryActions.visibility = collapsed ? Visibility.Gone : Visibility.Visible;
    if (current !is null && isPdf(current.mimeType)) {
      fieldsColumn.visibility = collapsed ? Visibility.Gone : Visibility.Visible;
    }
  }

  /// Pone la cantidad de firmas en el botón «Ver firmas» y lo deshabilita si no hay.
  void refreshSignatureCount() @trusted {
    size_t count = current is null ? 0 : current.signatureCount;
    validateButton.text = format(t("signpanel_validate_btn"), count).toUTF32;
    validateButton.enabled = count > 0;
    validateButton.tooltipText = tip(count > 0 ? "signpanel_validate_tooltip" : "signpanel_validate_tooltip_empty");
  }

  // Documento -----------------------------------------------------------------

  /**
   * Muestra un documento: su vista previa (las páginas de un documento virtual las trae
   * el servicio) y los controles que le corresponden.
   */
  void setDocument(Document document) @trusted {
    current = document;
    levelOverride = null;
    hideControls();
    PageSource source;
    if (document.isVirtual) {
      source = new ImageSource(document.pages, (int page) @safe => host.virtualPage(document, page));
    } else {
      source = new PreviewerSource(document.preview);
    }
    pages.setSource(source);
    signScale = document.settings.signScale;
    updateSizeLabel();
    int pageCount = pages.pageCount;
    pageSelector.setPages(pageCount);
    int configured = currentSettings().pageNumber;
    pageSelector.set(configured != 0 && configured <= pageCount && configured >= -pageCount ? configured : 1, false);
    auto settings = currentSettings();
    pages.moveSignature(pageIndexFor(pageSelector.value, pageCount),
      settings.signXf.isNull ? settings.signX : settings.signXf.get,
      settings.signYf.isNull ? settings.signY : settings.signYf.get);
    if (isPdf(document.mimeType)) {
      showPdfControls();
    } else if (isOpenXml(document.mimeType) || isOpenDocument(document.mimeType)) {
      showPreviewControls();
      signButton.enabled = true;
      saveButton.visibility = Visibility.Visible;
    } else {
      showOtherFormatControls();
    }
    cancelButton.visibility = document.isRemote && !document.isVirtual ? Visibility.Visible : Visibility.Gone;
    applyFooterState(footerCollapsed);
    pages.showSignature(!withoutVisible.checked);
    scheduleSignaturePreview();
    pages.scrollToPage(pageIndexFor(pageSelector.value, pageCount));
  }

  /// Vacía la pestaña (clean).
  void clean() @trusted {
    current = null;
    previewGeneration++;
    pages.setSource(null);
    pages.setSignatureImage(null, 0, 0);
    hideControls();
  }

  /// Vuelve a leer la configuración (updateConfig).
  void updateConfig() @trusted {
    auto settings = currentSettings();
    withoutVisible.checked = settings.withoutVisibleSign;
    reasonField.text = settings.reason.toUTF32;
    locationField.text = settings.place.toUTF32;
    contactField.text = settings.contact.toUTF32;
    rotationBox.selectedItemIndex = indexIn(rotationValues, settings.signRotation);
    zoomBox.selectedItemIndex = zoomIndexFor(settings.previewZoom);
    pages.setZoom(zoomAt(zoomBox.selectedItemIndex));
    if (current !is null) {
      pageSelector.set(settings.pageNumber, false);
      pages.moveSignature(pageIndexFor(pageSelector.value, pages.pageCount), settings.signX, settings.signY);
      scheduleSignaturePreview();
    }
  }

  // Ajustes con que se firma -------------------------------------------------

  /**
   * Ajustes del documento con lo que muestra la pestaña (getCurrentSettings): los datos,
   * la posición exacta del recuadro, la página, la rotación, la firma visible, el formato
   * y el nivel elegido en las opciones avanzadas.
   */
  Settings collectSettings() @trusted {
    auto base = currentSettings();
    auto collected = new Settings(base);
    collected.reason = reasonField.text.toUTF8.strip.replace("\t", " ");
    collected.place = locationField.text.toUTF8.strip.replace("\t", " ");
    collected.contact = contactField.text.toUTF8.strip.replace("\t", " ");
    string launchImage = launchProperty(signatureImageProperty);
    collected.image = launchImage !is null ? launchImage : base.image;
    auto placement = pages.signaturePlacement;
    auto offset = pages.cropOffset(placement.page);
    collected.signXf = placement.x + offset[0];
    collected.signYf = placement.y + offset[1];
    collected.signX = cast(int) collected.signXf.get;
    collected.signY = cast(int) collected.signYf.get;
    collected.signRotation = valueAt(rotationValues, rotationBox.selectedItemIndex);
    collected.pageNumber = pageSelector.value;
    collected.signScale = signScale;
    collected.hideSignatureAdvice = launchFlag(hideSignatureAdviceProperty);
    collected.isVisibleSignature = !withoutVisible.checked;
    bool otherFormat = formatGroup.visibility == Visibility.Visible;
    collected.signASiC = otherFormat && asicButton.checked;
    collected.forceCades = current !is null && otherFormat && !asicButton.checked
      && (current.mimeType == SupportedMimeType.BINARY || isOpenDocument(current.mimeType))
      && (cadesButton.checked || xadesButton.checked || jadesButton.checked);
    if (levelOverride !is null && current !is null) levelFor(collected, current.mimeType) = levelOverride;
    return collected;
  }

  /// Firmar: pide dónde guardar (salvo documentos remotos y virtuales) y encola la firma.
  private void requestSign() {
    if (current is null) return;
    auto document = current;
    auto settings = collectSettings();
    document.setSettings(settings);
    if (document.isRemote || document.isVirtual) {
      host.signDocument(document);
      return;
    }
    // Cancelar el diálogo cancela la firma.
    chooseSignedOutput(window, document, settings, () { host.signDocument(document); });
  }

  private void confirmCancel() {
    if (current is null || !current.isRemote) return;
    showConfirmDialog(window, t("signpanel_cancel_btn"), t("signpanel_cancel_confirm"), (bool accepted) {
      if (accepted) host.cancelRemoteDocument();
    });
  }

  /// Opciones avanzadas: el nivel de la firma de este documento (T, LT o LTA).
  private void showAdvancedOptions() {
    auto settings = currentSettings();
    string currentLevel = levelOverride;
    if (currentLevel is null && current !is null) currentLevel = levelFor(settings, current.mimeType);
    auto dialog = new FirmadorDialog(t("signpanel_advanced_options_btn"), window);
    auto row = new HorizontalLayout;
    row.addChild(new TextWidget(null, dt("signpanel_level_ades")));
    RadioButton[] levels;
    foreach (level; ["T", "LT", "LTA"]) {
      auto button = new RadioButton(null, level.toUTF32);
      button.checked = level == currentLevel;
      button.margins = Rect(8, 0, 0, 0);
      levels ~= button;
      row.addChild(button);
    }
    dialog.addChild(row);
    auto close = dialogAction(StandardAction.Close, "signpanel_advanced_options_close_btn");
    dialog.addButtons([close], 0, close);
    dialog.open((const Action result) {
      foreach (index, button; levels) if (button.checked) levelOverride = ["T", "LT", "LTA"][index];
    });
  }

  /// Ubicación rápida del recuadro en nueve posiciones de la página.
  private void showPositionDialog() {
    if (current is null) return;
    auto dialog = new FirmadorDialog(t("signpanel_sign_position"), window);
    auto grid = new TableLayout;
    grid.colCount = 3;
    immutable string[] keys = ["signpanel_sign_topleft", "signpanel_sign_topcenter", "signpanel_sign_topright",
      "signpanel_sign_centerleft", "signpanel_sign_centercenter", "signpanel_sign_centerright",
      "signpanel_sign_bottomleft", "signpanel_sign_bottomcenter", "signpanel_sign_bottomright"];
    foreach (index, key; keys) grid.addChild(placementButton(dialog, key, (index % 3) * 0.5f, (index / 3) * 0.5f));
    dialog.addChild(grid);
    auto close = dialogAction(StandardAction.Cancel, "dialog_cancel");
    dialog.addButtons([close], 0, close);
    dialog.open((const Action result) {});
  }

  /// Botón de una posición (función aparte: los cierres de un bucle comparten sus variables).
  private Button placementButton(FirmadorDialog dialog, string key, float ratioX, float ratioY) {
    auto button = new Button(null, dt(key));
    button.minWidth = 150;
    button.minHeight = 60;
    button.click = (Widget source) {
      pages.placeSignatureAt(ratioX, ratioY, 10);
      dialog.close(null);
      return true;
    };
    return button;
  }

  // Vista previa de la firma ---------------------------------------------------

  /// Credenciales conectadas (lo avisa el monitor de tarjetas).
  void cardsChanged(const(CardSignInfo)[] detected) @trusted {
    keepingPreviewCard({
      cards = detected;
      size_t identities;
      foreach (card; detected) if (hasIdentity(card)) identities++;
      if (identities > 1 && !askingPreferredCard) {
        askingPreferredCard = true;
        askPreferredCard();
      }
    });
  }

  /// Hace `change` y rehace la vista previa si cambió la credencial que se muestra en ella.
  private void keepingPreviewCard(scope void delegate() change) {
    string before = identityText(previewCard(cards, preferredCardKey));
    change();
    if (identityText(previewCard(cards, preferredCardKey)) != before) scheduleSignaturePreview();
  }

  private static string identityText(const CardSignInfo card) @safe {
    return card is null ? "" : card.commonName ~ "|" ~ card.organization ~ "|" ~ card.identification;
  }

  /// Pregunta cuál de varias credenciales se anuncia en el recuadro (sólo la vista previa).
  private void askPreferredCard() {
    const(CardSignInfo)[] identities;
    foreach (card; cards) if (hasIdentity(card)) identities ~= card;
    auto dialog = new FirmadorDialog(t("signpanel_default_card_title"), window);
    dialog.addChild(new TextWidget(null, dt("signpanel_default_card_prompt")));
    auto combo = new ComboBox("credencial", identities.map!(card => card.displayInfo.toUTF32).array);
    auto chosen = identities.countUntil!(card => identityKey(card) == preferredCardKey);
    combo.selectedItemIndex = chosen < 0 ? 0 : cast(int) chosen;
    dialog.addChild(combo);
    dialog.addOkCancel();
    dialog.open((const Action result) {
      askingPreferredCard = false;
      keepingPreviewCard({
        preferredCardKey = result !is null && result.id == StandardAction.Ok && combo.selectedItemIndex >= 0
          ? identityKey(identities[combo.selectedItemIndex]) : null;
      });
    });
  }

  /// Rehace el recuadro poco después del último cambio (escribir en los campos, escala…).
  private void scheduleSignaturePreview() {
    if (previewTimer != 0) cancelTimer(previewTimer);
    previewTimer = setTimer(300);
  }

  override bool onTimer(ulong id) {
    if (id != previewTimer) return super.onTimer(id);
    previewTimer = 0;
    refreshSignaturePreview();
    return false;
  }

  /// Muestra la escala de la firma en porcentaje.
  private void updateSizeLabel() {
    import std.math : round;
    sizeLabel.text = format("%d %%", cast(int) round(signScale * 100)).toUTF32;
  }

  /// Dibuja la apariencia de la firma en segundo plano y la pone en el recuadro.
  private void refreshSignaturePreview() {
    if (current is null || !isPdf(current.mimeType) || current.isVirtual) {
      pages.setSignatureImage(null, 0, 0);
      return;
    }
    auto appSettings = currentSettings();
    auto documentSettings = collectSettings();
    auto card = previewCard(cards, preferredCardKey);
    string text = signatureTextFor(card is null ? t("signpanel_name_person") : card.commonName,
      card is null ? t("signpanel_type_person") : card.organization,
      card is null ? "XXX-XXXXXXXXXXXX" : card.identification, documentSettings, appSettings, Clock.currTime);
    int page = pages.signaturePlacement.page;
    PageGeometry geometry = pages.pageGeometry(page);
    float scale = pages.currentScale;
    int generation = ++previewGeneration;
    // Si falla (por ejemplo, la imagen de la firma no se puede leer) se avisa: la firma fallaría igual.
    runInBackground("No se pudo dibujar la vista previa de la firma", {
      auto image = loadSignatureImage(documentSettings.image);
      auto visible = visibleSignatureFor(appSettings, documentSettings, text, image, geometry);
      auto preview = renderSignaturePreview(visible, geometry, scale);
      auto buffer = drawBufFromRaster(preview.raster);
      runOnUi(() {
        if (generation != previewGeneration) return;
        pages.setSignatureImage(buffer, preview.widthPoints, preview.heightPoints, documentSettings.signScale);
        pages.showSignature(!withoutVisible.checked);
      });
    });
  }
}

@("should step the signature scale to the next multiple even when the corner drag left it in between")
unittest {
  import std.math : isClose;
  assert(isClose(steppedSignatureScale(1, 1), 1.1) && isClose(steppedSignatureScale(1, -1), 0.9));
  assert(isClose(steppedSignatureScale(1.37, 1), 1.4) && isClose(steppedSignatureScale(1.37, -1), 1.3));
  assert(isClose(steppedSignatureScale(1.1f, 1), 1.2));
}

@("should announce the only identity or the chosen one when several credentials are connected")
unittest {
  import firmador.cards.cardinfo : CertificateSubject;
  auto first = new CardSignInfo(CardType.pkcs11, CertificateSubject("CPF-01"), "A", 0, null);
  auto second = new CardSignInfo(CardType.pkcs11, CertificateSubject("CPF-02"), "B", 1, null);
  auto unregistered = new CardSignInfo("/tmp/almacen.p12", "almacen.p12");
  assert(previewCard([first, unregistered], null) is first);
  assert(previewCard([first, second], null) is null);
  assert(previewCard([first, second], "CPF-02") is second);
  assert(previewCard([first, second], "CPF-09") is null);
}
