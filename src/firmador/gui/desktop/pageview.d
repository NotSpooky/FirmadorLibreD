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
 * Vista previa continua de un documento con el recuadro de la firma visible (la vista de
 * páginas de SignPanel en la versión Java). Las páginas se apilan con la escala elegida
 * (ancho automático, página completa o un porcentaje) y se dibujan en un hilo aparte sólo
 * cuando se ven, con una caché acotada. El recuadro de la firma se arrastra con el ratón,
 * se coloca con doble clic y se mueve con las flechas (Mayús: de 10 en 10 puntos).
 *
 * Las posiciones del recuadro son puntos «visuales» desde la esquina superior izquierda
 * de la página tal como se ve, como las espera la firma visible (firmador.pdf.sigpreview).
 */
module firmador.gui.desktop.pageview;

import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import core.thread : Thread;
import std.algorithm : max, min, remove, countUntil;
import std.conv : to;
import std.logger : error, trace, warning;
import std.math : round;

import dlangui.core.events;
import dlangui.core.types;
import dlangui.graphics.drawbuf;
import dlangui.graphics.images : loadImage;
import dlangui.widgets.scroll;
import dlangui.widgets.scrollbar;
import dlangui.widgets.widget;

import firmador.gui.desktop.uithread : runOnUi;
import firmador.pdf.engine : PageGeometry, PageRaster, PdfRect;
import firmador.pdf.sigpreview : visualRect, visualSize;
import firmador.previewers.previewer : Previewer;

/// Porcentajes fijos del selector de escala (ZOOM_FIXED_PERCENTS).
immutable int[] zoomPercents = [50, 75, 100, 200, 300, 400];

/// Modo de escala de la vista.
enum ZoomMode { autoWidth, fullPage, fixed }

/// Escala elegida.
struct Zoom {
  ZoomMode mode = ZoomMode.autoWidth;
  /// Factor de los modos fijos (1 = 100 %).
  float factor = 1;
}

/// Valores que guarda la configuración, en el orden del selector (zoomValues).
string[] zoomSettingValues() pure @safe {
  string[] values = ["AUTO_WIDTH", "FULL_PAGE"];
  foreach (percent; zoomPercents) values ~= percent.to!string;
  return values;
}

/// Posición en el selector del valor guardado; 0 (ancho automático) si no se reconoce.
int zoomIndexFor(string value) pure @safe {
  auto index = zoomSettingValues().countUntil(value);
  return index < 0 ? 0 : cast(int) index;
}

/// Escala de la posición del selector.
Zoom zoomAt(int index) pure nothrow @safe {
  if (index <= 0) return Zoom(ZoomMode.autoWidth);
  if (index == 1) return Zoom(ZoomMode.fullPage);
  return Zoom(ZoomMode.fixed, zoomPercents[min(index - 2, cast(int) zoomPercents.length - 1)] / 100f);
}

/// Margen alrededor de las páginas y separación entre ellas, en píxeles.
enum int pagePadding = 8;
enum int pageGap = 12;

/// Distancia mínima del recuadro a los bordes, para que el rectángulo final no salga de la página.
enum float edgeSafetyMarginPoints = 2;

/**
 * Píxeles por punto: el ancho de la página más ancha en el ancho visible, la página más
 * alta en el alto visible, o el porcentaje fijo (100 % es un punto por píxel de 96 ppp).
 */
float effectiveScale(Zoom zoom, float widestPoints, float tallestPoints, int viewportWidth, int viewportHeight,
    float pixelsPerPoint) pure nothrow @safe {
  final switch (zoom.mode) {
    case ZoomMode.fixed:
      return zoom.factor * pixelsPerPoint;
    case ZoomMode.autoWidth:
      if (widestPoints <= 0 || viewportWidth <= 2 * pagePadding) return pixelsPerPoint;
      return (viewportWidth - 2 * pagePadding) / widestPoints;
    case ZoomMode.fullPage:
      if (tallestPoints <= 0 || viewportHeight <= 2 * pagePadding) return pixelsPerPoint;
      float byHeight = (viewportHeight - 2 * pagePadding) / tallestPoints;
      float byWidth = widestPoints > 0 && viewportWidth > 2 * pagePadding
        ? (viewportWidth - 2 * pagePadding) / widestPoints : byHeight;
      return min(byHeight, byWidth);
  }
}

/**
 * Posición del recuadro limitada a la página: dentro de sus bordes con el margen de
 * seguridad. Devuelve [x, y] en puntos.
 */
float[2] clampToPage(float x, float y, float boxWidth, float boxHeight, float pageWidth, float pageHeight)
    pure nothrow @safe @nogc {
  float maxX = pageWidth - boxWidth - edgeSafetyMarginPoints;
  float maxY = pageHeight - boxHeight - edgeSafetyMarginPoints;
  return [max(0f, min(x, maxX)), max(0f, min(y, maxY))];
}

/// Páginas que muestra la vista.
interface PageSource {
  int pageCount() @safe;
  /// Geometría de la página, para ubicar la firma y saber su tamaño.
  PageGeometry geometry(int index) @safe;
  /// Página dibujada a la escala dada (se llama desde un hilo aparte).
  ColorDrawBuf render(int index, float scale) @safe;
  /// Admite ubicar una firma visible (PDF).
  bool placesSignature() @safe;
}

/// Geometría de una carta, para las páginas que todavía no se conocen.
PageGeometry letterGeometry() pure nothrow @safe @nogc {
  PageGeometry geometry;
  geometry.mediaBox = PdfRect(0, 0, 612, 792);
  geometry.cropBox = geometry.mediaBox;
  return geometry;
}

/// Imagen de dlangui de una página rasterizada (con transparencia si la trae).
ColorDrawBuf drawBufFromRaster(const PageRaster raster) @trusted {
  auto buffer = new ColorDrawBuf(raster.width, raster.height);
  foreach (row; 0 .. raster.height) {
    uint* line = buffer.scanLine(row);
    foreach (column; 0 .. raster.width) {
      size_t pixel = cast(size_t) row * raster.width + column;
      uint alpha = raster.alpha.length ? 255 - raster.alpha[pixel] : 0;
      line[column] = (alpha << 24) | (raster.rgb[pixel * 3] << 16) | (raster.rgb[pixel * 3 + 1] << 8)
        | raster.rgb[pixel * 3 + 2];
    }
  }
  return buffer;
}

/// Páginas de un documento local, dibujadas por su vista previa (mupdf).
final class PreviewerSource : PageSource {
  private Previewer previewer;

  this(Previewer previewer) @safe {
    this.previewer = previewer;
  }

  int pageCount() @safe {
    return previewer.pageCount();
  }

  PageGeometry geometry(int index) @safe {
    return previewer.pageGeometry(index);
  }

  ColorDrawBuf render(int index, float scale) @safe {
    return drawBufFromRaster(previewer.renderPage(index, scale));
  }

  bool placesSignature() @safe {
    return previewer.showsSignaturePosition();
  }
}

/// Páginas de un documento virtual: imágenes que entrega el servicio.
final class ImageSource : PageSource {
  private int pages;
  private immutable(ubyte)[] delegate(int page) @safe fetch;

  /// `fetch` trae la imagen de la página (desde 1) o null si no se pudo.
  this(int pages, immutable(ubyte)[] delegate(int page) @safe fetch) @safe {
    this.pages = pages;
    this.fetch = fetch;
  }

  int pageCount() @safe {
    return pages;
  }

  PageGeometry geometry(int index) @safe {
    return letterGeometry();
  }

  ColorDrawBuf render(int index, float scale) @trusted {
    auto bytes = fetch(index + 1);
    if (bytes.length == 0) return null;
    ColorDrawBuf decoded;
    try {
      decoded = loadImage(bytes, "pagina");
    } catch (Exception exception) {
      warning("No se pudo leer la imagen de la página ", index + 1, ": ", exception.msg);
      return null;
    }
    if (decoded is null) return null;
    // La imagen se ajusta al ancho que tendría una carta a esta escala.
    int width = max(1, cast(int) (612 * scale));
    int height = max(1, cast(int) (width * cast(float) decoded.height / decoded.width));
    auto scaled = new ColorDrawBuf(width, height);
    scaled.drawRescaled(Rect(0, 0, width, height), decoded, Rect(0, 0, decoded.width, decoded.height));
    return scaled;
  }

  bool placesSignature() @safe {
    return false;
  }
}

/// Posición del recuadro de firma.
struct SignaturePlacement {
  int page;
  /// Esquina superior izquierda en puntos visuales de la página.
  float x = 0;
  float y = 0;
}

/// Vista continua de las páginas con el recuadro de firma.
final class PageView : ScrollWidgetBase {
  /// Cambió la posición del recuadro (arrastre, doble clic, teclado).
  void delegate(SignaturePlacement placement) onSignatureMoved;
  /// Cambió la página que ocupa el centro de la vista.
  void delegate(int page) onCurrentPage;

  private PageSource source;
  private float[2][] pageSizes;
  private PageGeometry[] geometries;
  private int[] pageTops;
  private Zoom zoom;
  private float scale = 1;
  private int contentWidth, contentHeight;
  private ColorDrawBuf[int] cache;
  /// Escala con que se dibujó cada página de la caché.
  private float[int] cacheScale;
  /// Páginas pedidas al hilo de dibujo y la escala pedida.
  private float[int] pending;
  private int[] cacheOrder;
  private enum int cacheLimit = 12;
  private int generation;
  private int reportedPage = -1;

  private ColorDrawBuf signatureImage;
  private float signatureWidth = 0, signatureHeight = 0;
  private bool signatureShown;
  private SignaturePlacement placement;
  private bool dragging;

  private Mutex renderLock;
  private Condition renderWakeup;
  private int[] renderQueue;
  private int renderGeneration;
  private float renderScale;
  private PageSource renderSource;
  private bool renderStopping;

  this(string ID = null) @trusted {
    super(ID, ScrollBarMode.Auto, ScrollBarMode.Auto);
    focusable = true;
    backgroundColor = 0xE0E0E0;
    renderLock = new Mutex;
    renderWakeup = new Condition(renderLock);
    auto worker = new Thread(&renderLoop);
    worker.isDaemon = true;
    worker.start();
  }

  /// Muestra otro documento (null lo vacía).
  void setSource(PageSource newSource) @trusted {
    source = newSource;
    pageSizes = null;
    geometries = null;
    if (source !is null) {
      foreach (index; 0 .. source.pageCount()) {
        PageGeometry geometry;
        try {
          geometry = source.geometry(index);
        } catch (Exception exception) {
          warning("No se pudo leer la geometría de la página ", index + 1, ": ", exception.msg);
          geometry = letterGeometry();
        }
        geometries ~= geometry;
        pageSizes ~= visualSize(geometry.cropBox, geometry.rotation);
      }
    }
    placement = SignaturePlacement(0, placement.x, placement.y);
    reportedPage = -1;
    _visibleScrollableArea.left = 0;
    _visibleScrollableArea.top = 0;
    discardRenders();
    requestLayout();
  }

  int pageCount() const @safe {
    return cast(int) pageSizes.length;
  }

  /// Geometría de una página del documento.
  PageGeometry pageGeometry(int page) const @safe {
    return page >= 0 && page < geometries.length ? geometries[page] : letterGeometry();
  }

  /// Cambia la escala.
  void setZoom(Zoom newZoom) @trusted {
    zoom = newZoom;
    requestLayout();
  }

  /// Píxeles por punto con que se dibuja ahora.
  float currentScale() const @safe {
    return scale;
  }

  /**
   * Cambia la imagen del recuadro (la apariencia dibujada a `currentScale`) y su tamaño en
   * puntos; null oculta el recuadro.
   */
  void setSignatureImage(ColorDrawBuf image, float widthPoints, float heightPoints) @trusted {
    if (signatureImage !is image) release(signatureImage);
    signatureImage = image;
    signatureWidth = widthPoints;
    signatureHeight = heightPoints;
    signatureShown = image !is null && source !is null && source.placesSignature();
    if (signatureShown) moveSignature(placement.page, placement.x, placement.y);
    invalidate();
  }

  /// Oculta o muestra el recuadro (firma no visible, documentos sin PDF).
  void showSignature(bool shown) @trusted {
    signatureShown = shown && signatureImage !is null && source !is null && source.placesSignature();
    invalidate();
  }

  SignaturePlacement signaturePlacement() const @safe {
    return placement;
  }

  /// Offset del recorte visible dentro de la MediaBox (la firma se ubica respecto a la MediaBox).
  float[2] cropOffset(int page) const @safe {
    auto geometry = pageGeometry(page);
    auto crop = visualRect(geometry.cropBox, geometry.mediaBox, geometry.rotation);
    return [crop.left, crop.top];
  }

  /// Mueve el recuadro a esa página y posición (puntos), dentro de los bordes.
  void moveSignature(int page, float x, float y) @trusted {
    if (pageSizes.length == 0) return;
    page = max(0, min(page, cast(int) pageSizes.length - 1));
    auto clamped = clampToPage(x, y, signatureWidth, signatureHeight, pageSizes[page][0], pageSizes[page][1]);
    placement = SignaturePlacement(page, clamped[0], clamped[1]);
    if (onSignatureMoved !is null) onSignatureMoved(placement);
    invalidate();
  }

  /// Coloca el recuadro en una fracción de la página (posiciones del diálogo de ubicación).
  void placeSignatureAt(float ratioX, float ratioY, float paddingPoints) @trusted {
    if (pageSizes.length == 0) return;
    auto size = pageSizes[placement.page];
    float maxX = size[0] - signatureWidth - paddingPoints;
    float maxY = size[1] - signatureHeight - paddingPoints;
    moveSignature(placement.page, max(paddingPoints, maxX * ratioX), max(paddingPoints, maxY * ratioY));
    scrollToPage(placement.page);
  }

  /// Desplaza la vista para mostrar la página.
  void scrollToPage(int page) @trusted {
    if (page < 0 || page >= pageTops.length) return;
    int target = pageTops[page] - pagePadding;
    int maxTop = max(0, contentHeight - _clientRect.height);
    int top = max(0, min(target, maxTop));
    _visibleScrollableArea.bottom += top - _visibleScrollableArea.top;
    _visibleScrollableArea.top = top;
    updateScrollBars();
    invalidate();
  }

  // Distribución --------------------------------------------------------------

  private void computeLayout() {
    float widest = 0, tallest = 0;
    foreach (size; pageSizes) {
      widest = max(widest, size[0]);
      tallest = max(tallest, size[1]);
    }
    float newScale = effectiveScale(zoom, widest, tallest, _clientRect.width, _clientRect.height, SCREEN_DPI / 96f);
    if (newScale != scale) {
      // Las páginas ya dibujadas se siguen mostrando reescaladas hasta que llegue la nueva
      // versión: una escala pasajera (el primer cálculo antes de la barra de desplazamiento)
      // no debe dejar la vista en blanco.
      scale = newScale;
      invalidate();
    }
    pageTops = null;
    int y = pagePadding;
    contentWidth = 0;
    foreach (size; pageSizes) {
      pageTops ~= y;
      y += cast(int) round(size[1] * scale) + pageGap;
      contentWidth = max(contentWidth, cast(int) round(size[0] * scale) + 2 * pagePadding);
    }
    contentHeight = pageSizes.length ? y - pageGap + pagePadding : 0;
  }

  override Point fullContentSize() {
    _fullScrollableArea = Rect(0, 0, contentWidth, contentHeight);
    return Point(contentWidth, contentHeight);
  }

  override protected void handleClientRectLayout(ref Rect rc) {
    super.handleClientRectLayout(rc);
    _clientRect = rc;
    computeLayout();
  }

  override protected void updateScrollBars() {
    fullContentSize();
    _visibleScrollableArea.right = _visibleScrollableArea.left + _clientRect.width;
    _visibleScrollableArea.bottom = _visibleScrollableArea.top + _clientRect.height;
    int extraX = max(0, min(_visibleScrollableArea.left, _visibleScrollableArea.right - _fullScrollableArea.right));
    int extraY = max(0, min(_visibleScrollableArea.top, _visibleScrollableArea.bottom - _fullScrollableArea.bottom));
    _visibleScrollableArea.offset(-extraX, -extraY);
    super.updateScrollBars();
  }

  private void scrollBy(int dx, int dy) {
    int maxLeft = max(0, contentWidth - _clientRect.width);
    int maxTop = max(0, contentHeight - _clientRect.height);
    int left = max(0, min(_visibleScrollableArea.left + dx, maxLeft));
    int top = max(0, min(_visibleScrollableArea.top + dy, maxTop));
    _visibleScrollableArea = Rect(left, top, left + _clientRect.width, top + _clientRect.height);
    updateScrollBars();
    invalidate();
  }

  private bool handleScroll(ScrollEvent event, bool vertical) {
    int step = vertical ? 48 : 24;
    int page = vertical ? max(64, _clientRect.height - 32) : max(64, _clientRect.width - 32);
    int current = vertical ? _visibleScrollableArea.top : _visibleScrollableArea.left;
    int delta;
    switch (event.action) {
      case ScrollAction.LineUp: delta = -step; break;
      case ScrollAction.LineDown: delta = step; break;
      case ScrollAction.PageUp: delta = -page; break;
      case ScrollAction.PageDown: delta = page; break;
      case ScrollAction.SliderMoved: delta = event.position - current; break;
      default: return true;
    }
    if (vertical) scrollBy(0, delta);
    else scrollBy(delta, 0);
    return true;
  }

  override bool onVScroll(ScrollEvent event) {
    return handleScroll(event, true);
  }

  override bool onHScroll(ScrollEvent event) {
    return handleScroll(event, false);
  }

  /// Rectángulo de la página en coordenadas de la ventana.
  private Rect pageRect(int page) {
    int width = cast(int) round(pageSizes[page][0] * scale);
    int height = cast(int) round(pageSizes[page][1] * scale);
    int left = _clientRect.left + max(pagePadding, (max(contentWidth, _clientRect.width) - width) / 2)
      - _visibleScrollableArea.left;
    int top = _clientRect.top + pageTops[page] - _visibleScrollableArea.top;
    return Rect(left, top, left + width, top + height);
  }

  /// Página bajo una coordenada vertical de la ventana (la más cercana).
  private int pageAt(int y) {
    int best = 0;
    foreach (page; 0 .. cast(int) pageTops.length) {
      if (pageRect(page).top <= y) best = page;
    }
    return best;
  }

  // Dibujo ------------------------------------------------------------------

  override protected void drawClient(DrawBuf buf) {
    if (source is null) return;
    int[] wanted;
    foreach (page; 0 .. cast(int) pageSizes.length) {
      Rect rc = pageRect(page);
      // Se dibujan las visibles y se piden también las de una pantalla antes y después.
      bool near = rc.bottom >= _clientRect.top - _clientRect.height && rc.top <= _clientRect.bottom + _clientRect.height;
      if (!near) continue;
      if (auto image = page in cache) {
        buf.drawRescaled(rc, *image, Rect(0, 0, image.width, image.height));
      } else {
        buf.fillRect(rc, 0xFFFFFF);
      }
      bool current = (page in cacheScale) !is null && cacheScale[page] == scale;
      bool requested = (page in pending) !is null && pending[page] == scale;
      if (!current && !requested) wanted ~= page;
      buf.drawFrame(rc, 0xBEBEBE, Rect(1, 1, 1, 1), 0xFFFFFFFF);
    }
    if (wanted.length) requestRenders(wanted);
    if (signatureShown && placement.page < pageSizes.length) {
      Rect page = pageRect(placement.page);
      int left = page.left + cast(int) round(placement.x * scale);
      int top = page.top + cast(int) round(placement.y * scale);
      int width = cast(int) round(signatureWidth * scale);
      int height = cast(int) round(signatureHeight * scale);
      Rect box = Rect(left, top, left + width, top + height);
      buf.drawRescaled(box, signatureImage, Rect(0, 0, signatureImage.width, signatureImage.height));
      buf.drawFrame(box, focused ? 0x1A57B8 : 0x646464, Rect(1, 1, 1, 1), 0xFFFFFFFF);
    }
    reportCurrentPage();
  }

  private void reportCurrentPage() {
    if (pageTops.length == 0) return;
    int page = pageAt(_clientRect.top + _clientRect.height / 2);
    if (page == reportedPage) return;
    reportedPage = page;
    if (onCurrentPage !is null) onCurrentPage(page);
  }

  // Ratón y teclado ---------------------------------------------------------

  private bool insideSignature(int x, int y) {
    if (!signatureShown) return false;
    Rect page = pageRect(placement.page);
    int left = page.left + cast(int) round(placement.x * scale);
    int top = page.top + cast(int) round(placement.y * scale);
    return x >= left && y >= top && x < left + cast(int) round(signatureWidth * scale)
      && y < top + cast(int) round(signatureHeight * scale);
  }

  /// Centra el recuadro en el punto de la ventana, cambiando de página si hace falta.
  private void placeSignatureAtPoint(int x, int y) {
    int page = pageAt(y);
    Rect rc = pageRect(page);
    moveSignature(page, (x - rc.left) / scale - signatureWidth / 2, (y - rc.top) / scale - signatureHeight / 2);
  }

  override uint getCursorType(int x, int y) {
    return insideSignature(x, y) ? CursorType.SizeAll : CursorType.Arrow;
  }

  override bool onMouseEvent(MouseEvent event) {
    if (event.action == MouseAction.Wheel) return super.onMouseEvent(event);
    bool inClient = event.x >= _clientRect.left && event.x < _clientRect.right && event.y >= _clientRect.top
      && event.y < _clientRect.bottom;
    if (event.action == MouseAction.ButtonDown && event.button == MouseButton.Left && inClient) {
      setFocus();
      if (event.doubleClick && signatureShown) {
        placeSignatureAtPoint(event.x, event.y);
        return true;
      }
      if (insideSignature(event.x, event.y)) {
        dragging = true;
        return true;
      }
    }
    if (event.action == MouseAction.Move && dragging && (event.flags & MouseFlag.LButton)) {
      placeSignatureAtPoint(event.x, event.y);
      return true;
    }
    if ((event.action == MouseAction.ButtonUp || event.action == MouseAction.Cancel) && dragging) {
      dragging = false;
      return true;
    }
    return super.onMouseEvent(event);
  }

  override bool onKeyEvent(KeyEvent event) {
    if (event.action != KeyAction.KeyDown) return super.onKeyEvent(event);
    float step = (event.flags & KeyFlag.Shift) ? 10 : 1;
    switch (event.keyCode) {
      case KeyCode.LEFT: if (!signatureShown) break; moveSignature(placement.page, placement.x - step, placement.y); return true;
      case KeyCode.RIGHT: if (!signatureShown) break; moveSignature(placement.page, placement.x + step, placement.y); return true;
      case KeyCode.UP: if (!signatureShown) break; moveSignature(placement.page, placement.x, placement.y - step); return true;
      case KeyCode.DOWN: if (!signatureShown) break; moveSignature(placement.page, placement.x, placement.y + step); return true;
      case KeyCode.PAGEUP: scrollBy(0, -max(64, _clientRect.height - 32)); return true;
      case KeyCode.PAGEDOWN: scrollBy(0, max(64, _clientRect.height - 32)); return true;
      default: break;
    }
    return super.onKeyEvent(event);
  }

  // Dibujo en segundo plano ------------------------------------------------

  /// Olvida las páginas dibujadas (otro documento).
  private void discardRenders() {
    foreach (image; cache) release(image);
    cache = null;
    cacheScale = null;
    pending = null;
    cacheOrder = null;
    generation++;
    synchronized (renderLock) {
      renderQueue = null;
      renderGeneration = generation;
      renderScale = scale;
      renderSource = source;
    }
    invalidate();
  }

  private void requestRenders(int[] pages) {
    foreach (page; pages) pending[page] = scale;
    synchronized (renderLock) {
      renderGeneration = generation;
      renderScale = scale;
      renderSource = source;
      // Las que se ven van primero; las pedidas antes y ya no visibles se descartan.
      renderQueue = pages.dup;
      renderWakeup.notifyAll();
    }
  }

  private void renderLoop() {
    while (true) {
      int page, requestGeneration;
      float requestScale;
      PageSource requestSource;
      synchronized (renderLock) {
        while (renderQueue.length == 0 && !renderStopping) renderWakeup.wait();
        if (renderStopping) return;
        page = renderQueue[0];
        renderQueue = renderQueue[1 .. $];
        requestGeneration = renderGeneration;
        requestScale = renderScale;
        requestSource = renderSource;
      }
      if (requestSource is null) continue;
      ColorDrawBuf image;
      try {
        image = requestSource.render(page, requestScale);
      } catch (Exception exception) {
        error("No se pudo dibujar la página ", page + 1, ": ", exception.msg);
      }
      deliverRender(page, requestGeneration, requestScale, image);
    }
  }

  /**
   * Pasa una página dibujada al hilo de la ventana. Va en su propia función: los cierres
   * creados dentro de un bucle comparten sus variables en D, y la vuelta siguiente las
   * cambiaría antes de que la ventana las use.
   */
  private void deliverRender(int page, int requestGeneration, float renderedScale, ColorDrawBuf image) {
    runOnUi(() {
      if (requestGeneration != generation) return release(image);
      // Si falló queda como pedida, para no reintentarla sin fin hasta que cambie la escala.
      if (image is null) return;
      if ((page in pending) !is null && pending[page] == renderedScale) pending.remove(page);
      // Una versión de otra escala no reemplaza a la de la escala vigente.
      if ((page in cacheScale) !is null && cacheScale[page] == scale && renderedScale != scale) return release(image);
      if (auto previous = page in cache) release(*previous);
      cache[page] = image;
      cacheScale[page] = renderedScale;
      cacheOrder = cacheOrder.remove!(cached => cached == page) ~ page;
      while (cacheOrder.length > cacheLimit) {
        release(cache[cacheOrder[0]]);
        cache.remove(cacheOrder[0]);
        cacheScale.remove(cacheOrder[0]);
        cacheOrder = cacheOrder[1 .. $];
      }
      invalidate();
    });
  }

  /// Detiene el hilo de dibujo y libera las imágenes (al cerrar la ventana).
  void stopRendering() @trusted {
    synchronized (renderLock) {
      renderStopping = true;
      renderWakeup.notifyAll();
    }
    discardRenders();
    release(signatureImage);
    signatureImage = null;
  }

  /**
   * Libera una imagen que sólo guarda esta vista. No son recursos de dlangui (que los
   * libera con sus widgets): si quedaran para el recolector, se liberarían después de que
   * dlangui se cierra al salir.
   */
  private static void release(ColorDrawBuf image) {
    if (image !is null) destroy(image);
  }
}

@("should fit the widest page or the tallest page depending on the zoom mode")
unittest {
  assert(effectiveScale(Zoom(ZoomMode.autoWidth), 612, 792, 628, 400, 1.3) == 1);
  assert(effectiveScale(Zoom(ZoomMode.fullPage), 612, 792, 2000, 808, 1.3) == 1);
  assert(effectiveScale(Zoom(ZoomMode.fullPage), 612, 792, 322, 2000, 1.3) == 0.5);
  assert(effectiveScale(Zoom(ZoomMode.fixed, 2), 612, 792, 10, 10, 1.25) == 2.5);
  assert(zoomAt(zoomIndexFor("200")) == Zoom(ZoomMode.fixed, 2));
  assert(zoomAt(zoomIndexFor("desconocido")).mode == ZoomMode.autoWidth);
  assert(zoomSettingValues()[1] == "FULL_PAGE");
}

@("should keep the signature box inside the page margins when clamping its position")
unittest {
  assert(clampToPage(-5, 10, 100, 30, 612, 792) == [0f, 10f]);
  assert(clampToPage(600, 790, 100, 30, 612, 792) == [510f, 760f]);
}
