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
 * Avisos breves de la ventana (NotificationBar) y el contenedor que los hace flotar sobre
 * el contenido sin ocupar espacio (NotificationOverlay); los usa firmador.gui.desktop.window.
 */
module firmador.gui.desktop.notificationbar;

import std.algorithm : min;

import dlangui.core.events;
import dlangui.core.types;
import dlangui.graphics.drawbuf : DrawBuf;
import dlangui.widgets.layouts;
import dlangui.widgets.widget;

import firmador.gui.desktop.richtext : RichText;
import firmador.gui.guiinterface : NotificationType;

/**
 * Aviso breve (showNotification) que flota al pie de la ventana dentro de un
 * NotificationOverlay. Se oculta solo a los cinco segundos o al hacerle clic.
 */
final class NotificationBar : VerticalLayout {
  private RichText message;
  private ulong hideTimer;
  private uint frameColor;

  this() @trusted {
    super("avisos");
    padding = Rect(14, 8, 14, 8);
    message = new RichText("aviso");
    message.fontWeight = 800;
    message.alignment = Align.Center;
    addChild(message);
    visibility = Visibility.Gone;
  }

  /// Muestra el aviso con el color de su tipo; se oculta solo a los cinco segundos.
  void show(string html, NotificationType type) @trusted {
    uint background, foreground;
    final switch (type) {
      case NotificationType.success: background = 0xD4EDDA; foreground = 0x155724; break;
      case NotificationType.error: background = 0xF8D7DA; foreground = 0x721C24; break;
      case NotificationType.warning: background = 0xFFF3CD; foreground = 0x856404; break;
      case NotificationType.info: background = 0xD9EDF7; foreground = 0x0C5460; break;
    }
    backgroundColor = background;
    frameColor = foreground;
    message.textColor = foreground;
    message.setHtml(html);
    visibility = Visibility.Visible;
    if (hideTimer != 0) cancelTimer(hideTimer);
    hideTimer = setTimer(5000);
  }

  private void hide() {
    if (hideTimer != 0) cancelTimer(hideTimer);
    hideTimer = 0;
    visibility = Visibility.Gone;
  }

  override bool onTimer(ulong id) {
    if (id != hideTimer) return super.onTimer(id);
    hideTimer = 0;
    visibility = Visibility.Gone;
    return false;
  }

  /// Un clic lo cierra; el resto de la ventana sigue recibiendo los suyos.
  override bool onMouseEvent(MouseEvent event) {
    if (event.action == MouseAction.ButtonDown && event.button == MouseButton.Left) {
      hide();
      return true;
    }
    return super.onMouseEvent(event);
  }

  override void onDraw(DrawBuf buf) {
    if (visibility != Visibility.Visible) return;
    super.onDraw(buf);
    buf.drawFrame(_pos, frameColor, Rect(1, 1, 1, 1));
  }
}

/**
 * Contenido de la ventana con un NotificationBar que flota sobre su borde inferior: el
 * contenido ocupa siempre todo el espacio, así que mostrar u ocultar el aviso no cambia
 * el tamaño de nada. El aviso va primero entre los hijos para recibir antes los clics
 * sobre él (dlangui los reparte en orden), pero se dibuja al final, encima.
 */
final class NotificationOverlay : WidgetGroup {
  /// Ancho máximo del aviso, como fracción del de la ventana.
  private enum float maxWidthFraction = 0.7f;
  /// Separación del aviso con el borde inferior, en píxeles.
  private enum int bottomGap = 16;
  private Widget content;
  private NotificationBar bar;

  this(Widget content, NotificationBar bar) @trusted {
    super("contenedor");
    this.content = content;
    this.bar = bar;
    fillParent();
    addChild(bar);
    addChild(content);
  }

  override void measure(int parentWidth, int parentHeight) {
    content.measure(parentWidth, parentHeight);
    if (bar.visibility != Visibility.Gone) bar.measure(barWidthLimit(parentWidth), parentHeight);
    measuredContent(parentWidth, parentHeight, content.measuredWidth, content.measuredHeight);
  }

  override void layout(Rect rc) {
    _needLayout = false;
    if (visibility == Visibility.Gone) return;
    _pos = rc;
    content.layout(rc);
    if (bar.visibility == Visibility.Gone) return;
    bar.measure(barWidthLimit(rc.width), rc.height);
    int width = min(bar.measuredWidth, barWidthLimit(rc.width));
    int height = min(bar.measuredHeight, rc.height);
    int left = rc.left + (rc.width - width) / 2;
    int bottom = rc.bottom - min(bottomGap, rc.height - height);
    bar.layout(Rect(left, bottom - height, left + width, bottom));
  }

  override void onDraw(DrawBuf buf) {
    if (visibility != Visibility.Visible) return;
    super.onDraw(buf);
    content.onDraw(buf);
    bar.onDraw(buf);
  }

  private static int barWidthLimit(int width) pure {
    return width == SIZE_UNSPECIFIED ? width : cast(int) (width * maxWidthFraction);
  }
}
