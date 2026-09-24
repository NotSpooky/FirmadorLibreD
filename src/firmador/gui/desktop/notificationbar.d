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

/// Avisos breves de la ventana (NotificationBar, que usa firmador.gui.desktop.window).
module firmador.gui.desktop.notificationbar;

import dlangui.core.types;
import dlangui.widgets.layouts;
import dlangui.widgets.widget;

import firmador.gui.desktop.richtext : RichText;
import firmador.gui.guiinterface : NotificationType;

/// Barra de avisos breves al pie de la ventana (showNotification).
final class NotificationBar : VerticalLayout {
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
