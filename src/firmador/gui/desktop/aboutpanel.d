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

/// Pestaña «Acerca de» (AboutLayout): el logo, la versión y el enlace al sitio del proyecto.
module firmador.gui.desktop.aboutpanel;

import std.format : format;
import std.logger : error;

import dlangui.core.types;
import dlangui.widgets.controls;
import dlangui.widgets.layouts;
import dlangui.widgets.widget;

import firmador.configuration : baseUrl, firmadorVersion;
import firmador.gui.desktop.common;
import firmador.gui.desktop.dialogs : imageDrawable;
import firmador.gui.desktop.richtext : RichText;
import firmador.gui.desktop.window : DesktopInterface;
import firmador.i18n : t;
import firmador.settingsmanager : currentSettings;
import firmador.util.desktop : openUrl;

/// Pestaña «Acerca de».
final class AboutPanel : VerticalLayout {
  this(DesktopInterface host) @trusted {
    super("acerca-de");
    layoutWidth = FILL_PARENT;
    layoutHeight = FILL_PARENT;
    padding = Rect(24, 24, 24, 24);
    auto logo = new ImageWidget("logo");
    logo.drawable = imageDrawable(cast(immutable(ubyte)[]) import("firmador.png"), 128);
    logo.alignment = Align.Center;
    logo.layoutWidth = FILL_PARENT;
    addChild(logo);
    auto description = new RichText("descripcion", format(t("about_description_label"), firmadorVersion));
    description.alignment = Align.Center;
    description.layoutWidth = FILL_PARENT;
    description.margins = Rect(0, 16, 0, 16);
    addChild(description);
    auto website = makeButton("sitio-web", "about_website_link", "about_website_link_accesible", () {
      try {
        openUrl(baseUrl, currentSettings().preferredBrowser);
      } catch (Exception exception) {
        error(t("about_log_openurl"), ": ", exception.msg);
        host.showError(exception);
      }
      return true;
    });
    website.alignment = Align.Center;
    addChild(website);
  }
}
