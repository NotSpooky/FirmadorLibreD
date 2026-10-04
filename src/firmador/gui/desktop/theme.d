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
 * Tema de la ventana: aplica resources/theme/theme_firmador.xml (claro) o
 * theme_firmador_dark.xml según el ajuste themeMode y, con «system», el modo del sistema
 * (registro de Windows, portal de freedesktop en Linux, defaults en macOS). Los dos temas
 * heredan de los de dlangui y definen los colores propios (ThemeColor) que usan los controles
 * que dibujan por su cuenta; al compilar se comprueba que ambos archivos los definan. El tamaño
 * de la letra no está en los temas: sale del ajuste uiFontSize (applyUiFontSize).
 */
module firmador.gui.desktop.theme;

import std.algorithm : canFind;
import std.exception : enforce;
import std.format : format;
import std.logger : info, warning;
import std.traits : EnumMembers;
import std.typecons : Nullable;

/// Valores del ajuste themeMode, en el orden en que los muestra la configuración.
immutable string[] themeModes = ["system", "light", "dark"];

/// Variante del tema de la ventana.
enum ThemeVariant {
  light,
  dark,
}

/// Colores propios de los temas (<color id> de resources/theme/theme_firmador*.xml).
enum ThemeColor : string {
  accent = "firmador_accent",
  mutedText = "firmador_muted_text",
  successText = "firmador_success_text",
  errorText = "firmador_error_text",
  row = "firmador_row",
  rowSelected = "firmador_row_selected",
  pageArea = "firmador_page_area",
  pageBorder = "firmador_page_border",
  pageShadow = "firmador_page_shadow",
  signatureFrame = "firmador_signature_frame",
  successBackground = "firmador_success_background",
  successForeground = "firmador_success_foreground",
  errorBackground = "firmador_error_background",
  errorForeground = "firmador_error_foreground",
  warningBackground = "firmador_warning_background",
  warningForeground = "firmador_warning_foreground",
  infoBackground = "firmador_info_background",
  infoForeground = "firmador_info_foreground",
}

/// Archivos de resources/theme que se incorporan al ejecutable (por nombre, como los de dlangui).
private enum string[] themeResourceFiles = [
  "theme_firmador.xml", "theme_firmador_dark.xml",
  "firmador_button.xml", "firmador_button_dark.xml",
  "firmador_button_primary.xml", "firmador_button_primary_dark.xml",
  "firmador_button_link.xml", "firmador_button_link_dark.xml",
  "firmador_edit.xml", "firmador_edit_dark.xml",
  "firmador_tab.xml", "firmador_tab_dark.xml",
  "firmador_scroll_thumb.xml", "firmador_scroll_thumb_dark.xml",
];

static foreach (file; ["theme_firmador.xml", "theme_firmador_dark.xml"]) {
  static foreach (color; EnumMembers!ThemeColor) {
    static assert(import(file).canFind(`<color id="` ~ color ~ `"`),
      "resources/theme/" ~ file ~ " no define el color " ~ color ~ " de ThemeColor");
  }
}

/**
 * Variante del tema para el ajuste.
 *
 * Params:
 *   mode = themeMode: «light», «dark» o «system» (cualquier otro valor se toma como «system»).
 *   systemDark = si el sistema prefiere el modo oscuro; nulo si no se pudo saber.
 * Returns: la variante; con «system» y preferencia desconocida, la clara.
 */
ThemeVariant themeVariant(string mode, Nullable!bool systemDark) pure nothrow @safe @nogc {
  if (mode == "light") return ThemeVariant.light;
  if (mode == "dark") return ThemeVariant.dark;
  return !systemDark.isNull && systemDark.get ? ThemeVariant.dark : ThemeVariant.light;
}

/// Recurso de dlangui del tema (sin extensión).
string themeResourceId(ThemeVariant variant) pure nothrow @safe @nogc {
  final switch (variant) {
    case ThemeVariant.light: return "theme_firmador";
    case ThemeVariant.dark: return "theme_firmador_dark";
  }
}

/**
 * Preferencia del portal de freedesktop (org.freedesktop.appearance color-scheme): 1 es
 * oscuro, 2 claro y 0 (u otro valor) sin preferencia.
 */
Nullable!bool darkFromColorScheme(uint colorScheme) pure nothrow @safe @nogc {
  if (colorScheme == 1) return Nullable!bool(true);
  if (colorScheme == 2) return Nullable!bool(false);
  return Nullable!bool.init;
}

/**
 * Incorpora los recursos del tema y aplica el que corresponde a `mode` (themeMode), con la
 * letra de `fontPoints` (uiFontSize). Va antes de crear la primera ventana: los colores de
 * ThemeColor se leen al construir los controles.
 *
 * Throws: Exception si dlangui no pudo cargar el tema (cae en su tema por omisión sin avisar)
 *   o el tamaño de la letra está fuera de los límites de configuration.d.
 */
void applyTheme(string mode, int fontPoints) @trusted {
  import dlangui.graphics.resources : embeddedResourceList, embedResources;
  import dlangui.platforms.common.platform : Platform;
  import dlangui.widgets.styles : currentTheme;
  embeddedResourceList.addResources(embedResources!themeResourceFiles());
  if (!themeModes.canFind(mode)) warning("Modo de apariencia desconocido «", mode, "»: se usa el del sistema");
  string id = themeResourceId(themeVariant(mode, mode == "light" || mode == "dark" ? Nullable!bool.init
    : systemPrefersDark()));
  info("Tema de la ventana: ", id, " (modo «", mode, "»)");
  Platform.instance.uiTheme = id;
  enforce(currentTheme !is null && currentTheme.id == id, "dlangui no pudo cargar el tema " ~ id
    ~ " de resources/theme");
  applyUiFontSize(fontPoints);
}

/**
 * Cambia la letra del tema vigente a `points` puntos, que dlangui escala a los DPI de la
 * pantalla. Los estilos que no fijan su tamaño lo heredan; los controles ya creados lo toman
 * con Window.dispatchThemeChanged (firmador.gui.desktop.window).
 *
 * Throws: Exception si `points` está fuera de minUiFontSize..maxUiFontSize (configuration.d).
 */
void applyUiFontSize(int points) @trusted {
  import dlangui.core.types : makePointSize;
  import dlangui.widgets.styles : currentTheme;
  import firmador.configuration : maxUiFontSize, minUiFontSize;
  enforce(points >= minUiFontSize && points <= maxUiFontSize, format(
    "El tamaño de la letra de la ventana (%d) debe estar entre %d y %d puntos", points, minUiFontSize, maxUiFontSize));
  enforce(currentTheme !is null, "No hay un tema de dlangui al que cambiarle la letra");
  currentTheme.fontSize = makePointSize(points);
  // Cada estilo guarda su fuente: se vacían todas para que tomen el tamaño nuevo.
  currentTheme.onThemeChanged();
  info("Letra de la ventana: ", points, " pt");
}

/// Color propio del tema aplicado (applyTheme).
uint themeColor(ThemeColor color) @trusted {
  import dlangui.widgets.styles : currentTheme;
  return currentTheme.customColor(color);
}

/// El sistema prefiere el modo oscuro; nulo si no se puede saber (sin portal, Windows antiguo…).
private Nullable!bool systemPrefersDark() @trusted {
  version (Windows) {
    import std.windows.registry : Registry, RegistryException;
    try {
      auto key = Registry.currentUser.getKey(`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`);
      return Nullable!bool(key.getValue("AppsUseLightTheme").value_DWORD == 0);
    } catch (RegistryException exception) {
      info("Windows no indica el modo de apariencia (AppsUseLightTheme): ", exception.msg);
      return Nullable!bool.init;
    }
  } else version (OSX) {
    import std.process : execute;
    import std.string : strip;
    // Sin la clave (modo claro) defaults termina con error.
    auto result = execute(["defaults", "read", "-g", "AppleInterfaceStyle"]);
    return Nullable!bool(result.status == 0 && result.output.strip == "Dark");
  } else version (linux) {
    return portalPrefersDark();
  } else {
    return Nullable!bool.init;
  }
}

version (linux) {
  /**
   * Lee color-scheme del portal de freedesktop por D-Bus (gio, que ya se enlaza por
   * libsecret: src/c/csecret.c). Usa ReadOne y, en portales anteriores a la versión 2, Read,
   * que devuelve el valor dentro de otra variante.
   */
  private Nullable!bool portalPrefersDark() @trusted {
    import csecret;
    import std.string : fromStringz, toStringz;
    GError* failure;
    GDBusConnection* bus = g_bus_get_sync(G_BUS_TYPE_SESSION, null, &failure);
    if (bus is null) {
      info("Sin bus de sesión para leer el modo de apariencia: ", failure is null ? "" : failure.message.fromStringz);
      if (failure !is null) g_error_free(failure);
      return Nullable!bool.init;
    }
    scope (exit) g_object_unref(bus);
    GVariant* reply;
    foreach (method; ["ReadOne", "Read"]) {
      reply = g_dbus_connection_call_sync(bus, "org.freedesktop.portal.Desktop", "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Settings", method.toStringz,
        g_variant_new("(ss)", "org.freedesktop.appearance".ptr, "color-scheme".ptr), null,
        G_DBUS_CALL_FLAGS_NONE, 1000, null, &failure);
      if (reply !is null) break;
      info("El portal no respondió a ", method, " del modo de apariencia: ", failure.message.fromStringz);
      g_error_free(failure);
      failure = null;
    }
    if (reply is null) return Nullable!bool.init;
    scope (exit) g_variant_unref(reply);
    GVariant* boxed = g_variant_get_child_value(reply, 0);
    GVariant* value = g_variant_get_variant(boxed);
    g_variant_unref(boxed);
    if (g_variant_get_type_string(value).fromStringz == "v") {
      GVariant* inner = g_variant_get_variant(value);
      g_variant_unref(value);
      value = inner;
    }
    scope (exit) g_variant_unref(value);
    if (g_variant_get_type_string(value).fromStringz != "u") {
      warning("El portal devolvió color-scheme con un tipo inesperado: ", g_variant_get_type_string(value).fromStringz);
      return Nullable!bool.init;
    }
    return darkFromColorScheme(g_variant_get_uint32(value));
  }
}

@("should follow the system only when the mode is system or unknown")
unittest {
  auto dark = Nullable!bool(true);
  auto light = Nullable!bool(false);
  assert(themeVariant("light", dark) == ThemeVariant.light);
  assert(themeVariant("dark", light) == ThemeVariant.dark);
  assert(themeVariant("system", dark) == ThemeVariant.dark);
  assert(themeVariant("system", light) == ThemeVariant.light);
  assert(themeVariant("system", Nullable!bool.init) == ThemeVariant.light);
  assert(themeVariant("otro", dark) == ThemeVariant.dark);
}

@("should map the portal color scheme to dark, light or no preference")
unittest {
  assert(darkFromColorScheme(1).get);
  assert(!darkFromColorScheme(2).get);
  assert(darkFromColorScheme(0).isNull);
  assert(darkFromColorScheme(7).isNull);
}
