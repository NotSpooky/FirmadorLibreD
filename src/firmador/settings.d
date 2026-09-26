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
 * Ajustes del usuario (Settings en la versión Java) y su conversión, sin E/S, a y desde
 * las entradas de config.properties y de las configuraciones por documento. Los nombres
 * de campo son los de la versión Java porque viajan en JSON (@contract settings-json, ver
 * firmador.settingsjson) y las claves de config.properties se conservan para seguir
 * leyendo la configuración existente. La lectura y escritura de archivos está en
 * firmador.settingsmanager.
 */
module firmador.settings;

import std.algorithm : canFind, filter, map, startsWith;
import std.array : array, join, split;
import std.conv : to, ConvException;
import std.exception : enforce;
import std.format : format;
import std.logger : error;
import std.string : strip;
import std.typecons : Nullable;
import std.uni : icmp;

import firmador.configuration : defaultRemotePort, remotePortRange, dummyPluginName, checkUpdatePluginName,
  documentSignLogsPluginName;
import firmador.i18n : t, translate;

/// Nivel de firma AdES (baseline) que se aplica a cada formato.
enum SignatureLevel { b, t, lt, lta }

/// Posición del texto respecto de la imagen en la firma visible (SignerTextPosition de DSS).
enum SignerTextPosition { left, right, top, bottom }

/// Rotación de la firma visible (VisualSignatureRotation de DSS).
enum SignatureRotation { automatic, none, rotate90, rotate180, rotate270 }

/// Color con transparencia, como java.awt.Color.
struct Rgba {
  ubyte red, green, blue, alpha = 255;

}

/// Familia estándar PDF de la fuente de la firma visible (fuentes lógicas de Java).
enum FontFamily { sansSerif, serif, monospaced }

/// Estilo de la fuente de la firma visible.
struct FontStyle {
  bool bold;
  bool italic;
}

/**
 * Campos que el constructor de copia de Settings no copia, como el de la versión Java:
 * los oyentes, los orígenes autorizados, la posición exacta de la vista previa, la
 * contraseña del almacén y lo que es de la ejecución.
 */
private enum string[] notCopiedFields = ["signXf", "signYf", "registeredAllowedOrigins", "tempAllowedHosts",
  "noAuthorizedHosts", "extendDocument", "startFimadorRemote", "allowOriginPort", "keyPassword", "simplified_mode",
  "listeners"];

/// Receptor de cambios de configuración (ConfigListener).
alias ConfigListener = void delegate();

/// Nombre por omisión de la fuente de la firma visible (Font.SANS_SERIF en Java).
enum string defaultFontName = "SansSerif";

/// Texto con que la configuración marca un color transparente.
enum string transparentColorName = "transparente";

/**
 * Ajustes de firma y de la aplicación. Los campos públicos se llaman como en la versión
 * Java; los que allí eran @JsonIgnore se marcan en su documentación y no viajan en JSON.
 */
final class Settings {
  bool withoutVisibleSign = false;
  bool onlyimage = false;
  bool overwriteSourceFile = false;

  string reason = "";
  string place = "";
  string contact = "";
  string dateFormat = "dd/MM/yyyy hh:mm:ss a";
  string dateFormatEn = "MM/dd/yyyy hh:mm:ss a";
  string defaultSignMessage;
  int fontSize = 7;
  /// Tamaño de la imagen dentro de la firma; 0 deja el tamaño natural.
  int signImageWidth = 0;
  int signImageHeight = 0;
  /**
   * Fuente de la firma visible. Desde Firmador Remoto también puede ser
   * «base64:nombre:datos» o «file:nombre:ruta» con una fuente TrueType.
   */
  string font = defaultFontName;
  string fontColor = "#000000";
  string backgroundColor = transparentColorName;
  /// Biblioteca PKCS#11 adicional (no viaja en JSON).
  string extraPKCS11Lib = null;
  int signX = 198;
  int signY = 0;
  /// Posición exacta en puntos PDF que deja la previsualización (no viaja en JSON).
  Nullable!float signXf;
  Nullable!float signYf;
  /**
   * Escala de la firma visible de este documento, elegida en la vista previa: multiplica
   * fontSize y el tamaño de la imagen (1 = tal cual; límites en configuration.d). No
   * viaja en JSON.
   */
  float signScale = 1;
  /// Imagen de la firma: ruta, URI file: o, desde Firmador Remoto, data:image/png;base64,….
  string image = null;
  string fontAlignment = "RIGHT";
  string signRotation = "AUTOMATIC";
  /// Escala inicial de la previsualización: AUTO_WIDTH, FULL_PAGE o un porcentaje ("100").
  string previewZoom = "FULL_PAGE";
  bool showLogs = false;
  string advancedLogs = "WARNING";
  bool showTrayNotifications = false;

  int pageNumber = 1;
  /// Puerto que atiende Firmador Remoto en esta ejecución (no viaja en JSON ni se guarda).
  int portNumber = defaultRemotePort;
  string pAdESLevel = "LTA";
  string xAdESLevel = "LTA";
  string cAdESLevel = "LTA";
  string jAdESLevel = "LTA";
  string sofficePath = "";
  /// Almacenes PKCS#12 registrados (no viaja en JSON).
  string[] pKCS12File;

  /// Plugins activos y disponibles, por su nombre de clase Java (no viajan en JSON).
  string[] activePlugins;
  string[] availablePlugins;

  string registeredAllowedOrigins = "";
  string tempAllowedHosts = "";
  string noAuthorizedHosts = "";

  float pDFImgScaleFactor = 1;

  string language = "es";
  string country = "CR";
  string themeMode = "system";

  bool extendDocument = false;
  bool isVisibleSignature = false;
  bool hideSignatureAdvice = false;
  bool signASiC = false;
  bool forceCades = false;
  string startwindowstate = "NORMAL";
  int max_number_process_doc = 5;

  bool startFimadorRemote = false;

  /// Permite que el origin que lanza Firmador pida un puerto distinto del oficial.
  bool allowOriginPort = true;

  string preferredBrowser = "";

  /**
   * Contraseña del almacén de tokens de las conexiones. Nunca viaja en JSON: la versión
   * Java la enviaba al servicio remoto dentro de los ajustes, y es un secreto local.
   */
  string keyPassword = "";

  /// Modo simplificado; sin valor hasta que el usuario lo elige la primera vez.
  Nullable!bool simplified_mode;

  private ConfigListener[] listeners;

  /// Ajustes por omisión; el mensaje de firma sale del idioma por omisión (es_CR), como en Java.
  this() @safe {
    activePlugins = [dummyPluginName, checkUpdatePluginName];
    availablePlugins = [dummyPluginName, checkUpdatePluginName, documentSignLogsPluginName];
    defaultSignMessage = translate("configpanel_default_sign_message", language, country);
  }

  /**
   * Copia los ajustes de firma de otro, como el constructor de copia de Java: todos los
   * campos salvo los de notCopiedFields (oyentes, orígenes, posición exacta…); las listas
   * se copian para no compartirlas.
   */
  this(const Settings other) pure @safe {
    static foreach (index, field; Settings.tupleof) {{
      static if (!notCopiedFields.canFind(__traits(identifier, field))) {
        static if (is(typeof(field) == string[])) this.tupleof[index] = other.tupleof[index].dup;
        else this.tupleof[index] = other.tupleof[index];
      }
    }}
  }

  /**
   * Toma todos los valores de `other`, también los que el constructor de copia no copia
   * (contraseña del almacén, orígenes, modo…); conserva sus propios oyentes. Sirve para
   * cambiar una copia completa y aplicarla después de guardarla
   * (firmador.gui.desktop.configpanel).
   */
  void assign(const Settings other) pure @safe {
    static foreach (index, field; Settings.tupleof) {{
      static if (__traits(identifier, field) != "listeners") {
        static if (is(typeof(field) == string[])) this.tupleof[index] = other.tupleof[index].dup;
        else this.tupleof[index] = other.tupleof[index];
      }
    }}
  }

  /// Orígenes autorizados, permanentes y de esta sesión, sin repetidos.
  string[] getAllowedHosts() const pure @safe {
    return (splitHosts(tempAllowedHosts) ~ splitHosts(registeredAllowedOrigins)).uniqueInOrder;
  }

  /// Orígenes que pidieron acceso sin estar autorizados.
  string[] getNoAuthorizedHosts() const pure @safe {
    return splitHosts(noAuthorizedHosts);
  }

  /// Quita un origen de los permanentes o, si no estaba ahí, de los de esta sesión.
  void removeAllowedHost(string host) pure @safe {
    string wanted = host.strip;
    string[] registered = splitHosts(registeredAllowedOrigins);
    if (registered.canFind(wanted)) {
      registeredAllowedOrigins = registered.filter!(candidate => candidate != wanted).array.join("\n");
    } else {
      tempAllowedHosts = splitHosts(tempAllowedHosts).filter!(candidate => candidate != wanted).array.join("\n");
    }
  }

  void removeNoAuthorizedHost(string host) pure @safe {
    string wanted = host.strip;
    noAuthorizedHosts = splitHosts(noAuthorizedHosts).filter!(candidate => candidate != wanted).array.join("\n");
  }

  void addNoAuthorizedHost(string host) pure @safe {
    if (splitHosts(noAuthorizedHosts).canFind(host.strip)) return;
    noAuthorizedHosts = noAuthorizedHosts ~ "\n" ~ host;
  }

  void addTempAllowedHost(string host) pure @safe {
    tempAllowedHosts = tempAllowedHosts ~ "\n" ~ host;
  }

  void setRegisteredAllowedOrigins(const string[] origins) pure @safe {
    registeredAllowedOrigins = origins.join("\n");
  }

  /// Orígenes autorizados de forma permanente (los que se guardan en config.properties).
  string[] getRegisteredAllowedOrigins() const pure @safe {
    return splitHosts(registeredAllowedOrigins);
  }

  /// Autoriza un origen de forma permanente; los de esta sesión siguen siendo sólo de ella.
  void registerAllowedOrigin(string origin) pure @safe {
    string[] registered = splitHosts(registeredAllowedOrigins);
    if (!registered.canFind(origin.strip)) setRegisteredAllowedOrigins(registered ~ origin.strip);
  }

  /// Registra un oyente de cambios de configuración.
  void addListener(ConfigListener listener) pure @safe {
    listeners ~= listener;
  }

  /// Avisa a los oyentes que la configuración cambió.
  void updateConfig() {
    foreach (listener; listeners.dup) listener();
  }

  SignerTextPosition getFontAlignment() const pure @safe {
    switch (fontAlignment) {
      case "LEFT": return SignerTextPosition.left;
      case "BOTTOM": return SignerTextPosition.bottom;
      case "TOP": return SignerTextPosition.top;
      default: return SignerTextPosition.right;
    }
  }

  /// La firma visible lleva sólo la imagen, sin texto.
  bool isOnlyImageAlignment() const pure nothrow @safe @nogc {
    return fontAlignment == "ONLY IMAGE";
  }

  SignatureRotation getSignRotation() const pure @safe {
    return signatureRotationFor(signRotation);
  }

  /// Color del texto; si no se puede interpretar se registra el error y se usa negro.
  Rgba getFontColor() const @safe {
    return colorOrDefault(fontColor, Rgba(0, 0, 0, 255), "settings_error_decoding_font_color");
  }

  /// Color de fondo del texto; si no se puede interpretar se registra el error y queda transparente.
  Rgba getBackgroundColor() const @safe {
    return colorOrDefault(backgroundColor, Rgba(255, 255, 255, 0), "settings_error_decoding_background_color");
  }

  SignatureLevel getPAdESLevel() const pure @safe { return signatureLevelFor(pAdESLevel); }
  SignatureLevel getXAdESLevel() const pure @safe { return signatureLevelFor(xAdESLevel); }
  SignatureLevel getCAdESLevel() const pure @safe { return signatureLevelFor(cAdESLevel); }
  SignatureLevel getJAdESLevel() const pure @safe { return signatureLevelFor(jAdESLevel); }

  bool isSimplifiedMode() const pure nothrow @safe @nogc {
    return !simplified_mode.isNull && simplified_mode.get;
  }
}

/// Divide una lista de orígenes separada por saltos de línea, sin espacios ni vacíos.
string[] splitHosts(string hosts) pure @safe {
  return hosts.split("\n").map!(host => host.strip).filter!(host => host.length > 0).array;
}

private string[] uniqueInOrder(string[] values) pure @safe {
  string[] result;
  foreach (value; values) if (!result.canFind(value)) result ~= value;
  return result;
}

SignatureLevel signatureLevelFor(string level) pure @safe {
  switch (level) {
    case "B": return SignatureLevel.b;
    case "T": return SignatureLevel.t;
    case "LT": return SignatureLevel.lt;
    default: return SignatureLevel.lta;
  }
}

SignatureRotation signatureRotationFor(string rotation) pure @safe {
  switch (rotation) {
    case "NONE": return SignatureRotation.none;
    case "ROTATE_90": return SignatureRotation.rotate90;
    case "ROTATE_180": return SignatureRotation.rotate180;
    case "ROTATE_270": return SignatureRotation.rotate270;
    default: return SignatureRotation.automatic;
  }
}

/// Ángulo explícito de la rotación configurada (0 para AUTOMATIC y NONE).
int angleForRotation(string rotation) pure @safe {
  switch (rotation) {
    case "ROTATE_90": return 90;
    case "ROTATE_180": return 180;
    case "ROTATE_270": return 270;
    default: return 0;
  }
}

private immutable string[] fontFamilies = [
  "Arial", "Helvetica", "Nimbus Sans", "Nimbus Roman", "Times New Roman", "Courier New", "Nimbus Mono PS",
];

/// Familia PDF estándar para un nombre de fuente de la configuración (getFontName(…, true)).
FontFamily fontFamilyFor(string fontName) pure @safe {
  string family = displayFontNameFor(fontName);
  if (family == "Nimbus Roman" || family == "Times New Roman") return FontFamily.serif;
  if (family == "Courier New" || family == "Nimbus Mono PS") return FontFamily.monospaced;
  return FontFamily.sansSerif;
}

/// Nombre de familia de una fuente de la configuración («Arial Bold» → «Arial»); null si no es conocida.
string displayFontNameFor(string fontName) pure @safe {
  foreach (family; fontFamilies) {
    if (fontName.startsWith(family ~ " ")) {
      string style = fontName[family.length + 1 .. $];
      if (["Regular", "Italic", "Bold", "Bold Italic", "Oblique", "Bold Oblique"].canFind(style)) return family;
    }
  }
  return null;
}

/// Estilo de un nombre de fuente de la configuración («… Bold Italic», «… Oblique»…).
FontStyle fontStyleFor(string fontName) pure @safe {
  if (displayFontNameFor(fontName) is null) return FontStyle(false, false);
  import std.algorithm : endsWith;
  bool bold = fontName.endsWith(" Bold") || fontName.endsWith(" Bold Italic") || fontName.endsWith(" Bold Oblique");
  bool italic = fontName.endsWith(" Italic") || fontName.endsWith(" Oblique");
  return FontStyle(bold, italic);
}

/**
 * Interpreta un color como java.awt.Color.decode («#RRGGBB», «0xRRGGBB», decimal u octal
 * con 0 inicial) o la palabra «transparente».
 *
 * Throws: Exception con el texto recibido si no es un color.
 */
Rgba parseColor(string text) pure @safe {
  string value = text.strip;
  if (icmp(value, transparentColorName) == 0) return Rgba(255, 255, 255, 0);
  enforce(value.length > 0, "El color está vacío");
  bool negative = value[0] == '-';
  if (negative || value[0] == '+') value = value[1 .. $];
  uint radix = 10;
  if (value.startsWith("0x") || value.startsWith("0X")) {
    value = value[2 .. $];
    radix = 16;
  } else if (value.startsWith("#")) {
    value = value[1 .. $];
    radix = 16;
  } else if (value.startsWith("0") && value.length > 1) {
    value = value[1 .. $];
    radix = 8;
  }
  enforce(value.length > 0 && !negative, format("El color «%s» no es válido", text));
  uint number;
  try {
    number = value.to!uint(radix);
  } catch (ConvException) {
    throw new Exception(format("El color «%s» no es válido", text));
  }
  enforce(number <= 0xFFFFFF, format("El color «%s» está fuera del rango RGB", text));
  return Rgba(cast(ubyte) (number >> 16), cast(ubyte) (number >> 8), cast(ubyte) number, 255);
}

private Rgba colorOrDefault(string text, Rgba fallback, string errorKey) @safe {
  try {
    return parseColor(text);
  } catch (Exception exception) {
    error(t(errorKey), ": ", exception.msg);
    return fallback;
  }
}

/// Componentes de un origen de lanzamiento «url#puerto#minimizado» (processOrigin).
struct RemoteOrigin {
  string url = "http://localhost";
  int port = defaultRemotePort;
  bool minimized = false;
}

/// Separa un origen de lanzamiento; el puerto que no sea un número se cambia por `defaultPort`.
RemoteOrigin processOrigin(string origin, int defaultPort) pure @safe {
  RemoteOrigin result;
  result.port = defaultPort;
  if (origin is null) return result;
  string withoutProtocol = origin.startsWith("firmador:") ? origin["firmador:".length .. $] : origin;
  string[] parts = withoutProtocol.split("#");
  if (parts.length > 0) result.url = parts[0];
  if (parts.length > 1) {
    try {
      result.port = parts[1].to!int;
    } catch (ConvException) {
      result.port = defaultPort;
    }
  }
  if (parts.length > 2) result.minimized = icmp(parts[2], "true") == 0;
  return result;
}

/**
 * Puerto que debe atender Firmador Remoto para un origen: el oficial salvo que el ajuste
 * permita otro y el origen lo pida dentro del rango vecino. `outOfRange` indica que se
 * pidió uno fuera del rango.
 */
int resolveOriginPort(string origin, bool allowOriginPort, out bool outOfRange) pure @safe {
  outOfRange = false;
  if (!allowOriginPort) return defaultRemotePort;
  int port = processOrigin(origin, defaultRemotePort).port;
  int distance = port - defaultRemotePort;
  if (distance < 0) distance = -distance;
  if (distance > remotePortRange) {
    outOfRange = true;
    return defaultRemotePort;
  }
  return port;
}

/// Claves de config.properties que no son campos simples (ver settingsToProperties).
private enum string pluginsKey = "plugins";
private enum string pkcs12Key = "pkcs12file";

/// Lista de config.properties («a|b|c»); sin la clave devuelve `defaults`.
string[] listFromProperty(string data, bool present, const string[] defaults) pure @safe {
  if (!present && defaults.length > 0) return defaults.dup;
  if (data.length == 0) return [];
  return data.split("|").filter!(item => item.length > 0).array;
}

/// Decimal de config.properties, que la versión Java pudo escribir con coma decimal.
float floatFromProperty(string value, out bool valid) pure @safe {
  import std.array : replace;
  valid = true;
  try {
    return value.replace(",", ".").strip.to!float;
  } catch (ConvException) {
    valid = false;
    return 1;
  }
}

/**
 * Campos de config.properties que se leen y escriben tal cual (texto, entero o «true» /
 * «false»): el nombre del campo y su clave, las de la versión Java («singx» incluida). Los
 * demás tienen su propia conversión en applyProperties y settingsToProperties.
 */
private enum string[2][] propertyKeys = [
  ["withoutVisibleSign", "withoutvisiblesign"], ["showLogs", "showlogs"], ["overwriteSourceFile", "overwritesourcefile"],
  ["reason", "reason"], ["place", "place"], ["contact", "contact"], ["dateFormat", "dateformat"],
  ["defaultSignMessage", "defaultsignmessage"], ["pageNumber", "pagenumber"], ["fontSize", "fontsize"],
  ["font", "font"], ["fontColor", "fontcolor"], ["backgroundColor", "backgroundcolor"], ["signX", "singx"],
  ["signY", "singy"], ["fontAlignment", "fontalignment"], ["signRotation", "signrotation"],
  ["previewZoom", "previewzoom"], ["pAdESLevel", "padesLevel"], ["xAdESLevel", "xadesLevel"],
  ["cAdESLevel", "cadesLevel"], ["jAdESLevel", "jadesLevel"], ["sofficePath", "sofficePath"],
  ["language", "language"], ["country", "country"], ["startwindowstate", "startwindowstate"],
  ["themeMode", "themeMode"], ["showTrayNotifications", "showTrayNotifications"],
  ["max_number_process_doc", "max_number_process_doc"], ["signImageWidth", "signImageWidth"],
  ["signImageHeight", "signImageHeight"], ["startFimadorRemote", "startFimadorRemote"],
  ["allowOriginPort", "allowOriginPort"], ["preferredBrowser", "preferredBrowser"],
  ["registeredAllowedOrigins", "registeredAllowedOrigins"],
];

/**
 * Traslada config.properties a unos ajustes por omisión, con las mismas claves y valores
 * por omisión que SettingsManager.getSettings de la versión Java. La contraseña del
 * almacén de tokens no se toca aquí (ver firmador.settingsmanager).
 *
 * Returns: el texto de «pdfimgscalefactor» si no es un decimal válido (se usa 1), para que
 *   quien llama lo registre; null si es válido.
 * Throws: ConvException si un número entero no se puede leer, como parseInt en Java.
 */
string applyProperties(Settings conf, const string[string] props) pure @safe {
  string get(string key, string fallback) {
    if (auto value = key in props) return *value;
    return fallback;
  }
  bool getBool(string key, bool fallback) {
    return icmp(get(key, fallback ? "true" : "false"), "true") == 0;
  }
  int getInt(string key, int fallback) {
    return get(key, fallback.to!string).strip.to!int;
  }

  static foreach (entry; propertyKeys) {{
    alias Type = typeof(__traits(getMember, conf, entry[0]));
    static if (is(Type == bool)) {
      __traits(getMember, conf, entry[0]) = getBool(entry[1], __traits(getMember, conf, entry[0]));
    } else static if (is(Type == int)) {
      __traits(getMember, conf, entry[0]) = getInt(entry[1], __traits(getMember, conf, entry[0]));
    } else {
      __traits(getMember, conf, entry[0]) = get(entry[1], __traits(getMember, conf, entry[0]));
    }
  }}
  string advancedLogsRaw = get("advancedlogs", conf.advancedLogs);
  conf.advancedLogs = icmp(advancedLogsRaw, "true") == 0 ? "ALL"
    : icmp(advancedLogsRaw, "false") == 0 ? "INFO" : advancedLogsRaw;
  conf.image = "image" in props ? props["image"] : null;
  conf.extraPKCS11Lib = "extrapkcs11Lib" in props ? props["extrapkcs11Lib"] : null;
  conf.pKCS12File = listFromProperty(get(pkcs12Key, ""), (pkcs12Key in props) !is null, conf.pKCS12File);
  conf.activePlugins = listFromProperty(get(pluginsKey, ""), (pluginsKey in props) !is null, conf.activePlugins);
  bool validScale;
  string scaleText = get("pdfimgscalefactor", "1.00");
  conf.pDFImgScaleFactor = floatFromProperty(scaleText, validScale);
  if (auto simplified = "simplifiedMode" in props) {
    // La versión Java guardaba "null" antes de que se eligiera el modo.
    if (*simplified == "null") conf.simplified_mode.nullify();
    else conf.simplified_mode = icmp(*simplified, "true") == 0;
  } else {
    conf.simplified_mode.nullify();
  }
  return validScale ? null : scaleText;
}

/**
 * Entradas de config.properties para unos ajustes (setSettings en Java). Parte de las
 * existentes para no perder claves ajenas; `obfuscatedKeyPassword` es la contraseña del
 * almacén ya ofuscada, o null si vive en el llavero del sistema.
 */
string[string] settingsToProperties(const Settings conf, const string[string] existing, string obfuscatedKeyPassword)
    pure @safe {
  string[string] props;
  foreach (key, value; existing) props[key] = value;
  string boolText(bool value) { return value ? "true" : "false"; }
  static foreach (entry; propertyKeys) {{
    alias Type = typeof(__traits(getMember, Settings, entry[0]));
    auto value = __traits(getMember, conf, entry[0]);
    static if (is(Type == bool)) props[entry[1]] = boolText(value);
    else static if (is(Type == int)) props[entry[1]] = value.to!string;
    else props[entry[1]] = value;
  }}
  props["advancedlogs"] = conf.advancedLogs;
  props["pdfimgscalefactor"] = format("%.2f", conf.pDFImgScaleFactor);
  if (obfuscatedKeyPassword !is null) props["keyPassword"] = obfuscatedKeyPassword;
  else props.remove("keyPassword");
  props["simplifiedMode"] = conf.simplified_mode.isNull ? "null" : boolText(conf.simplified_mode.get);
  props[pluginsKey] = conf.activePlugins.join("|");
  if (conf.extraPKCS11Lib.length) props["extrapkcs11Lib"] = conf.extraPKCS11Lib;
  else props.remove("extrapkcs11Lib");
  props[pkcs12Key] = conf.pKCS12File.join("|");
  if (conf.image !is null) props["image"] = conf.image;
  else props.remove("image");
  foreach (string retired; retiredPropertyKeys) props.remove(retired);
  return props;
}

/**
 * Claves de config.properties que ya no se usan (el ancho y el alto de la firma, que nunca
 * cambiaron el recuadro: lo mide su contenido, escalado por signScale). Se quitan al guardar.
 */
private immutable string[] retiredPropertyKeys = ["signwidth", "signheight"];

/// Campos que se guardan en la configuración de un documento (docSettingsToProperties).
immutable string[] documentSettingsFields = [
  "country", "reason", "pDFImgScaleFactor", "fontSize", "language", "cAdESLevel", "signX", "pageNumber",
  "backgroundColor", "signY", "fontAlignment", "contact", "fontColor", "place", "image", "pAdESLevel",
  "overwriteSourceFile", "xAdESLevel", "dateFormat", "withoutVisibleSign", "defaultSignMessage", "font", "jAdESLevel",
  "signScale",
];

/// Campos que ya no se usan y que traen las configuraciones de documento guardadas antes; se ignoran.
private immutable string[] retiredDocumentFields = ["signWidth", "signHeight"];

/// Entradas de la configuración de un documento, con los nombres de campo como claves.
string[string] documentSettingsToProperties(const Settings settings) pure @safe {
  string[string] props;
  static foreach (field; documentSettingsFields) {{
    auto value = __traits(getMember, settings, field);
    static if (is(typeof(value) : const(char)[])) {
      if (value !is null) props[field] = value.idup;
    } else static if (is(typeof(value) == bool)) {
      props[field] = value ? "true" : "false";
    } else static if (is(typeof(value) == float)) {
      props[field] = javaFloatText(value);
    } else {
      props[field] = value.to!string;
    }
  }}
  return props;
}

/**
 * Aplica la configuración guardada de un documento sobre `settings`.
 *
 * Throws: Exception con la clave si hay un campo desconocido o un valor que no es del tipo esperado.
 */
void applyDocumentProperties(Settings settings, const string[string] props) pure @safe {
  foreach (key, value; props) {
    bool known = retiredDocumentFields.canFind(key);
    static foreach (field; documentSettingsFields) {
      if (key == field) {
        known = true;
        alias FieldType = typeof(__traits(getMember, settings, field));
        static if (is(FieldType == string)) {
          __traits(getMember, settings, field) = value;
        } else static if (is(FieldType == bool)) {
          __traits(getMember, settings, field) = icmp(value, "true") == 0;
        } else static if (is(FieldType == float)) {
          bool valid;
          __traits(getMember, settings, field) = floatFromProperty(value, valid);
          enforce(valid, format("Valor decimal inválido «%s» en %s", value, key));
        } else {
          try {
            __traits(getMember, settings, field) = value.strip.to!FieldType;
          } catch (ConvException) {
            throw new Exception(format("Valor «%s» no válido para %s", value, key));
          }
        }
      }
    }
    enforce(known, format("Campo desconocido «%s» en la configuración del documento", key));
  }
}

/// Texto de un float como Float.toString de Java («1.0», «1.5»).
string javaFloatText(float value) pure @safe {
  import std.string : indexOf;
  string text = format("%g", value);
  if (text.indexOf('.') < 0 && text.indexOf('e') < 0) text ~= ".0";
  return text;
}

@("should keep the Java defaults and keys when reading an empty config.properties")
unittest {
  auto conf = new Settings();
  applyProperties(conf, null);
  assert(conf.signX == 198 && conf.fontSize == 7);
  assert(conf.pAdESLevel == "LTA" && conf.language == "es" && conf.allowOriginPort);
  assert(conf.activePlugins == [dummyPluginName, checkUpdatePluginName]);
  assert(conf.simplified_mode.isNull);
  assert(conf.image is null);
}

@("should read every stored value when the Java version wrote config.properties")
unittest {
  auto conf = new Settings();
  assert(applyProperties(conf, ["singx": "10", "singy": "20", "advancedlogs": "true", "plugins": "",
    "pkcs12file": "/a.p12|/b.p12", "pdfimgscalefactor": "1,50", "simplifiedMode": "false", "image": "/firma.png",
    "fontalignment": "ONLY IMAGE"]) is null);
  assert(conf.signX == 10 && conf.signY == 20);
  assert(conf.advancedLogs == "ALL");
  assert(conf.activePlugins.length == 0);
  assert(conf.pKCS12File == ["/a.p12", "/b.p12"]);
  assert(conf.pDFImgScaleFactor == 1.5f);
  assert(!conf.simplified_mode.isNull && !conf.simplified_mode.get);
  assert(conf.image == "/firma.png" && conf.isOnlyImageAlignment);
  auto invalidScale = new Settings();
  assert(applyProperties(invalidScale, ["pdfimgscalefactor": "grande"]) == "grande");
  assert(invalidScale.pDFImgScaleFactor == 1);
}

@("should reproduce the settings when writing and reading config.properties again")
unittest {
  auto conf = new Settings();
  conf.reason = "Aprobación";
  conf.pKCS12File = ["/x.p12"];
  conf.simplified_mode = true;
  conf.extraPKCS11Lib = "/opt/lib.so";
  auto props = settingsToProperties(conf, ["otra": "se conserva", "image": "/vieja.png"], "OBF:abc");
  assert(props["otra"] == "se conserva");
  assert("image" !in props);
  assert(props["keyPassword"] == "OBF:abc");
  auto again = new Settings();
  applyProperties(again, props);
  assert(again.reason == "Aprobación" && again.pKCS12File == ["/x.p12"]);
  assert(again.isSimplifiedMode && again.extraPKCS11Lib == "/opt/lib.so");
  // Cada campo de la tabla de claves vuelve con el valor que se escribió.
  auto changed = new Settings();
  static foreach (entry; propertyKeys) {{
    alias Type = typeof(__traits(getMember, Settings, entry[0]));
    static if (is(Type == bool)) __traits(getMember, changed, entry[0]) = !__traits(getMember, changed, entry[0]);
    else static if (is(Type == int)) __traits(getMember, changed, entry[0]) = 42;
    else __traits(getMember, changed, entry[0]) = "valor de " ~ entry[0];
  }}
  auto reread = new Settings();
  applyProperties(reread, settingsToProperties(changed, null, null));
  static foreach (entry; propertyKeys) {
    assert(__traits(getMember, reread, entry[0]) == __traits(getMember, changed, entry[0]), entry[0]);
  }
}

@("should manage allowed and rejected origins without duplicates when editing the host lists")
unittest {
  auto conf = new Settings();
  conf.setRegisteredAllowedOrigins(["https://a.cr", "https://b.cr"]);
  conf.addTempAllowedHost("https://c.cr");
  conf.addTempAllowedHost("https://a.cr");
  assert(conf.getAllowedHosts() == ["https://c.cr", "https://a.cr", "https://b.cr"]);
  conf.removeAllowedHost("https://b.cr");
  assert(conf.registeredAllowedOrigins == "https://a.cr");
  conf.removeAllowedHost("https://c.cr");
  assert(conf.getAllowedHosts() == ["https://a.cr"]);
  conf.addNoAuthorizedHost("https://malo.cr");
  conf.addNoAuthorizedHost("https://malo.cr");
  assert(conf.getNoAuthorizedHosts() == ["https://malo.cr"]);
  conf.removeNoAuthorizedHost("https://malo.cr");
  assert(conf.getNoAuthorizedHosts().length == 0);
  conf.addTempAllowedHost("https://sesion.cr");
  conf.registerAllowedOrigin("https://siempre.cr");
  conf.registerAllowedOrigin("https://siempre.cr");
  assert(conf.getRegisteredAllowedOrigins() == ["https://a.cr", "https://siempre.cr"]);
}

@("should resolve the remote port only inside the allowed range when an origin asks for one")
unittest {
  bool outOfRange;
  assert(resolveOriginPort("http://localhost:8000#3520#False", true, outOfRange) == 3520 && !outOfRange);
  assert(resolveOriginPort("http://localhost:8000#3600", true, outOfRange) == defaultRemotePort && outOfRange);
  assert(resolveOriginPort("http://localhost:8000#3520", false, outOfRange) == defaultRemotePort);
  assert(resolveOriginPort("http://localhost:8000#abc", true, outOfRange) == defaultRemotePort);
  assert(resolveOriginPort(null, true, outOfRange) == defaultRemotePort);
  assert(processOrigin("firmador:https://sitio.cr#3517#True", defaultRemotePort).minimized);
}

@("should map configured font names to PDF families and styles")
unittest {
  assert(fontFamilyFor("Times New Roman Bold Italic") == FontFamily.serif);
  assert(fontStyleFor("Times New Roman Bold Italic") == FontStyle(true, true));
  assert(fontFamilyFor("Courier New Regular") == FontFamily.monospaced);
  assert(fontStyleFor("Helvetica Oblique") == FontStyle(false, true));
  assert(fontFamilyFor("SansSerif") == FontFamily.sansSerif);
  assert(displayFontNameFor("Nimbus Sans Bold") == "Nimbus Sans");
}

@("should decode colors like java.awt.Color.decode")
unittest {
  import std.exception : assertThrown;
  assert(parseColor("#FF8000") == Rgba(255, 128, 0, 255));
  assert(parseColor("0x000010") == Rgba(0, 0, 16, 255));
  assert(parseColor("16") == Rgba(0, 0, 16, 255));
  assert(parseColor("Transparente").alpha == 0);
  assertThrown(parseColor("rojo"));
  assertThrown(parseColor("#1000000"));
}

@("should round trip the per document settings when saving and loading them")
unittest {
  auto settings = new Settings();
  settings.reason = "Motivo";
  settings.pDFImgScaleFactor = 1.5;
  settings.overwriteSourceFile = true;
  auto props = documentSettingsToProperties(settings);
  assert(props["pDFImgScaleFactor"] == "1.5");
  assert("image" !in props);
  auto loaded = new Settings();
  applyDocumentProperties(loaded, props);
  assert(loaded.reason == "Motivo" && loaded.pDFImgScaleFactor == 1.5f && loaded.overwriteSourceFile);
  import std.exception : assertThrown;
  assertThrown(applyDocumentProperties(loaded, ["desconocido": "1"]));
  assertThrown(applyDocumentProperties(loaded, ["fontSize": "grande"]));
  // Las guardadas con el ancho y el alto de la firma, que ya no existen, se siguen leyendo.
  applyDocumentProperties(loaded, ["signWidth": "133", "signHeight": "33", "reason": "Otro"]);
  assert(loaded.reason == "Otro");
  assert("signwidth" !in settingsToProperties(new Settings(), ["signwidth": "133"], null));
}

@("should copy every value including the ones the copy constructor skips when assigning")
unittest {
  auto source = new Settings();
  source.keyPassword = "clave";
  source.simplified_mode = true;
  source.setRegisteredAllowedOrigins(["https://a.cr"]);
  source.pKCS12File = ["/tmp/a.p12"];
  auto copied = new Settings(source);
  assert(copied.keyPassword != "clave" && copied.simplified_mode.isNull);
  auto assigned = new Settings();
  assigned.assign(source);
  assert(assigned.keyPassword == "clave" && assigned.simplified_mode.get);
  assert(assigned.getRegisteredAllowedOrigins() == ["https://a.cr"]);
  // Las listas no se comparten.
  assigned.pKCS12File[0] = "/tmp/b.p12";
  assert(source.pKCS12File[0] == "/tmp/a.p12");
}
