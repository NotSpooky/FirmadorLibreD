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
 * Imagen y fuente de la firma visible según la configuración: la imagen puede ser una
 * ruta, un URI file: o, desde Firmador Remoto, «data:image/…;base64,…»; la fuente puede
 * ser una de las estándar o, desde Firmador Remoto, «base64:nombre:datos» o
 * «file:nombre:ruta» (Settings.getByteImage, FirmadorPAdES.getFont y
 * SignaturePreviewGenerator.loadSourceImage en la versión Java).
 */
module firmador.signers.resources;

import std.algorithm : startsWith;
import std.base64 : Base64;
import std.exception : enforce;
import std.file : exists, isFile, read;
import std.format : format;
import std.logger : error, info;
import std.string : indexOf, strip;
import std.uri : decodeComponent;

import firmador.pdf.appearance : standardFontName;
import firmador.pdf.pades : SignatureFont;
import firmador.settings : fontFamilyFor, fontStyleFor;

/// Origen de una imagen de firma ya interpretado, sin leer todavía el archivo.
struct ImageSource {
  enum Kind { none, path, inline }
  Kind kind;
  string path;
  immutable(ubyte)[] bytes;
}

/**
 * Interpreta el valor configurado de la imagen.
 *
 * Throws: Exception si es un «data:» mal formado.
 */
ImageSource parseImageSource(string image) pure @safe {
  ImageSource source;
  string value = image is null ? null : image.strip;
  if (value.length == 0) return source;
  if (value.startsWith("data:image/")) {
    auto comma = value.indexOf(',');
    enforce(comma > 0, "La imagen de la firma no trae datos después de la coma");
    source.kind = ImageSource.Kind.inline;
    source.bytes = Base64.decode(value[comma + 1 .. $]).idup;
    return source;
  }
  source.kind = ImageSource.Kind.path;
  source.path = value.startsWith("file:") ? pathFromFileUri(value) : value;
  return source;
}

/// Ruta local de un URI file: (file:///C:/…, file:/home/…, file://localhost/…).
string pathFromFileUri(string uri) pure @safe {
  string rest = uri["file:".length .. $];
  if (rest.startsWith("//")) {
    rest = rest[2 .. $];
    auto slash = rest.indexOf('/');
    rest = slash >= 0 ? rest[slash .. $] : "/";
  }
  string path = decodeComponent(rest);
  version (Windows) {
    if (path.length > 2 && path[0] == '/' && path[2] == ':') path = path[1 .. $];
  }
  return path;
}

/**
 * Bytes de la imagen configurada, o null si no hay imagen o el archivo no existe (se
 * registra, como en la versión Java, y la firma sigue sin imagen).
 */
immutable(ubyte)[] loadSignatureImage(string image) @trusted {
  ImageSource source;
  try {
    source = parseImageSource(image);
  } catch (Exception exception) {
    error("No se pudo interpretar la imagen de la firma: ", exception.msg);
    return null;
  }
  final switch (source.kind) {
    case ImageSource.Kind.none:
      return null;
    case ImageSource.Kind.inline:
      return source.bytes;
    case ImageSource.Kind.path:
      if (!exists(source.path) || !isFile(source.path)) {
        error("No existe la imagen de la firma: ", source.path);
        return null;
      }
      info("Leyendo la imagen de la firma ", source.path);
      return cast(immutable(ubyte)[]) read(source.path);
  }
}

/**
 * Fuente de la firma visible para el valor configurado.
 *
 * Throws: Exception si una fuente «base64:» o «file:» no se puede leer.
 */
SignatureFont resolveSignatureFont(string configured) @trusted {
  SignatureFont font;
  if (configured.startsWith("base64:")) {
    auto parts = splitFont(configured);
    font.trueType = Base64.decode(parts[1]).idup;
    return font;
  }
  if (configured.startsWith("file:")) {
    auto parts = splitFont(configured);
    info("Leyendo la fuente de la firma ", parts[1]);
    font.trueType = cast(immutable(ubyte)[]) read(parts[1]);
    return font;
  }
  font.standardName = standardFontName(fontFamilyFor(configured), fontStyleFor(configured));
  return font;
}

/// Nombre y datos de «tipo:nombre:datos»; los datos pueden contener ':' (rutas de Windows).
private string[2] splitFont(string configured) pure @safe {
  auto first = configured.indexOf(':');
  auto second = configured[first + 1 .. $].indexOf(':');
  enforce(second >= 0, format("La fuente «%s» no tiene el formato tipo:nombre:datos", configured[0 .. first]));
  string fontName = configured[first + 1 .. first + 1 + second];
  string data = configured[first + 2 + second .. $];
  string[2] result = [fontName, data];
  return result;
}

@("should read the three image forms and the custom font forms from the settings")
unittest {
  auto inline = parseImageSource("data:image/png;base64,AAEC");
  assert(inline.kind == ImageSource.Kind.inline && inline.bytes == [0, 1, 2]);
  assert(parseImageSource(" /home/u/firma.png ").path == "/home/u/firma.png");
  assert(parseImageSource("file:///home/u/mi%20firma.png").path == "/home/u/mi firma.png");
  assert(parseImageSource("file:/home/u/firma.png").path == "/home/u/firma.png");
  assert(parseImageSource(null).kind == ImageSource.Kind.none);
  assert(resolveSignatureFont("Times New Roman Bold").standardName == "Times-Bold");
  assert(resolveSignatureFont("SansSerif").standardName == "Helvetica");
  assert(resolveSignatureFont("base64:Libre:AAEC").trueType == [0, 1, 2]);
  assert(splitFont(`file:Mia:C:\fuentes\mia.ttf`)[1] == `C:\fuentes\mia.ttf`);
}
