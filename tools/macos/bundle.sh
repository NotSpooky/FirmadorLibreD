#!/bin/sh
# Firmador is a program to sign documents using AdES standards.
#
# Copyright (C) Firmador authors.
#
# This file is part of Firmador.
#
# Firmador is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Firmador is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Firmador.  If not, see <http://www.gnu.org/licenses/>.

# Arma Firmador.app a partir de bin/firmador (dub build) y lo comprime en el ZIP que se
# indica (con Firmador.app/Contents/… adentro, como lo espera la actualización automática:
# @contract release-artifacts), para que funcione en una Mac sin Homebrew:
# * Contents/Frameworks: las bibliotecas de Homebrew que el ejecutable enlaza (mupdf,
#   libxml2, libxslt, OpenSSL y las suyas), con sus rutas cambiadas a @executable_path.
# * SDL2 (sdl2-compat), SDL3 y FreeType, que dlangui no enlaza sino que abre al arrancar la
#   ventana: dlangui busca Contents/Frameworks/libSDL2.dylib y libfreetype.6.dylib, y
#   sdl2-compat busca libSDL3.dylib junto a sí misma.
# * Contents/Frameworks/ossl-modules/legacy.dylib, el proveedor de OpenSSL para los
#   almacenes PKCS#12 antiguos (src/firmador/crypto/openssl.d lo busca ahí).
# Todo va como archivos, sin enlaces simbólicos: la actualización (checkupdate.d) escribe
# cada entrada del ZIP como archivo. La firma es ad hoc: no hace falta una cuenta de Apple,
# pero macOS pide autorizar la aplicación la primera vez. La versión mínima de macOS es la
# más alta que piden los binarios del paquete, que es la del sistema donde se compilaron
# las bibliotecas de Homebrew. Necesita dylibbundler, pkg-config con libcrypto, sdl2, sdl3
# y freetype2, y las herramientas del sistema (otool, install_name_tool, vtool, plutil,
# codesign, ditto).
set -eu

fail() {
  echo "bundle: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "uso: $0 <paquete.zip>"
zip_path=$1
case "$zip_path" in
  /*) ;;
  *) zip_path="$(pwd)/$zip_path" ;;
esac

root="$(cd "$(dirname "$0")/../.." && pwd)"
binary="$root/bin/firmador"
[ -x "$binary" ] || fail "falta $binary; compile antes con dub build"

work="$root/.build/macos"
app="$work/Firmador.app"
contents="$app/Contents"
frameworks="$contents/Frameworks"
rm -rf "$work"
mkdir -p "$contents/MacOS" "$contents/Resources" "$frameworks/ossl-modules"

cp "$binary" "$contents/MacOS/firmador"

# Copia `$2` de la carpeta de bibliotecas del módulo de pkg-config `$1` como
# Contents/Frameworks/`$3` (el archivo, no el enlace) y le pone ese nombre de instalación.
copy_library() {
  libdir="$(pkg-config --variable=libdir "$1")" || fail "pkg-config no encuentra $1"
  [ -e "$libdir/$2" ] || fail "no está $libdir/$2"
  cp -L "$libdir/$2" "$frameworks/$3"
  # Homebrew instala las bibliotecas sólo para lectura.
  chmod 644 "$frameworks/$3"
  install_name_tool -id "@executable_path/../Frameworks/$3" "$frameworks/$3"
}
copy_library sdl2 libSDL2.dylib libSDL2.dylib
copy_library sdl3 libSDL3.dylib libSDL3.dylib
copy_library freetype2 libfreetype.6.dylib libfreetype.6.dylib

modules="$(pkg-config --variable=modulesdir libcrypto)"
[ -f "$modules/legacy.dylib" ] || fail "no está el proveedor legacy de OpenSSL en '$modules'"
cp "$modules/legacy.dylib" "$frameworks/ossl-modules/legacy.dylib"
chmod 644 "$frameworks/ossl-modules/legacy.dylib"
install_name_tool -id @executable_path/../Frameworks/ossl-modules/legacy.dylib \
  "$frameworks/ossl-modules/legacy.dylib"

# Copia las bibliotecas que no son del sistema de todo lo anterior y cambia sus rutas por
# @executable_path. Sin entrada estándar: si no encuentra una biblioteca falla en lugar de
# preguntar.
dylibbundler -of -b \
  -x "$contents/MacOS/firmador" \
  -x "$frameworks/libSDL2.dylib" \
  -x "$frameworks/libSDL3.dylib" \
  -x "$frameworks/libfreetype.6.dylib" \
  -x "$frameworks/ossl-modules/legacy.dylib" \
  -d "$frameworks" \
  -p @executable_path/../Frameworks/ < /dev/null

for library in libSDL2.dylib libSDL3.dylib libfreetype.6.dylib; do
  [ -f "$frameworks/$library" ] && [ ! -L "$frameworks/$library" ] || fail "falta $library en el paquete"
done
[ -z "$(find "$app" -type l)" ] || fail "quedaron enlaces simbólicos en el paquete: $(find "$app" -type l)"

# Ninguna biblioteca puede quedar apuntando a Homebrew ni a un @rpath: en otra Mac no están.
machos="$(find "$contents/MacOS" "$frameworks" -type f)"
# shellcheck disable=SC2086
if otool -L $machos | grep -E '^[[:space:]]+(/opt/homebrew|/usr/local|@rpath)/'; then
  fail "quedan bibliotecas enlazadas fuera del paquete (arriba)"
fi

cp "$root/packaging/macos/firmador.icns" "$contents/Resources/firmador.icns"

# Versión: la de resources/version.txt sin el sufijo (-SNAPSHOT), la misma que muestra el
# programa. Versión mínima de macOS: la más alta que pide alguno de los binarios.
version="$(tr -d '[:space:]' < "$root/resources/version.txt")"
version="${version%%-*}"
[ -n "$version" ] || fail "resources/version.txt está vacío"
# shellcheck disable=SC2086
minimum="$(for file in $machos; do vtool -show-build "$file"; done |
  awk '$1 == "minos" { print $2 }' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)"
[ -n "$minimum" ] || fail "no se pudo leer la versión mínima de macOS de los binarios"

plist="$contents/Info.plist"
cp "$root/packaging/macos/Info.plist" "$plist"
for key in CFBundleShortVersionString CFBundleVersion; do
  plutil -replace "$key" -string "$version" "$plist"
done
plutil -replace LSMinimumSystemVersion -string "$minimum" "$plist"
plutil -lint "$plist"

# Firma ad hoc: primero lo que va dentro, después el paquete, que sella el resto.
find "$frameworks" -type f -name '*.dylib' -exec codesign --force --sign - {} +
codesign --force --sign - "$app"
codesign --verify --strict --deep --verbose=2 "$app"

# Prueba: el ejecutable del paquete arranca (con -dshell y sin órdenes termina en el acto)
# y lo que carga es del paquete o del sistema, no de Homebrew.
loaded="$(DYLD_PRINT_LIBRARIES=1 "$contents/MacOS/firmador" -dshell < /dev/null 2>&1 > /dev/null)" ||
  fail "Firmador.app no arranca: $loaded"
if printf '%s\n' "$loaded" | grep -E '(/opt/homebrew|/usr/local)/'; then
  fail "Firmador.app carga bibliotecas de Homebrew (arriba)"
fi
# dyld muestra las del paquete como …/Contents/MacOS/../Frameworks/…
printf '%s\n' "$loaded" | grep -q 'Firmador\.app/Contents/.*Frameworks/' ||
  fail "Firmador.app no cargó sus bibliotecas: $loaded"

# Sin --norsrc ditto agrega entradas __MACOSX/Firmador.app/Contents/._*, que la
# actualización (checkupdate.d) copiaría dentro del paquete.
rm -f "$zip_path"
ditto -c -k --norsrc --keepParent "$app" "$zip_path"
echo "bundle: $zip_path (Firmador.app $version, macOS $minimum o posterior)"
