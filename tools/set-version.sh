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

# Pone la versión de una compilación en resources/version.txt, que el programa incorpora
# (configuration.firmadorVersion) y de la que salen la del .exe (tools/prebuild.sh), la del
# instalador (tools/windows/installer.ps1) y la de Firmador.app (tools/macos/bundle.sh), y en
# la entrada de AppStream del flatpak. La CI la llama con la etiqueta en las versiones
# publicadas y con <versión>-dev.<commit> en las demás.
set -eu

fail() {
  echo "set-version: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "uso: $0 <versión X.Y.Z[-sufijo]>"
version=$1
case "$version" in
  *[!0-9A-Za-z.-]*|"") fail "'$version' tiene caracteres que no van en una versión" ;;
esac
core="${version%%-*}"
case "$core" in
  *[!0-9.]*|.*|*.|*..*) fail "'$version' no empieza con X.Y.Z numéricos" ;;
  *.*.*.*) fail "'$version' tiene más de tres números" ;;
  *.*.*) ;;
  *) fail "'$version' no empieza con X.Y.Z numéricos" ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
printf '%s\n' "$version" > "$root/resources/version.txt"

# AppStream: la versión publicada es estable; las demás, de desarrollo.
if [ "$version" = "$core" ]; then type=stable; else type=development; fi
metainfo="$root/packaging/linux/io.github.notspooky.firmadorlibred.metainfo.xml"
sed -e "s|<release version=\"[^\"]*\" date=\"[^\"]*\" type=\"[^\"]*\"/>|<release version=\"$core\" date=\"$(date -u +%Y-%m-%d)\" type=\"$type\"/>|" \
  "$metainfo" > "$metainfo.new"
grep -q "<release version=\"$core\"" "$metainfo.new" || fail "no se encontró la entrada <release> en $metainfo"
mv "$metainfo.new" "$metainfo"
echo "set-version: $version"
