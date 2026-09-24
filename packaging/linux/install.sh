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

# Instala Firmador ya compilado (bin/firmador) en el prefijo indicado (por omisión
# /usr/local; DESTDIR para armar paquetes): el ejecutable, la entrada del menú con los
# tipos de documento y el esquema firmador:, los datos de AppStream y los íconos. Lo usan
# el flatpak (io.github.notspooky.firmadorlibred.yml) y los paquetes de cada
# distribución. Ver COMMANDS.md.
#
#   packaging/linux/install.sh [prefijo]
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
appId="io.github.notspooky.firmadorlibred"
executable="$root/bin/firmador"
destination="${DESTDIR:-}${1:-/usr/local}"

if [ ! -x "$executable" ]; then
  echo "install.sh: no existe $executable; compile antes con «dub build --build=release»" >&2
  exit 1
fi

install -D -m 755 "$executable" "$destination/bin/firmador"
install -D -m 644 "$here/$appId.desktop" "$destination/share/applications/$appId.desktop"
install -D -m 644 "$here/$appId.metainfo.xml" "$destination/share/metainfo/$appId.metainfo.xml"
for size in 128x128 256x256 512x512; do
  install -D -m 644 "$here/icons/$size.png" "$destination/share/icons/hicolor/$size/apps/$appId.png"
done
echo "Firmador instalado en $destination"
