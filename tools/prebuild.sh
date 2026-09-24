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

# Paso previo de dub: reúne en src/cinclude las cabeceras de las bibliotecas de C que
# ImportC necesita, según pkg-config, y compila con el compilador de C del sistema el
# puente con mupdf (src/shim/mupdfshim.c), que usa setjmp/longjmp y por eso no puede
# compilarse con ImportC. Ver COMMANDS.md.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/.build"
mkdir -p "$out"

packages="mupdf libxml-2.0 libxslt libcrypto"
case "$(uname -s)" in
  Linux*) packages="$packages libpcsclite libsecret-1" ;;
  Darwin*) ;;
  MINGW*|MSYS*|CYGWIN*) ;;
  *) packages="$packages libpcsclite" ;;
esac

for package in $packages; do
  if ! pkg-config --exists "$package"; then
    echo "prebuild: falta la biblioteca de desarrollo '$package' (pkg-config no la encuentra)" >&2
    exit 1
  fi
done

# ImportC recibe una sola ruta de cabeceras (cImportPaths en dub.json): se reúne en
# src/cinclude lo que hay en cada directorio -I de pkg-config, y los -D en
# firmador_pkgdefs.h, que incluye cada módulo de src/c antes que nada. El directorio se
# vacía pero no se borra: dub lo exige antes de ejecutar este paso.
include="$root/src/cinclude"
mkdir -p "$include"
find "$include" -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
defines="$include/firmador_pkgdefs.h"
printf '%s\n' "/* Generado por tools/prebuild.sh a partir de pkg-config. */" > "$defines"
for flag in $(pkg-config --cflags $packages); do
  case "$flag" in
    -I*)
      directory="${flag#-I}"
      for entry in "$directory"/*; do
        [ -e "$entry" ] || continue
        target="$include/$(basename "$entry")"
        [ -e "$target" ] && continue
        ln -s "$entry" "$target" 2>/dev/null || cp -R "$entry" "$target"
      done
      ;;
    -D*)
      definition="${flag#-D}"
      case "$definition" in
        *=*) printf '#define %s %s\n' "${definition%%=*}" "${definition#*=}" >> "$defines" ;;
        *) printf '#define %s 1\n' "$definition" >> "$defines" ;;
      esac
      ;;
  esac
done

cc="${CC:-cc}"
# shellcheck disable=SC2046
"$cc" -O2 -fPIC -std=c11 -Wall -Wextra -Werror $(pkg-config --cflags mupdf) \
  -c "$root/src/shim/mupdfshim.c" -o "$out/mupdfshim.o"
rm -f "$out/libfirmadorshim.a"
ar rcs "$out/libfirmadorshim.a" "$out/mupdfshim.o"
