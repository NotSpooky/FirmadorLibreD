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

# Arma packaging/licenses/accesskit.txt, el aviso de licencias de AccessKit y de los paquetes de
# Rust que su biblioteca precompilada lleva adentro (Cargo.lock de accesskit-c), que va con cada
# paquete de Firmador: las licencias MIT, BSD, Zlib y Apache piden acompañar el binario con sus
# avisos de copyright. Lee lo que tools/prebuild.sh deja en .build/accesskit (compile antes),
# descarga cada paquete de crates.io, lo verifica con el SHA-256 de Cargo.lock y copia sus
# archivos de licencia; los textos iguales se escriben una sola vez, con la lista de paquetes
# que los usan. Hay que volver a ejecutarlo al cambiar la versión de AccessKit
# (@contract accesskit-c). Necesita curl, tar y sha256sum (o shasum).
set -eu

fail() {
  echo "accesskit-notices: $*" >&2
  exit 1
}

root="$(cd "$(dirname "$0")/.." && pwd)"
source_dir="$root/.build/accesskit"
output="$root/packaging/licenses/accesskit.txt"
[ -f "$source_dir/Cargo.lock" ] || fail "falta $source_dir/Cargo.lock; compile antes (dub build)"
version="$(cat "$source_dir/VERSION")"

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/texts"

# Una línea «nombre versión checksum» por paquete de crates.io.
awk '
  /^\[\[package\]\]/ { if (name != "" && checksum != "") print name, version, checksum; name = ""; version = ""; checksum = "" }
  /^name = /     { gsub(/"/, "", $3); name = $3 }
  /^version = /  { gsub(/"/, "", $3); version = $3 }
  /^checksum = / { gsub(/"/, "", $3); checksum = $3 }
  END { if (name != "" && checksum != "") print name, version, checksum }
' "$source_dir/Cargo.lock" > "$work/packages"
[ -s "$work/packages" ] || fail "Cargo.lock no lista paquetes"

: > "$work/summary"
while read -r name crate_version checksum; do
  crate="$work/$name-$crate_version.crate"
  curl -fsSL --retry 3 -o "$crate" "https://static.crates.io/crates/$name/$name-$crate_version.crate"
  [ "$(sha256 "$crate")" = "$checksum" ] || fail "$name $crate_version no coincide con el SHA-256 de Cargo.lock"
  mkdir -p "$work/$name-$crate_version"
  tar -xzf "$crate" -C "$work" "$name-$crate_version"
  rm -f "$crate"
  package="$work/$name-$crate_version"
  license="$(awk '/^\[package\]/ { inside = 1; next } /^\[/ { inside = 0 } inside && /^license = / { sub(/^license = /, ""); gsub(/"/, ""); print; exit }' "$package/Cargo.toml")"
  [ -n "$license" ] || license="(sin campo license en Cargo.toml)"
  printf '%s %s: %s\n' "$name" "$crate_version" "$license" >> "$work/summary"
  found=false
  for file in "$package"/LICENSE* "$package"/LICENCE* "$package"/COPYING* "$package"/NOTICE* "$package"/UNLICENSE*; do
    [ -f "$file" ] || continue
    found=true
    key="$(sha256 "$file")"
    [ -f "$work/texts/$key" ] || cp "$file" "$work/texts/$key"
    printf '%s %s (%s)\n' "$name" "$crate_version" "$(basename "$file")" >> "$work/texts/$key.users"
  done
  [ "$found" = true ] || printf '%s %s no trae archivos de licencia: rige el texto estándar de %s.\n' \
    "$name" "$crate_version" "$license" >> "$work/summary-missing"
  rm -rf "$package"
done < "$work/packages"

mkdir -p "$(dirname "$output")"
{
  echo "AccessKit $version (accesskit-c) y los paquetes de Rust que su biblioteca precompilada"
  echo "lleva adentro, que Firmador usa para los lectores de pantalla. Generado por"
  echo "tools/accesskit-notices.sh a partir de su Cargo.lock."
  echo
  echo "================================================================================"
  echo "accesskit-c $version: MIT OR Apache-2.0"
  echo "================================================================================"
  echo
  cat "$source_dir/LICENSE-MIT"
  echo
  echo "--------------------------------------------------------------------------------"
  echo "Parte del código de AccessKit proviene de Chromium:"
  echo "--------------------------------------------------------------------------------"
  echo
  cat "$source_dir/LICENSE.chromium"
  echo
  echo "================================================================================"
  echo "Paquetes y sus licencias"
  echo "================================================================================"
  echo
  sort "$work/summary"
  if [ -f "$work/summary-missing" ]; then
    echo
    sort "$work/summary-missing"
  fi
  for text in $(ls "$work/texts" | grep -v '\.users$' | sort); do
    echo
    echo "================================================================================"
    echo "Texto usado por:"
    sed 's/^/  /' "$work/texts/$text.users" | sort
    echo "================================================================================"
    echo
    cat "$work/texts/$text"
  done
} > "$output"
echo "accesskit-notices: $output ($(wc -l < "$work/packages") paquetes)"
