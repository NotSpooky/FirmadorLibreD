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
# compilarse con ImportC. En Windows lo compila clang para MSVC con el runtime de C en DLL
# (/MD), como libmupdf.lib y las bibliotecas de vcpkg (tools/windows/build.ps1), y compila
# con llvm-rc los recursos del ejecutable (packaging/windows/firmador.rc: el ícono y los datos
# de la versión de resources/version.txt). También deja en .build/accesskit la biblioteca
# precompilada de AccessKit (accesibilidad), verificada. CC, AR y RC cambian el compilador, el
# archivador y el compilador de recursos. Ver COMMANDS.md.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/.build"
mkdir -p "$out"

packages="mupdf libxml-2.0 libxslt libcrypto"
cc="${CC:-cc}"
ar="${AR:-ar}"
compile_flags="-fPIC"
archive_flags=""
windows=false
case "$(uname -s)" in
  Linux*) packages="$packages libpcsclite libsecret-1" ;;
  Darwin*) ;;
  MINGW*|MSYS*|CYGWIN*)
    cc="${CC:-clang}"
    ar="${AR:-llvm-ar}"
    compile_flags="-fms-runtime-lib=dll"
    # link.exe lee el formato COFF de las bibliotecas de MSVC.
    archive_flags="--format=coff"
    windows=true
    ;;
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
# vacía pero no se borra: dub lo exige antes de ejecutar este paso. Se vacía con el
# propio sh y no con find, que en Windows puede ser el find.exe del sistema. Lo que se
# reúne nunca empieza con punto, así que * no toca .gitkeep.
include="$root/src/cinclude"
mkdir -p "$include"
for entry in "$include"/*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  rm -rf "$entry"
done
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

# Las cabeceras de mupdf son de terceros: van como cabeceras del sistema, para que sus
# avisos no cuenten en -Werror (en Linux ya lo son, en /usr/include).
mupdf_flags=""
for flag in $(pkg-config --cflags mupdf); do
  case "$flag" in
    -I*) mupdf_flags="$mupdf_flags -isystem ${flag#-I}" ;;
    *) mupdf_flags="$mupdf_flags $flag" ;;
  esac
done
# shellcheck disable=SC2086
"$cc" -O2 $compile_flags -std=c11 -Wall -Wextra -Werror $mupdf_flags \
  -c "$root/src/shim/mupdfshim.c" -o "$out/mupdfshim.o"
rm -f "$out/libfirmadorshim.a"
# shellcheck disable=SC2086
"$ar" rcs $archive_flags "$out/libfirmadorshim.a" "$out/mupdfshim.o"

# El ícono y los datos de la versión de firmador.exe: dub.json le pasa el .res al enlazador
# (lflags-windows). Sin preprocesar, el .rc no necesita las cabeceras del SDK de Windows, así
# que la versión se escribe en la plantilla antes de compilarla.
if [ "$windows" = true ]; then
  version="$(tr -d '[:space:]' < "$root/resources/version.txt")"
  case "$version" in
    *[!0-9A-Za-z.-]*|"")
      echo "prebuild: resources/version.txt no es una versión X.Y.Z[-sufijo]: '$version'" >&2
      exit 1
      ;;
  esac
  core="${version%%-*}"
  case "$core" in
    *.*.*) ;;
    *)
      echo "prebuild: la versión '$version' no empieza con X.Y.Z numéricos" >&2
      exit 1
      ;;
  esac
  major="${core%%.*}"
  rest="${core#*.}"
  minor="${rest%%.*}"
  patch="${rest#*.}"
  for part in "$major" "$minor" "$patch"; do
    case "$part" in
      ""|*[!0-9]*)
        echo "prebuild: la versión '$version' no empieza con X.Y.Z numéricos" >&2
        exit 1
        ;;
    esac
  done
  # La ruta del ícono es relativa a .build, donde queda el .rc completo.
  sed -e "s|@ICON@|../packaging/windows/firmador.ico|" -e "s|@VERSION@|$version|g" \
    -e "s|@VERSION_COMMA@|$major,$minor,$patch,0|g" "$root/packaging/windows/firmador.rc" > "$out/firmador.rc"
  "${RC:-llvm-rc}" -no-preprocess -fo "$out/firmador.res" "$out/firmador.rc"
fi

# AccessKit, con el que dlangui (configuración minimal-accesskit) expone la ventana a los
# lectores de pantalla: su biblioteca estática precompilada para esta plataforma queda en
# .build/accesskit/lib, que dub.json pone en la ruta del enlazador, y junto a ella sus licencias
# y su Cargo.lock, con los que tools/accesskit-notices.sh arma el aviso de licencias. El ZIP
# oficial se descarga una vez por versión, salvo que ya esté en .build (el flatpak lo trae así,
# sin red), y se verifica su SHA-256 antes de abrirlo (@contract accesskit-c).
accesskit_version=0.23.1
accesskit_sha256=35b7ca8a6f1e038b5da35e1e9e5a0adaed9bfcf21e1496d29598fbbadcc7043f
accesskit_dir="$out/accesskit"
if [ "$(cat "$accesskit_dir/VERSION" 2>/dev/null || true)" != "$accesskit_version" ]; then
  case "$(uname -s)/$(uname -m)" in
    Linux*/x86_64) accesskit_platform=linux/x86_64; accesskit_library=libaccesskit.a ;;
    Darwin*/arm64) accesskit_platform=macos/arm64; accesskit_library=libaccesskit.a ;;
    Darwin*/x86_64) accesskit_platform=macos/x86_64; accesskit_library=libaccesskit.a ;;
    MINGW*/x86_64|MSYS*/x86_64|CYGWIN*/x86_64) accesskit_platform=windows/x86_64/msvc; accesskit_library=accesskit.lib ;;
    *)
      echo "prebuild: AccessKit no publica bibliotecas para $(uname -s) $(uname -m)" >&2
      exit 1
      ;;
  esac
  accesskit_zip="$out/accesskit-c-$accesskit_version.zip"
  if [ ! -f "$accesskit_zip" ]; then
    echo "prebuild: descargando AccessKit $accesskit_version"
    curl -fsSL --retry 3 -o "$accesskit_zip.part" \
      "https://github.com/AccessKit/accesskit-c/releases/download/$accesskit_version/accesskit-c-$accesskit_version.zip"
    mv "$accesskit_zip.part" "$accesskit_zip"
  fi
  if command -v sha256sum > /dev/null 2>&1; then
    accesskit_actual="$(sha256sum "$accesskit_zip" | cut -d ' ' -f 1)"
  else
    accesskit_actual="$(shasum -a 256 "$accesskit_zip" | cut -d ' ' -f 1)"
  fi
  if [ "$accesskit_actual" != "$accesskit_sha256" ]; then
    rm -f "$accesskit_zip"
    echo "prebuild: el ZIP de AccessKit $accesskit_version tiene el SHA-256 $accesskit_actual y no el esperado $accesskit_sha256; se borró" >&2
    exit 1
  fi
  accesskit_extract="$out/accesskit-extraido"
  rm -rf "$accesskit_dir" "$accesskit_extract"
  mkdir -p "$accesskit_extract"
  if command -v unzip > /dev/null 2>&1; then
    unzip -q "$accesskit_zip" -d "$accesskit_extract"
  elif command -v bsdtar > /dev/null 2>&1; then
    bsdtar -xf "$accesskit_zip" -C "$accesskit_extract"
  elif [ "$windows" = true ]; then
    # El tar.exe de Windows (bsdtar) abre ZIP; el de Git Bash o MSYS2 no.
    "$(cygpath -u "$SYSTEMROOT")/System32/tar.exe" -xf "$(cygpath -w "$accesskit_zip")" -C "$(cygpath -w "$accesskit_extract")"
  else
    echo "prebuild: hace falta unzip o bsdtar para abrir el ZIP de AccessKit" >&2
    exit 1
  fi
  accesskit_source="$accesskit_extract/accesskit-c-$accesskit_version"
  if [ ! -f "$accesskit_source/lib/$accesskit_platform/static/$accesskit_library" ]; then
    echo "prebuild: el ZIP de AccessKit no trae lib/$accesskit_platform/static/$accesskit_library" >&2
    exit 1
  fi
  mkdir -p "$accesskit_dir/lib"
  cp "$accesskit_source/lib/$accesskit_platform/static/$accesskit_library" "$accesskit_dir/lib/"
  cp "$accesskit_source/LICENSE-MIT" "$accesskit_source/LICENSE-APACHE" "$accesskit_source/LICENSE.chromium" \
    "$accesskit_source/Cargo.lock" "$accesskit_dir/"
  rm -rf "$accesskit_extract"
  printf '%s\n' "$accesskit_version" > "$accesskit_dir/VERSION"
fi
