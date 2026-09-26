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

<#
.SYNOPSIS
  Compila Firmador en Windows con las dependencias que instaló setup.ps1.

.DESCRIPTION
  Carga el entorno x64 de Visual Studio sólo para este proceso (ImportC y el enlazador lo
  necesitan), pone en el PATH LDC, LLVM, el sh de Git y pkg-config, apunta PKG_CONFIG_PATH
  y LIB a las bibliotecas de -DepsRoot y compila con dub. Deja bin\firmador.exe junto con
  las DLL que necesita para ejecutarse: las de vcpkg y libcurl de LDC. No cambia variables
  de entorno del sistema ni requiere administrador.

.PARAMETER DepsRoot
  Carpeta de las dependencias que usó setup.ps1. Por omisión, .build\windows dentro del
  repositorio.

.PARAMETER Build
  Tipo de compilación de dub: release (optimizada, por omisión) o debug.
#>
[CmdletBinding()]
param(
  [string] $DepsRoot,
  [ValidateSet('release', 'debug')] [string] $Build = 'release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

$packageDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$layout = Get-BuildLayout (Resolve-DepsRoot $DepsRoot $packageDir)

$ldc = Join-Path $layout.LdcBin 'ldc2.exe'
$dub = Join-Path $layout.LdcBin 'dub.exe'
$required = @($ldc, $dub, (Join-Path $layout.PkgConfigDir 'pkg-config.exe'), (Join-Path $layout.Mupdf 'lib\libmupdf.lib'),
  (Join-Path $layout.VcpkgTriplet 'lib\libxml2.lib'))
foreach ($path in $required) {
  if (-not (Test-Path -LiteralPath $path)) {
    throw "Falta $path. Ejecute tools\windows\setup.ps1 (con el mismo -DepsRoot) en PowerShell como administrador."
  }
}

$visualStudio = Find-VisualStudio
if (-not $visualStudio) {
  throw 'No se encontró Visual Studio Build Tools con el compilador de C++ para x64. Ejecute tools\windows\setup.ps1.'
}
& (Join-Path $visualStudio 'Common7\Tools\Launch-VsDevShell.ps1') -Arch amd64 -HostArch amd64 -SkipAutomaticLocation |
  Out-Null

# dub ejecuta tools/prebuild.sh con el sh de Git, que usa clang, llvm-ar y pkg-config.
$git = Get-Tool 'git' (Get-GitCandidates)
$gitBin = Join-Path (Split-Path (Split-Path $git)) 'bin'
$llvmBin = Split-Path (Get-Tool 'clang' (Get-ClangCandidates))
$env:Path = (@($layout.LdcBin, $llvmBin, $gitBin, $layout.PkgConfigDir, $env:Path) -join ';')
$env:PKG_CONFIG_PATH = "$($layout.VcpkgTriplet)\lib\pkgconfig;$($layout.Mupdf)\lib\pkgconfig"
# El enlazador busca en LIB las bibliotecas de libs-windows de dub.json.
$env:LIB = "$($layout.VcpkgTriplet)\lib;$($layout.Mupdf)\lib;$env:LIB"

Push-Location $packageDir
try {
  Invoke-Native "Compilando Firmador ($Build)" $dub @('build', "--compiler=$ldc", "--build=$Build")
} finally {
  Pop-Location
}

$bin = Join-Path $packageDir 'bin'
Copy-Item -Path (Join-Path $layout.VcpkgTriplet 'bin\*.dll') -Destination $bin -Force
foreach ($file in @('libcurl.dll', 'curl-ca-bundle.crt')) {
  Copy-Item -LiteralPath (Join-Path $layout.LdcBin $file) -Destination $bin -Force
}
Write-Host "Listo: $(Join-Path $bin 'firmador.exe')" -ForegroundColor Green
