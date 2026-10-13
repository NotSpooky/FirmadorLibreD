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
  Arma el instalador de Firmador (MSI) con lo que build.ps1 dejó en bin\.

.DESCRIPTION
  Compila packaging\windows\firmador.wxs con WiX 5 y valida el resultado con las pruebas
  (ICE) de Windows Installer. El instalador lleva firmador.exe, sus DLL y curl-ca-bundle.crt;
  se instala para el usuario, sin permisos de administrador, y reemplaza versiones anteriores.

  Necesita el comando wix: «dotnet tool install --global wix --version 5.0.2». Es WiX 5 y no
  uno más nuevo porque desde WiX 6 la licencia agrega la Open Source Maintenance Fee, que se
  mide por los ingresos de quien compila y no por los de este proyecto.

.PARAMETER Output
  Ruta del .msi. Por omisión, firmador.msi en la carpeta del repositorio.

.PARAMETER Version
  Versión X.Y.Z[-sufijo]. Por omisión, la de resources\version.txt, que es la que lleva el
  programa; el instalador usa sólo X.Y.Z.
#>
[CmdletBinding()]
param(
  [string] $Output,
  [string] $Version
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'common.ps1')

$packageDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$bin = Join-Path $packageDir 'bin'
$source = Join-Path $packageDir 'packaging\windows\firmador.wxs'
if (-not $Output) { $Output = Join-Path $packageDir 'firmador.msi' }
if (-not $Version) { $Version = (Get-Content -Raw -LiteralPath (Join-Path $packageDir 'resources\version.txt')).Trim() }

# Windows Installer compara X.Y.Z, con X e Y hasta 255 y Z hasta 65535.
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$') {
  throw "La versión '$Version' no es X.Y.Z[-sufijo]"
}
if ([int] $Matches[1] -gt 255 -or [int] $Matches[2] -gt 255 -or [int] $Matches[3] -gt 65535) {
  throw "La versión '$Version' pasa los límites de Windows Installer (255.255.65535)"
}
$core = "$($Matches[1]).$($Matches[2]).$($Matches[3])"

foreach ($required in @('firmador.exe', 'curl-ca-bundle.crt', 'libcurl.dll', 'licencias\firmador-COPYING.txt')) {
  if (-not (Test-Path -LiteralPath (Join-Path $bin $required))) {
    throw "Falta bin\$required. Compile antes con tools\windows\build.ps1."
  }
}
$wix = Find-Tool 'wix' @("$env:USERPROFILE\.dotnet\tools\wix.exe")
if (-not $wix) {
  throw 'No se encontró wix. Instálelo con «dotnet tool install --global wix --version 5.0.2».'
}

Invoke-Native "Armando el instalador $core" $wix @('build', '-arch', 'x64', '-d', "Version=$core", '-bindpath',
  "bin=$bin", '-o', $Output, $source)
Invoke-Native 'Validando el instalador (ICE)' $wix @('msi', 'validate', $Output)
Write-Host "Listo: $Output"
