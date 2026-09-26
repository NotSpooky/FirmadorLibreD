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

# Lo que comparten setup.ps1 (instala) y build.ps1 (compila): versiones fijadas, dónde
# queda cada dependencia dentro de -DepsRoot y cómo se encuentran las herramientas.

# Versiones fijadas; cada una tenía al menos 5 días de publicada al elegirla.
$FirmadorVersions = @{
  Git = '2.55.0.5'
  BuildTools = '117.14.41'
  VcToolsWorkload = '1.0.0'
  Llvm = '22.1.8'
  SevenZip = '26.3.0'
  Ldc = '1.43.0'
  Vcpkg = '2026.07.29'
  Mupdf = '1.28.3'
}

# SHA-256 de lo que se descarga fuera de Chocolatey y vcpkg.
$FirmadorChecksums = @{
  Ldc = '60ae3d5e34287aa25433c7550520060a52f9f212e3d5ff6472a9067d8d17e47e'
  Mupdf = '37c3209dc0e06fa4f3781ed44839ad933a9e6143eb4731f99e069204715bcef2'
}

# Bibliotecas de C que se compilan con vcpkg (triplet x64-windows: DLL con /MD).
$FirmadorVcpkgPorts = @('libxml2', 'libxslt', 'openssl', 'sdl2', 'freetype', 'pkgconf')

<#
.SYNOPSIS
  Carpeta de dependencias ya resuelta: -DepsRoot, o .build\windows del paquete.
.DESCRIPTION
  Lanza un error si la ruta tiene espacios, con los que vcpkg y OpenSSL no compilan.
#>
function Resolve-DepsRoot([string] $DepsRoot, [string] $PackageDir) {
  if (-not $DepsRoot) { $DepsRoot = Join-Path $PackageDir '.build\windows' }
  $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DepsRoot)
  if ($full.Contains(' ')) {
    throw "La carpeta de dependencias «$full» tiene espacios, con los que vcpkg y OpenSSL no compilan. " +
      'Indique otra con -DepsRoot, por ejemplo -DepsRoot D:\firmador-deps.'
  }
  return $full
}

<#
.SYNOPSIS
  Rutas de cada dependencia dentro de la carpeta de dependencias.
#>
function Get-BuildLayout([string] $Root) {
  $triplet = Join-Path $Root 'vcpkg\x64-windows'
  $ldc = Join-Path $Root "ldc2-$($FirmadorVersions.Ldc)-windows-x64"
  return @{
    Root = $Root
    Downloads = Join-Path $Root 'descargas'
    Work = Join-Path $Root 'trabajo'
    LdcBin = Join-Path $ldc 'bin'
    VcpkgInstallRoot = Join-Path $Root 'vcpkg'
    VcpkgTriplet = $triplet
    VcpkgMarker = Join-Path $Root 'vcpkg\puertos.txt'
    PkgConfigDir = Join-Path $triplet 'tools\pkgconf'
    Mupdf = Join-Path $Root 'mupdf'
  }
}

<#
.SYNOPSIS
  Ruta de una herramienta: la del PATH o la primera de las ubicaciones conocidas que exista;
  $null si no está.
#>
function Find-Tool([string] $Name, [string[]] $Candidates = @()) {
  $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($command) { return $command.Source }
  foreach ($candidate in $Candidates) {
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

<#
.SYNOPSIS
  Como Find-Tool, pero lanza un error que dice dónde se buscó si la herramienta no está.
#>
function Get-Tool([string] $Name, [string[]] $Candidates = @()) {
  $path = Find-Tool $Name $Candidates
  if (-not $path) {
    throw "No se encontró $Name en el PATH ni en: $($Candidates -join ', '). Ejecute tools\windows\setup.ps1."
  }
  return $path
}

# Ubicaciones donde los instaladores dejan cada herramienta.
function Get-GitCandidates { @("$env:ProgramFiles\Git\cmd\git.exe") }
function Get-ClangCandidates { @("$env:ProgramFiles\LLVM\bin\clang.exe") }
function Get-SevenZipCandidates { @("$env:ProgramFiles\7-Zip\7z.exe") }
function Get-VswherePath { "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" }

<#
.SYNOPSIS
  Carpeta de Visual Studio (o Build Tools) que tiene el compilador de C++ para x64; $null si
  no hay ninguna.
#>
function Find-VisualStudio {
  $vswhere = Get-VswherePath
  if (-not (Test-Path -LiteralPath $vswhere)) { return $null }
  $path = & $vswhere -products * -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
  if ($LASTEXITCODE -ne 0 -or -not $path) { return $null }
  return $path
}

<#
.SYNOPSIS
  Ejecuta un programa externo, muestra su salida y lanza un error con el comando si termina
  con un código que no está en -AllowedExitCodes.
#>
function Invoke-Native {
  param(
    [Parameter(Mandatory)] [string] $What,
    [Parameter(Mandatory)] [string] $FilePath,
    [string[]] $Arguments = @(),
    [int[]] $AllowedExitCodes = @(0)
  )
  Write-Host "==> $What" -ForegroundColor Cyan
  & $FilePath @Arguments | Out-Host
  if ($AllowedExitCodes -notcontains $LASTEXITCODE) {
    throw "$What falló con el código $LASTEXITCODE`: $FilePath $($Arguments -join ' ')"
  }
}
