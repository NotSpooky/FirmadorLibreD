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
  Instala lo necesario para compilar Firmador en Windows y lo compila (build.ps1).

.DESCRIPTION
  Programas del sistema, con Chocolatey (que se instala si falta), sólo los que no estén:
  Git (su sh ejecuta tools/prebuild.sh), Visual Studio 2022 Build Tools con el entorno de
  C++ y el SDK de Windows, LLVM (clang y llvm-ar compilan el puente con mupdf) y 7-Zip.

  Dependencias del proyecto, todas dentro de -DepsRoot: LDC, las bibliotecas de C que
  compila vcpkg (libxml2, libxslt, OpenSSL, SDL2, FreeType y pkgconf) y mupdf compilado
  desde su código. Las descargas se verifican con SHA-256; al terminar se borran, igual
  que el código y los archivos intermedios de vcpkg y mupdf.

  Se puede volver a ejecutar: omite lo que ya está. Todo corre en esta misma ventana, sin
  reabrir PowerShell. Requiere PowerShell como administrador.

.PARAMETER DepsRoot
  Carpeta de las dependencias del proyecto, sin espacios. Por omisión, .build\windows
  dentro del repositorio.
#>
[CmdletBinding()]
param([string] $DepsRoot)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Invoke-WebRequest descarga mucho más lento mientras dibuja la barra de progreso.
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor
  [Net.SecurityProtocolType]::Tls12
. (Join-Path $PSScriptRoot 'common.ps1')

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'setup.ps1 instala programas del sistema: ejecútelo en PowerShell abierto como administrador.'
}

$packageDir = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$layout = Get-BuildLayout (Resolve-DepsRoot $DepsRoot $packageDir)
Write-Host "Dependencias del proyecto en $($layout.Root)"

<#
.SYNOPSIS
  Descarga un archivo en la carpeta de descargas y comprueba su SHA-256; devuelve su ruta.
#>
function Save-Verified([string] $Url, [string] $Sha256) {
  New-Item -ItemType Directory -Force $layout.Downloads | Out-Null
  $file = Join-Path $layout.Downloads ([IO.Path]::GetFileName(([Uri] $Url).AbsolutePath))
  Write-Host "==> Descargando $Url" -ForegroundColor Cyan
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $file
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash
  if ($actual -ne $Sha256) {
    Remove-Item -LiteralPath $file -Force
    throw "El SHA-256 de $Url no coincide: se esperaba $Sha256 y llegó $actual."
  }
  return $file
}

<#
.SYNOPSIS
  Chocolatey; si no está, lo instala con su instalador oficial después de comprobar que
  lleva una firma Authenticode válida de Chocolatey Software.
#>
function Get-Chocolatey {
  $candidates = @("$env:ALLUSERSPROFILE\chocolatey\bin\choco.exe")
  $choco = Find-Tool 'choco' $candidates
  if ($choco) { return $choco }
  New-Item -ItemType Directory -Force $layout.Downloads | Out-Null
  $installer = Join-Path $layout.Downloads 'chocolatey-install.ps1'
  Write-Host '==> Descargando el instalador de Chocolatey' -ForegroundColor Cyan
  Invoke-WebRequest -UseBasicParsing -Uri 'https://community.chocolatey.org/install.ps1' -OutFile $installer
  $signature = Get-AuthenticodeSignature -LiteralPath $installer
  if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike '*Chocolatey Software*') {
    throw "El instalador de Chocolatey no tiene una firma válida de Chocolatey Software (estado: $($signature.Status))."
  }
  & $installer | Out-Host
  return Get-Tool 'choco' $candidates
}

<#
.SYNOPSIS
  Instala un paquete de Chocolatey en la versión fijada. Avisa si el instalador pide
  reiniciar (códigos 1641 y 3010): la compilación puede seguir sin reiniciar.
#>
function Install-ChocoPackage([string] $Choco, [string] $Id, [string] $Version, [string] $PackageParameters) {
  $arguments = @('install', $Id, '--version', $Version, '--yes', '--no-progress')
  if ($PackageParameters) { $arguments += @('--package-parameters', $PackageParameters) }
  Invoke-Native "Instalando $Id $Version" $Choco $arguments -AllowedExitCodes 0, 1641, 3010
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "El instalador de $Id pidió reiniciar Windows; la compilación sigue, pero conviene reiniciar al terminar."
  }
}

<#
.SYNOPSIS
  Instala con Chocolatey los programas del sistema que falten.
#>
function Install-SystemTools {
  $missing = @()
  if (-not (Find-Tool 'git' (Get-GitCandidates))) { $missing += 'git' }
  if (-not (Find-VisualStudio)) { $missing += 'buildtools' }
  if (-not (Find-Tool 'clang' (Get-ClangCandidates))) { $missing += 'llvm' }
  if (-not (Find-Tool '7z' (Get-SevenZipCandidates))) { $missing += '7zip' }
  if ($missing.Count -eq 0) {
    Write-Host 'Git, Visual Studio Build Tools, LLVM y 7-Zip ya están instalados.'
    return
  }
  $choco = Get-Chocolatey
  if ($missing -contains 'git') { Install-ChocoPackage $choco 'git' $FirmadorVersions.Git }
  if ($missing -contains 'buildtools') {
    Install-ChocoPackage $choco 'visualstudio2022buildtools' $FirmadorVersions.BuildTools `
      '--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive --norestart --nocache --locale en-US'
    # Añade el entorno de C++ también a unas Build Tools que ya estaban instaladas sin él.
    Install-ChocoPackage $choco 'visualstudio2022-workload-vctools' $FirmadorVersions.VcToolsWorkload '--includeRecommended'
    if (-not (Find-VisualStudio)) {
      throw 'Visual Studio Build Tools quedó instalado sin el compilador de C++ para x64 ' +
        '(Microsoft.VisualStudio.Component.VC.Tools.x86.x64): revise el registro del instalador en %TEMP%.'
    }
  }
  if ($missing -contains 'llvm') { Install-ChocoPackage $choco 'llvm' $FirmadorVersions.Llvm }
  if ($missing -contains '7zip') { Install-ChocoPackage $choco '7zip' $FirmadorVersions.SevenZip }
}

<#
.SYNOPSIS
  Descarga LDC (con dub) y lo extrae en la carpeta de dependencias.
#>
function Install-Ldc {
  if (Test-Path -LiteralPath (Join-Path $layout.LdcBin 'ldc2.exe')) {
    Write-Host "LDC $($FirmadorVersions.Ldc) ya está."
    return
  }
  $version = $FirmadorVersions.Ldc
  $archive = Save-Verified "https://github.com/ldc-developers/ldc/releases/download/v$version/ldc2-$version-windows-x64.7z" `
    $FirmadorChecksums.Ldc
  $sevenZip = Get-Tool '7z' (Get-SevenZipCandidates)
  Invoke-Native "Extrayendo LDC $version" $sevenZip @('x', $archive, "-o$($layout.Root)", '-y', '-bso0', '-bsp0')
}

<#
.SYNOPSIS
  Compila con vcpkg las bibliotecas de C y las deja en la carpeta de dependencias; borra
  vcpkg (con sus descargas y archivos intermedios) al terminar.
#>
function Install-VcpkgLibraries {
  $expected = "$($FirmadorVersions.Vcpkg) $($FirmadorVcpkgPorts -join ' ')"
  if ((Test-Path -LiteralPath $layout.VcpkgMarker) -and
      ((Get-Content -LiteralPath $layout.VcpkgMarker -Raw).Trim() -eq $expected)) {
    Write-Host 'Las bibliotecas de vcpkg ya están.'
    return
  }
  $git = Get-Tool 'git' (Get-GitCandidates)
  # vcpkg usa git mientras compila.
  $env:Path = "$(Split-Path $git);$env:Path"
  $tool = Join-Path $layout.Work 'vcpkg'
  if (Test-Path -LiteralPath $tool) { Remove-Item -LiteralPath $tool -Recurse -Force }
  Invoke-Native "Descargando vcpkg $($FirmadorVersions.Vcpkg)" $git @('-c', 'advice.detachedHead=false', 'clone',
    '--depth', '1', '--branch', $FirmadorVersions.Vcpkg, 'https://github.com/microsoft/vcpkg', $tool)
  Invoke-Native 'Preparando vcpkg' (Join-Path $tool 'bootstrap-vcpkg.bat') @('-disableMetrics')
  # Sin caché binaria: vcpkg no deja copias en %LOCALAPPDATA%.
  $env:VCPKG_BINARY_SOURCES = 'clear'
  Invoke-Native "Compilando $($FirmadorVcpkgPorts -join ', ')" (Join-Path $tool 'vcpkg.exe') (@('install') +
    $FirmadorVcpkgPorts + @('--triplet', 'x64-windows', "--x-install-root=$($layout.VcpkgInstallRoot)",
    '--clean-after-build'))
  # tools/prebuild.sh llama a pkg-config; pkgconf va junto a sus DLL.
  Copy-Item -LiteralPath (Join-Path $layout.PkgConfigDir 'pkgconf.exe') `
    -Destination (Join-Path $layout.PkgConfigDir 'pkg-config.exe') -Force
  Set-Content -LiteralPath $layout.VcpkgMarker -Value $expected -Encoding Ascii
  Remove-Item -LiteralPath $tool -Recurse -Force
}

<#
.SYNOPSIS
  Descarga el código de mupdf, lo compila con su solución de Visual Studio y deja en la
  carpeta de dependencias sólo las cabeceras, libmupdf.lib y mupdf.pc.
#>
function Install-Mupdf {
  $library = Join-Path $layout.Mupdf 'lib\libmupdf.lib'
  if (Test-Path -LiteralPath $library) {
    Write-Host "mupdf $($FirmadorVersions.Mupdf) ya está."
    return
  }
  $version = $FirmadorVersions.Mupdf
  $archive = Save-Verified "https://mupdf.com/downloads/archive/mupdf-$version-source.tar.gz" $FirmadorChecksums.Mupdf
  New-Item -ItemType Directory -Force $layout.Work | Out-Null
  $source = Join-Path $layout.Work "mupdf-$version-source"
  if (Test-Path -LiteralPath $source) { Remove-Item -LiteralPath $source -Recurse -Force }
  # Los únicos enlaces simbólicos del archivo están en envoltorios y ejemplos que no se
  # compilan; Windows no los crea sin permisos especiales.
  Invoke-Native "Extrayendo mupdf $version" "$env:SystemRoot\System32\tar.exe" @('-xzf', $archive, '-C', $layout.Work,
    '--exclude', "mupdf-$version-source/thirdparty/zxing-cpp/wrappers",
    '--exclude', "mupdf-$version-source/thirdparty/freeglut/progs")
  $msbuild = & (Get-VswherePath) -products * -latest -requires Microsoft.Component.MSBuild `
    -find 'MSBuild\**\Bin\amd64\MSBuild.exe' | Select-Object -First 1
  if (-not $msbuild) { throw 'No se encontró MSBuild de Visual Studio Build Tools.' }
  # libmupdf.lib incluye las bibliotecas de las que depende (LinkLibraryDependencies).
  Invoke-Native "Compilando mupdf $version" $msbuild @((Join-Path $source 'platform\win32\mupdf.sln'),
    '/t:libmupdf', '/p:Configuration=Release', '/p:Platform=x64', '/p:PlatformToolset=v143', '/m', '/nologo',
    '/verbosity:minimal')
  $built = Join-Path $source 'platform\win32\x64\Release\libmupdf.lib'
  if (-not (Test-Path -LiteralPath $built)) { throw "La compilación de mupdf no dejó $built." }
  $pkgconfig = Join-Path $layout.Mupdf 'lib\pkgconfig'
  New-Item -ItemType Directory -Force $pkgconfig | Out-Null
  Copy-Item -LiteralPath (Join-Path $source 'include') -Destination $layout.Mupdf -Recurse -Force
  Copy-Item -LiteralPath $built -Destination $library -Force
  @(
    'prefix=${pcfiledir}/../..'
    'libdir=${prefix}/lib'
    'includedir=${prefix}/include'
    ''
    'Name: mupdf'
    'Description: MuPDF'
    "Version: $version"
    'Cflags: -I${includedir}'
    'Libs: -L${libdir} -llibmupdf'
  ) | Set-Content -LiteralPath (Join-Path $pkgconfig 'mupdf.pc') -Encoding Ascii
  Remove-Item -LiteralPath $source -Recurse -Force
}

<#
.SYNOPSIS
  Borra las descargas, los archivos de trabajo y las copias temporales de Chocolatey. Un
  archivo que no se pueda borrar sólo se avisa: no afecta la compilación.
#>
function Remove-Scratch {
  foreach ($path in @($layout.Downloads, $layout.Work, "$env:TEMP\chocolatey")) {
    if (-not (Test-Path -LiteralPath $path)) { continue }
    try {
      Remove-Item -LiteralPath $path -Recurse -Force
    } catch {
      Write-Warning "No se pudo borrar $path`: $($_.Exception.Message)"
    }
  }
}

try {
  Install-SystemTools
  Install-Ldc
  Install-VcpkgLibraries
  Install-Mupdf
} finally {
  Remove-Scratch
}
& (Join-Path $PSScriptRoot 'build.ps1') -DepsRoot $layout.Root
