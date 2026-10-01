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
  las DLL que necesita para ejecutarse: las de vcpkg, libcurl de LDC y las del runtime de
  Visual C++ que se usan, así que bin\ funciona en un Windows sin nada más instalado. No
  cambia variables de entorno del sistema ni requiere administrador.

.PARAMETER DepsRoot
  Carpeta de las dependencias que usó setup.ps1. Por omisión, .build\windows dentro del
  repositorio.

.PARAMETER Build
  Tipo de compilación de dub: release (optimizada, por omisión) o debug.

.PARAMETER Test
  Además corre las pruebas (dub test) con el mismo entorno, después de dejar las DLL en bin\.
#>
[CmdletBinding()]
param(
  [string] $DepsRoot,
  [ValidateSet('release', 'debug')] [string] $Build = 'release',
  [switch] $Test
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

# Runtime de Visual C++ junto al programa (Microsoft permite copiar lo de VC\Redist): lo usan
# el ejecutable, las DLL de vcpkg y el C++ que mupdf lleva adentro, y un Windows sin el
# «Visual C++ Redistributable» no lo tiene. Se copian sólo las DLL que importa algún archivo
# de bin\, incluidas las que importan las copiadas.
if (-not $env:VCToolsRedistDir) { throw 'El entorno de Visual Studio no definió VCToolsRedistDir.' }
$runtimeRoot = Join-Path $env:VCToolsRedistDir 'x64'
$runtime = Get-Item -Path (Join-Path $runtimeRoot 'Microsoft.VC*.CRT') | Select-Object -First 1
if (-not $runtime) { throw "No se encontró el runtime de Visual C++ (Microsoft.VC*.CRT) en $runtimeRoot." }
$runtimeDlls = @{}
foreach ($dll in Get-ChildItem -LiteralPath $runtime.FullName -Filter '*.dll') { $runtimeDlls[$dll.Name.ToLowerInvariant()] = $dll }
$pending = [System.Collections.Generic.Queue[string]]::new()
foreach ($file in Get-ChildItem -LiteralPath $bin -File | Where-Object { $_.Extension -in '.exe', '.dll' }) {
  $pending.Enqueue($file.FullName)
}
$copiedRuntime = @{}
while ($pending.Count) {
  $file = $pending.Dequeue()
  $dependents = & dumpbin /nologo /dependents $file
  if ($LASTEXITCODE -ne 0) { throw "dumpbin no pudo leer las dependencias de $file (código $LASTEXITCODE)." }
  foreach ($name in $dependents | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -match '^\S+\.dll$' }) {
    if (-not $runtimeDlls.ContainsKey($name) -or $copiedRuntime.ContainsKey($name)) { continue }
    $target = Join-Path $bin $runtimeDlls[$name].Name
    Copy-Item -LiteralPath $runtimeDlls[$name].FullName -Destination $target -Force
    $copiedRuntime[$name] = $true
    $pending.Enqueue($target)
  }
}
Write-Host "Runtime de Visual C++ ($($runtime.Name)): $(($copiedRuntime.Keys | Sort-Object) -join ', ')"
Write-Host "Listo: $(Join-Path $bin 'firmador.exe')" -ForegroundColor Green

if ($Test) {
  # El ejecutable de las pruebas queda en bin\, junto a las DLL que acaban de copiarse.
  Push-Location $packageDir
  try {
    Invoke-Native 'Probando Firmador' $dub @('test', "--compiler=$ldc")
  } finally {
    Pop-Location
  }
}
