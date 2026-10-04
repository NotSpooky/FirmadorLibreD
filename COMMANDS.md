# Comandos

Todo se ejecuta desde la raíz del repositorio. Las bibliotecas que hacen falta para
compilar están en el [README](README.md#compilación).


## Compilar y probar

| Comando | Qué hace |
|---|---|
| `dub build` | Compila `bin/firmador` (con información de depuración) |
| `dub build --build=release` | Compila la versión optimizada, la que se empaqueta |
| `dub test` | Ejecuta las pruebas unitarias (bloques `unittest`) |
| `dub run -- [documento…]` | Compila y abre la ventana |
| `sh tools/prebuild.sh` | Paso previo que dub ejecuta solo: cabeceras de C en `src/cinclude`, `.build/libfirmadorshim.a` y, en Windows, el ícono del `.exe` en `.build/firmador.res` (`CC`, `AR` y `RC` cambian el compilador, el archivador y el compilador de recursos) |


## Compilar en Windows

Desde la carpeta del repositorio, en PowerShell. Los detalles están en el
[README](README.md#windows).

| Comando | Qué hace |
|---|---|
| `powershell -NoProfile -ExecutionPolicy Bypass -File tools\windows\setup.ps1` | Como administrador: instala lo que falte (Chocolatey, Git, Build Tools, LLVM, 7-Zip, LDC, bibliotecas de vcpkg y mupdf) y compila |
| `powershell -NoProfile -ExecutionPolicy Bypass -File tools\windows\build.ps1` | Compila `bin\firmador.exe` y copia a su lado las DLL que necesita, con el runtime de Visual C++ |
| `… build.ps1 -Build debug` | Lo mismo, con información de depuración |
| `… setup.ps1 -DepsRoot D:\firmador-deps` | Deja las dependencias en esa carpeta (sin espacios) en vez de `.build\windows`; `build.ps1` la recibe igual |
| `… setup.ps1 -SkipBuild` | Sólo prepara las dependencias, sin compilar (para registrar antes otra copia de dlangui con `dub add-local`) |
| `… build.ps1 -Test` | Compila y además corre las pruebas (`dub test`) con el mismo entorno |


## Ejecutar

| Comando | Qué hace |
|---|---|
| `bin/firmador [documento…]` | Abre la ventana con esos documentos |
| `bin/firmador --background` | Arranca con la ventana minimizada |
| `bin/firmador -dargs entrada.pdf salida.pdf [almacen.p12]` | Firma desde la consola (PIN por la entrada estándar); también `-slotN`, `-timestamp`, `-visible-timestamp` |
| `bin/firmador -dshell` | Atiende comandos por lotes (`help` los lista) |
| `bin/firmador -Djnlp.remoteOrigin="http://localhost:8000#3516#False"` | Simula que una página lanza Firmador Remoto (como un enlace `firmador:`) |


## Diagnosticar

| Comando | Qué hace |
|---|---|
| `bin/firmador 2>&1 \| tee firmador.log` | Guarda la bitácora; su nivel es `advancedlogs=` en `config.properties` (`INFO`, `ALL`…) y `showlogs=true` muestra la pestaña de bitácoras |
| `pgrep -x firmador \| xargs -r kill` | Cierra una instancia que quedó abierta (la siguiente le pasaría los documentos) |
| `fuser -k 3516/tcp` | Libera el puerto de Firmador Remoto |
| `flatpak run --command=sh io.github.notspooky.firmadorlibred` | Abre una consola dentro del sandbox del flatpak |


## Empaquetar en Linux

Los archivos están en `packaging/linux/`.

| Comando | Qué hace |
|---|---|
| `packaging/linux/install.sh [prefijo]` | Instala `bin/firmador` ya compilado, la entrada del menú (documentos y esquema `firmador:`), AppStream e íconos en el prefijo (`/usr/local` si no se indica; `DESTDIR=…` para armar paquetes) |
| `flatpak-builder --user --install --install-deps-from=flathub --force-clean build-dir packaging/linux/io.github.notspooky.firmadorlibred.yml` | Construye el flatpak y lo instala para el usuario (descarga el runtime y el SDK 26.08 si faltan) |
| `flatpak-builder --repo=repository --install-deps-from=flathub --force-clean build-dir packaging/linux/io.github.notspooky.firmadorlibred.yml` | Construye el flatpak en el repositorio local `repository/` |
| `flatpak build-bundle --runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo repository firmadorlibre.flatpak io.github.notspooky.firmadorlibred` | Arma el archivo `firmadorlibre.flatpak` para publicar, a partir de `repository/`; al instalarlo, flatpak baja el runtime de Flathub aunque ese remoto no esté configurado |
| `flatpak install --user firmadorlibre.flatpak` | Instala ese archivo |
| `flatpak run io.github.notspooky.firmadorlibred [argumentos…]` | Ejecuta el flatpak (también con `-dargs` o `-dshell`) |
| `flatpak uninstall --user io.github.notspooky.firmadorlibred` | Desinstala el flatpak |
| `desktop-file-validate packaging/linux/*.desktop` | Revisa la entrada del menú |
| `appstreamcli validate --pedantic packaging/linux/*.metainfo.xml` | Revisa los datos de AppStream |

Si `flatpak-builder` no está instalado, `flatpak run org.flatpak.Builder …` acepta los
mismos argumentos; se instala con `flatpak install flathub org.flatpak.Builder`.

## Integración continua (GitHub Actions)

`.github/workflows/ci.yml` corre en cada cambio a `main`, en cada pull request y a mano
(«Run workflow» en la pestaña Actions):

| Trabajo | Qué hace |
|---|---|
| Linux (pruebas) | `dub test` con DMD y compilación optimizada con LDC, en Arch con los paquetes de su archivo de hace 7 días |
| Linux (flatpak) | Construye el flatpak con el manifiesto de `packaging/linux/` |
| Windows | `setup.ps1 -SkipBuild` y `build.ps1 -Test` en `windows-2022`; empaqueta lo de `bin\` sin `.pdb`. Las dependencias quedan guardadas entre ejecuciones mientras no cambien `common.ps1` ni `setup.ps1` |
| macOS (Apple Silicon) | Pruebas y compilación con LDC y las bibliotecas de Homebrew, que el ejecutable necesita instaladas |

Los paquetes se llaman `firmador_<linux|windows|macos>_<versión>.<flatpak|zip>`, con la versión
`v_0_4_0` para la etiqueta `0.4.0` y `dev_<commit>` en las demás ejecuciones. Se descargan:

| Desde | Cómo |
|---|---|
| Una ejecución | Pestaña Actions → la ejecución → «Artifacts», al pie (GitHub los entrega dentro de un zip; duran 90 días) |
| La consola | `gh run download <id-de-la-ejecución>` (`gh run list` muestra los id) |
| Una versión | `git tag 0.4.0 && git push origin 0.4.0` crea un borrador en Releases con los tres paquetes y `SHA256SUMS`; se revisa y se publica desde ahí |

Variables del repositorio (Settings → Secrets and variables → Actions → Variables):

| Variable | Valor |
|---|---|
| `DLANGUI_REPOSITORY` | Repositorio de la copia de dlangui con los arreglos de Win32, por ejemplo `NotSpooky/dlangui`; sin ella, el zip de Windows se compila con dlangui del registro y el trabajo avisa |
| `DLANGUI_REF` | Rama o etiqueta de esa copia, por ejemplo `win32-fixes-0.10.8` |

Para revisar el flujo antes de subirlo: `actionlint .github/workflows/ci.yml`.
