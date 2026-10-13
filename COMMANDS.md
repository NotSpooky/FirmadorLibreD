# Comandos

Todo se ejecuta desde la raíz del repositorio. Las bibliotecas que hacen falta para
compilar están en el [README](README.md#compilar).


## Compilar y probar

| Comando | Qué hace |
|---|---|
| `dub build` | Compila `bin/firmador` (con información de depuración) |
| `dub build --build=release` | Compila la versión optimizada, la que se empaqueta |
| `dub test` | Ejecuta las pruebas unitarias (bloques `unittest`) |
| `dub run -- [documento…]` | Compila y abre la ventana |
| Cambiar de dlangui | Es la copia con los arreglos de Windows y macOS (`NotSpooky/dlangui`, rama `win32-fixes-0.10.8`), una dependencia git que dub clona: se cambia el commit en `dub.json`, `dub.selections.json` y el manifiesto de flatpak (la fuente de dlangui y su carpeta) |
| `sh tools/macos/bundle.sh firmador.zip` | En macOS, después de `dub build --build=release`: arma `Firmador.app` en `.build/macos` con las bibliotecas de Homebrew adentro (necesita `dylibbundler`, `sdl2-compat` y `freetype` de Homebrew), lo firma ad hoc, prueba que arranque y lo comprime |
| `sh tools/prebuild.sh` | Paso previo que dub ejecuta solo: cabeceras de C en `src/cinclude`, `.build/libfirmadorshim.a`, la biblioteca de AccessKit (lectores de pantalla) en `.build/accesskit`, descargada una vez por versión y verificada con su SHA-256, y, en Windows, el ícono y los datos de la versión del `.exe` en `.build/firmador.res` (`CC`, `AR` y `RC` cambian el compilador, el archivador y el compilador de recursos) |
| `sh tools/accesskit-notices.sh` | Después de compilar, al cambiar la versión de AccessKit: rehace `packaging/licenses/accesskit.txt`, el aviso de licencias de AccessKit y de los paquetes de Rust que lleva su biblioteca (descarga cada uno de crates.io y lo verifica con el SHA-256 de su Cargo.lock) |
| `sh tools/set-version.sh 0.8.0` | Pone esa versión (X.Y.Z, con un sufijo como `-dev` si no es publicada) en `resources/version.txt` y en la entrada de AppStream; la CI lo hace en cada compilación |


## Compilar en Windows

Desde la carpeta del repositorio, en PowerShell. Los detalles están en el
[README](README.md#windows).

| Comando | Qué hace |
|---|---|
| `powershell -NoProfile -ExecutionPolicy Bypass -File tools\windows\setup.ps1` | Como administrador: instala lo que falte (Chocolatey, Git, Build Tools, LLVM, 7-Zip, LDC, bibliotecas de vcpkg y mupdf) y compila |
| `powershell -NoProfile -ExecutionPolicy Bypass -File tools\windows\build.ps1` | Compila `bin\firmador.exe` y copia a su lado las DLL que necesita, con el runtime de Visual C++ |
| `… build.ps1 -Build debug` | Lo mismo, con información de depuración |
| `… setup.ps1 -DepsRoot D:\firmador-deps` | Deja las dependencias en esa carpeta (sin espacios) en vez de `.build\windows`; `build.ps1` la recibe igual |
| `… setup.ps1 -SkipBuild` | Sólo prepara las dependencias, sin compilar |
| `… build.ps1 -Test` | Compila y además corre las pruebas (`dub test`) con el mismo entorno |
| `dotnet tool install --global wix --version 5.0.2` | Una vez: instala WiX 5, con el que se arma el instalador (no uno más nuevo: desde WiX 6 la licencia agrega la Open Source Maintenance Fee) |
| `… -File tools\windows\installer.ps1` | Después de `build.ps1`: arma `firmador.msi` con lo de `bin\` y lo valida (ICE); `-Output` cambia la ruta y `-Version` la versión, que por omisión es la de `resources\version.txt` |
| `msiexec /i firmador.msi` | Instala para el usuario, sin administrador (en `%LOCALAPPDATA%\Programs\Firmador Libre`), y abre Firmador al terminar |
| `msiexec /i firmador.msi ALLUSERS=1` | Como administrador: instala para todos los usuarios, en `Program Files` |
| `msiexec /i firmador.msi /qn LAUNCHFIRMADOR=0` | Instalación desatendida, sin abrir Firmador |
| `msiexec /x firmador.msi` | Desinstala (también desde *Configuración → Aplicaciones*) |


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
| Windows | `setup.ps1 -SkipBuild` y `build.ps1 -Test` en `windows-2022`; empaqueta lo de `bin\` sin `.pdb` en el `.zip` y en el instalador (`installer.ps1`, con WiX 5). En las versiones publicadas, si SignPath está configurado (abajo), los firma antes de publicarlos. Las dependencias quedan guardadas entre ejecuciones mientras no cambien `common.ps1` ni `setup.ps1` |
| macOS (Apple Silicon) | Pruebas y compilación con LDC y las bibliotecas de Homebrew en `macos-26`; `tools/macos/bundle.sh` arma `Firmador.app` con esas bibliotecas (también SDL2, SDL3 y FreeType) adentro, firma ad hoc y prueba que arranque sin Homebrew. Sirve desde macOS 26 |

Los paquetes se llaman `firmador_<linux|windows|macos>_<versión>.<flatpak|msi|zip>`, con la versión
`v_0_4_0` para la etiqueta `0.4.0` y `dev_<commit>` en las demás ejecuciones; la actualización
automática los busca con esos nombres ([CONTRACTS.md](CONTRACTS.md), `release-artifacts`). Se descargan:

| Desde | Cómo |
|---|---|
| Una ejecución | Pestaña Actions → la ejecución → «Artifacts», al pie (GitHub los entrega dentro de un zip; duran 90 días) |
| La consola | `gh run download <id-de-la-ejecución>` (`gh run list` muestra los id) |
| Una versión | `git tag 0.4.0 && git push origin 0.4.0` crea un borrador en Releases con los paquetes, `SHA256SUMS` y el enlace a la política de firma; se revisa y se publica desde ahí (ver abajo) |

Para revisar el flujo antes de subirlo: `actionlint .github/workflows/ci.yml`.

## Versiones y actualizaciones

* Las etiquetas son la versión: `X.Y.Z`, sin `v`. La CI la pone en el programa, el `.exe`, el
  instalador y Firmador.app (`tools/set-version.sh`), y rechaza etiquetas con otra forma.
* `resources/version.txt` lleva la versión de desarrollo, la última publicada con `-dev`
  (`0.8.0-dev`); las compilaciones que no son de una etiqueta salen como
  `0.8.0-dev.<commit>`. Después de publicar una versión, se pone ahí la nueva con `-dev`
  (`sh tools/set-version.sh 0.8.1-dev` después de publicar 0.8.1).
* La actualización automática consulta la última versión **publicada** (no los borradores)
  en GitHub y sólo instala lo que coincide con su `SHA256SUMS`. En Windows instala el `.msi`
  si Firmador se instaló con él; en macOS reemplaza Firmador.app; en Linux, en flatpak y con
  el `.zip` de Windows sólo avisa. Las versiones de desarrollo no se actualizan.
* Quien usa la `0.7.4` o una anterior no tiene esta actualización: tiene que instalar una
  vez el `.msi` (o el Firmador.app nuevo) a mano.

## Firma con SignPath

La firma de los paquetes de Windows queda lista en la CI y se activa al configurarla. Una
vez aprobada la solicitud en <https://signpath.org/apply> (la política que se pide está en
[CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md)):

1. En SignPath: vincular el sistema de compilación de GitHub (*Trusted build systems*) con el
   proyecto, crear la política de firma (por ejemplo `release-signing`) y la configuración de
   artefacto con el contenido de `packaging/windows/signpath-artifact-configuration.xml`, y un
   token de API de un usuario que pueda enviar solicitudes al proyecto.
2. En GitHub (*Settings → Secrets and variables → Actions*): el secreto `SIGNPATH_API_TOKEN`
   y las variables `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` y
   `SIGNPATH_SIGNING_POLICY_SLUG`, y `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG` si la
   configuración no es la predeterminada del proyecto.

Desde entonces, en cada etiqueta el trabajo de Windows sube el `.zip` y el `.msi`, espera
hasta una hora a que se apruebe la firma en SignPath y publica los firmados. Las demás
compilaciones no se firman. Mientras falte `SIGNPATH_ORGANIZATION_ID`, todo sigue sin firmar.

