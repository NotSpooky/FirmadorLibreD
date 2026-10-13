# Contratos entre archivos

Algunas formas de datos las comparten archivos que el compilador no puede revisar juntos:
JSON por HTTP, archivos que lee otro programa, nombres de paquetes que busca la
actualización. Cada participante lleva en su documentación `@contract <nombre>`, y aquí está
lo que significa cada nombre. Antes de cambiar una de estas formas:

```sh
grep -rn "@contract <nombre>" src tools packaging .github
```

da todos los archivos que tienen que seguir de acuerdo (algunos nombres quedan partidos
entre dos líneas del comentario: si no aparece, buscar `@contract` solo). Cambiar uno sin
los demás compila y pasa las pruebas.

Muchos contratos son con algo de afuera: las páginas que usan Firmador Remoto, los
servicios del BCCR o de terceros, los programas que usan el modo `-dshell`, o los archivos
que dejaba la versión Java, que esta versión sigue leyendo.

| Contrato | Qué se acuerda | Participantes | Del otro lado |
|---|---|---|---|
| `release-artifacts` | Las versiones publicadas: etiqueta `X.Y.Z`; paquetes `firmador_<linux\|windows\|macos>_v_X_Y_Z.<flatpak\|msi\|zip>` en las versiones de GitHub de `NotSpooky/FirmadorLibreD`; `SHA256SUMS` con líneas `<sha256>  <archivo>`; el ZIP de macOS con `Firmador.app/Contents/…`; el instalador deja su carpeta en `HKMU\Software\Firmador Libre\InstallFolder` y acepta `LAUNCHFIRMADOR` | `.github/workflows/ci.yml`, `packaging/windows/firmador.wxs`, `tools/macos/bundle.sh`, `src/firmador/configuration.d`, `src/firmador/plugins/checkupdate.d` | Las copias instaladas, que se actualizan con esto |
| `accesskit-c` | La versión de accesskit-c (0.23.1) y el SHA-256 de su ZIP; de él se toman la biblioteca estática de cada plataforma, que dub.json pone en el enlazador (`.build/accesskit/lib`, configuración `minimal-accesskit` de dlangui), y el Cargo.lock con que se arma el aviso de licencias | `tools/prebuild.sh`, `packaging/linux/io.github.notspooky.firmadorlibred.yml`, `tools/accesskit-notices.sh` y `packaging/licenses/accesskit.txt` (lo que genera), `dub.json` (sin etiqueta: JSON no admite comentarios) | Las declaraciones en D de `accesskit.h` de esa versión, en la copia de dlangui (`dlangui.platforms.common.accesskit`) |
| `remote-api` | Las rutas HTTP de Firmador Remoto en `127.0.0.1` (`/ok`, `/doRegister`, `/certificates`, `/sign`, `/signDocument`…) y cuándo exigen un origen autorizado | `src/firmador/remote/server.d` | Las páginas que piden firmas |
| `remote-dto` | Los mensajes JSON de Firmador Remoto, de las conexiones y del shell, con los nombres de campo de la versión Java | `src/firmador/remote/dto.d` | Las páginas y servicios que los envían o reciben |
| `settings-json` | El objeto `settings` en JSON (Firmador Remoto, shell y conexiones): los nombres de los campos públicos de `Settings` | `src/firmador/settings.d`, `src/firmador/settingsjson.d` | Las páginas, servicios y programas que mandan ajustes |
| `card-json` | El JSON de las credenciales de firma que publican `/certificates` y el comando `getcertificates` | `src/firmador/cards/cardinfo.d` | Las páginas y programas que eligen el certificado |
| `shell-protocol` | El modo `-dshell`: una línea `comando\|json\|pin` por pedido y dos por respuesta (`SUCCESS`/`ERROR` y el JSON) | `src/firmador/gui/shell.d` | Los programas que lo usan por tuberías |
| `external-service` | Los servicios externos con documentos virtuales: inicio de sesión en el navegador, tokens, lista de documentos y firma en el servidor | `src/firmador/connections/external.d` | Los servicios dados de alta |
| `firmadorconn` | Los archivos `.firmadorconn` con que un servicio externo se da de alta | `src/firmador/connections/config.d` | Los servicios que los publican |
| `services-urls-xml` | `servicesUrls.xml` del directorio de configuración, con las conexiones guardadas | `src/firmador/connections/config.d` | La versión Java, que usa el mismo archivo |
| `bccr-signalr` | La negociación y los mensajes SignalR (serverSentEvents) con Gaudi, del BCCR | `src/firmador/connections/gaudi.d` | El servicio del BCCR |
| `pkcs12-store-json` | `pkcs12cards.json`: los datos del titular de cada almacén PKCS#12 (nunca la contraseña) | `src/firmador/cards/pkcs12store.d` | La versión Java, con el mismo formato |
| `document-list-csv` | `document_list.csv`: nombre, ruta, ruta de salida y configuración de cada documento de la lista | `src/firmador/gui/desktop/documentlist.d` | La versión Java, con el mismo formato |
| `instance-mailbox` | `.firmador.lock` y `.firmador.command` del directorio de configuración: la segunda instancia deja su pedido y la primera lo atiende | `src/firmador/util/singleinstance.d` | Otra instancia de Firmador |
| `simple-report-xml` | El reporte de validación con la forma del reporte simple de DSS, al que se le aplica `resources/xslt/html/simple-report.xslt` | `src/firmador/validation/report.d` | La hoja XSLT, que viene de la versión Java |

Cuando una forma se puede expresar como un tipo de un módulo que importan todos los
participantes, el compilador la revisa y no hace falta un contrato: es preferible.
