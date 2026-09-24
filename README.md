# Firmador Libre (versión en D)

Herramienta de escritorio para firmar y validar documentos según la [Política de
Formatos Oficiales de los Documentos Electrónicos Firmados Digitalmente](https://www.mifirmadigital.go.cr/)
de Costa Rica: PDF (PAdES), XML (XAdES), JSON (JAdES), contenedores ASiC-E, OpenDocument,
Office (OOXML) y firmas CMS (CAdES), con tarjetas de firma digital o almacenes PKCS#12.

Esta es una migración del programa original de Java a [D](https://dlang.org/), sin
máquina virtual de Java: un solo ejecutable nativo que usa bibliotecas de C conocidas
(mupdf, OpenSSL, libxml2, libcurl, PC/SC) y una interfaz gráfica hecha con
[dlangui](https://github.com/buggins/dlangui).


## Créditos

Firmador fue creado y es mantenido por sus autores originales:

* Francisco de la Peña Fernández
* Luis Zárate Montero
* Victor Jiménez

y por quienes han contribuido al proyecto a lo largo de los años (ver [AUTHORS.md](AUTHORS.md)).

* Sitio del proyecto: <https://firmador.libre.cr>
* Código original (Java): <https://codeberg.org/firmador/firmador>

Esta versión conserva el comportamiento, los textos, la configuración
(`config.properties`) y el protocolo de Firmador Remoto de la versión Java, de modo que
las páginas y los programas que ya lo usan sigan funcionando. El diseño de las firmas
sigue lo que hacía la biblioteca [DSS](https://github.com/esig/dss) de la Comisión
Europea, que la versión Java usaba.

Firmador es software libre bajo la licencia **GPL versión 3 o posterior** (ver
[COPYING](COPYING)).


## Uso

### Interfaz gráfica

```sh
firmador [documento…]
```

Se abre la ventana; los documentos indicados (o arrastrados sobre ella) quedan listos
para firmar. La primera vez pregunta si usar el **modo simplificado** (una sola vista
para firmar) o el **completo** (lista de documentos, carpetas, conexiones).

Para firmar hace falta la tarjeta de firma digital con su lector y los controladores de
[Soporte Firma Digital](https://soportefirmadigital.com/sfdj/dl.aspx), o un almacén
PKCS#12 (`.p12`/`.pfx`) agregado en *Configuración → Opciones avanzadas*.

`--background` arranca con la ventana minimizada. Si Firmador ya está abierto, abrirlo
otra vez le pasa los documentos a la ventana existente.

### Desde la línea de comandos

Firmar un documento (el PIN se lee de la entrada estándar):

```sh
firmador -dargs entrada.pdf salida.pdf            # con la tarjeta
firmador -dargs entrada.pdf salida.pdf mio.p12    # con un almacén PKCS#12
firmador -dargs -slot1 entrada.pdf salida.pdf     # otra ranura del lector
firmador -dargs -timestamp entrada.pdf salida.pdf # sólo sello de tiempo, sin PIN
```

Atender comandos por lotes desde otro programa (firmar, validar, previsualizar, listar
certificados), con respuestas `SUCCESS`/`ERROR` y JSON:

```sh
firmador -dshell       # escriba «help» para ver los comandos
```

### Firmador Remoto

Las páginas web autorizadas pueden pedir firmas al Firmador abierto en la computadora
(puerto 3516 en `127.0.0.1`), igual que con la versión Java. Se activa desde la pestaña
*Conexión* o con enlaces `firmador:`.


## Compilación

Se necesita un compilador de D ([DMD](https://dlang.org/download.html) 2.113 o posterior,
o LDC), `dub`, un compilador de C, `pkg-config` y las bibliotecas de desarrollo:

| Biblioteca | Arch / Manjaro | Debian / Ubuntu |
|---|---|---|
| mupdf | `libmupdf` | `libmupdf-dev` |
| libxml2 y libxslt | `libxml2 libxslt` | `libxml2-dev libxslt1-dev` |
| OpenSSL 3 | `openssl` | `libssl-dev` |
| libcurl | `curl` | `libcurl4-openssl-dev` |
| PC/SC | `pcsclite` | `libpcsclite-dev` |
| libsecret (llavero) | `libsecret` | `libsecret-1-dev` |
| SDL2 y FreeType (ventana) | `sdl2 freetype2` | `libsdl2-dev libfreetype-dev` |

Luego:

```sh
dub build                   # genera bin/firmador
dub test                    # ejecuta las pruebas unitarias
dub build -b release        # versión optimizada
```

El paso previo (`tools/prebuild.sh`) reúne las cabeceras de C que ImportC necesita
según `pkg-config` y compila el puente con mupdf.


## Instalación en Linux

**Flatpak** (no necesita las bibliotecas de arriba: compila mupdf y el cliente de PC/SC,
y usa el runtime de freedesktop 26.08):

```sh
flatpak-builder --user --install --install-deps-from=flathub --force-clean \
  build-dir packaging/linux/io.github.notspooky.firmadorlibred.yml
flatpak run io.github.notspooky.firmadorlibred
```

Dentro de flatpak, Firmador usa el `pcscd` del sistema para los lectores y las
bibliotecas de las tarjetas instaladas en el sistema (Athena o JCOP4), y guarda su
configuración en `~/.config/firmadorlibre/config-flatpak-properties`.

**En el sistema**, después de `dub build --build=release`:

```sh
sudo packaging/linux/install.sh          # en /usr/local
packaging/linux/install.sh ~/.local      # sólo para el usuario
```

Instala el ejecutable, la entrada del menú (abre PDF, OpenDocument, Office y ASiC-E, y
los enlaces `firmador:` de Firmador Remoto) y los íconos. El resto de comandos (armar el
archivo `.flatpak` para publicar, diagnosticar…) está en [COMMANDS.md](COMMANDS.md).


## Pendiente (TODO)

Lo principal; el detalle está en [PENDING.md](PENDING.md).

* **Empaquetado**: instalador de Windows y paquete `.app` de macOS (con el esquema
  `firmador:` en su `Info.plist`). El flatpak de Linux está listo, falta publicarlo.
* **Aviso de actualizaciones**: está desactivado (`releaseCheckEnabled` en
  `configuration.d`) hasta que apunte a las versiones publicadas de este repositorio.
* **Probar en Windows y macOS**: el código para ambos está escrito (llavero del sistema,
  enlaces `firmador:` en macOS, consola en Windows) pero sólo se ha probado en Linux.
* **Ícono en la bandeja del sistema**: dlangui no lo ofrece; hoy los avisos con la
  ventana oculta usan las notificaciones del escritorio.
* **Accesibilidad**: dlangui no expone la interfaz a lectores de pantalla como lo hacía
  Swing; la navegación con teclado sí funciona.
* **Documentación**: `CONTRACTS.md`, y portar el manual de usuario y las preguntas
  frecuentes.
* **Pruebas**: una configuración de `dub test` sin el aviso del archivo principal, y
  portar las pruebas de la versión Java que falten.
* **Migración de sesiones**: los tokens de las conexiones externas se guardaban en
  `keystore.p12`; esta versión usa su propio almacén cifrado, así que hay que volver a
  iniciar sesión en esos servicios una vez.


## Estructura del proyecto

```
firmador/
├── dub.json                 Proyecto de dub (dependencias, bibliotecas de C)
├── resources/               Lo que va dentro del ejecutable: textos traducidos,
│                            certificados de la jerarquía nacional, plantillas
├── tools/prebuild.sh        Prepara las cabeceras de C y el puente con mupdf
├── packaging/linux/         Flatpak, entrada del menú, AppStream, íconos e instalador
└── src/
    ├── c/, shim/            Enlaces a bibliotecas de C (ImportC) y puente con mupdf
    └── firmador/
        ├── app.d            Punto de entrada: elige ventana, -dargs o -dshell
        ├── configuration.d  Constantes (servicios, puertos, límites)
        ├── settings*.d      Configuración del usuario (config.properties)
        ├── asn1/, x509/,    Formatos criptográficos: DER, certificados, CMS,
        │   cms/, crypto/    sellos de tiempo, OpenSSL
        ├── pdf/, xml/,      Firma de cada formato: PDF, XML, JSON, contenedores
        │   jose/, ooxml/,   ASiC/OpenDocument y Office
        │   containers/
        ├── signers/         Un firmador por formato y la elección del formato
        ├── validation/,     Validación de firmas: cadenas, revocación, reportes
        │   validators/
        ├── cards/, tokens/  Tarjetas (PKCS#11, PC/SC) y almacenes PKCS#12
        ├── documents/       Documentos abiertos y colas de firma y validación
        ├── remote/          Firmador Remoto (servidor HTTP local)
        ├── connections/     Conexiones: Gaudi (BCCR) y servicios externos
        ├── plugins/         Plugins (actualizaciones, bitácora de firmas…)
        ├── gui/             Modos de consola (-dargs, -dshell)
        │   └── desktop/     Ventana con dlangui: pestañas, diálogos, vista previa
        └── util/, net/      Utilidades: ZIP, PNG, fechas, HTTP, escritorio
```

Cada archivo empieza con una descripción de lo que hace y de qué parte de la versión
Java proviene. El mapa completo está en [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md).
