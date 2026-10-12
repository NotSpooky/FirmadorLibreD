# Política de firma de código (Code signing policy)

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by
[SignPath Foundation](https://signpath.org/).

*Firma de código gratuita de SignPath.io, con certificado de SignPath Foundation.*

> **Estado:** la solicitud a SignPath Foundation está en trámite. Hasta que la apruebe, los
> paquetes de Windows se publican sin firmar.

## Qué se firma

* Los paquetes de Windows de las versiones publicadas en
  [Releases](https://github.com/NotSpooky/FirmadorLibreD/releases): `firmador.exe`, dentro
  del instalador (`.msi`) y del `.zip`, y el instalador.
* Se compilan en GitHub Actions a partir de este repositorio
  ([.github/workflows/ci.yml](.github/workflows/ci.yml)), y SignPath verifica que vienen de
  ese flujo antes de firmarlos.
* Sólo se firma lo que se compila desde este repositorio. Las bibliotecas de terceros que
  acompañan al programa (las DLL de vcpkg, libcurl y el runtime de Visual C++) van tal como
  sus autores las publican.
* Cada firma la aprueba manualmente una de las personas aprobadoras.

## Equipo

| Rol | Personas |
|---|---|
| Autores (committers) y revisores | [Christian Durán Carvajal (NotSpooky)](https://github.com/NotSpooky) |
| Aprobadores | [Christian Durán Carvajal (NotSpooky)](https://github.com/NotSpooky) |

Los cambios de quienes no son autores se revisan antes de incorporarlos. Todas las cuentas
del equipo en GitHub y en SignPath usan verificación en dos pasos.

## Privacidad

Firmador Libre no envía información a otros sistemas salvo para lo que el usuario pide
(firmar con sello de tiempo, validar, sus conexiones) y para buscar actualizaciones, que se
puede desactivar. El detalle está en [PRIVACY.md](PRIVACY.md).
