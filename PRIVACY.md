# Privacidad

Firmador Libre funciona en su computadora: los documentos que firma o valida no salen de
ella, no hay cuentas, publicidad ni estadísticas de uso. Sólo se conecta a otros sistemas
en estos casos:

| Cuándo | Con quién | Qué se envía |
|---|---|---|
| Al firmar con sello de tiempo (niveles T, LT y LTA) | El servicio de sello de tiempo del SINPE (`tsa.sinpe.fi.cr`) | El resumen criptográfico (hash) de la firma, no el documento |
| Al firmar en los niveles LT y LTA, y al validar firmas | Los servicios de las autoridades certificadoras que indican los propios certificados (OCSP, listas de revocación y certificados de emisor) | Qué certificado se está consultando |
| Al abrir la ventana | La API de GitHub (`api.github.com`), para saber si hay una versión nueva | Una consulta anónima, con la versión de Firmador; GitHub ve la dirección IP, como en cualquier página |
| Al aceptar una actualización | GitHub (`github.com`), de donde se descarga | Nada más que la descarga |
| Si activa la conexión con Gaudi | El Banco Central de Costa Rica (`firmadigital.go.cr`) | Los certificados de su tarjeta y las firmas que usted autoriza |
| Si da de alta un servicio externo | Ese servicio | Los certificados de su tarjeta, el inicio de sesión que usted hace en el navegador y las firmas que usted autoriza |
| Si una página usa Firmador Remoto | Esa página, desde su navegador | Las firmas que usted autoriza. Firmador escucha sólo en `127.0.0.1` (su propia computadora) y atiende sólo a las páginas que usted autorizó |
| Si abre un enlace (Acerca de, avisos) | El sitio del enlace, en su navegador | Lo que envía cualquier navegador |

La búsqueda de actualizaciones se desactiva en *Configuración → Opciones avanzadas →
Plugins*, quitando `CheckUpdatePlugin`. Los tokens de las conexiones se guardan cifrados
en su computadora, con la clave en el llavero del sistema cuando lo hay, y las bitácoras,
también sólo en ella.

El PIN de la tarjeta y las contraseñas de los almacenes PKCS#12 no se guardan ni se envían:
se usan en el momento y se borran de la memoria.
