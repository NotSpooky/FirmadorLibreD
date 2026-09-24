/* Firmador is a program to sign documents using AdES standards.

Copyright (C) Firmador authors.

This file is part of Firmador.

Firmador is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Firmador is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Firmador.  If not, see <http://www.gnu.org/licenses/>.  */

/**
 * Constantes de configuración de toda la aplicación: servicios externos, puertos,
 * certificados de la jerarquía nacional incluidos y rutas de las bibliotecas PKCS#11.
 * Los ajustes que cambia el usuario viven en firmador.settings; aquí sólo hay valores
 * fijos de la versión.
 */
module firmador.configuration;

import std.string : strip;

/// Versión de esta compilación (resources/version.txt). Con «SNAPSHOT» se trata como desarrollo.
enum string firmadorVersion = import("version.txt").strip;

/// Sitio del proyecto; se cita en los avisos de actualización y en las firmas.
enum string baseUrl = "https://firmador.libre.cr";

/// Nombre de la aplicación que se deja en las firmas PAdES (/Prop_Build) y en OOXML.
enum string appName = "Firmador " ~ firmadorVersion ~ ", " ~ baseUrl;

/// Servicio de sellado de tiempo (RFC 3161) del BCCR.
enum string tsaUrl = "http://tsa.sinpe.fi.cr/tsaHttp/";

/// Límite de las respuestas de los servicios de validación (sello, OCSP, CRL, AIA).
enum size_t maxValidationResponseBytes = 64 * 1024 * 1024;

/// Tiempo máximo de conexión y de respuesta con los servicios de validación.
enum int validationServiceTimeoutSeconds = 30;

/// Zona horaria con la que se muestran las fechas: Costa Rica no usa horario de verano desde 1992.
enum int costaRicaUtcOffsetHours = -6;

/// Identificador de zona horaria que se registra en las bitácoras y reportes.
enum string costaRicaTimeZoneName = "America/Costa_Rica";

/// Puerto de Firmador Remoto registrado en IANA.
enum ushort defaultRemotePort = 3516;

/// Cuántos puertos por encima y por debajo del oficial puede pedir un origin.
enum ushort remotePortRange = 10;

/// Lo que responde /ok para que una página reconozca que aquí hay un Firmador Libre.
enum string remoteAppId = "firmador-libre";

/// Tamaño máximo del cuerpo de una petición a Firmador Remoto (documentos incluidos).
enum size_t remoteMaxBodyBytes = 256 * 1024 * 1024;

/// Tamaño máximo de la cabecera de una petición a Firmador Remoto.
enum size_t remoteMaxHeaderBytes = 64 * 1024;

/// Conexiones simultáneas que atiende cada puerto de Firmador Remoto.
enum int remoteMaxConnections = 16;

/// Esquema de URL con el que el navegador lanza Firmador Remoto.
enum string remoteUrlScheme = "firmador:";

/**
 * El aviso de actualizaciones (firmador.plugins.checkupdate) consulta y descarga las
 * versiones publicadas. Desactivado hasta que las URL de abajo apunten a las versiones
 * publicadas de este proyecto (@contract release-artifacts): las de la versión Java no
 * son ejecutables de esta.
 */
enum bool releaseCheckEnabled = false;

/// Consulta de la última versión publicada.
enum string releaseUrlCheck = baseUrl ~ "/version.txt";

/// Artefactos nativos publicados por sistema, con su suma SHA-256 en «<artefacto>.sha256».
enum string releaseLinuxUrl = baseUrl ~ "/firmador-linux-x86_64";
enum string releaseMacUrl = baseUrl ~ "/Firmador.zip";
enum string releaseWindowsUrl = baseUrl ~ "/Instalar%20Firmador.exe";

/// Compilación de desarrollo más reciente (versiones «SNAPSHOT»).
enum string releaseSnapshotUrl =
  "https://integracion.libre.cr/job/firmador/job/firmador/job/fixes/lastSuccessfulBuild/artifact/firmador-linux-x86_64";

/// Sufijo de las sumas de verificación que acompañan a cada artefacto.
enum string checksumSuffix = ".sha256";

/// Tiempo de caché de la lista de certificados leída de la tarjeta.
enum long pkcs11CertificateCacheMilliseconds = 30_000;

/// Cada cuánto vuelve a mirar el monitor de tarjetas si PC/SC no avisa de cambios.
enum long smartCardPollIntervalMilliseconds = 5_000;

/// Documentos que se firman, validan o previsualizan a la vez.
enum int maxSigningWorkers = 2;
enum int maxValidationWorkers = 3;
enum int maxPreviewWorkers = 5;

/// Longitud máxima del PIN que se lee por la entrada estándar (modo -dargs).
enum size_t maxPinLength = 128;

/// Espacio reservado para la firma CMS dentro de un PDF (bytes, antes de pasar a hexadecimal).
enum size_t padesSignatureContentSize = 13_312;

/// Espacio reservado para un sello de tiempo de documento dentro de un PDF.
enum size_t padesTimestampContentSize = 3_072;

/// Máximo de entradas de un ZIP (ASiC, OpenDocument, OOXML) que se acepta leer.
enum size_t maxZipEntries = 10_000;

/// Máximo de bytes descomprimidos de un ZIP, en total, para no agotar la memoria.
enum size_t maxZipExpandedBytes = 1024 * 1024 * 1024;

/// Raíces de la jerarquía nacional de firma digital en las que se confía (resources/certs).
immutable string[] trustedRootCertificates = [
  "certs/CA RAIZ NACIONAL - COSTA RICA v2.crt",
  "certs/CA RAIZ NACIONAL COSTA RICA.cer",
];

/**
 * Intermedias de la jerarquía nacional (y de sellado de tiempo). Se incluyen porque el
 * chip de las tarjetas de SINPE no trae las intermedias y sin ellas no se podría firmar
 * nivel B sin Internet (ver CRSigner en la versión Java).
 */
immutable string[] adjunctCertificates = [
  "certs/CA POLITICA PERSONA FISICA - COSTA RICA v2.crt",
  "certs/CA POLITICA PERSONA FISICA - COSTA RICA v2(1).crt",
  "certs/CA POLITICA PERSONA JURIDICA - COSTA RICA v2.crt",
  "certs/CA POLITICA PERSONA JURIDICA - COSTA RICA v2(1).crt",
  "certs/CA POLITICA SELLADO DE TIEMPO - COSTA RICA v2.crt",
  "certs/CA POLITICA SELLADO DE TIEMPO - COSTA RICA v2(1).crt",
  "certs/CA SINPE - PERSONA FISICA v2(1).crt",
  "certs/CA SINPE - PERSONA FISICA v2(2).crt",
  "certs/CA SINPE - PERSONA FISICA v2(3).crt",
  "certs/CA SINPE - PERSONA JURIDICA v2(1).crt",
  "certs/CA SINPE - PERSONA JURIDICA v2(2).crt",
  "certs/CA SINPE - PERSONA JURIDICA v2(3).crt",
  "certs/TSA SINPE v3.crt",
  "certs/TSA SINPE v4.crt",
];

/// Raíz con la que se verifica el TLS del hub del BCCR (Gaudi).
enum string bccrTlsRootCertificate = "certs/CA RAIZ NACIONAL - COSTA RICA v2.crt";

/// Tipos de comprobante electrónico de Hacienda que llevan su política de firma.
immutable string[] electronicReceiptTypes = [
  "FacturaElectronica", "TiqueteElectronico", "NotaDebitoElectronica", "NotaCreditoElectronica",
  "FacturaElectronicaCompra", "FacturaElectronicaExportacion", "MensajeReceptor",
];

/// Política de firma de los comprobantes electrónicos (resolución v4.3), tras el cambio de URL.
enum string haciendaPolicyId =
  "https://atv.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.3/"
  ~ "Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf";

/// La misma política con la URL anterior, que todavía aparece en comprobantes firmados.
enum string haciendaPolicyLegacyId =
  "https://www.hacienda.go.cr/ATV/ComprobanteElectronico/docs/esquemas/2016/v4.3/"
  ~ "Resoluci%C3%B3n_General_sobre_disposiciones_t%C3%A9cnicas_comprobantes_electr%C3%B3nicos_para_efectos_tributarios.pdf";

/// SHA-256 en base64 del documento de la política de Hacienda.
enum string haciendaPolicyDigestBase64 = "0h7Q3dFHhu0bHbcZEgVc07cEcDlquUeG08HG6Iototo=";

/// Copia local del documento de la política, para validarla sin descargarlo.
enum string haciendaPolicyDocument =
  "dgt/Resolucion_General_sobre_disposiciones_tecnicas_comprobantes_electronicos_para_efectos_tributarios.pdf";

/// Hub SignalR del BCCR con el que habla la conexión Gaudi.
enum string bccrUrl = "https://www.firmadigital.go.cr";
enum string bccrStartNegotiation = "/wcfv2/Bccr.Firma.Fva.Hub/signalr/negotiate?clientProtocol=1.4"
  ~ "&connectionData=%5B%7B%22name%22%3A%22administradordeclientes%22%7D%5D";
enum string bccrConnect = "/connect";

/// Agente con el que se presentan las integraciones ante los servicios externos.
enum string integrationUserAgent = "HttpClient (lang=D; os=linux; version=2.0)";

/// OID de uso extendido de autenticación de cliente, que separa el certificado de autenticación del de firma.
enum string clientAuthenticationEkuOid = "1.3.6.1.5.5.7.3.2";

/// Descripción que se deja en las firmas OOXML.
enum string ooxmlSignatureDescription = "Esto es una firma con firmador libre https://firmador.libre.cr/";

/// Nombre del directorio de configuración dentro de ~/.config (o %APPDATA% en Windows).
enum string configDirectoryName = "firmadorlibre";

/// Variable de entorno que fija la biblioteca PKCS#11.
enum string pkcs11LibraryEnvironmentVariable = "LIBASEP11";

/// Biblioteca PKCS#11 de Athena (IDProtect), la de las tarjetas de firma digital de Costa Rica.
version (Windows) {
  enum string athenaPkcs11Library = `System32\asepkcs.dll`;
  enum string jcop4Pkcs11Library = `Smart Card Middleware\bin\idoPKCS.dll`;
} else version (OSX) {
  enum string athenaPkcs11Library = "/Library/Application Support/Athena/libASEP11.dylib";
  enum string jcop4Pkcs11Library = "/Library/SCMiddleware/libidop11.dylib";
} else {
  enum string athenaPkcs11Library = "/usr/lib/x64-athena/libASEP11.so";
  enum string jcop4Pkcs11Library = "/usr/lib/SCMiddleware/libidop11.so";
}

/// Dónde ve flatpak el sistema anfitrión (permiso host-os), para usar sus bibliotecas PKCS#11.
enum string flatpakHostRoot = "/run/host";

/// Nombres de clase de los plugins, iguales a los de la versión Java para conservar config.properties.
enum string dummyPluginName = "cr.libre.firmador.plugins.DummyPlugin";
enum string checkUpdatePluginName = "cr.libre.firmador.plugins.CheckUpdatePlugin";
enum string documentSignLogsPluginName = "cr.libre.firmador.plugins.DocumentSignLogs";
enum string installerPluginName = "cr.libre.firmador.plugins.InstallerPlugin";

/// Entrada del llavero del sistema donde se guarda la contraseña del almacén de tokens.
enum string keyringServiceName = "firmador-keystore-password";
enum string keyringAccountName = "keystore";
