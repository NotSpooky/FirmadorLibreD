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
 * Servicios en línea que alimentan la firma y la validación (OnlineTSPSource,
 * OnlineOCSPSource, OnlineCRLSource y DefaultAIASource de DSS): sello de tiempo, OCSP,
 * CRL y certificados de emisor por AIA. Las respuestas sólo se interpretan aquí; su
 * verificación está en firmador.validation.revocation y firmador.validation.cmsverify.
 */
module firmador.validation.sources;

import core.sync.mutex : Mutex;
import std.bigint : BigInt;
import std.datetime.systime : Clock, SysTime;
import std.exception : enforce;
import std.format : format;
import std.logger : info, warning;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.cms.ocsp;
import firmador.cms.signeddata : parseSignedData;
import firmador.cms.tsp;
import firmador.configuration : tsaUrl, maxValidationResponseBytes, validationServiceTimeoutSeconds;
import firmador.crypto.digest;
import firmador.crypto.random : secureRandomBytes;
import firmador.net.http;
import firmador.x509.certificate;
import firmador.x509.crl;

private HttpOptions serviceOptions() pure @safe {
  HttpOptions options;
  import core.time : dur;
  options.connectTimeout = dur!"seconds"(validationServiceTimeoutSeconds);
  options.operationTimeout = dur!"seconds"(validationServiceTimeoutSeconds * 2);
  options.maxResponseBytes = maxValidationResponseBytes;
  return options;
}

/**
 * Servicios en línea con caché de CRL y certificados de emisor durante la ejecución. Donde
 * se recibe una, null significa sin conexión (firma nivel B sin Internet, validación sin
 * conexión): no se descargan emisores ni revocaciones.
 */
final class ValidationSource {
  private string timestampUrl;
  private CertificateRevocationList[string] crlCache;
  private Certificate[][string] issuerCache;
  private Mutex lock;

  this(string timestampUrl = tsaUrl) @safe {
    this.timestampUrl = timestampUrl;
    lock = new Mutex;
  }

  /**
   * Sello de tiempo sobre el resumen dado.
   *
   * Throws: Exception si el servicio no está disponible o rechaza la solicitud.
   */
  TimeStampToken timestamp(DigestAlgorithm digest, const(ubyte)[] imprint) @trusted {
    ubyte[] nonceBytes = secureRandomBytes(8);
    nonceBytes[0] &= 0x7F;
    BigInt nonce = 0;
    foreach (b; nonceBytes) nonce = nonce * 256 + b;
    auto request = buildTimeStampRequest(digest, imprint, nonce);
    auto response = httpPost(timestampUrl, request.der, "application/timestamp-query", null, serviceOptions());
    enforce!TimeStampException(response.status == 200,
      format("El servicio de sellado %s respondió %d", timestampUrl, response.status));
    auto token = parseTimeStampResponse(response.body, request);
    info("Sello de tiempo recibido de ", timestampUrl, " con fecha ", token.info.genTime.toISOExtString);
    return token;
  }

  /// Respuesta OCSP para el certificado, o la razón por la que no la hay en `failure`.
  bool ocsp(const Certificate certificate, const Certificate issuer, out OcspResponse result, out string failure)
      @safe {
    if (certificate.ocspUrls.length == 0) {
      failure = "El certificado no indica un servicio OCSP";
      return false;
    }
    auto request = buildOcspRequest(certificate, issuer);
    return fromFirstUrl!OcspResponse(certificate.ocspUrls, (url) => parseOcspResponse(serviceBody("El servicio OCSP",
      url, httpPost(url, request, "application/ocsp-request", null, serviceOptions()))), result, failure);
  }

  /// CRL del certificado según sus puntos de distribución, o la razón en `failure`.
  bool crl(const Certificate certificate, out CertificateRevocationList list, out string failure) @safe {
    if (certificate.crlUrls.length == 0) {
      failure = "El certificado no indica dónde está su CRL";
      return false;
    }
    return fromFirstUrl!CertificateRevocationList(certificate.crlUrls, (url) {
      synchronized (lock) {
        auto cached = url in crlCache;
        if (cached !is null && (cached.nextUpdate.isNull || cached.nextUpdate.get > Clock.currTime)) return *cached;
      }
      auto downloaded = parseCrl(serviceBody("La CRL", url, httpGet(url, null, serviceOptions())));
      synchronized (lock) crlCache[url] = downloaded;
      return downloaded;
    }, list, failure);
  }

  /// Certificados del emisor según AIA (vacío si no hay o no se pudieron descargar).
  Certificate[] issuers(const Certificate certificate) @safe {
    Certificate[] found;
    string failure;
    fromFirstUrl!(Certificate[])(certificate.caIssuersUrls, (url) {
      synchronized (lock) {
        auto cached = url in issuerCache;
        if (cached !is null && cached.length) return *cached;
      }
      auto downloaded = certificatesFromAia(serviceBody("El certificado de emisor", url,
        httpGet(url, null, serviceOptions())));
      synchronized (lock) issuerCache[url] = downloaded;
      enforce(downloaded.length, "La descarga no trae certificados");
      return downloaded;
    }, found, failure);
    return found;
  }
}

/// Cuerpo de la respuesta de un servicio de validación, si respondió 200.
private const(ubyte)[] serviceBody(string service, string url, HttpResponse response) pure @safe {
  enforce(response.status == 200, format("%s %s respondió %d", service, url, response.status));
  return response.body;
}

/**
 * Prueba las URL en orden hasta que `fetch` obtenga algo de una. Cada fallo se registra
 * como aviso, porque se sigue con la siguiente, y el último queda en `failure`.
 *
 * Returns: true si alguna URL dio `result`.
 */
private bool fromFirstUrl(T)(const string[] urls, scope T delegate(string url) @safe fetch, out T result,
    out string failure) @safe {
  foreach (url; urls) {
    try {
      result = fetch(url);
      return true;
    } catch (Exception exception) {
      failure = format("Falló la consulta a %s: %s", url, exception.msg);
      warning(failure);
    }
  }
  return false;
}

/**
 * Certificados de una descarga AIA: un certificado DER o PEM, o un PKCS#7 sólo con
 * certificados (.p7c).
 *
 * Throws: Exception si el contenido no es ninguno de esos formatos, con el motivo de cada
 * intento.
 */
Certificate[] certificatesFromAia(const(ubyte)[] content) pure @safe {
  try {
    return parseCertificates(content);
  } catch (Exception asCertificate) {
    try {
      return parseSignedData(content).certificates;
    } catch (Exception asPkcs7) {
      throw new Exception(format("La descarga no es un certificado (%s) ni un PKCS#7 con certificados (%s)",
        asCertificate.msg, asPkcs7.msg), asPkcs7);
    }
  }
}

@("should report why both formats failed when an AIA download is neither a certificate nor PKCS#7")
unittest {
  import std.algorithm : canFind;
  import std.exception : collectException;
  auto failure = collectException(certificatesFromAia(cast(const(ubyte)[]) "no es DER"));
  assert(failure !is null && failure.msg.canFind("certificado (") && failure.msg.canFind("PKCS#7 con certificados ("));
}
