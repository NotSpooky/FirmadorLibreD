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

/// Origen de datos de validación; la firma nivel B no necesita ninguno.
interface ValidationDataSource {
  /**
   * Sello de tiempo sobre el resumen dado.
   *
   * Throws: Exception si el servicio no está disponible o rechaza la solicitud.
   */
  TimeStampToken timestamp(DigestAlgorithm digest, const(ubyte)[] imprint) @safe;

  /// Respuesta OCSP para el certificado, o la razón por la que no la hay en `failure`.
  bool ocsp(const Certificate certificate, const Certificate issuer, out OcspResponse response, out string failure)
    @safe;

  /// CRL del certificado según sus puntos de distribución, o la razón en `failure`.
  bool crl(const Certificate certificate, out CertificateRevocationList list, out string failure) @safe;

  /// Certificados del emisor según AIA (vacío si no hay o no se pudieron descargar).
  Certificate[] issuers(const Certificate certificate) @safe;
}

private HttpOptions serviceOptions() @safe {
  HttpOptions options;
  import core.time : dur;
  options.connectTimeout = dur!"seconds"(validationServiceTimeoutSeconds);
  options.operationTimeout = dur!"seconds"(validationServiceTimeoutSeconds * 2);
  options.maxResponseBytes = maxValidationResponseBytes;
  return options;
}

/// Servicios en línea con caché de CRL y certificados de emisor durante la ejecución.
final class OnlineValidationSource : ValidationDataSource {
  private string timestampUrl;
  private CertificateRevocationList[string] crlCache;
  private Certificate[][string] issuerCache;
  private Mutex lock;

  this(string timestampUrl = tsaUrl) @safe {
    this.timestampUrl = timestampUrl;
    lock = new Mutex;
  }

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

  bool ocsp(const Certificate certificate, const Certificate issuer, out OcspResponse result, out string failure)
      @trusted {
    if (certificate.ocspUrls.length == 0) {
      failure = "El certificado no indica un servicio OCSP";
      return false;
    }
    auto request = buildOcspRequest(certificate, issuer);
    foreach (url; certificate.ocspUrls) {
      try {
        auto response = httpPost(url, request, "application/ocsp-request", null, serviceOptions());
        if (response.status != 200) {
          failure = format("El servicio OCSP %s respondió %d", url, response.status);
          warning(failure);
          continue;
        }
        result = parseOcspResponse(response.body);
        return true;
      } catch (Exception exception) {
        failure = format("Falló la consulta OCSP a %s: %s", url, exception.msg);
        warning(failure);
      }
    }
    return false;
  }

  bool crl(const Certificate certificate, out CertificateRevocationList list, out string failure) @trusted {
    if (certificate.crlUrls.length == 0) {
      failure = "El certificado no indica dónde está su CRL";
      return false;
    }
    foreach (url; certificate.crlUrls) {
      lock.lock();
      auto cached = url in crlCache;
      bool fresh = cached !is null && (cached.nextUpdate.isNull || cached.nextUpdate.get > Clock.currTime);
      if (fresh) {
        list = *cached;
        lock.unlock();
        return true;
      }
      lock.unlock();
      try {
        auto response = httpGet(url, null, serviceOptions());
        if (response.status != 200) {
          failure = format("La CRL %s respondió %d", url, response.status);
          warning(failure);
          continue;
        }
        list = parseCrl(response.body);
        lock.lock();
        crlCache[url] = list;
        lock.unlock();
        return true;
      } catch (Exception exception) {
        failure = format("No se pudo descargar la CRL %s: %s", url, exception.msg);
        warning(failure);
      }
    }
    return false;
  }

  Certificate[] issuers(const Certificate certificate) @trusted {
    Certificate[] found;
    foreach (url; certificate.caIssuersUrls) {
      lock.lock();
      auto cached = url in issuerCache;
      lock.unlock();
      if (cached !is null) {
        found ~= *cached;
        continue;
      }
      try {
        auto response = httpGet(url, null, serviceOptions());
        if (response.status != 200) {
          warning(format("El certificado de emisor %s respondió %d", url, response.status));
          continue;
        }
        auto downloaded = certificatesFromAia(response.body);
        lock.lock();
        issuerCache[url] = downloaded;
        lock.unlock();
        found ~= downloaded;
        if (downloaded.length) break;
      } catch (Exception exception) {
        warning(format("No se pudo descargar el certificado de emisor %s: %s", url, exception.msg));
      }
    }
    return found;
  }
}

/// Sin servicios en línea (firma nivel B sin Internet, validación sin conexión).
final class OfflineValidationSource : ValidationDataSource {
  TimeStampToken timestamp(DigestAlgorithm digest, const(ubyte)[] imprint) @safe {
    throw new TimeStampException("No hay conexión con el servicio de sellado");
  }

  bool ocsp(const Certificate certificate, const Certificate issuer, out OcspResponse response, out string failure)
      @safe {
    failure = "Validación sin conexión";
    return false;
  }

  bool crl(const Certificate certificate, out CertificateRevocationList list, out string failure) @safe {
    failure = "Validación sin conexión";
    return false;
  }

  Certificate[] issuers(const Certificate certificate) @safe {
    return [];
  }
}

/**
 * Certificados de una descarga AIA: un certificado DER o PEM, o un PKCS#7 sólo con
 * certificados (.p7c).
 *
 * Throws: Exception si el contenido no es ninguno de esos formatos.
 */
Certificate[] certificatesFromAia(const(ubyte)[] content) @safe {
  try {
    return parseCertificates(content);
  } catch (Exception) {
    auto signedData = parseSignedData(content);
    return signedData.certificates;
  }
}
