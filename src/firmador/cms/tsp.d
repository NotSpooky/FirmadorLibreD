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
 * Sellos de tiempo RFC 3161: la solicitud que se envía al servicio del BCCR
 * (firmador.configuration.tsaUrl) y la lectura de la respuesta y del TSTInfo. La
 * verificación criptográfica del sello, como la de cualquier SignedData, está en
 * firmador.validation.cmsverify.
 */
module firmador.cms.tsp;

import std.bigint : BigInt;
import std.datetime.systime : SysTime;
import std.exception : enforce;
import std.format : format;

import firmador.asn1.der;
import firmador.asn1.oids;
import firmador.cms.signeddata;
import firmador.crypto.digest;

/// Solicitud de sello lista para enviar, con el nonce para comprobar la respuesta.
struct TimeStampRequest {
  ubyte[] der;
  BigInt nonce;
  DigestAlgorithm digest;
  immutable(ubyte)[] imprint;
}

/// Contenido firmado de un sello de tiempo.
struct TstInfo {
  string policy;
  DigestAlgorithm imprintAlgorithm;
  immutable(ubyte)[] imprint;
  BigInt serialNumber;
  SysTime genTime;
  bool hasNonce;
  BigInt nonce;
}

/// Sello de tiempo: el ContentInfo completo, su SignedData y su TSTInfo.
struct TimeStampToken {
  immutable(ubyte)[] der;
  SignedData signedData;
  TstInfo info;
}

/**
 * Sella un resumen SHA-256 ya calculado (SigningServices.timestampDigest en
 * firmador.signers.common); lo reciben los formatos que agregan sellos.
 */
alias Timestamper = TimeStampToken delegate(const(ubyte)[] digest) @safe;

/// El servicio de sellado rechazó la solicitud o respondió algo que no corresponde.
class TimeStampException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/**
 * TimeStampReq v1 con el resumen dado, el nonce y certReq verdadero (el servicio incluye
 * su certificado, que hace falta para validar el sello).
 */
TimeStampRequest buildTimeStampRequest(DigestAlgorithm digest, const(ubyte)[] imprint, BigInt nonce) @safe {
  enforce(imprint.length == digestLength(digest), "El resumen no tiene la longitud de su algoritmo");
  TimeStampRequest request;
  request.nonce = nonce;
  request.digest = digest;
  request.imprint = imprint.idup;
  auto messageImprint = derSequence(derAlgorithm(digestOid(digest), true), derOctetString(imprint));
  request.der = derSequence(derInteger(1), messageImprint, derIntegerBig(nonce), derBoolean(true));
  return request;
}

/**
 * Lee un TimeStampToken (ContentInfo con SignedData cuyo contenido es un TSTInfo).
 *
 * Throws: Asn1Exception si la estructura no es la de un sello.
 */
TimeStampToken parseTimeStampToken(const(ubyte)[] der) @safe {
  TimeStampToken token;
  token.der = der.idup;
  token.signedData = parseSignedData(der);
  enforce!Asn1Exception(token.signedData.eContentType == oidTstInfo, "El sello de tiempo no contiene un TSTInfo");
  enforce!Asn1Exception(token.signedData.hasEContent, "El sello de tiempo no trae su TSTInfo");
  enforce!Asn1Exception(token.signedData.signerInfos.length == 1, "El sello de tiempo debe tener un único firmante");
  token.info = parseTstInfo(token.signedData.eContent);
  return token;
}

/// Interpreta el TSTInfo.
TstInfo parseTstInfo(const(ubyte)[] der) @safe {
  TstInfo info;
  auto reader = parseDer(der).reader();
  reader.next("la versión del TSTInfo");
  info.policy = reader.next("la política del sello").oidValue;
  auto imprint = reader.next("el resumen sellado").reader();
  info.imprintAlgorithm = digestFromOid(parseAlgorithmIdentifier(imprint.next("el algoritmo sellado"),
    "El algoritmo del resumen sellado").oid);
  info.imprint = imprint.next("el valor sellado").octetStringValue.idup;
  info.serialNumber = reader.next("el serial del sello").integerValue;
  info.genTime = reader.next("la fecha del sello").timeValue;
  while (!reader.empty) {
    auto field = reader.next("un campo opcional del TSTInfo");
    if (field.isUniversal(UniversalTag.integer)) {
      info.hasNonce = true;
      info.nonce = field.integerValue;
    }
  }
  return info;
}

/**
 * Lee la respuesta del servicio de sellado y comprueba que conteste a la solicitud:
 * estado concedido, mismo resumen y mismo nonce.
 *
 * Throws: TimeStampException con el estado y el texto del servicio si lo rechazó, o si la
 * respuesta no corresponde a la solicitud.
 */
TimeStampToken parseTimeStampResponse(const(ubyte)[] der, const TimeStampRequest request) @safe {
  auto reader = parseDer(der).reader();
  auto status = reader.next("el estado del sello").reader();
  long code = status.next("el código de estado").smallIntegerValue;
  if (code != 0 && code != 1) {
    string text;
    DerElement freeText;
    if (status.nextUniversal(UniversalTag.sequence, freeText)) {
      foreach (line; freeText.children()) text ~= line.stringValue ~ " ";
    }
    throw new TimeStampException(format("El servicio de sellado rechazó la solicitud (estado %d) %s", code, text));
  }
  enforce!TimeStampException(!reader.empty, "El servicio de sellado no devolvió el sello");
  auto token = parseTimeStampToken(reader.next("el sello").raw);
  enforce!TimeStampException(token.info.imprintAlgorithm == request.digest && token.info.imprint == request.imprint,
    "El sello de tiempo recibido no corresponde al resumen enviado");
  enforce!TimeStampException(token.info.hasNonce && token.info.nonce == request.nonce,
    "El sello de tiempo recibido no corresponde al nonce enviado");
  return token;
}

@("should build a request that carries the imprint and the nonce when asking for a time stamp")
unittest {
  auto imprint = digestOf(DigestAlgorithm.sha256, cast(const(ubyte)[]) "datos");
  auto request = buildTimeStampRequest(DigestAlgorithm.sha256, imprint, BigInt("123456789012345"));
  auto fields = parseDer(request.der).children();
  assert(fields[0].smallIntegerValue == 1);
  assert(fields[1].children()[1].octetStringValue == imprint);
  assert(fields[2].integerValue == BigInt("123456789012345"));
  assert(fields[3].booleanValue);
}

@("should report the TSA status text when the service rejects the request")
unittest {
  import std.exception : collectExceptionMsg;
  import std.algorithm : canFind;
  auto request = buildTimeStampRequest(DigestAlgorithm.sha256, new ubyte[32], BigInt(1));
  auto rejected = derSequence(derSequence(derInteger(2), derSequence(derUtf8String("politica no admitida"))));
  auto message = collectExceptionMsg(parseTimeStampResponse(rejected, request));
  assert(message.canFind("estado 2") && message.canFind("politica no admitida"));
}
