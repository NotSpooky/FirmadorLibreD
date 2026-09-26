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
 * Cliente HTTP sobre libcurl (std.net.curl): peticiones con límite de tamaño y de tiempo
 * para los servicios de validación (sello de tiempo, OCSP, CRL, AIA) y las conexiones, y
 * lectura de eventos del servidor (SSE) para Gaudi y las conexiones externas. Cada
 * petición queda en la bitácora con su método, URL, tamaños y estado.
 */
module firmador.net.http;

import core.atomic : atomicLoad;
import core.time : dur, Duration;
import std.array : appender;
import std.exception : basicExceptionCtors;
import std.format : format;
import std.logger : info, warning;
import etc.c.curl : CurlOption;
import std.net.curl : HTTP, CurlException;
import std.string : indexOf, startsWith, toLower;

/// Error de red o respuesta que no se pudo recibir.
class HttpException : Exception {
  mixin basicExceptionCtors;
}

/// Respuesta HTTP completa.
struct HttpResponse {
  int status;
  string statusText;
  ubyte[] body;
  /// Cabeceras con el nombre en minúsculas.
  string[string] headers;

  /// Cuerpo como texto UTF-8.
  string text() const pure @safe {
    import std.utf : validate;
    string value = cast(string) body.idup;
    validate(value);
    return value;
  }
}

/// Opciones de una petición.
struct HttpOptions {
  Duration connectTimeout = dur!"seconds"(30);
  /// Tiempo máximo total; cero es sin límite (flujos de eventos).
  Duration operationTimeout = dur!"seconds"(60);
  size_t maxResponseBytes = 64 * 1024 * 1024;
  /// Archivo PEM con las raíces de confianza TLS; vacío usa las del sistema.
  string caFile;
  /// Raíces de confianza TLS en PEM, en memoria; tiene prioridad sobre caFile.
  string caPem;
  bool followRedirects = true;
}

/**
 * Hace una petición y devuelve la respuesta, cualquiera sea su estado.
 *
 * Throws: HttpException si no hubo respuesta (red, TLS, tiempo o tamaño excedido).
 */
HttpResponse httpRequest(string method, string url, const(ubyte)[] requestBody, const string[string] headers,
    HttpOptions options = HttpOptions.init) @trusted {
  HttpResponse response;
  auto received = appender!(ubyte[]);
  bool tooLarge = false;
  auto http = HTTP(url);
  const(ubyte)[] retainedBody = configure(http, method, requestBody, headers, options);
  scope (exit) retainedBody = null;
  http.onReceiveStatusLine = (HTTP.StatusLine line) {
    response.status = line.code;
    response.statusText = line.reason;
    response.headers = null;
    received.clear();
  };
  http.onReceiveHeader = (in char[] key, in char[] value) {
    response.headers[key.idup.toLower] = value.idup;
  };
  http.onReceive = (ubyte[] data) {
    if (received[].length + data.length > options.maxResponseBytes) {
      tooLarge = true;
      return cast(size_t) 0;
    }
    received ~= data;
    return data.length;
  };
  info(format("%s %s (%d bytes)", method, url, requestBody.length));
  try {
    http.perform();
  } catch (CurlException exception) {
    if (tooLarge) {
      throw new HttpException(format("La respuesta de %s supera el límite de %d bytes", url, options.maxResponseBytes));
    }
    warning(format("%s %s falló: %s", method, url, exception.msg));
    throw new HttpException(format("No se pudo conectar con %s: %s", url, exception.msg));
  }
  response.body = received[];
  info(format("%s %s respondió %d (%d bytes)", method, url, response.status, response.body.length));
  return response;
}

/// GET con las opciones dadas.
HttpResponse httpGet(string url, const string[string] headers = null, HttpOptions options = HttpOptions.init) @safe {
  return httpRequest("GET", url, null, headers, options);
}

/// POST con el cuerpo y su tipo.
HttpResponse httpPost(string url, const(ubyte)[] requestBody, string contentType, const string[string] headers = null,
    HttpOptions options = HttpOptions.init) @safe {
  string[string] allHeaders;
  foreach (key, value; headers) allHeaders[key] = value;
  allHeaders["Content-Type"] = contentType;
  return httpRequest("POST", url, requestBody, allHeaders, options);
}

/**
 * Saca de `buffer` las líneas completas de un flujo de eventos y devuelve el valor no
 * vacío de cada campo «data» (con «data:» o «data: », como permite la especificación de
 * SSE); lo que queda sin salto de línea sigue en `buffer`. Cada línea es un mensaje, como
 * los leía la versión Java: los servicios mandan un JSON por línea.
 *
 * Params:
 *   buffer = lo recibido y aún no procesado; se queda con la línea incompleta.
 * Returns: los datos, en orden.
 */
string[] takeSseData(ref string buffer) pure @safe {
  string[] payloads;
  while (true) {
    auto newline = buffer.indexOf('\n');
    if (newline < 0) return payloads;
    string line = buffer[0 .. newline];
    buffer = buffer[newline + 1 .. $];
    if (line.length && line[$ - 1] == '\r') line = line[0 .. $ - 1];
    if (!line.startsWith("data:")) continue;
    string payload = line["data:".length .. $];
    if (payload.startsWith(" ")) payload = payload[1 .. $];
    if (payload.length) payloads ~= payload;
  }
}

/**
 * Abre un flujo de eventos (text/event-stream) y entrega cada dato a `onData`
 * (takeSseData), hasta que el servidor cierre, `cancelled` se active o `onData` devuelva
 * false. Devuelve el estado HTTP de la respuesta.
 *
 * Throws: HttpException si no se pudo conectar.
 */
int httpEventStream(string url, const string[string] headers, scope bool delegate(string data) onData,
    shared(bool)* cancelled, HttpOptions options = HttpOptions.init) @trusted {
  options.operationTimeout = Duration.zero;
  int status;
  string pending;
  bool stopped = false;
  auto errorBody = appender!(ubyte[]);
  auto http = HTTP(url);
  configure(http, "GET", null, headers, options);
  bool acceptGiven = false;
  foreach (key, value; headers) if (key.toLower == "accept") acceptGiven = true;
  if (!acceptGiven) http.addRequestHeader("Accept", "text/event-stream");
  http.onReceiveStatusLine = (HTTP.StatusLine line) {
    status = line.code;
  };
  http.onReceive = (ubyte[] data) {
    if (cancelled !is null && atomicLoad(*cancelled)) {
      stopped = true;
      return cast(size_t) 0;
    }
    if (status != 200) {
      if (errorBody[].length < 64 * 1024) errorBody ~= data;
      return data.length;
    }
    pending ~= cast(const(char)[]) data;
    foreach (payload; takeSseData(pending)) {
      if (!onData(payload)) {
        stopped = true;
        return cast(size_t) 0;
      }
    }
    return data.length;
  };
  // Sin progreso libcurl no vuelve a llamar a onReceive; así se atiende la cancelación.
  http.onProgress = (size_t dlTotal, size_t dlNow, size_t ulTotal, size_t ulNow) {
    return cancelled !is null && atomicLoad(*cancelled) ? 1 : 0;
  };
  info("Abriendo flujo de eventos ", url);
  try {
    http.perform();
  } catch (CurlException exception) {
    if (stopped || (cancelled !is null && atomicLoad(*cancelled))) {
      info("Flujo de eventos ", url, " cerrado a pedido");
      return status;
    }
    throw new HttpException(format("Se perdió la conexión con %s: %s", url, exception.msg));
  }
  if (status != 200) {
    warning(format("El flujo de eventos %s respondió %d: %s", url, status, cast(string) errorBody[]));
  }
  info("El servidor cerró el flujo de eventos ", url);
  return status;
}

/// struct curl_blob de libcurl, que etc.c.curl todavía no declara.
private struct CurlBlob {
  void* data;
  size_t len;
  uint flags;
}

/// CURLOPTTYPE_BLOB (40000) + 309.
private enum int curlOptCainfoBlob = 40_309;
private enum uint curlBlobCopy = 1;

/**
 * Prepara la petición. Devuelve el cuerpo que libcurl leerá sin copiarlo: quien llama debe
 * mantenerlo vivo hasta que termine perform().
 */
private const(ubyte)[] configure(ref HTTP http, string method, const(ubyte)[] requestBody,
    const string[string] headers, HttpOptions options) @trusted {
  http.connectTimeout = options.connectTimeout;
  if (options.operationTimeout != Duration.zero) http.operationTimeout = options.operationTimeout;
  if (options.caPem.length) {
    // CURLOPT_CAINFO_BLOB (libcurl 7.77): con CURL_BLOB_COPY libcurl copia el PEM al fijarlo.
    CurlBlob blob = CurlBlob(cast(void*) options.caPem.ptr, options.caPem.length, curlBlobCopy);
    http.handle.set(cast(CurlOption) curlOptCainfoBlob, cast(void*) &blob);
  } else if (options.caFile.length) {
    http.caInfo = options.caFile;
  }
  http.maxRedirects = options.followRedirects ? 5 : 0;
  // setPostData añade su propio Content-Type: el de las cabeceras se le pasa a él para no
  // enviar dos (el servicio de sellado del BCCR rechaza la petición si llegan dos).
  string contentType = "application/octet-stream";
  foreach (key, value; headers) {
    if (key.toLower == "content-type") contentType = value;
    else http.addRequestHeader(key, value);
  }
  switch (method) {
    case "GET":
      http.method = HTTP.Method.get;
      return null;
    case "POST", "PUT":
      const(ubyte)[] retained = requestBody.length ? requestBody : cast(const(ubyte)[]) "";
      http.setPostData(retained, contentType);
      http.method = method == "POST" ? HTTP.Method.post : HTTP.Method.put;
      return retained;
    case "DELETE":
      http.method = HTTP.Method.del;
      return null;
    default:
      throw new HttpException(format("Método HTTP no admitido: %s", method));
  }
}

/// Codifica un texto para una URL o un formulario (URLEncoder.encode).
string urlEncode(string text) pure @safe {
  import std.ascii : isAlphaNum, upperHexDigits = hexDigits;
  auto output = appender!string;
  foreach (char character; text) {
    if (isAlphaNum(character) || character == '-' || character == '_' || character == '.' || character == '*') {
      output ~= character;
    } else if (character == ' ') {
      output ~= '+';
    } else {
      output ~= '%';
      output ~= upperHexDigits[(cast(ubyte) character) >> 4];
      output ~= upperHexDigits[(cast(ubyte) character) & 0x0F];
    }
  }
  return output[];
}

/// Añade parámetros de consulta a una URL (URIBuilder.addParameter).
string withQuery(string url, const string[2][] parameters) pure @safe {
  auto output = appender!string;
  output ~= url;
  bool first = url.indexOf('?') < 0;
  foreach (parameter; parameters) {
    output ~= first ? "?" : "&";
    first = false;
    output ~= urlEncode(parameter[0]);
    output ~= "=";
    output ~= urlEncode(parameter[1]);
  }
  return output[];
}

@("should encode text like URLEncoder when building query strings")
unittest {
  assert(urlEncode("a b&c=d/é") == "a+b%26c%3Dd%2F%C3%A9");
  assert(withQuery("https://x/negotiate?clientProtocol=1.4", [["transport", "serverSentEvents"]])
    == "https://x/negotiate?clientProtocol=1.4&transport=serverSentEvents");
  assert(withQuery("https://x/send", [["a", "1"], ["b", "2"]]) == "https://x/send?a=1&b=2");
}

@("should take every data field with or without the space and keep the partial line when splitting an event stream")
unittest {
  string buffer = "event: x\r\ndata: {\"a\":1}\r\n\r\ndata:{}\n: comentario\ndata: \ndata:{\"b\"";
  assert(takeSseData(buffer) == [`{"a":1}`, "{}"]);
  assert(buffer == `data:{"b"`);
  buffer ~= ":2}\n";
  assert(takeSseData(buffer) == [`{"b":2}`] && buffer.length == 0);
}
