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
 * Servidor HTTP/1.1 mínimo para Firmador Remoto: escucha sólo en la interfaz de bucle
 * local, atiende una petición por conexión (Connection: close) en un hilo propio y limita
 * el tamaño de las cabeceras y del cuerpo y las conexiones simultáneas
 * (configuration.remoteMaxHeaderBytes, remoteMaxBodyBytes y remoteMaxConnections). Rechaza
 * las peticiones ambiguas (Content-Length y Transfer-Encoding a la vez, largos repetidos).
 */
module firmador.remote.http;

import core.sync.mutex : Mutex;
import core.thread : Thread;
import core.time : dur, Duration;
import std.algorithm : canFind, endsWith, startsWith;
import std.array : appender, split;
import std.ascii : isDigit, isHexDigit;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.logger : error, info, trace, warning;
import std.socket;
import std.string : indexOf, strip, toLower;
import std.uri : decodeComponent;

import firmador.configuration : remoteMaxBodyBytes, remoteMaxConnections, remoteMaxHeaderBytes;

/// La petición no es HTTP/1.1 válida o pasa los límites; `status` es la respuesta que corresponde.
class HttpProtocolException : Exception {
  int status;

  this(int status, string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
    this.status = status;
  }
}

/// Petición recibida.
struct HttpRequest {
  string method;
  /// Ruta sin la consulta, con los escapes resueltos.
  string path;
  string query;
  /// Cabeceras con el nombre en minúsculas.
  string[][string] headers;
  immutable(ubyte)[] body;

  /// Primer valor de la cabecera, o null.
  string header(string name) const pure @safe {
    if (auto values = name.toLower in headers) return (*values).length ? (*values)[0] : null;
    return null;
  }
}

/// Respuesta a enviar.
struct HttpResponse {
  int status = 200;
  string[2][] headers;
  immutable(ubyte)[] body;

  /// Reemplaza la cabecera.
  void setHeader(string name, string value) pure @safe {
    foreach (ref header; headers) {
      if (header[0].toLower == name.toLower) {
        header[1] = value;
        return;
      }
    }
    headers ~= [name, value];
  }

  /// Añade otra cabecera con el mismo nombre.
  void addHeader(string name, string value) pure @safe {
    headers ~= [name, value];
  }

  /// Cuerpo JSON con estado 200.
  void json(immutable(ubyte)[] payload) pure @safe {
    status = 200;
    body = payload;
    setHeader("Content-Type", "application/json");
  }
}

/// Atiende una petición; puede bloquearse (espera respuestas del usuario).
alias HttpHandler = void delegate(ref const HttpRequest request, ref HttpResponse response) @safe;

/// Frase de estado de los códigos que usa Firmador.
string reasonPhrase(int status) pure nothrow @safe @nogc {
  switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 408: return "Request Timeout";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default: return "Status";
  }
}

/// Métodos que se atienden.
private immutable string[] supportedMethods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"];

/// Cabecera de la petición ya interpretada, antes del cuerpo.
struct RequestHead {
  HttpRequest request;
  /// Largo del cuerpo si viene con Content-Length.
  size_t contentLength;
  bool chunked;
}

/**
 * Interpreta la línea de petición y las cabeceras (sin la línea vacía final).
 *
 * Throws: HttpProtocolException con el estado que corresponde si no son válidas.
 */
RequestHead parseRequestHead(const(char)[] head) pure @safe {
  auto lines = head.split("\r\n");
  enforce(lines.length > 0 && lines[0].length, new HttpProtocolException(400, "Petición vacía"));
  auto parts = lines[0].split(" ");
  enforce(parts.length == 3, new HttpProtocolException(400, "Línea de petición no válida"));
  enforce(parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0", new HttpProtocolException(400, "Versión HTTP no admitida"));
  RequestHead result;
  result.request.method = parts[0].idup;
  enforce(supportedMethods.canFind(result.request.method), new HttpProtocolException(501, "Método no admitido"));
  string target = parts[1].idup;
  enforce(target.startsWith("/"), new HttpProtocolException(400, "Destino de la petición no válido"));
  auto question = target.indexOf('?');
  string rawPath = question >= 0 ? target[0 .. question] : target;
  result.request.query = question >= 0 ? target[question + 1 .. $] : "";
  try {
    result.request.path = decodeComponent(rawPath);
  } catch (Exception) {
    throw new HttpProtocolException(400, "Ruta con escapes no válidos");
  }
  foreach (line; lines[1 .. $]) {
    auto colon = line.indexOf(':');
    enforce(colon > 0, new HttpProtocolException(400, "Cabecera no válida"));
    string name = line[0 .. colon].idup.toLower;
    enforce(!name.canFind(' ') && !name.canFind('\t'), new HttpProtocolException(400, "Nombre de cabecera no válido"));
    result.request.headers[name] ~= line[colon + 1 .. $].strip.idup;
  }
  auto lengths = "content-length" in result.request.headers;
  auto encodings = "transfer-encoding" in result.request.headers;
  // Largo y codificación a la vez permiten contrabando de peticiones: se rechazan.
  enforce(!(lengths && encodings), new HttpProtocolException(400, "Content-Length y Transfer-Encoding a la vez"));
  if (encodings) {
    enforce((*encodings).length == 1 && (*encodings)[0].toLower == "chunked",
      new HttpProtocolException(501, "Transfer-Encoding no admitido"));
    result.chunked = true;
  } else if (lengths) {
    enforce((*lengths).length == 1, new HttpProtocolException(400, "Content-Length repetido"));
    string text = (*lengths)[0];
    enforce(text.length > 0 && text.length <= 12, new HttpProtocolException(400, "Content-Length no válido"));
    foreach (char character; text) enforce(isDigit(character), new HttpProtocolException(400, "Content-Length no válido"));
    result.contentLength = text.to!size_t;
    enforce(result.contentLength <= remoteMaxBodyBytes, new HttpProtocolException(413, "Cuerpo demasiado grande"));
  }
  return result;
}

/**
 * Decodifica un cuerpo chunked; devuelve false si todavía falta parte.
 *
 * Throws: HttpProtocolException si la codificación no es válida o pasa el límite.
 */
bool decodeChunked(const(ubyte)[] data, out immutable(ubyte)[] body, out size_t consumed) pure @safe {
  auto output = appender!(immutable(ubyte)[]);
  size_t position = 0;
  while (true) {
    size_t lineEnd = position;
    while (lineEnd + 1 < data.length && !(data[lineEnd] == '\r' && data[lineEnd + 1] == '\n')) lineEnd++;
    if (lineEnd + 1 >= data.length) return false;
    auto sizeText = cast(const(char)[]) data[position .. lineEnd];
    auto extension = sizeText.indexOf(';');
    if (extension >= 0) sizeText = sizeText[0 .. extension];
    sizeText = sizeText.strip;
    enforce(sizeText.length > 0 && sizeText.length <= 16, new HttpProtocolException(400, "Tamaño de fragmento no válido"));
    foreach (char character; sizeText) {
      enforce(isHexDigit(character), new HttpProtocolException(400, "Tamaño de fragmento no válido"));
    }
    size_t size = sizeText.to!size_t(16);
    enforce(output[].length + size <= remoteMaxBodyBytes, new HttpProtocolException(413, "Cuerpo demasiado grande"));
    position = lineEnd + 2;
    if (size == 0) {
      // Cierre: se aceptan remolques vacíos (sólo la línea en blanco final).
      if (position + 1 >= data.length) return false;
      enforce(data[position] == '\r' && data[position + 1] == '\n',
        new HttpProtocolException(501, "Remolques de chunked no admitidos"));
      consumed = position + 2;
      body = output[];
      return true;
    }
    if (position + size + 2 > data.length) return false;
    output ~= data[position .. position + size];
    enforce(data[position + size] == '\r' && data[position + size + 1] == '\n',
      new HttpProtocolException(400, "Fragmento sin fin de línea"));
    position += size + 2;
  }
}

/// Bytes de la respuesta con Content-Length y Connection: close.
immutable(ubyte)[] serializeResponse(const HttpResponse response, bool headRequest) pure @safe {
  auto output = appender!string;
  output ~= format("HTTP/1.1 %d %s\r\n", response.status, reasonPhrase(response.status));
  foreach (header; response.headers) {
    enforce(!header[0].canFind('\r') && !header[0].canFind('\n') && !header[1].canFind('\r') && !header[1].canFind('\n'),
      "Cabecera de respuesta con saltos de línea");
    output ~= header[0] ~ ": " ~ header[1] ~ "\r\n";
  }
  bool noBody = response.status == 204 || response.status == 304;
  if (!noBody) output ~= format("Content-Length: %d\r\n", response.body.length);
  output ~= "Connection: close\r\n\r\n";
  auto bytes = cast(immutable(ubyte)[]) output[];
  return noBody || headRequest ? bytes : bytes ~ response.body;
}

/// El puerto de bucle local ya tiene quien escuche (sonda de isPortAvailable).
bool isLoopbackPortInUse(ushort port) @trusted {
  auto socket = new TcpSocket(AddressFamily.INET);
  scope (exit) socket.close();
  socket.blocking = false;
  try {
    socket.connect(new InternetAddress("127.0.0.1", port));
  } catch (SocketException) {
    return false;
  }
  auto writable = new SocketSet;
  writable.add(socket);
  auto errors = new SocketSet;
  errors.add(socket);
  if (Socket.select(null, writable, errors, dur!"msecs"(300)) <= 0) return false;
  int failure;
  socket.getOption(SocketOptionLevel.SOCKET, SocketOption.ERROR, failure);
  return failure == 0 && writable.isSet(socket);
}

/// Servidor HTTP en el bucle local.
final class HttpServer {
  private ushort port;
  private HttpHandler handler;
  private TcpSocket listener;
  private Mutex lock;
  private size_t activeConnections;
  private shared bool stopping;
  private shared bool accepting;
  /// Tiempo máximo para recibir una petición completa.
  private Duration receiveTimeout = dur!"seconds"(60);

  this(ushort port, HttpHandler handler) @safe {
    this.port = port;
    this.handler = handler;
    lock = new Mutex;
  }

  /**
   * Abre el puerto y empieza a atender en un hilo aparte.
   *
   * Throws: SocketException si el puerto no se puede usar.
   */
  void start() @trusted {
    listener = new TcpSocket(AddressFamily.INET);
    listener.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    listener.bind(new InternetAddress("127.0.0.1", port));
    listener.listen(remoteMaxConnections);
    info("Firmador Remoto escuchando en 127.0.0.1:", port);
    import core.atomic : atomicStore;
    atomicStore(accepting, true);
    auto acceptor = new Thread(&acceptLoop);
    acceptor.isDaemon = true;
    acceptor.start();
  }

  /// Deja de aceptar conexiones.
  void stop() @trusted {
    import core.atomic : atomicStore;
    atomicStore(stopping, true);
    if (listener !is null) {
      listener.shutdown(SocketShutdown.BOTH);
      listener.close();
    }
  }

  /// Sigue aceptando conexiones (no se detuvo ni se cerró el puerto).
  bool isRunning() const pure @safe {
    import core.atomic : atomicLoad;
    return atomicLoad(accepting);
  }

  private void acceptLoop() @trusted {
    import core.atomic : atomicLoad, atomicStore;
    scope (exit) atomicStore(accepting, false);
    while (!atomicLoad(stopping)) {
      Socket client;
      try {
        client = listener.accept();
      } catch (SocketException exception) {
        if (atomicLoad(stopping)) break;
        if (!listener.isAlive) {
          error("Firmador Remoto dejó de escuchar en el puerto ", port, ": ", exception.msg);
          break;
        }
        warning("Error aceptando conexión de Firmador Remoto: ", exception.msg);
        continue;
      }
      bool accepted;
      synchronized (lock) {
        accepted = activeConnections < remoteMaxConnections;
        if (accepted) activeConnections++;
      }
      if (!accepted) {
        respondAndClose(client, HttpResponse(503), false);
        continue;
      }
      startWorker(client);
    }
  }

  /**
   * Atiende una conexión en su propio hilo. Va en una función aparte: un cierre creado
   * en el bucle de aceptación compartiría `client` con la vuelta siguiente, y dos hilos
   * podrían atender el mismo socket.
   */
  private void startWorker(Socket client) @trusted {
    auto worker = new Thread(() { serve(client); });
    worker.isDaemon = true;
    worker.start();
  }

  private void serve(Socket client) @trusted {
    scope (exit) {
      synchronized (lock) activeConnections--;
    }
    HttpRequest request;
    try {
      request = receiveRequest(client);
    } catch (HttpProtocolException exception) {
      trace("Petición rechazada: ", exception.msg);
      respondAndClose(client, HttpResponse(exception.status), false);
      return;
    } catch (Exception exception) {
      trace("Conexión cerrada al leer la petición: ", exception.msg);
      client.close();
      return;
    }
    HttpResponse response;
    try {
      handler(request, response);
    } catch (Exception exception) {
      error("Error atendiendo ", request.method, " ", request.path, ": ", exception.msg);
      response = HttpResponse(500);
    }
    respondAndClose(client, response, request.method == "HEAD");
  }

  private HttpRequest receiveRequest(Socket client) @trusted {
    client.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, receiveTimeout);
    ubyte[] buffer;
    ubyte[65_536] chunk;
    ptrdiff_t headEnd = -1;
    while (headEnd < 0) {
      auto received = client.receive(chunk[]);
      enforce(received > 0, "La conexión se cerró antes de terminar la petición");
      buffer ~= chunk[0 .. received];
      headEnd = findHeadEnd(buffer);
      if (headEnd < 0) {
        enforce(buffer.length <= remoteMaxHeaderBytes, new HttpProtocolException(431, "Cabeceras demasiado grandes"));
      }
    }
    enforce(headEnd <= remoteMaxHeaderBytes, new HttpProtocolException(431, "Cabeceras demasiado grandes"));
    auto head = parseRequestHead(cast(const(char)[]) buffer[0 .. headEnd]);
    ubyte[] rest = buffer[headEnd + 4 .. $];
    if (head.chunked) {
      while (true) {
        size_t consumed;
        immutable(ubyte)[] decoded;
        if (decodeChunked(rest, decoded, consumed)) {
          head.request.body = decoded;
          break;
        }
        enforce(rest.length <= remoteMaxBodyBytes + 1_048_576, new HttpProtocolException(413, "Cuerpo demasiado grande"));
        auto received = client.receive(chunk[]);
        enforce(received > 0, "La conexión se cerró antes de terminar el cuerpo");
        rest ~= chunk[0 .. received];
      }
    } else {
      while (rest.length < head.contentLength) {
        auto received = client.receive(chunk[]);
        enforce(received > 0, "La conexión se cerró antes de terminar el cuerpo");
        rest ~= chunk[0 .. received];
      }
      head.request.body = cast(immutable(ubyte)[]) rest[0 .. head.contentLength].idup;
    }
    return head.request;
  }

  private static ptrdiff_t findHeadEnd(const(ubyte)[] buffer) pure nothrow @safe @nogc {
    if (buffer.length < 4) return -1;
    foreach (index; 0 .. buffer.length - 3) {
      if (buffer[index] == '\r' && buffer[index + 1] == '\n' && buffer[index + 2] == '\r' && buffer[index + 3] == '\n') {
        return index;
      }
    }
    return -1;
  }

  private static void respondAndClose(Socket client, HttpResponse response, bool headRequest) @trusted {
    scope (exit) client.close();
    try {
      auto bytes = serializeResponse(response, headRequest);
      size_t sent = 0;
      while (sent < bytes.length) {
        auto count = client.send(bytes[sent .. $]);
        if (count <= 0) break;
        sent += count;
      }
      client.shutdown(SocketShutdown.SEND);
    } catch (Exception exception) {
      trace("No se pudo enviar la respuesta: ", exception.msg);
    }
  }
}

@("should parse the request line, headers and a fixed-length body declaration")
unittest {
  auto head = parseRequestHead("POST /doc%20uno.pdf?x=1 HTTP/1.1\r\nHost: localhost\r\nOrigin: https://a.cr\r\n"
    ~ "Content-Length: 12");
  assert(head.request.method == "POST");
  assert(head.request.path == "/doc uno.pdf");
  assert(head.request.query == "x=1");
  assert(head.request.header("origin") == "https://a.cr");
  assert(head.contentLength == 12 && !head.chunked);
}

@("should reject ambiguous framing and oversized bodies when parsing untrusted requests")
unittest {
  import std.exception : collectException;
  auto both = collectException!HttpProtocolException(parseRequestHead(
    "POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked"));
  assert(both !is null && both.status == 400);
  auto twice = collectException!HttpProtocolException(parseRequestHead(
    "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2"));
  assert(twice !is null && twice.status == 400);
  auto huge = collectException!HttpProtocolException(parseRequestHead("POST / HTTP/1.1\r\nContent-Length: 999999999999"));
  assert(huge !is null && huge.status == 413);
  auto method = collectException!HttpProtocolException(parseRequestHead("TRACE / HTTP/1.1"));
  assert(method !is null && method.status == 501);
}

@("should decode chunked bodies only once complete")
unittest {
  size_t consumed;
  immutable(ubyte)[] body;
  assert(!decodeChunked(cast(const(ubyte)[]) "5\r\nhola ", body, consumed));
  auto complete = cast(const(ubyte)[]) "5\r\nhola \r\n5;x=1\r\nmundo\r\n0\r\n\r\n";
  assert(decodeChunked(complete, body, consumed) && body == cast(immutable(ubyte)[]) "hola mundo");
  assert(consumed == complete.length);
  assert(decodeChunked(cast(const(ubyte)[]) "0\r\n\r\n", body, consumed) && body.length == 0);
}

@("should serialize responses without body for 204 and with Content-Length otherwise")
unittest {
  HttpResponse response;
  response.status = 204;
  response.setHeader("Access-Control-Allow-Origin", "*");
  string text = cast(string) serializeResponse(response, false);
  assert(text == "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n");
  response.status = 200;
  response.body = cast(immutable(ubyte)[]) "{}";
  assert((cast(string) serializeResponse(response, false)).endsWith("Content-Length: 2\r\nConnection: close\r\n\r\n{}"));
}
