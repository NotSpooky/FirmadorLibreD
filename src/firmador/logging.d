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
 * Bitácora de la aplicación sobre std.logger: cada mensaje va a la salida de error y a
 * los receptores registrados (la pestaña de bitácoras de la interfaz,
 * firmador.gui.desktop.logpanel). El nivel sale del ajuste «advancedLogs», que guarda
 * nombres de nivel de java.util.logging para seguir leyendo la configuración de la
 * versión Java. También da withContext, para registrar y relanzar un fallo con su contexto.
 */
module firmador.logging;

import core.sync.mutex : Mutex;
import std.datetime.systime : Clock;
import std.format : format;
import std.logger : error, Logger, LogLevel, sharedLog, globalLogLevel;
import std.stdio : stderr;
import std.string : toUpper;

/**
 * Hace `action` y, si falla, registra el error con `context` y lo relanza con ese contexto
 * y la causa encadenada: el cierre de las operaciones que no se pueden recuperar (guardar
 * la configuración o las conexiones, registrar una firma…).
 *
 * Params:
 *   context = qué se hacía, con lo que hace falta para ubicarlo (la ruta del archivo…).
 *   action = la operación.
 * Returns: lo que devuelve `action`.
 * Throws: Exception con «context: motivo» y la causa original.
 */
T withContext(T)(string context, scope T delegate() action) {
  try {
    return action();
  } catch (Exception exception) {
    error(context, ": ", exception.msg);
    throw new Exception(context ~ ": " ~ exception.msg, exception);
  }
}

/// Receptor de mensajes de bitácora ya formateados.
alias LogSink = void delegate(LogLevel level, string line) nothrow;

private __gshared LogSink[] sinks;
private __gshared Mutex sinkLock;

shared static this() {
  sinkLock = new Mutex;
}

/// Nivel de std.logger que corresponde a un nombre de java.util.logging (SEVERE, WARNING, INFO, CONFIG, FINE…).
LogLevel logLevelFromJulName(string name) pure @safe {
  switch (name.toUpper) {
    case "OFF": return LogLevel.off;
    case "SEVERE": return LogLevel.error;
    case "WARNING": return LogLevel.warning;
    case "INFO", "CONFIG": return LogLevel.info;
    case "FINE", "FINER", "FINEST", "ALL": return LogLevel.trace;
    default: return LogLevel.info;
  }
}

private final class FirmadorLogger : Logger {
  this(LogLevel level) @safe {
    super(level);
  }

  override protected void writeLogMsg(ref LogEntry entry) @trusted {
    string line = format("%s [%s] %s:%d %s", Clock.currTime.toISOExtString()[0 .. 19], levelName(entry.logLevel),
      entry.moduleName, entry.line, entry.msg);
    try {
      stderr.writeln(line);
      stderr.flush();
    } catch (Exception) {
      // Sin salida de error (aplicación lanzada sin terminal) sólo quedan los receptores.
    }
    sinkLock.lock();
    LogSink[] current = sinks.dup;
    sinkLock.unlock();
    foreach (sink; current) sink(entry.logLevel, line);
  }
}

private string levelName(LogLevel level) pure nothrow @safe @nogc {
  final switch (level) {
    case LogLevel.all, LogLevel.trace: return "FINE";
    case LogLevel.info: return "INFO";
    case LogLevel.warning: return "WARNING";
    case LogLevel.error, LogLevel.critical, LogLevel.fatal: return "SEVERE";
    case LogLevel.off: return "OFF";
  }
}

/// Instala la bitácora de la aplicación con el nivel dado (nombre de java.util.logging).
void configureLogging(string julLevelName) @trusted {
  LogLevel level = logLevelFromJulName(julLevelName);
  globalLogLevel = level;
  sharedLog = cast(shared) new FirmadorLogger(LogLevel.all);
}

/// Cambia el nivel de la bitácora ya instalada.
void setLogLevel(string julLevelName) @trusted {
  globalLogLevel = logLevelFromJulName(julLevelName);
}

/// Registra un receptor; lo usa la pestaña de bitácoras de la interfaz.
void addLogSink(LogSink sink) @trusted {
  synchronized (sinkLock) sinks ~= sink;
}

@("should map java.util.logging level names when reading the advancedLogs setting")
unittest {
  assert(logLevelFromJulName("SEVERE") == LogLevel.error);
  assert(logLevelFromJulName("warning") == LogLevel.warning);
  assert(logLevelFromJulName("CONFIG") == LogLevel.info);
  assert(logLevelFromJulName("ALL") == LogLevel.trace);
  assert(logLevelFromJulName("desconocido") == LogLevel.info);
}
