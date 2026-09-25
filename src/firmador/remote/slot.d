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
 * Documento enviado a Firmador Remoto para firmarlo en la ventana (RemoteDocInformation):
 * la página lo envía por POST a /{nombre} y pregunta por el mismo nombre hasta recibir el
 * firmado (200) o el rechazo (406). Lo comparten el hilo del servidor y la interfaz.
 */
module firmador.remote.slot;

/// Estados HTTP con que se contesta el sondeo de un documento.
enum RemoteStatus : int { ok = 200, accepted = 202, noContent = 204, notAcceptable = 406 }

/// Documento recibido y su resultado.
final class RemoteDocumentSlot {
  /// Nombre con que la página lo envió (la ruta sin la barra).
  immutable string name;
  /// Contenido recibido.
  immutable(ubyte)[] content;
  private RemoteStatus status_;
  private immutable(ubyte)[] signed_;

  this(string name, immutable(ubyte)[] content, RemoteStatus status) pure @safe {
    this.name = name;
    this.content = content;
    status_ = status;
  }

  RemoteStatus status() pure @trusted {
    synchronized (this) return status_;
  }

  /// Documento firmado que se devuelve a la página (vacío hasta firmarlo).
  immutable(ubyte)[] signed() pure @trusted {
    synchronized (this) return signed_;
  }

  /// La interfaz firmó el documento: la página lo recibe con 200.
  void complete(immutable(ubyte)[] signedContent) pure @trusted {
    synchronized (this) {
      signed_ = signedContent;
      status_ = RemoteStatus.ok;
    }
  }

  /// El usuario lo rechazó o falló: la página recibe 406 y puede volver a enviarlo.
  void reject() pure @trusted {
    synchronized (this) status_ = RemoteStatus.notAcceptable;
  }
}
