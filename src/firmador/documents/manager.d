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
 * Trabajo en segundo plano sobre los documentos (DocumentManager y los schedulers de la
 * versión Java): colas de vista previa y validación con varios hilos
 * (configuration.maxPreviewWorkers y maxValidationWorkers) y la cola de firma, que pide
 * la credencial una vez por lote, firma de a un documento (los dispositivos PKCS#11 no
 * admiten firmas simultáneas), guarda cada documento firmado y avisa el final del lote.
 */
module firmador.documents.manager;

import core.sync.condition : Condition;
import core.sync.mutex : Mutex;
import core.thread : Thread;
import std.file : write;
import std.format : format;
import std.logger : error, info;
import std.uri : encode;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.configuration : maxPreviewWorkers, maxValidationWorkers;
import firmador.documents.document;
import firmador.gui.guiinterface;
import firmador.i18n : t;

/**
 * Cola de documentos atendida por `workerCount` hilos. `allDone` se llama cuando la cola
 * queda vacía y ningún hilo trabaja.
 */
final class DocumentQueue {
  private Mutex lock;
  private Condition wakeup;
  private Document[] pending;
  private size_t active;
  private bool stopping;
  private void delegate(Document) @safe work;
  private void delegate() @safe allDone;
  private Thread[] workers;

  this(size_t workerCount, void delegate(Document) @safe work, void delegate() @safe allDone) @trusted {
    lock = new Mutex;
    wakeup = new Condition(lock);
    this.work = work;
    this.allDone = allDone;
    foreach (_; 0 .. workerCount) {
      auto worker = new Thread(&run);
      worker.isDaemon = true;
      worker.start();
      workers ~= worker;
    }
  }

  /// Encola los documentos.
  void add(Document[] documents) @trusted {
    synchronized (lock) {
      pending ~= documents;
      wakeup.notifyAll();
    }
  }

  /// Detiene los hilos cuando terminen lo que están haciendo.
  void stop() @trusted {
    synchronized (lock) {
      stopping = true;
      pending = null;
      wakeup.notifyAll();
    }
  }

  private void run() @trusted {
    while (true) {
      Document document;
      synchronized (lock) {
        while (pending.length == 0 && !stopping) wakeup.wait();
        if (stopping) return;
        document = pending[0];
        pending = pending[1 .. $];
        active++;
      }
      try {
        work(document);
      } catch (Throwable failure) {
        error("Error procesando ", document.name, ": ", failure.msg);
      }
      bool finished;
      synchronized (lock) {
        active--;
        finished = active == 0 && pending.length == 0;
      }
      if (finished) {
        try {
          allDone();
        } catch (Throwable failure) {
          error("Error al avisar el fin de la cola: ", failure.msg);
        }
      }
    }
  }
}

/// Documentos en segundo plano y sus avisos a la interfaz.
final class DocumentManager {
  private GuiInterface gui;
  private DocumentQueue previews;
  private DocumentQueue validations;
  private Mutex signingLock;
  private Condition signingWakeup;
  private Document[] signingPending;
  private string[] savedPaths;
  private bool stopping;

  this(GuiInterface gui) @trusted {
    this.gui = gui;
    previews = new DocumentQueue(maxPreviewWorkers, (document) @safe => document.loadPreview(),
      () @safe => gui.previewAllDone());
    validations = new DocumentQueue(maxValidationWorkers, (Document document) @safe {
      document.validate();
    }, () @safe => gui.validateAllDone());
    signingLock = new Mutex;
    signingWakeup = new Condition(signingLock);
    auto signer = new Thread(&signingLoop);
    signer.isDaemon = true;
    signer.start();
  }

  /// Carga la vista previa del documento en segundo plano (schedulePreview).
  void schedulePreview(Document document) @safe {
    previews.add([document]);
  }

  /// Valida los documentos en segundo plano.
  void scheduleValidation(Document[] documents) @safe {
    validations.add(documents);
  }

  /**
   * Valida y prepara la vista previa de los documentos (processDocument). Con más de
   * `limit` documentos (0: sin límite) no los procesa y avisa, como la versión Java.
   */
  void processDocuments(Document[] documents, int limit) @safe {
    if (limit != 0 && documents.length >= limit) {
      gui.previewAllDone();
      gui.showMessage(format("Por razones de rendimiento no se procesan mas de %s documentos", limit));
      return;
    }
    foreach (document; documents) {
      validations.add([document]);
      previews.add([document]);
    }
  }

  /// Firma un documento mostrando su vista previa al terminar (addDocument).
  void scheduleSigning(Document document) @safe {
    document.setShowPreview(true);
    enqueueSigning([document]);
  }

  /// Firma un lote de documentos sin mostrar vistas previas (addDocuments).
  void scheduleSigning(Document[] documents) @safe {
    foreach (document; documents) document.setShowPreview(false);
    enqueueSigning(documents);
  }

  private void enqueueSigning(Document[] documents) @trusted {
    synchronized (signingLock) {
      signingPending ~= documents;
      signingWakeup.notifyAll();
    }
  }

  /// Detiene los hilos (al cerrar la aplicación).
  void stop() @trusted {
    previews.stop();
    validations.stop();
    synchronized (signingLock) {
      stopping = true;
      signingPending = null;
      signingWakeup.notifyAll();
    }
  }

  private void signingLoop() @trusted {
    while (true) {
      Document[] batch;
      synchronized (signingLock) {
        while (signingPending.length == 0 && !stopping) signingWakeup.wait();
        if (stopping) return;
        batch = signingPending;
        signingPending = null;
      }
      try {
        signBatch(batch);
      } catch (Throwable failure) {
        error("Error en el lote de firma: ", failure.msg);
        gui.progressEnd();
      }
    }
  }

  private void signBatch(Document[] batch) @trusted {
    gui.progressStart(format(t("signer_scheduler_sign_process"), batch.length), t("signer_scheduler_signing_document"));
    CardSignInfo card = gui.getPin();
    if (card is null) {
      info("Firma cancelada: no se eligió credencial");
      gui.progressHeader(t("signer_scheduler_cancelled_process"));
      gui.progressEnd();
      return;
    }
    // El PIN sólo vive mientras dura el lote.
    scope (exit) card.destroyPin();
    foreach (document; batch) {
      gui.progressHeader(t("signer_scheduler_signing") ~ " " ~ document.name);
      gui.progressUpdate(0, "");
      try {
        document.setSignedWithErrors(false);
        document.sign(card);
        saveSigned(document);
      } catch (Exception exception) {
        document.setSignedWithErrors(true);
        error("Error firmando ", document.name, ": ", exception.msg);
        gui.showError(exception);
      }
      gui.signDone(document);
    }
    gui.progressEnd();
    signAllDone();
  }

  /// Guarda el documento firmado junto al original (DocumentManager.signDone).
  private void saveSigned(Document document) @trusted {
    auto signed = document.signedContent;
    if (document.signedWithErrors || signed is null || document.isRemote) return;
    string path = document.pathToSave;
    try {
      write(path, signed);
      info("Documento firmado guardado en ", path);
      synchronized (signingLock) savedPaths ~= path;
    } catch (Exception exception) {
      error("Error guardando el documento firmado en ", path, ": ", exception.msg);
      gui.showError(exception);
    }
  }

  /// Avisa los archivos guardados en el lote con enlaces a cada uno (signAllDone).
  private void signAllDone() @trusted {
    string[] paths;
    synchronized (signingLock) {
      paths = savedPaths;
      savedPaths = null;
    }
    string links;
    foreach (path; paths) links ~= format(`<a href="file://%s">%s</a><br>`, encode(path), path);
    if (links.length) gui.showMessage(t("guiswing_dialog_document_success") ~ links);
    gui.signAllDone();
  }
}
