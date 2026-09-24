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
 * Documento abierto en Firmador (Document de la versión Java): su archivo o contenido
 * en memoria (documentos remotos), el firmador y la vista previa según su tipo, la
 * validación, la firma con la credencial, la extensión a LTA y el nombre con que se
 * guarda firmado. Se usa desde los hilos de firma, validación y vista previa
 * (firmador.documents.manager); los cambios de estado van a la interfaz.
 */
module firmador.documents.document;

import std.algorithm : canFind;
import std.file : read;
import std.logger : error, info;
import std.path : baseName, dirName, extension, stripExtension, buildPath;
import std.uuid : UUID, randomUUID;

import firmador.cards.cardinfo : CardSignInfo;
import firmador.documents.mimetype;
import firmador.gui.guiinterface;
import firmador.previewers.previewer;
import firmador.settings : Settings;
import firmador.settingsmanager : currentSettings;
import firmador.signers.asic : AsicSigner;
import firmador.signers.cades : CadesSigner;
import firmador.signers.detector : signerFor;
import firmador.signers.documentsigner;
import firmador.validation.model : DetachedContent;
import firmador.validation.sources : OnlineValidationSource;
import firmador.validators.factory : validateDocument;

/// Estado de firma del documento.
enum DocumentStatus { toSign = 0, signed = 1, errorSigning = 2 }

/// Documento abierto.
final class Document {
  /// Identificador (el que usan las integraciones remotas).
  immutable UUID id;
  private GuiInterface gui;
  private string name_;
  private string pathname_;
  private SupportedMimeType mimeType_;
  private immutable(ubyte)[] data;
  private immutable(ubyte)[] signedContent_;
  private Settings settings_;
  private DocumentSigner signer_;
  private Previewer preview_;
  private string pathToSave_;
  private bool valid_, validated_, previewLoaded_, ready_, signedWithErrors_, showPreview_ = true, massiveSign_;
  private bool remote_, virtual_, validating_;
  private string report_;
  private CardSignInfo usedCard_;
  private DocumentStatus status_;
  private size_t signatureCount_;
  private int pages_;
  private string service_, serial_, origin_, expirationDate_, createdAt_;
  /// Otros archivos que se firman en el mismo contenedor ASiC (firma de carpetas).
  DetachedContent[] additionalDocuments;

  /// Documento de un archivo local.
  this(GuiInterface gui, string pathname) @safe {
    info("Se creó una nueva instancia de Document para ", pathname);
    this.id = randomUUID();
    this.gui = gui;
    pathname_ = pathname;
    name_ = baseName(pathname);
    mimeType_ = detectMimeType(pathname);
    settings_ = currentSettings();
    preview_ = previewerFor(mimeType_, settings_);
    signer_ = signerFor(gui, settings_, mimeType_);
  }

  /**
   * Documento en memoria (recibido por Firmador Remoto o por el shell). `status` indica
   * si ya viene firmado.
   */
  this(GuiInterface gui, immutable(ubyte)[] content, string name, DocumentStatus status = DocumentStatus.toSign) @safe {
    this.id = randomUUID();
    this.gui = gui;
    name_ = name;
    status_ = status;
    mimeType_ = detectMimeType(name);
    if (status == DocumentStatus.toSign) data = content;
    else signedContent_ = content;
    settings_ = currentSettings();
    preview_ = previewerFor(mimeType_, settings_);
    signer_ = signerFor(gui, settings_, mimeType_);
    remote_ = true;
  }

  /// Documento virtual de una conexión (se firma en el servidor; sólo se conocen sus datos).
  this(GuiInterface gui, UUID id, string name, string mimeType, string service, int pages, string serial,
      string origin, string expirationDate, string createdAt) @safe {
    this.id = id;
    this.gui = gui;
    name_ = name;
    virtual_ = true;
    remote_ = true;
    mimeType_ = mimeTypeFromString(mimeType);
    pages_ = pages;
    settings_ = currentSettings();
    preview_ = previewerFor(mimeType_, settings_);
    service_ = service;
    serial_ = serial;
    origin_ = origin;
    expirationDate_ = expirationDate;
    createdAt_ = createdAt;
  }

  string name() const @safe { return name_; }
  string pathname() const @safe { return pathname_; }
  SupportedMimeType mimeType() const @safe { return mimeType_; }
  bool isRemote() const @safe { return remote_; }
  bool isVirtual() const @safe { return virtual_; }
  string service() const @safe { return service_; }
  string serial() const @safe { return serial_; }
  string origin() const @safe { return origin_; }
  string expirationDate() const @safe { return expirationDate_; }
  string createdAt() const @safe { return createdAt_; }
  int pages() const @safe { return pages_; }

  /**
   * Contenido original: el recibido en memoria o el del archivo.
   *
   * Throws: FileException si el archivo no se puede leer.
   */
  immutable(ubyte)[] content() @trusted {
    synchronized (this) {
      if (data is null && pathname_.length) data = cast(immutable(ubyte)[]) read(pathname_);
      return data;
    }
  }

  /// Ajustes con que se firma el documento.
  Settings settings() @trusted {
    synchronized (this) return settings_;
  }

  /// Cambia los ajustes y vuelve a elegir el firmador según ellos (setSettings).
  void setSettings(Settings settings) @trusted {
    synchronized (this) {
      settings_ = settings;
      signer_ = signerFor(gui, settings, mimeType_);
    }
  }

  DocumentSigner signer() @trusted {
    synchronized (this) return signer_;
  }

  void setSigner(DocumentSigner signer) @trusted {
    synchronized (this) signer_ = signer;
  }

  /// Firma en un contenedor ASiC-E (forcesignASiC).
  void forceAsic() @safe {
    setSigner(new AsicSigner(gui));
  }

  /// Firma separada CAdES (forceCades).
  void forceCades() @safe {
    setSigner(new CadesSigner(gui));
  }

  Previewer preview() @trusted {
    synchronized (this) return preview_;
  }

  void setPreview(Previewer preview) @trusted {
    synchronized (this) preview_ = preview;
  }

  /**
   * Valida el documento una sola vez y avisa (validate). Devuelve si tiene firmas.
   *
   * Throws: Exception si el documento no se pudo interpretar; la validación queda hecha.
   */
  bool validate() @trusted {
    synchronized (this) {
      if (validated_) return valid_;
    }
    scope (exit) validateDone();
    auto validation = validateDocument(signedContent_ !is null && status_ == DocumentStatus.signed && data is null
      ? signedContent_ : content(), name_, settings, new OnlineValidationSource);
    synchronized (this) {
      valid_ = validation.signed;
      signatureCount_ = validation.signatureCount;
      report_ = validation.reportHtml;
      return valid_;
    }
  }

  /**
   * Firma con la credencial y, si los ajustes lo piden, extiende a LTA (sign). El
   * resultado queda en signedContent; si falla, signedWithErrors. Quien firma avisa a la
   * interfaz (firmador.documents.manager lo hace después de guardar).
   */
  void sign(CardSignInfo card) @trusted {
    synchronized (this) {
      usedCard_ = card;
      signedWithErrors_ = false;
    }
    if (settings.signASiC) forceAsic();
    SigningInput input;
    input.content = content();
    input.name = name_;
    input.mimeType = mimeType_;
    input.settings = settings;
    input.additionalDocuments = additionalDocuments;
    auto signed = signer.sign(input, card);
    synchronized (this) {
      signedContent_ = signed;
      if (signed is null) {
        signedWithErrors_ = true;
        status_ = DocumentStatus.errorSigning;
      }
    }
    if (settings.extendDocument && signed !is null) extend();
    synchronized (this) {
      if (!signedWithErrors_) status_ = DocumentStatus.signed;
    }
  }

  /// Extiende la firma a LTA con el firmador del documento (extend).
  void extend() @trusted {
    ExtensionInput input;
    input.signed = signedContent;
    input.name = name_;
    // Como la versión Java, sólo lo que no es un tipo conocido se extiende con el original aparte.
    if (mimeType_ == SupportedMimeType.BINARY) input.detached = [DetachedContent(name_, content())];
    auto extended = signer.extend(input);
    synchronized (this) {
      if (extended !is null) signedContent_ = extended;
    }
    extendsDone();
  }

  /// Contenido firmado, o null si no se firmó.
  immutable(ubyte)[] signedContent() @trusted {
    synchronized (this) return signedContent_;
  }

  void setSignedContent(immutable(ubyte)[] signed) @trusted {
    synchronized (this) signedContent_ = signed;
  }

  /// Extensión del documento firmado según su firmador (getExtension).
  string signedExtension() @safe {
    return signer.signedExtension(name_);
  }

  /// Ruta donde se guarda firmado: junto al original con «-firmado» (getPathToSave).
  string pathToSave() @trusted {
    synchronized (this) {
      if (pathToSave_ is null) {
        string base = pathname_.length ? pathname_ : name_;
        pathToSave_ = signedFileName(base, signer_.signedExtension(name_));
      }
      return pathToSave_;
    }
  }

  void setPathToSave(string path) @trusted {
    synchronized (this) pathToSave_ = path;
  }

  /// Nombre con que se guarda firmado (getPathToSaveName).
  string pathToSaveName() @safe {
    return baseName(pathToSave);
  }

  /// Carga la vista previa (salvo documentos virtuales) y avisa aunque falle (loadPreview).
  void loadPreview() @trusted {
    scope (exit) previewDone();
    if (virtual_) return;
    try {
      preview.load(content(), name_);
    } catch (Exception exception) {
      error("Vista previa de ", name_, ": ", exception.msg);
    }
  }

  /// Carga la vista previa de un contenido recibido aparte (loadPreviewRemote).
  void loadPreviewOf(immutable(ubyte)[] remoteContent) @trusted {
    scope (exit) previewDone();
    try {
      preview.load(remoteContent, name_);
    } catch (Exception exception) {
      error("Vista previa de ", name_, ": ", exception.msg);
    }
  }

  /// Valida y carga la vista previa si falta (setPrincipal).
  void makePrincipal() @safe {
    if (!validated) validate();
    if (!previewLoaded) loadPreview();
  }

  /// Páginas de la vista previa (getNumberOfPages).
  int previewPageCount() @safe {
    return preview.pageCount();
  }

  string report() @trusted { synchronized (this) return report_; }
  void setReport(string report) @trusted { synchronized (this) report_ = report; }
  bool isSigned() @trusted { synchronized (this) return valid_; }
  bool validated() @trusted { synchronized (this) return validated_; }
  bool previewLoaded() @trusted { synchronized (this) return previewLoaded_; }
  bool isReady() @trusted { synchronized (this) return ready_; }
  size_t signatureCount() @trusted { synchronized (this) return signatureCount_; }
  void setSignatureCount(size_t count) @trusted { synchronized (this) signatureCount_ = count; }
  bool signedWithErrors() @trusted { synchronized (this) return signedWithErrors_; }
  void setSignedWithErrors(bool value) @trusted { synchronized (this) signedWithErrors_ = value; }
  CardSignInfo usedCard() @trusted { synchronized (this) return usedCard_; }
  bool showPreview() @trusted { synchronized (this) return showPreview_; }
  void setShowPreview(bool value) @trusted { synchronized (this) showPreview_ = value; }
  bool massiveSign() @trusted { synchronized (this) return massiveSign_; }
  void setMassiveSign(bool value) @trusted { synchronized (this) massiveSign_ = value; }
  DocumentStatus status() @trusted { synchronized (this) return status_; }
  void setStatus(DocumentStatus value) @trusted { synchronized (this) status_ = value; }
  bool validating() @trusted { synchronized (this) return validating_; }
  void setValidating(bool value) @trusted { synchronized (this) validating_ = value; }

  private void previewDone() @trusted {
    synchronized (this) {
      previewLoaded_ = true;
      ready_ = previewLoaded_ && validated_;
    }
    gui.previewDone(this);
  }

  private void validateDone() @trusted {
    synchronized (this) {
      validated_ = true;
      ready_ = previewLoaded_ && validated_;
    }
    gui.validateDone(this);
  }

  private void extendsDone() @trusted {
    gui.extendsDone(this);
    synchronized (this) status_ = DocumentStatus.signed;
  }
}

/**
 * Ruta del documento firmado: la del original sin extensión, «-firmado» y la extensión
 * del formato (Document.getPathToSave).
 */
string signedFileName(string original, string signedExtension) pure @safe {
  string directory = dirName(original);
  string stem = stripExtension(baseName(original));
  string file = stem ~ "-firmado" ~ signedExtension;
  return directory == "." && !original.canFind('/') && !original.canFind('\\') ? file : buildPath(directory, file);
}

@("should name the signed file next to the original with the format extension")
unittest {
  assert(signedFileName("/home/a/contrato.pdf", ".pdf") == "/home/a/contrato-firmado.pdf");
  assert(signedFileName("/home/a/datos.json", ".json") == "/home/a/datos-firmado.json");
  assert(signedFileName("/home/a/sin", ".asice") == "/home/a/sin-firmado.asice");
  assert(signedFileName("factura.xml", ".xml") == "factura-firmado.xml");
}
