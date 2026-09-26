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
 * Detección de credenciales de firma (SmartCardDetector y PKCS11Manager): lee las
 * tarjetas por PKCS#11, arma las entradas de los almacenes PKCS#12 configurados y, con la
 * ventana abierta, vigila los lectores (firmador.cards.terminalwatcher) para avisar a los
 * oyentes sólo cuando la lista cambia. También resuelve las operaciones que la conexión
 * Gaudi hace directamente con la tarjeta.
 */
module firmador.cards.detector;

import core.atomic : atomicLoad, atomicStore;
import core.stdc.config : c_ulong;
import core.sync.mutex : Mutex;
import core.thread : Thread;
import core.time : dur, MonoTime;
import std.algorithm : canFind;
import std.exception : basicExceptionCtors;
import std.file : exists, isFile;
import std.logger : error, info, trace, warning;

import firmador.cards.cardinfo;
import firmador.cards.pkcs11library;
import firmador.cards.pkcs12store;
import firmador.cards.terminalwatcher;
import firmador.configuration : clientAuthenticationEkuOid, pkcs11CertificateCacheMilliseconds,
  smartCardPollIntervalMilliseconds;
import firmador.crypto.digest : DigestAlgorithm;
import firmador.settingsmanager : currentSettings;
import firmador.tokens.pkcs11;
import firmador.tokens.token;
import firmador.x509.certificate;

/// Oyente de cambios en las credenciales detectadas (SmartCardListener).
alias SmartCardListener = void delegate(const(CardSignInfo)[] cards);

/// La biblioteca PKCS#11 es de otra arquitectura (UnsupportedArchitectureException).
class UnsupportedArchitectureException : Exception {
  mixin basicExceptionCtors;
}

/// Certificado leído de una tarjeta, con dónde está y cómo se llama su clave.
struct DetectedCertificate {
  Certificate certificate;
  TokenCertificate token;
}

/// Certificados de autenticación y de firma de la tarjeta; null los que no tenga.
struct AuthenticationAndSignCertificates {
  Certificate authentication;
  Certificate signing;

  /// Trae los dos (lo que pide el hub del BCCR y los servicios externos para conectarse).
  bool complete() const pure nothrow @safe @nogc {
    return authentication !is null && signing !is null;
  }
}

/// Detector de credenciales compartido por la aplicación.
final class SmartCardDetector {
  private Mutex lock;
  private Mutex listenerLock;
  private SmartCardListener[] listeners;
  private CardSignInfo[] cardinfo;
  private string lastFingerprint;
  private DetectedCertificate[] cachedCertificates;
  private MonoTime cacheTime;
  private bool cacheValid;
  private shared bool stopping;
  private Thread monitor;
  private CardTerminalWatcher watcher;
  /// Registro de almacenes PKCS#12; se puede sustituir en pruebas.
  Pkcs12CredentialStore pkcs12Store;

  this() @trusted {
    lock = new Mutex;
    listenerLock = new Mutex;
    pkcs12Store = Pkcs12CredentialStore.instance();
  }

  /// Biblioteca PKCS#11 según la configuración vigente.
  string libraryPath() @safe {
    return pkcs11LibraryPath(currentSettings().extraPKCS11Lib);
  }

  /// Arranca el monitor de lectores (sólo con la ventana: los modos de consola leen a demanda).
  void start() @trusted {
    if (monitor !is null) return;
    monitor = new Thread(&run);
    monitor.isDaemon = true;
    monitor.name = "SmartCardDetector";
    monitor.start();
  }

  /// Termina el monitoreo de forma ordenada.
  void shutdown() @trusted {
    atomicStore(stopping, true);
    if (watcher !is null) watcher.cancel();
  }

  private void run() @trusted {
    try {
      watcher = CardTerminalWatcher.create();
      while (!atomicLoad(stopping)) {
        scanAndNotifyIfChanged();
        if (atomicLoad(stopping)) break;
        if (watcher !is null) {
          if (watcher.awaitChange(smartCardPollIntervalMilliseconds)) invalidateCache();
        } else {
          Thread.sleep(dur!"msecs"(smartCardPollIntervalMilliseconds));
        }
      }
      if (watcher !is null) watcher.close();
    } catch (Throwable failure) {
      error("El monitor de tarjetas se detuvo: ", failure.msg);
    }
  }

  /// Un fallo leyendo el lector no puede matar el monitor: se reintenta en la próxima vuelta.
  private void scanAndNotifyIfChanged() @trusted {
    try {
      if (scanCards(true)) notifyListeners();
    } catch (Exception exception) {
      trace("Escaneo de tarjetas fallido, se reintentará: ", exception.msg);
    }
  }

  /// Olvida los certificados leídos de la tarjeta para volver a pedirlos.
  void invalidateCache() @trusted {
    synchronized (lock) cacheValid = false;
  }

  /**
   * Certificados de las tarjetas presentes, con caché de 30 s: la interfaz los consulta a
   * menudo y leer la tarjeta cada vez sería lento.
   */
  DetectedCertificate[] certificates() @trusted {
    lock.lock();
    scope (exit) lock.unlock();
    if (cacheValid && cachedCertificates.length > 0
        && (MonoTime.currTime - cacheTime).total!"msecs" < pkcs11CertificateCacheMilliseconds) {
      return cachedCertificates.dup;
    }
    cacheTime = MonoTime.currTime;
    cachedCertificates = searchCertificates();
    cacheValid = true;
    return cachedCertificates.dup;
  }

  private DetectedCertificate[] searchCertificates() @trusted {
    Pkcs11Module module_;
    try {
      module_ = Pkcs11Module.load(libraryPath());
    } catch (Pkcs11LibraryException exception) {
      import std.algorithm : canFind;
      if (exception.msg.canFind("incompatible architecture") || exception.msg.canFind("need 'arm64e'")) {
        import firmador.i18n : t;
        throw new UnsupportedArchitectureException(t("smartcardDetector_unsupported_arch") ~ " (" ~ exception.msg ~ ")");
      }
      throw exception;
    }
    DetectedCertificate[] found;
    foreach (slot; module_.slotsWithToken()) {
      if (!module_.hasToken(slot)) {
        info("No hay tarjeta en la ranura ", slot);
        continue;
      }
      try {
        auto label = module_.tokenLabelAndSerial(slot);
        info("Tarjeta: ", label[0], " (", label[1], ")");
        auto session = module_.openSession(slot);
        scope (exit) session.close();
        foreach (tokenCertificate; session.certificates()) {
          try {
            found ~= DetectedCertificate(parseCertificate(tokenCertificate.der), tokenCertificate);
            trace("Identificador del par de claves: ", tokenCertificate.label);
          } catch (Exception exception) {
            warning("Se omite un certificado ilegible de la ranura ", slot, ": ", exception.msg);
          }
        }
      } catch (Pkcs11Exception exception) {
        if (exception.msg == "CKR_TOKEN_NOT_RECOGNIZED") {
          info("La ranura dice tener una tarjeta pero la biblioteca no la reconoce");
          continue;
        }
        throw exception;
      }
    }
    return found;
  }

  /// Tarjetas PKCS#11 con un certificado de firma (readListSmartCard).
  CardSignInfo[] readListSmartCard() @safe {
    CardSignInfo[] cards;
    foreach (detected; certificates()) {
      if (!isSigningCertificate(detected.certificate)) continue;
      auto subject = certificateSubject(detected.certificate);
      trace(subject.firstName, " ", subject.lastName, " (", subject.identification, "), ", subject.organization, ", ",
        detected.certificate.serialHex, " [", detected.token.label, "] (vence ", subject.expires, ")");
      cards ~= new CardSignInfo(CardType.pkcs11, subject, detected.token.label, cast(long) detected.token.slot,
        detected.certificate);
    }
    return cards;
  }

  /// Entradas de los almacenes PKCS#12 configurados, sin tocar la tarjeta.
  CardSignInfo[] readPkcs12Cards(const string[] paths) @safe {
    CardSignInfo[] cards;
    string[] seen;
    foreach (path; paths) {
      if (path.length == 0 || seen.canFind(path)) continue;
      seen ~= path;
      if (!exists(path) || !isFile(path)) {
        warning("No existe el almacén PKCS#12 indicado: ", path);
        continue;
      }
      auto meta = pkcs12Store.get(path);
      if (meta !is null) {
        try {
          import std.file : getSize;
          if (meta.fileSize != cast(long) getSize(path) || meta.fileLastModified != fileLastModifiedMillis(path))
            info("El almacén ", path, " cambió desde que se registró; su información puede estar desactualizada");
        } catch (Exception) {
        }
      }
      cards ~= pkcs12Card(path, meta);
    }
    return cards;
  }

  /**
   * Relee la lista de credenciales. Devuelve true si difiere de la última notificada.
   *
   * Throws: UnsupportedArchitectureException si la biblioteca es de otra arquitectura.
   */
  private bool scanCards(bool includePkcs12) @trusted {
    lock.lock();
    scope (exit) lock.unlock();
    CardSignInfo[] found;
    try {
      found = readListSmartCard();
    } catch (UnsupportedArchitectureException exception) {
      throw exception;
    } catch (Exception exception) {
      info("No se pudieron leer las tarjetas: ", exception.msg);
      found = [];
    }
    if (includePkcs12) found ~= readPkcs12Cards(currentSettings().pKCS12File);
    cardinfo = found;
    string currentFingerprint = fingerprint(found);
    bool changed = currentFingerprint != lastFingerprint;
    lastFingerprint = currentFingerprint;
    return changed;
  }

  /// Lee ahora mismo tarjetas y almacenes y avisa a los oyentes (readSaveListSmartCard).
  CardSignInfo[] readSaveListSmartCard() @trusted {
    scanCards(true);
    notifyListeners();
    synchronized (lock) return cardinfo.dup;
  }

  /// Credenciales con certificado: las que la API remota puede ofrecer y seleccionar.
  CardSignInfo[] readCardsWithIdentity() @safe {
    CardSignInfo[] withIdentity;
    foreach (card; readSaveListSmartCard()) {
      if (card.certificate !is null) withIdentity ~= card;
      else info("Se omite ", card.tokenSerialNumber, " en la API remota: no tiene certificado con el cual identificarlo");
    }
    return withIdentity;
  }

  /// Última lista leída.
  CardSignInfo[] listCardInfo() @trusted {
    synchronized (lock) return cardinfo.dup;
  }

  /// Hay al menos un certificado en la tarjeta.
  bool isCardPresent() @safe {
    try {
      return certificates().length > 0;
    } catch (Exception) {
      return false;
    }
  }

  /**
   * Cierra la sesión de usuario abierta en la tarjeta, para que el próximo uso vuelva a
   * pedir el PIN. Los almacenes PKCS#12 no tienen sesión que cerrar.
   */
  void restoreSessions() @trusted {
    lock.lock();
    auto current = cardinfo.dup;
    lock.unlock();
    foreach (card; current) {
      if (card.cardType != CardType.pkcs11) continue;
      try {
        auto session = Pkcs11Module.load(libraryPath()).openSession(cast(c_ulong) card.slotID);
        scope (exit) session.close();
        session.logout();
      } catch (Exception exception) {
        warning("No se pudo cerrar la sesión en la ranura ", card.slotID, ": ", exception.msg);
      }
      invalidateCache();
      return;
    }
  }

  /**
   * Certificados de autenticación y de firma de la tarjeta, con la entrada de firma
   * añadida a la lista de credenciales (getAuthenticationAndSignCertificates, lo que pide
   * el hub del BCCR al conectarse).
   */
  AuthenticationAndSignCertificates authenticationAndSignCertificates() @trusted {
    AuthenticationAndSignCertificates result;
    foreach (detected; certificates()) {
      if (detected.certificate.extendedKeyUsages.canFind(clientAuthenticationEkuOid)) {
        result.authentication = detected.certificate;
      } else {
        result.signing = detected.certificate;
      }
      if (isSigningCertificate(detected.certificate)) {
        lock.lock();
        cardinfo ~= new CardSignInfo(CardType.pkcs11, certificateSubject(detected.certificate), detected.token.label,
          cast(long) detected.token.slot, detected.certificate);
        lock.unlock();
      }
    }
    return result;
  }

  /**
   * Firma `data` con SHA-256 y la clave del certificado de firma (el que no es de
   * autenticación), como getSignPrivateKey + Signature SHA256withRSA en Java.
   *
   * Throws: Pkcs11Exception si la tarjeta rechaza el PIN; Exception si no hay certificado de firma.
   */
  ubyte[] signWithSignKey(SecretPin pin, const(ubyte)[] data) @trusted {
    foreach (detected; certificates()) {
      if (detected.certificate.extendedKeyUsages.canFind(clientAuthenticationEkuOid)) continue;
      auto token = new Pkcs11SignatureToken(libraryPath(), pin, cast(long) detected.token.slot);
      scope (exit) token.close();
      foreach (key; token.keys()) {
        if (sameCertificate(key.certificate, detected.certificate)) return token.sign(key, DigestAlgorithm.sha256, data);
      }
    }
    throw new Exception("No se encontró la clave privada de firma en la tarjeta");
  }

  /**
   * Registra un oyente y le entrega lo ya detectado: el monitor sólo avisa cuando la lista
   * cambia, y quien se suscribe después del primer escaneo no se enteraría nunca de la
   * tarjeta que ya estaba puesta.
   */
  void addListener(SmartCardListener listener) @trusted {
    if (listener is null) return;
    listenerLock.lock();
    if (listeners.canFind(listener)) {
      listenerLock.unlock();
      return;
    }
    listeners ~= listener;
    listenerLock.unlock();
    auto detected = listCardInfo();
    if (detected.length) notifyOne(listener, detected);
  }

  private void notifyListeners() @trusted {
    listenerLock.lock();
    auto current = listeners.dup;
    listenerLock.unlock();
    auto detected = listCardInfo();
    foreach (listener; current) notifyOne(listener, detected);
  }

  private void notifyOne(SmartCardListener listener, const(CardSignInfo)[] detected) @trusted {
    try {
      listener(detected);
    } catch (Exception exception) {
      // Un oyente roto no puede impedir que se enteren los demás.
      warning("Fallo notificando el cambio de tarjetas a un oyente: ", exception.msg);
    }
  }
}

/// Credencial de reserva «sólo PIN»: PKCS#11 con la primera ranura disponible.
CardSignInfo createPinOnlyCard(SecretPin pin) pure @safe {
  return new CardSignInfo(pin);
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
}

@("should offer only end entity certificates with signature and non repudiation when filtering card certificates")
unittest {
  auto signing = parseCertificate(makeTestIdentity("Firma", "x", true).certificateDer);
  auto authentication = parseCertificate(makeTestIdentity("Autenticación", "x", false).certificateDer);
  auto root = bundledCertificate!"certs/CA RAIZ NACIONAL - COSTA RICA v2.crt"();
  assert(isSigningCertificate(signing));
  assert(!isSigningCertificate(authentication));
  assert(!isSigningCertificate(root));
}
