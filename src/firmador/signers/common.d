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
 * Lo que comparten todos los firmadores (CRSigner en la versión Java): abrir el
 * dispositivo de la credencial, elegir la clave de no repudio, la cadena de la jerarquía
 * nacional del firmante, los servicios de sello y validación, el texto de la firma visible
 * y el aviso de cada fallo con el mismo criterio que la versión Java.
 */
module firmador.signers.common;

import std.algorithm : canFind;
import std.datetime.systime : Clock, SysTime;
import std.exception : enforce;
import std.format : format;
import std.logger : error, info, warning;
import std.string : strip;
import std.array : replace;

import firmador.asn1.oids;
import firmador.cards.cardinfo;
import firmador.cards.pkcs11library;
import firmador.cms.tsp;
import firmador.crypto.digest;
import firmador.crypto.openssl : WrongPasswordException;
import firmador.gui.guiinterface;
import firmador.i18n : t;
import firmador.settings;
import firmador.settingsmanager : currentSettings;
import firmador.tokens.pkcs11 : Pkcs11Exception, Pkcs11LibraryException;
import firmador.tokens.token;
import firmador.util.datetime;
import firmador.validation.certpath;
import firmador.validation.pool;
import firmador.validation.sources;
import firmador.x509.certificate;

/// La operación no se pudo completar y el motivo ya se le mostró al usuario.
class ReportedSigningFailure : Exception {
  /// Params: cause = la excepción que se avisó, encadenada para quien necesite su tipo.
  this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line, cause);
  }
}

/// Dispositivo abierto con la clave que se usa para firmar.
struct SigningKey {
  SignatureToken token;
  TokenKey key;

  Certificate certificate() pure @safe {
    return key.certificate;
  }

  /// Firma `data` con SHA-256.
  ubyte[] sign(const(ubyte)[] data) @safe {
    return token.sign(key, DigestAlgorithm.sha256, data);
  }

  void close() @safe {
    token.close();
  }
}

/**
 * Servicios que usa una firma: conjunto de certificados y servicios en línea. Las copias
 * comparten el conjunto y el servicio, que las funciones de abajo amplían y consultan.
 */
struct SigningServices {
  CertificatePool pool;
  ValidationSource source;
}

/// Servicios con la jerarquía nacional y conexión a los servicios del BCCR.
SigningServices onlineSigningServices() @safe {
  return SigningServices(CertificatePool.withNationalHierarchy(), new ValidationSource);
}

/// Cadena del certificado con la jerarquía incluida, del emisor a la raíz (getCertificateChain en Java).
Certificate[] issuerChain(SigningServices services, Certificate certificate) @safe {
  bool trusted;
  auto path = buildPath(certificate, services.pool, null, trusted);
  return path.length > 1 ? path[1 .. $] : [];
}

/**
 * Intermedios del firmante hasta la raíz de confianza, sin ella: lo que DSS incluye en la
 * firma (BaselineBCertificateSelector con trustAnchorBPPolicy).
 */
Certificate[] intermediateChain(SigningServices services, Certificate certificate) @safe {
  Certificate[] intermediates;
  foreach (issuer; issuerChain(services, certificate)) {
    if (services.pool.isTrusted(issuer)) break;
    intermediates ~= issuer;
  }
  return intermediates;
}

/// Sello de tiempo sobre `data`.
TimeStampToken timestamp(SigningServices services, const(ubyte)[] data) @safe {
  return timestamper(services)(digestOf(DigestAlgorithm.sha256, data));
}

/// Sellador de resúmenes SHA-256 ya calculados, para los formatos que agregan sellos.
Timestamper timestamper(SigningServices services) @safe {
  return (const(ubyte)[] digest) @safe => services.source.timestamp(DigestAlgorithm.sha256, digest);
}

/**
 * Datos de validación de lo que reúne cada formato para su nivel LT
 * (xadesSigningMaterial, jadesSigningMaterial…): cadenas y revocación de sus
 * `certificates`, sin repetir las revocaciones que la firma ya trae.
 */
ValidationData validationData(SigningServices services, ValidationData material) @safe {
  return validationData(services, material.certificates, material.ocspResponses, material.crls);
}

/// Datos de validación (cadenas y revocación) de los certificados, para los niveles LT.
ValidationData validationData(SigningServices services, Certificate[] certificates,
    const(ubyte[])[] embeddedOcsp = null, const(ubyte[])[] embeddedCrls = null) @safe {
  return collectValidationData(certificates, services.pool, services.source, Clock.currTime, embeddedOcsp,
    embeddedCrls);
}

/// Excepción más interna de la cadena (getRootCause).
Throwable rootCause(Throwable failure) pure @safe {
  Throwable current = failure;
  while (current.next !is null) current = current.next;
  return current;
}

/**
 * Abre el dispositivo de la credencial y elige la primera clave de no repudio
 * (getSignatureConnection + getPrivateKey). Si falla, avisa por la interfaz como la
 * versión Java y lanza ReportedSigningFailure.
 */
SigningKey openSigningKey(GuiInterface gui, CardSignInfo card) @trusted {
  enforce(card !is null, "No se indicó la credencial con la que firmar");
  SignatureToken token;
  try {
    if (card.cardType == CardType.pkcs12) {
      token = new Pkcs12SignatureToken(card.tokenSerialNumber, card.pin);
    } else {
      token = new Pkcs11SignatureToken(pkcs11LibraryPath(currentSettings().extraPKCS11Lib), card.pin, card.slotID);
    }
  } catch (WrongPasswordException exception) {
    // Con la excepción y no con su texto: -dshell detiene el lote según el tipo (gui/errors.d).
    error("Error al obtener la conexión de firma: ", exception.msg);
    gui.showError(exception);
    throw new ReportedSigningFailure(exception.msg, exception);
  } catch (Pkcs11LibraryException exception) {
    error("Error al conectar con el dispositivo: ", exception.msg);
    if (exception.msg.canFind("need 'arm64e'")) gui.showMessage(t("pin_dialog_warning_arm"));
    else gui.showError(exception);
    throw new ReportedSigningFailure(exception.msg, exception);
  } catch (Pkcs11Exception exception) {
    error("Error ", exception.msg, " obteniendo manejador de llaves privadas de la tarjeta");
    if (exception.msg == "CKR_TOKEN_NOT_RECOGNIZED") {
      info(exception.msg, " (dispositivo de firma no reconocido)");
    }
    gui.showError(exception);
    throw new ReportedSigningFailure(exception.msg, exception);
  } catch (Exception exception) {
    error("Error al obtener la conexión de firma: ", exception.msg);
    gui.showError(exception);
    throw new ReportedSigningFailure(exception.msg, exception);
  }
  gui.nextStep(t("signers_getting_key_handler"));
  // Como en CRSigner.getPrivateKey: la primera clave de no repudio. Las tarjetas de firma
  // digital sin modificar traen una sola.
  auto chosen = selectNonRepudiationKey(token.keys());
  if (chosen.isNull) {
    token.close();
    error("El dispositivo no tiene una clave de firma de no repudio");
    gui.showError(new Exception(t("guiswing_show_error_providerexception")));
    throw new ReportedSigningFailure("Sin clave de no repudio");
  }
  return SigningKey(token, chosen.get);
}

/// Firma de bytes que preparó otro (un servidor o Firmador Remoto) y con qué clave se hizo.
struct PreparedDataSignature {
  ubyte[] value;
  bool rsa;
  Certificate certificate;
}

/**
 * Firma con SHA-256 bytes preparados por otro (BasicSigner.sign): abre la credencial, elige
 * la clave de no repudio y firma. Null si no se pudo; el motivo ya se mostró.
 */
PreparedDataSignature* signPreparedData(GuiInterface gui, CardSignInfo card, const(ubyte)[] data) @safe {
  return withSigningKey!(PreparedDataSignature*)(gui, card, "Error al firmar los datos preparados",
    (signingKey) => new PreparedDataSignature(signingKey.sign(data), signingKey.key.rsa, signingKey.certificate));
}

/**
 * Abre la credencial, hace `use` con su clave y la cierra. Si no se puede abrir, o `use`
 * falla, avisa (salvo que ya se avisó: ReportedSigningFailure) y devuelve `T.init`.
 *
 * Params:
 *   gui = donde se avisa.
 *   card = la credencial, con su PIN.
 *   failureContext = qué se hacía, para la bitácora si `use` falla.
 *   use = lo que se hace con la clave abierta.
 */
T withSigningKey(T)(GuiInterface gui, CardSignInfo card, string failureContext,
    scope T delegate(SigningKey signingKey) @safe use) @safe {
  try {
    auto signingKey = openSigningKey(gui, card);
    scope (exit) signingKey.close();
    return use(signingKey);
  } catch (ReportedSigningFailure) {
    return T.init;
  } catch (Exception exception) {
    error(failureContext, ": ", exception.msg);
    gui.showError(exception);
    return T.init;
  }
}

/**
 * Comprueba que el certificado esté vigente ahora: DSS se niega a firmar con uno vencido.
 * Avisa y lanza ReportedSigningFailure si no lo está.
 */
void requireValidCertificate(GuiInterface gui, const Certificate certificate) @safe {
  auto now = Clock.currTime;
  if (now > certificate.notAfter) {
    warning("El certificado seleccionado para firmar ha vencido: ", certificate.toString);
    gui.showMessage(t("signers_expired_certificate"));
    throw new ReportedSigningFailure("Certificado vencido");
  }
  if (now < certificate.notBefore) {
    warning("El certificado seleccionado para firmar todavía no es válido: ", certificate.toString);
    gui.showError(new Exception(format("El certificado no es válido antes de %s", certificate.notBefore.toISOExtString)));
    throw new ReportedSigningFailure("Certificado aún no válido");
  }
}

/// Texto de la firma visible con los datos del certificado de firma (getSignatureText).
string signatureText(const Certificate certificate, const Settings documentSettings, const Settings appSettings,
    SysTime now) @safe {
  return signatureTextFor(certificate.subject.first(oidCommonName), certificate.subject.first(oidOrganization),
    certificate.subject.first(oidSerialNumber), documentSettings, appSettings, now);
}

/**
 * Texto de la firma visible: nombre, organización e identificación, fecha declarada y la
 * razón, el lugar y el contacto o, si no hay, el mensaje de firma. La vista previa lo usa
 * con los datos de la tarjeta conectada o con los de ejemplo.
 */
string signatureTextFor(string commonName, string organization, string identification,
    const Settings documentSettings, const Settings appSettings, SysTime now) @safe {
  string pattern = documentSettings.dateFormat.strip.length ? documentSettings.dateFormat : appSettings.getDateFormat();
  string date = formatJavaDate(pattern, now.toOtherTZ(costaRicaTimeZone()), dateLanguageFor(appSettings.language));
  string additional;
  if (!documentSettings.hideSignatureAdvice) {
    additional = appSettings.defaultSignMessage;
    if (documentSettings.defaultSignMessage.strip.length) additional = documentSettings.defaultSignMessage;
  }
  bool hasReason = documentSettings.reason.strip.length > 0;
  bool hasLocation = documentSettings.place.strip.length > 0;
  if (hasReason) additional = t("signers_visible_signature_reason") ~ " " ~ documentSettings.reason ~ "\n";
  if (hasLocation) {
    string place = t("signers_visible_signature_place") ~ " " ~ documentSettings.place;
    additional = hasReason ? additional ~ place : place;
  }
  if (documentSettings.contact.strip.length) {
    string contact = t("signers_visible_signature_contact") ~ " " ~ documentSettings.contact;
    additional = hasReason || hasLocation ? additional ~ "  " ~ contact : contact;
  }
  return commonName ~ "\n" ~ organization ~ ", " ~ identification ~ ".\n" ~ t("signers_visible_signature_declared_date")
    ~ " " ~ date ~ "\n" ~ additional.replace("\t", " ");
}

/// Mensaje de «no se pudo añadir el sello» con la causa, como en la versión Java.
string timestampFailureMessage(string key, Throwable failure) @safe {
  string cause = rootCause(failure).msg;
  string template_ = t(key);
  return template_.canFind("%s") ? template_.replace("%s", cause) : template_ ~ " " ~ cause;
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
  import std.datetime.date : DateTime;
  import std.datetime.timezone : UTC;
}

@("should compose the visible signature text with reason, place and contact like the Java version")
unittest {
  auto certificate = parseCertificate(makeTestIdentity("JUAN PEREZ (FIRMA)", "x").certificateDer);
  auto appSettings = new Settings();
  auto documentSettings = new Settings();
  documentSettings.reason = "Aprobado";
  documentSettings.place = "San José";
  documentSettings.contact = "8888-8888";
  auto now = SysTime(DateTime(2026, 9, 22, 20, 4, 5), UTC());
  string text = signatureText(certificate, documentSettings, appSettings, now);
  import std.string : splitLines;
  auto lines = text.splitLines;
  assert(lines[0] == "JUAN PEREZ (FIRMA)");
  assert(lines[1] == ", CPF-01-0101-0101.");
  assert(lines[2] == t("signers_visible_signature_declared_date") ~ " 22/09/2026 02:04:05 p. m.");
  assert(lines[3] == t("signers_visible_signature_reason") ~ " Aprobado");
  assert(lines[4] == t("signers_visible_signature_place") ~ " San José  " ~ t("signers_visible_signature_contact")
    ~ " 8888-8888");
  documentSettings.reason = "";
  documentSettings.place = "";
  documentSettings.contact = "";
  assert(signatureText(certificate, documentSettings, appSettings, now).splitLines[3]
    == appSettings.defaultSignMessage.splitLines[0]);
}
