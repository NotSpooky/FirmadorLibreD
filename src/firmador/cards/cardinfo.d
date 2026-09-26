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
 * Credenciales de firma detectadas (CardSignInfo en la versión Java): tarjetas PKCS#11,
 * almacenes PKCS#12 y la credencial «sólo PIN», con los datos del titular que salen del
 * certificado (CertificateSubject). Su JSON es el que publican /certificates y el comando
 * getcertificates del shell (@contract card-json, ver toJson).
 */
module firmador.cards.cardinfo;

import std.format : format;
import std.json : JSONValue;
import std.string : strip;

import firmador.asn1.oids;
import firmador.i18n : t;
import firmador.tokens.token : SecretPin;
import firmador.util.datetime : costaRicaDay;
import firmador.x509.certificate : Certificate;

/// Tipo de credencial; los valores son los de las constantes de la versión Java.
enum CardType : int { pkcs11 = 1, pkcs12 = 2, onlyPin = 3, remote = 4 }

/// Datos del titular tal como vienen en el subject del certificado.
struct CertificateSubject {
  string identification;
  string firstName;
  string lastName;
  string commonName;
  string organization;
  /// Fecha de caducidad en formato yyyy-MM-dd, que es lo que se enseña en la interfaz.
  string expires;
}

/// Datos del titular de un certificado (CertificateSubject.parse).
CertificateSubject certificateSubject(const Certificate certificate) pure @safe {
  CertificateSubject subject;
  subject.identification = certificate.subject.first(oidSerialNumber);
  subject.lastName = certificate.subject.first(oidSurname);
  subject.firstName = certificate.subject.first(oidGivenName);
  subject.commonName = certificate.subject.first(oidCommonName);
  subject.organization = certificate.subject.first(oidOrganization);
  subject.expires = costaRicaDay(certificate.notAfter);
  return subject;
}

/// Credencial de firma.
final class CardSignInfo {
  CardType cardType;
  string identification;
  string firstName;
  string lastName;
  string commonName;
  string organization;
  string expires;
  /// En PKCS#11 la etiqueta de la clave; en PKCS#12 la ruta del almacén.
  string tokenSerialNumber;
  /// Ranura PKCS#11, -1 si es la primera disponible o no aplica.
  long slotID = -1;
  SecretPin pin;
  /// Certificado de la credencial (null en un PKCS#12 que nunca se registró).
  Certificate certificate;

  /// Tarjeta PKCS#11 detectada.
  this(CardType cardType, const CertificateSubject subject, string tokenSerialNumber, long slotID,
      Certificate certificate) pure @safe {
    this.cardType = cardType;
    identification = subject.identification;
    firstName = subject.firstName;
    lastName = subject.lastName;
    commonName = subject.commonName;
    organization = subject.organization;
    expires = subject.expires;
    this.tokenSerialNumber = tokenSerialNumber;
    this.slotID = slotID;
    this.certificate = certificate;
  }

  /// PKCS#12 sin registrar: sólo la ruta, con textos de relleno en lugar del titular.
  this(string path, string identification) @safe {
    cardType = CardType.pkcs12;
    tokenSerialNumber = path;
    this.identification = identification;
    firstName = t("cardsigninfo_name");
    lastName = t("cardsigninfo_of_the_person");
    commonName = t("cardsigninfo_name_person");
    organization = t("cardsigninfo_type_person");
    expires = "";
  }

  /// Credencial «sólo PIN»: PKCS#11 con la primera ranura disponible.
  this(SecretPin pin) pure @safe {
    cardType = CardType.onlyPin;
    this.pin = pin;
  }

  /// Serial decimal del certificado; null si no tiene (lo que publica «tokenSerialNumber» en JSON).
  string idToken() const pure @safe {
    return certificate is null ? null : certificate.serialDecimal;
  }

  /// Texto con que se muestra en listas y en el diálogo de PIN.
  string displayInfo() const @safe {
    if (cardType == CardType.pkcs11 || (cardType == CardType.pkcs12 && certificate !is null)) {
      string name = (firstName ~ " " ~ lastName).strip;
      // En persona jurídica no hay nombre ni apellidos y quedaría un " (…)" suelto.
      if (name.length == 0) name = commonName;
      return name ~ " (" ~ identification ~ t("cardsigninfo_expires") ~ expires ~ ")";
    }
    return identification;
  }

  /// Destruye el PIN guardado.
  void destroyPin() pure @safe {
    if (pin !is null) pin.destroy();
  }

  /// JSON público de la credencial, con los mismos nombres que serializaba Jackson.
  JSONValue toJson() const pure @safe {
    JSONValue json;
    json["identification"] = jsonOrNull(identification);
    json["firstName"] = jsonOrNull(firstName);
    json["lastName"] = jsonOrNull(lastName);
    json["commonName"] = jsonOrNull(commonName);
    json["organization"] = jsonOrNull(organization);
    json["tokenSerialNumber"] = jsonOrNull(idToken);
    json["certificate"] = certificate is null ? JSONValue(null) : JSONValue(certificate.base64);
    return json;
  }
}

private JSONValue jsonOrNull(string value) pure @safe {
  return value is null ? JSONValue(null) : JSONValue(value);
}

/**
 * Empareja una credencial con un identificador enviado por el cliente: el serial del
 * certificado (decimal u hexadecimal) o la identificación del titular, y en PKCS#12
 * también el nombre o la ruta del almacén. No se compara la etiqueta de la clave, que en
 * las tarjetas es la misma para todas («LlaveDeFirma»).
 */
bool matchesIdentifier(const CardSignInfo card, string identifier) pure @safe {
  import std.path : baseName;
  import std.uni : icmp;
  if (card is null || identifier is null) return false;
  string id = identifier.strip;
  if (id.length == 0) return false;
  if (card.cardType == CardType.pkcs12) {
    string path = card.tokenSerialNumber;
    if (path.length && (id == path || id == baseName(path))) return true;
  }
  if (card.certificate !is null) {
    if (icmp(id, card.certificate.serialDecimal) == 0 || icmp(id, card.certificate.serialHex) == 0) return true;
  }
  return id == card.identification;
}

/// Huella de una lista de credenciales, para saber si una nueva lectura cambió algo.
string fingerprint(const CardSignInfo[] cards) pure @safe {
  string result;
  foreach (card; cards) {
    result ~= format("%d|%s|%s|%d|%s;", cast(int) card.cardType, card.identification, card.tokenSerialNumber,
      card.slotID, card.certificate is null ? "" : card.certificate.serialDecimal);
  }
  return result;
}

version (unittest) {
  import firmador.crypto.openssl : makeTestIdentity;
  import firmador.x509.certificate : parseCertificate;
}

@("should publish the Jackson field names and the decimal serial when serializing a card")
unittest {
  auto identity = makeTestIdentity("JUAN PEREZ PEREZ (FIRMA)", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto subject = certificateSubject(certificate);
  assert(subject.identification == "CPF-01-0101-0101");
  assert(subject.commonName == "JUAN PEREZ PEREZ (FIRMA)");
  auto card = new CardSignInfo(CardType.pkcs11, subject, "LlaveDeFirma", 0, certificate);
  auto json = card.toJson();
  assert(json["tokenSerialNumber"].str == "4242");
  assert(json["certificate"].str == certificate.base64);
  assert("pin" !in json.object && "slotID" !in json.object);
}

@("should match cards by certificate serial, identification or store name but not by key label")
unittest {
  auto identity = makeTestIdentity("Titular", "x");
  auto certificate = parseCertificate(identity.certificateDer);
  auto card = new CardSignInfo(CardType.pkcs11, certificateSubject(certificate), "LlaveDeFirma", 1, certificate);
  assert(matchesIdentifier(card, "4242"));
  assert(matchesIdentifier(card, "1092"));
  assert(matchesIdentifier(card, " CPF-01-0101-0101 "));
  assert(!matchesIdentifier(card, "LlaveDeFirma"));
  assert(!matchesIdentifier(card, ""));
  auto store = new CardSignInfo("/home/u/certs/almacen.p12", "almacen.p12");
  assert(matchesIdentifier(store, "almacen.p12"));
  assert(matchesIdentifier(store, "/home/u/certs/almacen.p12"));
  assert(fingerprint([card]) != fingerprint([card, store]));
}
