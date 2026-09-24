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
 * Nombres distinguidos X.500 (subject e issuer de los certificados): sus atributos, la
 * forma RFC 2253 que escribe X500Principal.getName() en Java (la que llevan las firmas
 * XAdES en X509IssuerName) y la comparación de nombres de RFC 5280 §7.1.
 */
module firmador.x509.name;

import std.algorithm : map;
import std.array : appender, array, join;
import std.ascii : toLower, isWhite;
import std.exception : enforce;
import std.format : format;
import std.uni : toLowerUni = toLower;

import firmador.asn1.der;
import firmador.asn1.oids;

/// Atributo de un nombre: tipo, texto y el elemento DER original del valor.
struct NameAttribute {
  string oid;
  string value;
  /// El valor no era una cadena y se muestra en hexadecimal.
  bool binary;
  immutable(ubyte)[] valueDer;
}

/// Nombre X.500 con su codificación DER y sus RDN en el orden en que están codificados.
struct DistinguishedName {
  immutable(ubyte)[] der;
  NameAttribute[][] rdns;

  /// Primer valor del atributo pedido, o "" si no está (del más general al más específico).
  string first(string oid) const pure @safe {
    foreach (rdn; rdns) foreach (attribute; rdn) if (attribute.oid == oid) return attribute.value;
    return "";
  }

  /// Nombre común, o el nombre completo si no tiene (lo que DSS llama nombre legible).
  string readableName() const pure @safe {
    string commonName = first(oidCommonName);
    return commonName.length ? commonName : toRfc2253();
  }

  /// Forma RFC 2253, como X500Principal.getName(): del RDN más específico al más general.
  string toRfc2253() const pure @safe {
    string[] parts;
    foreach_reverse (rdn; rdns) {
      parts ~= rdn.map!(attribute => attributeText(attribute, false)).array.join("+");
    }
    return parts.join(",");
  }

  /// Forma legible (RFC 1779 con palabras clave), para mostrar en la interfaz y en bitácoras.
  string toDisplayString() const pure @safe {
    string[] parts;
    foreach_reverse (rdn; rdns) {
      parts ~= rdn.map!(attribute => attributeText(attribute, true)).array.join(" + ");
    }
    return parts.join(", ");
  }

  /// Igualdad de nombres de RFC 5280 §7.1: mismos atributos y valores sin distinguir mayúsculas ni espacios repetidos.
  bool matches(const DistinguishedName other) const pure @safe {
    if (der == other.der) return true;
    if (rdns.length != other.rdns.length) return false;
    foreach (index, rdn; rdns) {
      if (rdn.length != other.rdns[index].length) return false;
      foreach (attributeIndex, attribute; rdn) {
        auto otherAttribute = other.rdns[index][attributeIndex];
        if (attribute.oid != otherAttribute.oid) return false;
        if (attribute.binary || otherAttribute.binary) {
          if (attribute.valueDer != otherAttribute.valueDer) return false;
        } else if (normalizeValue(attribute.value) != normalizeValue(otherAttribute.value)) {
          return false;
        }
      }
    }
    return true;
  }
}

/**
 * Interpreta un Name (SEQUENCE OF RelativeDistinguishedName).
 *
 * Throws: Asn1Exception si la estructura no es la de un nombre X.500.
 */
DistinguishedName parseName(const DerElement element) pure @safe {
  enforce!Asn1Exception(element.isSequence, "Se esperaba un nombre X.500 (SEQUENCE)");
  DistinguishedName name;
  name.der = element.raw.idup;
  foreach (rdnElement; element.children()) {
    enforce!Asn1Exception(rdnElement.isSet, "Se esperaba un RDN (SET) en el nombre X.500");
    NameAttribute[] rdn;
    foreach (attributeElement; rdnElement.children()) {
      auto reader = attributeElement.reader();
      NameAttribute attribute;
      attribute.oid = reader.next("el tipo del atributo").oidValue;
      auto value = reader.next("el valor del atributo");
      reader.finish("el atributo del nombre");
      attribute.valueDer = value.raw.idup;
      try {
        attribute.value = value.stringValue;
      } catch (Exception) {
        attribute.binary = true;
        attribute.value = "#" ~ hexLower(value.raw);
      }
      rdn ~= attribute;
    }
    enforce!Asn1Exception(rdn.length > 0, "RDN vacío en el nombre X.500");
    name.rdns ~= rdn;
  }
  return name;
}

/// Nombre DER a partir de pares (OID, valor) del más general al más específico, en UTF8String.
ubyte[] encodeName(const string[2][] attributes) pure @safe {
  ubyte[][] rdns;
  foreach (pair; attributes) {
    ubyte[] value = pair[0] == oidCountry || pair[0] == oidSerialNumber
      ? derTlv(0x13, cast(const(ubyte)[]) pair[1]) : derUtf8String(pair[1]);
    rdns ~= derSet(derSequence(derOid(pair[0]), value));
  }
  return derSequence(rdns);
}

private string attributeText(const NameAttribute attribute, bool display) pure @safe {
  string keyword = keywordFor(attribute.oid, display);
  if (attribute.binary) return keyword ~ "=" ~ attribute.value;
  if (!display && keyword == attribute.oid) {
    // X500Principal escribe en hexadecimal el valor de los atributos sin palabra clave.
    return keyword ~ "=#" ~ hexLower(attribute.valueDer);
  }
  return keyword ~ "=" ~ escapeValue(attribute.value);
}

private string keywordFor(string oid, bool display) pure @safe {
  switch (oid) {
    case oidCommonName: return "CN";
    case oidCountry: return "C";
    case oidLocality: return "L";
    case oidStateOrProvince: return "ST";
    case oidOrganization: return "O";
    case oidOrganizationalUnit: return "OU";
    case oidStreetAddress: return "STREET";
    case oidDomainComponent: return "DC";
    case oidUserId: return "UID";
    default: break;
  }
  if (display) {
    switch (oid) {
      case oidSerialNumber: return "SERIALNUMBER";
      case oidSurname: return "SURNAME";
      case oidGivenName: return "GIVENNAME";
      case oidTitle: return "T";
      case oidEmailAddress: return "EMAILADDRESS";
      case oidOrganizationIdentifier: return "ORGANIZATIONIDENTIFIER";
      default: break;
    }
  }
  return oid;
}

/// Escape de RFC 2253 §2.4.
private string escapeValue(string value) pure @safe {
  auto output = appender!string;
  foreach (index, char character; value) {
    bool special = character == ',' || character == '+' || character == '"' || character == '\\' || character == '<'
      || character == '>' || character == ';' || character == '=';
    bool leading = index == 0 && (character == ' ' || character == '#');
    bool trailing = index == value.length - 1 && character == ' ';
    if (special || leading || trailing) output ~= '\\';
    output ~= character;
  }
  return output[];
}

private string normalizeValue(string value) pure @safe {
  auto output = appender!string;
  bool pendingSpace = false;
  foreach (dchar character; value) {
    if (character == ' ' || character == '\t' || character == '\n' || character == '\r') {
      pendingSpace = output[].length > 0;
      continue;
    }
    if (pendingSpace) {
      output ~= ' ';
      pendingSpace = false;
    }
    output ~= toLowerUni(character);
  }
  return output[];
}

/// Hexadecimal en minúsculas de unos bytes.
string hexLower(const(ubyte)[] bytes) pure @safe {
  import std.ascii : lowerHexDigits;
  auto output = new char[bytes.length * 2];
  foreach (index, b; bytes) {
    output[index * 2] = lowerHexDigits[b >> 4];
    output[index * 2 + 1] = lowerHexDigits[b & 0x0F];
  }
  return output.idup;
}

@("should write names like X500Principal when producing RFC 2253 text")
unittest {
  auto encoded = encodeName([[oidCountry, "CR"], [oidOrganization, "BANCO CENTRAL DE COSTA RICA"],
    [oidOrganizationalUnit, "DIVISION SISTEMAS DE PAGO"], [oidSerialNumber, "CPJ-4-000-004017"],
    [oidCommonName, "CA SINPE, PERSONA FISICA v2"]]);
  auto name = parseName(parseDer(encoded));
  assert(name.first(oidOrganization) == "BANCO CENTRAL DE COSTA RICA");
  assert(name.readableName == "CA SINPE, PERSONA FISICA v2");
  assert(name.toRfc2253 == `CN=CA SINPE\, PERSONA FISICA v2,2.5.4.5=#131043504a2d342d3030302d303034303137,`
    ~ "OU=DIVISION SISTEMAS DE PAGO,O=BANCO CENTRAL DE COSTA RICA,C=CR");
  assert(name.toDisplayString == `CN=CA SINPE\, PERSONA FISICA v2, SERIALNUMBER=CPJ-4-000-004017, `
    ~ "OU=DIVISION SISTEMAS DE PAGO, O=BANCO CENTRAL DE COSTA RICA, C=CR");
}

@("should match names that differ only in case and spacing when comparing issuers")
unittest {
  auto first = parseName(parseDer(encodeName([[oidCountry, "CR"], [oidCommonName, "CA  Raiz Nacional"]])));
  auto second = parseName(parseDer(encodeName([[oidCountry, "cr"], [oidCommonName, "ca raiz nacional"]])));
  auto different = parseName(parseDer(encodeName([[oidCountry, "CR"], [oidCommonName, "Otra CA"]])));
  assert(first.matches(second));
  assert(!first.matches(different));
}
