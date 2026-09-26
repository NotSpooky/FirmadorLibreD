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

/// Identificadores de objeto (OID) de X.509, CMS, CAdES, TSP y OCSP que usa la aplicación.
module firmador.asn1.oids;

// Atributos de nombres (X.520)
enum string oidCommonName = "2.5.4.3";
enum string oidSurname = "2.5.4.4";
enum string oidSerialNumber = "2.5.4.5";
enum string oidCountry = "2.5.4.6";
enum string oidLocality = "2.5.4.7";
enum string oidStateOrProvince = "2.5.4.8";
enum string oidStreetAddress = "2.5.4.9";
enum string oidOrganization = "2.5.4.10";
enum string oidOrganizationalUnit = "2.5.4.11";
enum string oidTitle = "2.5.4.12";
enum string oidGivenName = "2.5.4.42";
enum string oidOrganizationIdentifier = "2.5.4.97";
enum string oidEmailAddress = "1.2.840.113549.1.9.1";
enum string oidDomainComponent = "0.9.2342.19200300.100.1.25";
enum string oidUserId = "0.9.2342.19200300.100.1.1";

// Extensiones X.509
enum string oidSubjectKeyIdentifier = "2.5.29.14";
enum string oidKeyUsage = "2.5.29.15";
enum string oidSubjectAltName = "2.5.29.17";
enum string oidBasicConstraints = "2.5.29.19";
enum string oidCrlNumber = "2.5.29.20";
enum string oidCrlReason = "2.5.29.21";
enum string oidCrlDistributionPoints = "2.5.29.31";
enum string oidCertificatePolicies = "2.5.29.32";
enum string oidAuthorityKeyIdentifier = "2.5.29.35";
enum string oidExtendedKeyUsage = "2.5.29.37";
enum string oidFreshestCrl = "2.5.29.46";
enum string oidAuthorityInfoAccess = "1.3.6.1.5.5.7.1.1";
enum string oidAccessOcsp = "1.3.6.1.5.5.7.48.1";
enum string oidAccessCaIssuers = "1.3.6.1.5.5.7.48.2";
enum string oidOcspNoCheck = "1.3.6.1.5.5.7.48.1.5";
enum string oidOcspBasic = "1.3.6.1.5.5.7.48.1.1";
enum string oidEkuTimeStamping = "1.3.6.1.5.5.7.3.8";
enum string oidEkuOcspSigning = "1.3.6.1.5.5.7.3.9";

// Algoritmos
enum string oidRsaEncryption = "1.2.840.113549.1.1.1";
enum string oidSha1WithRsa = "1.2.840.113549.1.1.5";
enum string oidRsaPss = "1.2.840.113549.1.1.10";
enum string oidSha256WithRsa = "1.2.840.113549.1.1.11";
enum string oidSha384WithRsa = "1.2.840.113549.1.1.12";
enum string oidSha512WithRsa = "1.2.840.113549.1.1.13";
enum string oidMgf1 = "1.2.840.113549.1.1.8";
enum string oidEcPublicKey = "1.2.840.10045.2.1";
enum string oidEcdsaWithSha1 = "1.2.840.10045.4.1";
enum string oidEcdsaWithSha256 = "1.2.840.10045.4.3.2";
enum string oidEcdsaWithSha384 = "1.2.840.10045.4.3.3";
enum string oidEcdsaWithSha512 = "1.2.840.10045.4.3.4";
enum string oidSha1 = "1.3.14.3.2.26";
enum string oidSha224 = "2.16.840.1.101.3.4.2.4";
enum string oidSha256 = "2.16.840.1.101.3.4.2.1";
enum string oidSha384 = "2.16.840.1.101.3.4.2.2";
enum string oidSha512 = "2.16.840.1.101.3.4.2.3";

// CMS (RFC 5652) y atributos
enum string oidData = "1.2.840.113549.1.7.1";
enum string oidSignedData = "1.2.840.113549.1.7.2";
enum string oidContentType = "1.2.840.113549.1.9.3";
enum string oidMessageDigest = "1.2.840.113549.1.9.4";
enum string oidSigningTime = "1.2.840.113549.1.9.5";
enum string oidTstInfo = "1.2.840.113549.1.9.16.1.4";
enum string oidSigningCertificate = "1.2.840.113549.1.9.16.2.12";
enum string oidSigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
enum string oidSignatureTimeStampToken = "1.2.840.113549.1.9.16.2.14";
enum string oidArchiveTimestampV3 = "0.4.0.1733.2.4";
enum string oidAtsHashIndexV3 = "0.4.0.19122.1.5";
enum string oidRevocationInfoOcsp = "1.3.6.1.5.5.7.16.2";

// Tipos de uso de claves de KeyUsage (orden de bits de RFC 5280)
enum KeyUsageBit : size_t {
  digitalSignature = 0,
  nonRepudiation = 1,
  keyEncipherment = 2,
  dataEncipherment = 3,
  keyAgreement = 4,
  keyCertSign = 5,
  cRLSign = 6,
  encipherOnly = 7,
  decipherOnly = 8,
}
