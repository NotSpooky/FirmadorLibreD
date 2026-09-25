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
 * Validación de un documento según su tipo (ValidatorFactory y GeneralValidator): PDF,
 * XML, JSON (JAdES), contenedores ASiC y OpenDocument, OOXML (con su reporte propio) y
 * firmas CMS sueltas. Los documentos de otros tipos, o que no traen firmas, se informan
 * como no firmados.
 */
module firmador.validators.factory;

import std.algorithm : canFind, startsWith;
import std.logger : info, trace;

import firmador.containers.asic : classifyContainer;
import firmador.documents.mimetype;
import firmador.settings : Settings;
import firmador.util.zip;
import firmador.validation.model;
import firmador.validation.report : reportHtml;
import firmador.validation.sources : ValidationDataSource;
import firmador.validators.cadesvalidator : validateCades;
import firmador.validators.containervalidator : validateContainer;
import firmador.validators.jadesvalidator : validateJades;
import firmador.validators.ooxmlvalidator : checkOoxmlSignatures, ooxmlReport;
import firmador.validators.pdfvalidator : validatePdf;
import firmador.validators.xmlvalidator : validateXml;

/// Resultado de validar un documento para la interfaz.
struct DocumentValidation {
  /// El documento tiene firmas (isSigned).
  bool signed;
  /// Cantidad de firmas (amountOfSignatures).
  size_t signatureCount;
  /// Reporte HTML (getStringReport).
  string reportHtml;
}

/// El ZIP es un contenedor ASiC (con mimetype ASiC o META-INF/signature*.p7s o signatures*.xml).
private bool isAsicContainer(const ZipEntry[] entries) pure @safe {
  auto content = classifyContainer(entries);
  if (content.mimeType.startsWith("application/vnd.etsi.asic")) return true;
  return classifyContainer(entries, true).signatureDocuments.length > 0 || content.signatureDocuments.length > 0;
}

/**
 * Valida el documento por su tipo.
 *
 * Throws: Exception si el documento está dañado de forma que no se puede interpretar.
 */
DocumentValidation validateDocument(immutable(ubyte)[] content, string name, const Settings settings,
    ValidationDataSource source) @trusted {
  auto type = detectMimeType(name);
  info("Validando ", name);
  DocumentValidationResult result;
  if (isOpenXml(type)) {
    auto checks = checkOoxmlSignatures(content, source);
    return DocumentValidation(checks.length > 0, checks.length, ooxmlReport(checks, settings));
  }
  if (isPdf(type)) {
    result = validatePdf(content, name, source);
  } else if (isXml(type)) {
    result = validateXml(content, name, source);
  } else if (isJson(type)) {
    try {
      result = validateJades(content, name, source);
    } catch (Exception exception) {
      trace("El JSON no es un JWS: ", exception.msg);
      result.documentName = name;
    }
  } else if (isOpenDocument(type) || isAsic(type) || isZip(type) || looksLikeZip(content)) {
    auto entries = readZip(content);
    if (isOpenDocument(type) || isAsic(type) || isAsicContainer(entries)) result = validateContainer(content, name, source);
    else result.documentName = name;
  } else {
    // Firma CMS suelta (p7s, p7m) o cualquier otro archivo.
    try {
      result = validateCades(content, name, source);
    } catch (Exception exception) {
      trace("El archivo no es una firma CMS: ", exception.msg);
      result.documentName = name;
    }
  }
  size_t count = result.signatures.length;
  return DocumentValidation(count > 0, count, reportHtml(result));
}
