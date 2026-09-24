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
 * Texto con que se muestra un error al usuario (UtilsService.showError y
 * handlePKCS11Exception en la versión Java): los códigos de PKCS#11 más comunes y la
 * biblioteca de firma ausente tienen su explicación; lo demás se muestra con el tipo y el
 * detalle. Lo usan la ventana y los modos de consola.
 */
module firmador.gui.errors;

import std.algorithm : canFind;
import std.format : format;

import firmador.i18n : t;
import firmador.signers.common : rootCause;
import firmador.tokens.pkcs11 : Pkcs11Exception, Pkcs11LibraryException;

/// Mensaje para el usuario (HTML sencillo) y si es sólo una advertencia (PIN incorrecto).
struct UserError {
  string message;
  bool warning;
}

/// Mensaje de un error, a partir de su causa raíz.
UserError userErrorFor(Throwable failure) @safe {
  auto cause = rootCause(failure);
  string detail = cause.msg.idup;
  if (auto pkcs11 = cast(Pkcs11Exception) cause) return pkcs11Error(detail);
  if (cast(Pkcs11LibraryException) cause && (detail.canFind("asepkcs") || detail.canFind("libASEP11"))) {
    return UserError(t("guiswing_show_error_installers"), false);
  }
  return UserError(format(t("guiswing_show_error_default"), typeid(cause).name, detail), false);
}

/// Explicación de un código de PKCS#11 (handlePKCS11Exception).
private UserError pkcs11Error(string code) @safe {
  switch (code) {
    case "CKR_GENERAL_ERROR":
      version (OSX) {
        return UserError("Error genérico del controlador de tarjetas.<br>"
          ~ "Si se está ejecutando Agente GAUDI, debe hacer clic en el icono de Agente GAUDI<br>"
          ~ "de la barra superior derecha. En el menú que aparece, elegir 'Salir'.<br>"
          ~ "Esto permitirá que Firmador funcione correctamente.", false);
      } else {
        return UserError(t("guiswing_show_error_pkcs11_general"), false);
      }
    case "CKR_SLOT_ID_INVALID": return UserError(t("guiswing_show_error_pkcs11_slotinvalid"), false);
    case "CKR_PIN_INCORRECT": return UserError(t("guiswing_show_error_pkcs11_pinincorrect"), true);
    case "CKR_PIN_LOCKED": return UserError(t("guiswing_show_error_pkcs11_pinlocked"), false);
    case "CKR_PIN_LEN_RANGE": return UserError(t("guiswing_show_error_pkcs11_pintooshort"), false);
    case "CKR_FUNCTION_FAILED", "0x80000066": return UserError(t("guiswing_show_error_pkcs11_update_plugin"), false);
    default:
      return UserError(format(t("guiswing_show_error_pkcs11_default"), "Pkcs11Exception", code), false);
  }
}

@("should explain PKCS#11 codes and wrap other errors with their type when showing them")
unittest {
  import firmador.i18n : setMessagesLocale;
  setMessagesLocale("es", "CR");
  auto incorrect = userErrorFor(new Pkcs11Exception(0xA0, "C_Login"));
  assert(incorrect.warning && incorrect.message == t("guiswing_show_error_pkcs11_pinincorrect"));
  assert(!userErrorFor(new Pkcs11Exception(0xA4, "C_Login")).warning);
  auto missing = userErrorFor(new Pkcs11LibraryException("no se pudo cargar /usr/lib/x64-athena/libASEP11.so"));
  assert(missing.message == t("guiswing_show_error_installers"));
  auto other = userErrorFor(new Exception("disco lleno"));
  assert(other.message.canFind("object.Exception") && other.message.canFind("disco lleno"));
}
