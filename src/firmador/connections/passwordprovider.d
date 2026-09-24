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
 * Llavero del sistema para la contraseña del almacén de tokens (PasswordProvider en la
 * versión Java): Secret Service con libsecret en Linux (src/c/csecret.c), el
 * administrador de credenciales en Windows y el llavero de macOS. firmador.settingsmanager
 * lo usa al leer la configuración; si no hay llavero la contraseña queda ofuscada en
 * config.properties. La contraseña nunca se escribe en la bitácora.
 */
module firmador.connections.passwordprovider;

import std.exception : enforce;
import std.format : format;
import std.logger : error, info, warning;
import std.string : fromStringz, toStringz;

import firmador.configuration : keyringAccountName, keyringServiceName;
import firmador.settingsmanager : SecureCredentialStore;

/// Descripción del estado del llavero para la bitácora (getStorageInfo).
string storageDescription(bool available, bool hasPassword) pure nothrow @safe {
  if (!available) return "Credential Manager: NO DISPONIBLE";
  return hasPassword ? "Credential Manager del SO: ACTIVO" : "Credential Manager del SO: DISPONIBLE (sin contraseña guardada)";
}

/**
 * Llavero del sistema de esta plataforma, o null si no hay uno usable (sin servicio de
 * secretos en la sesión, por ejemplo).
 */
SecureCredentialStore systemCredentialStore() @safe {
  version (linux) {
    auto store = new LibsecretCredentialStore;
  } else version (Windows) {
    auto store = new WindowsCredentialStore;
  } else version (OSX) {
    auto store = new KeychainCredentialStore;
  } else {
    warning("No hay llavero del sistema en esta plataforma; la contraseña del almacén de tokens irá en la configuración");
    return null;
  }
  if (!store.isAvailable()) {
    warning("El llavero del sistema no está disponible; la contraseña del almacén de tokens irá en la configuración");
    return null;
  }
  info("Llavero del sistema disponible para la contraseña del almacén de tokens");
  return store;
}

/// Comportamiento común: disponibilidad calculada una vez y descripción del estado.
private abstract class CachedCredentialStore : SecureCredentialStore {
  private bool probed;
  private bool available;

  /// Consulta la contraseña; null si no hay. Lanza si el llavero no responde.
  protected abstract string lookup() @safe;
  /// Guarda la contraseña. Lanza si el llavero la rechaza.
  protected abstract void store(string password) @safe;

  bool isAvailable() @safe {
    if (!probed) {
      probed = true;
      try {
        lookup();
        available = true;
      } catch (Exception exception) {
        warning("El llavero del sistema no responde: ", exception.msg);
        available = false;
      }
    }
    return available;
  }

  string load() @safe {
    if (!isAvailable()) return null;
    try {
      return lookup();
    } catch (Exception exception) {
      error("No se pudo leer la contraseña del llavero del sistema: ", exception.msg);
      throw new Exception("No se pudo leer la contraseña del llavero del sistema: " ~ exception.msg, exception);
    }
  }

  bool save(string password) @safe {
    enforce(password.length > 0, "La contraseña del almacén de tokens no puede estar vacía");
    if (!isAvailable()) {
      warning("Llavero del sistema no disponible, no se puede guardar la contraseña");
      return false;
    }
    try {
      store(password);
      info("Contraseña guardada en el llavero del sistema");
      return true;
    } catch (Exception exception) {
      error("No se pudo guardar la contraseña en el llavero del sistema: ", exception.msg);
      return false;
    }
  }

  string storageInfo() @safe {
    if (!isAvailable()) return storageDescription(false, false);
    try {
      return storageDescription(true, lookup().length > 0);
    } catch (Exception exception) {
      return "Credential Manager del SO: ERROR - " ~ exception.msg;
    }
  }
}

version (linux) {
  import csecret;

  /// Secret Service (GNOME Keyring, KWallet, portal de flatpak) mediante libsecret.
  private final class LibsecretCredentialStore : CachedCredentialStore {
    private SecretSchema schema;

    this() @trusted {
      schema.name = "cr.libre.firmador.KeystorePassword";
      schema.flags = SECRET_SCHEMA_NONE;
      schema.attributes[0].name = "service";
      schema.attributes[0].type = SECRET_SCHEMA_ATTRIBUTE_STRING;
      schema.attributes[1].name = "account";
      schema.attributes[1].type = SECRET_SCHEMA_ATTRIBUTE_STRING;
    }

    protected override string lookup() @trusted {
      GError* failure = null;
      char* found = secret_password_lookup_sync(&schema, null, &failure, "service".ptr,
        keyringServiceName.toStringz, "account".ptr, keyringAccountName.toStringz, null);
      throwOnError(failure, "consultar");
      if (found is null) return null;
      scope (exit) secret_password_free(found);
      return fromStringz(found).idup;
    }

    protected override void store(string password) @trusted {
      GError* failure = null;
      auto stored = secret_password_store_sync(&schema, "default".ptr, "Firmador Libre".ptr, password.toStringz, null,
        &failure, "service".ptr, keyringServiceName.toStringz, "account".ptr, keyringAccountName.toStringz, null);
      throwOnError(failure, "guardar");
      enforce(stored, "libsecret no guardó la contraseña");
    }

    private static void throwOnError(GError* failure, string action) @trusted {
      if (failure is null) return;
      string message = failure.message is null ? "sin detalle" : fromStringz(failure.message).idup;
      g_error_free(failure);
      throw new Exception(format("libsecret no pudo %s la contraseña: %s", action, message));
    }
  }
}

version (Windows) {
  import core.sys.windows.windef : BOOL, DWORD, FILETIME, LPBYTE;
  import core.sys.windows.winbase : GetLastError;
  import std.utf : toUTF16z;

  private extern (Windows) nothrow @nogc {
    struct CREDENTIAL_ATTRIBUTEW {
      wchar* Keyword;
      DWORD Flags;
      DWORD ValueSize;
      LPBYTE Value;
    }

    struct CREDENTIALW {
      DWORD Flags;
      DWORD Type;
      wchar* TargetName;
      wchar* Comment;
      FILETIME LastWritten;
      DWORD CredentialBlobSize;
      LPBYTE CredentialBlob;
      DWORD Persist;
      DWORD AttributeCount;
      CREDENTIAL_ATTRIBUTEW* Attributes;
      wchar* TargetAlias;
      wchar* UserName;
    }

    BOOL CredReadW(const(wchar)* targetName, DWORD type, DWORD flags, CREDENTIALW** credential);
    BOOL CredWriteW(CREDENTIALW* credential, DWORD flags);
    void CredFree(void* buffer);
  }

  private enum DWORD credTypeGeneric = 1;
  private enum DWORD credPersistLocalMachine = 2;
  private enum DWORD errorNotFound = 1168;

  /// Administrador de credenciales de Windows (advapi32).
  private final class WindowsCredentialStore : CachedCredentialStore {
    protected override string lookup() @trusted {
      CREDENTIALW* credential = null;
      if (!CredReadW(keyringServiceName.toUTF16z, credTypeGeneric, 0, &credential)) {
        DWORD code = GetLastError();
        if (code == errorNotFound) return null;
        throw new Exception(format("CredReadW falló con el código %d", code));
      }
      scope (exit) CredFree(credential);
      return (cast(char[]) credential.CredentialBlob[0 .. credential.CredentialBlobSize]).idup;
    }

    protected override void store(string password) @trusted {
      auto blob = cast(ubyte[]) password.dup;
      scope (exit) blob[] = 0;
      CREDENTIALW credential;
      credential.Type = credTypeGeneric;
      credential.TargetName = cast(wchar*) keyringServiceName.toUTF16z;
      credential.UserName = cast(wchar*) keyringAccountName.toUTF16z;
      credential.CredentialBlobSize = cast(DWORD) blob.length;
      credential.CredentialBlob = blob.ptr;
      credential.Persist = credPersistLocalMachine;
      enforce(CredWriteW(&credential, 0), format("CredWriteW falló con el código %d", GetLastError()));
    }
  }
}

version (OSX) {
  private extern (C) nothrow @nogc {
    alias OSStatus = int;
    alias SecKeychainItemRef = void*;
    OSStatus SecKeychainFindGenericPassword(const(void)* keychainOrArray, uint serviceNameLength,
      const(char)* serviceName, uint accountNameLength, const(char)* accountName, uint* passwordLength,
      void** passwordData, SecKeychainItemRef* itemRef);
    OSStatus SecKeychainAddGenericPassword(void* keychain, uint serviceNameLength, const(char)* serviceName,
      uint accountNameLength, const(char)* accountName, uint passwordLength, const(void)* passwordData,
      SecKeychainItemRef* itemRef);
    OSStatus SecKeychainItemModifyAttributesAndData(SecKeychainItemRef itemRef, const(void)* attrList, uint length,
      const(void)* data);
    OSStatus SecKeychainItemFreeContent(void* attrList, void* data);
    void CFRelease(const(void)* object);
  }

  private enum OSStatus errSecSuccess = 0;
  private enum OSStatus errSecItemNotFound = -25_300;

  /// Llavero de macOS (Security.framework).
  private final class KeychainCredentialStore : CachedCredentialStore {
    protected override string lookup() @trusted {
      uint length;
      void* data;
      auto status = SecKeychainFindGenericPassword(null, cast(uint) keyringServiceName.length, keyringServiceName.ptr,
        cast(uint) keyringAccountName.length, keyringAccountName.ptr, &length, &data, null);
      if (status == errSecItemNotFound) return null;
      enforce(status == errSecSuccess, format("SecKeychainFindGenericPassword falló con el código %d", status));
      scope (exit) SecKeychainItemFreeContent(null, data);
      return (cast(char*) data)[0 .. length].idup;
    }

    protected override void store(string password) @trusted {
      SecKeychainItemRef item;
      auto status = SecKeychainFindGenericPassword(null, cast(uint) keyringServiceName.length, keyringServiceName.ptr,
        cast(uint) keyringAccountName.length, keyringAccountName.ptr, null, null, &item);
      if (status == errSecSuccess) {
        scope (exit) CFRelease(item);
        status = SecKeychainItemModifyAttributesAndData(item, null, cast(uint) password.length, password.ptr);
        enforce(status == errSecSuccess, format("SecKeychainItemModifyAttributesAndData falló con el código %d", status));
        return;
      }
      enforce(status == errSecItemNotFound, format("SecKeychainFindGenericPassword falló con el código %d", status));
      status = SecKeychainAddGenericPassword(null, cast(uint) keyringServiceName.length, keyringServiceName.ptr,
        cast(uint) keyringAccountName.length, keyringAccountName.ptr, cast(uint) password.length, password.ptr, null);
      enforce(status == errSecSuccess, format("SecKeychainAddGenericPassword falló con el código %d", status));
    }
  }
}

@("should describe the keyring state without the password when reporting storage info")
unittest {
  assert(storageDescription(false, true) == "Credential Manager: NO DISPONIBLE");
  assert(storageDescription(true, true) == "Credential Manager del SO: ACTIVO");
  assert(storageDescription(true, false) == "Credential Manager del SO: DISPONIBLE (sin contraseña guardada)");
}
