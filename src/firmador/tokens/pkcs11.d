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
 * Acceso a tarjetas de firma por PKCS#11 (lo que en la versión Java hacían SunPKCS11 y
 * el Pkcs11SignatureToken de DSS): carga de la biblioteca del fabricante, enumeración de
 * ranuras y certificados, inicio de sesión con PIN y firma. Todas las llamadas a la
 * biblioteca pasan por un mismo cerrojo porque el monitor de tarjetas, el diálogo de PIN
 * y la firma corren en hilos distintos (PKCS11_LOCK en Java). Ver firmador.tokens.token.
 */
module firmador.tokens.pkcs11;

import core.stdc.config : c_ulong;
import core.sync.mutex : Mutex;
import std.algorithm : canFind;
import std.conv : to;
import std.exception : enforce;
import std.format : format;
import std.logger : info, trace, warning;
import std.string : fromStringz, strip, toStringz;

import cpkcs11;

import firmador.crypto.digest;

// Banderas definidas en la cabecera con desplazamientos, que ImportC no evalúa.
private enum c_ulong flagTokenPresent = 1UL << 0;
private enum c_ulong flagOsLockingOk = 1UL << 1;
private enum c_ulong flagRwSession = 1UL << 1;
private enum c_ulong flagSerialSession = 1UL << 2;

/// Error devuelto por la biblioteca PKCS#11; el mensaje es el nombre del código (CKR_PIN_INCORRECT…).
class Pkcs11Exception : Exception {
  c_ulong code;

  this(c_ulong code, string operation, string file = __FILE__, size_t line = __LINE__) @safe {
    this.code = code;
    super(pkcs11ErrorName(code), file, line);
    this.operation = operation;
  }

  /// Función de PKCS#11 que falló, para las bitácoras.
  string operation;
}

/// La biblioteca PKCS#11 no se pudo cargar (ruta, dependencias o arquitectura).
class Pkcs11LibraryException : Exception {
  this(string message, string file = __FILE__, size_t line = __LINE__) pure nothrow @safe {
    super(message, file, line);
  }
}

/// Nombre del código de retorno de PKCS#11, como los mensajes de PKCS11Exception en Java.
string pkcs11ErrorName(c_ulong code) pure @safe {
  switch (code) {
    case 0x00: return "CKR_OK";
    case 0x01: return "CKR_CANCEL";
    case 0x02: return "CKR_HOST_MEMORY";
    case 0x03: return "CKR_SLOT_ID_INVALID";
    case 0x05: return "CKR_GENERAL_ERROR";
    case 0x06: return "CKR_FUNCTION_FAILED";
    case 0x07: return "CKR_ARGUMENTS_BAD";
    case 0x08: return "CKR_NO_EVENT";
    case 0x09: return "CKR_NEED_TO_CREATE_THREADS";
    case 0x0A: return "CKR_CANT_LOCK";
    case 0x10: return "CKR_ATTRIBUTE_READ_ONLY";
    case 0x11: return "CKR_ATTRIBUTE_SENSITIVE";
    case 0x12: return "CKR_ATTRIBUTE_TYPE_INVALID";
    case 0x13: return "CKR_ATTRIBUTE_VALUE_INVALID";
    case 0x20: return "CKR_DATA_INVALID";
    case 0x21: return "CKR_DATA_LEN_RANGE";
    case 0x30: return "CKR_DEVICE_ERROR";
    case 0x31: return "CKR_DEVICE_MEMORY";
    case 0x32: return "CKR_DEVICE_REMOVED";
    case 0x50: return "CKR_FUNCTION_CANCELED";
    case 0x54: return "CKR_FUNCTION_NOT_SUPPORTED";
    case 0x60: return "CKR_KEY_HANDLE_INVALID";
    case 0x62: return "CKR_KEY_SIZE_RANGE";
    case 0x63: return "CKR_KEY_TYPE_INCONSISTENT";
    case 0x68: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case 0x70: return "CKR_MECHANISM_INVALID";
    case 0x71: return "CKR_MECHANISM_PARAM_INVALID";
    case 0x82: return "CKR_OBJECT_HANDLE_INVALID";
    case 0x90: return "CKR_OPERATION_ACTIVE";
    case 0x91: return "CKR_OPERATION_NOT_INITIALIZED";
    case 0xA0: return "CKR_PIN_INCORRECT";
    case 0xA1: return "CKR_PIN_INVALID";
    case 0xA2: return "CKR_PIN_LEN_RANGE";
    case 0xA3: return "CKR_PIN_EXPIRED";
    case 0xA4: return "CKR_PIN_LOCKED";
    case 0xB0: return "CKR_SESSION_CLOSED";
    case 0xB1: return "CKR_SESSION_COUNT";
    case 0xB3: return "CKR_SESSION_HANDLE_INVALID";
    case 0xB4: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case 0xB5: return "CKR_SESSION_READ_ONLY";
    case 0xC0: return "CKR_SIGNATURE_INVALID";
    case 0xC1: return "CKR_SIGNATURE_LEN_RANGE";
    case 0xD0: return "CKR_TEMPLATE_INCOMPLETE";
    case 0xD1: return "CKR_TEMPLATE_INCONSISTENT";
    case 0xE0: return "CKR_TOKEN_NOT_PRESENT";
    case 0xE1: return "CKR_TOKEN_NOT_RECOGNIZED";
    case 0xE2: return "CKR_TOKEN_WRITE_PROTECTED";
    case 0x100: return "CKR_USER_ALREADY_LOGGED_IN";
    case 0x101: return "CKR_USER_NOT_LOGGED_IN";
    case 0x102: return "CKR_USER_PIN_NOT_INITIALIZED";
    case 0x103: return "CKR_USER_TYPE_INVALID";
    case 0x104: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case 0x105: return "CKR_USER_TOO_MANY_TYPES";
    case 0x150: return "CKR_BUFFER_TOO_SMALL";
    case 0x190: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case 0x191: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    default: return format("0x%08X", code);
  }
}

private __gshared Mutex pkcs11Lock;
private __gshared Pkcs11Module[string] loadedModules;

shared static this() {
  pkcs11Lock = new Mutex;
}

/// Toma el cerrojo de PKCS#11 durante `action` (también para agrupar varias llamadas).
auto withPkcs11Lock(T)(scope T delegate() action) @trusted {
  pkcs11Lock.lock();
  scope (exit) pkcs11Lock.unlock();
  return action();
}

/// Texto de un campo de longitud fija de PKCS#11 (relleno con espacios).
string fixedText(T)(const ref T field) @trusted {
  auto bytes = cast(const(char)[]) (cast(const(ubyte)*) &field)[0 .. T.sizeof];
  import std.utf : validate;
  string text = bytes.idup.strip;
  try {
    validate(text);
    return text;
  } catch (Exception) {
    import std.array : appender;
    auto latin = appender!string;
    foreach (b; cast(const(ubyte)[]) bytes) latin ~= cast(dchar) b;
    return latin[].strip;
  }
}

/// Biblioteca PKCS#11 cargada e inicializada; se reutiliza por ruta durante toda la ejecución.
final class Pkcs11Module {
  immutable string libraryPath;
  private void* handle;
  private CK_FUNCTION_LIST* functions;

  private this(string libraryPath) @safe {
    this.libraryPath = libraryPath;
  }

  /**
   * Carga (una sola vez por ruta) e inicializa la biblioteca.
   *
   * Throws: Pkcs11LibraryException si no se puede cargar; Pkcs11Exception si C_Initialize falla.
   */
  static Pkcs11Module load(string libraryPath) @trusted {
    enforce!Pkcs11LibraryException(libraryPath.length > 0, "No se configuró la biblioteca PKCS#11");
    pkcs11Lock.lock();
    scope (exit) pkcs11Lock.unlock();
    if (auto existing = libraryPath in loadedModules) return *existing;
    auto loaded = new Pkcs11Module(libraryPath);
    loaded.open();
    loadedModules[libraryPath] = loaded;
    return loaded;
  }

  private void open() @trusted {
    info("Cargando la biblioteca PKCS#11 ", libraryPath);
    version (Windows) {
      import core.sys.windows.windows : LoadLibraryW, GetProcAddress, GetLastError;
      import std.utf : toUTF16z;
      handle = LoadLibraryW(libraryPath.toUTF16z);
      enforce!Pkcs11LibraryException(handle !is null,
        format("No se pudo cargar la biblioteca PKCS#11 %s (error %d)", libraryPath, GetLastError()));
      auto getFunctionList = cast(CK_C_GetFunctionList) GetProcAddress(handle, "C_GetFunctionList");
    } else {
      import core.sys.posix.dlfcn : dlopen, dlsym, dlerror, RTLD_NOW, RTLD_LOCAL;
      handle = dlopen(libraryPath.toStringz, RTLD_NOW | RTLD_LOCAL);
      enforce!Pkcs11LibraryException(handle !is null,
        format("No se pudo cargar la biblioteca PKCS#11 %s: %s", libraryPath, fromStringz(dlerror())));
      auto getFunctionList = cast(CK_C_GetFunctionList) dlsym(handle, "C_GetFunctionList");
    }
    enforce!Pkcs11LibraryException(getFunctionList !is null,
      format("La biblioteca %s no exporta C_GetFunctionList", libraryPath));
    check(getFunctionList(&functions), "C_GetFunctionList");
    enforce!Pkcs11LibraryException(functions !is null, format("La biblioteca %s no entregó sus funciones", libraryPath));

    CK_C_INITIALIZE_ARGS arguments;
    arguments.flags = flagOsLockingOk;
    c_ulong result = functions.C_Initialize(&arguments);
    if (result != CKR_OK && result != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      trace("C_Initialize no aceptó CKF_OS_LOCKING_OK (", pkcs11ErrorName(result), "); se reintenta sin banderas");
      arguments.flags = 0;
      result = functions.C_Initialize(&arguments);
    }
    if (result != CKR_CRYPTOKI_ALREADY_INITIALIZED) check(result, "C_Initialize");
    CK_INFO libraryInfo;
    check(functions.C_GetInfo(&libraryInfo), "C_GetInfo");
    info("Interfaz PKCS#11: ", fixedText(libraryInfo.libraryDescription), " de ", fixedText(libraryInfo.manufacturerID));
  }

  private static void check(c_ulong result, string operation) @safe {
    if (result != CKR_OK) throw new Pkcs11Exception(result, operation);
  }

  /// Ranuras con una tarjeta presente.
  CK_SLOT_ID[] slotsWithToken() @trusted {
    return withPkcs11Lock!(CK_SLOT_ID[])(() {
      c_ulong count;
      check(functions.C_GetSlotList(CK_TRUE, null, &count), "C_GetSlotList");
      auto slots = new CK_SLOT_ID[count];
      if (count) check(functions.C_GetSlotList(CK_TRUE, slots.ptr, &count), "C_GetSlotList");
      return slots[0 .. count];
    });
  }

  /// La ranura reporta una tarjeta presente.
  bool hasToken(CK_SLOT_ID slot) @trusted {
    return withPkcs11Lock!bool(() {
      CK_SLOT_INFO slotInfo;
      check(functions.C_GetSlotInfo(slot, &slotInfo), "C_GetSlotInfo");
      trace("Ranura ", slot, ": ", fixedText(slotInfo.slotDescription));
      return (slotInfo.flags & flagTokenPresent) != 0;
    });
  }

  /// Etiqueta y número de serie de la tarjeta de una ranura.
  string[2] tokenLabelAndSerial(CK_SLOT_ID slot) @trusted {
    return withPkcs11Lock!(string[2])(() {
      CK_TOKEN_INFO tokenInfo;
      check(functions.C_GetTokenInfo(slot, &tokenInfo), "C_GetTokenInfo");
      string[2] result = [fixedText(tokenInfo.label), fixedText(tokenInfo.serialNumber)];
      return result;
    });
  }

  /// Abre una sesión en la ranura (de sólo lectura salvo que se pida lo contrario).
  Pkcs11Session openSession(CK_SLOT_ID slot, bool readWrite = false) @trusted {
    return withPkcs11Lock!Pkcs11Session(() {
      CK_SESSION_HANDLE session;
      c_ulong flags = flagSerialSession | (readWrite ? flagRwSession : 0);
      check(functions.C_OpenSession(slot, flags, null, null, &session), "C_OpenSession");
      return new Pkcs11Session(this, slot, session);
    });
  }

  /// Mecanismos que admite la tarjeta de la ranura.
  c_ulong[] mechanisms(CK_SLOT_ID slot) @trusted {
    return withPkcs11Lock!(c_ulong[])(() {
      c_ulong count;
      check(functions.C_GetMechanismList(slot, null, &count), "C_GetMechanismList");
      auto list = new c_ulong[count];
      if (count) check(functions.C_GetMechanismList(slot, list.ptr, &count), "C_GetMechanismList");
      return list[0 .. count];
    });
  }
}

/// Certificado guardado en la tarjeta con los atributos que lo emparejan con su clave.
struct TokenCertificate {
  immutable(ubyte)[] der;
  string label;
  immutable(ubyte)[] id;
  CK_SLOT_ID slot;
}

/// Sesión abierta en una ranura.
final class Pkcs11Session {
  private Pkcs11Module owner;
  immutable CK_SLOT_ID slot;
  private CK_SESSION_HANDLE handle;
  private bool open;

  private this(Pkcs11Module owner, CK_SLOT_ID slot, CK_SESSION_HANDLE handle) @safe {
    this.owner = owner;
    this.slot = slot;
    this.handle = handle;
    this.open = true;
  }

  /// Cierra la sesión (se puede llamar más de una vez).
  void close() @trusted {
    withPkcs11Lock!void(() {
      if (!open) return;
      open = false;
      c_ulong result = owner.functions.C_CloseSession(handle);
      if (result != CKR_OK && result != 0xB3 && result != 0xB0)
        warning("C_CloseSession devolvió ", pkcs11ErrorName(result));
    });
  }

  /**
   * Inicia sesión de usuario con el PIN; si ya estaba iniciada no es un error.
   *
   * Throws: Pkcs11Exception con CKR_PIN_INCORRECT, CKR_PIN_LOCKED… si la tarjeta lo rechaza.
   */
  void login(const(char)[] pin, bool contextSpecific = false) @trusted {
    withPkcs11Lock!void(() {
      c_ulong userType = contextSpecific ? CKU_CONTEXT_SPECIFIC : CKU_USER;
      c_ulong result = owner.functions.C_Login(handle, userType, cast(ubyte*) pin.ptr, pin.length);
      if (result == CKR_USER_ALREADY_LOGGED_IN) {
        trace("El usuario ya había iniciado sesión en la ranura ", slot);
        return;
      }
      Pkcs11Module.check(result, "C_Login");
      info("Inicio de sesión exitoso en la ranura ", slot);
    });
  }

  /// Cierra la sesión de usuario; si no había, se ignora.
  void logout() @trusted {
    withPkcs11Lock!void(() {
      c_ulong result = owner.functions.C_Logout(handle);
      if (result != CKR_OK) trace("C_Logout ignorado: ", pkcs11ErrorName(result));
    });
  }

  private CK_OBJECT_HANDLE[] findObjects(CK_ATTRIBUTE[] template_) @trusted {
    CK_OBJECT_HANDLE[] found;
    Pkcs11Module.check(owner.functions.C_FindObjectsInit(handle, template_.ptr, template_.length), "C_FindObjectsInit");
    scope (exit) owner.functions.C_FindObjectsFinal(handle);
    CK_OBJECT_HANDLE[32] batch;
    while (true) {
      c_ulong count;
      Pkcs11Module.check(owner.functions.C_FindObjects(handle, batch.ptr, batch.length, &count), "C_FindObjects");
      if (count == 0) break;
      found ~= batch[0 .. count];
      if (found.length > 1024) break;
    }
    return found;
  }

  private immutable(ubyte)[] attribute(CK_OBJECT_HANDLE object, c_ulong type) @trusted {
    CK_ATTRIBUTE query = CK_ATTRIBUTE(type, null, 0);
    c_ulong result = owner.functions.C_GetAttributeValue(handle, object, &query, 1);
    if (result == 0x12 || result == 0x11 || query.ulValueLen == cast(c_ulong) -1) return null;
    Pkcs11Module.check(result, "C_GetAttributeValue");
    auto value = new ubyte[query.ulValueLen];
    query.pValue = value.ptr;
    Pkcs11Module.check(owner.functions.C_GetAttributeValue(handle, object, &query, 1), "C_GetAttributeValue");
    return value.idup;
  }

  private CK_ATTRIBUTE classTemplate(ref c_ulong objectClass) @trusted {
    return CK_ATTRIBUTE(CKA_CLASS, &objectClass, c_ulong.sizeof);
  }

  /// Certificados guardados en la tarjeta.
  TokenCertificate[] certificates() @trusted {
    return withPkcs11Lock!(TokenCertificate[])(() {
      c_ulong objectClass = CKO_CERTIFICATE;
      CK_ATTRIBUTE[1] query = [classTemplate(objectClass)];
      TokenCertificate[] result;
      foreach (object; findObjects(query[])) {
        auto value = attribute(object, CKA_VALUE);
        if (value.length == 0) continue;
        TokenCertificate certificate;
        certificate.der = value;
        certificate.label = cast(string) attribute(object, CKA_LABEL).idup;
        certificate.id = attribute(object, CKA_ID);
        certificate.slot = slot;
        result ~= certificate;
      }
      return result;
    });
  }

  /**
   * Clave privada que acompaña al certificado: la de mismo CKA_ID, si no la de misma
   * etiqueta, y si no la única que haya.
   *
   * Throws: Exception si no se encuentra una clave que corresponda.
   */
  CK_OBJECT_HANDLE privateKeyFor(const TokenCertificate certificate) @trusted {
    return withPkcs11Lock!CK_OBJECT_HANDLE(() {
      c_ulong objectClass = CKO_PRIVATE_KEY;
      CK_OBJECT_HANDLE[] keys = findObjects([classTemplate(objectClass)]);
      enforce(keys.length > 0, "La tarjeta no expone claves privadas después de iniciar sesión");
      if (certificate.id.length) {
        foreach (key; keys) if (attribute(key, CKA_ID) == certificate.id) return key;
      }
      if (certificate.label.length) {
        foreach (key; keys) if (cast(string) attribute(key, CKA_LABEL) == certificate.label) return key;
      }
      enforce(keys.length == 1, format("No se encontró la clave privada del certificado «%s» entre %d claves",
        certificate.label, keys.length));
      return keys[0];
    });
  }

  /// La clave es RSA (si no, se trata como EC).
  bool isRsaKey(CK_OBJECT_HANDLE key) @trusted {
    return withPkcs11Lock!bool(() {
      auto type = attribute(key, CKA_KEY_TYPE);
      if (type.length != c_ulong.sizeof) return true;
      return *cast(const(c_ulong)*) type.ptr == CKK_RSA;
    });
  }

  /**
   * Firma `data` con la clave: RSA PKCS#1 v1.5 (con CKM_SHA256_RSA_PKCS y similares si la
   * tarjeta los tiene, o CKM_RSA_PKCS con el DigestInfo calculado aquí) o ECDSA, cuya firma
   * se devuelve como r||s. `pin` se vuelve a presentar si la clave exige autenticarse en
   * cada uso (CKA_ALWAYS_AUTHENTICATE).
   *
   * Throws: Pkcs11Exception si la tarjeta no firma.
   */
  ubyte[] sign(CK_OBJECT_HANDLE key, DigestAlgorithm digest, const(ubyte)[] data, const(char)[] pin) @trusted {
    bool rsa = isRsaKey(key);
    c_ulong[] available = owner.mechanisms(slot);
    return withPkcs11Lock!(ubyte[])(() {
      c_ulong mechanismType;
      ubyte[] input;
      if (rsa) {
        c_ulong combined = combinedRsaMechanism(digest);
        if (combined != 0 && available.canFind(combined)) {
          mechanismType = combined;
          input = data.dup;
        } else {
          mechanismType = CKM_RSA_PKCS;
          input = digestInfoPrefix(digest).dup ~ digestOf(digest, data);
        }
      } else {
        mechanismType = CKM_ECDSA;
        input = digestOf(digest, data);
      }
      CK_MECHANISM mechanism = CK_MECHANISM(mechanismType, null, 0);
      Pkcs11Module.check(owner.functions.C_SignInit(handle, &mechanism, key), "C_SignInit");
      auto alwaysAuthenticate = attribute(key, CKA_ALWAYS_AUTHENTICATE);
      if (alwaysAuthenticate.length && alwaysAuthenticate[0] != 0) {
        Pkcs11Module.check(owner.functions.C_Login(handle, CKU_CONTEXT_SPECIFIC, cast(ubyte*) pin.ptr, pin.length),
          "C_Login (CKU_CONTEXT_SPECIFIC)");
      }
      c_ulong length;
      Pkcs11Module.check(owner.functions.C_Sign(handle, input.ptr, input.length, null, &length), "C_Sign");
      auto signature = new ubyte[length];
      Pkcs11Module.check(owner.functions.C_Sign(handle, input.ptr, input.length, signature.ptr, &length), "C_Sign");
      return signature[0 .. length];
    });
  }
}

private c_ulong combinedRsaMechanism(DigestAlgorithm digest) pure nothrow @safe @nogc {
  final switch (digest) {
    case DigestAlgorithm.sha1: return 0x06;
    case DigestAlgorithm.sha224: return 0x46;
    case DigestAlgorithm.sha256: return 0x40;
    case DigestAlgorithm.sha384: return 0x41;
    case DigestAlgorithm.sha512: return 0x42;
  }
}

@("should name PKCS#11 return codes like the Java wrapper when reporting errors")
unittest {
  assert(pkcs11ErrorName(0xA0) == "CKR_PIN_INCORRECT");
  assert(pkcs11ErrorName(0xE1) == "CKR_TOKEN_NOT_RECOGNIZED");
  assert(pkcs11ErrorName(0x80000066) == "0x80000066");
  assert(combinedRsaMechanism(DigestAlgorithm.sha256) == CKM_SHA256_RSA_PKCS);
}
