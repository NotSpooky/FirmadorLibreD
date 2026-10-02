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
 * Selectores de archivos y carpetas del sistema (pickPaths): en Linux el portal de
 * freedesktop (org.freedesktop.portal.FileChooser, por D-Bus con gio, que ya se enlaza por
 * libsecret: src/c/csecret.c), que muestra el diálogo de GNOME o KDE y funciona dentro de
 * flatpak; en Windows IFileOpenDialog e IFileSaveDialog. Sin portal (y en macOS) se usa el
 * diálogo de dlangui. Lo usan chooseFiles, chooseDirectory y chooseSaveFile de
 * firmador.gui.desktop.common, que guardan la carpeta elegida.
 */
module firmador.gui.desktop.filepicker;

import std.file : exists, FileException, isDir;
import std.logger : info, warning;
import std.path : dirName;
import std.sumtype : match, SumType;
import std.utf : toUTF32;

import dlangui.core.events : Action;
import dlangui.core.stdaction : StandardAction;
import dlangui.core.i18n : UIString;
import dlangui.dialogs.dialog : Dialog, DialogFlag;
import dlangui.dialogs.filedlg : FileDialog, FileDialogFlag;
import dlangui.platforms.common.platform : Window;

/// Qué se elige.
enum PickKind {
  /// Uno o varios archivos que existen.
  open,
  /// Una carpeta que existe.
  directory,
  /// Dónde guardar un archivo.
  save,
}

/// Pedido a un selector, sea el del sistema o el de dlangui.
struct PickRequest {
  PickKind kind;
  string title;
  /// Carpeta inicial que existe (nearestExistingDirectory), o vacía para la del selector.
  string startDirectory;
  /// Con PickKind.open: se pueden elegir varios archivos.
  bool multiple;
  /// Con PickKind.save: nombre propuesto.
  string proposedName;
  /// Con PickKind.save: extensión de salida con punto (".pdf"); el selector de Windows la
  /// añade a un nombre sin extensión antes de preguntar si se reemplaza.
  string defaultExtension;
}

/**
 * Carpeta desde la que empezar: `candidate` o la más cercana de sus superiores para la que
 * `isDirectory` sea cierta.
 *
 * Returns: la carpeta, o null si no queda ninguna.
 */
string nearestExistingDirectory(alias isDirectory)(string candidate) {
  while (candidate.length) {
    if (isDirectory(candidate)) return candidate;
    string above = dirName(candidate);
    if (above == candidate) break;
    candidate = above;
  }
  return null;
}

/// La ruta existe y es una carpeta; falso también si no se puede consultar.
bool usableDirectory(string path) @trusted {
  try {
    return exists(path) && isDir(path);
  } catch (FileException ignored) {
    // Se borró entre las dos consultas o no se puede leer: no sirve para empezar.
    return false;
  }
}

/// Bytes terminados en cero (`ay` de D-Bus), como pide el portal para las rutas.
struct PortalBytes {
  string value;
}

/// Valor de una opción del portal: booleano, texto o ruta.
alias PortalValue = SumType!(bool, string, PortalBytes);

/// Opción del diccionario `a{sv}` de OpenFile y SaveFile.
struct PortalOption {
  string name;
  PortalValue value;
}

/// Método del portal para el pedido.
string portalMethod(PickKind kind) pure nothrow @safe @nogc {
  return kind == PickKind.save ? "SaveFile" : "OpenFile";
}

/**
 * Opciones de OpenFile o SaveFile para el pedido. El portal ignora las que no conoce
 * (`directory` y `current_folder` de OpenFile son de su versión 3).
 *
 * Params:
 *   request = el pedido.
 *   token = handle_token, que fija la ruta de la respuesta (portalRequestPath).
 */
PortalOption[] portalOptions(const PickRequest request, string token) pure @safe {
  PortalOption[] options = [PortalOption("handle_token", PortalValue(token)), PortalOption("modal", PortalValue(true))];
  final switch (request.kind) {
    case PickKind.open:
      options ~= PortalOption("multiple", PortalValue(request.multiple));
      break;
    case PickKind.directory:
      options ~= PortalOption("directory", PortalValue(true));
      break;
    case PickKind.save:
      if (request.proposedName.length) options ~= PortalOption("current_name", PortalValue(request.proposedName));
      break;
  }
  if (request.startDirectory.length) {
    options ~= PortalOption("current_folder", PortalValue(PortalBytes(request.startDirectory)));
  }
  return options;
}

/**
 * Ruta de la señal Response del pedido: el nombre único de la conexión sin «:» y con «_»
 * en lugar de «.», y el token (org.freedesktop.portal.Request).
 */
string portalRequestPath(string uniqueName, string token) pure @safe {
  import std.array : replace;
  string sender = uniqueName.length && uniqueName[0] == ':' ? uniqueName[1 .. $] : uniqueName;
  return "/org/freedesktop/portal/desktop/request/" ~ sender.replace(".", "_") ~ "/" ~ token;
}

/**
 * Muestra el selector y entrega las rutas elegidas (vacío si se cancela). Se llama desde el
 * hilo de la ventana; `done` también se llama en él.
 *
 * Throws: Exception si el selector del sistema falla (no si falta: entonces se usa el de dlangui).
 */
void pickPaths(Window parent, PickRequest request, void delegate(string[] paths) done) @trusted {
  version (Windows) {
    done(windowsPick(request));
  } else version (linux) {
    portalPickAsync(parent, request, done);
  } else {
    dlanguiPick(parent, request, done);
  }
}

/// Diálogo de archivos de dlangui, modal y redimensionable; pregunta antes de reemplazar.
private void dlanguiPick(Window parent, PickRequest request, void delegate(string[] paths) done) @trusted {
  import std.algorithm : endsWith;
  uint kind;
  final switch (request.kind) {
    case PickKind.open: kind = FileDialogFlag.FileMustExist; break;
    case PickKind.directory: kind = FileDialogFlag.SelectDirectory; break;
    case PickKind.save: kind = FileDialogFlag.Save | FileDialogFlag.ConfirmOverwrite; break;
  }
  auto dialog = new FileDialog(UIString.fromRaw(request.title.toUTF32), parent, null,
    DialogFlag.Modal | DialogFlag.Resizable | kind);
  if (request.startDirectory.length) dialog.path = request.startDirectory;
  if (request.kind == PickKind.open) dialog.allowMultipleFiles = request.multiple;
  if (request.kind == PickKind.save) dialog.filename = request.proposedName;
  dialog.dialogResult = (Dialog source, const Action result) {
    final switch (request.kind) {
      case PickKind.open:
        if (result is null || result.id != StandardAction.Open) return done(null);
        string[] paths = request.multiple ? dialog.filenames : null;
        if (paths.length == 0 && dialog.filename.length) paths = [dialog.filename];
        return done(paths);
      case PickKind.directory:
        if (result is null || result.id != StandardAction.OpenDirectory) return done(null);
        // dlangui entrega la carpeta con la barra final.
        string chosen = dialog.filename;
        while (chosen.length > 1 && (chosen.endsWith("/") || chosen.endsWith("\\"))) chosen = chosen[0 .. $ - 1];
        return done([chosen.length ? chosen : dialog.path]);
      case PickKind.save:
        if (result is null || result.id != StandardAction.Save) return done(null);
        return done([result.stringParam.length ? result.stringParam : dialog.filename]);
    }
  };
  dialog.show();
}

version (linux) {
  import csecret;

  /// Hay un selector del portal abierto: la ventana sigue activa y un segundo clic abriría otro.
  private bool portalPickerOpen;

  /// Resultado de pedirle un selector al portal.
  private struct PortalOutcome {
    /// No hay portal (ni bus de sesión): se usa el diálogo de dlangui.
    bool unavailable;
    string[] paths;
  }

  /// Respuesta que deja la señal Response.
  private struct PortalAnswer {
    bool received;
    uint response;
    string[] uris;
  }

  /// Pide el selector al portal en un hilo aparte y entrega las rutas en el de la ventana.
  private void portalPickAsync(Window parent, PickRequest request, void delegate(string[] paths) done) {
    import firmador.gui.desktop.uithread : runInBackground, runOnUi;
    if (portalPickerOpen) {
      info("Ya hay un selector de archivos abierto: se ignora el nuevo pedido");
      return done(null);
    }
    string parentWindow = portalParentWindow();
    portalPickerOpen = true;
    runInBackground("Error del selector de archivos del sistema", {
      PortalOutcome outcome = portalPick(request, parentWindow);
      runOnUi(() {
        portalPickerOpen = false;
        if (outcome.unavailable) return dlanguiPick(parent, request, done);
        done(outcome.paths);
      });
    }, () {
      portalPickerOpen = false;
      done(null);
    });
  }

  /**
   * Ventana padre para el portal («x11:<XID en hexadecimal>»): la que tiene el foco del
   * teclado, que es la de Firmador donde se pidió el selector. Vacía si SDL no usa X11 o
   * ninguna ventana tiene el foco; el diálogo se abre igual, sin quedar sobre ella. No se
   * llega a la ventana por dlangui.platforms.sdl.sdlapp: importarla enlaza los envoltorios de
   * FreeType de dlangui, y mupdf los usaría en lugar de libfreetype donde dlangui no la cargó
   * (las pruebas).
   */
  private string portalParentWindow() @trusted {
    import bindbc.sdl : SDL_GetKeyboardFocus, SDL_GetWindowWMInfo, SDL_SysWMinfo, SDL_SYSWM_X11, SDL_VERSION;
    import std.format : format;
    auto focused = SDL_GetKeyboardFocus();
    if (focused is null) return "";
    // SDL escribe la variante de su sistema de ventanas, que puede ser mayor que la unión de
    // bindbc-sdl (la de Wayland ocupa 64 bytes): se le da lugar de sobra.
    align(16) ubyte[512] buffer;
    auto windowInfo = cast(SDL_SysWMinfo*) buffer.ptr;
    SDL_VERSION(&windowInfo.version_);
    if (!SDL_GetWindowWMInfo(focused, windowInfo) || windowInfo.subsystem != SDL_SYSWM_X11) return "";
    return format("x11:%x", windowInfo.info.x11.window);
  }

  /// Guarda la respuesta del portal (callback de g_dbus_connection_signal_subscribe).
  extern (C) private void onPortalResponse(GDBusConnection* connection, const(char)* sender, const(char)* objectPath,
      const(char)* interfaceName, const(char)* signalName, GVariant* parameters, void* userData) {
    auto answer = cast(PortalAnswer*) userData;
    uint response;
    GVariant* results;
    g_variant_get(parameters, "(u@a{sv})", &response, &results);
    answer.response = response;
    GVariant* uris = g_variant_lookup_value(results, "uris", null);
    if (uris !is null) {
      size_t count;
      auto list = g_variant_get_strv(uris, &count);
      foreach (index; 0 .. count) {
        size_t length;
        while (list[index][length] != '\0') length++;
        answer.uris ~= list[index][0 .. length].idup;
      }
      g_free(cast(void*) list);
      g_variant_unref(uris);
    }
    g_variant_unref(results);
    answer.received = true;
  }

  /// Opciones como `a{sv}` de gio (con referencia flotante, la toma la llamada).
  private GVariant* portalVariant(const PortalOption[] options) @trusted {
    import std.string : toStringz;
    GVariantType* dictionary = g_variant_type_new("a{sv}");
    scope (exit) g_variant_type_free(dictionary);
    GVariantBuilder* builder = g_variant_builder_new(dictionary);
    scope (exit) g_variant_builder_unref(builder);
    foreach (option; options) {
      GVariant* value = option.value.match!(
        (bool flag) => g_variant_new_boolean(flag ? 1 : 0),
        (string text) => g_variant_new_string(text.toStringz),
        (PortalBytes bytes) => g_variant_new_bytestring(bytes.value.toStringz));
      g_variant_builder_add(builder, "{sv}", option.name.toStringz, value);
    }
    return g_variant_builder_end(builder);
  }

  /**
   * Muestra el selector del portal y espera la respuesta, en el hilo que lo llama (no el de
   * la ventana). Se suscribe a la respuesta antes de pedir el selector, en la ruta que
   * fija el token, para no perderla.
   *
   * Throws: Exception si el portal responde con error o con rutas que no se pueden leer.
   */
  private PortalOutcome portalPick(PickRequest request, string parentWindow) @trusted {
    import std.array : replace;
    import std.exception : enforce;
    import std.format : format;
    import std.string : fromStringz, toStringz;
    import std.uuid : randomUUID;
    enum string desktopName = "org.freedesktop.portal.Desktop";
    GError* failure;
    GDBusConnection* bus = g_bus_get_sync(G_BUS_TYPE_SESSION, null, &failure);
    if (bus is null) return portalUnavailable("no hay bus de sesión", failure);
    scope (exit) g_object_unref(bus);
    GMainContext* context = g_main_context_new();
    g_main_context_push_thread_default(context);
    scope (exit) {
      g_main_context_pop_thread_default(context);
      g_main_context_unref(context);
    }
    PortalAnswer answer;
    uint subscribe(string path) {
      return g_dbus_connection_signal_subscribe(bus, desktopName, "org.freedesktop.portal.Request", "Response",
        path.toStringz, null, G_DBUS_SIGNAL_FLAGS_NONE,
        &onPortalResponse, &answer, null);
    }
    string token = "firmador_" ~ randomUUID().toString().replace("-", "_");
    string expectedPath = portalRequestPath(g_dbus_connection_get_unique_name(bus).fromStringz.idup, token);
    uint subscription = subscribe(expectedPath);
    scope (exit) g_dbus_connection_signal_unsubscribe(bus, subscription);
    GVariant* reply = g_dbus_connection_call_sync(bus, desktopName, "/org/freedesktop/portal/desktop",
      "org.freedesktop.portal.FileChooser", portalMethod(request.kind).toStringz,
      g_variant_new("(ss@a{sv})", parentWindow.toStringz, request.title.toStringz,
        portalVariant(portalOptions(request, token))),
      null, G_DBUS_CALL_FLAGS_NONE, -1, null, &failure);
    if (reply is null) return portalUnavailable("el portal no abrió el selector", failure);
    const(char)* handle;
    g_variant_get(reply, "(&o)", &handle);
    string actualPath = handle.fromStringz.idup;
    g_variant_unref(reply);
    if (actualPath != expectedPath) {
      // Portales anteriores a la versión 0.9 no usan el token para la ruta.
      warning("El portal respondió en ", actualPath, " en lugar de ", expectedPath);
      g_dbus_connection_signal_unsubscribe(bus, subscription);
      subscription = subscribe(actualPath);
    }
    while (!answer.received) g_main_context_iteration(context, 1);
    // 0 es éxito, 1 cancelado por el usuario y 2 otro error.
    if (answer.response == 1) return PortalOutcome(false, null);
    enforce(answer.response == 0, format("El selector de archivos del sistema terminó con error (código %d)",
      answer.response));
    string[] paths;
    foreach (uri; answer.uris) {
      GError* conversion;
      char* path = g_filename_from_uri(uri.toStringz, null, &conversion);
      if (path is null) {
        string reason = conversion is null ? "" : conversion.message.fromStringz.idup;
        if (conversion !is null) g_error_free(conversion);
        throw new Exception(format("El selector de archivos devolvió una dirección que no es un archivo local (%s): %s",
          uri, reason));
      }
      paths ~= path.fromStringz.idup;
      g_free(path);
    }
    info("Selector del sistema: ", paths.length, " ruta(s) elegida(s)");
    return PortalOutcome(false, paths);
  }

  /// Registra por qué no se usó el portal y libera el error de gio.
  private PortalOutcome portalUnavailable(string why, GError* failure) @trusted {
    import std.string : fromStringz;
    warning("Selector de archivos del sistema no disponible (", why, "): se usa el de dlangui. ",
      failure is null ? "" : failure.message.fromStringz);
    if (failure !is null) g_error_free(failure);
    return PortalOutcome(true, null);
  }
}

version (Windows) {
  import core.sys.windows.objbase : CoCreateInstance, CoInitializeEx, COINIT, CoTaskMemFree, CoUninitialize;
  import core.sys.windows.unknwn : IUnknown;
  import core.sys.windows.windef : BOOL, DWORD, HRESULT, HWND, UINT;
  import core.sys.windows.basetyps : GUID;
  import core.sys.windows.wtypes : CLSCTX;
  import core.sys.windows.winerror : RPC_E_CHANGED_MODE;

  // Interfaces de shobjidl.h que druntime no declara, en el orden de su tabla de métodos.
  // Los métodos que no se usan van con argumentos genéricos: sólo cuenta su lugar.

  private interface IShellItem : IUnknown {
  extern (Windows):
    HRESULT BindToHandler(void* bindContext, const(GUID)* handler, const(GUID)* riid, void** result);
    HRESULT GetParent(IShellItem* parent);
    HRESULT GetDisplayName(uint form, wchar** name);
    HRESULT GetAttributes(uint mask, uint* attributes);
    HRESULT Compare(IShellItem item, uint hint, int* order);
  }

  private interface IShellItemArray : IUnknown {
  extern (Windows):
    HRESULT BindToHandler(void* bindContext, const(GUID)* handler, const(GUID)* riid, void** result);
    HRESULT GetPropertyStore(int flags, const(GUID)* riid, void** result);
    HRESULT GetPropertyDescriptionList(void* keyType, const(GUID)* riid, void** result);
    HRESULT GetAttributes(int flags, uint mask, uint* attributes);
    HRESULT GetCount(DWORD* count);
    HRESULT GetItemAt(DWORD index, IShellItem* item);
    HRESULT EnumItems(void** items);
  }

  private interface IModalWindow : IUnknown {
  extern (Windows):
    HRESULT Show(HWND owner);
  }

  private interface IFileDialog : IModalWindow {
  extern (Windows):
    HRESULT SetFileTypes(UINT count, const(void)* filters);
    HRESULT SetFileTypeIndex(UINT index);
    HRESULT GetFileTypeIndex(UINT* index);
    HRESULT Advise(void* events, DWORD* cookie);
    HRESULT Unadvise(DWORD cookie);
    HRESULT SetOptions(DWORD options);
    HRESULT GetOptions(DWORD* options);
    HRESULT SetDefaultFolder(IShellItem folder);
    HRESULT SetFolder(IShellItem folder);
    HRESULT GetFolder(IShellItem* folder);
    HRESULT GetCurrentSelection(IShellItem* item);
    HRESULT SetFileName(const(wchar)* name);
    HRESULT GetFileName(wchar** name);
    HRESULT SetTitle(const(wchar)* title);
    HRESULT SetOkButtonLabel(const(wchar)* text);
    HRESULT SetFileNameLabel(const(wchar)* label);
    HRESULT GetResult(IShellItem* item);
    HRESULT AddPlace(IShellItem item, int place);
    HRESULT SetDefaultExtension(const(wchar)* extension);
    HRESULT Close(HRESULT result);
    HRESULT SetClientGuid(const(GUID)* guid);
    HRESULT ClearClientData();
    HRESULT SetFilter(void* filter);
  }

  private interface IFileOpenDialog : IFileDialog {
  extern (Windows):
    HRESULT GetResults(IShellItemArray* items);
    HRESULT GetSelectedItems(IShellItemArray* items);
  }

  extern (Windows) private HRESULT SHCreateItemFromParsingName(const(wchar)* path, void* bindContext,
    const(GUID)* riid, void** item);

  private immutable GUID clsidFileOpenDialog = GUID(0xDC1C5A9C, 0xE88A, 0x4DDE,
    [0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7]);
  private immutable GUID clsidFileSaveDialog = GUID(0xC0B4E2F3, 0xBA21, 0x4773,
    [0x8D, 0xBA, 0x33, 0x5E, 0xC9, 0x46, 0xEB, 0x8B]);
  private immutable GUID iidFileOpenDialog = GUID(0xD57C7288, 0xD4AD, 0x4768,
    [0xBE, 0x02, 0x9D, 0x96, 0x95, 0x32, 0xD9, 0x60]);
  private immutable GUID iidFileSaveDialog = GUID(0x84BCCD23, 0x5FDE, 0x4CDB,
    [0xAE, 0xA4, 0xAF, 0x64, 0xB8, 0x3D, 0x78, 0xAB]);
  private immutable GUID iidShellItem = GUID(0x43826D1E, 0xE718, 0x42EE,
    [0xBC, 0x55, 0xA1, 0xE2, 0x61, 0xC3, 0x7B, 0xFE]);

  private enum : DWORD {
    fosOverwritePrompt = 0x2,
    fosPickFolders = 0x20,
    fosForceFileSystem = 0x40,
    fosAllowMultiSelect = 0x200,
    fosPathMustExist = 0x800,
    fosFileMustExist = 0x1000,
  }
  /// SIGDN_FILESYSPATH: la ruta del sistema de archivos.
  private enum uint sigdnFileSystemPath = 0x80058000;
  /// HRESULT_FROM_WIN32(ERROR_CANCELLED): el usuario cerró el diálogo.
  private enum HRESULT cancelledByUser = cast(HRESULT) 0x800704C7;

  /// Lanza si `result` es un error de COM, con lo que se intentaba.
  private void check(HRESULT result, string action) {
    import std.format : format;
    if (result < 0) throw new Exception(format("No se pudo %s en el selector de archivos (0x%08X)", action, result));
  }

  /// Ruta de un elemento del selector; lo libera.
  private string shellItemPath(IShellItem item) {
    import core.stdc.wchar_ : wcslen;
    import std.utf : toUTF8;
    scope (exit) item.Release();
    wchar* name;
    check(item.GetDisplayName(sigdnFileSystemPath, &name), "leer la ruta elegida");
    scope (exit) CoTaskMemFree(name);
    return name[0 .. wcslen(name)].toUTF8;
  }

  /**
   * IFileOpenDialog o IFileSaveDialog, modal sobre la ventana activa del hilo, que es la de
   * Firmador donde se pidió el selector (sin ella, el diálogo se abre sin dueña). Show tiene
   * su propio ciclo de mensajes, así que corre en el hilo de la ventana. No se llega a la
   * ventana por dlangui.platforms.windows.winapp: importarla enlaza su arranque, que llama
   * a UIAppMain de firmador.app, y las pruebas se compilan sin ese módulo.
   */
  private string[] windowsPick(PickRequest request) @trusted {
    import core.sys.windows.winuser : GetActiveWindow;
    import std.exception : enforce;
    import std.format : format;
    import std.utf : toUTF16z;
    HRESULT started = CoInitializeEx(null, COINIT.COINIT_APARTMENTTHREADED);
    enforce(started >= 0 || started == RPC_E_CHANGED_MODE,
      format("No se pudo iniciar COM para el selector de archivos (0x%08X)", started));
    scope (exit) if (started >= 0) CoUninitialize();
    bool saving = request.kind == PickKind.save;
    void* created;
    check(CoCreateInstance(saving ? &clsidFileSaveDialog : &clsidFileOpenDialog, null, CLSCTX.CLSCTX_INPROC_SERVER,
      saving ? &iidFileSaveDialog : &iidFileOpenDialog, &created), "crear el diálogo");
    IFileDialog dialog = cast(IFileDialog) created;
    scope (exit) dialog.Release();
    DWORD options;
    check(dialog.GetOptions(&options), "leer las opciones");
    final switch (request.kind) {
      case PickKind.open:
        options |= fosFileMustExist | (request.multiple ? fosAllowMultiSelect : 0);
        break;
      case PickKind.directory:
        options |= fosPickFolders | fosPathMustExist;
        break;
      case PickKind.save:
        options |= fosOverwritePrompt | fosPathMustExist;
        break;
    }
    check(dialog.SetOptions(options | fosForceFileSystem), "fijar las opciones");
    check(dialog.SetTitle(request.title.toUTF16z), "poner el título");
    if (request.startDirectory.length) {
      void* folder;
      // Una carpeta que el Shell no reconoce sólo hace que el diálogo empiece en la suya.
      if (SHCreateItemFromParsingName(request.startDirectory.toUTF16z, null, &iidShellItem, &folder) >= 0) {
        IShellItem start = cast(IShellItem) folder;
        scope (exit) start.Release();
        check(dialog.SetFolder(start), "elegir la carpeta inicial");
      }
    }
    if (saving && request.proposedName.length) check(dialog.SetFileName(request.proposedName.toUTF16z), "proponer el nombre");
    if (saving && request.defaultExtension.length > 1) {
      check(dialog.SetDefaultExtension(request.defaultExtension[1 .. $].toUTF16z), "fijar la extensión");
    }
    HRESULT shown = dialog.Show(GetActiveWindow());
    if (shown == cancelledByUser) return null;
    check(shown, "mostrar el diálogo");
    if (request.kind == PickKind.open) {
      IShellItemArray items;
      check((cast(IFileOpenDialog) created).GetResults(&items), "leer los archivos elegidos");
      scope (exit) items.Release();
      DWORD count;
      check(items.GetCount(&count), "contar los archivos elegidos");
      string[] paths;
      foreach (index; 0 .. count) {
        IShellItem item;
        check(items.GetItemAt(index, &item), "leer un archivo elegido");
        paths ~= shellItemPath(item);
      }
      return paths;
    }
    IShellItem chosen;
    check(dialog.GetResult(&chosen), "leer lo elegido");
    return [shellItemPath(chosen)];
  }
}

@("should start from the nearest existing parent when the folder no longer exists")
unittest {
  static bool existing(string path) pure nothrow @safe {
    return path == "/home/ana" || path == "/";
  }
  assert(nearestExistingDirectory!existing("/home/ana/borrada/sub") == "/home/ana");
  assert(nearestExistingDirectory!existing("/home/ana") == "/home/ana");
  assert(nearestExistingDirectory!existing("/otra/cosa") == "/");
  assert(nearestExistingDirectory!existing("relativa/sin/padre") is null);
  assert(nearestExistingDirectory!existing("") is null);
}

@("should build the portal request path from the connection name when using a handle token")
unittest {
  assert(portalRequestPath(":1.42", "firmador_x") == "/org/freedesktop/portal/desktop/request/1_42/firmador_x");
}

@("should ask the portal for folders, multiple files or a proposed name when building its options")
unittest {
  static string[] names(PortalOption[] options) pure @safe {
    import std.algorithm : map;
    import std.array : array;
    return options.map!(option => option.name).array;
  }
  auto save = portalOptions(PickRequest(PickKind.save, "Guardar", "/home/ana", false, "a-firmado.pdf", ".pdf"), "t");
  assert(portalMethod(PickKind.save) == "SaveFile");
  assert(names(save) == ["handle_token", "modal", "current_name", "current_folder"]);
  assert(save[3].value.match!((PortalBytes bytes) => bytes.value, (_) => "") == "/home/ana");
  auto folder = portalOptions(PickRequest(PickKind.directory, "Carpeta"), "t");
  assert(portalMethod(PickKind.directory) == "OpenFile");
  assert(names(folder) == ["handle_token", "modal", "directory"]);
  auto files = portalOptions(PickRequest(PickKind.open, "Abrir", null, true), "t");
  assert(files[2].value.match!((bool flag) => flag, (_) => false));
}
