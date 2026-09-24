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
 * Modo -dshell (GUIShell, RequestsShell y ResponsesShell): atiende comandos por la
 * entrada estándar para que otro programa firme, valide o previsualice por lotes
 * (@contract shell-protocol). Cada comando es una línea «comando|json|pin» y cada
 * respuesta, dos líneas en la salida estándar: «SUCCESS» o «ERROR» (SUCCESS sólo si todo
 * el lote fue bien) y el JSON en una línea o el aviso de dónde se guardó. Los
 * diagnósticos van a la salida de error y a la bitácora, nunca a la estándar.
 *
 * Si el dispositivo rechaza el PIN se aborta el resto del lote: cada documento gastaría
 * otro intento y tres seguidos bloquean la tarjeta.
 */
module firmador.gui.shell;

import std.algorithm : canFind, map;
import std.array : array, replace, split;
import std.exception : enforce;
import std.file : exists, isFile, mkdirRecurse, read, readText, write;
import std.format : format;
import std.json : JSONType, JSONValue, toJSON;
import std.logger : error, info, warning;
import std.path : dirName;
import std.stdio : stderr, stdout;
import std.string : join, strip, toLower;

import firmador.cards.cardinfo : CardSignInfo, matchesIdentifier;
import firmador.cards.detector : createPinOnlyCard, SmartCardDetector;
import firmador.configuration : shellMaxLineLength;
import firmador.documents.document : Document;
import firmador.documents.mimetype : detectMimeType;
import firmador.gui.console;
import firmador.gui.errors : isAuthenticationFailure;
import firmador.i18n : htmlToText, t;
import firmador.previewers.previewer : previewerFor;
import firmador.remote.dto : remoteDocumentJson;
import firmador.settings : Settings;
import firmador.settingsjson : settingsFromJson;
import firmador.settingsmanager : currentSettings;
import firmador.signers.common : rootCause;
import firmador.tokens.token : SecretPin;
import firmador.util.base64 : encodeBase64;
import firmador.util.json;
import firmador.util.png : encodePng;

/// Texto para los documentos que no se intentaron tras un fallo de autenticación.
enum string notAttempted = "No intentado: el lote se abortó tras un fallo de autenticación con el dispositivo, "
  ~ "para no gastar más intentos y arriesgar el bloqueo.";

/// Estado de cada elemento de una respuesta.
enum string statusSuccess = "SUCCESS";
enum string statusError = "ERROR";

/// Documento de un lote de firma (SignCommand).
struct SignItem {
  string externalId;
  string filePath;
  /// Ajustes propios (null: los vigentes).
  Settings settings;
}

/// Documento de un lote de firma remota (SignRemoteCommand): el documento viaja en base64.
struct SignRemoteItem {
  string externalId;
  immutable(ubyte)[] document;
  string documentName;
  Settings settings;
}

/// Documento de un lote de validación (ValidateCommand).
struct ValidateItem {
  string externalId;
  string filePath;
}

/// Un lote: los elementos, el dispositivo pedido y dónde guardar la respuesta.
struct ShellBatch(Item) {
  Item[] commands;
  string serialNumber;
  string fileOutput;
}

/// Petición de vista previa (PreviewCommand): una ruta o el documento en base64.
struct PreviewRequest {
  string filePath;
  immutable(ubyte)[] document;
  string fileOutput;
}

/// Rechaza los campos que el comando no conoce (como Jackson con FAIL_ON_UNKNOWN_PROPERTIES).
private void requireKnownFields(const JSONValue json, const string[] known, string what) @safe {
  foreach (key; objectKeys(json, what)) {
    enforce!JsonShapeException(known.canFind(key), format("%s: campo desconocido «%s»", what, key));
  }
}

private Settings optionalSettings(const JSONValue json, string what) @safe {
  auto found = member(json, "settings");
  if (found is null || found.type == JSONType.null_) return null;
  return settingsFromJson(*found, currentSettings());
}

private Item[] parseItems(Item)(const JSONValue json, string what, Item delegate(const JSONValue item) @safe parse)
    @safe {
  auto commands = member(json, "commands");
  enforce!JsonShapeException(commands !is null && commands.type == JSONType.array,
    what ~ ": falta la lista «commands»");
  Item[] items;
  foreach (item; arrayItems(*commands, what ~ ": «commands»")) {
    enforce!JsonShapeException(isObject(item), what ~ ": cada comando debe ser un objeto JSON");
    items ~= parse(item);
  }
  enforce!JsonShapeException(items.length > 0, what ~ ": la lista «commands» está vacía");
  return items;
}

/**
 * Lote de sign (ListSignCommand).
 *
 * Throws: JsonShapeException con el campo que falla.
 */
ShellBatch!SignItem parseSignBatch(const JSONValue json) @safe {
  enum what = "El comando sign";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  requireKnownFields(json, ["commands", "serialnumber", "fileOutput"], what);
  ShellBatch!SignItem batch;
  batch.serialNumber = optionalString(json, "serialnumber", what);
  batch.fileOutput = optionalString(json, "fileOutput", what);
  batch.commands = parseItems!SignItem(json, what, (const JSONValue item) @safe {
    requireKnownFields(item, ["externalId", "settings", "filePath"], what);
    return SignItem(optionalString(item, "externalId", what), requiredString(item, "filePath", what),
      optionalSettings(item, what));
  });
  return batch;
}

/**
 * Lote de signremote (ListSignRemoteCommand).
 *
 * Throws: JsonShapeException con el campo que falla.
 */
ShellBatch!SignRemoteItem parseSignRemoteBatch(const JSONValue json) @safe {
  enum what = "El comando signremote";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  requireKnownFields(json, ["commands", "serialnumber", "fileOutput"], what);
  ShellBatch!SignRemoteItem batch;
  batch.serialNumber = optionalString(json, "serialnumber", what);
  batch.fileOutput = optionalString(json, "fileOutput", what);
  batch.commands = parseItems!SignRemoteItem(json, what, (const JSONValue item) @safe {
    requireKnownFields(item, ["base64Document", "documentName", "settings", "externalId"], what);
    return SignRemoteItem(optionalString(item, "externalId", what), requiredBase64(item, "base64Document", what).idup,
      requiredString(item, "documentName", what), optionalSettings(item, what));
  });
  return batch;
}

/**
 * Lote de validate (ListValidateCommand).
 *
 * Throws: JsonShapeException con el campo que falla.
 */
ShellBatch!ValidateItem parseValidateBatch(const JSONValue json) @safe {
  enum what = "El comando validate";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  requireKnownFields(json, ["commands", "fileOutput"], what);
  ShellBatch!ValidateItem batch;
  batch.fileOutput = optionalString(json, "fileOutput", what);
  batch.commands = parseItems!ValidateItem(json, what, (const JSONValue item) @safe {
    requireKnownFields(item, ["externalId", "filePath"], what);
    return ValidateItem(optionalString(item, "externalId", what), requiredString(item, "filePath", what));
  });
  return batch;
}

/**
 * Petición de preview (PreviewCommand).
 *
 * Throws: JsonShapeException si falta la ruta y el documento, o un campo no es válido.
 */
PreviewRequest parsePreviewRequest(const JSONValue json) @safe {
  enum what = "El comando preview";
  enforce!JsonShapeException(isObject(json), what ~ " debe ser un objeto JSON");
  requireKnownFields(json, ["filePath", "fileOutput", "base64Document"], what);
  PreviewRequest request;
  request.filePath = optionalString(json, "filePath", what);
  request.fileOutput = optionalString(json, "fileOutput", what);
  string encoded = optionalString(json, "base64Document", what);
  if (encoded.length) request.document = decodeBase64Field(encoded, what ~ ": «base64Document»").idup;
  enforce!JsonShapeException(request.document.length || request.filePath.length,
    "La ruta del archivo no puede estar vacía.");
  return request;
}

/// Resultado de un elemento: los campos propios más «externalId», «status» y «errorMessage».
JSONValue itemResult(string externalId, JSONValue fields, string errorMessage) @safe {
  JSONValue result = fields.type == JSONType.object ? fields : JSONValue(string[string].init);
  result["externalId"] = externalId is null ? JSONValue(null) : JSONValue(externalId);
  result["status"] = errorMessage is null ? statusSuccess : statusError;
  result["errorMessage"] = errorMessage is null ? JSONValue(null) : JSONValue(errorMessage);
  return result;
}

/// El texto en una sola línea: un salto de línea desincronizaría al cliente del protocolo.
string singleLine(string text) pure @safe {
  return text.replace("\r", " ").replace("\n", " ");
}

/// Las dos líneas de un error del protocolo.
string[2] errorLines(string message) pure @safe {
  return [statusError, "ERROR: " ~ singleLine(message)];
}

/// Interfaz del modo: todo lo que no es protocolo va a la salida de error.
final class ShellInterface : ConsoleInterface {
  private SmartCardDetector detector;
  /// Lo encienden showError y showMessage: aborta el lote para no bloquear la tarjeta.
  private bool authenticationFailed;

  this(SmartCardDetector detector) @safe {
    this.detector = detector;
  }

  void showError(Throwable failure) @trusted {
    auto cause = rootCause(failure);
    // Un PIN o una contraseña rechazados detienen el lote antes de bloquear la tarjeta.
    if (isAuthenticationFailure(failure)) authenticationFailed = true;
    error("Error en modo -dshell: ", cause.msg);
    stderr.writeln("ERROR: ", typeid(cause).name, ": ", cause.msg);
  }

  /// Los avisos no pueden ir a la salida estándar, que es la de las respuestas.
  void showMessage(string message) @trusted {
    info(message);
    stderr.writeln(message);
  }

  void showErrorAlert(string title, string message) @trusted {
    error(title, ": ", message);
    stderr.writeln("ERROR: ", title, " - ", message);
  }

  /// El PIN llega con cada comando: no hay a quién pedirlo.
  CardSignInfo getPin() @safe {
    return null;
  }

  /// Atiende comandos hasta «exit», «quit» o el final de la entrada.
  void run() @trusted {
    stdout.writeln("Firmador Shell - Escuchando comandos");
    stdout.writeln("Comandos disponibles: sign, signremote, validate, getcertificates, preview, help, exit|quit");
    stdout.writeln("Escriba 'help' para ver la sintaxis completa.");
    // La línea trae el PIN: se lee en un arreglo propio que se borra tras cada comando.
    auto buffer = new char[shellMaxLineLength];
    scope (exit) buffer[] = '\0';
    while (true) {
      stdout.write("> ");
      stdout.flush();
      size_t length;
      bool received;
      try {
        received = readStandardInputLine(buffer, length);
      } catch (Exception tooLong) {
        reportFailure(tooLong);
        stdout.flush();
        continue;
      }
      if (!received) break;
      // Sólo se quitó el salto de línea: el PIN es el último campo y sus espacios cuentan.
      char[] line = buffer[0 .. length];
      scope (exit) line[] = '\0';
      if (line.strip.length == 0) continue;
      auto parts = splitCommand(line);
      string command = parts[0].strip.toLower.idup;
      try {
        if (command == "exit" || command == "quit") {
          stdout.writeln("Saliendo...");
          break;
        }
        dispatch(command, parts);
      } catch (Exception exception) {
        // Informar y seguir: una excepción no debe cerrar la sesión.
        reportFailure(exception);
      } finally {
        stdout.flush();
      }
    }
  }

  /// Atiende un comando; `parts` apunta a la línea leída, que run borra al terminar.
  private void dispatch(string command, const(char[])[] parts) @trusted {
    switch (command) {
      case "sign":
        if (parts.length < 3) return printError("Uso incorrecto. Formato: sign|<json_file>|<pin>");
        executeSign(parseSignBatch(readCommandJson(parts[1].idup)), parts[2]);
        break;
      case "signremote":
        if (parts.length < 3) return printError("Uso incorrecto. Formato: signremote|<json_file>|<pin>");
        executeSignRemote(parseSignRemoteBatch(readCommandJson(parts[1].idup)), parts[2]);
        break;
      case "validate":
        if (parts.length < 2) return printError("Uso incorrecto. Formato: validate|<json_file>");
        executeValidate(parseValidateBatch(readCommandJson(parts[1].idup)));
        break;
      case "getcertificates":
        JSONValue[] cards;
        foreach (card; detector.readSaveListSmartCard()) cards ~= card.toJson();
        emit(JSONValue(cards), parts.length >= 2 ? parts[1].strip.idup : null, "Certificados guardados en: ", true);
        break;
      case "preview":
        if (parts.length < 2) return printError("Uso incorrecto. Formato: preview|<json_file>");
        executePreview(parsePreviewRequest(readCommandJson(parts[1].idup)));
        break;
      case "help":
        showHelp();
        break;
      default:
        printError("Comando no reconocido. Escriba 'help' para ver comandos disponibles.");
        break;
    }
  }

  private void printError(string message) @trusted {
    foreach (line; errorLines(message)) stdout.writeln(line);
  }

  private void reportFailure(Throwable failure) @trusted {
    auto cause = rootCause(failure);
    showError(cause);
    printError(cause.msg.idup);
  }

  /// Escribe la respuesta en fileOutput o la emite en una línea tras la de estado.
  private void emit(JSONValue response, string fileOutput, string outputMessage, bool allOk) @trusted {
    string secondLine;
    if (fileOutput.length) {
      string parent = dirName(fileOutput);
      if (parent.length && !exists(parent)) mkdirRecurse(parent);
      write(fileOutput, toJSON(response, true));
      info("Respuesta guardada en ", fileOutput);
      // La ruta viene del JSON y puede traer saltos de línea.
      secondLine = outputMessage ~ singleLine(fileOutput);
    } else {
      secondLine = toJSON(response);
    }
    stdout.writeln(allOk ? statusSuccess : statusError);
    stdout.writeln(secondLine);
  }

  /**
   * Credencial con el identificador pedido, o la única disponible; con varias candidatas
   * se pide precisar, porque firmar con otra gastaría un intento de la tarjeta. Sin
   * identificador ni dispositivos visibles se usa la primera ranura PKCS#11.
   */
  private CardSignInfo requireCard(string serialNumber, const(char)[] pin) @trusted {
    CardSignInfo[] cards;
    try {
      cards = detector.readSaveListSmartCard();
    } catch (Exception exception) {
      showError(exception);
    }
    auto choice = chooseCard(cards, serialNumber, false);
    CardSignInfo card;
    final switch (choice.kind) {
      case CardChoice.Kind.found:
        card = cards[choice.matches[0]];
        break;
      case CardChoice.Kind.pinOnly:
        warning("No se detectaron dispositivos; se firmará con el primer slot PKCS#11 disponible");
        card = createPinOnlyCard(null);
        break;
      case CardChoice.Kind.notFound:
        printError("No se encontró un dispositivo de firma con el identificador: " ~ serialNumber);
        return null;
      case CardChoice.Kind.ambiguous:
        string candidates = choice.matches.map!(index => "\n  - " ~ cards[index].displayInfo).join;
        printError((serialNumber.strip.length == 0
          ? "Hay varios dispositivos de firma disponibles: indique 'serialnumber' en el JSON."
          : "El identificador '" ~ serialNumber ~ "' coincide con más de un dispositivo; use el número de serie del "
            ~ "certificado o la ruta completa del .p12.") ~ candidates);
        return null;
    }
    card.pin = new SecretPin(pin);
    return card;
  }

  /**
   * Hace `process` con cada elemento y arma su resultado (itemResult); un error se
   * informa y queda en su resultado. Si `abortRest` se enciende, los que faltan quedan
   * sin intentar.
   *
   * Returns: los resultados; `allOk` dice si todos salieron bien.
   */
  private JSONValue[] collectResults(Item)(Item[] items, scope JSONValue delegate(Item item) @safe process,
      scope bool delegate() @safe abortRest, out bool allOk) @trusted {
    allOk = true;
    JSONValue[] results;
    foreach (index, item; items) {
      try {
        results ~= itemResult(item.externalId, process(item), null);
      } catch (Exception exception) {
        allOk = false;
        auto cause = rootCause(exception);
        showError(cause);
        results ~= itemResult(item.externalId, JSONValue(null), cause.msg.idup);
      }
      if (abortRest()) {
        allOk = false;
        foreach (skipped; items[index + 1 .. $]) results ~= itemResult(skipped.externalId, JSONValue(null), notAttempted);
        break;
      }
    }
    return results;
  }

  /// Firma cada elemento con la misma credencial; aborta el resto si el PIN falla.
  private void executeBatch(Item)(ShellBatch!Item batch, const(char)[] pin, string outputMessage, string listName,
      JSONValue delegate(Item item, CardSignInfo card) @safe signOne) @trusted {
    authenticationFailed = false;
    auto card = requireCard(batch.serialNumber, pin);
    if (card is null) return;
    // La credencial se comparte entre documentos: el PIN se destruye al terminar el lote.
    scope (exit) card.destroyPin();
    bool allOk;
    JSONValue response;
    response[listName] = collectResults(batch.commands, (Item item) => signOne(item, card), () => authenticationFailed,
      allOk);
    emit(response, batch.fileOutput, outputMessage, allOk);
  }

  private void executeSign(ShellBatch!SignItem batch, const(char)[] pin) @trusted {
    executeBatch!SignItem(batch, pin, "Documento firmado guardado en: ", "listResponseSignDocuments",
      (SignItem item, CardSignInfo card) @trusted {
        enforce(exists(item.filePath) && isFile(item.filePath), "El archivo no existe - " ~ item.filePath);
        auto document = signWith(new Document(this, item.filePath), item.settings, card);
        JSONValue fields;
        fields["base64SignedDocument"] = encodeBase64(document.signedContent);
        return fields;
      });
  }

  /**
   * Firma documentos que llegan en base64 y devuelve cada uno como RemoteDocument
   * (bytes y nombre con que se guardaría firmado).
   */
  private void executeSignRemote(ShellBatch!SignRemoteItem batch, const(char)[] pin) @trusted {
    executeBatch!SignRemoteItem(batch, pin, "Firma remota guardada en: ", "listResponseRemoteDocuments",
      (SignRemoteItem item, CardSignInfo card) @trusted {
        auto document = signWith(new Document(this, item.document, item.documentName), item.settings, card);
        JSONValue fields;
        fields["remoteDocument"] = remoteDocumentJson(document.signedContent, document.pathToSaveName);
        return fields;
      });
  }

  private void executeValidate(ShellBatch!ValidateItem batch) @trusted {
    bool allOk;
    JSONValue response;
    response["listValidateDocumentResponses"] = collectResults(batch.commands, (ValidateItem item) @trusted {
      enforce(exists(item.filePath) && isFile(item.filePath), "El archivo no existe - " ~ item.filePath);
      auto document = new Document(this, item.filePath);
      document.validate();
      JSONValue fields;
      fields["report"] = htmlToText(document.report);
      return fields;
    }, () => false, allOk);
    emit(response, batch.fileOutput, "Reporte guardado en: ", allOk);
  }

  /// Páginas del documento en PNG a escala 1 (72 ppp), como renderImage(i, 1).
  private void executePreview(PreviewRequest request) @trusted {
    immutable(ubyte)[] content;
    string name;
    if (request.document.length) {
      content = request.document;
      name = "document.pdf";
    } else {
      if (!exists(request.filePath)) return printError("El archivo no existe - " ~ request.filePath);
      content = cast(immutable(ubyte)[]) read(request.filePath);
      name = request.filePath;
    }
    auto settings = new Settings(currentSettings());
    settings.pDFImgScaleFactor = 1;
    auto previewer = previewerFor(detectMimeType(name), settings);
    scope (exit) previewer.close();
    try {
      previewer.load(content, name);
    } catch (Exception exception) {
      error("No se pudo cargar la vista previa: ", exception.msg);
    }
    int pages = previewer.pageCount();
    if (pages <= 0) {
      return printError("No se pudo generar la previsualización de "
        ~ (request.document.length ? "el documento recibido" : request.filePath));
    }
    string[] images;
    foreach (page; 0 .. pages) images ~= encodeBase64(encodePng(previewer.renderPage(page)));
    JSONValue response;
    response["previewImages"] = images;
    emit(response, request.fileOutput, "Previsualización guardada en: ", true);
  }

  private void showHelp() @trusted {
    foreach (line; helpText) stdout.writeln(line);
  }
}

/// «comando|json|pin»: a lo sumo tres partes, el PIN puede contener «|».
inout(char)[][] splitCommand(inout(char)[] line) pure @safe {
  import std.string : indexOf;
  inout(char)[][] parts;
  inout(char)[] rest = line;
  while (parts.length < 2) {
    auto separator = rest.indexOf('|');
    if (separator < 0) break;
    parts ~= rest[0 .. separator];
    rest = rest[separator + 1 .. $];
  }
  return parts ~ rest;
}

/**
 * JSON del comando leído del archivo indicado.
 *
 * Throws: JsonShapeException si falta la ruta, no se puede leer o no es JSON.
 */
private JSONValue readCommandJson(string path) @trusted {
  string trimmed = path.strip;
  enforce!JsonShapeException(trimmed.length > 0, "No se indicó la ruta del JSON del comando");
  string text;
  try {
    text = readText(trimmed);
  } catch (Exception exception) {
    throw new JsonShapeException(format("JSON inválido o ilegible: %s (%s)", trimmed, exception.msg));
  }
  return parseJsonText(text, "El JSON " ~ trimmed);
}

private immutable string[] helpText = [
  "Comandos disponibles:",
  "  sign|<json_file>|<pin>            - Firmar documento(s) desde JSON",
  "  signremote|<json_file>|<pin>      - Firmar documento(s) remotamente",
  "  validate|<json_file>              - Validar documento(s)",
  "  preview|<json_file>               - Previsualizar un documento (PNG en base64)",
  "  getcertificates[|<output_file>]   - Listar dispositivos y almacenes disponibles",
  "  help                              - Mostrar esta ayuda",
  "  exit | quit                       - Salir del programa (también al cerrar la entrada)",
  "",
  "Ejemplos:",
  "  sign|config.json|1234",
  "  signremote|remote_config.json|1234",
  "  validate|validate_config.json",
  "  preview|preview_config.json",
  "  getcertificates|certificates.json",
  "",
  "El JSON de sign y signremote admite 'serialnumber' (opcional) para elegir el",
  "dispositivo: el serial del certificado, o el nombre del fichero .p12",
  "configurado. Sin él sólo funciona si hay un único dispositivo disponible.",
  "",
  "Salida: dos líneas por comando, precedidas del indicador '> '.",
  "  > SUCCESS | > ERROR  (SUCCESS sólo si TODOS los elementos del lote fueron bien)",
  "  <mensaje con la ruta de fileOutput, o el JSON completo en una sola línea>",
  "Cada elemento del JSON lleva su propio 'status' y 'errorMessage'.",
  "Si el PIN resulta incorrecto se aborta el lote entero: cada documento",
  "adicional gastaría otro intento y tres seguidos bloquean la tarjeta.",
  "Los diagnósticos y las trazas van por la salida de error, no por aquí.",
];

/**
 * Ejecuta el modo hasta que termine la entrada; devuelve el código de salida (0).
 *
 * Params:
 *   detector = tarjetas (no se monitorean en este modo).
 */
int runShellMode(SmartCardDetector detector) @trusted {
  auto shell = new ShellInterface(detector);
  shell.run();
  return 0;
}

@("should keep pipes inside the PIN and require the command JSON shapes when parsing shell input")
unittest {
  import std.exception : assertThrown;
  assert(splitCommand("sign|/tmp/a.json|12|34 ") == ["sign", "/tmp/a.json", "12|34 "]);
  assert(splitCommand("help") == ["help"]);
  auto batch = parseSignBatch(parseJsonText(`{"commands":[{"externalId":"1","filePath":"/tmp/a.pdf"}],`
    ~ `"serialnumber":"123","fileOutput":null}`, "x"));
  assert(batch.commands.length == 1 && batch.commands[0].settings is null && batch.serialNumber == "123");
  assertThrown!JsonShapeException(parseSignBatch(parseJsonText(`{"commands":[]}`, "x")));
  assertThrown!JsonShapeException(parseSignBatch(parseJsonText(`{"commands":[{"filePath":"a","pin":"1"}]}`, "x")));
  auto remote = parseSignRemoteBatch(parseJsonText(`{"commands":[{"base64Document":"AAE=","documentName":"a.pdf"}]}`,
    "x"));
  assert(remote.commands[0].document == [0, 1]);
  assertThrown!JsonShapeException(parsePreviewRequest(parseJsonText(`{"fileOutput":"x"}`, "x")));
}

@("should report each item status and keep error lines on one line when building responses")
unittest {
  JSONValue fields;
  fields["report"] = "ok";
  auto success = itemResult("7", fields, null);
  assert(success["status"].str == "SUCCESS" && success["errorMessage"].isNull && success["report"].str == "ok");
  auto failure = itemResult(null, JSONValue(null), "falló");
  assert(failure["status"].str == "ERROR" && failure["externalId"].isNull);
  assert(errorLines("a\nb") == ["ERROR", "ERROR: a b"]);
}
