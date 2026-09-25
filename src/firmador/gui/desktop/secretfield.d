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
 * Campo para PIN y contraseñas (JPasswordField en la versión Java) que guarda lo escrito
 * en un búfer propio que se borra, en vez de las cadenas inmutables de EditLine, que
 * quedan en memoria sin poder borrarse. Lo usan firmador.gui.desktop.dialogs y
 * firmador.gui.desktop.configpanel.
 */
module firmador.gui.desktop.secretfield;

import std.array : replicate;
import std.utf : encode, isValidDchar;

import dlangui.core.events;
import dlangui.core.types;
import dlangui.graphics.drawbuf : ClipRectSaver, DrawBuf;
import dlangui.graphics.fonts : FontRef;
import dlangui.widgets.styles : STYLE_EDIT_LINE;
import dlangui.widgets.widget;

/**
 * Texto secreto en UTF-8 que borra todo byte que deja de usar: lo que se quita, el
 * almacenamiento anterior al crecer y todo al vaciarse.
 */
struct SecretText {
  private char[] storage;
  private size_t used;

  /// Cantidad de caracteres (no de bytes).
  size_t characterCount() const pure nothrow @safe @nogc {
    size_t count;
    foreach (character; storage[0 .. used]) if ((character & 0xC0) != 0x80) count++;
    return count;
  }

  /**
   * Agrega un carácter al final.
   *
   * Throws: UTFException si `character` no es válido en Unicode.
   */
  void append(dchar character) pure @safe {
    char[4] encoded;
    scope (exit) encoded[] = '\0';
    size_t size = encode(encoded, character);
    if (used + size > storage.length) {
      size_t capacity = storage.length < 16 ? 32 : storage.length * 2;
      while (capacity < used + size) capacity *= 2;
      auto grown = new char[capacity];
      grown[] = '\0';
      grown[0 .. used] = storage[0 .. used];
      storage[] = '\0';
      storage = grown;
    }
    storage[used .. used + size] = encoded[0 .. size];
    used += size;
  }

  /// Quita el último carácter completo, si hay, y borra sus bytes.
  void removeLast() pure nothrow @safe @nogc {
    if (used == 0) return;
    size_t start = used - 1;
    while (start > 0 && (storage[start] & 0xC0) == 0x80) start--;
    storage[start .. used] = '\0';
    used = start;
  }

  /**
   * Entrega el texto y queda vacío. Quien lo recibe debe borrarlo (`secret[] = '\0'`) al
   * terminar; la parte sin usar del almacenamiento ya está en cero.
   */
  char[] take() pure nothrow @safe @nogc {
    auto taken = storage[0 .. used];
    storage = null;
    used = 0;
    return taken;
  }

  /// Borra el texto.
  void clear() pure nothrow @safe @nogc {
    storage[] = '\0';
    used = 0;
  }
}

/**
 * Campo de una línea que muestra un punto por carácter. Acepta lo que se escribe (si pasa
 * `accepts`), borra con Retroceso y llama a `onEnter` con Intro; no admite pegar, para
 * que el secreto no pase por el portapapeles.
 */
final class SecretField : Widget {
  /// Caracteres que se admiten; null admite todos los imprimibles.
  bool delegate(dchar character) @safe accepts;
  /// Se llama al pulsar Intro.
  void delegate() onEnter;
  private SecretText secret;

  this(string id) @trusted {
    super(id);
    styleId = STYLE_EDIT_LINE;
    focusable = true;
    clickable = true;
  }

  /// Cantidad de caracteres escritos.
  size_t length() const pure @safe {
    return secret.characterCount;
  }

  /// Entrega lo escrito en UTF-8 y vacía el campo (SecretText.take: quien lo recibe lo borra).
  char[] take() @trusted {
    invalidate();
    return secret.take();
  }

  /// Borra lo escrito.
  void clear() @trusted {
    secret.clear();
    invalidate();
  }

  override bool onKeyEvent(KeyEvent event) {
    if (event.action == KeyAction.Text) {
      foreach (dchar character; event.text) {
        bool printable = character >= 0x20 && character != 0x7F && isValidDchar(character);
        if (printable && (accepts is null || accepts(character))) secret.append(character);
      }
      invalidate();
      return true;
    }
    if (event.action == KeyAction.KeyDown || event.action == KeyAction.Repeat) {
      if (event.keyCode == KeyCode.BACK) {
        secret.removeLast();
        invalidate();
        return true;
      }
      if (event.keyCode == KeyCode.RETURN && event.action == KeyAction.KeyDown) {
        if (onEnter !is null) onEnter();
        return true;
      }
    }
    return super.onKeyEvent(event);
  }

  override void measure(int parentWidth, int parentHeight) {
    measuredContent(parentWidth, parentHeight, 0, font.height);
  }

  override void onDraw(DrawBuf buf) {
    if (visibility != Visibility.Visible) return;
    super.onDraw(buf);
    Rect content = _pos;
    applyMargins(content);
    applyPadding(content);
    auto saver = ClipRectSaver(buf, content, alpha);
    FontRef shown = font;
    dstring bullets = replicate("•"d, secret.characterCount);
    int top = content.top + (content.height - shown.height) / 2;
    shown.drawText(buf, content.left, top, bullets, textColor);
    if (focused) {
      int caret = content.left + shown.textSize(bullets).x;
      buf.fillRect(Rect(caret, top, caret + 1, top + shown.height), textColor);
    }
  }
}

@("should keep multi-byte characters whole and wipe every byte it drops when editing a secret")
unittest {
  import std.algorithm : all;
  import std.utf : toUTF8;
  SecretText secret;
  foreach (dchar character; "pín€𝄞"d) secret.append(character);
  assert(secret.characterCount == 5);
  // Retroceso quita el carácter de 4 bytes entero y deja sus bytes en cero.
  auto whole = secret.storage;
  size_t before = secret.used;
  secret.removeLast();
  assert(secret.used == before - 4 && whole[secret.used .. before].all!(character => character == '\0'));
  // Al crecer, el almacenamiento anterior queda en cero.
  auto previous = secret.storage;
  foreach (_; 0 .. 40) secret.append('1');
  assert(secret.storage !is previous && previous.all!(character => character == '\0'));
  auto taken = secret.take();
  assert(taken == "pín€" ~ replicate("1", 40));
  assert(secret.characterCount == 0 && secret.take().length == 0);
  taken[] = '\0';
  secret.append('x');
  auto storage = secret.storage;
  secret.clear();
  assert(storage.all!(character => character == '\0') && secret.characterCount == 0);
}
