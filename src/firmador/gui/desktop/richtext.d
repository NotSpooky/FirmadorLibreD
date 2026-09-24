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
 * Texto con formato para los reportes de validación y los mensajes (lo que en Swing
 * mostraban JLabel y JEditorPane con HTML). Entiende el HTML sencillo que producen la hoja
 * resources/xslt/html/simple-report.xslt y los textos de messages*.properties: párrafos,
 * saltos de línea, negrita, cursiva, enlaces, títulos y listas. RichText lo dibuja con
 * ajuste de línea; los enlaces se abren con un clic y Ctrl+C copia el texto.
 */
module firmador.gui.desktop.richtext;

import std.algorithm : canFind, max, min, startsWith;
import std.array : appender;
import std.conv : ConvException, to;
import std.string : indexOf, strip, toLower;
import std.uni : isWhite;
import std.utf : toUTF32;

import dlangui.core.events;
import dlangui.core.types;
import dlangui.graphics.drawbuf;
import dlangui.graphics.fonts;
import dlangui.platforms.common.platform : Platform;
import dlangui.widgets.widget;

/// Trozo de texto con un mismo formato.
struct TextRun {
  dstring text;
  bool bold;
  bool italic;
  /// Destino del enlace (vacío si no es enlace).
  string link;
}

/// Bloque de texto: párrafo, título, elemento de lista o definición.
struct RichBlock {
  TextRun[] runs;
  /// Sangría en niveles (listas y definiciones).
  int indent;
  /// Título: se dibuja más grande.
  bool heading;
  /// Elemento de lista: lleva viñeta.
  bool bullet;
}

private immutable string[] blockTags = ["p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "dt", "dd", "tr",
  "blockquote", "pre", "table", "ul", "ol", "dl", "center"];

/// Decodifica las entidades HTML de un texto (&amp;, &lt;, &#233;, &#xE9;…).
string decodeEntities(string text) pure @safe {
  auto output = appender!string;
  size_t position = 0;
  while (position < text.length) {
    if (text[position] != '&') {
      output ~= text[position++];
      continue;
    }
    auto end = text[position .. $].indexOf(';');
    if (end < 2 || end > 10) {
      output ~= text[position++];
      continue;
    }
    string entity = text[position + 1 .. position + end];
    dchar decoded = 0;
    switch (entity) {
      case "amp": decoded = '&'; break;
      case "lt": decoded = '<'; break;
      case "gt": decoded = '>'; break;
      case "quot": decoded = '"'; break;
      case "apos": decoded = '\''; break;
      case "nbsp": decoded = '\u00A0'; break;
      default:
        if (entity.length > 1 && entity[0] == '#') {
          try {
            uint code = entity[1] == 'x' || entity[1] == 'X' ? entity[2 .. $].to!uint(16) : entity[1 .. $].to!uint;
            if (code > 0 && code <= 0x10FFFF && (code < 0xD800 || code > 0xDFFF)) decoded = cast(dchar) code;
          } catch (ConvException) {
            decoded = 0;
          }
        }
        break;
    }
    if (decoded == 0) {
      output ~= text[position++];
      continue;
    }
    output ~= decoded;
    position += end + 1;
  }
  return output[];
}

/// Valor de un atributo de una etiqueta (`href` de `<a href="…">`), o null.
private string attributeValue(string tag, string name) pure @safe {
  string lowered = tag.toLower;
  auto found = lowered.indexOf(name ~ "=");
  if (found < 0) return null;
  size_t start = found + name.length + 1;
  if (start >= tag.length) return null;
  char quote = tag[start];
  if (quote == '"' || quote == '\'') {
    auto close = tag[start + 1 .. $].indexOf(quote);
    if (close < 0) return null;
    return decodeEntities(tag[start + 1 .. start + 1 + close]);
  }
  size_t end = start;
  while (end < tag.length && !isWhite(tag[end]) && tag[end] != '>') end++;
  return decodeEntities(tag[start .. end]);
}

/**
 * Interpreta el HTML sencillo en bloques. Los espacios se colapsan como en HTML, las
 * etiquetas desconocidas se ignoran conservando su texto y el contenido de script y style
 * se descarta.
 */
RichBlock[] parseRichText(string html) pure @safe {
  RichBlock[] blocks;
  RichBlock current;
  int bold, italic, indent, skip;
  string[] links;
  // El último carácter del bloque es un espacio o un salto (o el bloque está vacío).
  bool afterSpace = true;

  void flush() {
    // Quita el espacio final del bloque.
    while (current.runs.length && current.runs[$ - 1].text.length && current.runs[$ - 1].text[$ - 1] == ' ') {
      current.runs[$ - 1].text = current.runs[$ - 1].text[0 .. $ - 1];
      if (current.runs[$ - 1].text.length == 0) current.runs = current.runs[0 .. $ - 1];
    }
    if (current.runs.length) blocks ~= current;
    current = RichBlock.init;
    current.indent = indent;
    afterSpace = true;
  }

  void addText(dstring text) {
    if (skip > 0 || text.length == 0) return;
    TextRun run = TextRun(text, bold > 0, italic > 0, links.length ? links[$ - 1] : null);
    if (current.runs.length && current.runs[$ - 1].bold == run.bold && current.runs[$ - 1].italic == run.italic
        && current.runs[$ - 1].link == run.link) {
      current.runs[$ - 1].text ~= run.text;
    } else {
      current.runs ~= run;
    }
  }

  void addWords(string raw) {
    auto collapsed = appender!dstring;
    foreach (dchar character; decodeEntities(raw).toUTF32) {
      bool space = isWhite(character) && character != '\u00A0';
      if (space && afterSpace) continue;
      collapsed ~= space ? ' ' : character;
      afterSpace = space;
    }
    addText(collapsed[]);
  }

  current.indent = 0;
  size_t position = 0;
  while (position < html.length) {
    auto open = html[position .. $].indexOf('<');
    if (open < 0) {
      addWords(html[position .. $]);
      break;
    }
    if (open > 0) addWords(html[position .. position + open]);
    size_t tagStart = position + open;
    if (html[tagStart .. $].startsWith("<!--")) {
      auto commentEnd = html[tagStart .. $].indexOf("-->");
      position = commentEnd < 0 ? html.length : tagStart + commentEnd + 3;
      continue;
    }
    auto close = html[tagStart .. $].indexOf('>');
    if (close < 0) {
      addWords(html[tagStart .. $]);
      break;
    }
    string tag = html[tagStart + 1 .. tagStart + close].strip;
    position = tagStart + close + 1;
    bool closing = tag.startsWith("/");
    if (closing) tag = tag[1 .. $].strip;
    bool selfClosing = tag.length && tag[$ - 1] == '/';
    size_t nameEnd = 0;
    while (nameEnd < tag.length && !isWhite(tag[nameEnd]) && tag[nameEnd] != '/') nameEnd++;
    string name = tag[0 .. nameEnd].toLower;

    switch (name) {
      case "br":
        // Un espacio justo antes del salto no se ve: se quita.
        if (current.runs.length && current.runs[$ - 1].text.length && current.runs[$ - 1].text[$ - 1] == ' ') {
          current.runs[$ - 1].text = current.runs[$ - 1].text[0 .. $ - 1];
        }
        addText("\n");
        afterSpace = true;
        break;
      case "b", "strong":
        bold += closing ? (bold > 0 ? -1 : 0) : 1;
        break;
      case "i", "em":
        italic += closing ? (italic > 0 ? -1 : 0) : 1;
        break;
      case "a":
        if (closing) {
          if (links.length) links = links[0 .. $ - 1];
        } else if (!selfClosing) {
          links ~= attributeValue(tag, "href");
        }
        break;
      case "script", "style":
        skip += closing ? (skip > 0 ? -1 : 0) : (selfClosing ? 0 : 1);
        break;
      default:
        if (!blockTags.canFind(name)) break;
        flush();
        // Los contenedores (y la definición, que puede traer párrafos) sangran lo que llevan dentro.
        if (name == "ul" || name == "ol" || name == "dl" || name == "blockquote" || name == "dd") {
          indent = closing ? max(0, indent - 1) : indent + 1;
          current.indent = indent;
        } else if (!closing) {
          current.heading = name.length == 2 && name[0] == 'h' && name[1] >= '1' && name[1] <= '6';
          current.bullet = name == "li";
          current.indent = indent;
        }
        break;
    }
  }
  flush();
  return blocks;
}

/// Texto plano de los bloques, un bloque por línea (para copiarlo).
dstring plainText(const RichBlock[] blocks) pure @safe {
  auto output = appender!dstring;
  foreach (index, block; blocks) {
    if (index) output ~= '\n';
    if (block.bullet) output ~= "• ";
    foreach (run; block.runs) output ~= run.text;
  }
  return output[];
}

/**
 * Trozo ya ubicado para dibujarlo. Guarda el estilo y no la fuente: estos trozos los libera
 * el recolector, que al salir puede correr después de que dlangui cerró FreeType.
 */
private struct PlacedText {
  int x, y, width, height;
  dstring text;
  bool bold, italic, heading;
  string link;
}

/// Texto con formato, ajuste de línea y enlaces.
class RichText : Widget {
  private RichBlock[] blocks;
  private PlacedText[] placed;
  private int laidOutWidth = -1;
  private int contentHeight;
  /// Se llama al hacer clic en un enlace, con su destino.
  void delegate(string link) onLink;

  this(string ID = null, string html = null) @trusted {
    super(ID);
    styleId = "TEXT";
    focusable = true;
    trackHover = true;
    setHtml(html);
  }

  /// Cambia el contenido.
  void setHtml(string html) @trusted {
    blocks = parseRichText(html is null ? "" : html);
    laidOutWidth = -1;
    requestLayout();
  }

  /// Texto sin formato.
  override @property dstring text() const {
    return plainText(blocks);
  }

  /// Cambia el contenido por texto sin formato.
  override @property Widget text(dstring plain) {
    import firmador.xml.dom : escapeXml;
    import std.array : replace;
    import std.utf : toUTF8;
    setHtml(escapeXml(plain.toUTF8).replace("\n", "<br>"));
    return this;
  }

  override @property Widget text(UIString plain) {
    return text(plain.value);
  }

  private FontRef fontFor(bool bold, bool italic, bool heading) {
    FontRef base = font();
    int size = heading ? base.size * 5 / 4 : base.size;
    return FontManager.instance.getFont(size, bold || heading ? FontWeight.Bold : FontWeight.Normal, italic,
      base.family, base.face);
  }

  /// Ubica los trozos con el ancho disponible.
  private void layoutText(int width) {
    placed = null;
    int y = 0;
    FontRef base = font();
    int indentStep = base.height * 3 / 2;
    foreach (blockIndex, block; blocks) {
      if (blockIndex) y += base.height / 2;
      int left = block.indent * indentStep;
      int x = left;
      int lineHeight = base.height;
      if (block.bullet) {
        placed ~= PlacedText(x, y, 0, base.height, "• "d, false, false, false, null);
        left += base.textSize("• "d).x;
        x = left;
      }
      foreach (run; block.runs) {
        FontRef runFont = fontFor(run.bold, run.italic, block.heading);
        lineHeight = max(lineHeight, runFont.height);
        size_t start = 0;
        while (start < run.text.length) {
          if (run.text[start] == '\n') {
            x = left;
            y += lineHeight;
            start++;
            continue;
          }
          size_t end = start;
          // Una palabra con su espacio siguiente, o un salto de línea.
          while (end < run.text.length && run.text[end] != ' ' && run.text[end] != '\n') end++;
          if (end < run.text.length && run.text[end] == ' ') end++;
          dstring word = run.text[start .. end];
          int wordWidth = runFont.textSize(word).x;
          if (x > left && x + wordWidth > width) {
            x = left;
            y += lineHeight;
            if (word.length && word[0] == ' ') {
              start++;
              continue;
            }
          }
          if (wordWidth > width - left && word.length > 1) {
            // Palabra más ancha que la línea (rutas, enlaces): se corta por caracteres.
            size_t fit = 1;
            while (fit < word.length && runFont.textSize(word[0 .. fit + 1]).x <= width - x) fit++;
            word = word[0 .. fit];
            wordWidth = runFont.textSize(word).x;
            end = start + fit;
          }
          placed ~= PlacedText(x, y, wordWidth, runFont.height, word, run.bold, run.italic, block.heading, run.link);
          x += wordWidth;
          start = end;
        }
      }
      y += lineHeight;
    }
    contentHeight = y;
    laidOutWidth = width;
  }

  override void measure(int parentWidth, int parentHeight) {
    int available = parentWidth == SIZE_UNSPECIFIED ? 600 : parentWidth - margins.left - margins.right
      - padding.left - padding.right;
    if (maxWidth > 0 && maxWidth < available) available = maxWidth - padding.left - padding.right;
    available = max(available, 80);
    if (available != laidOutWidth || _needLayout) layoutText(available);
    int widest = 0;
    foreach (piece; placed) widest = max(widest, piece.x + piece.width);
    measuredContent(parentWidth, parentHeight, widest, contentHeight);
  }

  override void layout(Rect rc) {
    super.layout(rc);
    Rect content = rc;
    applyMargins(content);
    applyPadding(content);
    if (content.width != laidOutWidth && content.width > 0) layoutText(content.width);
  }

  override void onDraw(DrawBuf buf) {
    if (visibility != Visibility.Visible) return;
    super.onDraw(buf);
    Rect rc = _pos;
    applyMargins(rc);
    auto saver = ClipRectSaver(buf, rc, alpha);
    applyPadding(rc);
    uint color = textColor;
    foreach (piece; placed) {
      uint pieceColor = piece.link.length ? 0x1A57B8 : color;
      FontRef pieceFont = fontFor(piece.bold, piece.italic, piece.heading);
      pieceFont.drawText(buf, rc.left + piece.x, rc.top + piece.y, piece.text, pieceColor);
      if (piece.link.length) {
        int underline = rc.top + piece.y + pieceFont.baseline + 1;
        buf.fillRect(Rect(rc.left + piece.x, underline, rc.left + piece.x + piece.width, underline + 1), pieceColor);
      }
    }
  }

  /// Enlace bajo el punto (coordenadas de la ventana), o null.
  private string linkAt(int x, int y) {
    Rect rc = _pos;
    applyMargins(rc);
    applyPadding(rc);
    foreach (piece; placed) {
      if (piece.link.length && x >= rc.left + piece.x && x < rc.left + piece.x + piece.width
          && y >= rc.top + piece.y && y < rc.top + piece.y + piece.height) {
        return piece.link;
      }
    }
    return null;
  }

  override uint getCursorType(int x, int y) {
    return linkAt(x, y) !is null ? CursorType.Hand : CursorType.Arrow;
  }

  override bool onMouseEvent(MouseEvent event) {
    if (event.action == MouseAction.ButtonDown && event.button == MouseButton.Left) {
      setFocus();
      string link = linkAt(event.x, event.y);
      if (link !is null && onLink !is null) {
        onLink(link);
        return true;
      }
    }
    return super.onMouseEvent(event);
  }

  override bool onKeyEvent(KeyEvent event) {
    if (event.action == KeyAction.KeyDown && event.keyCode == KeyCode.KEY_C && (event.flags & KeyFlag.Control)) {
      Platform.instance.setClipboardText(text);
      return true;
    }
    return super.onKeyEvent(event);
  }
}

@("should split the report HTML into blocks with bold runs and collapsed spaces when parsing")
unittest {
  auto blocks = parseRichText("<html><p>El documento   <b>está firmado</b>.\n Contiene 1</p>"
    ~ "<p>Firmado por <b>ANA</b><br>Fecha</p><dl><dt>Detalle</dt><dd><p><b>ERROR: </b>x &amp; y</p></dd></dl></html>");
  assert(blocks.length == 4);
  assert(blocks[0].runs.length == 3);
  assert(blocks[0].runs[0].text == "El documento "d && !blocks[0].runs[0].bold);
  assert(blocks[0].runs[1].text == "está firmado"d && blocks[0].runs[1].bold);
  assert(blocks[0].runs[2].text == ". Contiene 1"d);
  assert(blocks[1].runs[1].text == "ANA"d && blocks[1].runs[2].text == "\nFecha"d);
  assert(blocks[2].indent == 1 && blocks[3].indent == 2);
  assert(blocks[3].runs[1].text == "x & y"d);
}

@("should keep link targets and decode entities when parsing messages")
unittest {
  auto blocks = parseRichText(`Guardado en:<br><a href="file:///tmp/a%20b.pdf">/tmp/a b.pdf</a><br>`
    ~ "&#233;&#xE9;&nbsp;&bogus;<script>no</script>");
  assert(blocks.length == 1);
  assert(blocks[0].runs[1].link == "file:///tmp/a%20b.pdf" && blocks[0].runs[1].text == "/tmp/a b.pdf"d);
  assert(plainText(blocks) == "Guardado en:\n/tmp/a b.pdf\néé\u00A0&bogus;"d);
  assert(parseRichText("<ul><li>uno</li><li>dos</li></ul>")[1].bullet);
}
