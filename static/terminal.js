'use strict';

(() => {
  const MAX_LOCAL_PASTE = 32 * 1024;
  const MAX_SEQUENCE_LENGTH = 1024;
  const MAX_COLUMNS = 240;
  const MAX_ROWS = 100;
  const DEFAULT_FOREGROUND = '#e2e8f0';
  const DEFAULT_BACKGROUND = '#020617';
  const PALETTE = [
    '#000000', '#cd0000', '#00cd00', '#cdcd00', '#0000ee', '#cd00cd', '#00cdcd', '#e5e5e5',
    '#7f7f7f', '#ff0000', '#00ff00', '#ffff00', '#5c5cff', '#ff00ff', '#00ffff', '#ffffff',
  ];

  function blankCell(style = {}) {
    return {
      char: ' ', fg: style.fg ?? null, bg: style.bg ?? null,
      bold: Boolean(style.bold), dim: Boolean(style.dim), italic: Boolean(style.italic),
      underline: Boolean(style.underline), inverse: Boolean(style.inverse), hidden: Boolean(style.hidden),
      strike: Boolean(style.strike), continuation: false,
    };
  }

  function clamp(value, minimum, maximum) {
    return Math.min(maximum, Math.max(minimum, value));
  }

  function color256(index) {
    const value = clamp(Number(index) || 0, 0, 255);
    if (value < 16) return PALETTE[value];
    if (value < 232) {
      const component = value - 16;
      const red = Math.floor(component / 36);
      const green = Math.floor((component % 36) / 6);
      const blue = component % 6;
      const levels = [0, 95, 135, 175, 215, 255];
      return `rgb(${levels[red]}, ${levels[green]}, ${levels[blue]})`;
    }
    const gray = 8 + (value - 232) * 10;
    return `rgb(${gray}, ${gray}, ${gray})`;
  }

  function characterWidth(character) {
    if (/\p{Mark}/u.test(character)) return 0;
    const code = character.codePointAt(0) ?? 0;
    if (
      code >= 0x1100 &&
      (code <= 0x115f || code === 0x2329 || code === 0x232a ||
        (code >= 0x2e80 && code <= 0xa4cf && code !== 0x303f) ||
        (code >= 0xac00 && code <= 0xd7a3) || (code >= 0xf900 && code <= 0xfaff) ||
        (code >= 0xfe10 && code <= 0xfe19) || (code >= 0xfe30 && code <= 0xfe6f) ||
        (code >= 0xff00 && code <= 0xff60) || (code >= 0xffe0 && code <= 0xffe6) ||
        (code >= 0x1f300 && code <= 0x1faff) || (code >= 0x20000 && code <= 0x3fffd))
    ) return 2;
    return 1;
  }

  class TerminalRenderer {
    constructor(container) {
      this.container = container;
      this.columns = 80;
      this.rows = 24;
      this.cursorX = 0;
      this.cursorY = 0;
      this.savedCursor = { x: 0, y: 0 };
      this.scrollTop = 0;
      this.scrollBottom = this.rows - 1;
      this.wraparound = true;
      this.cursorVisible = true;
      this.applicationCursor = false;
      this.bracketedPaste = false;
      this.alternate = null;
      this.style = blankCell();
      this.lines = this.createLines(this.rows);
      this.parserState = 'normal';
      this.sequence = '';
      this.renderPending = false;
      this.screen = document.createElement('div');
      this.screen.className = 'terminal-screen';
      this.screen.setAttribute('aria-live', 'off');
      this.container.replaceChildren(this.screen);
      this.scheduleRender();
    }

    createLine() {
      return Array.from({ length: this.columns }, () => blankCell());
    }

    createLines(count) {
      return Array.from({ length: count }, () => this.createLine());
    }

    resize(columns, rows) {
      const nextColumns = clamp(columns, 20, MAX_COLUMNS);
      const nextRows = clamp(rows, 5, MAX_ROWS);
      if (nextColumns === this.columns && nextRows === this.rows) return;
      const buffers = [this.lines];
      if (this.alternate !== null) buffers.push(this.alternate.lines);
      for (const lines of buffers) {
        for (const line of lines) {
          if (line.length > nextColumns) line.length = nextColumns;
          else while (line.length < nextColumns) line.push(blankCell());
        }
      }
      this.columns = nextColumns;
      for (const lines of buffers) {
        if (lines.length > nextRows) lines.length = nextRows;
        else while (lines.length < nextRows) lines.push(this.createLine());
      }
      this.rows = nextRows;
      this.scrollTop = 0;
      this.scrollBottom = nextRows - 1;
      this.cursorX = clamp(this.cursorX, 0, this.columns - 1);
      this.cursorY = clamp(this.cursorY, 0, this.rows - 1);
      this.scheduleRender();
    }

    reset() {
      this.cursorX = 0;
      this.cursorY = 0;
      this.savedCursor = { x: 0, y: 0 };
      this.scrollTop = 0;
      this.scrollBottom = this.rows - 1;
      this.wraparound = true;
      this.cursorVisible = true;
      this.applicationCursor = false;
      this.bracketedPaste = false;
      this.alternate = null;
      this.style = blankCell();
      this.lines = this.createLines(this.rows);
      this.scheduleRender();
    }

    feed(data) {
      for (const character of data) this.consume(character);
      this.scheduleRender();
    }

    consume(character) {
      if (this.parserState === 'normal') {
        if (character === '\x1b') this.parserState = 'escape';
        else if (character === '\x9b') {
          this.parserState = 'csi';
          this.sequence = '';
        } else if (character < ' ' || character === '\x7f') this.control(character);
        else this.print(character);
        return;
      }
      if (this.parserState === 'escape') {
        this.parserState = 'normal';
        if (character === '[') {
          this.parserState = 'csi';
          this.sequence = '';
        } else if (character === ']' || character === 'P' || character === '^' || character === '_') {
          this.parserState = 'string';
          this.sequence = '';
        } else if (character === '(' || character === ')' || character === '*' || character === '+') {
          this.parserState = 'charset';
        } else if (character === '7') this.saveCursor();
        else if (character === '8') this.restoreCursor();
        else if (character === 'D') this.lineFeed();
        else if (character === 'E') {
          this.cursorX = 0;
          this.lineFeed();
        } else if (character === 'M') this.reverseIndex();
        else if (character === 'c') this.reset();
        return;
      }
      if (this.parserState === 'charset') {
        this.parserState = 'normal';
        return;
      }
      if (this.parserState === 'string') {
        if (character === '\x07') this.parserState = 'normal';
        else if (character === '\x1b') this.parserState = 'string-escape';
        else if (this.sequence.length < MAX_SEQUENCE_LENGTH) this.sequence += character;
        return;
      }
      if (this.parserState === 'string-escape') {
        this.parserState = character === '\\' ? 'normal' : 'string';
        return;
      }
      if (this.parserState === 'csi') {
        if (character >= '@' && character <= '~') {
          this.executeCsi(this.sequence, character);
          this.sequence = '';
          this.parserState = 'normal';
        } else if (this.sequence.length < MAX_SEQUENCE_LENGTH) this.sequence += character;
        else {
          this.sequence = '';
          this.parserState = 'normal';
        }
      }
    }

    control(character) {
      if (character === '\b') this.cursorX = Math.max(0, this.cursorX - 1);
      else if (character === '\t') this.cursorX = Math.min(this.columns - 1, (Math.floor(this.cursorX / 8) + 1) * 8);
      else if (character === '\n' || character === '\v' || character === '\f') this.lineFeed();
      else if (character === '\r') this.cursorX = 0;
    }

    print(character) {
      const width = characterWidth(character);
      if (width === 0) {
        const previous = this.cursorX > 0 ? this.lines[this.cursorY][this.cursorX - 1] : null;
        if (previous && !previous.continuation) previous.char += character;
        return;
      }
      if (this.cursorX >= this.columns || (width === 2 && this.cursorX === this.columns - 1)) {
        if (!this.wraparound) this.cursorX = this.columns - 1;
        else {
          this.cursorX = 0;
          this.lineFeed();
        }
      }
      this.clearWideCell(this.cursorX, this.cursorY);
      const cell = blankCell(this.style);
      cell.char = character;
      this.lines[this.cursorY][this.cursorX] = cell;
      if (width === 2 && this.cursorX + 1 < this.columns) {
        const continuation = blankCell(this.style);
        continuation.char = '';
        continuation.continuation = true;
        this.lines[this.cursorY][this.cursorX + 1] = continuation;
      }
      this.cursorX += width;
    }

    clearWideCell(x, y) {
      const line = this.lines[y];
      if (line[x]?.continuation && x > 0) line[x - 1] = blankCell();
      if (x + 1 < this.columns && line[x + 1]?.continuation) line[x + 1] = blankCell();
    }

    lineFeed() {
      if (this.cursorY === this.scrollBottom) this.scrollUp(1);
      else this.cursorY = Math.min(this.rows - 1, this.cursorY + 1);
    }

    reverseIndex() {
      if (this.cursorY === this.scrollTop) this.scrollDown(1);
      else this.cursorY = Math.max(0, this.cursorY - 1);
    }

    scrollUp(count) {
      const amount = clamp(count, 1, this.scrollBottom - this.scrollTop + 1);
      this.lines.splice(this.scrollTop, amount);
      for (let index = 0; index < amount; index += 1) this.lines.splice(this.scrollBottom, 0, this.createLine());
    }

    scrollDown(count) {
      const amount = clamp(count, 1, this.scrollBottom - this.scrollTop + 1);
      this.lines.splice(this.scrollBottom - amount + 1, amount);
      for (let index = 0; index < amount; index += 1) this.lines.splice(this.scrollTop, 0, this.createLine());
    }

    saveCursor() {
      this.savedCursor = { x: this.cursorX, y: this.cursorY };
    }

    restoreCursor() {
      this.cursorX = clamp(this.savedCursor.x, 0, this.columns - 1);
      this.cursorY = clamp(this.savedCursor.y, 0, this.rows - 1);
    }

    executeCsi(raw, final) {
      let prefix = '';
      if (raw.startsWith('?') || raw.startsWith('>') || raw.startsWith('!')) {
        prefix = raw[0];
        raw = raw.slice(1);
      }
      const parameterText = raw.replace(/[ -/].*$/u, '');
      const parameters = parameterText.split(';').map((item) => {
        const first = item.split(':', 1)[0];
        return first === '' ? 0 : Number.parseInt(first, 10) || 0;
      });
      const value = (index, fallback = 1) => parameters[index] || fallback;
      if (final === 'A') this.cursorY = Math.max(this.scrollTop, this.cursorY - value(0));
      else if (final === 'B') this.cursorY = Math.min(this.scrollBottom, this.cursorY + value(0));
      else if (final === 'C' || final === 'a') this.cursorX = Math.min(this.columns - 1, this.cursorX + value(0));
      else if (final === 'D') this.cursorX = Math.max(0, this.cursorX - value(0));
      else if (final === 'E') {
        this.cursorY = Math.min(this.scrollBottom, this.cursorY + value(0));
        this.cursorX = 0;
      } else if (final === 'F') {
        this.cursorY = Math.max(this.scrollTop, this.cursorY - value(0));
        this.cursorX = 0;
      } else if (final === 'G' || final === '`') this.cursorX = clamp(value(0) - 1, 0, this.columns - 1);
      else if (final === 'd') this.cursorY = clamp(value(0) - 1, 0, this.rows - 1);
      else if (final === 'H' || final === 'f') {
        this.cursorY = clamp(value(0) - 1, 0, this.rows - 1);
        this.cursorX = clamp(value(1) - 1, 0, this.columns - 1);
      } else if (final === 'J') this.eraseDisplay(parameters[0] || 0);
      else if (final === 'K') this.eraseLine(parameters[0] || 0);
      else if (final === 'X') this.eraseCharacters(value(0));
      else if (final === '@') this.insertCharacters(value(0));
      else if (final === 'P') this.deleteCharacters(value(0));
      else if (final === 'L') this.insertLines(value(0));
      else if (final === 'M') this.deleteLines(value(0));
      else if (final === 'S') this.scrollUp(value(0));
      else if (final === 'T') this.scrollDown(value(0));
      else if (final === 'm') this.setGraphics(parameters);
      else if (final === 's') this.saveCursor();
      else if (final === 'u') this.restoreCursor();
      else if (final === 'r' && prefix === '') this.setScrollRegion(parameters);
      else if ((final === 'h' || final === 'l') && prefix === '?') this.setPrivateModes(parameters, final === 'h');
    }

    eraseDisplay(mode) {
      if (mode === 2 || mode === 3) {
        this.lines = this.createLines(this.rows);
        return;
      }
      if (mode === 0) {
        this.eraseRange(this.cursorY, this.cursorX, this.columns);
        for (let row = this.cursorY + 1; row < this.rows; row += 1) this.eraseRange(row, 0, this.columns);
      } else if (mode === 1) {
        for (let row = 0; row < this.cursorY; row += 1) this.eraseRange(row, 0, this.columns);
        this.eraseRange(this.cursorY, 0, this.cursorX + 1);
      }
    }

    eraseLine(mode) {
      if (mode === 0) this.eraseRange(this.cursorY, this.cursorX, this.columns);
      else if (mode === 1) this.eraseRange(this.cursorY, 0, this.cursorX + 1);
      else if (mode === 2) this.eraseRange(this.cursorY, 0, this.columns);
    }

    eraseRange(row, start, end) {
      for (let column = start; column < end; column += 1) this.lines[row][column] = blankCell(this.style);
    }

    eraseCharacters(count) {
      this.eraseRange(this.cursorY, this.cursorX, Math.min(this.columns, this.cursorX + count));
    }

    insertCharacters(count) {
      const line = this.lines[this.cursorY];
      const amount = clamp(count, 1, this.columns - this.cursorX);
      line.splice(this.cursorX, 0, ...Array.from({ length: amount }, () => blankCell(this.style)));
      line.length = this.columns;
    }

    deleteCharacters(count) {
      const line = this.lines[this.cursorY];
      line.splice(this.cursorX, count);
      while (line.length < this.columns) line.push(blankCell(this.style));
    }

    insertLines(count) {
      if (this.cursorY < this.scrollTop || this.cursorY > this.scrollBottom) return;
      const amount = clamp(count, 1, this.scrollBottom - this.cursorY + 1);
      this.lines.splice(this.cursorY, 0, ...this.createLines(amount));
      this.lines.splice(this.scrollBottom + 1, amount);
    }

    deleteLines(count) {
      if (this.cursorY < this.scrollTop || this.cursorY > this.scrollBottom) return;
      const amount = clamp(count, 1, this.scrollBottom - this.cursorY + 1);
      this.lines.splice(this.cursorY, amount);
      for (let index = 0; index < amount; index += 1) this.lines.splice(this.scrollBottom, 0, this.createLine());
    }

    setScrollRegion(parameters) {
      const top = clamp((parameters[0] || 1) - 1, 0, this.rows - 1);
      const bottom = clamp((parameters[1] || this.rows) - 1, 0, this.rows - 1);
      if (top < bottom) {
        this.scrollTop = top;
        this.scrollBottom = bottom;
        this.cursorX = 0;
        this.cursorY = 0;
      }
    }

    setPrivateModes(parameters, enabled) {
      for (const mode of parameters) {
        if (mode === 1) this.applicationCursor = enabled;
        else if (mode === 7) this.wraparound = enabled;
        else if (mode === 25) this.cursorVisible = enabled;
        else if (mode === 2004) this.bracketedPaste = enabled;
        else if (mode === 47 || mode === 1047 || mode === 1049) this.useAlternateScreen(enabled);
      }
    }

    useAlternateScreen(enabled) {
      if (enabled && this.alternate === null) {
        this.alternate = {
          lines: this.lines, cursorX: this.cursorX, cursorY: this.cursorY,
          savedCursor: this.savedCursor, scrollTop: this.scrollTop, scrollBottom: this.scrollBottom,
        };
        this.lines = this.createLines(this.rows);
        this.cursorX = 0;
        this.cursorY = 0;
        this.savedCursor = { x: 0, y: 0 };
        this.scrollTop = 0;
        this.scrollBottom = this.rows - 1;
      } else if (!enabled && this.alternate !== null) {
        const primary = this.alternate;
        this.lines = primary.lines;
        this.cursorX = primary.cursorX;
        this.cursorY = primary.cursorY;
        this.savedCursor = primary.savedCursor;
        this.scrollTop = primary.scrollTop;
        this.scrollBottom = primary.scrollBottom;
        this.alternate = null;
      }
    }

    setGraphics(parameters) {
      const values = parameters.length ? parameters : [0];
      for (let index = 0; index < values.length; index += 1) {
        const code = values[index];
        if (code === 0) this.style = blankCell();
        else if (code === 1) this.style.bold = true;
        else if (code === 2) this.style.dim = true;
        else if (code === 3) this.style.italic = true;
        else if (code === 4) this.style.underline = true;
        else if (code === 7) this.style.inverse = true;
        else if (code === 8) this.style.hidden = true;
        else if (code === 9) this.style.strike = true;
        else if (code === 22) {
          this.style.bold = false;
          this.style.dim = false;
        } else if (code === 23) this.style.italic = false;
        else if (code === 24) this.style.underline = false;
        else if (code === 27) this.style.inverse = false;
        else if (code === 28) this.style.hidden = false;
        else if (code === 29) this.style.strike = false;
        else if (code >= 30 && code <= 37) this.style.fg = PALETTE[code - 30];
        else if (code >= 40 && code <= 47) this.style.bg = PALETTE[code - 40];
        else if (code >= 90 && code <= 97) this.style.fg = PALETTE[code - 90 + 8];
        else if (code >= 100 && code <= 107) this.style.bg = PALETTE[code - 100 + 8];
        else if (code === 39) this.style.fg = null;
        else if (code === 49) this.style.bg = null;
        else if ((code === 38 || code === 48) && values[index + 1] === 5 && values[index + 2] !== undefined) {
          this.style[code === 38 ? 'fg' : 'bg'] = color256(values[index + 2]);
          index += 2;
        } else if ((code === 38 || code === 48) && values[index + 1] === 2 && values[index + 4] !== undefined) {
          const red = clamp(values[index + 2], 0, 255);
          const green = clamp(values[index + 3], 0, 255);
          const blue = clamp(values[index + 4], 0, 255);
          this.style[code === 38 ? 'fg' : 'bg'] = `rgb(${red}, ${green}, ${blue})`;
          index += 4;
        }
      }
    }

    scheduleRender() {
      if (this.renderPending) return;
      this.renderPending = true;
      window.requestAnimationFrame(() => {
        this.renderPending = false;
        this.render();
      });
    }

    render() {
      const fragment = document.createDocumentFragment();
      for (let rowIndex = 0; rowIndex < this.rows; rowIndex += 1) {
        const row = document.createElement('div');
        row.className = 'terminal-row';
        const line = this.lines[rowIndex];
        let span = null;
        let key = null;
        for (let column = 0; column < this.columns; column += 1) {
          const cell = line[column] ?? blankCell();
          const cursor = this.cursorVisible && rowIndex === this.cursorY && column === Math.min(this.cursorX, this.columns - 1);
          const nextKey = this.styleKey(cell, cursor);
          if (nextKey !== key) {
            span = document.createElement('span');
            this.applyStyle(span, cell, cursor);
            row.append(span);
            key = nextKey;
          }
          span.append(document.createTextNode(cell.continuation ? '' : cell.char));
        }
        fragment.append(row);
      }
      this.screen.replaceChildren(fragment);
    }

    styleKey(cell, cursor) {
      return [cell.fg, cell.bg, cell.bold, cell.dim, cell.italic, cell.underline, cell.inverse, cell.hidden, cell.strike, cursor].join('|');
    }

    applyStyle(span, cell, cursor) {
      let foreground = cell.fg ?? DEFAULT_FOREGROUND;
      let background = cell.bg ?? DEFAULT_BACKGROUND;
      if (cell.inverse) [foreground, background] = [background, foreground];
      span.style.color = foreground;
      span.style.backgroundColor = background;
      if (cell.bold) span.style.fontWeight = '700';
      if (cell.dim) span.style.opacity = '0.65';
      if (cell.italic) span.style.fontStyle = 'italic';
      const decorations = [];
      if (cell.underline) decorations.push('underline');
      if (cell.strike) decorations.push('line-through');
      if (decorations.length) span.style.textDecoration = decorations.join(' ');
      if (cell.hidden) span.style.color = background;
      if (cursor) span.classList.add('terminal-cursor');
    }
  }

  const container = document.getElementById('terminal');
  const status = document.getElementById('terminal-status');
  const reconnectButton = document.getElementById('reconnect-button');
  const disconnectButton = document.getElementById('disconnect-button');
  const passwordForm = document.getElementById('ssh-password-form');
  const passwordInput = document.getElementById('ssh-password');
  const computerName = document.body.dataset.computerName ?? '';
  const authentication = document.body.dataset.authentication ?? 'key';
  const localDevelopment = document.body.dataset.localDevelopment === 'true';
  if (!container || !status || !reconnectButton || !disconnectButton || !computerName) return;

  const renderer = new TerminalRenderer(container);
  const input = document.createElement('textarea');
  input.className = 'terminal-input';
  input.setAttribute('aria-label', `Input for SSH terminal ${computerName}`);
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('autocapitalize', 'off');
  input.setAttribute('spellcheck', 'false');
  input.rows = 1;
  container.append(input);
  let socket = null;
  let dimensions = { cols: 80, rows: 24 };

  function setStatus(message, state) {
    status.textContent = message;
    status.dataset.state = state;
  }

  function csrfToken() {
    for (const part of document.cookie.split(';')) {
      const [name, ...value] = part.trim().split('=');
      if (name === 'flasgo-csrf') return value.join('=');
    }
    return '';
  }

  function measure() {
    const probe = document.createElement('span');
    probe.className = 'terminal-probe';
    probe.textContent = 'M';
    container.append(probe);
    const rectangle = probe.getBoundingClientRect();
    probe.remove();
    const styles = window.getComputedStyle(container);
    const horizontalPadding = Number.parseFloat(styles.paddingLeft) + Number.parseFloat(styles.paddingRight);
    const verticalPadding = Number.parseFloat(styles.paddingTop) + Number.parseFloat(styles.paddingBottom);
    const cols = clamp(Math.floor((container.clientWidth - horizontalPadding) / Math.max(rectangle.width, 1)), 20, MAX_COLUMNS);
    const rows = clamp(Math.floor((container.clientHeight - verticalPadding) / Math.max(rectangle.height, 1)), 5, MAX_ROWS);
    dimensions = { cols, rows };
    renderer.resize(cols, rows);
    if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'resize', cols, rows }));
  }

  function sendInput(data) {
    if (!data || socket?.readyState !== WebSocket.OPEN) return;
    let chunk = '';
    let bytes = 0;
    const encoder = new TextEncoder();
    for (const character of data) {
      const characterBytes = encoder.encode(character).length;
      if (bytes + characterBytes > 4096 && chunk) {
        socket.send(JSON.stringify({ type: 'input', data: chunk }));
        chunk = '';
        bytes = 0;
      }
      chunk += character;
      bytes += characterBytes;
    }
    if (chunk) socket.send(JSON.stringify({ type: 'input', data: chunk }));
  }

  function keySequence(event) {
    const arrows = {
      ArrowUp: renderer.applicationCursor ? '\x1bOA' : '\x1b[A',
      ArrowDown: renderer.applicationCursor ? '\x1bOB' : '\x1b[B',
      ArrowRight: renderer.applicationCursor ? '\x1bOC' : '\x1b[C',
      ArrowLeft: renderer.applicationCursor ? '\x1bOD' : '\x1b[D',
    };
    const keys = {
      Enter: '\r', Backspace: '\x7f', Escape: '\x1b', Home: '\x1b[H', End: '\x1b[F',
      Insert: '\x1b[2~', Delete: '\x1b[3~', PageUp: '\x1b[5~', PageDown: '\x1b[6~',
      F1: '\x1bOP', F2: '\x1bOQ', F3: '\x1bOR', F4: '\x1bOS', F5: '\x1b[15~',
      F6: '\x1b[17~', F7: '\x1b[18~', F8: '\x1b[19~', F9: '\x1b[20~', F10: '\x1b[21~',
      F11: '\x1b[23~', F12: '\x1b[24~',
    };
    if (event.key === 'Tab') return event.shiftKey ? '\x1b[Z' : '\t';
    if (arrows[event.key]) return arrows[event.key];
    if (keys[event.key]) return keys[event.key];
    if (event.ctrlKey && !event.altKey && !event.metaKey) {
      if (event.shiftKey && ['c', 'v'].includes(event.key.toLowerCase())) return null;
      const upper = event.key.toUpperCase();
      if (upper >= 'A' && upper <= 'Z') return String.fromCharCode(upper.charCodeAt(0) - 64);
      const controls = { '@': '\x00', '[': '\x1b', '\\': '\x1c', ']': '\x1d', '^': '\x1e', _: '\x1f', '?': '\x7f' };
      return controls[event.key] ?? null;
    }
    if (event.altKey && !event.ctrlKey && !event.metaKey && event.key.length === 1) return `\x1b${event.key}`;
    return null;
  }

  function showPasswordPrompt(message = 'Password required') {
    if (authentication !== 'password' || !passwordForm || !passwordInput) return;
    passwordForm.hidden = false;
    reconnectButton.hidden = true;
    disconnectButton.disabled = true;
    setStatus(message, 'waiting');
    passwordInput.focus();
  }

  function connect(password = null) {
    if (window.location.protocol !== 'https:' && !localDevelopment) {
      setStatus('HTTPS is required', 'error');
      disconnectButton.disabled = true;
      return;
    }
    reconnectButton.hidden = true;
    disconnectButton.disabled = false;
    setStatus('Connecting…', 'connecting');
    const websocketScheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${websocketScheme}://${window.location.host}/ws/terminal?device=${encodeURIComponent(computerName)}`;
    socket = new WebSocket(url, 'wake-terminal-v1');
    socket.addEventListener('open', () => {
      const authorization = { type: 'auth', csrf: csrfToken(), ...dimensions };
      if (authentication === 'password') authorization.password = password;
      socket.send(JSON.stringify(authorization));
      password = null;
    });
    socket.addEventListener('message', (event) => {
      if (typeof event.data !== 'string') return;
      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
        socket.close(1002, 'Invalid server message');
        return;
      }
      if (message.type === 'ready') {
        setStatus('Connected', 'connected');
        input.focus();
      } else if (message.type === 'output' && typeof message.data === 'string') renderer.feed(message.data);
      else if (message.type === 'error' && typeof message.message === 'string') setStatus(message.message, 'error');
      else if (message.type === 'exit') setStatus('Remote session ended', 'closed');
    });
    socket.addEventListener('close', () => {
      password = null;
      if (authentication === 'password') {
        showPasswordPrompt(status.dataset.state === 'error' ? status.textContent : 'Password required');
      } else {
        if (status.dataset.state !== 'error') setStatus('Disconnected', 'closed');
        reconnectButton.hidden = false;
        disconnectButton.disabled = true;
      }
    });
    socket.addEventListener('error', () => {
      password = null;
      setStatus('Connection failed', 'error');
    });
  }

  input.addEventListener('keydown', (event) => {
    const sequence = keySequence(event);
    if (sequence !== null) {
      event.preventDefault();
      sendInput(sequence);
    }
  });
  let composing = false;
  input.addEventListener('compositionstart', () => {
    composing = true;
  });
  input.addEventListener('compositionend', () => {
    composing = false;
    if (input.value) sendInput(input.value);
    input.value = '';
  });
  input.addEventListener('input', () => {
    if (composing) return;
    if (input.value) sendInput(input.value);
    input.value = '';
  });
  input.addEventListener('paste', (event) => {
    event.preventDefault();
    let text = event.clipboardData?.getData('text/plain') ?? '';
    if (text.length > MAX_LOCAL_PASTE) text = text.slice(0, MAX_LOCAL_PASTE);
    if (renderer.bracketedPaste) text = `\x1b[200~${text}\x1b[201~`;
    sendInput(text);
  });
  container.addEventListener('click', () => input.focus());
  reconnectButton.addEventListener('click', () => {
    renderer.reset();
    connect();
  });
  if (passwordForm && passwordInput) {
    passwordForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const password = passwordInput.value;
      if (!password) return;
      passwordInput.value = '';
      passwordForm.hidden = true;
      renderer.reset();
      connect(password);
    });
  }
  disconnectButton.addEventListener('click', () => socket?.close(1000, 'Disconnected by user'));
  window.addEventListener('beforeunload', () => socket?.close(1000, 'Page closed'));
  new ResizeObserver(measure).observe(container);
  measure();
  if (authentication === 'password') showPasswordPrompt();
  else connect();
})();
