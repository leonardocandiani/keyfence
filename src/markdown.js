'use strict';
// Credentials written as markdown: a bold field, a table row or a password
// column. The emphasis marks and the pipes sit where the labeled rule expects
// `:` or `=`, so it never saw these. This file only reads the layout; whether a
// value is a secret is decided by the caller.

const MAX_LABEL = 48;
// The spaces around the label are capped: open-ended ones made long runs quadratic.
const BOLD = /(\*\*|__)[ \t]{0,4}((?:(?!\*\*|__)[^\n|`]){1,48}?)[ \t]{0,4}(?::[ \t]{0,4}\1|\1[ \t]{0,4}:)/g;
const WRAPPERS = ['**', '__', '`', '"', "'"];

// The value without the marks around it, and where it starts.
function unwrap(text, start) {
  let value = text;
  let at = start;
  let quoted = false;
  for (const w of WRAPPERS) {
    if (value.length > w.length * 2 && value.startsWith(w) && value.endsWith(w)) {
      value = value.slice(w.length, -w.length);
      at += w.length;
      quoted = quoted || w.length === 1;
    }
  }
  return { value, start: at, quoted };
}

// The inside of a leading quote or code span, or null.
function wrapped(s) {
  if (!/^[`"']/.test(s)) return null;
  const close = s.indexOf(s[0], 1);
  const inner = close < 0 ? '' : s.slice(1, close);
  return inner && inner === inner.trim() ? inner : null;
}

// The line without a closing break mark and a note in parentheses. A note is
// set apart by a space; glued to the value, parentheses are part of it.
function withoutTail(line) {
  let s = line.trimEnd().replace(/(?:\\|<br ?\/?>)$/, '').trimEnd();
  const open = s.lastIndexOf('(');
  if (s.endsWith(')') && /\s/.test(s[open - 1] || '')) s = s.slice(0, open).trimEnd();
  return s;
}

// `**Senha:** x`: a quoted value may be followed by anything; a bare one has to
// end the line (a note in parentheses aside), or it is just a sentence.
function boldFields(text, labelOf) {
  const out = [];
  for (const m of text.matchAll(BOLD)) {
    const label = labelOf(m[2]);
    if (!label) continue;
    let at = m.index + m[0].length;
    while (text[at] === ' ' || text[at] === '\t') at++;
    const nl = text.indexOf('\n', at);
    const rest = text.slice(at, nl < 0 ? text.length : nl);
    const inner = wrapped(rest);
    if (inner !== null) out.push({ label, value: inner, start: at + 1, quoted: true });
    else {
      const bare = withoutTail(rest);
      if (bare && !/\s/.test(bare)) out.push({ label, ...unwrap(bare, at) });
    }
  }
  return out;
}

// Cells of a table line with their offsets, or null. A pipe inside backticks or
// escaped belongs to the cell. The outer pipes are required unless `inTable`:
// a delimiter row already said these lines are a table.
function cellsOf(line, offset, inTable = false) {
  const head = /^[ \t>]*\|?/.exec(line)[0];
  const body = line.trimEnd();
  if (!inTable && !(head.endsWith('|') && body.length > head.length && body.endsWith('|'))) return null;
  const cells = [];
  let from = head.length;
  let pipes = head.endsWith('|') ? 1 : 0;
  const push = (to) => {
    const raw = body.slice(from, to);
    const lead = raw.length - raw.trimStart().length;
    cells.push(unwrap(raw.trim(), offset + from + lead));
  };
  for (let i = from; i < body.length; i++) {
    if (body[i] === '\\') i++;
    else if (body[i] === '`') {
      const close = body.indexOf('`', i + 1);
      if (close > 0) i = close;
    } else if (body[i] === '|') {
      push(i);
      pipes++;
      from = i + 1;
    }
  }
  if (from < body.length) push(body.length);
  return pipes && cells.length ? cells : null;
}

const isRule = (cells) => Boolean(cells) && cells.every((c) => /^:?-+:?$/.test(c.value));

// The lines with their cells: a delimiter row (`--- | ---`) makes a table of the
// line above it and of the lines with a pipe below it.
function tableLines(text) {
  let offset = 0;
  const lines = text.split('\n').map((line) => {
    const at = offset;
    offset += line.length + 1;
    return { line, at, cells: cellsOf(line, at) };
  });
  for (let i = 1; i < lines.length; i++) {
    const rule = cellsOf(lines[i].line, lines[i].at, true);
    const header = isRule(rule) && cellsOf(lines[i - 1].line, lines[i - 1].at, true);
    if (!header) continue;
    lines[i - 1].cells = header;
    lines[i].cells = rule;
    // The rows are read once: the search resumes after the table.
    for (; i + 1 < lines.length; i++) {
      const row = cellsOf(lines[i + 1].line, lines[i + 1].at, true);
      if (!row) break;
      lines[i + 1].cells = row;
    }
  }
  return lines;
}

// `| Senha | x |` in any table, and every row under a column headed `Senha`.
function tableFields(text, labelOf, isPasswordLabel) {
  const out = [];
  const pair = (label, cell) => {
    // A value with spaces is only a passphrase when quotes mark where it starts and ends.
    if (label && cell && (cell.quoted || !/\s/.test(cell.value))) out.push({ label, ...cell });
  };
  let header = null;
  let columns = [];
  for (const { cells } of tableLines(text)) {
    if (!cells) {
      header = null;
      columns = [];
    } else if (isRule(cells)) {
      columns = (header || []).map((c) => {
        const label = labelOf(c.value);
        return label && isPasswordLabel(label) ? label : null;
      });
    } else {
      pair(labelOf(cells[0].value), cells[1]);
      columns.forEach((label, i) => pair(label, cells[i]));
      header = cells;
    }
  }
  return out;
}

// `keywords` is the label alternation of the labeled rule; the label of a field
// or cell is the last keyword in it, read as a whole word (`Senha do painel`,
// `API Key`, never `Passos`).
function markdownFields(text, keywords, isPasswordLabel) {
  const word = new RegExp(`(?<!\\p{L})${keywords}(?!\\p{L})`, 'giu');
  const labelOf = (s) => {
    if (s.length > MAX_LABEL || s.startsWith('/')) return null; // a route (`/auth/login`) is not a label
    const found = [...s.replace(/ /g, '_').matchAll(word)].pop();
    return found ? s.slice(found.index, found.index + found[0].length) : null;
  };
  return [...boldFields(text, labelOf), ...tableFields(text, labelOf, isPasswordLabel)];
}

module.exports = { markdownFields };
