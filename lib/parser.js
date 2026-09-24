'use strict';

// A structural parser for Firebase security rules: services, match blocks,
// allow statements and functions. Conditions are kept as token ranges, not
// expression trees — every check here is about the shape of a condition, and a
// shape survives syntax this parser has never heard of. Anything it cannot
// place is skipped to the next `;` or `}`, so a file mid-edit still lints.

const { lex } = require('./lexer');

const READS = ['read', 'get', 'list'];
const WRITES = ['write', 'create', 'update', 'delete'];

/**
 * @typedef {import('./lexer').Token} Token
 * @typedef {{name: string, params: string[], body: Token[], returns: Token[]|null,
 *            start: number, end: number}} Fn
 * @typedef {{methods: string[], cond: Token[]|null, start: number, end: number,
 *            keywordEnd: number, match: Match}} Allow
 * @typedef {{path: string, recursive: boolean, start: number, end: number,
 *            headerEnd: number, parent: Match|null, service: Service,
 *            allows: Allow[], children: Match[], fns: Fn[]}} Match
 * @typedef {{name: string, start: number, end: number, matches: Match[], fns: Fn[]}} Service
 * @typedef {{kind: string, start: number, end: number, message: string}} ParseError
 */

/**
 * @param {string} src
 */
function parse(src) {
  const { tokens, comments, errors: lexErrors } = lex(src);
  const errors = /** @type {ParseError[]} */ ([]);
  for (const e of lexErrors) {
    if (e.kind === 'unterminated-string') {
      errors.push({ kind: 'unterminated-string', start: e.start, end: e.end,
        message: 'This string is never closed.' });
    } else if (e.kind === 'unterminated-comment') {
      errors.push({ kind: 'unterminated-comment', start: e.start, end: e.end,
        message: 'This comment is never closed, so everything after it is ignored.' });
    }
  }
  checkBalance(tokens, errors);

  const out = {
    src, tokens, comments, errors,
    version: /** @type {{value: string, start: number, end: number}|null} */ (null),
    services: /** @type {Service[]} */ ([]),
    allows: /** @type {Allow[]} */ ([]),
    matches: /** @type {Match[]} */ ([]),
    functions: /** @type {Fn[]} */ ([]),
  };

  let i = 0;
  const at = (k) => tokens[k];
  const is = (k, v) => tokens[k] && tokens[k].value === v;

  // Top level: rules_version and services. Anything else is skipped.
  while (i < tokens.length) {
    const t = at(i);
    if (t.type === 'ident' && t.value === 'rules_version') {
      let j = i + 1;
      if (is(j, '=')) j++;
      const v = at(j);
      if (v && v.type === 'string') {
        out.version = { value: v.value.slice(1, -1), start: t.start, end: v.end };
        j++;
      }
      if (is(j, ';')) j++;
      i = j;
      continue;
    }
    if (t.type === 'ident' && t.value === 'service') {
      let j = i + 1;
      const nameParts = [];
      while (j < tokens.length && !is(j, '{')) {
        nameParts.push(tokens[j].value);
        j++;
      }
      if (!is(j, '{')) break;
      const close = matching(tokens, j);
      const service = /** @type {Service} */ ({
        name: nameParts.join(''), start: t.start,
        end: close === -1 ? tokens[tokens.length - 1].end : tokens[close].end,
        matches: [], fns: [],
      });
      out.services.push(service);
      parseBody(j + 1, close === -1 ? tokens.length : close, null, service);
      i = close === -1 ? tokens.length : close + 1;
      continue;
    }
    i++;
  }

  /**
   * @param {number} from first token inside the braces
   * @param {number} to index of the closing brace
   * @param {Match|null} parent
   * @param {Service} service
   */
  function parseBody(from, to, parent, service) {
    let k = from;
    while (k < to) {
      const t = at(k);
      if (t.type === 'ident' && t.value === 'match') {
        let j = k + 1;
        const pathToks = [];
        // A wildcard's brace always follows a '/'; the block's brace never does.
        const opensBlock = (x) => is(x, '{') && !(tokens[x - 1] && tokens[x - 1].value === '/');
        while (j < to && !opensBlock(j)) { pathToks.push(tokens[j]); j++; }
        if (!opensBlock(j)) { k = j; continue; }
        const close = matching(tokens, j);
        const end = close === -1 || close > to ? to : close;
        const path = pathToks.map((p) => p.value).join('');
        const m = /** @type {Match} */ ({
          path, recursive: /=\*\*\}/.test(path),
          start: t.start, headerEnd: tokens[j].end,
          end: tokens[Math.min(end, tokens.length - 1)].end,
          parent, service, allows: [], children: [], fns: [],
        });
        if (parent) parent.children.push(m); else service.matches.push(m);
        out.matches.push(m);
        parseBody(j + 1, end, m, service);
        k = end + 1;
        continue;
      }
      if (t.type === 'ident' && t.value === 'allow') {
        let j = k + 1;
        const methods = [];
        while (j < to && at(j).type === 'ident') {
          methods.push(at(j).value);
          j++;
          if (is(j, ',')) j++; else break;
        }
        let cond = null;
        const keywordEnd = tokens[j - 1] ? tokens[j - 1].end : t.end;
        if (is(j, ':')) {
          j++;
          if (is(j, 'if')) j++;
          const condStart = j;
          while (j < to && !is(j, ';')) {
            // A missing semicolon should not swallow the next statement.
            if (at(j).type === 'ident' && (at(j).value === 'allow' || at(j).value === 'match' ||
                at(j).value === 'function') && depthBetween(tokens, condStart, j) === 0) break;
            j++;
          }
          cond = tokens.slice(condStart, j);
        }
        const endTok = is(j, ';') ? at(j) : tokens[Math.max(j - 1, k)];
        if (parent) {
          const a = /** @type {Allow} */ ({ methods, cond, start: t.start, end: endTok.end,
            keywordEnd, match: parent });
          parent.allows.push(a);
          out.allows.push(a);
        }
        k = is(j, ';') ? j + 1 : j;
        continue;
      }
      if (t.type === 'ident' && t.value === 'function') {
        const nameTok = at(k + 1);
        let j = k + 2;
        const params = [];
        if (is(j, '(')) {
          const close = matching(tokens, j);
          for (let p = j + 1; p < close; p++) if (at(p).type === 'ident') params.push(at(p).value);
          j = close + 1;
        }
        if (!is(j, '{')) { k = j; continue; }
        const close = matching(tokens, j);
        const end = close === -1 || close > to ? to : close;
        const body = tokens.slice(j + 1, end);
        const fn = /** @type {Fn} */ ({ name: nameTok ? nameTok.value : '', params, body,
          returns: lastReturn(body), start: t.start, end: tokens[Math.min(end, tokens.length - 1)].end });
        if (parent) parent.fns.push(fn); else service.fns.push(fn);
        out.functions.push(fn);
        k = end + 1;
        continue;
      }
      // Unknown: skip to the end of this statement.
      let j = k;
      while (j < to && !is(j, ';') && !is(j, '}')) {
        if (is(j, '{')) { const c = matching(tokens, j); j = c === -1 ? to : c; }
        j++;
      }
      k = j + 1;
    }
  }

  return out;
}

/** Index of the bracket that closes the one at `open`, or -1. */
function matching(tokens, open) {
  const pairs = { '{': '}', '(': ')', '[': ']' };
  const want = pairs[tokens[open].value];
  let depth = 0;
  for (let k = open; k < tokens.length; k++) {
    const v = tokens[k].value;
    if (tokens[k].type !== 'punct') continue;
    if (v === tokens[open].value) depth++;
    else if (v === want) { depth--; if (depth === 0) return k; }
  }
  return -1;
}

function depthBetween(tokens, from, to) {
  let d = 0;
  for (let k = from; k < to; k++) {
    const v = tokens[k].value;
    if (tokens[k].type !== 'punct') continue;
    if (v === '(' || v === '[' || v === '{') d++;
    else if (v === ')' || v === ']' || v === '}') d--;
  }
  return d;
}

/** The expression of the last `return … ;` in a function body. */
function lastReturn(body) {
  let found = null;
  for (let k = 0; k < body.length; k++) {
    if (body[k].type === 'ident' && body[k].value === 'return') {
      let j = k + 1;
      let d = 0;
      while (j < body.length) {
        const v = body[j].value;
        if (body[j].type === 'punct') {
          if (v === '(' || v === '[' || v === '{') d++;
          else if (v === ')' || v === ']' || v === '}') d--;
          else if (v === ';' && d === 0) break;
        }
        j++;
      }
      found = body.slice(k + 1, j);
      k = j;
    }
  }
  return found;
}

/** Unclosed and stray brackets, reported where a person would look for them. */
function checkBalance(tokens, errors) {
  const stack = [];
  const pairs = { ')': '(', ']': '[', '}': '{' };
  for (const t of tokens) {
    if (t.type !== 'punct') continue;
    if (t.value === '(' || t.value === '[' || t.value === '{') stack.push(t);
    else if (t.value in pairs) {
      const top = stack[stack.length - 1];
      if (top && top.value === pairs[t.value]) stack.pop();
      else {
        errors.push({ kind: 'unbalanced', start: t.start, end: t.end,
          message: `This '${t.value}' has nothing to close.` });
      }
    }
  }
  for (const t of stack) {
    errors.push({ kind: 'unbalanced', start: t.start, end: t.end,
      message: `This '${t.value}' is never closed.` });
  }
}

module.exports = { parse, READS, WRITES };
