'use strict';

// Tokens for the Firebase security rules language. Only as much as the
// structural parser and the checks need: the linter never evaluates a rule, so
// there is no attempt to type expressions or to know every built-in.

const PUNCT3 = [];
const PUNCT2 = ['==', '!=', '<=', '>=', '&&', '||'];
const PUNCT1 = '{}()[];,:.=!<>+-*/%?$';

/**
 * @typedef {{type: 'ident'|'number'|'string'|'punct'|'comment',
 *            value: string, start: number, end: number}} Token
 * @typedef {{kind: 'unterminated-string'|'unterminated-comment'|'stray',
 *            start: number, end: number, text: string}} LexError
 */

/**
 * @param {string} src
 * @returns {{tokens: Token[], comments: Token[], errors: LexError[]}}
 */
function lex(src) {
  const tokens = [];
  const comments = [];
  const errors = [];
  let i = 0;
  const n = src.length;

  while (i < n) {
    const c = src[i];

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { i++; continue; }

    if (c === '/' && src[i + 1] === '/') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      comments.push({ type: 'comment', value: src.slice(i, stop), start: i, end: stop });
      i = stop;
      continue;
    }
    if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end === -1) {
        errors.push({ kind: 'unterminated-comment', start: i, end: n, text: src.slice(i, i + 2) });
        comments.push({ type: 'comment', value: src.slice(i), start: i, end: n });
        break;
      }
      comments.push({ type: 'comment', value: src.slice(i, end + 2), start: i, end: end + 2 });
      i = end + 2;
      continue;
    }

    if (c === "'" || c === '"') {
      let j = i + 1;
      let closed = false;
      while (j < n) {
        if (src[j] === '\\') { j += 2; continue; }
        if (src[j] === c) { closed = true; break; }
        if (src[j] === '\n') break;       // strings never span lines here
        j++;
      }
      if (!closed) {
        errors.push({ kind: 'unterminated-string', start: i, end: j, text: src.slice(i, j) });
        tokens.push({ type: 'string', value: src.slice(i, j), start: i, end: j });
        i = j;
        continue;
      }
      tokens.push({ type: 'string', value: src.slice(i, j + 1), start: i, end: j + 1 });
      i = j + 1;
      continue;
    }

    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < n && /[0-9.eE_]/.test(src[j])) j++;
      tokens.push({ type: 'number', value: src.slice(i, j), start: i, end: j });
      i = j;
      continue;
    }

    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_]/.test(src[j])) j++;
      tokens.push({ type: 'ident', value: src.slice(i, j), start: i, end: j });
      i = j;
      continue;
    }

    const three = src.slice(i, i + 3);
    if (PUNCT3.includes(three)) {
      tokens.push({ type: 'punct', value: three, start: i, end: i + 3 });
      i += 3;
      continue;
    }
    const two = src.slice(i, i + 2);
    if (PUNCT2.includes(two)) {
      tokens.push({ type: 'punct', value: two, start: i, end: i + 2 });
      i += 2;
      continue;
    }
    if (PUNCT1.includes(c)) {
      tokens.push({ type: 'punct', value: c, start: i, end: i + 1 });
      i++;
      continue;
    }

    errors.push({ kind: 'stray', start: i, end: i + 1, text: c });
    i++;
  }

  return { tokens, comments, errors };
}

module.exports = { lex };
