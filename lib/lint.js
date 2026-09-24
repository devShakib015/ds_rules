'use strict';

// The checks. Each one looks for a mistake that leaks or breaks data and can be
// seen without running the rules — and each stays quiet when the shape is only
// usually wrong. A security linter that cries wolf gets uninstalled, and then it
// catches nothing.

const { parse, READS, WRITES } = require('./parser');
const { lex } = require('./lexer');

const DOCS = 'https://github.com/devShakib015/ds_rules#';

/** id -> default severity and a one-line title (the README lists the same). */
const CHECKS = {
  'open-write': { severity: 'error', title: 'Anyone can write' },
  'open-read-recursive': { severity: 'error', title: 'Anyone can read a whole subtree' },
  'public-read': { severity: 'hint', title: 'Public read of one path' },
  'test-mode': { severity: 'error', title: 'Firebase test mode is still on' },
  'test-mode-expired': { severity: 'warning', title: 'Test mode has expired' },
  'root-recursive-grant': { severity: 'warning', title: 'A grant on every document' },
  'signed-in-write': { severity: 'warning', title: 'Any signed-in user can write' },
  'unvalidated-write': { severity: 'info', title: 'Writes are not validated' },
  'storage-unchecked-upload': { severity: 'warning', title: 'Uploads have no size or type limit' },
  'email-unverified': { severity: 'info', title: 'Email claim without email_verified' },
  'too-many-lookups': { severity: 'warning', title: 'More get()/exists() calls than a request allows' },
  'rules-version': { severity: 'warning', title: "No rules_version = '2'" },
  'syntax': { severity: 'error', title: 'Unbalanced or unterminated' },
};

const LOOKUP_LIMIT = 10;
const LOOKUPS = new Set(['get', 'exists', 'getAfter', 'existsAfter']);

/**
 * @param {string} src
 * @param {{disabled?: string[], today?: Date}} [opts]
 * @returns {{id: string, severity: string, start: number, end: number,
 *            message: string, docs: string}[]}
 */
function lint(src, opts = {}) {
  const disabled = new Set(opts.disabled || []);
  const today = opts.today || new Date();
  const doc = parse(src);
  const out = [];
  const add = (id, start, end, message, severity) => {
    if (disabled.has(id)) return;
    out.push({ id, severity: severity || CHECKS[id].severity, start, end, message, docs: DOCS + id });
  };

  for (const e of doc.errors) add('syntax', e.start, e.end, e.message);

  // Nothing to say about a file that is not rules — a udev or Prometheus
  // `.rules` file shares the extension and none of the language.
  const services = doc.services.filter((s) => /^(cloud\.firestore|firebase\.storage)$/.test(s.name));
  if (!services.length) return finish(out, doc, src);

  if (!doc.version || doc.version.value !== '2') {
    const at = doc.version || { start: services[0].start, end: services[0].start + 'service'.length };
    add('rules-version', at.start, at.end, doc.version
      ? `rules_version is '${doc.version.value}'. Version 2 is what recursive wildcards and collection-group queries are written for.`
      : "No rules_version = '2'; so this file runs as version 1, where recursive wildcards match differently and collection-group queries can't be allowed at all.");
  }

  const fns = new Map();
  for (const f of doc.functions) if (f.name && f.returns) fns.set(f.name, f.returns);

  // The email claim is checked where it is written, once — not on every allow
  // that happens to call isAdmin().
  for (const f of doc.functions) {
    if (!f.returns) continue;
    const c = canon(f.returns);
    if (c.includes('request . auth . token . email') && !c.includes('email_verified')) {
      add('email-unverified', f.start, f.start + 'function'.length + 1 + f.name.length,
        emailMessage());
    }
  }

  for (const a of doc.allows) {
    const service = a.match.service.name;
    const storage = service === 'firebase.storage';
    const reads = a.methods.filter((m) => READS.includes(m));
    const writes = a.methods.filter((m) => WRITES.includes(m));
    const inlined = a.cond ? inline(a.cond, fns, 0) : null;
    const ors = inlined ? disjuncts(inlined) : [];
    const alwaysFalse = ors.length > 0 && ors.every((d) => canon(d) === 'false');
    if (alwaysFalse) continue;

    const where = a.match.path || 'this path';
    const open = a.cond === null || ors.some((d) => canon(d) === 'true');

    if (open) {
      if (writes.length) {
        const also = reads.length ? ` and ${list(reads)}` : '';
        add('open-write', a.start, a.keywordEnd,
          `Anyone — signed in or not — can ${list(writes)}${also} ${scope(a.match)}.`);
      } else if (reads.length && a.match.recursive && isRootLevel(a.match)) {
        add('open-read-recursive', a.start, a.keywordEnd,
          `Anyone can ${list(reads)} ${scope(a.match)}, including collections nobody has created yet.`);
      } else if (reads.length) {
        // A folder called /public with a recursive wildcard is how public files
        // are served. Only the whole database or bucket deserves an error.
        const what = a.match.recursive ? `everything under ${where}` : where;
        add('public-read', a.start, a.keywordEnd,
          `Public ${list(reads)}. Fine for published content — just keep anything private out of ${what}.`);
      }
      continue;   // nothing else here matters more
    }

    const test = ors.map(testModeDate).find(Boolean);
    if (test) {
      const date = test.toISOString().slice(0, 10);
      if (test >= startOfDay(today)) {
        add('test-mode', a.start, a.keywordEnd,
          `Firebase test mode: anyone can ${list(a.methods)} ${scope(a.match)} until ${date}.`);
      } else {
        add('test-mode-expired', a.start, a.keywordEnd,
          `Test mode ended on ${date}, so this rule now refuses every request. Replace it with rules that say who can do what.`);
      }
      continue;
    }

    if (a.match.recursive && isRootLevel(a.match)) {
      add('root-recursive-grant', a.start, a.keywordEnd,
        `This grants ${list(a.methods)} on ${scope(a.match).replace(/^every /, 'every ')}. Rules are OR'ed, so no narrower rule anywhere else can take this access back.`);
    }

    // Creating is often the point (a comment, a post); changing or deleting
    // somebody else's document never is. A create is judged by what it stores.
    const modifies = writes.filter((m) => m !== 'create');
    if (modifies.length && ors.some(isSignedInOnly)) {
      add('signed-in-write', a.start, a.keywordEnd,
        `Any signed-in user can ${list(modifies)} here — anybody's document, including from an account made a minute ago. Compare request.auth.uid with the document's owner.`);
    }

    const creates = a.methods.filter((m) => m === 'write' || m === 'create' || m === 'update');
    const text = canon(inlined || []);
    if (creates.length && storage) {
      const size = text.includes('request . resource . size');
      const type = text.includes('request . resource . contentType');
      if (!size || !type) {
        const missing = !size && !type ? 'size or content type' : !size ? 'size' : 'content type';
        add('storage-unchecked-upload', a.start, a.keywordEnd,
          `Uploads here aren't limited by ${missing}. Anyone allowed to write can store any file, as large as Storage lets them.`);
      }
    } else if (creates.length && !text.includes('request . resource')) {
      // Unchecked fields from a stranger are a real problem; from the owner or
      // the admin they are usually trust, not a leak — but an owner who can
      // write any field can also write `role: 'admin'`, so it still gets said.
      const bound = isIdentityBound(text);
      add('unvalidated-write', a.start, a.keywordEnd,
        bound
          ? `Nothing here checks request.resource. Only the owner or an admin can ${list(creates)}, but they can set any field — a role or owner field included.`
          : `Nothing here checks request.resource, so ${article(list(creates))} can set any fields, of any type and size.`,
        bound ? 'hint' : undefined);
    }

    if (a.cond) {
      const own = canon(a.cond);
      if (own.includes('request . auth . token . email') && !own.includes('email_verified')) {
        add('email-unverified', a.start, a.keywordEnd, emailMessage());
      }
    }

    const lookups = countLookups(inlined || []);
    if (lookups > LOOKUP_LIMIT) {
      add('too-many-lookups', a.start, a.keywordEnd,
        `${lookups} document lookups in one condition (including the functions it calls). A single-document request allows ${LOOKUP_LIMIT}, and past that the request is denied.`);
    }
  }

  return finish(out, doc, src);
}

function emailMessage() {
  return 'Checks the email claim without email_verified. Harmless while email/password is your only sign-in method; add request.auth.token.email_verified == true before enabling another provider.';
}

// ------------------------------------------------------------- suppression

/**
 * `// rules-lint-ignore` silences everything on its own line and the next;
 * `// rules-lint-ignore: open-write, public-read` silences only those.
 */
function finish(out, doc, src) {
  const lineOf = lineIndex(src);
  const quiet = [];
  for (const c of doc.comments) {
    const m = /rules-lint-ignore(?:\s*:\s*([\w\s,-]+))?/.exec(c.value);
    if (!m) continue;
    const ids = m[1] ? m[1].split(',').map((s) => s.trim()).filter(Boolean) : null;
    const line = lineOf(c.start);
    quiet.push({ lines: [line, line + 1], ids });
  }
  return out
    .filter((d) => !quiet.some((q) => q.lines.includes(lineOf(d.start)) &&
      (!q.ids || q.ids.includes(d.id))))
    .sort((a, b) => a.start - b.start || a.id.localeCompare(b.id));
}

function lineIndex(src) {
  const starts = [0];
  for (let i = 0; i < src.length; i++) if (src[i] === '\n') starts.push(i + 1);
  return (offset) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo;
  };
}

// ------------------------------------------------------------- expressions

/** A comparable form: token values joined by single spaces. */
function canon(tokens) {
  return tokens.map((t) => t.value).join(' ');
}

function stripParens(tokens) {
  let t = tokens;
  while (t.length >= 2 && t[0].value === '(' && closes(t, 0) === t.length - 1) t = t.slice(1, -1);
  return t;
}

function closes(tokens, open) {
  let d = 0;
  for (let k = open; k < tokens.length; k++) {
    if (tokens[k].type !== 'punct') continue;
    if (tokens[k].value === '(') d++;
    else if (tokens[k].value === ')') { d--; if (d === 0) return k; }
  }
  return -1;
}

function splitTop(tokens, op) {
  const parts = [];
  let d = 0, from = 0;
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (t.type !== 'punct') continue;
    if (t.value === '(' || t.value === '[' || t.value === '{') d++;
    else if (t.value === ')' || t.value === ']' || t.value === '}') d--;
    else if (t.value === op && d === 0) { parts.push(tokens.slice(from, k)); from = k + 1; }
  }
  parts.push(tokens.slice(from));
  return parts;
}

/** Every alternative that on its own grants access. */
function disjuncts(tokens) {
  const out = [];
  for (const part of splitTop(stripParens(tokens), '||')) {
    const p = stripParens(part);
    if (splitTop(p, '||').length > 1) out.push(...disjuncts(p));
    else out.push(p);
  }
  return out;
}

/**
 * Replace calls to functions declared in the file with their return
 * expressions, so `if isSignedIn()` is judged by what isSignedIn() says.
 * Parameters are left as names: every check here is about request.* and
 * built-ins, which a parameter cannot stand in for.
 */
function inline(tokens, fns, depth) {
  if (depth > 4) return tokens;
  const out = [];
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    const prev = tokens[k - 1];
    const next = tokens[k + 1];
    if (t.type === 'ident' && fns.has(t.value) && next && next.value === '(' &&
        !(prev && prev.value === '.')) {
      const close = closes(tokens, k + 1);
      if (close !== -1) {
        out.push({ ...next, value: '(' });
        out.push(...inline(fns.get(t.value), fns, depth + 1));
        out.push({ ...tokens[close], value: ')' });
        k = close;
        continue;
      }
    }
    out.push(t);
  }
  return out;
}

const SIGNED_IN = new Set([
  'request . auth != null', 'null != request . auth',
  'request . auth . uid != null', 'null != request . auth . uid',
]);

/** Does the condition tie access to a particular identity, not just any user? */
function isIdentityBound(text) {
  return text.includes('request . auth . uid ==') || text.includes('== request . auth . uid') ||
         text.includes('request . auth . token') ||
         // A role looked up on the caller's own document, however many helper
         // functions the path went through: get(/users/$(request.auth.uid)).
         /\$ (\( )+request \. auth \. uid/.test(text);
}

function isSignedInOnly(d) {
  return SIGNED_IN.has(canon(d));
}

function testModeDate(d) {
  const m = /^request \. time <=? timestamp \. date \( (\d{4}) , (\d{1,2}) , (\d{1,2}) \)$/.exec(canon(d));
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
}

function countLookups(tokens) {
  let n = 0;
  for (let k = 0; k < tokens.length; k++) {
    const t = tokens[k];
    if (t.type === 'ident' && LOOKUPS.has(t.value) && tokens[k + 1] && tokens[k + 1].value === '(' &&
        !(tokens[k - 1] && tokens[k - 1].value === '.')) n++;
  }
  return n;
}

// ------------------------------------------------------------- scope words

function isRootLevel(match) {
  const root = (p) => /^\/databases\/\{\w+\}\/documents$/.test(p) || /^\/b\/\{\w+\}\/o$/.test(p);
  const joined = /^\/databases\/\{\w+\}\/documents\/\{\w+=\*\*\}$/.test(match.path) ||
                 /^\/b\/\{\w+\}\/o\/\{\w+=\*\*\}$/.test(match.path);
  if (joined) return true;
  return !!match.parent && root(match.parent.path) && /^\/\{\w+=\*\*\}$/.test(match.path);
}

function scope(match) {
  const storage = match.service && match.service.name === 'firebase.storage';
  if (match.recursive && isRootLevel(match)) {
    return storage ? 'every file in the bucket' : 'every document in the database';
  }
  if (match.recursive) return `everything under ${match.path}`;
  return `at ${match.path}`;
}

function list(methods) {
  const uniq = [...new Set(methods)];
  if (uniq.length <= 1) return uniq[0] || 'access';
  return uniq.slice(0, -1).join(', ') + ' and ' + uniq[uniq.length - 1];
}

/** "a create", "an update", "a write". */
function article(phrase) {
  return (/^[aeiou]/i.test(phrase) ? 'an ' : 'a ') + phrase;
}

function startOfDay(d) {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
}

module.exports = { lint, CHECKS, _internal: { canon, disjuncts, inline, lex } };
