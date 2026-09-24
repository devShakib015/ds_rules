'use strict';

// extension.js against a stand-in `vscode` module: enough of the API to prove
// activation wires the right events, that ranges and severities survive the
// trip into Diagnostics, and that settings are obeyed. The real editor is
// checked by hand before a release; this catches the wiring breaking.

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

function fakeVscode(config) {
  const handlers = {};
  const sets = new Map();
  const on = (name) => (fn) => { (handlers[name] = handlers[name] || []).push(fn); return { dispose() {} }; };
  class Position { constructor(line, character) { this.line = line; this.character = character; } }
  class Range { constructor(start, end) { this.start = start; this.end = end; } }
  class Diagnostic { constructor(range, message, severity) { Object.assign(this, { range, message, severity }); } }
  const api = {
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
    Position, Range, Diagnostic,
    Uri: { parse: (s) => ({ toString: () => s }) },
    languages: {
      createDiagnosticCollection: () => ({
        set: (uri, ds) => sets.set(uri.toString(), ds),
        delete: (uri) => sets.delete(uri.toString()),
        dispose() {},
      }),
    },
    workspace: {
      textDocuments: [],
      getConfiguration: () => ({ get: (k, d) => (k in config ? config[k] : d) }),
      onDidOpenTextDocument: on('open'), onDidSaveTextDocument: on('save'),
      onDidChangeTextDocument: on('change'), onDidCloseTextDocument: on('close'),
      onDidChangeConfiguration: on('config'),
    },
  };
  return { api, handlers, sets };
}

function doc(fileName, text, languageId = 'firestore-rules') {
  const lines = text.split('\n');
  return {
    fileName, languageId, uri: { toString: () => fileName },
    getText: () => text,
    positionAt(offset) {
      let line = 0, seen = 0;
      while (line < lines.length - 1 && seen + lines[line].length + 1 <= offset) { seen += lines[line].length + 1; line++; }
      return { line, character: offset - seen };
    },
  };
}

function load(config = {}) {
  const fake = fakeVscode(config);
  const original = Module._load;
  Module._load = function (request, ...rest) {
    if (request === 'vscode') return fake.api;
    return original.call(this, request, ...rest);
  };
  delete require.cache[require.resolve('../extension')];
  try {
    const ext = require('../extension');
    const context = { subscriptions: [] };
    ext.activate(context);
    return { ...fake, ext, context };
  } finally {
    Module._load = original;
  }
}

const RULES = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /notes/{id} {
      allow write: if true;
    }
  }
}`;

test('opening a rules file produces a diagnostic on the right line', () => {
  const { handlers, sets } = load();
  handlers.open[0](doc('/p/firestore.rules', RULES));
  const [d] = sets.get('/p/firestore.rules');
  assert.equal(d.severity, 0);
  assert.equal(d.range.start.line, 4);
  assert.equal(d.range.start.character, 6);
  assert.equal(d.source, 'Firestore Rules');
  assert.equal(d.code.value, 'open-write');
  assert.match(d.code.target.toString(), /#open-write$/);
});

test('a .rules file owned by another extension is still checked', () => {
  const { handlers, sets } = load();
  handlers.open[0](doc('/p/firestore.rules', RULES, 'firestore'));
  assert.equal(sets.get('/p/firestore.rules').length, 1);
});

test('a TypeScript file is ignored', () => {
  const { handlers, sets } = load();
  handlers.open[0](doc('/p/index.ts', RULES, 'typescript'));
  assert.equal(sets.has('/p/index.ts'), false);
});

test('disabled checks and the master switch are obeyed', () => {
  let { handlers, sets } = load({ disabledChecks: ['open-write'] });
  handlers.open[0](doc('/p/firestore.rules', RULES));
  assert.deepEqual(sets.get('/p/firestore.rules'), []);

  ({ handlers, sets } = load({ enable: false }));
  handlers.open[0](doc('/p/firestore.rules', RULES));
  assert.equal(sets.has('/p/firestore.rules'), false);
});

test('closing a file clears its diagnostics', () => {
  const { handlers, sets } = load();
  const d = doc('/p/firestore.rules', RULES);
  handlers.open[0](d);
  handlers.close[0](d);
  assert.equal(sets.has('/p/firestore.rules'), false);
});

test('typing is debounced, then checked', async () => {
  const { handlers, sets } = load();
  const d = doc('/p/firestore.rules', RULES);
  handlers.change[0]({ document: d });
  handlers.change[0]({ document: d });
  assert.equal(sets.has('/p/firestore.rules'), false);
  await new Promise((r) => setTimeout(r, 350));
  assert.equal(sets.get('/p/firestore.rules').length, 1);
});
