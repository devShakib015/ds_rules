'use strict';

// The VS Code side: run lib/lint.js over rules files and show what it finds.
// Everything that decides *what* to say lives in lib/, which knows nothing
// about the editor and is tested on its own.

const vscode = require('vscode');
const { lint } = require('./lib/lint');

const SEVERITY = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  info: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

// Other rules extensions register their own language ids for the same files,
// so a rules file is recognised by id *or* by name — and lib/lint.js stays
// silent on any `.rules` file that is not Firebase rules at all.
const LANGUAGE_IDS = new Set(['firestore-rules', 'firestore', 'firestorerules', 'firebase-rules']);

function isRulesFile(doc) {
  return LANGUAGE_IDS.has(doc.languageId) || /\.rules$/.test(doc.fileName);
}

function settings() {
  const c = vscode.workspace.getConfiguration('firestoreRulesLinter');
  return {
    enabled: c.get('enable', true),
    disabled: c.get('disabledChecks', []),
  };
}

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  const collection = vscode.languages.createDiagnosticCollection('firestore-rules');
  context.subscriptions.push(collection);
  const timers = new Map();

  const check = (doc) => {
    if (!isRulesFile(doc)) return;
    const s = settings();
    if (!s.enabled) { collection.delete(doc.uri); return; }
    const found = lint(doc.getText(), { disabled: s.disabled });
    collection.set(doc.uri, found.map((f) => {
      const d = new vscode.Diagnostic(
        new vscode.Range(doc.positionAt(f.start), doc.positionAt(f.end)),
        f.message, SEVERITY[f.severity]);
      d.source = 'Firestore Rules';
      d.code = { value: f.id, target: vscode.Uri.parse(f.docs) };
      return d;
    }));
  };

  // While typing, wait for a pause: a half-written condition is not worth a
  // squiggle, and nobody reads one that flickers.
  const soon = (doc) => {
    if (!isRulesFile(doc)) return;
    const key = doc.uri.toString();
    clearTimeout(timers.get(key));
    timers.set(key, setTimeout(() => { timers.delete(key); check(doc); }, 300));
  };

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(check),
    vscode.workspace.onDidSaveTextDocument(check),
    vscode.workspace.onDidChangeTextDocument((e) => soon(e.document)),
    vscode.workspace.onDidCloseTextDocument((doc) => collection.delete(doc.uri)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('firestoreRulesLinter')) vscode.workspace.textDocuments.forEach(check);
    }),
    { dispose: () => timers.forEach(clearTimeout) },
  );

  vscode.workspace.textDocuments.forEach(check);
}

function deactivate() {}

module.exports = { activate, deactivate, isRulesFile };
