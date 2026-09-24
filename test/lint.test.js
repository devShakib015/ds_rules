'use strict';

// One test per check, with the smallest rules that show it — and the other
// half, which matters as much: rules that look alarming and are fine must say
// nothing. `node --test` runs these; there are no dependencies.

const test = require('node:test');
const assert = require('node:assert/strict');
const { lint } = require('../lib/lint');

const TODAY = new Date('2026-09-24');
const run = (src, opts = {}) => lint(src, { today: TODAY, ...opts });
const ids = (src, opts) => run(src, opts).map((d) => d.id);
const loud = (src, opts) => run(src, opts).filter((d) => d.severity !== 'hint').map((d) => d.id);

const fs = (body, version = "rules_version = '2';") => `${version}
service cloud.firestore {
  match /databases/{database}/documents {
${body}
  }
}`;
const st = (body) => `rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
${body}
  }
}`;

// ------------------------------------------------------------------ open

test('open-write: an unconditional write', () => {
  assert.deepEqual(ids(fs('match /notes/{id} { allow write: if true; }')), ['open-write']);
  assert.deepEqual(ids(fs('match /notes/{id} { allow create; }')), ['open-write']);
});

test('open-write: true hidden behind || still opens it', () => {
  assert.deepEqual(ids(fs('match /n/{id} { allow write: if request.auth.uid == id || true; }')),
    ['open-write']);
});

test('open-write names the whole database for a root wildcard', () => {
  const [d] = run(fs('match /{document=**} { allow read, write: if true; }'));
  assert.equal(d.id, 'open-write');
  assert.match(d.message, /every document in the database/);
  assert.match(d.message, /write and read/);
});

test('open-read-recursive: the whole database readable', () => {
  assert.deepEqual(ids(fs('match /{document=**} { allow read: if true; }')), ['open-read-recursive']);
});

test('public-read: one open collection is a hint, not an error', () => {
  const [d] = run(fs('match /profile/{id} { allow read: if true; }'));
  assert.equal(d.id, 'public-read');
  assert.equal(d.severity, 'hint');
});

test('public-read: a recursive public folder in Storage is a hint', () => {
  const src = st('match /public/{allPaths=**} { allow read: if true; }');
  assert.deepEqual(loud(src), []);
  assert.deepEqual(ids(src), ['public-read']);
});

test('if false says nothing', () => {
  assert.deepEqual(ids(fs('match /{document=**} { allow read, write: if false; }')), []);
});

// ------------------------------------------------------------- test mode

test('test-mode: the console default before its date', () => {
  const src = fs('match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 10, 24); }');
  const [d] = run(src);
  assert.equal(d.id, 'test-mode');
  assert.equal(d.severity, 'error');
  assert.match(d.message, /2026-10-24/);
});

test('test-mode-expired: after its date the rule refuses everything', () => {
  const [d] = run(fs('match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 8, 1); }'));
  assert.equal(d.id, 'test-mode-expired');
  assert.equal(d.severity, 'warning');
});

// ---------------------------------------------------------- broad grants

test('root-recursive-grant: any real condition on every document', () => {
  assert.ok(ids(fs('match /{document=**} { allow read: if request.auth != null; }'))
    .includes('root-recursive-grant'));
});

test('root-recursive-grant: not for a recursive match inside one user', () => {
  const src = fs('match /users/{uid}/{doc=**} { allow read: if request.auth.uid == uid; }');
  assert.ok(!ids(src).includes('root-recursive-grant'));
});

test('signed-in-write: update by any signed-in user', () => {
  assert.ok(ids(fs('match /stats/{id} { allow update: if request.auth != null; }'))
    .includes('signed-in-write'));
});

test('signed-in-write: seen through a helper function', () => {
  const src = fs(`function signedIn() { return request.auth != null; }
    match /stats/{id} { allow delete: if signedIn(); }`);
  assert.ok(ids(src).includes('signed-in-write'));
});

test('signed-in-write: a create alone is judged by what it stores, not by this', () => {
  const src = fs('match /posts/{id} { allow create: if request.auth != null && request.resource.data.uid == request.auth.uid; }');
  assert.deepEqual(ids(src), []);
});

test('signed-in-write: an owner check is not "any signed-in user"', () => {
  const src = fs('match /users/{uid} { allow update: if request.auth != null && request.auth.uid == uid && request.resource.data.keys().hasOnly(["name"]); }');
  assert.deepEqual(ids(src), []);
});

// ------------------------------------------------------------ validation

test('unvalidated-write: a stranger can store anything', () => {
  const [d] = run(fs('match /posts/{id} { allow create: if request.auth != null; }'));
  assert.equal(d.id, 'unvalidated-write');
  assert.equal(d.severity, 'info');
});

test('unvalidated-write: owner or admin only is a hint', () => {
  for (const cond of [
    'request.auth.uid == uid',
    "request.auth.token.email == 'a@b.c' && request.auth.token.email_verified == true",
    'get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == "admin"',
  ]) {
    const d = run(fs(`match /users/{uid} { allow update: if ${cond}; }`))
      .find((x) => x.id === 'unvalidated-write');
    assert.ok(d, cond);
    assert.equal(d.severity, 'hint', cond);
  }
});

test('unvalidated-write: a role behind two helper functions still counts as bound', () => {
  const src = fs(`function uid() { return request.auth.uid; }
    function userPath() { return /databases/$(database)/documents/users/$(uid()); }
    function isAdmin() { return get(userPath()).data.role == 'admin'; }
    match /sponsors/{id} { allow write: if isAdmin(); }`);
  assert.deepEqual(loud(src), []);
});

test('unvalidated-write: validation inside a helper function counts', () => {
  const src = fs(`function valid() { return request.resource.data.keys().hasOnly(['a']); }
    match /x/{id} { allow create: if request.auth != null && valid(); }`);
  assert.deepEqual(ids(src), []);
});

test('unvalidated-write: delete has nothing to validate', () => {
  assert.deepEqual(ids(fs('match /x/{id} { allow delete: if request.auth.uid == id; }')), []);
});

test('storage-unchecked-upload: size and type both needed', () => {
  const none = run(st('match /u/{f} { allow write: if request.auth != null; }'))
    .find((d) => d.id === 'storage-unchecked-upload');
  assert.match(none.message, /size or content type/);
  const sizeOnly = run(st('match /u/{f} { allow write: if request.resource.size < 1000; }'))
    .find((d) => d.id === 'storage-unchecked-upload');
  assert.match(sizeOnly.message, /content type/);
  assert.deepEqual(ids(st(`match /u/{f} { allow write: if request.auth.uid != null
    && request.resource.size < 5 * 1024 * 1024 && request.resource.contentType.matches('image/.*'); }`)), []);
});

// -------------------------------------------------------------- identity

test('email-unverified: reported once, on the function that checks it', () => {
  const src = fs(`function isAdmin() { return request.auth != null && request.auth.token.email == 'a@b.c'; }
    match /a/{id} { allow write: if isAdmin(); }
    match /b/{id} { allow write: if isAdmin(); }`);
  assert.equal(ids(src).filter((i) => i === 'email-unverified').length, 1);
});

test('email-unverified: quiet when email_verified is checked', () => {
  const src = fs(`function isAdmin() { return request.auth.token.email == 'a@b.c' && request.auth.token.email_verified == true; }
    match /a/{id} { allow write: if isAdmin() && request.resource.data.size() < 10; }`);
  assert.deepEqual(ids(src), []);
});

// --------------------------------------------------------------- limits

test('too-many-lookups: eleven get() calls in one condition', () => {
  const calls = Array.from({ length: 11 }, (_, i) => `get(/databases/$(database)/documents/c/d${i}).data.ok`).join(' && ');
  assert.ok(ids(fs(`match /x/{id} { allow read: if ${calls}; }`)).includes('too-many-lookups'));
});

test('too-many-lookups: ten is the limit, not over it', () => {
  const calls = Array.from({ length: 10 }, (_, i) => `exists(/databases/$(database)/documents/c/d${i})`).join(' && ');
  assert.ok(!ids(fs(`match /x/{id} { allow read: if ${calls}; }`)).includes('too-many-lookups'));
});

// ------------------------------------------------------------- the file

test('rules-version: missing, or set to 1', () => {
  assert.ok(ids(fs('match /x/{id} { allow read: if false; }', '')).includes('rules-version'));
  assert.ok(ids(fs('match /x/{id} { allow read: if false; }', "rules_version = '1';")).includes('rules-version'));
});

test('syntax: an unclosed block and an unclosed string', () => {
  assert.ok(ids("rules_version = '2';\nservice cloud.firestore {\n  match /x/{id} {\n").includes('syntax'));
  assert.ok(ids(fs("match /x/{id} { allow read: if resource.data.a == 'b; }")).includes('syntax'));
});

test('not a rules file at all: a udev .rules file says nothing', () => {
  assert.deepEqual(ids('SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666"\n'), []);
});

// ---------------------------------------------------------- suppression

test('rules-lint-ignore silences the next line', () => {
  const src = fs(`match /profile/{id} {
      // rules-lint-ignore
      allow write: if true;
    }`);
  assert.deepEqual(ids(src), []);
});

test('rules-lint-ignore with ids silences only those', () => {
  const src = fs(`match /{document=**} {
      // rules-lint-ignore: public-read
      allow read, write: if true;
    }`);
  assert.deepEqual(ids(src), ['open-write']);
});

test('disabled checks from settings are dropped', () => {
  assert.deepEqual(ids(fs('match /p/{id} { allow read: if true; }'), { disabled: ['public-read'] }), []);
});

// -------------------------------------------- Firebase's own examples

// Straight from the Firebase documentation's basic-rules page. None of these
// is a mistake, so none of them may produce anything above a hint.
test("Firebase's documented patterns produce nothing louder than a hint", () => {
  const docs = [
    // content-owner only access
    fs(`match /some_collection/{userId}/{documents=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }`),
    // mixed public and private access
    fs(`match /some_collection/{document} {
      allow read: if true;
      allow write: if request.auth.uid == request.resource.data.author_uid
        && request.resource.data.keys().hasOnly(['author_uid', 'text']);
    }`),
    // attribute-based access
    fs(`match /some_collection/{document} {
      allow read: if request.auth.token.role == 'admin' || resource.data.visibility == 'public';
    }`),
  ];
  for (const src of docs) {
    // The README promises nothing louder than a hint here.
    assert.deepEqual(run(src).filter((d) => d.severity !== 'hint').map((d) => d.id), [], src);
  }
});

test('ranges point at the allow statement, not the whole file', () => {
  const src = fs('match /notes/{id} { allow write: if true; }');
  const [d] = run(src);
  assert.equal(src.slice(d.start, d.end), 'allow write');
});
