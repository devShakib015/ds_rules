## 0.1.0

First release.

Thirteen checks for Firestore and Storage rules, each one a mistake that leaks
or breaks data and can be seen without running the rules: open writes, a
readable database, Firebase test mode left on (or expired), grants on every
document, any-signed-in-user edits, unvalidated writes, unchecked uploads, an
unverified email claim, too many lookups, a missing `rules_version = '2'`, and
unbalanced or unterminated syntax.

Conditions are read through the functions they call. Public reads and writes
limited to an owner or admin are hints, not problems, and Google's documented
example rules produce nothing louder than a hint — that is a test, not a hope.

Highlighting for `.rules`, `firestore.rules` and `storage.rules`, five snippets,
and `// rules-lint-ignore` for the one line you mean.
