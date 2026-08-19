# Changelog

## 0.0.6

New this release:

- **Compound assignment and increment/decrement** (`+= -= *= /= %=`, postfix `++` /
  `--`) are now lexed, parsed, formatted, and syntax-highlighted. The formatter
  preserves the compact spelling (`i += 1`, `i++`) instead of expanding it, and
  the bundled language server understands the operators everywhere.

## 0.0.5

New this release:

- **OS-aware platform-support diagnostic** — warns when a program calls a builtin
  that is not supported on the operating system the language server is running on
  (for example a Windows/Linux-only builtin used on macOS). Configurable via
  `mutant.lint.rules.platformSupport.severity`.
- **Unreachable-code diagnostic** — flags statements after an unconditional
  `return` / `break` / `continue`. Configurable via
  `mutant.lint.rules.unreachableCode.severity`.
- **Hover and completion** now show each builtin's capability category (e.g.
  `filesystem`, `network`, `graph database`) and any platform constraint.
- **Semantic highlighting** recognizes the `&&`, `||`, `<=`, and `>=` operators.
- The discard identifier `_` is no longer flagged as a duplicate declaration.
- Bundled `mlsp` language-server binaries rebuilt for all six targets
  (Windows / Linux / macOS × amd64 / arm64).

Existing capabilities: canonical strict-semicolon formatting (format-on-save by
default), diagnostics (unused / undefined / duplicate declarations, deep nesting,
and missing/redundant semicolons with quick fixes), hover, completion, semantic
tokens, go-to-definition, references, rename, and document/workspace symbols.
