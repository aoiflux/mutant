# Changelog

## Unreleased

- **Names resolve across modules the way the compiler resolves them.** The
  language server now asks the same symbol graph the compiler builds, so
  `stats.mean` has go-to-definition, hover, completion, find-references and
  rename in every file that imports it, under whatever alias each file chose,
  and call hierarchy finds callers in files nobody has opened. Answers are
  scoped to the import closure, so go-to-definition no longer jumps into a
  module nothing imported.
- **A new diagnostic: `unusedImport`**, at information severity rather than
  warning, because an imported module's top-level statements run whether or not
  its namespace is read. `mutant.lint.rules.unusedImport.severity` sets it.
- **A new diagnostic: `classifiedPlaintext`.** Plaintext read out of a
  classified record with `record_read` refuses to go to `putln`, `fs_write`,
  `http_post` and ten other builtins when the program runs; the editor now says
  so at the line, before the program runs and asks for a passphrase.
  `record_release(buffer, reason)` is the way to comply, and its result is never
  reported. The rule reads the runtime's own lists, so it cannot warn about a
  builtin that does not refuse. `mutant.lint.rules.classifiedPlaintext.severity`
  sets it.
- **Every new builtin is highlighted and hoverable** -- 161 of them, across disk
  image verification, partition-offset opening, deleted-file recovery, journals,
  slack, the forensic ledger, classified records and disclosure -- with no change
  here, because the grammar and the hover cards are both generated from the
  registry.

## 0.2.0

New this release:

- **Debugging** — a `mutant` debug type. Press F5 on a `.mut` file with no
  `launch.json` and the extension debugs the file in front of you; a saved
  configuration takes `program`, `stopOnEntry`, `modulePaths` and `noDebug`.
  The adapter is the CLI itself (`mutant debug`), found through the existing
  `mutant.cli.path` setting, so the binary that runs a program is the binary
  that debugs it.
- **Every builtin is highlighted.** The grammar's list of builtin names was
  maintained by hand and had fallen to 76 of the language's 497 — the reporting,
  chain-of-custody and schema-interchange families were all invisible, and so
  were most of `net_*` and `str_*`. The list is now generated from the builtin
  registry by `cmd/gendocs`, with a test in the repo that fails if the two ever
  disagree, so a builtin is highlighted as soon as it exists.
- **The bundled language server says what it is.** `mlsp --version` prints the
  release it was built from and the number of builtins it knows
  (`mlsp 2.5.0 (497 builtins)`), so "which version of the language does my
  editor actually understand?" is a question with an answer. The packaging
  scripts ask it too: a VSIX can no longer be built around a server older than
  the language in the tree it was cut from.
- **Sigma rules are highlighted and hoverable.** The language gained four
  `sigma_*` builtins that parse and evaluate Sigma detection rules, and the
  generated grammar and the server's hover cards picked them up with no change
  here — which is the point of generating both from the registry.
- **A new diagnostic: `assignmentTarget`.** The compiler used to accept
  `counts[host]["n"] = 1` and quietly lose the write; it now emits the write-back
  chain that makes it work, and refuses by name the two targets it still cannot
  emit — one with no variable under it, and an index before the last one that
  would be evaluated more than once. The editor reports both where they are
  written rather than at the next build, and a test runs the analyzer and the
  compiler over the same programs, so the two answers cannot drift apart.
- **The settings documentation caught up with the settings.** This README listed
  16 of the 24 lint rules; the eight it omitted were the whole security family —
  weak crypto, hardcoded secrets, command injection, path traversal, TLS
  verification, unbounded resources and evidence mutation. Those are the rules
  most worth knowing about and the least likely to be found by scrolling a
  settings pane. A test now fails when a rule exists that the README does not
  mention.

## 0.1.0

New this release:

- **Snippets** — `fn`, `let`, `letr` (multi-value bind), `guard`, `if`/`ife`,
  `for`, `struct`/`structlit`, `enum`, `macro`, and `putln`/`putf`.
- **Richer editor configuration** — folding via `// region` / `// endregion`
  markers, indentation rules, comment-continuation on Enter, and a Mutant-aware
  word pattern.
- **Grammar** — macro declarations (`let NAME = macro(...)`) and capitalized
  type-usage sites (`Point { … }`, `Color.Green`) are now scoped.
- **Mutant tasks** — a task provider wrapping the real CLI: `gen` (compile a
  `.mut` to `.mu`), run a compiled `.mu`, and `release` (standalone build). The
  CLI is resolved from the new `mutant.cli.path` setting (default `mutant`).
- **Language server upgrades** (bundled `mlsp`): member/dot completion
  (`x.field`, `Enum.Variant`), folding ranges, parameter-name inlay hints,
  semantic-token range + delta requests, richer code-action/rename capabilities,
  and workspace-wide indexing so go-to-definition, references, and rename work
  across files you have not opened.
- **Type-aware editor smarts** — the language server now infers best-effort types
  (from literals, `let` bindings, struct/enum, and a curated builtin table) and
  surfaces them in hover (`count : int`), completion detail, and inlay type hints
  on `let` bindings. Purely informational — no annotations, no type errors, no
  runtime effect; anything uncertain simply shows nothing.
- **Reference codeLens** — a clickable "N references" lens above every top-level
  declaration (opens the references peek).
- **Document links** — string literals that name an existing file (e.g.
  `fs_read("evidence/$MFT")`) become ctrl-clickable links that open the file.
- **Status bar indicator** — shows Mutant LSP state (running / starting / failed /
  stopped); click to restart.
- **Menus + keybindings** — "Mutant: Format Document" in the editor context menu
  for `.mut` files, and `Ctrl+Alt+R` (`Cmd+Alt+R` on macOS) to restart the LSP.
- **Packaging** — the extension now bundles with esbuild and publishes
  per-platform `.vsix` packages (each carrying only its own `mlsp` binary),
  replacing the single ~250 MB all-platforms package.

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
