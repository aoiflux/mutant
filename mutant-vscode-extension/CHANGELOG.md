# Changelog

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
