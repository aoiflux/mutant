# Mutant Language Tools

VS Code language support for Mutant.

## Included in this MVP

- Language Server integration over stdio
- Diagnostics from the Mutant LSP server
- Hover, completion, go to definition, references, and rename
- Starter syntax highlighting via TextMate grammar

## Configuration

- `mutant.languageServer.path`: executable/command path for Mutant LSP (default:
  empty string; auto-detect in workspace)
- `mutant.languageServer.args`: additional CLI args for the server
- `mutant.lint.rules.duplicateTopLevelDeclaration.severity`: severity for the
  duplicate declaration lint rule (`error`, `warning`, `information`, `hint`,
  `off`)
- `mutant.lint.rules.unusedDeclaration.severity`: severity for the unused
  declaration lint rule (`error`, `warning`, `information`, `hint`, `off`)
- `mutant.lint.rules.undefinedDeclaration.severity`: severity for the undefined
  identifier lint rule (`error`, `warning`, `information`, `hint`, `off`)
- `mutant.lint.rules.nestingComplexity.severity`: severity for deep nesting
  diagnostics in function bodies (`error`, `warning`, `information`, `hint`,
  `off`)
- `mutant.format.onType.enabled`: opt-in on-type formatting while typing
  (`false` by default)

By default, Mutant files use `editor.formatOnSave: true` via extension
configuration defaults, so canonical style is enforced when saving. By default,
`editor.formatOnType` remains disabled for Mutant files; enable
`mutant.format.onType.enabled` if you want live formatting while typing.

When `mutant.languageServer.path` is empty, the extension checks common local
paths such as `mlsp(.exe)` in the workspace and parent folder before falling
back to command lookup from PATH.

Setting a lint rule severity to `off` suppresses that rule.

## Local Development

1. `npm install`
2. `npm run compile`
3. Build the language server binary when needed:

```powershell
../lsp/build.ps1 -HostOnly
```

```bash
./lsp/build.sh --host-only
```

This produces `mlsp` artifacts in `lsp/dist/` for local extension use. 4. Press
`F5` in VS Code to launch the extension development host

Debug configuration is included in `.vscode/launch.json` and build tasks are in
`.vscode/tasks.json`.

If your LSP binary is not on PATH, set `mutant.languageServer.path` to an
absolute path.

## Troubleshooting

For full troubleshooting coverage (PATH setup, settings validation, logs,
restart flow), see `../docs/VSCODE_EXTENSION_TROUBLESHOOTING.md`.

Quick commands:

- `Mutant: Show LSP Status`
- `Mutant: Show LSP Logs`
- `Mutant: Copy LSP Logs`
- `Mutant: Restart LSP`

Key settings:

- `mutant.languageServer.path`
- `mutant.languageServer.args`

## Smoke Test Workflow

1. Run the VS Code task `smoke: lsp features`.
2. Press `F5` to start the extension development host.
3. Run command `Mutant: Open Smoke File`.
4. Run command `Mutant: Run LSP Smoke Checks`.
5. Run command `Mutant: Show LSP Status` to verify server state.
6. Run command `Mutant: Show LSP Logs` to inspect Mutant-only server logs.
7. Run command `Mutant: Copy LSP Logs` to copy recent logs for bug reports.
8. If needed, run `Mutant: Restart LSP` to recover from startup failures.
9. Verify:

- Linting: warning on duplicate top-level `answer` declaration.
- Semantic colors: keywords, numbers, strings, enum/type identifiers receive
  semantic highlighting.
- Formatting: run `Format Document` and confirm trailing spaces are removed and
  a single final newline remains.
