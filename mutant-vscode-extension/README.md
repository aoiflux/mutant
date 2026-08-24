# Mutant Language Tools

VS Code language support for Mutant.

## Features

- A dedicated Mutant language server (`mlsp`) over stdio (gopls-style), with
  prebuilt binaries bundled for Windows, Linux, and macOS.
- **Diagnostics**: missing/redundant semicolons, unused / undefined / duplicate
  declarations, deep-nesting hints, unreachable code, and **OS-aware
  platform-support warnings** — flags a builtin that isn't supported on the
  operating system the server is running on. Each rule's severity is
  configurable, and several carry quick fixes.
- **Canonical formatting** (format-on-save by default): four-space indentation
  and strict semicolons, emitted from the AST so the same source always formats
  to the same bytes.
- **Hover & completion** showing each builtin's signature, summary, capability
  category, and any platform constraint.
- **Semantic highlighting**, go-to-definition, references, rename, document and
  workspace symbols, and signature help.
- Syntax highlighting via a TextMate grammar.

## Configuration

- `mutant.languageServer.path`: executable/command path for Mutant LSP (default:
  empty string; auto-detect packaged binary first, then workspace)
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
- `mutant.lint.rules.semicolon.severity`: severity for missing/redundant
  semicolon diagnostics (each with a quick fix)
- `mutant.lint.rules.unreachableCode.severity`: severity for unreachable-code
  diagnostics (statements after an unconditional `return`/`break`/`continue`)
- `mutant.lint.rules.platformSupport.severity`: severity for OS-aware
  platform-support warnings (a builtin unsupported on the host OS)
- `mutant.lint.rules.builtinArity.severity`: severity for wrong-argument-count
  calls to fixed-arity builtins
- `mutant.lint.rules.builtinArgType.severity`: severity for arguments of a type
  a builtin parameter cannot accept
- `mutant.lint.rules.builtinSingleReturn.severity`: severity for binding several
  names from a builtin that returns one value
- `mutant.lint.rules.builtinPairReturn.severity`: severity for binding one name
  from a builtin that returns a `(value, err)` pair, which leaves the name
  holding the pair rather than the value
- `mutant.lint.rules.spawnGlobalWrite.severity`: severity for a `spawn`/`pmap`/
  `peach` callback writing a global, which lands in that worker's copy and is
  lost when the callback finishes
- `mutant.strictFormatting`: master on/off switch for canonical formatting
  (`true` by default)
- `mutant.format.onType.enabled`: opt-in on-type formatting while typing
  (`false` by default)

By default, Mutant files use `editor.formatOnSave: true` via extension
configuration defaults, so canonical style is enforced when saving. By default,
`editor.formatOnType` remains disabled for Mutant files; enable
`mutant.format.onType.enabled` if you want live formatting while typing.

When `mutant.languageServer.path` is empty, the extension first tries packaged
platform binaries in `bin/`:

- `mlsp-windows-amd64.exe`
- `mlsp-windows-arm64.exe`
- `mlsp-linux-amd64`
- `mlsp-linux-arm64`
- `mlsp-darwin-amd64`
- `mlsp-darwin-arm64`

If no packaged binary matches the current platform/arch, it then checks common
local paths such as `mlsp(.exe)` in the workspace and parent folder before
falling back to command lookup from PATH.

Setting a lint rule severity to `off` suppresses that rule.

## Local Development

1. `npm install`
2. `npm run compile`
3. Build the language server binary when needed:

```powershell
../lsp/build.ps1 -HostOnly
```

```bash
../lsp/build.sh --host-only
```

This produces `mlsp` artifacts in `lsp/dist/` for local extension use.

4. Press `F5` in VS Code to launch the extension development host.

For publishing with bundled binaries:

1. Build all LSP targets:

```powershell
../lsp/build.ps1
```

```bash
../lsp/build.sh
```

2. Stage binaries into extension `bin/`:

```bash
npm run prepare:lsp-bins
```

3. Package/publish the extension. `vscode:prepublish` already runs
   `prepare:lsp-bins` automatically.

Debug configuration is included in `.vscode/launch.json` and build tasks are in
`.vscode/tasks.json`.

If your LSP binary is not on PATH, set `mutant.languageServer.path` to an
absolute path.

## Troubleshooting

For a deeper walkthrough of the language server and extension (PATH setup,
settings, logs, restart flow), see
[../docs/LSP_EXTENSION_ONBOARDING_60_MIN.md](../docs/LSP_EXTENSION_ONBOARDING_60_MIN.md)
and [../docs/LSP_EXTENSION_LLD.md](../docs/LSP_EXTENSION_LLD.md).

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

## License

This extension is licensed under GNU AGPL v3.0 only.

See [LICENSE](LICENSE).
