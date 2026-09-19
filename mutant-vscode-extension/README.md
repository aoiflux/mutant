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
  workspace symbols, and signature help. Rename reaches files you have not
  opened.
- **Call hierarchy** (Shift+Alt+H, or "Peek Call Hierarchy"): who calls a
  function and what it calls, across files. A call into another module --
  `stats.mean(...)` -- is followed to the module that declares it, and a caller
  in a file nobody has opened still appears.
- **Debugging** (press F5 on a `.mut`): breakpoints with hit counts, step
  over/into/out, the call stack, and Arguments / Locals / Globals with arrays,
  hashes and structs expandable. The CLI is the debug adapter -- the extension
  runs `mutant debug` and speaks the Debug Adapter Protocol to it. Conditional
  breakpoints and watch expressions beyond a plain variable name are
  deliberately not supported; see `docs/DEBUGGING.md` for why.
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
- `mutant.lint.rules.unusedImport.severity`: severity for an import whose
  namespace is never read (`error`, `warning`, `information`, `hint`, `off`;
  `information` by default, because an imported module's top-level statements
  run whether or not its namespace is used)
- `mutant.lint.rules.undefinedDeclaration.severity`: severity for the undefined
  identifier lint rule (`error`, `warning`, `information`, `hint`, `off`)
- `mutant.lint.rules.nestingComplexity.severity`: severity for deep nesting
  diagnostics in function bodies (`error`, `warning`, `information`, `hint`,
  `off`)
- `mutant.lint.rules.semicolon.severity`: severity for missing/redundant
  semicolon diagnostics (each with a quick fix)
- `mutant.lint.rules.unreachableCode.severity`: severity for unreachable-code
  diagnostics (statements after an unconditional `return`/`break`/`continue`, and
  a `match` arm written after `_`)
- `mutant.lint.rules.platformSupport.severity`: severity for OS-aware
  platform-support warnings (a builtin unsupported on the host OS)
- `mutant.lint.rules.builtinArity.severity`: severity for wrong-argument-count
  calls to fixed-arity builtins
- `mutant.lint.rules.builtinArgType.severity`: severity for arguments of a type
  a builtin parameter cannot accept
- `mutant.lint.rules.builtinSingleReturn.severity`: severity for binding several
  names from a builtin that returns one value
- `mutant.lint.rules.builtinDeprecated.severity`: severity for calling a builtin
  that is kept only for compatibility; names its replacement. Defaults to `hint`,
  because the call still works.
- `mutant.lint.rules.builtinPairReturn.severity`: severity for binding one name
  from a builtin that returns a `(value, err)` pair, which leaves the name
  holding the pair rather than the value
- `mutant.lint.rules.spawnGlobalWrite.severity`: severity for a `spawn`/`pmap`/
  `peach` callback writing a global, which lands in that worker's copy and is
  lost when the callback finishes
- `mutant.lint.rules.unclosedResource.severity`: severity for opening a handle
  (`ntfs_open`, `zip_open`, `chan_new`, `net_connect`, ...) that nothing in the
  same scope closes. Quiet whenever the handle escapes the scope, the closer is
  named in it, or the resource is deliberately held for the program's life
- `mutant.lint.rules.uncheckedError.severity`: severity for binding the error
  half of a `(value, err)` builtin and never reading it before the name is
  rebound or the scope ends. Quiet when the error is read in any way, when the
  failure is caught through the value instead, or when `_` is bound to say the
  failure is deliberately ignored
- `mutant.lint.rules.matchExhaustiveness.severity`: severity for a `match` whose
  arms are variants of one enum declared in the same file, with no `_` arm and a
  variant left out. An unmatched subject raises at run time rather than yielding
  null, so a variant added to an enum leaves every existing match over it one arm
  short. Quiet unless it is certain: a literal pattern, two different enums, an
  imported enum, a `_` arm, or a name that is both an enum and a binding all
  suppress it
- `mutant.lint.rules.assignmentTarget.severity`: severity for an assignment
  target the compiler refuses -- one with no variable under it (`[1, 2][0] = 9`),
  or an index before the last one that is not a name or a literal and would
  therefore be evaluated more than once. Both are build failures, so this reports
  them where they are written. Defaults to `error`, matching the build

The security family. These report a program that compiles and runs, which is
what makes them worth having: nothing else in the toolchain objects.

- `mutant.lint.rules.tlsVerificationDisabled.severity`: severity for turning off
  certificate verification, or accepting a TLS version that is no longer safe
- `mutant.lint.rules.weakCrypto.severity`: severity for reaching for a broken or
  obsolete algorithm where a current one takes the same call
- `mutant.lint.rules.hardcodedSecret.severity`: severity for a credential written
  into the source, where it outlives the program and travels with the file
- `mutant.lint.rules.commandInjection.severity`: severity for building a shell
  command out of a value the program did not choose
- `mutant.lint.rules.pathTraversal.severity`: severity for building a filesystem
  path out of a value the program did not choose
- `mutant.lint.rules.unboundedResource.severity`: severity for reading something
  whose size the program does not control into memory with no ceiling on it
- `mutant.lint.rules.evidenceMutation.severity`: severity for writing to evidence
  a case opened read-only -- the one rule here about the report rather than the
  machine, because an altered artifact is an artifact that proves nothing

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
