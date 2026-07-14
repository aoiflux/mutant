# Mutant v2.2.0 Release Notes

Release date: 2026-07-14

## Release Overview

v2.2.0 is a major iteration focused on broad platform maturity: stronger runtime
behavior, wider builtin/forensics coverage, improved REPL + WASM experience, and
deeper security and tooling support.

This release includes a large integration set from the development branch:

- 44 non-merge commits
- 325 changed files
- 55,404 insertions and 5,951 deletions

## Highlights

### REPL and WASM Experience

- Added interactive REPL tab completion with context-aware ranking.
- Added shared REPL help surfaces across terminal, WASM, and web flows.
- Expanded WASM REPL support and related build/serve integration.

### Language and Execution Pipeline

- Added support for if/else ladder handling.
- Continued parser/evaluator/compiler/VM alignment work.
- Multi-value behavior refactor and follow-up fixes.
- Macro-related fixes and expanded macro examples.
- Bytecode/compression and polymorphic generation updates.

### Builtins and Operational Coverage

- Broad updates across builtin modules, including: binary analysis, bytes,
  cache, command execution, database wrappers, detection, disk/filesystem
  parsers, email/network/registry/memory forensics, JSON/Lua/text/regex helpers,
  policy engine, and security status utilities.
- Extensive builtin test updates to improve regression coverage and confidence.

### Security and Anti-Tamper

- Sandbox detection updates.
- Expanded anti-tamper and process-scan implementation and tests.
- Cross-platform security path updates for Windows/Linux/macOS components.
- Security docs refresh with LLD, runbook, migration, and traceability updates.

### LSP and VS Code Extension

- LSP analyzer/server/workspace improvements (diagnostics, resolver,
  highlighting, signature help, symbol index, server transport/formatting).
- LSP build script updates for packaging and distribution.
- VS Code extension updates across packaging scripts, syntax assets, linting,
  smoke tests, and activation/test harnesses.

### Docs and Examples

- Significant docs expansion in implementation/security/deep-dive references.
- Large example suite expansion and refresh across automation, binary,
  filesystem, graph, lua, macros, memory, network, policy, registry, security,
  and text workflows.

## Impact by Area (File Touch Count)

- examples: 102
- builtin: 60
- security: 35
- docs: 24
- lsp: 23
- mutant-vscode-extension: 16

## Potentially Notable Behavioral Changes

- REPL behavior now includes ranked tab completion.
- if/else ladder parsing/compilation behavior is now supported.
- Multi-value and related builtin semantics received refactoring and fixes.
- Security detection and anti-tamper flows have updated behavior paths.

## Upgrade Notes

1. Pull latest main and rebuild binaries.
2. Re-run your script suite, especially builtin-heavy and security-sensitive
   workloads.
3. If you use editor tooling, update/reload the Mutant VS Code extension and
   validate language features in your workspace.
4. If you use WASM/web REPL, re-verify deploy/runtime assumptions.

## Suggested Post-Upgrade Verification

- Run full Go test suite in your target OS environment.
- Smoke test parser/compiler/VM with representative scripts.
- Validate core builtin workflows you rely on in production.
- Validate REPL, WASM REPL, LSP startup, and extension activation.

## Breaking Changes

No explicit release-blocking breaking change is declared for v2.2.0.

Given the scale of this release, treat it as a high-change upgrade and validate
critical automation paths before broad rollout.

## Known Issues

No release-blocking known issues are documented at publication time.

## Full Diff

For exact file-level changes, compare:

- main...dev (pre-merge scope)
- previous release tag...v2.2.0 (post-tag release view)
