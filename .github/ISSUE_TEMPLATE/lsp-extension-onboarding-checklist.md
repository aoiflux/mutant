---
name: LSP/Extension Onboarding Checklist
about: Track a new engineer's first-week onboarding progress for Mutant language tooling.
title: "onboarding: <engineer-name> - lsp/extension"
labels: ["onboarding", "lsp", "extension"]
assignees: []
---

## Engineer Info

- Name:
- Start date:
- Mentor:
- Target completion date:

## Read Before Starting

- [ ] Read
      [docs/LSP_EXTENSION_ONBOARDING_60_MIN.md](../docs/LSP_EXTENSION_ONBOARDING_60_MIN.md)
- [ ] Read [docs/LSP_EXTENSION_LLD.md](../docs/LSP_EXTENSION_LLD.md)
- [ ] Read
      [docs/VSCODE_LSP_TEACHING_REFERENCE.md](../docs/VSCODE_LSP_TEACHING_REFERENCE.md)
- [ ] Read
      [docs/VSCODE_EXTENSION_TROUBLESHOOTING.md](../docs/VSCODE_EXTENSION_TROUBLESHOOTING.md)

## Environment Setup

- [ ] `go test ./lsp/internal/analyzer -v` passes
- [ ] `go test ./lsp/internal/server -v` passes
- [ ] `go test ./...` passes
- [ ] `cd vscode-extension && npm install && npm run compile && npm test` passes
- [ ] Extension Development Host launches via `F5`

## Operational Familiarity

- [ ] Run `Mutant: Show LSP Status`
- [ ] Run `Mutant: Show LSP Logs`
- [ ] Run `Mutant: Copy LSP Logs`
- [ ] Run `Mutant: Restart LSP`
- [ ] Run `Mutant: Run LSP Smoke Checks`

## Request-Flow Understanding

- [ ] Trace completion path in code:
  - [ ] [vscode-extension/src/extension.ts](../vscode-extension/src/extension.ts)
  - [ ] [lsp/internal/server/server.go](../lsp/internal/server/server.go)
  - [ ] [lsp/internal/analyzer/analyzer.go](../lsp/internal/analyzer/analyzer.go)
- [ ] Explain how deterministic completion order is enforced
- [ ] Explain when workspace symbol index is used as fallback

## First Contribution (Pick One)

- [ ] Add/update a snippet in
      [lsp/internal/analyzer/language_teach.go](../lsp/internal/analyzer/language_teach.go)
- [ ] Add a builtin + teaching update in
      [builtin/builtin.go](../builtin/builtin.go)
- [ ] Add or tune a lint rule in
      [lsp/internal/analyzer/diagnostics.go](../lsp/internal/analyzer/diagnostics.go)

## Contribution Quality Gates

- [ ] Added/updated tests for changed behavior
- [ ] No regression in `go test ./...`
- [ ] Docs updated when developer-facing behavior changed
- [ ] PR description includes request flow touched and risk assessment

## Mentor Sign-Off

- [ ] Engineer can explain extension startup + binary selection behavior
- [ ] Engineer can debug LSP issues using status/log/restart flow
- [ ] Engineer can add a small language feature with tests
- [ ] Engineer can safely modify docs and link references

## Notes:
