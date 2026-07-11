# Mutant Examples

This folder is organized by feature area so examples are easy to discover.

## How to run

Run from repository root:

```powershell
mutant examples/text/text_matching_example.mut
```

Some examples use fixture files in:

- `examples/data/`
- `examples/memory_dump.bin`
- `examples/offline_hive.json`

## Folder map

- `examples/basics/` language syntax and control flow
- `examples/text/` text, fuzzy matching, regex pipelines
- `examples/policy/` OPA/Rego policy loading and decisions
- `examples/cache/` cache open/put/get/ttl/stats workflows
- `examples/filesystem/` fs I/O and filesystem forensics
- `examples/network/` http/net and network-forensics style flows
- `examples/binary/` binary/PE parsing and entropy-driven triage
- `examples/registry/` offline registry forensic examples
- `examples/email/` email parsing and phishing triage
- `examples/memory/` memory scanning and shellcode/PE hunting
- `examples/graph/` graph modeling and timeline-style investigation
- `examples/detection/` detection builtins and multi-signal scoring
- `examples/security/` environment diagnostics and anti-analysis status
- `examples/lua/` Lua interop examples and helper scripts
- `examples/bytes/` byte cursor and binary-safe parsing helpers

## Suggested learning path

1. Start with `examples/basics/`
2. Move to `examples/text/` and `examples/cache/`
3. Explore `examples/policy/` for policy gates
4. Use forensic folders (`memory`, `registry`, `email`, `network`, `binary`)
5. Finish with `examples/graph/` and `examples/detection/` for correlation
