# What Is Mutant?

Mutant is a programming language built for practical security work, forensic
automation, and cross-platform analysis tooling.

It is not just a scripting language with a few security helpers bolted on. The
language, compiler, virtual machine, runtime security layer, and example corpus
are designed together so you can write small programs that do real
investigations, produce reusable artifacts, and run under a security model that
includes encryption, signing, anti-tamper checks, anti-debugging, anti-sandbox
checks, and bytecode polymorphism.

## The short version

If you want a concise answer to “what does it do?”:

- It automates security and forensic workflows.
- It can compile `.mut` source into encrypted bytecode and standalone binaries.
- It has builtins for text, filesystem, network, registry, memory, binary
  parsing, command execution, JSON, Lua, graph modeling, detection, policy, and
  cache workflows.
- It includes runtime protections such as signature verification, anti-tamper
  checks, anti-debug checks, anti-sandbox checks, process protection, and
  polymorphic bytecode stages.
- It ships with real examples that you can study, adapt, and chain together.

## What you can do with it

Mutant is useful when you want to turn an investigation idea into a repeatable
script, a report, or a portable standalone tool.

### 1. Build security triage workflows

Use Mutant to collect signals from a host, score them, and emit a report.

Good starting examples:

- [examples/security/security_environment_report.mut](../examples/security/security_environment_report.mut)
- [examples/security/security_diagnostics_example.mut](../examples/security/security_diagnostics_example.mut)
- [examples/detection/detection_example.mut](../examples/detection/detection_example.mut)
- [examples/detection/detection_multi_signal_score.mut](../examples/detection/detection_multi_signal_score.mut)

Typical questions this answers:

- Is the runtime in a suspicious environment?
- Is a debugger attached?
- Is the system likely sandboxed?
- Do multiple weak signals add up to a stronger finding?

### 2. Automate network and IOC hunting

Mutant can fetch, parse, normalize, and correlate network observations.

Examples:

- [examples/network/network_service_recon_graph.mut](../examples/network/network_service_recon_graph.mut)
- [examples/network/network_triage_dns_tls.mut](../examples/network/network_triage_dns_tls.mut)
- [examples/network/http_recon_fetcher.mut](../examples/network/http_recon_fetcher.mut)
- [examples/network/ioc_fetcher.mut](../examples/network/ioc_fetcher.mut)
- [examples/network/pcap_offline_analysis.mut](../examples/network/pcap_offline_analysis.mut)

Typical questions this answers:

- What hosts and services are exposed?
- Which endpoints resolve from a domain or IOC list?
- What does a TLS or DNS profile look like?
- Can I turn raw network evidence into a structured graph?

### 3. Parse and triage files, disk images, and binary artifacts

Mutant has builtins and examples for filesystem, binary, disk image, and
bytes-oriented analysis.

Examples:

- [examples/filesystem/fs_example.mut](../examples/filesystem/fs_example.mut)
- [examples/filesystem/fs_forensics_example.mut](../examples/filesystem/fs_forensics_example.mut)
- [examples/filesystem/ntfs_example.mut](../examples/filesystem/ntfs_example.mut)
- [examples/filesystem/ext_example.mut](../examples/filesystem/ext_example.mut)
- [examples/filesystem/raw_example.mut](../examples/filesystem/raw_example.mut)
- [examples/filesystem/vhdi_example.mut](../examples/filesystem/vhdi_example.mut)
- [examples/binary/binary_analysis_example.mut](../examples/binary/binary_analysis_example.mut)
- [examples/binary/binary_triage_sections_entropy.mut](../examples/binary/binary_triage_sections_entropy.mut)
- [examples/bytes/bytes_cursor_sample_demo.mut](../examples/bytes/bytes_cursor_sample_demo.mut)

Typical questions this answers:

- What does this executable or disk image contain?
- What sections, strings, imports, or entropy signals stand out?
- Can I walk a filesystem image and extract structured evidence?
- Can I read bytes safely and build my own parser logic?

### 4. Work with registry, memory, and email evidence

Mutant is strong when the investigation crosses evidence types.

Examples:

- [examples/registry/registry_forensics_example.mut](../examples/registry/registry_forensics_example.mut)
- [examples/registry/registry_persistence_hunt.mut](../examples/registry/registry_persistence_hunt.mut)
- [examples/memory/memory_forensics_example.mut](../examples/memory/memory_forensics_example.mut)
- [examples/memory/memory_scan_to_detection.mut](../examples/memory/memory_scan_to_detection.mut)
- [examples/email/email_forensics_example.mut](../examples/email/email_forensics_example.mut)
- [examples/email/email_attachment_triage.mut](../examples/email/email_attachment_triage.mut)

Typical questions this answers:

- What persistence traces exist in a registry hive?
- Can I scan memory for shellcode or PE-like signals?
- What URLs or attachments are embedded in an email campaign?
- Can I correlate those findings into a single investigation flow?

### 5. Model findings as graphs and timelines

Mutant includes graph database builtins so you can preserve relationships
instead of throwing away context.

Examples:

- [examples/graph/db_example.mut](../examples/graph/db_example.mut)
- [examples/graph/db_wrappers_example.mut](../examples/graph/db_wrappers_example.mut)
- [examples/graph/mini_log_correlator.mut](../examples/graph/mini_log_correlator.mut)
- [examples/graph/mini_timeline_builder.mut](../examples/graph/mini_timeline_builder.mut)
- [examples/graph/graph_detection_timeline.mut](../examples/graph/graph_detection_timeline.mut)

Typical questions this answers:

- Which hosts, files, users, and indicators are connected?
- Can I build a timeline from scattered evidence?
- Can I persist findings for later pivoting?

### 6. Wrap policy, command execution, and Lua interop into controlled workflows

Mutant can orchestrate external behavior while still keeping the scripts
readable and focused.

Examples:

- [examples/policy/policy_engine_example.mut](../examples/policy/policy_engine_example.mut)
- [examples/policy/policy_inline_allow_deny.mut](../examples/policy/policy_inline_allow_deny.mut)
- [examples/cache/cache_example.mut](../examples/cache/cache_example.mut)
- [examples/cache/cache_ttl_workflow.mut](../examples/cache/cache_ttl_workflow.mut)
- [examples/lua/lua_run_string_example.mut](../examples/lua/lua_run_string_example.mut)
- [examples/lua/lua_run_file_example.mut](../examples/lua/lua_run_file_example.mut)
- [examples/lua/lua_run_http_example.mut](../examples/lua/lua_run_http_example.mut)

Typical questions this answers:

- Can I gate actions through a policy decision?
- Can I cache intermediate results or shared state?
- Can I call into Lua where that is the right tool?

## Why Mutant exists

Most languages can script a task. Mutant is aimed at a narrower, more
operational question:

How do you make small programs that are useful for security work, easy to ship,
and harder to inspect or tamper with?

That is why the language focuses on:

- compact syntax,
- rich builtins for evidence handling,
- encrypted bytecode,
- signed artifacts,
- runtime protection,
- polymorphic compilation stages,
- and examples that reflect real analysis workflows.

## The security model

Mutant’s security features are part of the story, not an afterthought.

### Source to bytecode to signed artifact

The compile pipeline starts in
[generator/generate.go](../generator/generate.go):

- parse source code,
- expand macros,
- compile to bytecode,
- optionally apply polymorphic mutation,
- encrypt the bytecode,
- and sign the result.

The encryption layer lives in [security/crypto.go](../security/crypto.go):

- password-based AES-GCM encryption,
- deterministic options where appropriate,
- secure metadata handling,
- and explicit zeroization helpers.

### Runtime verification and tamper resistance

The runner in [runner/runner.go](../runner/runner.go) verifies and protects
execution before the VM starts.

That includes:

- signature verification,
- secure mode / compatibility mode handling,
- anti-tamper response plumbing,
- anti-debug checks,
- anti-sandbox checks,
- process protection probes,
- and remote process scan hooks.

The detection helpers are implemented in the [security/](../security/) package,
including:

- [security/antidebug.go](../security/antidebug.go)
- [security/sandbox.go](../security/sandbox.go)
- [security/antitamper_probe.go](../security/antitamper_probe.go)

### Polymorphic bytecode

The compiler has a polymorphic engine in
[compiler/polymorphic.go](../compiler/polymorphic.go).

That engine can mutate bytecode in controlled ways so the output is not a simple
static signature.

This is useful for:

- reducing obvious bytecode fingerprints,
- experimenting with safe bytecode transformations,
- and shipping artifacts that are harder to trivially compare.

## Practical use cases

Here is the “why would I use this?” answer in plain language.

### For security analysts

Use Mutant to turn ad hoc triage into repeatable scripts.

Examples:

- collect environment signals and score risk,
- enumerate suspicious processes,
- parse registry hives,
- inspect memory images,
- normalize URLs and attachments,
- and store everything into a graph or report.

### For incident responders

Use it to build one-off response utilities that are still easy to maintain.

Examples:

- a script that collects and packages host evidence,
- a parser for an unfamiliar artifact format,
- a timeline builder for a cluster of host events,
- a reusable triage command sequence.

### For reverse engineers

Use Mutant when you need byte-oriented helpers, pattern extraction, and
structured output.

Examples:

- decode fields from binary formats,
- walk sections and imports,
- inspect bytes without dropping into a different language,
- and build tiny parsers around a real artifact.

### For engineers building security tools

Use Mutant as a compact language for shipping focused tools.

Examples:

- packaging a security workflow into a standalone executable,
- reusing builtins instead of rebuilding plumbing every time,
- keeping scripts cross-platform,
- and using runtime security features to protect the artifact.

## Macro support

Macros are part of the language for advanced metaprogramming.

The macro examples in [examples/macros/](../examples/macros/) show practical
patterns:

- [examples/macros/macro_quote_unquote_basics.mut](../examples/macros/macro_quote_unquote_basics.mut)
- [examples/macros/macro_rewrite_unless.mut](../examples/macros/macro_rewrite_unless.mut)
- [examples/macros/macro_mini_dsl_rules.mut](../examples/macros/macro_mini_dsl_rules.mut)

Use macros when you want to:

- reduce repetition in domain-specific workflows,
- rewrite syntax into reusable AST shapes,
- and build small embedded DSLs for repetitive operations.

## If you want the shortest mental model

Think of Mutant as:

> a secure, cross-platform scripting language for evidence collection, analysis,
> and tooling, with built-in support for encrypted/signed artifacts and
> practical security workflows.

## Where to start

If you are new to the language, this is the best path:

1. Read [README.md](../README.md) for the quick overview.
2. Try
   [examples/security/security_environment_report.mut](../examples/security/security_environment_report.mut).
3. Try
   [examples/network/network_service_recon_graph.mut](../examples/network/network_service_recon_graph.mut).
4. Try
   [examples/registry/registry_forensics_example.mut](../examples/registry/registry_forensics_example.mut).
5. Try
   [examples/macros/macro_quote_unquote_basics.mut](../examples/macros/macro_quote_unquote_basics.mut).
6. Explore [examples/](../examples/) by folder once the basic patterns make
   sense.
