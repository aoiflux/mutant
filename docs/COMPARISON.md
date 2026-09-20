# Why Mutant, and when not to

Every practitioner who finds this project already has a way of doing the work.
This page is the honest comparison against the four most likely ones, including
the cases where the answer is "keep what you have".

If you want the short version: **Mutant compiles an investigation into one
signed, encrypted, dependency-free binary that runs the same way on any host.**
Nothing else in this list does that. Everything else in this list does something
Mutant does not.

## What Mutant actually is

A programming language and toolchain for security and forensic work. 528
builtins across 38 categories — filesystem and disk-image parsers, registry and
Windows artifacts, binary analysis, memory, network, email, crypto, timelines
— in a language with functions, closures, structs, enums, macros and
concurrency. Pure Go, no cgo, cross-compiles to `darwin`, `linux` and `windows`
on `amd64`/`arm64` (and 32-bit variants) from any of them.

Source is `.mut`. `mutant program.mut` compiles it to an encrypted `.mu`
artifact; `mutant program.mu` runs it; `mutant release` turns it into a
standalone executable with no runtime to install. The compiled artifact is
signed, and its bytecode is polymorphically mutated per build, so two builds of
the same source are not byte-identical.

## The one-line comparison

| | Mutant | Python + plaso | Velociraptor | osquery | YARA + Sigma |
|---|---|---|---|---|---|
| **Shape** | compiled language | library + CLI toolchain | client/server platform | agent + SQL | rule languages |
| **You write** | programs | programs + config | VQL queries and artifacts | SQL | declarative rules |
| **Deploys as** | one static binary | a Python environment | server + endpoint agents | an agent/daemon | rules + an engine to run them |
| **Runs across a fleet** | no | no (per host) | **yes, this is the point** | yes, with a manager | via whatever runs them |
| **Live host state** | some | no | yes | **yes, this is the point** | no |
| **Parses captured artifacts** | yes, broadly | **yes, very broadly** | yes | no | file/memory content only |
| **Artifact integrity** | signed + encrypted bytecode | none | signed artifacts | none | signed rules (external) |
| **Ecosystem** | small, one maintainer | large, mature | large, active | large, mature | **very large** |

---

## vs. Python + plaso

**Where plaso wins, decisively: parser coverage.** log2timeline has been
absorbing artifact formats for over a decade, and the breadth is not close.
If your question is "timeline everything on this image", plaso parses formats
Mutant has never heard of, and the honest recommendation is to use it.

**Where Mutant wins: the thing you hand to someone else.** A plaso analysis is
a Python program plus the environment it needs — an interpreter version, a
dependency set, a virtualenv that resolves today and may not next quarter.
Getting that onto an isolated host, a customer's estate, or an incident
responder's laptop is its own project. `mutant release` produces one file with
nothing under it. Cross-compile a Windows binary from Linux and hand it over.

**Where Mutant wins: one language for the whole job.** In a plaso workflow you
parse with one tool, filter and sort with another, and write the analysis in
Python around both. In Mutant the parse, the correlation, the detection logic
and the report are the same program in the same language — which matters most
when the analysis is bespoke, which bespoke analysis usually is.

**They interoperate.** `bodyfile_parse` reads a Sleuth Kit bodyfile and
`mactime` builds the MACB timeline from it, so a Mutant program can start from
output the rest of the ecosystem already produces, and `timeline_merge`
composes it with anything else you have normalised to epoch seconds.

**Choose plaso** for maximum artifact coverage on a full-disk supertimeline.
**Choose Mutant** when the analysis is custom, or when getting the tool onto
the host is the hard part.

## vs. Velociraptor

**Different category, and the wrong comparison to lose sight of.**
Velociraptor is an endpoint DFIR *platform*: a server, agents on the endpoints,
scheduled and interactive collection, hunts across thousands of machines,
results collected centrally. Mutant is none of that. There is no server, no
agent, no enrolment, no fleet, no scheduler, no console.

**If the question is "run this across 5,000 endpoints and collect the
results", the answer is Velociraptor, and Mutant does not compete.**

**Where Mutant is different: what the analysis is written in.** VQL is a
query language shaped for the platform's collection model. Mutant is a general
programming language — closures, recursion, structs, enums, macros, its own
concurrency — so an analysis with real control flow is written directly rather
than assembled from artifacts and plugins.

**Where Mutant is different: what the artifact is.** A Velociraptor artifact is
YAML the server distributes to agents. A Mutant artifact is a signed, encrypted,
mutated binary that runs by itself with the platform absent. Those solve
different problems: one is fleet reach, the other is a self-contained,
tamper-evident tool you can hand to a third party who runs no agents.

**They compose.** Nothing stops a Velociraptor artifact from executing a Mutant
binary and collecting its stdout — recipe 14 in the
[cookbook](COOKBOOK.md) emits JSON lines for exactly that reason.

## vs. osquery

**Also a different category.** osquery exposes live operating-system state as
SQL tables — processes, sockets, users, packages, kernel extensions — either
interactively or as a daemon streaming results to a manager. It is very good at
that and Mutant does not try to replace it.

**The dividing line is live state versus captured artifacts.** osquery answers
"what is true on this machine right now" and is designed to keep answering it
on a schedule. Mutant's live-host surface is deliberately narrower
(`process_*`, `net_*`, some registry), and its centre of gravity is the
opposite direction: parse a disk image, a hive, an EVTX file, a `.pf`, a memory
dump, an email, a pcap — evidence that has already been captured, often on a
machine other than the one being examined.

**SQL is a good fit for tables and a poor one for parsers.** "Join processes
against open sockets" is a natural query. "Parse this hive, decode the
shimcache, correlate against prefetch, score the result" is a program.

**Choose osquery** for continuous live-state visibility and inventory.
**Choose Mutant** when you are working on captured evidence, or when the logic
does not fit in a query.

## vs. YARA + Sigma

**Rules are declarative; Mutant is not.** YARA matches patterns in file and
memory content; Sigma describes log detections in a portable format compiled to
whatever backend you run. Both are excellent at what they do, both have
communities producing rules continuously, and neither is a general programming
language. Where a rule expresses your detection cleanly, a rule is the right
answer — it is reviewable, shareable, and the ecosystem does half your work.

**Be clear about one thing: Mutant does not have a YARA engine.**
`bin_yara_scan` is a literal multi-string scan — every offset of every literal
you give it, case-sensitively or not. No conditions, no wildcards, no modules,
no rule syntax. A real YARA engine requires cgo, and this project's hard
constraint is that everything builds under `CGO_ENABLED=0`. If you need YARA,
use YARA.

**Sigma is a different answer, because it is a different problem.** A Sigma rule
is YAML and a matching model, neither of which needs a C library, so Mutant
evaluates Sigma rules directly: `sigma_parse`, `sigma_parse_all`, `sigma_match`
and `sigma_scan` run a rule or a ruleset over an `events_from` timeline. Fields
are looked up on the event and then inside `extra`, where the parser's entry is
kept verbatim, so a rule written in a source's own taxonomy runs with no
field-mapping configuration in between. What is *not* supported is anything that
counts or correlates across events — aggregations, `near`, `timeframe` — along
with rule collections and the backend-specific `|expand`; each of those is a
compile error naming itself rather than a rule that quietly never fires. See
[DETECTION_RULES.md](DETECTION_RULES.md).

**Where Mutant fits alongside them: everything around the match.** Rules tell
you *that* something matched. The work of getting the bytes in front of the
rule — mounting the image, walking the filesystem, decoding the artifact — and
the work after the match — correlating hits, building the timeline, scoring,
reporting — is program-shaped, and that is the part Mutant is for. A pipeline
where YARA and Sigma do the matching and Mutant does the parsing, correlation
and reporting is a reasonable design.

---

## Where Mutant is the wrong choice

Stated plainly, because a comparison page that only lists strengths is
advertising.

- **You need fleet-wide collection.** No server, no agents, no hunts. Use
  Velociraptor.
- **You need maximum artifact coverage on a full-disk timeline.** plaso parses
  more formats. Use plaso, and pull its output into Mutant if you want the
  analysis in one language.
- **You need real YARA rules.** Not supported, and the cgo constraint means it
  is not coming. (Sigma is supported — see above — except for rules that
  aggregate or correlate across events.)
- **You need continuous live-state monitoring.** That is osquery's job.
- **You need a large ecosystem, or the guarantee it implies.** One maintainer,
  no formal governance, a small community, and no rule corpus to draw on. A
  mature tool has been wrong in public more times and been fixed for it.
- **You need deleted-key recovery from a real hive.** `reg_deleted_keys` is
  populated only for the JSON source; unallocated-cell carving is not
  implemented, and the builtin documents that rather than returning a plausible
  nothing.
- **You need carving that extracts.** `fs_carve` reports the offsets where
  known signatures begin. It does not determine length or write files out.
- **AGPL-3.0 does not work for you.** That is the licence, including for
  network use.

## Where Mutant is genuinely different

Three things, and they are the reasons to use it:

**One compiled, signed, dependency-free binary that runs the same investigation
on any host.** Not a script plus an interpreter plus a dependency set. Not an
agent that has to be deployed first. One file, cross-compiled to the target
from wherever you are, with the analysis inside it.

**The analysis itself is protected.** Bytecode is encrypted and signed;
mutation level 0–10 makes each build's bytecode different; the runtime detects
sandboxes, VMs and debuggers and, in the default secure mode, refuses to run
when it finds them. If your detection logic is the sensitive part — because it
encodes what you know about an adversary, or because it is a commercial product
— nothing else on this page ships it that way. (That protection is worth what
protection of a binary you have given someone is ever worth. It raises cost; it
does not make analysis impossible.)

**A real language, not a query dialect or a rule format.** Closures, recursion,
structs, enums, macros, a concurrency model where each worker is a whole VM with
a snapshot of globals. Analysis whose shape is a program gets written as a
program.

## Reading on

- **[Mutant in 30 minutes](TUTORIAL_30_MIN.md)** — install to standalone binary
- **[Cookbook](COOKBOOK.md)** — fourteen complete programs, organised by
  investigation
- **[Capability Reference](CAPABILITY_REFERENCE.md)** — all 528 builtins with
  signatures and return shapes; read this before deciding coverage is enough
- **[Security model](SECURITY_LLD.md)** — what the signing, encryption, tamper
  detection and mutation actually promise, and what they do not
