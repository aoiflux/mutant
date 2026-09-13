package main

// The hand-written half of the capability reference: the prose that frames the
// generated tables. Everything else — headings, counts, signatures, platforms,
// and summaries — is read from builtin.Builtins and builtin/metadata.go.
//
// Category names here must match what builtin.CapabilityCategory returns.
// gendocs fails if any category it finds is missing from this list, or if a
// category listed here has no builtins, so a new capability category cannot
// slip into the language without also being described here.

const documentTitle = "Mutant Capability Reference"

const documentPreamble = `> Generated from the builtin metadata (` + "`builtin/metadata.go`" + `) — the source of truth.
> Regenerate with ` + "`go run ./cmd/gendocs`" + `; check for drift with ` + "`go run ./cmd/gendocs -check`" + `.
> Do not hand-edit the tables below: signatures, parameter types, platforms, and
> counts are all read from the metadata, and edits here are overwritten.

This is the canonical, category-grouped catalog of every Mutant builtin. There are currently **%d registered builtins** across **%d capability categories**. For language syntax and keywords see [MUTANT_LANGUAGE_REFERENCE.md](MUTANT_LANGUAGE_REFERENCE.md); deep-dive guides are linked per category below.

## How to read this reference

- **Fallible builtins return a ` + "`(value, err)`" + ` pair**, matching the language idiom ` + "`let value, err = some_call(...);`" + `. Check ` + "`err`" + ` before using ` + "`value`" + `. Infallible helpers return a bare value.
- **Parameter types are shown inline** in each signature, e.g. ` + "`str_repeat(s: STRING, n: INTEGER)`" + `. A parameter with no type shown accepts any value. These are the same contracts the language server checks a call against (the ` + "`builtinArgType`" + ` diagnostic), and the same words the runtime uses when a call fails. A parameter shown as ` + "`BYTES|STRING`" + ` accepts either representation and the builtin hands back the one it was given; ` + "`string_to_bytes(s, \"raw\")`" + ` converts losslessly from a builtin that still returns text.
- **The Platforms column** lists the operating systems a builtin actually works on. ` + "`all`" + ` means it is pure-Go and cross-platform (it operates on captured artifacts, so it runs on any host). A restricted set (e.g. ` + "`windows/linux`" + `) means the builtin fails honestly elsewhere — and the language server will flag such a call when you are editing on an unsupported OS (the ` + "`platformSupport`" + ` diagnostic).
- **Pure-Go, no cgo.** The entire standard library builds and runs with ` + "`CGO_ENABLED=0`" + ` on Windows, Linux, and macOS.

## Platform-restricted builtins

Almost every builtin is cross-platform. The exceptions:
`

// categorySection describes one generated ` + "`## Heading (N)`" + ` section. The order
// here is the order of the document; it is curated rather than alphabetical so
// the language's own primitives come first and the forensics families group
// together at the end.
type categorySection struct {
	// category is the string builtin.CapabilityCategory returns.
	category string
	// heading is how that category is titled in the document.
	heading string
	// blurb is the paragraph under the heading.
	blurb string
}

var categorySections = []categorySection{
	{
		category: "standard library",
		heading:  "Standard Library",
		blurb:    "Core language primitives: collection and hash operations, first-class higher-order functions (`map`/`filter`/`reduce`/`each`/`sort_by`), math helpers, I/O, and runtime/security introspection.",
	},
	{
		category: "testing",
		heading:  "Testing",
		blurb:    "What `mutant test` reads. `test(name, fn)` names a test and runs it where it is written, so a test file reads top to bottom and a test declared inside another is a subtest of it; `before_each`/`after_each` register fixtures for the tests declared after them. The assertions record what they saw against the test that is running AND return it, so a failure is both something the report can name with a file and line and an ordinary value the program can look at. A test that dies is caught at its own boundary and costs the file no other test. See [TESTING.md](TESTING.md).",
	},
	{
		category: "concurrency",
		heading:  "Concurrency",
		blurb:    "Run work alongside the rest of the program and pass values between the pieces. `spawn` starts a closure on its own VM and hands back a handle for `task_wait`/`task_done`; `chan_*` moves values between them. Each task gets a snapshot of globals, so a channel or a return value is the way back, not a shared variable. For applying one callback across an array, reach for `pmap`/`peach` in the standard library instead.",
	},
	{
		category: "strings",
		heading:  "Strings",
		blurb:    "Rune-aware string manipulation: case, trimming, padding, slicing, joining, and formatting. Pairs with the `text_*`/`regex_*` matching family.",
	},
	{
		category: "text analysis",
		heading:  "Text Analysis",
		blurb:    "Substring search, splitting/replacing, regular expressions, and fuzzy matching (Levenshtein, Jaro-Winkler, similarity).",
	},
	{
		category: "structured data",
		heading:  "Structured Data",
		blurb:    "The formats evidence actually arrives in. JSON and NDJSON/JSONL (Zeek, Elastic bulk, OCSF), CSV/TSV (every SIEM export and hash set), XML (Scheduled Tasks, OOXML, Nessus, plist), YAML including multi-document streams (Sigma rulesets), TOML, and the binary serializations -- CBOR for COSE/WebAuthn, MessagePack for agent traffic, plus schemaless walkers for protobuf and DER/ASN.1 that report structure when no `.proto` or ASN.1 module is at hand. Then base64/base32/hex/URL encoding, gzip/zlib compression, base conversion, and type conversion. Every decoder shares one bridge, so a byte string is a BYTES buffer and a timestamp is RFC 3339 no matter which format it came from. See [STRUCTURED_DATA.md](STRUCTURED_DATA.md).",
	},
	{
		category: "math",
		heading:  "Math",
		blurb:    "Numeric constants and random-number helpers (cryptographically-random bytes via `rand_bytes`). Arithmetic helpers like `abs`/`min`/`max`/`sum` live in the standard library.",
	},
	{
		category: "hashing",
		heading:  "Hashing",
		blurb:    "Cryptographic and checksum digests (MD5/SHA-1/SHA-256/SHA-512/CRC-32/BLAKE2), HMAC, and identifier generators (UUID v4/v7, nanoid, random hex).",
	},
	{
		category: "time",
		heading:  "Time",
		blurb:    "Unix timestamps, formatting, parsing, and arithmetic (UTC).",
	},
	{
		category: "bytes",
		heading:  "Bytes",
		blurb:    "Binary buffer inspection and construction: fixed-width integer reads/writes (LE/BE), a streaming cursor, slicing, and byte/char conversions.",
	},
	{
		category: "archives",
		heading:  "Archives",
		blurb:    "Read evidence containers in place: `zip_*` for the .zip a KAPE, CyLR or Velociraptor collection arrives as, `tar_*` for the .tar and .tar.gz a Linux triage script produces (bzip2 and zstd too, detected by magic rather than by extension). Nothing is extracted to disk -- an entry goes straight into a BYTES buffer for whatever parses it next -- so the classic extraction escape cannot be exploited through these builtins. It is still reported: every entry carries `unsafe_path`, because an archive containing such a name is a finding in its own right. Every decompression is bounded, here and in `gunzip`/`zlib_decompress`, at 1000x its input and 1 GiB, which a caller can override per call with `max_bytes`.",
	},
	{
		category: "filesystem",
		heading:  "Filesystem",
		blurb:    "Read/write/manage files and directories, plus file-level forensics: hashing, entropy, string extraction, magic-type detection, carving, diffing, and NTFS deleted-file recovery.",
	},
	{
		category: "network",
		heading:  "Network",
		blurb:    "Sockets and TLS sessions, an in-process X.509 CA, HTTP-message inspection, listeners/serve loops, WebSocket framing, scanning, and offline pcap analysis. See [SECURE_NETWORKING.md](SECURE_NETWORKING.md).",
	},
	{
		category: "http",
		heading:  "Http",
		blurb:    "HTTP client requests and low-level request/response parsing and building for proxy/inspection workflows.",
	},
	{
		category: "graph database",
		heading:  "Graph Database",
		blurb:    "Graph-oriented data modeling: typed nodes/edges, named relations, indexed artifact attributes, BFS traversal, shortest-path, statistics, and timelines. See [GRAPH_DATABASE.md](GRAPH_DATABASE.md).",
	},
	{
		category: "cache",
		heading:  "Cache",
		blurb:    "In-memory key/value cache with TTLs and hit/miss statistics.",
	},
	{
		category: "policy",
		heading:  "Policy",
		blurb:    "Load and evaluate allow/deny policies with rule metadata and evaluation traces.",
	},
	{
		category: "runtime integration",
		heading:  "Runtime Integration",
		blurb:    "Embed and securely execute Lua in a restricted sandbox (no `io`, dangerous `os.*` stripped, bounded execution). See [RUNTIME_INTEGRATION.md](RUNTIME_INTEGRATION.md).",
	},
	{
		category: "command execution",
		heading:  "Command Execution",
		blurb:    "Guarded execution of external commands, subject to the `command_exec` capability policy.",
	},
	{
		category: "cryptography",
		heading:  "Cryptography",
		blurb:    "X.509 certificate parsing, JWT decoding, PEM decoding, and authenticated AES-GCM encryption/decryption.",
	},
	{
		category: "fingerprinting",
		heading:  "Fingerprinting",
		blurb:    "Malware/host fingerprints: PE import hash (imphash), JA3 TLS-client fingerprint, and NTLM/LM password hashes (for authorized credential testing).",
	},
	{
		category: "network intelligence",
		heading:  "Network Intelligence",
		blurb:    "IOC handling: defang/refang, IP/CIDR math, domain/eTLD+1 extraction, validation, and IOC extraction from free text.",
	},
	{
		category: "detection",
		heading:  "Detection",
		blurb:    "Heuristic detectors for code injection, C2 beaconing, persistence, privilege escalation, and suspicious files, driven by supplied evidence.",
	},
	{
		category: "process forensics",
		heading:  "Process Forensics",
		blurb:    "Live process inspection: enumeration, tree, environment, open files, threads, modules, executable hashing, memory scanning, and signaling.",
	},
	{
		category: "memory forensics",
		heading:  "Memory Forensics",
		blurb:    "Memory-dump analysis: segmentation with entropy, string extraction, pattern scanning, and PE/shellcode discovery.",
	},
	{
		category: "binary analysis",
		heading:  "Binary Analysis",
		blurb:    "PE/ELF/Mach-O/DWARF parsing, imports, sections, strings, entropy, literal signature scanning, and Go-binary metadata recovery (GoReSym).",
	},
	{
		category: "chain of custody",
		heading:  "Chain of Custody",
		blurb:    "A case session that records who opened what, when, with which build of the tool. `case_open(id, examiner)` starts it; from there every evidence opener records its source into the manifest and every builtin that reads through an evidence handle is counted against that source. `case_verify` re-measures the sources and reports drift; `case_write` seals the manifest with a SHA-256 over its own contents and an Ed25519 signature, and `case_manifest_verify` checks both from the file alone. Nothing is recorded until a case is opened, so a program that does not use this is unaffected by it. The read-only guarantee the manifest asserts is machine-checked: see [EVIDENCE_HANDLING_POLICY.md](EVIDENCE_HANDLING_POLICY.md).",
	},
	{
		category: "registry forensics",
		heading:  "Registry Forensics",
		blurb:    "Windows registry across three sources via one polymorphic API (regf hive file, hive-JSON, or live Windows registry), plus Amcache and Shimcache execution evidence.",
	},
	{
		category: "filesystem forensics",
		heading:  "Filesystem Forensics",
		blurb:    "Read-only filesystem parsers for NTFS/FAT/exFAT/ext/HFS+/XFS images and standalone $MFT timelines, with rich MAC timestamps and metadata.",
	},
	{
		category: "disk image forensics",
		heading:  "Disk Image Forensics",
		blurb:    "Container and partition-table parsers: raw images, EWF/E01, VHD/VHDX (with differencing chains), and MBR/GPT partition tables.",
	},
	{
		category: "windows artifacts",
		heading:  "Windows Artifacts",
		blurb:    "Execution and shell-activity artifacts: Prefetch, Windows Event Logs (EVTX), shell links (LNK), and Jump Lists.",
	},
	{
		category: "unix artifacts",
		heading:  "Unix Artifacts",
		blurb:    "Unix log artifacts: RFC 5424 / RFC 3164 syslog parsing.",
	},
	{
		category: "browser artifacts",
		heading:  "Browser Artifacts",
		blurb:    "Chromium/Firefox history, cookies, and downloads, plus generic read-only SQLite querying (forensically safe: originals are never modified).",
	},
	{
		category: "forensic timeline",
		heading:  "Forensic Timeline",
		blurb:    "Normalize timestamps across epochs and merge/sort artifact events into a single supertimeline; Sleuth Kit bodyfile/mactime interop.",
	},
	{
		category: "schema interchange",
		heading:  "Schema Interchange",
		blurb:    "Normalize any parsed artifact into one event vocabulary, then write that vocabulary out in whichever schema the next tool reads. `events_from` maps an artifact's entries onto a fixed set of event fields -- one event per timestamp the artifact recorded, with the source entry carried verbatim in `extra` so nothing is lost -- and `event_kinds()` reports what each supported artifact maps. `ecs_event`, `ocsf_event` and `timesketch_event` render those events as Elastic Common Schema documents, OCSF events, or the plaso records Timesketch ingests, one event or a whole timeline at a time. Thirteen artifacts and three schemas cost sixteen mappings here rather than thirty-nine, so a new parser reaches every schema by describing itself once. An artifact Mutant does not know is described with a mapping hash rather than waiting for support. See [INTERCHANGE_SCHEMAS.md](INTERCHANGE_SCHEMAS.md).",
	},
	{
		category: "email forensics",
		heading:  "Email Forensics",
		blurb:    "Parse raw email into headers/body/attachments/URLs and cryptographically verify DKIM (with SPF/DMARC reporting).",
	},
	{
		category: "hash-set forensics",
		heading:  "Hash-Set Forensics",
		blurb:    "NSRL-style known-file hash sets for include/exclude filtering.",
	},
}
