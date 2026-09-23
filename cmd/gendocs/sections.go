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
- **Every builtin has two spellings.** A name with an underscore in it is also reachable through its family: ` + "`hash.blake2`" + ` is ` + "`hash_blake2`" + `, ` + "`fs.read`" + ` is ` + "`fs_read`" + `, and so on for every name in this table. The two are one function — the dotted form is folded into the flat one at compile time rather than looked up in a list — so the tables below list only the flat name. A variable, parameter or imported module that already binds the family name wins, so no existing program changes meaning.

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
		category: "forensic ledger",
		heading:  "Forensic Ledger",
		blurb:    "The same graph engine under a posture that cannot be turned off: every commit signed and attributed, a log containing an unsigned commit refused on replay, the image verified before it loads, the redaction ledger on, and every retired segment kept. There is no options hash anywhere in the family, because each setting is a decision about what the resulting document may claim. Ledger handles are their own space -- no `db_` builtin resolves one -- and a ledger directory refuses to open as an ordinary graph.",
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
		blurb:    "Two ways to decide that something is worth looking at. The `detect_*` builtins are heuristic detectors for code injection, C2 beaconing, persistence, privilege escalation and suspicious files, driven by supplied evidence. The `sigma_*` builtins run real [Sigma](https://sigmahq.io) rules -- the portable YAML detection format -- over `events_from()` timelines: `sigma_parse` and `sigma_parse_all` compile a rule or a whole ruleset, `sigma_match` asks one rule about one event, and `sigma_scan` runs a ruleset over a timeline. A rule this engine cannot evaluate is a compile error rather than a silent non-match, and both `sigma_match` and `sigma_scan` report the fields a rule read that the evidence never carried -- a rule that could not have fired is not a host that came back clean. See [DETECTION_RULES.md](DETECTION_RULES.md).",
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
		category: "reporting",
		heading:  "Reporting",
		blurb:    "An investigation ends in a report, not a stdout dump. `report_new` starts one and `report_section`/`report_text`/`report_list`/`report_table` fill it in; the report itself is a plain hash, so it can be JSON-encoded, diffed against the last one, or written by hand, and every builder returns a new document rather than changing the one it was given. `report_render` writes it as HTML, Markdown or CSV. Nearly every string in a report came from the evidence, which is to say it was written by the subject of the investigation, so the model holds values and each format is escaped for the thing that actually goes wrong in it: HTML is the boundary, and never turns evidence text into a link; Markdown is escaped for structure, so a pipe in a filename cannot shift a table column; CSV guards the cells a spreadsheet would execute when the file is opened.",
	},
	{
		category: "chain of custody",
		heading:  "Chain of Custody",
		blurb:    "A case session that records who opened what, when, with which build of the tool. `case_open(id, examiner)` starts it; from there every evidence opener records its source into the manifest and every builtin that reads through an evidence handle is counted against that source. `case_verify` re-measures the sources and reports drift; `case_write` seals the manifest with a SHA-256 over its own contents and an Ed25519 signature, and `case_manifest_verify` checks both from the file alone. Nothing is recorded until a case is opened, so a program that does not use this is unaffected by it. The read-only guarantee the manifest asserts is machine-checked: see [EVIDENCE_HANDLING_POLICY.md](EVIDENCE_HANDLING_POLICY.md). The case key is separate and never travels as an argument: `case_key_create`, `case_key_open`, `case_key_rotate` and `case_key_fingerprint` take a path to a key file whose passphrase is read from the terminal, and `class_define`/`class_list` declare the classification labels a record segment may carry, each tagged by an HMAC keyed to the case key so that two investigations declaring the same label produce different tags. What a classification does and does not promise is stated in [DISCLOSURE_POLICY.md](DISCLOSURE_POLICY.md).",
	},
	{
		category: "classified records",
		heading:  "Classified Records",
		blurb:    "Evidence encrypted at rest, in a container whose structure is public and whose content is not. `record_classify_range` names a run of bytes and the class it carries; `record_seal` writes a `.mrec` in which each classification span is split into segments of at most 64 KiB, and a segment is at once the AEAD unit, the key-derivation unit and the smallest disclosable unit -- so holding one segment's key can never open bytes of two classifications. A `default` class is required and covers every byte no range names, because a record with an unlabelled remainder discloses that remainder to everyone. Range boundaries and lengths are public by construction, which is deliberate: a redaction nobody can see is a redaction nobody can challenge. `record_seal_quantised` rounds boundaries outward where a short secret must not advertise its length; it requires a `rounds_to` option naming the one class rounding may grow, and records how many bytes changed class beside the class they changed into -- a count with no direction cannot be read, because whether widening a range withholds those bytes or releases them depends on which of the two classes is the more sensitive, and nothing here orders them. `record_verify` checks a record holding no key at all -- the property a recipient granted nothing still has -- and reports in a `does_not_prove` field what a valid signature does not establish. `record_read` refuses a span it cannot fully decrypt and names the segments; `record_read_partial` is the separate contract that returns the holes as data. Plaintext either read returns is marked with the record and the classes it came from, and every builtin that sends a value out of the process -- `putln`, `putf`, `fs_write`, `fs_append`, `http_post`, `http_request`, `report_write`, `report_render`, `case_note`, `cache_put`, `ledger_add_node`, `ledger_add_edge` and `db_add_artifact` -- refuses a marked buffer wherever it sits in its arguments, naming the record and never a byte; `bytes_slice` carries the mark to the slice, and `+` of two buffers to the joined one. `record_release(buffer, reason)` is the deliberate way out: it requires a reason and an open case, writes the release into the case timeline, and returns an unmarked copy. The mark catches accidents, not adversaries: a conversion to a string, to hex or to JSON drops it, and so does a loop that rebuilds the buffer byte by byte. What a disclosure can and cannot promise is stated in [DISCLOSURE_POLICY.md](DISCLOSURE_POLICY.md).",
	},
	{
		category: "disclosure",
		heading:  "Disclosure",
		blurb:    "Who may open which part of a record, decided once and reviewable before anything is handed over. `view_define(label, classes)` declares a named posture -- the set of classifications a grant issued under that name will open -- and `view_list` reports the postures in force. A view names the classes it grants and cannot negate: an \"everything except\" posture would widen by itself every time a class was declared after it, changing what it releases with nothing edited and nothing recorded, which is the one way a disclosure can change invisibly. `view_preview(record, view)` says exactly what a view would release from a particular record and exactly what it would hold back, as byte ranges on both sides, and it does so as arithmetic over the record's public header -- it opens no segment and needs no plaintext. Where the record was sealed by `record_seal_quantised`, the preview states the rounding in the terms of the view in front of it, because rounding moves bytes into one named class and therefore releases more or withholds more depending on whether this view grants that class. A preview says what would be disclosed; it does not say that the classification which put those bytes where they are was correct, and it says so in a `does_not_say` field. The `disclose_*` family then carries a posture out. `disclose_to_passphrase(ledger, record, view, recipient)` issues a grant -- the key material for exactly the segments the view selects, 56 bytes a segment, sealed under a passphrase asked for at the terminal -- and writes the disclosure into the forensic ledger before handing anything back; a disclosure the ledger could not record was not issued. The record a recipient receives is byte-identical to the one under custody: a disclosure is a key grant, never a re-encryption. `disclose_bundle` lays the package down the way `case_bundle` does, with the ledger's inclusion proof for the disclosure and a signed manifest, and returns the snapshot root to be sent by another route; `disclose_verify(dir, root)` is the recipient's side, and a null root is a finding, never a pass. `record_open(path, {\"grant\": path})` reads a record under a grant alone, with no case and no case key. `disclose_withdraw` records a withdrawal and stops further grants -- it is not a revocation, nothing reaches a recipient's copy, and `bytes_recoverable` is false on every row this family writes -- while `disclose_history` and `disclose_for_segment` answer who was given what, listing withdrawn recipients because they still hold what they were given. `disclose_reclassified` records that a record was sealed again under different classes and reports which recipients hold bytes whose class changed, without saying which way: nothing in this tool orders classes. What a disclosure can and cannot promise is stated in [DISCLOSURE_POLICY.md](DISCLOSURE_POLICY.md).",
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
		blurb:    "Normalize any parsed artifact into one event vocabulary, then write that vocabulary out in whichever schema the next tool reads. `events_from` maps an artifact's entries onto a fixed set of event fields -- one event per timestamp the artifact recorded, with the source entry carried verbatim in `extra` so nothing is lost -- and `event_kinds()` reports what each supported artifact maps. `ecs_event`, `ocsf_event` and `timesketch_event` render those events as Elastic Common Schema documents, OCSF events, or the plaso records Timesketch ingests, one event or a whole timeline at a time. Fourteen artifacts and three schemas cost seventeen mappings here rather than forty-two, so a new parser reaches every schema by describing itself once. `stix_bundle` and `stix_pattern` take the other road out of an investigation -- indicators rather than events -- rendering `extract_iocs` output as a STIX 2.1 bundle whose every id is derived from the indicator itself, so a re-run over the same evidence is the same bundle byte for byte. An artifact Mutant does not know is described with a mapping hash rather than waiting for support. See [INTERCHANGE_SCHEMAS.md](INTERCHANGE_SCHEMAS.md).",
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
