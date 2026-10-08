# Changelog

All notable changes to Mutant are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
What "breaking" means for artifacts, builtins, the language and the CLI is
defined in [CONTRIBUTING.md](CONTRIBUTING.md#compatibility-and-stability).

Entries for v2.4.0 and later are written from the release notes and the commits.
Entries before that are reconstructed from git history and are summaries, not
exhaustive lists.

## [Unreleased]

### Added

- **A release gate you can run.** `scripts/release_gate.sh` and
  `scripts/release_gate.ps1` run every check a release has to pass -- the
  toolchain `go.mod` pins, gofmt, vet on three platforms, the six build targets
  and the WebAssembly REPL, the tests, the race detector, fuzzing, the generated
  documents, the example sweep against its recorded output, module
  verification, the changelog date against the tag, and govulncheck -- and print
  one table. A reachable vulnerability fails a full run; `--quick` / `-Quick`
  skips that step unless `--vuln` / `-Vuln` asks for it.
  Everything it builds is what a release ships: the pinned toolchain with
  `CGO_ENABLED=0`, the race detector's test binaries alone excepted, and the
  sweep runs a binary the gate built rather than one built by whatever `go` is
  first on the PATH. Every choice is a parameter; nothing is read from the
  environment and nothing is written into the working tree -- a log directory
  inside the repository is refused, since the Go files the gate writes there
  would join the module it is checking. `scripts/coverage.sh` and
  `scripts/coverage.ps1` measure unit and cross-package coverage per package
  through a new `cmd/covreport`. There is still no CI: this is the command a
  contributor runs, and the one the owner runs before tagging.

- **Every limit is named, and a guard keeps it that way.** A value that bounds
  what Mutant will do -- how much it reads, how deep it recurses, how long it
  waits, how many entries it keeps -- is a constant with a `//mutant:limit`
  directive and a written reason, and `docs/LIMITS_REFERENCE.md`, a third
  artifact `go run ./cmd/gendocs` generates, lists each with its value and the
  flag that overrides it, if one does. `go test ./policy/` fails on a limit
  written as a bare literal in any of ten recognised shapes; the 174 already in
  the tree are held in a per-file budget that can only shrink. See section 6 of
  [CONFIGURATION_POLICY.md](docs/CONFIGURATION_POLICY.md).

- **The documentation is checked against the tree.** Every `mutant` fence
  compiles, allowing for names an earlier fence defined; every `name(` in prose
  is a registered builtin; every `mutant` command line uses flags the binary
  spells, and none teaches the retired `run`, `-pwd` or `--password` forms;
  every path a document or a Go comment cites exists in a clone; every relative
  link and anchor resolves. The examples check walks every directory now, and
  also fails when a README names a program that is not there. The version the
  documents state is held to `global.Version`: the tutorial's sample output,
  SECURITY.md's supported-versions table, this file's first release and compare
  links, and a new `mutantLanguageVersion` field in the extension's manifest.

- **Examples can record what they print.** `go run ./cmd/sweep --golden`
  compares each reproducible example's output with a `.golden` file beside it,
  and `--update-golden` writes them; output that varies between two runs of the
  same bytecode gets no golden, because one sample of it is not its value. A
  golden recorded on one OS checks a run on another: the separators in a source
  position and the few system errors Windows words differently are normalized,
  and the evidence fixtures in `examples/data` are checked out byte for byte. A
  new `// mutant:sweep needs-input -- <what>` marker compiles an example that
  needs evidence, a network peer or a passphrase, or that reports on the machine
  it runs on, and counts it separately, so the number of examples whose output
  was actually checked is never inflated. A difference between two mutation
  levels fails the sweep only if it repeats when both are run again, so output
  that carries the time is no longer reported as the engine changing a program.

- **`db_compact`, and a memory budget for `db_open_disk`.** Graphene v0.9.0
  compacts a disk store's write-ahead log on request, and caps the memory a
  disk store may use; v0.4.0 had no memory configuration at all.

- **Integrity that is checked, not only reported.** `ewf_metadata` has always
  returned the MD5 and SHA-1 an acquisition tool stored inside an E01 image, and
  nothing compared them with the data. `ewf_verify` does: it re-hashes the
  image, reports each digest's match beside whether one was stored at all, and
  lists the bad ranges. An image that stores no digest is **not verified**,
  rather than verified by default. `ewf_segments` finds a segment set from its
  first file and names any segment missing from it, and `ewf_open_partial` opens
  an incomplete set on purpose rather than by accident.

  Six `*_verify` builtins -- `ntfs_verify`, `fat_verify`, `xfat_verify`,
  `ext_verify`, `hfs_verify` and `xfs_verify` -- run whatever integrity checks
  each filesystem library carries. Every check reports `checked` beside
  `passed`, and a volume is `verified` only when at least one check ran and every
  check that ran passed; one boolean would have an HFS+ volume assert a check its
  format does not contain. `fat_verify` walks the directory tree before it reads
  the FAT mirror comparison, because that comparison happens only as entries are
  looked up, and a volume holding only root entries would otherwise report
  verified with no comparison made.

- **Security events are recorded, not only counted.** `security.auditEvent` was a
  no-op at fourteen call sites, so a manifest could say the debugger check tripped
  eleven times and nothing could say when. It now feeds an append-only,
  length-prefixed hash chain, read through `audit_head`, `audit_write` and
  `audit_verify`. The head is bound into the case manifest inside the existing
  seal, and `audit_verify` takes the head as an argument, because a log checked
  against the head stored inside it has been checked against a value its own
  writer chose. At most 4096 entries stay readable; the head still commits to
  every event, and `entries`, `retained` and `dropped` are three numbers. Every
  document says what it does not cover: an edited entry breaks every link after
  it, and no document can show that a whole document is missing.

- **A partition opens where it lies.** The second argument to `ntfs_open`,
  `fat_open`, `xfat_open`, `ext_open`, `hfs_open` and `xfs_open` is a byte offset
  or, better, a row straight from `table_list_partitions`, which carries
  `start_byte` and `length_byte` together so that no line of a script does
  arithmetic on an offset. Nothing is carved out first. The offset goes to the
  library rather than to a wrapping reader, so every offset a filesystem reports
  stays image-absolute: a partition-relative offset looks exactly like an
  absolute one, and intersecting the two succeeds and is wrong. Every open the
  case manifest records now carries `volume_offset` and `volume_length`, so two
  partitions of one image no longer read as the same open twice.

- **Files stream rather than load whole.** Eighteen builtins, three verbs across
  the six filesystems: `*_extract_file` writes a file out a megabyte at a time
  and digests it on the way past, `*_hash_file` digests it where it lies, and
  `*_read_file_at` returns one window of it. A file larger than memory is
  reachable, including a disk image inside a disk image. Each reports the
  recorded `size` beside `located_bytes` and never reads past the latter: a FAT
  entry whose chain broke at deletion still claims its original length, and the
  clusters past the recoverable prefix now belong to some other file. A short
  chain extracts its prefix and says `truncated: true`, and the digest covers
  what was read, never what was claimed. Extraction refuses a destination that
  exists and removes its partial output on failure.

- **Which partition table is true can be the script's decision.** A disk that
  two schemes both describe was resolved by a preference the script never saw.
  `table_open` still resolves by preference and now lists every candidate it
  passed over; `table_open_strict` refuses and names them; `table_open_as`
  forces `mbr`, `gpt`, `bsd`, `sun` or `mac`, so an examiner records having
  decided; and `table_open_all` returns a handle per scheme -- on a hybrid disk
  the only route to the MBR's real entries. `table_detect` asks without opening
  anything, and `table_nested` reaches a disklabel inside an MBR slice with
  offsets computed by the inner table. `table_open` gained `gpt_backup`: the two
  GPT copies are written together, so a mismatch is a tamper indicator rather
  than a health check. Every partition row now says what it is: only an
  `allocated` row is a volume, and the rows marked `occupies_space` tile the
  device exactly once.

- **What the filesystems remember about files that are gone.** Seven builtins --
  `ntfs_deleted`, `fat_deleted`, `xfat_deleted`, `ext_deleted`, `hfs_deleted`,
  `xfs_deleted` and `xfs_unlinked` -- give every supported filesystem the
  deleted-entry listing that existed only for NTFS resident data. The field that
  matters is `content_state`, not a `recoverable` flag, because six formats
  destroy six different things at deletion: ext4 zeroes the extent tree and
  leaves the file fully described and wholly unlocatable, while exFAT's
  `NoFatChain` keeps a layout the volume stated while the file was live. Eight
  `*_recover_file` builtins write what remains back out, addressed by the index
  the scan gave the entry, and count three kinds of zero apart: bytes read from
  the image, sparse holes whose zeros are the content, and unlocated ranges
  written only so that later offsets land. `fat_recover_file_assuming_contiguous`
  and its exFAT twin are separate names rather than a flag, so the hypothesis is
  written at the call site.

- **Journals.** Nine builtins read the one structure in these formats that
  records the past: NTFS's USN journal and `$LogFile` (`ntfs_usn_journal`,
  `ntfs_log_records`, `ntfs_log_transactions`), ext's JBD2 (`ext_journal`,
  `ext_journal_block_copies`, `ext_journal_inode_versions`,
  `ext_recover_journalled_file`) and the XFS log (`xfs_log_records`,
  `xfs_log_transactions`). All three are written round and round, so every scan
  says whether it crossed the wrap, and where it did the array is not a timeline
  and nothing here reorders it. `$LogFile` and the XFS log carry no clock, so
  what they give is an ordering, not a timeline. `ext_recover_journalled_file` is
  the one route here to an ext4 file the filesystem itself can no longer locate.
  ext's fast-commit records are deliberately not read: they carry no sequence and
  no timestamp.

- **Slack, and the other thing called slack.** `ntfs_slack`, `fat_slack`,
  `xfat_slack`, `ext_slack`, `hfs_slack`, `xfs_slack`, `ext_dir_slack` and
  `hfs_unallocated`. File slack lies past the recorded size; unwritten space lies
  inside it and was never written, and only four of the six formats record that
  second boundary. Every range carries its class rather than merging the two.
  These address a live file by path, so the slack of a deleted file is out of
  their reach, and the reference says so.

- **Content and labels a path does not address.** `ntfs_streams`,
  `ntfs_read_stream`, `ntfs_extract_stream`, `ntfs_security`,
  `ntfs_security_descriptors`, `ntfs_reparse`, `ext_xattrs`, `xfs_xattrs`,
  `hfs_xattrs` and `hfs_resource_fork`. An alternate stream or a resource fork is
  a second body of bytes; a descriptor or an attribute asserts something about
  the file and holds none of its content, and the two are never summed. A
  descriptor with no DACL grants everyone access and one with an empty DACL
  denies everyone, so `dacl_present` is its own field.

- **Virtual disks as the three things a byte stream hides.** `vhdi_extents`,
  `vhdi_chain`, `vhdi_changed_extents`, `vhdi_changed_since`, `vhdi_probe` and
  `vhdi_discover`: an address space that is mostly absent, a device spread over
  several files, and a change record answerable at block level. A range with no
  bytes behind it reports `file_offset: -1` rather than the zero the library
  returns, because on a dynamic VHD byte zero is the footer's mirror. A VHD chain
  cannot record a deletion at all, and `deletions_expressible` says when that
  applies. `vhdi_probe` registers the image it names as evidence; `vhdi_discover`,
  which is asked about a directory, registers nothing.

- **What a filesystem can record, and what this one did.** Six
  `*_capabilities` builtins report each library's own capability set in three
  states -- supported, unsupported and unanswered -- because a question the
  library never answers is not a no: HFS has recorded creation dates since 1985
  and libhfs does not declare it. Each answer says whether it came from the
  format or from the volume in hand. Six `*_report` builtins walk a whole volume
  into one row shape, and `events_from(report, "fs_report")` carries any of them
  into the ECS, OCSF and Timesketch emitters. `complete` means the walk had no
  known gap and nothing more; only `xfs_report` can reconcile against the
  volume's own inode counters, so `completeness_checked` and
  `completeness_proven` are separate fields.

- **A forensic ledger.** Thirty-nine `ledger_*` builtins, in a new
  `forensic ledger` category, put graphene's signed-store layer within reach of a
  script. `ledger_open` has a fixed strict posture and no options hash: every
  commit signed and attributed, and a retention policy that keeps every commit's
  actor, timestamp and signature through compaction.

  - **Proofs:** `ledger_prove_node`, `ledger_verify_proof`,
    `ledger_proof_describe`, `ledger_root_export` and `ledger_verify_chain`. The
    root is always an argument, never read from the proof.
  - **Custody and anchoring:** `ledger_custody`, `ledger_custody_anchored`,
    `ledger_checkpoint`, `ledger_checkpoint_history`, `ledger_verify_anchor` and
    `ledger_verify_store`. The witness is an argument, and graphene's insecure
    local anchor is not reachable from the language. A write made since the last
    compaction moves none of the six heads a checkpoint binds, and graphene
    reports that as clean; `ledger_verify_anchor` reports it as a gap.
  - **Attributed redaction:** four `ledger_redact_*` scopes, each requiring a
    reason, `ledger_redaction_impact` to preview a cascade, `ledger_redactions`,
    and three `ledger_prove_*redaction` proofs. A redaction does not remove the
    content from the ledger directory -- the retired log segment that retention
    keeps for attribution still holds it -- and every redaction reports
    `retained_segments` rather than implying otherwise. A reason containing one
    of the redacted values is refused, because graphene publishes the reason
    where it cannot be redacted.
  - **Reads:** `ledger_node`, `ledger_edge`, `ledger_provenance`, `ledger_path`,
    `ledger_subgraph`, `ledger_patterns`, `ledger_query_nodes`,
    `ledger_explain_query`, four `ledger_declare_*` index declarations and
    `ledger_indexes`. Declaring a key ordered changes its range comparisons from
    numeric to byte-wise -- over `9, 10, 1x, 100, 2`, a `between "2" and "100"`
    goes from four records to none -- so `ledger_declare_ordered` reports
    `order_differs` before it declares, and `ledger_query_nodes` reports which
    comparison answered.

  `db_open_disk` refuses a ledger directory: one unsigned write through it would
  leave a store the strict open then refuses entirely.

- **`mutant graph export` and `mutant graph query`.** `export` walks an entry
  file's whole import closure and writes a graphene store of its symbol graph: a
  node per module and per declaration, joined by `DECLARES`, `ENCLOSES`,
  `REFERENCES` and `IMPORTS`, with `USES_TYPE`, `CONSTRUCTS` and `MATCHES` as
  further labels on a reference that names a type, builds a struct or is
  compared against in a match arm. A struct or enum another module declares is
  resolved the way the compiler resolves it, against the modules compiled first;
  a use the compiler would refuse has no edge, and the export says how many.
  `query` reads the store back through eleven named questions -- `summary`,
  `modules`, `where`, `callers`, `callees`, `outline`, `exported`, `types`,
  `type`, `deps` and `rdeps` -- rather than a filter surface, because in this
  engine a filter on an unindexed key matches nothing and returns no error.
  `deps` and `rdeps` follow each import in its own direction and keep every
  one, which graphene's own walks do not. The store is identified by its own
  label table before anything opens it, and a store with no lock file is read
  live rather than have one created for it, so the first question put to a
  restored store does not modify it. Each answer says what it does not cover:
  `callers` is complete within a module and a floor across one, and a question
  that read every record to answer says so.

- **Classified records.** `case_key_create`, `case_key_open`, `case_key_rotate`
  and `case_key_fingerprint` take a path, never key material; the passphrase is
  asked for at the terminal, and an options key named `passphrase`, `password`,
  `secret` or `key` is refused by name. `class_define` and `class_list`
  pre-declare the labels a byte range may carry, so a typo is an error rather
  than a new secret class. Ten `record_*` builtins, in a new `classified records`
  category, seal a file into a `.mrec` container: ranges of uniform
  classification, split into segments of at most 64 KiB, each segment its own
  XChaCha20-Poly1305 unit under a key derived from its record, index, offset,
  length and class, so a segment moved anywhere else fails to open rather than
  only failing its tag. `record_verify` authenticates the whole file holding
  **no key**. `record_read` errors when a requested span overlaps a segment it
  cannot decrypt, and `record_read_partial` returns `{bytes, holes}` as a
  separate contract. `record_seal_quantised` rounds boundaries outward so a short
  secret does not advertise its length, and requires `rounds_to`, the one class
  rounding may grow, because every byte it grows over changes class. Rotating
  the case key invalidates no grant already issued.

- **Disclosure: a grant of segments, sealed under a passphrase.** `view_define`,
  `view_list` and `view_preview`, in a new `disclosure` category, name a set of
  classes. A view cannot negate, because "everything except restricted" widens by
  itself each time a class is declared after it. `view_preview` is arithmetic
  over the public header -- no key, no plaintext -- and states a rounding in the
  terms of the view in front of it. `disclose_to_passphrase` issues a grant of
  exactly the segments a view covers, 56 bytes of key and nonce per segment,
  sealed under a passphrase, and commits it to the ledger before handing it over;
  a ledger failure means nothing was issued. `disclose_bundle` writes one
  disclosure's package: the record byte for byte, the sealed grant, the ledger's
  inclusion proof, a report, a manifest sealed and signed over all four, and
  `SHA256SUMS` last. The snapshot root is returned and not packaged, and
  `disclose_verify` requires it as an argument; a null root is recorded as a
  finding, never read as a pass. `disclose_withdraw` returns
  `bytes_recoverable: false`, because a recipient holding the ciphertext and a
  key holds both halves, and no builtin is named `revoke`.
  `disclose_history`, `disclose_for_segment` and `disclose_reclassified` answer
  who holds what, and who holds segments whose classification has since changed.

  A grant is sealed under a passphrase and nothing else. That is a decision, not
  a gap: there is no public-key `disclose_to`, and should one ever be added, the
  holder of a private key is trusted to keep it secret, as the examiner keeps the
  case-key passphrase. See [DISCLOSURE_POLICY.md](docs/DISCLOSURE_POLICY.md).

- **Plaintext read from a classified record does not leave the process by
  accident.** A buffer from `record_read` or `record_read_partial` carries its
  record and class, `bytes_slice` and `+` of two buffers carry it on, and
  thirteen builtins refuse it anywhere in their arguments: `putln`, `putf`,
  `fs_write`, `fs_append`, `http_post`, `http_request`, `report_write`,
  `report_render`, `case_note`, `cache_put`, `ledger_add_node`,
  `ledger_add_edge` and `db_add_artifact`. `record_release(buffer, reason)` is
  the recorded way out: it needs a reason and an open case, records the release
  in the case timeline, and returns an unmarked copy. The mark is deliberately
  not consulted by `Inspect`, which is the identity function for equality,
  `unique`, `contains` and hash keys. It catches accidents, not adversaries: a
  loop that rebuilds the buffer a byte at a time launders it. A policy guard
  keeps `Inspect` and runtime format strings out of the files that handle
  plaintext.

  The editor says so first. A new `classifiedPlaintext` lint rule -- a warning
  by default, `mutant.lint.rules.classifiedPlaintext.severity` in the extension
  -- reports a read handed to one of those builtins, directly, through a name
  bound once, through `bytes_slice` or `record_read_partial`'s `bytes`, or inside
  a literal array, hash or struct, at the line and before the program runs and
  asks for a passphrase. Its lists are the runtime's own,
  `builtin.ClassifiedSinks` and `builtin.ClassifiedSources`, and tests that read
  the builtin package's source hold both to the code that refuses and marks,
  and hold every sink to numbering arguments the way the script wrote them. A
  value from a user function, a name bound twice and `a + b` are not followed,
  so the rule never reports what it cannot be sure of.

- **An example that runs the whole path.**
  `examples/forensics/record_disclosure.mut` opens a seized USB stick image,
  finds its one volume, verifies it and extracts a phishing email from it where
  it lies, seals the email with the victim's address classified `pii` and the
  attachment `restricted`, discloses it to a `counsel` view and a
  `malware-desk` view, bundles both, and re-measures custody at the end. It also
  tries once to write the address out, to show the refusal.
  `examples/data/usb_stick.img` is a 100 KiB MBR disk holding one FAT12
  partition, rebuilt byte for byte by `go run examples/data/make_usb_stick.go`,
  and `TestTheRecordDisclosureExampleRunsEndToEnd` runs the program with its
  seven terminal prompts scripted and checks that the email taken off the image
  is identical to `examples/data/phish.eml`.

- **A `db_*` store can be read back.** Everything the family wrote, nothing
  could read: properties went into graphene's index with no builtin to look a
  node up by one, and the only way to learn what a store held was to have been
  the program that wrote it. Five builtins read it (659 → 664):
  `db_find(db, key, value, nodeType?)` looks nodes up by one indexed value, and
  says in `key_indexed` whether the key was ever indexed at all -- graphene
  answers a lookup on an unknown key with nothing and no error, so an empty list
  alone could not tell "no host has that address" from a misspelled key;
  `db_node(db, id)` reads a node's type and every indexed property, and shows a
  key indexed twice as both values rather than picking one; `db_relations(db,
  node, direction)` lists a node's edges with the relation each carries;
  `db_schema(db)` counts types, indexed keys and relations; and `db_verify(db)`
  cross-checks the indexes against the records, reporting `checked` and
  `consistent` apart so a store that cannot check itself never reads as a pass.
  `db_open_disk` takes `read_only`, which opens a store without changing it --
  never creating one, refused while a writer holds it, and read without a lock
  when it has no `graphene.lock`, which `db_stats`' new `lock_free` field then
  explains. `db_compact` reports the `snapshot_root` of the image it wrote and
  the `prev_root` it replaced.

- **The editor knows the words a builtin takes.** A parameter can now declare
  the closed set of words it accepts -- `db_bfs` and `db_relations`' direction,
  `ledger_path`'s cost model -- from the builtin's own list, and a new
  `builtinArgChoice` rule warns about a string literal outside it before the
  program runs. It compares the way the builtin does, ignoring case and
  surrounding space, and looks only at literals.
  `mutant.lint.rules.builtinArgChoice.severity` sets it.

- **The editor knows what the case builtins refuse.** Four new lint rules, each
  a warning by default, report a call the run time refuses, in its own words,
  before the program runs and asks for a passphrase. `roleLiteral`: a role
  `case_open` or `ledger_open` refuses -- a word that is not a role, a
  recipient's role such as `legal`, or `unasserted`. `filteredLedgerHandle`:
  the handle `ledger_under_view` returns, passed to a builtin that does not read
  under a view. `secretOption`: an option named `passphrase`, `password`,
  `secret` or `key`, which those builtins refuse by name. `lifecycleState`: a
  state `case_transition` never moves a case to, naming the builtin that does.
  Each reads what the builtin package exports -- `RoleOptionBuiltins` and
  `ExaminerRoleRefusal`, `RefusesLedgerViewHandle`, `SecretOptionRefusers`,
  `CaseMoves` -- and tests that read the package's source or call every builtin
  concerned hold each to the code, so none can warn about a call the run time
  accepts. `mutant.lint.rules.<rule>.severity` sets each.

- **A record's key is erased, and so is the case's, and a case is disposed of.**
  `record_erase(ledger, path, reason, options?)` overwrites the record key in
  one copy's header with zeros as wide as it, forces the write to the disk,
  reads it back, and records the erasure in the case's ledger with the file's
  digest before and after; `{"preview": true}` checks everything and writes
  nothing. It destroys that copy's key and nothing else, and its
  `does_not_erase` field says so: every other copy still opens with the case
  key, and a grant already issued still opens the segments it names.
  `case_key_erase(ledger, key_path, reason, options?)` is the erasure that
  reaches every copy: it overwrites the key file and removes it, or with
  `{"generation": n}` erases one earlier generation in the file. Both are
  recorded by an examiner acting as a case_owner or an administrator, and both
  are refused under a legal hold. `case_transition(ledger, "disposed", reason)`
  disposes of a retained case once no hold is in force, the retention period
  has run, every exhibit is returned or disposed of and the case key is erased,
  and a refusal names everything still missing. `erasure_list` reads the
  erasures back with the ledger alone, `record_verify` reports an erased copy
  as `erased` -- its signature no longer holds, because it covered the bytes
  the erasure overwrote -- and `case_key_fingerprint` says which generations
  are erased. The lifecycle reader refuses a move the lifecycle does not have.

- **A case is reviewed, and kept.** `review_request(ledger, subject, note,
  options?)` asks for a review of the attached case, of one of its records or of
  one of its redaction versions, and binds what it asks about by a hash: a
  record by its file's SHA-256, a redaction version by the digest of what it
  releases, and the case by a manifest `case_write` wrote, which must still hash
  to its seal and have been written with the case where it stands -- the
  manifest a run renders in memory changes each time it is looked at. A review
  of the case moves it from active to in_review, and `review_decide(ledger,
  request, decision, reason)` concludes it or sends it back; a decision is
  recorded by an examiner acting as reviewer who did not ask for the review,
  and a request is decided once. `retention_set(ledger, until, basis)` retains a
  concluded case until a date, and `retention_hold(ledger, reason, options?)`
  places a legal hold, on the examiner's own authority or one they name: while
  a hold is in force `evidence_dispose` refuses, until `retention_release` lifts
  it. `review_list` and `retention_list` read both back with the ledger alone, and
  `case_transition` refuses the moves the review and retention builtins make,
  naming the one that makes each.

- **A ledger's older redactions can be reviewed.**
  `ledger_redactions_review(ledger, through_seq, reason)` records that an
  examiner has answered for the ledger's redactions, up to a sequence number,
  that were recorded with no role, by a build that may not have refused a
  redaction of a disclosure record. Each review is the next event of the
  ledger's one hash-linked chain of reviews. `ledger_redactions` marks each
  redaction still in question `unguarded` and reports `reviewed_through`,
  `unguarded_redactions`, `reviews_intact` and `reviews_reason`;
  `disclose_history`, `disclose_for_segment`, `disclose_reclassified` and
  `redaction_versions` report `unguarded_redactions`. See Security.

- **A record can be searched as one of its readers could read it.**
  `record_search(record, pattern, options?)` finds a literal -- BYTES, or a
  STRING's UTF-8 bytes -- in what one reader of a record could read. Opened
  under a grant, that is the segments the grant opens; opened with the case
  key, the search must name a view and reads exactly the segments a grant under
  it would open, the partition `view_preview` reports. No other segment is read
  from the file. A match that would need even one byte the search did not read
  is never reported, and every offset the pattern occurs at is, overlapping
  ones included and across segment boundaries, in time proportional to what
  was read. Each hit carries its offset, the segments and classes it lies in,
  and a `context` of up to `context` bytes either side (default 32, at most
  4096), clipped where the readable bytes stop and never zero-filled, and
  marked like a read's output: the sinks refuse it and `record_release` lets it
  go. `count` is every match, `hits` the first `max_hits` of them (default 100,
  at most 1000), `complete` whether every segment was searched, and a segment
  the reader should open and cannot is listed in `failures` rather than
  counted as withheld. `ignore_ascii_case` folds ASCII capitals and nothing
  else. The open case's timeline records every search, with the pattern only
  as a digest keyed to the case key -- a bare SHA-256 of a guessable term would
  confirm every guess -- and with no case key open, in no form at all. Literal
  only: a regular expression read a segment at a time would miss matches
  without saying so. The editor's `classifiedPlaintext` rule warns about a hit,
  or its context, handed to a builtin that refuses it.

- **A script's ledger nodes can be classified, and the ledger read under a
  view.** `ledger_classify(ledger, node, classes, reason)` records which of the
  open case's declared classes a node a script wrote holds -- one, several, or
  none, which no view shows -- as a hash-linked chain of that node's
  classifications in the ledger. The chain names the node by id and no edge
  joins them, so a classified node can still be redacted.
  `ledger_classifications(ledger, node?)` lists them with the views that show
  each node, and with the ledger alone lists every case's.
  `ledger_under_view(ledger, view)` returns a second handle through which
  `ledger_node`, `ledger_edge`, `ledger_provenance`, `ledger_path`,
  `ledger_subgraph`, `ledger_patterns`, `ledger_query_nodes` and
  `ledger_prove_node` show only what the view shows: the script nodes
  classified within the classes it grants, the case's Case and Record nodes,
  the Classification nodes it grants, and the edges among them. No walk crosses
  a node the view withholds, a withheld node and one the ledger never held get
  the same answer, and nothing counts what was withheld. Every other builtin
  that takes a ledger refuses the handle by name, and `ledger_close` drops it.
  It is not access control: the program holding it holds the ledger's own
  handle too.

- **A disclosure is issued against the recipient's role.** `role_define(role,
  views)` gives a recipient role -- `legal`, `external_partner`,
  `restricted_viewer`, or `reviewer` or `auditor`, who are on both sides -- its
  bundle: the views it may be granted, possibly none, which it then says in
  `grants_nothing`. `role_assign(ledger, recipient, role, reason)` records that
  a named recipient holds one, or ends it with `none`, as a hash-linked chain of
  their assignments kept apart from the examiners', and `role_list(ledger?)`
  reports the bundles and who holds which role -- with the ledger alone, every
  case's. A bundle defined while the case is attached is written into its
  ledger and read back by a later attach. Roles are asserted, like an
  examiner's: a refusal a role causes keeps the record consistent, and the
  passphrase on a grant is still the only thing that stops anybody reading.

- **Redaction versions.** Every disclosure names the version of its record's
  redaction under its view -- what the view releases from the evidence, as
  plaintext byte ranges -- in a hash-linked chain per view that follows the
  evidence through its reclassifications. A version is written only when what
  the view releases changes, by the disclosure that first issues it or ahead of
  one by `redaction_commit(ledger, record, view, reason)`, so that it can be
  reviewed first. `redaction_versions(ledger, record_uid)` lists them with the
  disclosures issued under each, and calls every disclosure issued under a
  version since superseded `stale`. It needs no case open.

- **An exhibit has a custody chain.** `evidence_intake(ledger, exhibit, path)`
  takes a file into the attached case: it is hashed with SHA-256 whatever the
  case's hash policy, written into the ledger as an EvidenceFile node that
  belongs to the case, and held by the examiner who took it in.
  `evidence_release(ledger, exhibit, to, reason)` hands it to another examiner
  the case assigns, and `evidence_accept(ledger, exhibit, path)` records them
  taking it after hashing what they were handed: a file that does not match the
  intake is refused, and nothing recorded, unless they state what happened with
  `{"discrepancy": ...}`. `evidence_return` returns an exhibit out of the case;
  if it comes back, `evidence_intake` takes it in again under its own name, as
  the next step of the same chain, and holds what came back to the same test
  against the first intake. `evidence_dispose` records a disposal, by a
  case_owner or an administrator; a disposal deletes nothing and is final. The
  steps form a hash-linked custody chain every reader checks -- down to each
  hand-off being recorded by the holder the ledger names, each accept by the
  person it was released to, and each hash check agreeing with its own
  digests -- and `evidence_history(ledger)` reads every exhibit's custody back
  with no case open. A new exhibit is refused while the case is in review,
  concluded, retained or disposed; the movement of one already taken in, a
  returned one coming back included, is refused in no state.

- **A case keeps its state in its ledger.** `case_attach(ledger)` binds the open
  case to a ledger. The first attach registers it -- a Case node, a `registered`
  lifecycle event and the examiner's assignment -- and a later run's attach
  reads back its lifecycle state, every examiner's latest assignment, and the
  classes and views declared under the open key generation, tagging each class
  again and refusing a ledger whose tag the key does not give. While attached,
  `class_define` and `view_define` write through to the ledger, answer a
  definition read back with `already_defined: true`, and report `in_ledger`;
  `class_list`, `view_list` and the manifest say where each came from, and the
  manifest gains a `ledger_state` block. `case_transition(ledger, to, reason)`
  moves the case from registered to active and reopens a concluded one, and each
  state refuses what it cannot take: in review, sealing, definitions,
  reclassifications and disclosures; concluded or retained, sealing; disposed,
  everything but a withdrawal and the movement of an exhibit. `case_assign(ledger, examiner, role, reason)`
  records a role in the case or ends one with `none`, and `case_attach` refuses
  an examiner the ledger assigns no role or a different one. Lifecycle events
  and assignments are hash-linked chains, and a fork is refused by every reader.
  The ledger's label table now also names the labels the rest of the case
  builtins will write, so their numbers are fixed before anything uses them.

- **Roles are recorded.** `case_open` and `ledger_open` take `{"role": ...}`:
  one of administrator, case_owner, lead_investigator, investigator, reviewer
  or auditor. A ledger opened by the case's examiner takes the case's role
  unless it names its own, and `ledger_open` reports `role`, `role_id` and
  `role_source`. The role is stamped on every case timeline entry, written into
  the manifest beside `role_authenticated: false`, kept by graphene on every
  redaction record, and written on every Disclosure, Withdrawal and
  ReclassEvent and on their PERFORMED_BY edges. It is never checked. Three
  refusals keep the record consistent with it, and each says it is not access
  control: a recipient role (legal, external_partner, restricted_viewer) cannot
  be asserted by an examiner, one examiner cannot hold two roles in one
  process, and a ledger opened as auditor refuses every write -- the four
  redactions, `ledger_add_node`, `ledger_add_edge`, `ledger_compact`,
  `ledger_checkpoint`, `disclose_to_passphrase`, `disclose_withdraw` and
  `disclose_reclassified` -- and cannot create a ledger that does not exist.
  A script's own `ledger_add_node` or `ledger_add_edge` commit records the actor
  and not the role: graphene v0.9.0 keeps no role on a commit, and Mutant passes
  it anyway so a graphene that does will record it.

- **The editor says what a macro body may not do.** A new `macroSafety` lint
  rule, a warning by default, reports a builtin a macro body calls that the
  compiler refuses while expanding it -- one that reads or writes a file, reaches
  the network, starts a process, draws entropy, reads the clock, decodes
  cryptographic material, or answers from state something else set. It repeats
  `builtin.MacroRefusal`, the sentence the expander itself prints, so the two
  cannot come to say different things, and it names the spelling the author wrote:
  `fs.write` for the dotted form, `fs_write` for the flat one. Nothing inside a
  `quote(...)` is reported, because that is the source the macro emits rather than
  code the compiler runs -- and an `unquote(...)` inside one is, because that is
  the compiler running again. Expansion stops at the first refusal, so a build
  names one of them where the editor names them all.
  `mutant.lint.rules.macroSafety.severity` sets it.

- **`exec_argv(argv)` runs a program with exactly the arguments given, and no
  shell in between.** The first element names the program and the rest reach it
  as they stand, so a value in one is a single argument however it is spelled --
  a space does not add a word and a `;` starts nothing. It is where a shell
  `exec_string` does not know the flags for is reached, by writing the
  invocation out: `exec_argv(["zsh", "-lc", cmd])`, or `exec_argv(["fish",
  "-c", cmd])`. It is also the way to run a program with no shell at all, which
  is the better choice wherever a value has to reach a command line. A program
  that is not installed is reported in the result's `error` field with an exit
  code of -1; an argv that is not an array of strings, or that names no program,
  is a caller mistake and comes back as an error object. The same attempt
  record, the same timeout and the same output cap apply as to `exec_string`, so
  it is not a way around the command controls.

  `commandInjection` knows about it, and reports the one shape where an element
  is not just an argument: a value spliced into an element that follows `-c`,
  `-lc`, `/C` or `-Command`, which tells the program to read a command from the
  next element. It looks at the flag and not at the program, because there is no
  closed set of shells left to recognise. A spliced element with no such flag
  before it is not reported, because that is the whole point of the builtin.

### Changed

- **A bare `--password` is refused.** 2.5.0 warned on it and promised the next
  minor release would require the explicit opt-in; this is that release.
  `--password` and `--pwd`, in every spelling and on every command, stop the run
  before anything compiles, runs or is written, and the refusal names what to
  use instead: the prompt (the default), `--password-file`, `--password-stdin`,
  or `--password-insecure <value>` for someone who accepts that argv is readable
  by every local user. The `--dev` refusal on `release` no longer recommends the
  flag. The example sweep passes `--password-insecure`, and the VS Code
  extension's task `password` field now does too.

- **The language server reports the language release it teaches.** Its
  `serverInfo.version` was the constant `0.1.0`, a version nothing here ever
  had; it is now `global.Version`, the same string `mlsp --version` prints.

- **`object.LuaPatch` no longer carries `DecryptedChecksum`.** The field was
  documented as set after decryption for validation, but nothing set it or read
  it, and storing the value in a variable would have dropped it anyway.
  Validation happens where a patch runs, against `ChecksumExpected`. A new test
  stores and reloads every object type with every exported field set, which is
  how this was found and how the next dropped field will be.

- **Every `github.com/aoiflux/*` dependency is on its latest release.**
  `libext` v0.2.0 -> v0.3.0, `libfat` v0.2.0 -> v0.3.1, `libhfs` v0.2.0 ->
  v0.3.2, `libntfs` v0.3.1 -> v0.3.3, `libvhdi` v0.2.0 -> v0.3.0, `libxfat`
  v1.2.0 -> v1.4.0, `libxfs` v0.3.1 -> v0.4.1, and `graphene` v0.4.0 ->
  v0.9.0, which moved on its own with the namespace-fold fix below. `libewf`
  v0.2.1 and `libtable` v0.2.2 were already current. No transitive dependency
  moved.

  Six of the seven needed no code change: nothing exported was removed from
  any of them, and the four documented breaking changes land on API Mutant
  does not call -- `libntfs`'s `Options.BaseOffset` (never set here), the
  `libvhdi` `vhdimap.ByteRange` coordinate space, `libfat`'s `FATReport`
  offsets, and `libhfs`'s report keys and package clause, which an aliased
  import is immune to.

- **`xfat_read_file` no longer writes the file it is reading to a temp
  directory.** libxfat extracted only to a path, so an exFAT file's content
  round-tripped through `os.CreateTemp` to be read straight back -- the bytes
  of an evidence file, written to shared storage, to answer a read. v1.3.0
  added a reading API and the round trip is gone.

  The error behaviour is deliberately unchanged: a chain that runs out before
  the entry's recorded length is still an error rather than a silently shorter
  file, and it still wraps libxfat's `ErrTruncatedChain`. `ReadEntry` alone
  would have returned the short content without saying so, which is why the
  entry is opened and `Located()` checked instead.

  This retires one of the two entries in `policy.EvidenceWriteAllowlist`. The
  guard failed the moment the write went away, which is what the allowlist is
  for; see [docs/EVIDENCE_HANDLING_POLICY.md](docs/EVIDENCE_HANDLING_POLICY.md).

- **A deleted entry's `name` from `xfat_list_files` and `xfat_metadata` no
  longer ends in `" (deleted)"`.** libxfat stopped decorating the name in
  v1.3.0. The decoration was presentation inside the parser: it produced a
  name that could not be compared against the same file seen live, against
  another tool's output, or against an earlier reading of the same volume, and
  it landed in every composed path. The `deleted` key already carries the
  fact, and a script that wants the old rendering appends the string itself.

  The `has_fat_chain` and `indexed` keys keep both their names and their
  meanings, although the methods behind them were renamed and one had its
  sense inverted upstream.

- **`table_open`'s warnings are records, not sentences.** Each warning is now
  `{code, message, lba}`, beside a deduplicated `warning_codes`, where it was a
  string. The prose is written for a report and reworded between library
  releases, so a script that matched on it stopped matching without being told.
  A script that printed the old strings reads `w["message"]`; one that matched
  on them should branch on `w["code"]` instead.

- **The editor resolves names the way the compiler does.** Deciding what a name
  refers to moved into one walk in `sema` that the compiler, the language server
  and `mutant lint` share, replacing five separate resolvers in the server and a
  sixth scan that patched the gap they shared. `stats.mean` now has
  go-to-definition, hover, completion, find-references and rename across every
  importer, under whatever alias each file chose, and call hierarchy finds
  callers in files nobody has opened. Cross-file answers are scoped to the import
  closure rather than to every file in the workspace, so go-to-definition no
  longer jumps into a module nothing imported. A new `unusedImport` rule reports
  at information severity, since an imported module's top-level statements run
  whether or not its namespace is read. `mutant lint` builds the same workspace
  the editor holds rather than reading one file at a time.

- **`case_open`, `case_evidence` and `case_write` refuse an option they do
  not take.** They used to read their one option (`hash`, or `sign`) and
  ignore everything else, so `case_open(id, examiner, {"hash_policy":
  "sha256"})` opened a case that digested nothing, and `{"signed": false}`
  signed. An unknown key, an options argument that is not a hash, and a value
  of the wrong type are now errors. Every `case_*`, `class_*`, `record_*` and
  `view_*` builtin with an options hash also refuses a key named `passphrase`,
  `password`, `secret` or `key` by name, before it looks at any other argument,
  as DISCLOSURE_POLICY section 8 says; only `case_key_*` did before.

- **`sandbox_status` reports only probes that measure something.** Three of its
  probe signals measured nothing: `acpi_pci` and `gpu_feature` answered "not
  implemented yet", and `ld_preload` answered "env-based preload checks
  disabled". They are no longer probes. `acpi_pci` re-reported what
  `cpuid_hypervisor` already reports, and `ld_preload` could never see anything
  in a statically linked build, which never runs the dynamic loader
  `LD_PRELOAD` works through.

- **A probe that did not look says so, and so does process protection.** The
  six probes that read Windows process structures answered "not supported on
  this platform" elsewhere with `detected: false`, the same shape as a clean
  result. All five probes of the runner's process protection are among them, so
  on Linux and macOS that stage looked at nothing and passed without a word.
  Every probe signal in `sandbox_status` and `debug_status` now carries
  `measured`, which is false for a probe that could not run or whose check
  failed, and a run whose process protection measured nothing says so once on
  stderr. Process protection runs on Windows only, and the docs now say so.

- **`db_add_relation` stores its relation.** It used to add a plain edge and
  send the relation only to `db_timeline`'s journal, which lives in the process
  and is cleared by `db_close`, so a reopened store -- or any reader but the
  program that wrote it -- held the edges with no relation at all, while the
  reference said they were labelled. The edge and its relation now land in one
  transaction, the relation indexed on the edge where `db_relations` and
  `db_schema` read it back. It takes an optional `attrs` hash, stored beside the
  relation as `attr_<key>` and refused if it holds classified plaintext, and it
  refuses an empty relation, one that is not valid UTF-8, and a node that does
  not exist. **Stores written by earlier releases cannot be repaired:** the
  labels were never in them, and `db_relations` reports those edges with
  `relation: null` and counts them as `unlabelled`.

- **`db_bfs` refuses a direction it does not know.** Any word other than `in`
  or `out` used to mean `both`, so a misspelled `"outbound"` walked every edge
  both ways and reported nothing wrong; a negative depth was walked as zero.
  Both are errors now, and `OUT` or ` out ` are read as `out`. It returns every
  edge it crosses: graphene's walk keeps one edge per neighbour, so of three
  relations from a process to one file it returned one. It runs under the same
  fixed traversal budget as the `ledger_*` walks, and is refused rather than cut
  short when it reaches it.

- **`db_shortest_path` returns an empty array for two nodes that are not
  connected,** as its documentation always said; it returned an error. A node
  that does not exist is still an error, and now says which argument named it.
  It runs under the traversal budget, and its documentation says what it always
  did: it walks edges in either direction.

- **An attribute key that is not a string is refused.** `db_add_artifact` used
  to skip such a key, and reported the node with fewer properties than the
  script gave it and nothing to say which had gone.

- **`ledger_open` takes an options hash, and the one option is the role.**
  The posture stays out of reach: `sign`, `strict`, `retention` and every other
  key are refused before anything is opened. `ledger_redactions` and the four
  redaction builtins report each record's `role` and `role_id` and where its
  actor's name came from (`actor_source`), and `disclose_history` reports the
  role each disclosure and withdrawal was made under.

- **`disclose_to_passphrase` needs the recipient to hold a role whose bundle
  holds the view.** A disclosure to a recipient the ledger assigns no recipient
  role in force, whose role has no bundle, or whose bundle does not hold the
  view is refused -- before any key material is derived or any passphrase asked
  for, and again under the ledger lock before the write. A script that
  disclosed before 2.6.0 needs a `role_define` and a `role_assign` first;
  `examples/forensics/record_disclosure.mut` shows both. The grant is still
  exactly the view. The recipient's role, the assignment, the bundle and the
  redaction version the disclosure carries out are recorded in the ledger, the
  case manifest, the package and `disclose_history`, and `disclose_verify`
  checks the package's role and version against the ledger's record.

- **The ledger's walks, matches, queries and proofs say which view answered.**
  `ledger_provenance`, `ledger_path`, `ledger_subgraph`, `ledger_patterns`,
  `ledger_query_nodes` and `ledger_prove_node` return `view`: empty on the
  ledger's own handle, and under a handle from `ledger_under_view` the view's
  name, because there `complete`, `found` and `stopped_at` are claims about what
  the view shows. `ledger_close` takes such a handle and drops it, leaving the
  ledger open.

- **A Rego policy is no longer offered the builtins that reach the network: `http.send`,
  `json.match_schema` and `json.verify_schema`.** `policy_load`, `policy_eval`, `policy_allow`,
  `policy_rules` and `policy_trace` refuse a policy, or a query, that calls one, before anything
  is evaluated. `http.send`'s client took its proxy from `HTTP_PROXY`, `HTTPS_PROXY` and
  `NO_PROXY` and its timeout from `HTTP_SEND_TIMEOUT`, and `policy_load` evaluates a policy to
  validate it, so loading one was enough to send a request wherever the environment pointed it
  (M26-DAT-030). The two schema builtins fetch a schema's remote `$ref` through the same proxy
  (M26-DAT-032), and cannot be offered without it. Fetch with `http_get` and pass what it
  returns in the policy's input.

- **An artifact's header may ask for no more Argon2id work than the costliest derivation in the
  tree.** A password-encrypted artifact carries its key's Argon2id cost, and the runner pays it
  before anything in the artifact has been authenticated; the header could ask for eight passes
  over 4 GiB in sixteen lanes. It may now ask for at most three passes over 256 MiB in four
  lanes -- what a case-key or grant file costs -- and for no less memory than the 64 MiB the
  generator writes. Every artifact a Mutant build has written asks for one pass over 64 MiB, and
  still runs (M26-LIM-010).

- **The limit guard's budget lists each unnamed limit, and the limits of `security/` and
  `runner/` are named.** `policy/limit_budget.go` holds the findings the tree still carries by
  rule, function and expression rather than as a count per file, so naming one limit can no
  longer make room for a new one beside it (M26-LIM-005). A value counted in kibibytes,
  milliseconds or microseconds says so, and the limits reference prints it as the size or time
  it is. The record format's bounds, the anti-tamper thresholds, the Argon2 band and the command
  and remote-scan scores are named with their reasons, the record format's fixed sizes are marked
  as format facts, and two remote-scan fields and two tamper-delay bounds that nothing read are
  gone. The names change no compiled instruction.

- **`mutant fmt` and format-on-save keep the brackets you wrote, and add none.** The formatter
  printed every operator expression inside its own pair of brackets, so `putf("a=" + b + "\n")`
  came back as `putf((("a=" + b) + "\n"))`, and once a file was formatted the brackets it had
  added could not be told from the author's. The parser now records which expressions were
  written inside brackets, and the formatter prints those and no others; a doubled pair prints
  as one. Six examples that format-on-save had bracketed in 7e7ca13 lost the brackets it added,
  and parse to the same trees as before (M26-LSP-030).

- **A block is a scope, and a `let` has to declare something new. BREAKING.** A
  name declared inside `{ ... }` now means nothing after the closing brace, and
  may shadow a name from outside it. Every brace-delimited region is one: a bare
  block, an `if` or `else` body, a loop body, a `match` arm. A loop header is a
  scope with the body nested inside it, so a body may shadow the name the header
  declared; a function's parameters and its body share one scope, so a `let` at
  the top of a body cannot take a parameter's name. The rules are Go's, measured
  against the Go compiler rather than read off the specification.
  Within one scope, a `let` is refused unless at least one of the names on its
  left is new to that scope — which is Go's rule for a short declaration, and is
  what makes the `(value, err)` idiom work rather than a special case for it:
  `let head, err = read(a); let tail, err = read(b);` is fine because `tail` is
  new, while `let x = 1; let x = 2;` is refused and `x = 2` is what was meant. A
  parameter list naming one parameter twice is refused for the same reason. The
  blank is always allowed, however many times.
  One deviation from Go, and it is deliberate: in Go, `_, err := f()` with `err`
  already declared is an error and the remedy is `_, err = f()`. Mutant has no
  multi-target assignment, so refusing it would offer no legal way to write
  "call it and keep the error" — 27 lines of one shipped example. A blank on the
  left therefore counts as new. Adding `_, err = f()` would close the gap and is
  the only part of Go's rule Mutant cannot yet express.
  What this costs: a program that declared a name inside a block and read it
  after the block closed no longer compiles, and neither does one that threads a
  single handle through a pipeline by rebinding it. Measured across the 123
  shipped example programs, two needed a change — each declared `ok, err` twice
  at one file's top level — and both are clearer for it, since one `ok` for two
  different keys discarded the first answer before anything read it. The editor
  agrees with the compiler because it reads scope out of the same walk: a block
  shadow is no longer reported as a duplicate declaration, and a real duplicate
  now is. Nothing about the bytecode, the opcodes or a frame's layout changes.

- **`exec_string` and `cmd_builder` accept any shell the host has, by name.**
  `powershell`, `pwsh`, `cmd`, `batch`, `bash` and `sh` keep their own
  invocations, where `-c` would be wrong or where the executable is not the
  name. Any other bare name -- `zsh`, `dash`, `ksh`, `mksh`, `fish`, `nu` -- is
  given the command with `-c`, which is the one convention every POSIX shell
  shares and which fish, csh, tcsh, nu and xonsh share with them, so no list
  here has to be kept correct for a shell nobody here has tried. A shell whose
  flag is not `-c` is reached through `exec_argv` instead. A shell that is not
  installed is reported in the result's `error` field, as it was before.

  What is refused is a value that is not a shell name: a path like `/bin/sh`, or
  a command line like `sh -c`. Either would have been looked up as one long file
  name and come back as not found, which reads as "that shell is not installed"
  when the argument was never a shell name -- so it now says which of the two
  went wrong. This widens the `-c` part of the fix recorded under Fixed below,
  which reached `bash` and `sh` only.

### Fixed

- **`go run ./cmd/gendocs -check` answers for the hand-written documents too.**
  It compared the three artifacts it generates and nothing else, and reported
  `docs/CAPABILITY_REFERENCE.md is up to date` in the same words whether or not
  the documents around it agreed with the registry. Those go stale separately,
  and regenerating the artifacts is the act that makes them stale: on
  2026-10-06 a new builtin took the count to 694, all three artifacts were
  regenerated and current, `-check` reported all three up to date, and
  `go test ./...` failed three tests in `cmd/gendocs` on the commit itself.
  Seven sentences across six documents still said 693, and the category index
  still gave Command Execution 4 builtins and linked to
  `#command-execution-4`, an anchor that stopped existing the moment the
  heading it names was regenerated as `## Command Execution (5)`.

  The prose counts, the per-category index and every document link were already
  checked, by tests in `cmd/gendocs`. They are no longer written there: they
  live in `cmd/gendocs/consistency.go`, and the tests and `-check` are two
  callers of one implementation, so the tree `scripts/release_gate.sh` and
  `scripts/release_gate.ps1` call consistent is the tree the suite calls
  consistent. Each check also reports what it examined -- so many claims, rows
  and links -- because a check whose scope nobody can see is one a reader reads
  too much into, which is how "the generated reference is up to date" came to
  be heard as "the documentation is up to date". A check that matches nothing
  now fails instead of passing, and eight tests point each check at a tree that
  is wrong on purpose, because "the check runs" is not the claim that mattered.

  Writing mode reports them as well, and exits non-zero when any is wrong. That
  is where the information is worth most: the count gendocs has just generated
  is the count a sentence elsewhere now contradicts, and it can name the file
  and the line to edit rather than leaving it to a five-minute suite run, or to
  a reader. Adding or removing a builtin is a documentation change in about
  eight places that nothing generates, and this lists them.

- A `let` initializer no longer reads the binding it is about to create, and a
  loop whose body redeclares the loop's own name no longer hangs. Both were one
  cause: nothing in the language was a scope except a function literal, so
  `Define` allocated a fresh slot and overwrote the name, and the name meant the
  new slot from the first line of the statement that declared it. Inside an
  initializer that read a slot the statement had not yet written — null at the
  top level, and whatever an earlier call left in the frame at that offset
  inside a function, which is why the wrong answers were plausible numbers.
  `let total = 10` shadowed in a closure printed 301 after an unrelated call,
  `let len = len(xs)` printed the argument array and then `%!d(string=)`, and
  `let s = s + 1` over a parameter faulted in the VM. Worse, a `for` statement
  compiles its post section after its body, so once the body redeclared the
  counter, `i++` incremented the body's slot while the condition went on reading
  the original: `for (let i = 0; i < 3; i++) { let i = 9; }` never terminated,
  and nothing reported it. The tree-walking engine answered 1 for the same
  program, from one name-keyed environment. Both are fixed by scoping blocks
  correctly rather than by refusing them, so that program now terminates and
  answers 3, which is what Go answers. The initializer reordering is also Go's
  rule — a declared name's scope begins after its declaration — and it takes one
  thing away: a brand-new name can no longer reach itself through a call, so
  `let step = wrap(fn(n) { return step(n - 1); });` is `undefined variable:
  step`, which is what Go says about the same shape. Direct recursion is
  untouched. See the entry under Changed for the scope rules. (M26-CMP-001)

- A `break` or a `continue` written inside a function no longer escapes the call
  and drives the caller's loop. The compiler refuses such a signal — a function
  body is a loop boundary — but the tree-walking engine ran it and let the
  signal leave the call as the call's *value*: `unwrapReturnValue` unwraps only a
  return, so a break fell straight through and the loop around the call obeyed
  it. `for (let i = 0; i < 3; i++) { let f = fn() { break; }; f(); out = out + 1; }`
  answered 0 where 3 is right, and the same held for `continue`, for `while` and
  for `for ... in`; with the closure never called the answer was 3, which is what
  showed the signal only escapes when the call runs. That mattered beyond the one
  engine, because `mutant gen` runs macro definition and expansion for every
  module with no flag behind it, so an `unquote` argument is user code the
  tree-walker executes before anything is compiled: a macro whose argument ran
  that shape spliced the literal 0 into the program, which then built and printed
  it with exit 0 and no diagnostic. A function body is now a boundary in both
  engines, the escaping signal is reported rather than returned, and macro
  expansion names the macro it happened in. The sentence itself moved into `sema`
  beside the other refusals, so the two engines cannot drift into two phrasings
  of one rule again — which is what this defect was. (M26-EVL-023)

- **The allocation bounds in `builtin/` measure the parser rather than the
  process.** Six tests assert that a count written in a file's header cannot
  size an allocation, and each measured it by reading
  `runtime.MemStats.TotalAlloc` across the call. That counter is process-wide and
  cumulative: everything allocated between the two readings lands in the
  difference, by any goroutine and by the runtime itself. Against bounds as small
  as 1 MiB it was mostly other people's memory, so the same tests passed when run
  alone and failed in a full `go test ./builtin`. That is the worst way for a
  test to fail — a gate that is red on a correct tree teaches people to ignore
  red — and two staged fixes could not be gated at all while it was.

  How far off the figure was is worth recording. `TestABinaryPlistIsNotSizedByItsCounts`
  failed at 1,998,144 bytes on a tree where the fix was correct, and the parse it
  measures allocates 8,312. More than 99% of what it asserted on had nothing to
  do with the code under test.

  Each one now runs the same parse over two fixtures differing only in the number
  written in the header, and bounds the difference rather than the total: the
  difference cancels the parse's own cost, which turns the assertion into whether
  the declared count decides the size, and the lowest of several readings is
  taken because contamination can only ever add. Measured under a full package
  run, four of the six differences are exactly zero and the largest is 31 KiB
  against a 4 MiB allowance, where the defects these tests exist for cost between
  16 MiB and 900 MiB.

  The twin is a wrong count too rather than a valid one — two objects where the
  file holds one, two array references, one entry rather than 2^20, sixty-four
  bytes of record in a forty-byte capture, a header field of twice the budget —
  so both measurements are of the same refusal and the difference between them is
  the cost of the number alone. Each test fails loudly if its twin is ever
  accepted, because from that point the difference means nothing.
  `builtin/allocation_gap_test.go` carries the reasoning, and the DestList bound
  was found by this pass: it had the same defect and was in neither inventory.

- **`plist_parse` no longer returns a value a binary plist does not contain.**
  The declared object count was checked against the bytes from the offset
  table's start to the end of the file, and the last thirty-two bytes of a
  binary plist are the trailer, which is not table. The check therefore handed
  the table the trailer's own bytes as room for offsets, so a file could declare
  up to `32/offsetIntSize` objects more than its table holds and the offsets for
  those were read out of the trailer. On a forty-five byte file with four-byte
  offsets the table holds exactly one entry and nine objects were allowed; with
  the top object pointing at one of the eight phantoms, `plist_parse` returned a
  two-character string decoded from the trailer's bytes and no error at all.

  A refusal would have been fine and a dropped value would have been bad. A
  confident answer about an artifact that the artifact does not contain is the
  one outcome a parser here may not have, and the input is exactly the kind an
  examiner is handed rather than writes. The bound is now the room the table
  really has, which refuses nothing real because a well-formed plist puts its
  offset table immediately before the trailer. (M26-ART-035)

  It was found by the entry above, and that is the useful part. The small twin
  for the differential measurement was a count of two, chosen because it should
  have been refused for the same reason 2^24 is; the test asserts that its twin
  is refused, because otherwise the two measurements are of different code paths
  and their difference means nothing. That assertion failed, which is how a
  parser that fabricates data came to light from a change to how memory is
  measured. The field had already been reviewed once, under M26-ART-005, and
  this half was missed: the check's own comment stated the flawed premise.

- Calling a name that has no value is reported instead of crashing the
  tree-walking engine. Macro definitions are removed before anything runs, but
  only the top-level ones, so a `macro` literal nested inside an `unquote`
  argument survived into code the tree-walker executes — and that engine has no
  case for a macro literal, so the name was bound to nothing and calling it
  dereferenced it. `mutant gen` died with a nil pointer dereference on a program
  that is only a few lines long. It now says that a macro definition must appear
  at the top level, where it is expanded before anything runs, which is both what
  went wrong and what to do about it. The compiler already refused the same
  nesting, so only the expansion path was exposed. This is the tree-walking half
  of M26-VM-003, which was fixed in the VM.

- **The disclosure policy promised an erasure nothing performed.** It said
  crypto-erasure was available and listed it among the operations, and no
  builtin erased or rewrapped any key. `record_erase` and `case_key_erase` do
  now, and sections 3 and 7 say what each destroys and what it cannot reach:
  destroying one record's key is not enough while copies of the record exist.

- **A withdrawal could leave its examiner unable to write to the ledger.** A
  disclose_* write finds an Actor, Record, Class or View node the ledger
  already holds before adding one, and asked only the ledger -- which cannot see
  a node added earlier in the same transaction. So `disclose_withdraw` on the
  examiner's own authority, its default, by an examiner the ledger held no
  Actor node for wrote two, and every later disclosure-family write naming that
  examiner was refused as a ledger written to by something else. A transaction
  now finds what it has itself added.

- **`fat_deleted` reported a live file's content as an orphan's, and
  `fat_recover_file` wrote it.** A record the orphan sweep finds sits in a
  deleted directory's freed cluster without its own 0xE5 marker, so libfat
  walked the current FAT from its first cluster -- and when that cluster had
  since been given to a live file, the walk returned that file's chain. The
  scan said `preserved`, `allocation_checked: true`, `reallocated: false`, and
  the recovery wrote the live file's bytes under the orphan's name with no
  caveat. An orphan's chain is as freed as a deleted entry's: it is now located
  for its first cluster alone, as the scope has always said, and `reallocated`
  is read from the allocation table, so a recovery over a reassigned cluster
  carries the caveat that it is most likely another file's content.
  `allocation_checked` is true only when that read succeeded.

- **A `while` or C-style `for` inside a `for…in` broke the outer loop.** The
  compiler stripped the pop after an expression statement that ended a
  condition-driven loop's body, post or init section, so each iteration leaked
  one stack slot. `for…in` reads its cursor at a fixed offset from the top of the
  stack, so its next advance read the leaked value and failed with "loop cursor
  was replaced". Every loop body is stack-neutral again, and
  `vm/loop_nesting_test.go` runs each nesting shape as its own case.

- **`rand.*`, `sort.*`, `assert.*` and `gunzip.*` failed in compiled
  programs.** The compiler's shadow test for `ns.member` also found builtins, so
  the four families whose namespace is itself a builtin's name never folded, and
  compiled a field read on a builtin that the VM can only refuse. Nine builtins
  ran under the evaluator and in macro expansion, failed under the VM, and were
  offered by the editor throughout. The test ignores the builtin scope now, and
  `parity/` holds the two engines to each other on it.

- **`db_add_artifact` was N+1 unchecked writes.** It is one transaction now,
  and a store handle the timeline kept is no longer leaked.

- **Documents that pointed at nothing, taught retired commands, or did not
  compile.** SECURITY.md named 2.4.x as the supported release; three example
  READMEs taught `mutant run` with `-pwd`, which puts the password in the
  process table; four source comments cited a design note that exists nowhere,
  in a directory git ignores; a MODULES.md example elided its bodies with a
  comment syntax Mutant does not have; two links pointed at capability-reference
  anchors that had moved; CONTRIBUTING named the packaging script's old path;
  and four example programs were named by no README. The checks that found them
  are the ones added above, so none of these can come back unnoticed.

- **This file dated 2.5.0 three days before it was tagged, and listed half of it
  as unreleased.** Fourteen entries that shipped in the v2.5.0 tag sat under
  `[Unreleased]`; they are under `[2.5.0]` now, and 2.5.0 is dated 2026-09-17,
  the day the tag was made. The release gate compares the two from here on.

- **NTFS evidence was opened writable.** libntfs promotes any `io.WriterAt` to a
  writable volume, and `*os.File` implements it whatever mode the file was opened
  in, so `ntfs_open` handed the library a volume it could write to. It is opened
  read-only now.

- **Lint rules disagreed with the compiler about which names were taken.** The
  duplicate-declaration rule reported every shadow as a duplicate -- a parameter
  shadowing a `let`, or a value named like a struct -- and offered a quick fix
  that deleted one of two lines the program needed. The builtin rules went
  silent where a struct or enum shared a builtin's name, so
  `struct rand { x; }; rand.int(1, 5);` drew no arity, argument or `(value, err)`
  check. `platformSupport` reported a local value named like a namespace as an
  unsupported builtin. All of them now ask the same graph the compiler builds.

- **Undefined names the build refuses drew no diagnostic, and names it accepts
  drew four.** `struct Point { x }; Point;`, `len{x: 1}` and an enum used above
  its declaration failed the build from files the editor showed clean, while a
  four-line program using a struct, an enum and a macro from an import reported
  all three undefined and the import unused. The evaluator also folded
  `str.upper("a")` to the builtin under `enum str { x }`, where the VM refused
  it; both refuse now, in the same words.

- **The `hardcodedSecret` rule flagged the idiom it recommends.** A name ending
  `_file`, `_path` or `_dir` holding a real path matched both its name pattern
  and its looks-issued check, so an author who had just moved a secret out of the
  source was told to move it out of the source. Those suffixes are exempt.

- **A bad hash algorithm in a `case_open` custody policy was reported as an
  `fs_hash` error**, naming a builtin the script never called. The error names
  the builtin that was.

- **Running a program bounds what it reads.** The runner read the program's
  file whole whatever its size, and inflated its bytecode to whatever size the
  zstd frame declared, so a disk image named by mistake was read into memory
  and a payload of a few hundred bytes could ask for gigabytes. A file over
  1 GiB is now refused before it is read, and bytecode that inflates past
  256 MiB is refused while inflating. Both limits are in
  `docs/LIMITS_REFERENCE.md`.

- **A killed `record_seal` no longer leaves part of a record under the
  record's name.** The record was written in place and removed only when the
  seal saw an error, so a process killed mid-seal left a file with a valid
  header and some of the segments, where a complete record was expected. The
  record is now written beside its name and renamed into place once complete;
  a seal that is killed leaves an empty file, which `record_open` refuses as an
  interrupted seal, and a `.mutant-record-*` file of partial ciphertext.

- **Two ledger reads said less than they knew.** `ledger_query_nodes` on a key
  the ledger's index never held returned an empty answer indistinguishable from
  "no such record" -- a misspelt key, or any of the `disclose_*` family's own
  properties, which that family keeps unindexed. The result now carries
  `unindexed_keys` and `index_keys_known`. `ledger_path` walks edges in either
  direction and did not say when a hop ran against its edge; it now returns
  `reversed_hops` and `directed`.

- **`mutant graph export` reports a store it could not close.** The export
  discarded the store's close error, so an export whose store was never marked
  cleanly shut down still reported success. The close error is now the
  export's error.

- **A ledger or disk graph store the program forgot to close is closed at its
  end.** A store still open when the process exited was recorded by its next
  open as a restart after an unclean shutdown -- in a custody ledger, a
  permanent audit entry for a crash that did not happen. Running a `.mu`,
  `mutant test`, the debugger and the REPL now close every `ledger_open` and
  `db_open_disk` store the program left open, and name each on stderr.

- **`db_open_disk` reads a store's label table before opening it.** graphene
  registers a store's label names for the whole process, and `db_open_disk`
  opened any directory. Opening an exported symbol graph let `db_add_node`
  write nodes under the label the graph names `Module`, which `mutant graph
  query` then could not decode; opening a store that named a disclosure-ledger
  label differently made every later disclosure, withdrawal and
  reclassification in the run fail. A table that names the custom labels 0-127
  `db_*` writes, renames a disclosure label, or is torn is now refused before
  anything is opened.

- **`db_index_prop` reported success on a node that does not exist.** graphene
  does not look for the node before indexing it, so a mistyped or stale id wrote
  an entry pointing at nothing. It now looks the node up first and refuses by
  name.

- **Every disclosure write rewrote the ledger's label table.** The disclosure
  family's label names were written and fsynced beside the ledger on every
  disclosure, withdrawal and reclassification. They are now written on the
  first of these after each `ledger_open`. Asking about a reclassification that
  is already recorded went from about 4 ms to about 14 µs.

- **Four examples reported the wrong numbers, and their recorded output locked
  them in.** `mini_timeline_builder` indexed `fs_stat`'s error field for every
  file, which is null for a file that stats cleanly, so its output was a run of
  argument errors; it now indexes an error only when there is one.
  `incident_graph`, `binary_triage_sections_entropy` and
  `memory_scan_to_detection` printed `len()` of a result hash -- a count of its
  keys -- as the number of nodes reached, sections and PE headers: 2 nodes for
  3, 3 sections for 15, 3 PE headers for 1. `incident_graph` now also looks the
  process up with `db_find` and lists what it touched with `db_relations`.

- **A withdrawal recorded who made it and not on whose authority,** though the
  disclosure policy promised both. `disclose_withdraw(ledger, disclosure,
  reason, {"authorised_by": name})` records the authority; left out, it is the
  examiner's own. The Withdrawal carries the name and `authority_basis`
  (`self` or `named`) and an AUTHORISED_BY edge to that name's Actor node, and
  `disclose_history` shows both. A withdrawal recorded before this release
  reports its basis as `not recorded`.

- **`ledger_redactions` named whoever was reading the ledger as the actor of
  every redaction.** The name came from the reading session, not the record, so
  a redaction one examiner made was attributed by name to the next one to open
  the ledger. The name is now the one behind the record's own actor id: this
  session's, or the one a disclosure-family Actor node pairs with it, and
  otherwise empty, with `actor_source` saying which.

- **A case could be written through a ledger it was not attached to.** A
  builtin that takes the ledger asks it for the case's state, and another
  ledger records no lifecycle for the case, so a disclosure or a
  reclassification written through one went ahead while the case was in review
  in the ledger it was attached to. `disclose_to_passphrase`,
  `disclose_reclassified`, `role_assign` and `redaction_commit` now refuse a
  ledger other than the one the case is attached to.

- **`ledger_patterns` could report a match naming a node the ledger does not
  hold.** It refused a pattern with no edges, since every node then matches on
  its own, but accepted one with a single node on no edge, which matched every
  candidate on its own -- and over a scope, graphene takes the scope's ids as an
  unlabelled node's candidates without reading them, so a match could name any
  id in the scope. A pattern node on no edge of the pattern is now refused, and
  the refusal names it.

- **The documentation names every builtin that refuses classified
  plaintext.** `record_release`'s documentation, the disclosure policy and the
  classified-records source all stopped their list of the builtins that refuse
  a marked buffer at `db_add_artifact`, although `db_add_relation` refuses one
  too; `record_release`'s also left out `report_table` and `report_list`. A test
  now holds `record_release`'s documentation to the list the run time is held
  to.

- **A lint report on a call inside a `return` was given twice.** The parser
  records a return's first value twice over, and the walk most of the lint rules
  share followed both, so `classifiedPlaintext`, `commandInjection`,
  `evidenceMutation`, `pathTraversal`, `tlsVerificationDisabled`,
  `unboundedResource` and `weakCrypto` each reported a call written in a
  `return` twice, in the editor and in `mutant lint`. The statements inside an
  `if` or `match` that a function returns were walked twice too. Each is walked
  once now.

- **Every analysis built the set of builtin names again for each rule that
  asks.** Seven lint rules built a set of every builtin's name, about 27 KB,
  each time a document was analysed -- on every keystroke -- although the
  language server builds that set once when it starts, and the four new case
  rules would have made it eleven. They read the one set now: analysing a
  50-declaration document allocates about 160 KB less than before, the four new
  rules included.

- **The HTTP builtins went through whatever proxy the environment named.** `http_get`,
  `http_post`, `http_request` and `lua_run_http` sent every request through net/http's default
  transport, which takes a proxy from `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY`, so whoever set
  the examiner's environment saw every fetch and upload and could rewrite a plain-HTTP answer.
  On Linux, `SSL_CERT_FILE` and `SSL_CERT_DIR` likewise chose the certificate authorities those
  requests, `net_tls_connect` and `net_tls_upgrade_client` trusted. The builtins now send
  through a transport that names no proxy, and on Linux read the system's certificate
  authorities from where Go reads them when neither variable is set (M26-NET-010). The
  configuration guard now refuses net/http's default client and transport, an `http.Client`
  with no transport of its own and, in the Linux build, `x509.SystemCertPool`.

- **On Linux the `process_*` builtins read `/proc` from wherever `HOST_PROC` named.**
  `process_list`, `process_tree`, `process_env`, `process_hash`, `process_modules`,
  `process_open_files` and `process_threads` go through gopsutil, which builds every path it
  reads from `HOST_PROC` unless it is told the directory, and decides that a process exists by
  signalling it when that directory is not a mount, so the environment decided what they
  reported (M26-NET-025). gopsutil is now told `/proc`, and every other directory it would look
  up.

- **The limits reference and the configuration policy claimed more than was true.**
  `docs/LIMITS_REFERENCE.md` said every value that bounds Mutant was a named constant and that
  it was the list of them, while the guard's budget held 167 that were not, and it listed a test
  helper's settle timeout beside the limits of a run. It now says how many limits the guard finds
  unnamed, and lists the limits of the tools around Mutant -- the test helpers, the guard itself
  -- after those that bound a run (M26-LIM-003). The configuration policy excused binary-format
  offsets from the guard because "their bounds are tested by fuzzing instead"; the tree has no
  fuzz targets yet, and the policy says so (M26-LIM-002).

- **A count an examiner mistyped was charged to the host.** `str_repeat`, `str_pad_left`,
  `str_pad_right` and `rand_bytes` allocated whatever size the script asked for, and so did
  `random_hex` and `nanoid`. The result was not an error and was not a crash: the process stayed
  alive holding tens of gibibytes of committed memory, printing nothing, surviving an ordinary
  kill, so the case it was opened for was neither finished nor released and the machine an
  examiner shares was the thing that degraded (M26-BLT-013). All six now refuse a result over
  32 MiB, naming the builtin, the size asked for and the limit, in the same shape as every other
  argument refusal. The refusal also happens at expansion time, so a macro body that asks for one
  can no longer wedge a compile. The bound is `maxBuiltinResultBytes` in
  `builtin/result_limit.go`, the language server shows it on the parameter before the call is
  run, and `docs/LIMITS_REFERENCE.md` lists it with its reason.

- **The formatter could write an `if`, `while` or `match` condition that did not parse.** It
  left out the brackets the statement needs whenever the printed condition began with `(` and
  ended with `)`, which a call on a bracketed callee such as `(-f)(1)` does. It now always
  writes them (M26-LSP-008).

- **The five disk-image examples failed on any real image.** `vhdi_example.mut`,
  `hfs_example.mut`, `xfs_example.mut`, `ewf_example.mut` and `raw_example.mut` built their
  lines with `+`, and an image's sizes and numbers are integers, so each stopped at the first
  one with `unsupported types for binary operation: STRING, INTEGER`. They also ran their lines
  together and passed the data they read to `putf` as the format, and `raw_example.mut` printed
  `sector_size`, which `raw_metadata` calls `assumed_sector_size`. They now print through
  `putf`'s verbs. The sweep cannot supply an image, so tests run the VHD and raw examples
  against generated ones, and a sweep test refuses a `putf` format any example decides at run
  time (M26-EX-020).

- **Calling something that was not a function did not fail.** The VM tested the callee slot for a
  closure or a builtin, and when it held neither it called whatever was at the bottom of the stack
  instead -- which is usually the function currently running. A dispatch table with no entry for
  the value it was keyed on therefore re-invoked its own caller and handed back that result, so a
  program that looked up a handler by a string from the evidence got an answer it never computed
  and nothing was reported anywhere (M26-VM-003). When the value at the bottom of the stack was
  the caller, the call recursed on itself: `fn() { let x = 5; return x(); }` did not return a wrong
  number, it ran until something stopped it, and in a test what stopped it was the ten-minute
  timeout. The fallback is gone, and a callee that cannot be called is refused by name --
  `calling non-function and non-built-in: INTEGER`, naming the type the author wrote and not the
  encrypted form it is stored in. The tree-walking evaluator always refused this, so the two
  engines no longer disagree about what the same expression means.

- **A failing task named the instruction that failed, and that name changed with the build.**
  `task_wait` handed the waiting program an error reading `vm_runtime_error ip=6 op=OpDiv:
  integer division by zero`, and the same source built at another mutation level said `ip=12`.
  A program that printed a failed task's error printed different output depending on how it was
  built, which is the one thing mutation promises not to do, and the number described the
  mutated instruction layout to whoever read that output (M26-VM-002). An error a program
  receives as a value now carries a source position instead of a bytecode one -- and the
  position is the line the task died on, not the `task_wait` that collected it, which is what a
  reader was looking for in the first place. The failure also brings the task's own call stack
  with it, readable as `err.stack`. An error that ends the run is unchanged: there the
  instruction pointer and the opcode are what a bug report needs, and they are still printed.
  A `with_resource` closer that fails and a test that dies rather than asserting were the same
  defect and are fixed with it.

- A `break` or a `continue` inside a function literal is refused at compile time
  instead of rewriting an unrelated instruction. The compiler's record of which
  loop a jump belongs to hung off the compiler rather than off the scope, and
  starting a function body neither saved nor cleared it — so a `break` inside a
  closure was recorded against the *enclosing* loop, as a position in the
  closure's own instruction stream. The loop then patched that position in its
  own stream, overwriting the first operand of whatever instruction sat there,
  and the closure kept the placeholder jump nobody had patched. Nothing was
  reported, and what went wrong depended on where the offset landed: a `break`
  in a callback inside a `for` made an unrelated `let marker = 1;` print 1053, a
  `continue` in one inside a `for ... in` failed with a stack underflow blamed
  on the program's first line, and one shape took `mutant gen` down with an
  index-out-of-range panic. A function body is now a boundary, so such a `break`
  is what it always was — one with no loop to leave — and says so. A loop
  *inside* the closure is unaffected and still patches its own stream. No
  shipped program uses the refused shape. (M26-CMP-002)

- **The workshop's evidence corpus can be built, and the ten beats have now
  actually run.** `build_evidence.{sh,ps1}` could not produce the QUILLDROP
  corpus with the generator their own install line installs: fsagen v0.1.0
  refused the playbook, first for pairing `template:` with `content:` and then,
  with that removed, for a `delete` whose path template redrew its random
  component and so named files that had never been created. Nothing had ever
  got past that, which is why all ten `.golden` files record only the “missing
  evidence” line — the code inside `quilldrop.ready()` had never executed on
  any machine. The lure is now built by `action: email`, so beat 2 parses a
  real RFC 5322 message; the staging tree is deleted by reference; and a third
  refusal that no report had recorded is fixed — `Finance/*.xlsx` filled with
  random bytes is refused, because the extension promises an OOXML spreadsheet
  fsagen will not fake, and both escapes it offers write text, which cannot
  reach beat 1's 7.9 entropy floor. Those exhibits are `.xlsx.enc`, which is
  what an encrypted spreadsheet looks like on disk, measured at 7.997,
  and the contract document is corrected to match the generator. All ten beats
  then ran end to end, every one exit 0, with beat 10 verifying beat 9's seal.
  Both scripts and both attendee-facing install lines now pin
  `fsagen@v0.1.0`; `@latest` became v0.2.0 on 2026-10-02. (M26-EX-018)

- **What the workshop said about ext4 and APFS was wrong in both directions.**
  It said the corpus “still builds” there and that only beat 3 was affected.
  Measured: without `--on-unsupported=skip` the run exits 1 and writes no
  corpus at all, because Mark-of-the-Web needs an alternate data stream; and
  with that flag the modelled timeline comes back with every `crtime` at 0, so
  beat 6 — which asks whether a file's modification time precedes its creation
  time — reports nothing on any row and its entire anti-forensics finding
  silently disappears. One fewer line of output and no diagnostic. Both build
  scripts now pass the flag, which is a no-op on NTFS, and then put the
  question beat 6 asks to the timeline they have just written, saying plainly
  when the finding cannot fire. That is a measurement of the output rather than
  a guess about the filesystem, so it is correct on ReFS, on FAT32 and on a
  network share as well. The documented platform table is now the measured
  one, and what it measures is NTFS against WSL ext4; APFS is a separate
  correction, below. (M26-EX-019)

- **The workshop told six readers to take the pre-built corpus and never
  said where it comes from.** The scripts and the docs offer it in six
  places -- `build_evidence.sh` even prints "see evidence/README.md" at the
  moment beat 6's finding cannot fire -- and `evidence/README.md` was the one
  file that did not answer. The run sheet told the presenter to hand it over
  without saying what they were handing over. The owner decisions of
  2026-10-04 make a pre-built, checksummed corpus the default for every
  attendee rather than a fallback, so the gap sat on the primary documented
  path, and the packaging plan existed only under `plans/`, which is
  gitignored and which no attendee can read. `evidence/README.md` now has a
  section saying what travels together -- the 98-file case tree, the 131-row
  modelled timeline, and a `SHA256SUMS` in the format `sha256sum -c` reads,
  which is the convention `case_bundle` already writes -- that the presenter
  supplies it, and how to check it on either platform; the other five
  references name that section. No filename or URL is printed, deliberately:
  the asset is named in the release it travels with, and a name written here
  would be the same dangling promise one level down. (M26-EX-021)

- **A measured ext4 result was explained by a mechanism that is wrong, and
  then extended to a platform nobody had run.** `evidence/README.md` said
  that Mark-of-the-Web, the alternate data stream, `crtime` and `ctime` are
  "Windows + NTFS only". `ctime` is POSIX and fsagen reads it on Linux
  unconditionally through `statx`; and a birth time belongs to the volume
  rather than to the operating system -- APFS keeps one, and fsagen's darwin
  path reads it from `Birthtimespec`. The single measurement behind that
  sentence was WSL ext4, and the table it introduces has no APFS column, yet
  four places generalised it to "ext4 or APFS", so a Mac presenter read an
  ext4 number as a macOS number and was told to hand out a corpus they may
  not need. Every measured number is kept; the prose is narrowed to the
  volume it was measured on, APFS is named as unmeasured, and the reader is
  pointed at the check both scripts already run against the timeline they
  have just written -- which was always the right authority, since it
  measures the output instead of predicting it from a filesystem name.
  Measured while checking this: fsagen v0.1.0 does cross-build for darwin on
  both architectures, so macOS is not shut out of generating at all.
  Separately, `evidence/README.md`'s hand-run `fsagen` command omitted
  `--on-unsupported=skip`, which both build scripts pass and which is a
  no-op on NTFS, so the one command the document spells out was refused on
  exactly the volumes the surrounding text is about. (M26-EX-022)

- **A Windows 10 or 11 jump list lost every entry after its first.** `jumplist_parse` read a
  DestList entry's path size at 0x74 from version 3 on. The format keeps it at 0x80 from version
  2 on, and 0x74 is the entry's access count, so the path came out of the wrong bytes and the next
  entry was looked for in the wrong place: on a real jump list the walk stopped after one entry,
  and the hostname, time, pin and path of every other were lost (M26-ART-001).

- **`prefetch_parse` read the run count from the wrong field on current Windows.** Version 30
  prefetch files come in two layouts. The one later Windows 10 builds and Windows 11 write keeps
  the run count at 0xC8, where 0xD0 is another field. The file says which layout it is, by where
  its file metrics array starts, and the run count is read from that layout now (M26-ART-002).

- **A registry value over 16 KiB came back as 12 bytes.** On a hive of version 1.4 or later, a
  value longer than one 16344-byte segment is stored through a big data record, and
  `hive_get_value`, `hive_list_values` and every hive-backed `reg_*` read returned the record
  instead of the value. They follow it now, and only where the format puts one: a short value
  that happens to begin "db" is data, which the reader behind `shimcache_parse` used to get wrong
  the other way (M26-ART-010).

- **Nested email parts were dropped with everything in them.** `email_parse`,
  `email_attachments` and `email_urls` read a message's top level only, so a multipart/alternative
  inside a multipart/mixed -- how most mail is built, phishing included -- lost its text and HTML
  bodies, its links and any attachment inside it. Nested parts are walked with their own
  boundaries now, down to 16 levels, past which the message is refused by name (M26-ART-013).

- **A crafted artifact could hang its parser or exhaust the host.** A registry index root naming
  itself cost 2^33 calls, and a chain of them returned a million copies of one subkey; each list
  is now read once (M26-ART-004). A binary plist of forty arrays, each holding two references to
  the next, expanded to 2^40 values; a plist is now refused once it would describe more values
  than it has bytes, which only shared containers can make it do, and a container holding itself
  is named as one (M26-ART-008). An EVTX chunk declaring 2^64 records over one that states a size
  of zero parsed that record until memory ran out; a chunk's records are now walked first and the
  parser told how many there are (M26-ART-006). And a count read out of a file -- DestList
  entries, registry values and big data sizes, plist objects and arrays -- no longer sizes an
  allocation before the bytes it promises are there to read: one header could ask for 240 GB,
  which no `recover` catches (M26-ART-005).

- **The language server pointed at the wrong place on any line holding a
  non-ASCII character.** LSP 3.16 defines `Position.character` as an offset in
  UTF-16 code units and offers no way to negotiate another encoding:
  `positionEncoding` arrived in 3.17 and this server is built on
  `protocol_3_16`. Mutant's lexer counts columns in BYTES, and the server
  equated the two numbers. They agree on an ASCII line and on no other, so from
  the first non-ASCII character of a line onwards every range sent out was too
  far right and every position read in was taken too far left, by one unit per
  extra UTF-8 byte.

  The trigger is not a non-ASCII identifier. A non-ASCII character anywhere
  earlier on the line does it, inside a string or a comment included, so this
  was live for ordinary ASCII-named code -- 18 of the shipped `.mut` files carry
  non-ASCII in a string or a comment. Everything that carries a range was
  affected: diagnostics underlined the wrong span, go-to-definition and hover
  resolved the wrong token or none, inlay hints landed inside words, document
  links missed -- and the server advertises `RenameProvider`, so accepting a
  rename applied its edit at the wrong offset in the user's own file.

  The conversion now happens once, at the protocol boundary, in
  `protocol.Mapper`. Byte columns are deliberately NOT replaced with character
  columns: the CLI, the parser's own messages and the sweep goldens all read
  `token.Position` as bytes and the goldens pin it, so nothing in the lexer, the
  parser or the AST changes. Seventy-five conversion sites across thirty files
  now go through two functions, and the three package-level converters that did
  the arithmetic without a document in hand are deleted rather than corrected,
  so a new call site cannot quietly reintroduce it.

  Three surfaces beyond the ones reported. A semantic token carries a start and
  a length, and both are in the protocol's units: the length was either the byte
  difference `end-start` or `len([]rune(text))`, and a rune count is wrong too
  for any rune outside the basic multilingual plane, which needs two UTF-16
  units. That same rune count gave a document's last position in three more
  places. And `lsp/api` now converts back to a byte column, so `mutant lint`
  keeps reporting the column the parser reports.

  On an ASCII document every number is unchanged, and that is asserted rather
  than argued: the existing suite passes untouched and
  `TestAnASCIIDocumentIsUnaffected` pins it. Each new fixture was proved to fail
  on the old arithmetic first. (M26-LSP-027)

- **The sandbox detector named WSL on a machine that had no WSL.** On Windows a
  parent process named `bash.exe` scored 90 under the type `WSL`, over the 70
  that counts as detected. Git for Windows, MSYS2 and Cygwin all ship a
  `bash.exe`, so a program started from any of those shells was halted and told
  it was running under WSL. The halt is intended and is unchanged -- an emulated
  shell is one of the environments the detector exists to notice -- but the type
  is now `MSYS/Cygwin or legacy WSL`, which is everything that name can prove:
  the legacy WSL launcher is called `bash.exe` as well, and the two cannot be
  separated there, because the parent is read from `tasklist`, whose image-name
  column is a basename and never a path. A run that is really under WSL is still
  reported as `WSL`, since it scores from its context environment and its UNC
  working directory too, and the tie-break prefers the specific type.

  The parent name was also compared as a substring, so a name that merely held
  one of the list's entries scored the same 90: `notwsl.exe` and `mywsl.exe`
  hold `wsl.exe`, and `gitbash.exe` holds `bash.exe`. None of those is a shell
  or a launcher and none of them scores at all now -- a single name is compared
  whole. The three other callers of the substring helper search a blob -- a
  `tasklist` dump, the contents of a cgroup file -- where a substring is the
  right match, and they are unchanged. `docs/TUTORIAL_30_MIN.md` and
  `docs/SANDBOX_DETECTION.md` record the type and why it names two things.
  (M26-TMP-003)

- **A longer process name was read as a shorter one, and in both directions.**
  The Windows sandbox detector ran `tasklist` and searched the whole dump for
  each process name it knows, so a name that merely held one of them was read as
  being it. Forwards, that halted a run with nothing wrong with it: the guest
  tools and integration services are worth between 70 and 85 each, all at or
  above the 70 that counts as detected, so one process called `myvmtoolsd.exe`
  was enough on its own. Backwards it did the opposite and turned the detector
  off -- a name holding `vmwp.exe` made it decide this machine was a Hyper-V
  *host*, and the host role gates the CPUID vendor, the device listing and the
  SMBIOS table off, so a Hyper-V guest went undetected. The listing is now asked
  for as CSV and read into a set of image names, each compared whole. The format
  mattered too: the default table cuts the name column at 25 characters, which
  13 of the 312 processes on the machine this was written on exceed, and one of
  its own rows is `System Idle Process`, whose name holds spaces.
  (M26-TMP-020)

  `USERPROFILE` was searched the same way for the Windows Sandbox account's
  profile folder, and that signal alone is worth 95, so a directory that merely
  held the name -- a copy of that profile kept elsewhere -- halted the run. A
  profile variable is that directory, not something containing it, so the path
  now has to end there. The neighbouring `USERNAME` check already compared
  whole. (M26-TMP-021)

  This corrects the entry above. It reported that the three remaining callers of
  the substring helper all search a blob where a substring is the right match;
  two of those three were these `tasklist` reads, and a listing of names is not
  that kind of blob. The one that is -- the contents of a cgroup file on Linux
  -- is unchanged, and is now the only caller left.

- **On Linux the parent-debugger check searched the parent's command line, so
  ordinary words were read as debuggers.** It read the whole of
  `/proc/<ppid>/cmdline`, arguments included, lowercased it and looked for each
  name in its list as a substring. `rr` is in that list and is inside `current`,
  `terraform` and `mirror`; `ida` is inside `validate` and `candidate`. Run on
  real Linux, a parent whose arguments held `cases/current/triage.mu`,
  `terraform` or `validate the image` was reported as a debugger in all three
  cases, and in secure mode that ends the run. The check now reads
  `/proc/<ppid>/comm` -- the executable's name, not its arguments -- and compares
  it exactly; all three report clean, and a parent whose executable really is
  named `gdb` is still detected. No names were added to the list: every candidate
  sets `TracerPid` while it is actually tracing, which the other check already
  catches, so more names would only widen the collision set for no gain. An
  unreadable `comm` fails open, because not knowing what started a program is not
  evidence that a debugger did. (M26-TMP-002)

- **`exec_string` and `cmd_run` could not run a command on Linux or macOS at
  all.** The shell defaulted to `powershell` on every platform, and the
  non-Windows shells were handed the command as a file path instead of after
  `-c`, so `bash` exited 127 with the whole command treated as a script name and
  `sh` was not reachable by any spelling. The default is now `powershell` on
  Windows and `sh` everywhere else, `bash` and `sh` are given `-c`, and `pwsh`
  runs the real `pwsh` binary. Three deliberate behaviour changes go with that.
  On WSL, `exec_string` with no shell argument used to reach PowerShell through
  Windows interop and now runs `sh -c`, so a script that relied on that must name
  `powershell` explicitly. `exec_string(cmd, "bash")` on Windows goes from doing
  nothing to running the command inside WSL. And `pwsh` stops silently running
  PowerShell 5.1. Windows' own default is unchanged, and `powershell`, `cmd` and
  `batch` keep working by name on every platform. (M26-TMP-005)

- **On macOS the parent-debugger check had the same defect with a worse list.**
  The output of `ps -o comm=` was substring-matched, and the list holds the bare
  words `trace`, which is inside `ltrace`, `dtrace` and `pytrace`, and `heap`,
  which is inside `heaptrack`; `xcode` matched anything invoked by path under
  `/Applications/Xcode.app`. The base name is now compared exactly, through the
  same matcher and the same lists as the Linux side -- both lists moved into the
  untagged file, so one function serves both platforms and both platforms' rules
  are testable from any host. This was found while fixing M26-TMP-002, and
  neither row mentioned it. Alongside it, `go build` and `go vet` now pass for
  `linux` and `darwin`: nothing had ever compiled these paths, which is how two
  platforms' worth of this check went unexamined. (M26-TMP-019)

- The lexer reads source as the runes it is written in, so a program that names a variable
  `grün`, `café` or `вода` compiles and runs instead of hanging the tool that read it. The cursor
  was declared a rune but filled from a single byte, and the first byte of a multi-byte letter is
  itself a letter in Latin-1, so a name was taken to end one byte into itself: every letter whose
  UTF-8 form begins `0xc3` read as the same identifier, which made `xà` and `xÅ` one variable, and
  `mutant fmt` wrote the truncated halves back over the author's file as bytes that were not UTF-8
  at all. Separately, the scan dispatched on `unicode.IsNumber` while the number reader looped on
  `unicode.IsDigit`; a superscript two or a vulgar fraction is the first but not the second, so the
  reader took nothing and the token had no width, and a lexer that hands out the same token for
  ever is read for ever — `mutant`, `mutant lint` and `mutant fmt` all spun instead of answering,
  and so did the language server. Both predicates are now `IsDigit`, and `NextToken` guarantees
  that a token which is not the last one consumed at least one rune, so a disagreement of that kind
  can cost a wrong token but not the process. Unicode identifiers are supported rather than
  refused, and are not normalised, which is the rule Go uses for its own. Invalid UTF-8 is reported
  one position at a time instead of being silently misread. (M26-LEX-001, M26-LEX-002)

- A struct now prints its fields in the order its own declaration gave them, and
  two structs are compared field by field rather than by their printed text.
  `Struct.Inspect` ranged a Go map, which yields a different order on every CALL
  rather than merely on every run, and Inspect was the identity both engines
  compared structs by. So `p == q` for two records built from the same literal
  answered true about one time in six for a six-field struct, `p == p` was
  usually false, `p == q` and `p != q` could both answer true in a single
  statement, and printing one record twice printed it two ways — all without a
  diagnostic. `contains`, `index_of` and `unique` asked the same question through
  the same identity, so a search for a record that was present found it about
  half the time and a dedup kept both copies of one record. A struct holding
  another struct, or held in an array, was wrong for the same reason. Equality is
  now `object.ValuesEqual`, one definition shared by `==` in both engines and by
  the collection builtins, so a search cannot answer differently from the
  comparison written by hand; it also means a string that spells `P { a: 1 }` is
  no longer equal to the struct, which it was in both engines, as a buffer,
  an error and an enum value already were not. A struct with a field that no
  declaration named — which only `OpSetField` can produce — prints it last, in
  sorted order, rather than hiding it. Ordering operators on structs are still
  refused, and the editor already said so. (M26-EVL-004)
- **A struct's fields are fixed by its declaration, in both engines and in the
  editor.** Reading a field no struct declared gave null, and writing one added
  it. So a mistyped read was an absent value that compared unequal to
  everything, printed as nothing and flowed on into whatever used it; and a
  mistyped write left the field the author meant to change holding its old
  value while the record gained one its type never declared, the write appearing
  to succeed. Both are refused now. The compiler refuses them before the program
  runs wherever it can prove what the receiver holds -- a name bound once from a
  struct literal and never assigned again -- both engines refuse the rest in the
  same words, and the language server says those words first. An error's unknown
  field is still null, for its own reason: a field a stripped build stamps
  nothing into still has to read, which is now written where it is relied on
  rather than deferring to a struct rule it no longer shares.
  (M26-CMP-017, M26-CMP-018)

- **`P { a: 1, c: 3 }` said "missing field b" and never mentioned `c`.** One
  mistyped field name makes two faults -- a name the declaration does not
  contain, and a declared field nothing set -- and only the second was reported,
  so the author was sent to look at a field they had not touched. Both are
  reported together now, which is what identifies the pair as one typo:
  `struct P has no field c and needs a value for field b: it declares a, b`. The
  separate field-count refusal is gone: a count that differs means the names
  differ, and the names are what has to change either way. The one exception is
  a field name written twice, which is why a repeat is now refused where it was
  written -- `struct P declares field a twice`, `struct P sets field a twice` --
  rather than two steps later as "expects 2 fields, got 1", which named neither
  the mistake nor its line. (M26-CMP-019)

- **A struct literal meant something different in each engine.** The
  tree-walking evaluator checked none of the three things the compiler checks, so
  a literal of an undeclared type, one missing a declared field, and one naming a
  field the type does not declare were all values there and all refused by the
  compiler. That engine is what computes `unquote(...)` during macro expansion,
  so it is not dead code. It makes the same three checks now, and macro expansion
  is given the program's struct declarations, so a type the program plainly
  declares is not refused as undeclared inside an unquote. Nothing a program can
  write reached the old laxness: a struct has no source form, so it could never
  be spliced back out of an unquote in the first place. (M26-EVL-019)

- **`toml_parse` and `msgpack_parse` crashed the process on a deeply nested document.** Both
  libraries recurse once per level, and nothing bounded them: convertNative's depth check runs on
  what they return, after the recursion. Two million levels overflowed the stack, a fatal error no
  `recover` catches. A document's shape is now measured from its bytes first, and one nested past
  256 levels is refused (M26-DAT-004). The same measurement refuses a TOML key of more than 256
  dotted parts, which the library re-walked once per part -- 16,000 parts took 7.9 s
  (M26-DAT-033) -- and a MessagePack container declaring more values than its bytes can hold,
  which the library allocated before reading one: five bytes asked for 64 GiB (M26-DAT-034).

- **`toml_parse` moved local date-times by the host's UTC offset and labelled them Z.** A TOML
  local date-time, date or time names no instant, and is now rendered as it was written; an offset
  date-time is still rendered in UTC (M26-DAT-015). An array of tables, `[[name]]`, is read rather
  than refused (M26-DAT-016).

- **Three decoders let the last copy of a repeated key win without a word.** `json_parse`,
  `ndjson_parse` and `msgpack_parse` refuse a key written twice in one object, as the CBOR and YAML
  readers already did (M26-DAT-035, M26-DAT-036). `msgpack_parse` reads integer map keys, which it
  could not, and `cbor_encode` and `msgpack_encode` write INTEGER and BOOLEAN keys as what they
  are rather than as text: COSE's `{1: -7}` round-trips, and `{1: v}` no longer encodes the same
  as `{"1": v}` (M26-DAT-014).

- **`json_parse` read a document's first value and dropped the rest.** It requires exactly one
  now, and so does every `ndjson_parse` line, where a stray `}` used to pass (M26-DAT-017). An
  integer too wide for INTEGER comes back as its exact decimal text, not a rounded FLOAT
  (M26-DAT-018), and text that is not UTF-8, or half a surrogate pair, is refused rather than
  rewritten to U+FFFD (M26-DAT-037).

- **`protobuf_parse` refused every group, and could hold hundreds of times its input.** A group is
  read with its own field number (M26-DAT-011), one field budget covers every nested reading
  (M26-DAT-012), and past the 32-level limit a group is refused rather than skipped while a
  length-delimited field says `message_unchecked: true` (M26-DAT-038).

- **`der_parse` read a UTCTime from 1950-1968 as 2050-2068**, and took superlinear time over a
  huge INTEGER. Two-digit years follow RFC 5280 (M26-DAT-013), and an integer longer than 4 KiB
  is rendered as exact hexadecimal, in `cbor_parse` as well (M26-DAT-029).

- **`xml_find` returned one element several times, out of document order**, and four `**` over
  a chain of sixty elements returned 595,665 results. Each element comes back once, in document
  order (M26-DAT-019).

- **An HTTP message head is bounded in fields as well as in bytes.** Nothing
  bounded how many header fields a head could carry, and the cost of a field is
  not its length: each one becomes an entry in an `http.Header` and then a pair
  in the hash the builtin hands back, which is held as a VM variable and
  re-encrypted on every store. With a 1 MiB head bound in place, 87,964
  one-line fields fitted in 1,044,485 bytes on the wire and grew the heap by
  33,246,576 -- 31.8 times what arrived. A head is now capped at 100 fields, and
  a head past the cap is refused rather than trimmed: a hash holding the first
  hundred fields of a larger head would be a wrong answer with nothing in it to
  say so. The refusal says how many fields arrived as well as how many are
  allowed, because the difference between 101 and 90,000 is the difference
  between a verbose client and an attack. The cap counts the lines that
  arrived, not the distinct names, so a head spelling one name ninety thousand
  times is ninety thousand fields and not one. It applies to every builtin in
  this build that turns an HTTP head into a hash: `http_conn_read_request`,
  `http_conn_read_response`, their two `_head` variants, `http_parse_request`,
  `http_parse_response` (M26-NET-028), and `http_get`, `http_post` and
  `http_request`, whose response head had no byte bound of its own beyond
  `net/http`'s 10 MiB transport default (M26-NET-032). **This is a behaviour
  change**: a script reading a head of more than 100 fields used to get a hash
  and now gets an error. 100 is Apache httpd's `LimitRequestFields` default and
  Tomcat's `maxHeaderCount` default; `net/http` has no field count of its own.
  Email headers are deliberately not capped at this figure -- a real message
  accumulates a `Received` field per hop -- and `email_parse` and its four
  siblings are unchanged.

- **A recursion with no stopping case ran until the host gave out, and through
  `map` it killed the process outright.** Nothing bounded how deeply calls could
  nest. The constant that looked like the bound, `global.MaxFrames`, sat one line
  below a comment saying the VM grows these slices dynamically, and it was read as
  a limit by two comments elsewhere in the VM that describe reporting a runaway
  recursion as an error. Measured: `let f = fn(n) { return f(n + 1); }; f(0);`
  reached 73,298 frames in eight seconds and returned nothing at all, and the same
  recursion written through `map` reached 82,366 while also growing the Go stack,
  because `map`, `filter`, `each`, `reduce`, `sort_by`, `with_resource` and `test`
  call their callback by re-entering the engine. Past the Go stack's own default
  that form ends in `fatal error: stack overflow`, which no `recover` contains, so
  the process dies with the run's cleanup unrun -- no `CleanupSensitiveData`, no
  `WaitForTasks`. A call may now be 10,000 deep and the next one is refused with
  `this call would be 10001 deep, over the limit of 10000 nested calls`. The
  ceiling is on frames and not on calls, so a program that calls a function sixty
  thousand times in a loop is unaffected, and it is checked in the one place a
  frame is entered, so the plain path and the callback path are bounded by the same
  number. 10,000 nested callback re-entries were measured to fit in 32 MiB of Go
  stack against a 1 GiB default, which is why one ceiling is enough for both.
  `global.MaxFrames` is gone rather than renamed: the frame capacity is
  `vm.initialFrameCapacity` now, in the package that grows it, next to the limit.
  (M26-VM-006, and in part M26-VM-021)
- **An ext volume inside a disk image could not be opened.** `ext_open` at a partition offset
  refused every ext volume as a corrupt superblock. libext reads relative to the reader it is
  given and adds its base offset only to the offsets it reports, so handed the image from byte
  zero it looked for the superblock in whatever preceded the partition. It is handed a reader
  that starts at the volume now, and the offsets it reports stay image-absolute (M26-FS1-001).

- **An NTFS file's size came from the copy NTFS keeps least current.** `mft_parse`,
  `fs_deleted` and `ntfs_deleted` took a record's size from its `$FILE_NAME` attribute, which
  NTFS updates lazily and which is routinely stale or zero, and `ntfs_recover_file` cut a
  recovery to that figure -- or, when it was zero, padded it out to the whole of its clusters,
  with no caveat either way. The size is now the default `$DATA` stream's wherever the record
  holds the start of that stream, and `$FILE_NAME`'s only where it does not (M26-FS2-002).

- **A partition's byte range could wrap round to another partition's.** Every partition table's
  `start_byte` and `length_byte` were LBAs times the block size in unchecked arithmetic, so a crafted
  entry reported a negative length or the start of a different partition, and `fat_open` on it opened
  that partition. The fields now come from checked arithmetic and read -1 when they do not fit, and
  opening such an entry is refused (M26-FS1-002). A region whose offset plus length passes the largest
  offset an image can hold is refused too, where it was opened "bounded" with a reader that ran on
  without end (M26-FS1-014).

- **`ewf_open_partial` misplaced the segments after a hole.** libewf concatenates the chunk tables of
  the segments it is handed, so with a segment missing every chunk after the gap decoded at the wrong
  offset: a set of segments 1 and 3 read segment 3's data where segment 2's belongs. A set with a hole
  now decodes segments 1 up to the first gap, lists the rest in a new `undecoded_segments` field, and
  is refused outright when segment 1 is missing; an explicit list must be 1..k by each file's own header
  (M26-FS1-010). `partial` is true whenever the image is not whole -- a hole, a last segment with no
  done section, a first segment that is not number 1, or fewer chunks than the volume declares -- where
  it said false for a list with a hole (M26-FS1-009). A list of one path is opened as given, never
  expanded by discovery (M26-FS1-018).

- **`vhdi_discover` gave its duplicate-identity warnings in a different order on every run.** They
  came out in map order; they are sorted by identity now (M26-FS1-016).

- **A read that came up short was a whole file.** libfat, libxfat and libntfs end a read with
  `io.EOF` where the image ends inside a file, and libntfs and libhfs where a file's own map runs out,
  and the `*_extract_file`, `*_hash_file` and `*_read_file_at` builtins took that for the end of the
  file: a prefix was extracted, hashed and reported as the file. A read that stops short of the bytes
  the volume located is an error now, and an extraction that fails removes what it wrote
  (M26-FS1-003). A deleted file's recovery reads nothing past the end of the image, counts the bytes
  its runs place there apart from the ones it could not place, and refuses an output that would be
  nothing but stand-in zeros (M26-FS2-005). `fs_hash` and the `*_hash_file` builtins report the
  algorithm they computed under its canonical name (M26-FS1-017).

- **The NTFS walks trusted a count the image does not hold.** `ntfs_verify`, `ntfs_report` and
  `ntfs_deleted` walked every record the `$MFT` declares about itself, unbounded by the image, so a
  crafted 128 KiB image could run the process out of memory; and `ntfs_verify` took a record it could
  not read for an unallocated one, so a truncated MFT verified. The walks now follow record 0's own run
  list, checked against the boot sector, and cover only the records the image holds; the rest are
  named, a record that will not read is a finding and fails the new structural check `mft_readable`,
  and `ntfs_deleted` says it is incomplete (M26-FS1-005, M26-FS1-006, M26-FS2-003). `ntfs_report`
  refuses an image that does not hold its whole MFT, because libntfs's report walk cannot be bounded
  from outside.

- **`verified` could rest on no check at all, and on checks that never compared anything.** Every
  `*_verify` check now has a `kind`, `integrity` or `structural`, and `verified` needs an integrity
  check to have run, so ext2, HFS+ and XFS v4 -- formats with nothing to compare -- are no longer
  verified (M26-FS1-004). `hfs_verify` no longer fails a volume for an attributes B-tree its format
  does not have (M26-FS1-011). `ext_verify` never compared an inode's checksum -- libext compares one on
  every read and keeps the answer only on a handle opened to refuse a mismatch -- so an ext4 volume
  with an edited inode verified, and the summary said verifying again after a walk would widen the
  check; it compares the superblock, the group descriptors, the allocation bitmaps and every allocated
  inode now (M26-FS2-027). libxfs v0.4.1 reads the stored superblock and inode CRCs in the wrong byte
  order, so `xfs_verify` failed every healthy v5 volume with a critical finding and `xfs_report`
  carried a mismatch anomaly for every inode; the comparisons are made here now, and a real mismatch is
  still reported (M26-FS2-030).

- **A path named a different file.** Paths are no longer trimmed: `" a.txt"` and `"a.txt"` are two
  names on every filesystem that allows both, and ext, XFS and HFS+ keep a backslash as the character it
  is. HFS+ refuses a path ending in a space, since libhfs trims it. An exFAT name held by a live file
  and a deleted one finds the live one, and two deleted files of one name are refused rather than one
  chosen (M26-FS1-007, M26-FS1-008).

- **Allocation was "checked" where nothing asked.** A deleted FAT file's assumed run, and every cluster
  of an exFAT recovery, are asked about cluster by cluster, and the first in use is named
  (M26-FS2-004, M26-FS2-017). An ext inode on the orphan list owns its blocks and is no longer reported
  reallocated, and an ext or HFS+ entry whose allocation could not be read is no longer reported checked
  (M26-FS2-006, M26-FS2-016). A FAT or exFAT record seen in a deleted directory and again by the sweep is
  one row (M26-FS2-015), and libxfat's virtual `$OrphanFiles` root is not a deleted file (M26-FS2-026).

- **Warnings were lost, and their loss was a clean result.** libext keeps 256 warnings per handle and
  libhfs one of each kind; a scan after the list filled, or a second file with the same damage, said
  complete with no warnings. Both now say so (M26-FS2-008, M26-FS2-021). The ext scans count the
  inode-table slots they read, and a slot past the end of the image -- which libext passes over
  without a word -- makes them incomplete (M26-FS2-018, M26-FS2-028). The `$LogFile` scans count the
  record pages libntfs drops for a failed update sequence -- a torn write -- and say they are incomplete
  (M26-FS2-029).

- **Reports and scans put things in the wrong place.** `ext_report`'s fragments end exclusively, like
  every other format's, and sit at their real offset in the file, so a run after a hole is placed after
  the hole; a row whose block map could not be read says so and the report is incomplete
  (M26-FS1-012, M26-FS1-013). `xfs_report` bounds its volume (M26-FS1-015). `xfs_unlinked` says it is
  incomplete when an inode would not read, and an XFS time of zero is no time rather than 1970
  (M26-FS2-013, M26-FS2-014). `xfs_slack` no longer counts a directory's live index blocks, 32 GiB into
  it, as slack (M26-FS2-020). A fragmented HFS+ attribute value reports every range it occupies
  (M26-FS2-022). `ntfs_log_transactions` groups records in LSN order, so a transaction across the wrap
  is one transaction, and a record met twice is reported once (M26-FS2-023, part of M26-FS2-024).
  `fs_carve` reports where a signature's file begins, not where the signature is, and `fs_walk`
  measures depth from the root it was given (M26-FS2-010, M26-FS2-011). An inode number past the volume
  is refused rather than read as another inode's (M26-FS2-007).

- **`mutant fmt` rewrote a file it could not parse, and shortened the strings
  inside it.** With no tree to read, the formatter fell back to stripping
  trailing whitespace from every line, and that fallback cannot tell a line of
  code from a line inside a triple-quoted string: a banner whose first row
  ended in three spaces came back three bytes shorter. The CLI wrote that
  result over the file and exited 0, `--check` exited 1 for the wrong reason --
  it was reporting a whitespace diff it had invented against a file it could
  not format -- and `--stdout` printed the invented text. A file that does not
  parse is now left exactly as it is: `mutant fmt` prints its parse errors in
  `mutant lint`'s shape and exits non-zero in all three modes, and the editor's
  formatting, range-formatting and on-type-formatting requests answer with no
  edits at all. There is deliberately no whitespace-only fallback, which is
  what `gofmt`, `rustfmt` and `prettier` all do here: the diagnostics already
  say what is wrong, and nothing can be formatted until it is fixed
  (M26-TOOL-014).

- **A sandboxed Lua script could run past its timeout without bound.** The
  five-second cap was a `context` handed to gopher-lua, which consults it only
  between VM instructions, so a single call into a Go library function never
  looked at it. A backtracking pattern search is exactly that one call:
  `string.find(string.rep("a", 400), ".-.-.-b")` ran for 43 seconds and noticed
  its deadline only once it had finished, and the cost rises about fifteenfold
  for every doubling of the subject. The chunk now runs on its own goroutine
  and the calling builtin waits on the clock, so `lua_run_string`,
  `lua_run_file` and `lua_run_http` always return within the cap and report the
  script as abandoned. `string.rep` is bounded at 8 MiB in the same change,
  because it is the one call a sandboxed script uses to manufacture a subject
  large enough for the search to matter, and it refuses rather than truncating.
  What the deadline bounds is the caller's wait, not the host's CPU: an
  abandoned chunk's current library call still runs to its own end, and
  `docs/RUNTIME_INTEGRATION.md` says so (M26-TOOL-010).

- **An index one past the start of an array or a string took the interpreter
  down, and the audit chain recorded it as tampering.** `xs[-1]` is the last
  element, so `xs[-4]` of a three-element array reached element -1 of a Go slice:
  the panic was recovered, reported as `vm_runtime_error: recovered panic:
  runtime error: index out of range [-1]`, and counted as a VM integrity
  failure -- which means "the program running is not the program that was
  compiled". On the CLI an ordinary mistake in a script therefore left a tamper
  entry in the one log that is meant to be worth trusting. Every ordered
  container now answers null to an index that names nothing, from either
  direction, and the audit chain does not move. The tree-walking evaluator had
  the opposite fault on the same expression -- it answered null to *any* negative
  index on an array -- so `xs[-1]` meant the last element when a program was
  compiled and nothing when the same program was interpreted. Buffers were the
  one container that was already right in both engines, and they are what the
  shared rule is taken from. (M26-VM-008)

- **A string index returned a character the string does not contain.** `s[i]`
  indexed by byte and then converted that byte to a rune, which is not the byte
  and not the character: in a string holding `h`, `e`-acute, `l`, `l`, `o`, `s[1]`
  was U+00C3 and `s[2]` was U+00A9, neither of which is in it, and the string
  appeared to have six characters where it has five. It is indexed by rune now,
  which is what the for-in iterator, `str_char_at`, `str_substr` and
  `str_reverse` have always done -- `object.NewIterator` states the rule and the
  reason. A byte that begins no valid sequence reads as U+FFFD, as it already did
  in those four; a program that means the bytes should hold a buffer, which is
  what `BYTES` is for. `len(s)` still counts bytes. The evaluator did not index
  strings at all before -- `s[0]` was "index operator not supported: STRING" --
  and does now, in the same words and with the same answers. (M26-VM-009)

- **`!x` was not the negation of truthiness, so `if (x)` and `if (!x)` could both
  skip their branch.** `0`, `0.0`, `""` and an empty buffer are falsy -- that is
  what `if`, `while`, `for`, `match`, `&&`, `||` and `filter` have always meant by
  them -- but `!` consulted none of that. On a compiled program it compared the
  operand against three singleton pointers and answered `false` to anything else;
  in the tree-walking evaluator it compared rendered text. So `!0` was `false`,
  which is the same answer as `!true`: `0` was falsy and `!0` was falsy too, and
  `if (!count) { putln("no hits"); }` never fired for zero hits. `!!x` was not `x`.
  There is one implementation of truthiness now, `object.IsTruthy`, and `!` is its
  negation in both engines, so `!x` is always a boolean, exactly one of `x` and
  `!x` is truthy, and `!!x` has `x`'s truthiness. Two of these were also
  disagreements between the engines rather than only wrong: `!""` and
  `!<empty buffer>` were true when a program was interpreted and false when it was
  compiled, and `!"false"` was the other way round -- the evaluator was comparing
  the string `"false"` against the rendering of `false`. The rule is now stated in
  the language reference, which never stated it, and corrected in
  `docs/WASM_REPL_REFERENCE.md`, which listed a whitespace-only string as falsy and
  left out `0.0` and the empty buffer. (M26-VM-007)

- **A function whose body produced no value crashed the compiler.** The
  tree-walking evaluator returned a Go `nil` rather than `null` for a call to a
  function whose body yields nothing -- an empty body, or, far more commonly, a body
  whose last statement is a `let`, which is how a function that works by side effect
  is written. The `nil` was handed to the program, and whatever touched it next
  dereferenced it. Because that engine is what computes `unquote(...)` during macro
  expansion, the result was `mutant prog.mut` ending with `panic: runtime error:
  invalid memory address or nil pointer dereference` and a goroutine dump, at
  compile time, from three different ordinary spellings: `type_of(f())`, `!f()` and
  `f() == 1`. Where it did not crash it was wrong instead -- `if (f())` took the
  true branch here and the false branch on the VM, and `while (f())` never
  terminated here and ran zero times there. Such a call is `null` now, as it always
  was on the VM, which is also what the builtin path in the same function had always
  returned for the same case. (M26-EVL-020)


- **A `pmap`, `peach` or `spawn` worker could write the caller's variables.** A
  worker has always been given its own copy of the variables its callback
  captured directly, and the language reference promises that "an assignment to
  either stays local to that worker". That promise held for one route to a
  variable and failed for six: a function the callback captured, a function held
  in a global, a function inside a captured array, hash, struct, enum or
  multi-value, a function handed in as a `pmap` element, and the argument of
  `spawn(fn, arg)`. Along any of those, every worker and the caller wrote one
  storage location with no synchronisation -- `go test -race` reported six races,
  and the observable effect was lost updates: eight workers bumping a counter
  fifty times each left the caller's counter reading 432, 503 and 422 on three
  runs of the same program. A worker now gets its own copy of every variable it
  can reach, found by following the same paths the storage seal already follows,
  and a variable reached two ways is still one variable inside the worker, so a
  program's own aliasing is untouched. A recursive function, whose storage holds
  the function that holds the storage, terminates. The walk costs 34us per
  worker where there is nothing to detach -- against 782us to build a worker and
  244us to copy its globals -- and the globals are examined once per call rather
  than once per worker, so a program with no function in a global pays nothing
  (M26-VM-004).


- **Every variable read cost time in proportion to the value's size.** Reading a
  variable moved it from a slot, a global or a cell onto the stack, and the move
  opened the value and sealed the result again with the same key -- two
  ChaCha20 passes and two allocations over the whole payload to arrive back at
  the bytes it started with. Sealing also derived its key per call, two SHA-256
  hashes for every eight bytes: building an array of 800 elements in a loop made
  2,890,011 derivations for 22 MiB of payload. A value that is only moving is
  now moved, and the key is derived once per run -- the VM already derived it
  for its instructions. A stored value still records the seed it was sealed
  under, and one sealed under a different seed is still opened with a key
  derived for it, which is what the REPL does on every line. Nothing in the VM
  mutates a container in storage form, so the two slots a moved container is
  now reachable from are safe: every write takes its target from the stack,
  which rebuilds it. `examples/binary/static_bin_analysis.mut`, which reads a
  3 MiB buffer out of a struct field in a loop, went from 40.8 s to 22.2 s
  against the release sweep's 60 s limit (M26-VM-001).

- **Reading a `.tar.zst` could return the wrong bytes.** Its zstd decoder was never closed, and
  went on reading the archive from its own goroutines after a read returned, racing the next
  read's seek: one or two reads in twenty failed or came back wrong, and dozens of goroutines
  outlived `tar_close`. Every decompressor is closed when its walk ends now, and zstd decodes as
  it is read (M26-DAT-005).

- **`tar_open` could not open an archive that compresses past 1000:1, and nothing could make
  it.** It takes an optional `max_bytes` now, which every later read through the handle keeps
  (M26-DAT-006). A plain tar whose first member's name begins with a compression magic -- a file
  called `BZhistory.txt` -- opens as the plain tar it is (M26-DAT-008). What a handle holds is
  the listing, at most 128 MiB of names, link targets and owners, where it kept every header
  whole (M26-DAT-010).

- **`tar_read` returned a hard link as an empty buffer.** A hard link reads as the member it
  names; a symbolic link, a directory or a device holds no content and is refused, saying which
  (M26-DAT-009). A name two members share -- a tar appended to holds every version of a file --
  is refused rather than read as the first, the stale one, in `tar_read` and `zip_read` alike,
  and either reads a member by its position in the listing, which the second argument now
  accepts (M26-DAT-039).

- **`unsafe_path` judged a symbolic link from the wrong place.** A tar link's target is read from
  the link's own directory, so `usr/lib/libfoo.so -> ../lib64/libfoo.so.1` is not flagged, and a
  zip symlink entry's target is checked at all, where only its name was (M26-DAT-007).

- **`sqlite_query` bound a buffer as its hex text,** so a lookup by a key or a hash never
  matched; it binds as a BLOB, and a value with no SQLite type is refused rather than bound as the
  text it prints as (M26-DAT-023, M26-DAT-040). A result with two columns of one name is refused,
  where a row kept only the second (M26-DAT-040). TEXT in a DATE, DATETIME or TIMESTAMP column
  keeps its fraction and its offset, where it was moved to UTC and cut to the second;
  `CAST(col AS TEXT)` returns it as stored (M26-DAT-024).

- **`time_parse` gave an instant that depended on the examiner's machine: a zone
  abbreviation was read as UTC on a host that does not use it.** The value and
  the layout went to Go's `time.Parse`, which resolves an abbreviation -- the
  `MST` layout verb -- only when it belongs to the host's own zone, and
  otherwise keeps the name, applies offset 0 and returns no error. So
  `time_parse("2024-07-01 10:00 PDT", "2006-01-02 15:04 MST")` was 1719853200 on
  a Los Angeles host and 1719828000 on a UTC or Kolkata one: seven hours apart,
  both silent, and a timeline built from mail or log timestamps carried the
  difference without saying so. Parsing is now done against UTC, so the host
  cannot change the answer, and an abbreviation that cannot be resolved is
  refused with the two ways to say what was meant. `UTC` and `GMT` still parse,
  being the only abbreviations Go accepts that name +0000; a numeric offset, an
  `RFC3339` value, a layout with no zone element, and an abbreviation written
  beside its offset (`MST-0700`) are all unaffected. The one case this turns
  from right into an error is an abbreviation that happens to match the host --
  deliberately: a result that is correct only on one machine cannot be
  reproduced on another, and a refusal that names the fix is worth more than an
  answer that is right by accident. (M26-BLT-003)

- **Integer arithmetic stays exact, and `nan` or an out-of-range float is refused
  rather than turned into the most negative integer.** Nine builtins took their
  operands through a helper that returned every INTEGER as a `float64`, so they
  did integer work in a type that cannot hold an `int64`. Above 2^53 two
  different integers share one float, and each site got that wrong its own way:
  `sum` accumulated in the float and narrowed the total back, so adding 1 to an
  NTFS file time returned the file time; `min` and `max` compared the rounded
  copies and returned the wrong argument; `clamp` rebuilt its answer from the
  float instead of returning the bound that won; `floor`, `ceil` and `round`
  widened an integer only to narrow it again; `sort` ordered on the float; and
  `to_int` narrowed with no range test, so `to_int(1e19)` and `to_int(nan)` both
  returned `-9223372036854775808`. `abs` had no guard for the one integer whose
  negation is itself, so `abs` of it was negative. None of it produced a
  diagnostic, and a forensic timestamp is an `int64` of nanoseconds. Each builtin
  still returns the kind its contract declares; what changed is that an INTEGER
  argument is no longer rounded on the way through, and that a total leaving the
  `int64` range is refused -- naming the element that did it -- rather than
  wrapped. `avg` is unchanged: its contract declares FLOAT, and accumulating in
  `int64` would refuse an average that is representable when its total is not.
  (M26-BLT-004)
- **Two builtins no longer panic on an argument a caller is entitled to pass,
  and no longer record that panic as evidence of tampering.** `str_substr`
  clamped the start against the string and only then added the length, so asking
  for the rest of a string by passing a number larger than it wrapped the sum
  negative, the clamp could not fire on a negative, and the slice panicked --
  with a start of 0 the sum does not overflow, which is why the obvious case
  worked. `rand_int` computed `hi - lo` as an `int64`, so a range wider than
  `int64` wrapped non-positive and the draw panicked on its own argument. Both
  now answer: `str_substr` returns the rest of the string, and `rand_int` draws
  uniformly from a range of any width, keeping its previous draw for every range
  that fits so no seeded run moves. This mattered beyond the crash. A builtin
  panic is contained as a runtime error and recorded as an integrity failure in
  the audit chain a case manifest seals, so a bad argument wrote a tamper record
  into the evidence. `str_repeat` and `str_pad_left`/`str_pad_right` already
  refused what they could not build; they are now held to it by tests.
  (M26-BLT-006)
- **Renaming a module member from its own declaration now edits every file that
  imports it.** The rename handler looked at the workspace-wide uses only when
  the result for the current file came back empty -- and with the cursor on a
  declaration it never is, because the declaration itself is in it. So pressing
  F2 on a definition, the place a rename is usually started, was the one place
  that renamed nothing outside the file, while "find all references" from the
  same cursor listed the importers correctly. Both now ask one function, so the
  two can no longer disagree, and no span is edited twice. (M26-LSP-003)
- **The background workspace scan no longer replaces an unsaved file's
  declarations with the copy on disk.** The scan checked whether the editor had a
  file open by building a URI for it and looking that string up. VS Code spells a
  Windows document `file:///c%3A/...` and the server built `file:///C:/...`, so
  on Windows the check matched nothing and the scan treated every open document
  as closed. It then indexed the file a second time and pushed the saved text
  into the shared workspace -- which is keyed by path, not by URI -- so a
  function you had just written and not yet saved disappeared, and the file
  importing it was told the module had no such member. The scan now compares
  canonical paths, and a URI is kept exactly as the client spelled it. An import
  of a file no editor has open still resolves, which is what the scan is for and
  is covered by its own test. (M26-LSP-005)
- **`net_banner` threw away the greeting of every service that waits for the
  client.** SSH, SMTP and FTP each write their banner and then hold the
  connection open for a command, so the read ends at `net_banner`'s own deadline
  rather than at an EOF. `io.ReadAll` reports that as an error, and the error was
  taken for the whole answer: `{ok: false, banner: "", error: "i/o timeout"}` for
  a greeting that had already arrived in full. The three services most worth
  fingerprinting were the three it could not fingerprint. What decides the answer
  is now the bytes rather than the error -- a read deadline is how a banner ends,
  not a failure, and `io.ReadAll` hands back what it read alongside the error --
  so the greeting is reported with `ok: true`. A read that ends with no bytes at
  all is still a failure, and a peer that closes cleanly having said nothing
  still reports `ok: true` with an empty banner, exactly as before.
  (M26-NET-001)

- **A greeting past 4 KiB was clipped and reported as a whole banner.** The read
  was bounded at exactly `maxBannerBytes`, and `io.LimitReader` returns EOF at
  its bound while `io.ReadAll` turns EOF into nil, so a peer that sent a
  megabyte came back as `{ok: true, banner: <the first 4096 bytes>, error: ""}`
  -- the prefix of a longer stream presented as a complete greeting, with
  nothing in the hash able to say otherwise. An examiner comparing or hashing
  banners could not tell a 4 KiB banner from the first 4 KiB of something
  larger. The read now takes one byte past the cap and refuses when it arrives,
  which is the same fix as the body cap below and is there for the same reason.
  The cap itself is unchanged, a greeting of exactly 4096 bytes still arrives
  whole, and no real SSH, SMTP or FTP greeting comes near it. (M26-NET-026)

- **A pid past 2^31 was truncated and killed a different, live process.** A
  script's integer is 64 bits and a pid is not: gopsutil takes an `int32` and
  Windows takes a `DWORD`. `process_kill(getpid() + 2^32)` compared unequal to
  the current pid, walked past the guard that exists to refuse exactly that, and
  then killed the run anyway with the low 32 bits. The test that pins it ends the
  process running it and prints no failure message, because the binary is gone
  before it can; that signature is the evidence. `process_hash` and the rest
  answered about one process while labelling the answer with another. Every pid
  argument is now narrowed where it is read, in one place, and a value outside
  the range is refused by name. Zero is still accepted by the query builtins, and
  that is deliberate: Windows reports the System Idle Process as pid 0 and
  `process_list` returns it first, and `syslog_parse` writes 0 for any line with
  no procid, so the ordinary loop over what Mutant handed back reaches
  `process_threads(0)`, which answers today. `process_kill` alone refuses 0 and
  negative values, because to `kill(2)` those name process groups and not
  processes. (M26-NET-005)

- **The request line and header block of an intercepted message were read
  without a bound.** `maxHTTPBodyBytes` capped the body and nothing capped the
  head, so a peer -- which on an intercepted connection is whatever is on the
  wire -- could send one header field of any length and have it read in full: an
  8 MiB field grew the heap by 12 MiB and a 32 MiB field by 69 MiB, and both were
  accepted. The head is now bounded at 1 MiB, the figure net/http uses for its
  own servers, with 4 KiB of slack for the single `bufio` fill that can
  legitimately carry the start of a body past the end of the head -- which is
  also what net/http's server allows, and for the same reason. The limit sits on
  the reader beneath the `bufio.Reader` and is released once the head is parsed,
  so `http_conn_read_request_head` followed by `net_conn_read` still streams a
  body of any size; a 2 MiB body drawn through the 1 MiB head budget is a
  regression test. (M26-NET-008)

- **A pcap record header sized its own allocation.** gopacket takes the snapshot
  length out of the file header and then accepts any record no longer than it, so
  a forty-byte file declaring a snaplen of `0xffffffff` drew a 16 MiB allocation
  out of each of `net_capture_raw`, `net_pcap_analyze` and `net_os_fingerprint`.
  The reader's snaplen is now held to the file's own length, which no honest
  capture can exceed, and the forty-byte file is refused before anything is
  allocated for it. A constant would have been wrong: USBPcap declares 128 MiB
  and writes records in the megabytes, and EBHSCR records run to 32 MiB, and both
  read correctly today -- a record's index, timestamp and length come out of its
  sixteen-byte header and need no decoder, so a link type gopacket cannot decode
  costs the empty `src`, `dst` and `protocol` fields and nothing else. A gzipped
  capture is the one case where the file's size bounds nothing, because gopacket
  decompresses it transparently, and there a 128 MiB ceiling applies instead.
  (M26-NET-009)

- **A body past 32 MiB was cut and reported as a whole one.** The body was read
  as `io.ReadAll(io.LimitReader(body, maxHTTPBodyBytes))`; `io.LimitReader`
  returns EOF at its bound and `io.ReadAll` turns EOF into nil, so a 40 MiB body
  came back as exactly 32 MiB with no error and no flag. An intercepted response
  was recorded as complete with 8 MiB missing and nothing in the result could
  tell a caller. `http_conn_read_request`, `http_conn_read_response`,
  `http_parse_request` and `http_parse_response` now read one byte past the cap
  and refuse when it arrives. This is a behaviour change: a script that read a
  body larger than 32 MiB used to get the first 32 MiB and now gets an error.
  Take the head with `http_conn_read_request_head` and stream the body with
  `net_conn_read` to read one of any size. (M26-NET-031)

- **A response cut off mid-body was reported as a successful empty one.**
  `http_get`, `http_post` and `http_request` read the body with `io.ReadAll` and
  then dropped the error: the body became `""`, the response hash's `error` field
  was a hard-coded empty string, and the pair's error was nil. A server that
  declared `Content-Length: 100` and sent 10 bytes before closing therefore came
  back as `{status: 200, body: "", error: ""}` with no error anywhere, so a
  dropped IOC feed or evidence download read as a document with nothing in it and
  a script that treats an empty feed as "no indicators" got a false negative. The
  bytes that did arrive are now returned, the reason travels with them in the
  `error` field, and the pair's error is non-nil. The machinery for that was
  already in place -- the field is what decides whether an error is returned, and
  only the producer never filled it in. The status line and headers are reported
  as before, which is what tells a truncated response, with its real status, from
  a connection that never produced one, which still reports status 0.
  (M26-NET-002)

- **`process_tree` looped forever and grew until the process died, starting with
  `process_tree(0)` on Windows.** The walk was breadth-first over a parent map
  with no visited set, so a process that is its own parent put itself in its own
  child list: every pass appended it again, and the queue and the result both
  grew without bound. Windows reports pid 0, the System Idle Process, with parent
  pid 0, and `process_list` returns it first -- so a triage script that called
  `process_tree` for each pid it listed met this on the first one, at 2 MiB
  growing past 1 GiB in under five seconds. A parent cycle caused by pid reuse
  did the same from an ordinary pid. Nothing panicked, so the `recover()` around
  a builtin could not help. Each pid is now reported at most once, the root is
  never its own descendant, and the walk ends after at most one pass per distinct
  pid whatever the parent links say. Ordinary trees are unchanged, children still
  sorted by pid at each level. (M26-NET-003)

- **The live registry reported a value that does not exist as a present, empty
  `REG_NONE` value, with no error.** Every error from the underlying read,
  `ERROR_FILE_NOT_FOUND` included, was mapped to an entry of type `REG_NONE` with
  empty data and handed back as a success, so `reg_get_value` on a live source
  answered "yes, an empty REG_NONE" for every name ever asked, while the JSON and
  hive-file sources answered `value not found`. "Does this Run key hold value X?"
  came back yes for any X. Because real `REG_NONE` values exist, absence was not
  merely unreported but indistinguishable from a value that is there. All three
  sources now give the same `value not found` error, from one function rather
  than from three copies of a string, and a value that is present and empty is
  still returned as itself. The type-specific reads no longer discard their
  errors either, so a value deleted or retyped between the call that reads its
  type and the call that reads its data is reported instead of coming back as a
  zero value; and `reg_list_values` fails rather than silently omitting a value
  that vanished while it was listing. (M26-NET-004)

- **A small `.pcap.gz` was an unbounded read in `net_pcap_analyze` and `net_os_fingerprint`.**
  Both looped over every record in a capture and accumulated a map entry per flow and per
  fingerprint with no cap at all, and pcapgo recognises the gzip magic and wraps the file in a
  decompressor, so the size of a compressed capture bounded nothing inside it. A 31 KiB file of
  two million sixteen-byte record headers read for 2.3 seconds, and 200,000 records each carrying
  a distinct flow left 224 MiB of live heap behind — 541 bytes per record, linear in a count the
  file does not disclose, so a larger file is an out-of-memory rather than a slow read. Evidence
  files are untrusted by definition. `net_capture_raw`, which already stopped at a record cap and
  marked the result `truncated`, was the contrast rather than a third case. Two bounds now
  compose, and both are reported the way `net_capture_raw` already reported its one: the record
  cap it had is now shared by all three readers, and a new named limit bounds how far a
  *compressed* capture may expand. The second bound is on the decompressed stream and not on the
  file, because the file's smallness is the attack — gopacket opens the decompressor itself, so
  Mutant now opens the gzip layer first and hands gopacket a stream that has already been counted.
  A capture gzipped more than once is refused, because a second decompressor inside gopacket would
  sit outside that count; such a file failed its header check before this change too. All three
  builtins return `truncated: true` when they stopped at either bound, and then every count, every
  flow row and every fingerprint covers only the records that were read. An uncompressed capture
  is read exactly as before: there the file's own length is the bound, and a constant could only
  refuse something real. (M26-NET-027, and M26-NET-034 for the result size a million flow rows
  still reaches)

- **Neither REPL could call a function defined on an earlier line.** `let add = fn(a, b) { a + b };`
  and then `add(1, 2);` failed in both the terminal and the browser REPL, and the error said the
  program had been built by a newer version of mutant. Each line is its own program, and the
  keystream its bytecode is sealed with is derived from that line's instruction length -- the
  number the VM recovers and derives its one decryption key from. The constant pool carries from
  line to line, so sealing it again on every line encrypted a function compiled earlier a second
  time, under the new line's key, and the VM then read the earlier line's ciphertext as opcodes.
  Both REPLs now seal through one shared helper that re-keys a carried-over function from the
  length it was sealed under to this line's, in place on the same function object so that a
  closure held in a global agrees with the pool; a line it cannot re-key is refused rather than
  half-written. Integers and strings bound on an earlier line were never affected, because each
  records the seed it was encrypted under (M26-TOOL-013). Fixing that exposed a second defect
  behind it: the terminal REPL wiped its own session after every line. The per-line cleanup's
  stack sweep emptied the shared encrypted constants and dropped closures' captured values, so a
  function that used a literal could not be called twice and a closure could not be called at all
  after the line that created it -- the same hazard `net_serve` and the browser REPL already
  avoid, and they now all avoid it for the same stated reason (M26-TOOL-040). The unknown-opcode
  message no longer names one cause: it says the instruction did not decode, and that the bytecode
  may be damaged or decrypted with the wrong key, or may come from a newer mutant.

### Security

- **A string literal in an open document can no longer send the language server
  to a network share, at a device, or outside the workspace.** The editor
  underlines string literals that name an existing file, so that an examiner can
  click through to an image or a report. Deciding whether a file exists means
  asking the filesystem, and the handler asked about any literal that looked
  like an absolute path — including a UNC path such as one naming a host that
  does not answer. That lookup ran on the single goroutine the server reads
  client messages on, so completion, hover, diagnostics and every other feature
  stopped until the network gave up: measured at 42 seconds for one literal in
  one document. A path reaching out of the workspace was offered as a live,
  clickable link, and nothing refused a Windows device name. A document is just
  text, and opening one is not consent to resolve what it says.
  Links are now resolved only inside directories the operator chose — the
  document's own folder and the workspace roots — and only through `os.Root`,
  which refuses a `..` escape, a reserved device name such as `NUL` or
  `CON.txt`, an alternate data stream, and a symbolic link whose target leaves
  the root. Anything else is refused before the filesystem is asked at all, so
  there is no lookup to wait for. Relative paths work exactly as before,
  including `../evidence/usb.img` from a notes file inside a case folder, and a
  single file opened with no folder still links files beside it. One request is
  also now bounded: a literal is looked up once however many times it appears,
  and one request makes at most 1024 lookups, so no single document decides how
  long the rest of the editor waits. (M26-LSP-002)

- **A field named twice in a sealed document was authenticated away.** `encoding/json` keeps the
  last of two identically-named fields and drops the first without a word, and four readers in this
  tree authenticate a document over a canonical form they rebuild from what the decoder kept — so a
  second copy of any field, inserted in front of the real one, was a value a reader saw and that no
  hash and no signature covered. Measured rather than argued: a probe replicating
  `case_manifest_verify`'s decoder settings and its canonical rebuild field for field signed an
  honest 98-byte manifest with Ed25519, and that one signature verified against a forged 119-byte
  file — both produced the identical canonical bytes and the identical SHA-256, so the digest
  matched, the signature held, and the verifier reported the file verified. `DisallowUnknownFields`
  does not catch it: the name is known, it is simply there twice. The four readers are the case
  manifest, the disclosure manifest, the case key file and the grant file, and each now refuses
  such a document as a verification failure, naming the field and the byte its second spelling ends
  at. The canonical form itself is deliberately unchanged, so every document this build has already
  sealed still verifies. `jwt_decode` had the same fault without a seal under it: a header spelled
  `{"alg":"none","alg":"HS256"}` was read here as the last copy and by a library that keeps the
  first as the other, over the identical signed token, and `alg` is the field that decides whether a
  signature is checked at all. Both of its segments refuse a repeated name now, which RFC 7519
  permits a parser to do. Nothing a JSON encoder emits is refused by any of this — no encoder writes
  a member name twice — and the one shape this build itself writes, a manifest whose `fields` array
  names a field that is also a key, still verifies and is held to that by a test. One more line
  changed with them and nothing about it is visible today: `json_parse`'s own end-of-input check
  compared a sentinel with `==`, which the newer of Go 1.26's two `encoding/json` engines would read
  as a trailing document and refuse every well-formed file; it asks `errors.Is` now, as the shared
  check beside it already did. (M26-CUS-032, M26-BLT-027)

- **A file this build verifies holds one document, and every parser now reads all of it.** Nine
  parsers decoded the first JSON document in a file and stopped. Bytes after it were never looked
  at, never hashed and never covered by the signature the verifier went on to report as holding —
  so a case manifest, a disclosure manifest, an audit log, a case key file, a record header, a
  record footer, a grant file, a registry hive and both segments of a JSON Web Token could each
  carry a second document that nothing had checked, and the file was reported verified. The seal
  is computed over the document the decoder returned, which is exactly why the tail changed no
  hash and raised no finding: an examiner was told a file verified when part of it had never been
  read. Six of the nine had no check at all. The other three had one, and it was not enough:
  `decoder.More()` reports that there is nothing further to read whenever the next character is
  `}` or `]`, so a document followed by a single closing brace passed — and every byte after that
  brace went unexamined, a whole second document included. All nine now ask one shared check that
  accepts only the end of the input, and refuse with the byte offset the document ended at, as a
  verification failure rather than a parse success. Trailing whitespace still parses, deliberately:
  a rewrite interrupted between the truncate and the write leaves a key file padded with newlines,
  and refusing to open it would turn a survivable crash into a lost case key. `jwt_decode` is the
  one with a second lesson in it — a header segment holding two documents gave this build one
  answer for `alg`, the field that decides whether a signature is checked at all, and the next
  library along another. (M26-CUS-026, M26-CUS-031, M26-REC-028, M26-BLT-025, M26-BLT-026)

- **The run time printed what `putln` had just refused to print.** A buffer read out of a
  classified record is refused by `putln`, `fs_write`, `report_render` and thirteen other
  builtins. It was not refused by the three places the run time prints a value with no builtin
  involved: a traceback's arguments, the debugger's variables pane, and the value a finished
  program is echoed as by `mutant prog.mu`, by the REPL and by a debug session that steps to the
  end. A program that ended on the buffer printed all of it; a function that failed with one as a
  parameter printed the front of it; the variables pane, which has four times the room, printed
  more than either. The three now ask the same walk the sinks ask, before rendering anything, and
  print a notice naming the record and the classes instead. The walk itself gained two carriers
  it had no arm for: the values an error holds in `Related` -- so `putln(err)` no longer prints a
  buffer the error was built around -- and a value still sealed, which is how a captured variable
  reaches a sink, since a cell is handed back by pointer without being opened. One renderer now
  serves the traceback and the pane, which were the same twenty lines in two files.
- **An empty program crashed the runner.** A file with nothing in it, or only a comment, compiled
  and then died with a Go nil-pointer panic and a goroutine dump, exit 2, because the value it
  ended on was read without checking for nil -- exiting quietly was the whole of what was wanted.
  The REPL and the debug adapter both checked already. A new file run from the editor was the
  common way to see it.
- **A traceback reported a captured parameter as its ciphertext.** A parameter an inner function
  closes over lives in a cell, and decrypting a cell returns the cell, because the write-through
  a closure needs would be lost in a copy. The traceback rendered what was inside: `f(n=[153 72
  150 254 248 119 238 27])` where `n` was 2999, with different bytes on every run, so the
  traceback could not be compared between runs either. It takes the cell off first now, which is
  what the debugger already did.

- **A crafted artifact could kill the process parsing it, and one kind could
  do it silently.** A count read straight out of a registry hive, a jump list
  or a binary plist sized an allocation before the bytes it promised were
  there to read, so the memory a parse asked for grew with a header field
  rather than with the file: a 32-byte DestList stream claiming 2^22 entries
  asked for 224 MiB, and a 48-byte plist claiming 2^24 objects asked for
  128 MiB. A Go allocation past what the host can commit is a fatal error no
  `recover` catches, and every one of these entry points wraps itself in one.
  Separately, a binary plist refers to its values by index, and expanding that
  graph into a tree was bounded only by nesting depth -- so twenty levels of
  arrays each holding two references to the next returned a 32 MiB value tree
  from 119 bytes **with no error at all**, and four times that per two further
  levels. Every pre-size is now bounded by what the bytes can hold, and a
  plist that would expand to more values than it has bytes is refused, naming
  the shared containers that did it; a shared string is decoded once, and a
  container holding itself is named as one.
  (M26-ART-005, M26-ART-008, MVF-2026-0012, MVF-2026-0013)

- **Two of those were reported from outside the project as well.** The
  allocation half -- a count read out of a file sizing an allocation before
  the bytes are there -- and the binary plist expansion were found
  independently and reproduced against 2.5.0 through a compiled artifact,
  which established that a crafted evidence file can kill a running script
  outright rather than return an error. Reported by **Pranjal**, a BTech
  student in his fifth semester at the National Forensic Sciences University
  (NFSU). He asked to be credited publicly, and the name and affiliation are
  printed at his request. (M26-ART-005, M26-ART-008)

- **The code-signature encoder destroyed the timestamp it wrote, and the
  decoder panicked on a malformed one.** `CodeSignature.Encode` wrote the
  timestamp as `string(rune(cs.Timestamp))` -- a Unicode code point, not a
  number. Every Unix timestamp since 1970-01-13 is larger than the largest
  valid code point, so the conversion yielded U+FFFD and the field encoded as
  `efbfbd` whatever the time was; `DecodeSignature` then read one byte of it
  and returned 239 for every real timestamp, and indexed an empty slice when
  the field was absent. The timestamp is now eight big-endian bytes, and a
  field of any other length is refused by name. **Nothing called this pair**,
  so it carries no MVF identifier and the custody seal that does carry a
  signature, writing its fields separately, was never affected --
  [docs/advisories/README.md](docs/advisories/README.md) records why.
  (M26-SEC-009)

- **A key-derivation branch would have opened data under any password.**
  `ReconstructKey` picked a derivation by the algorithm name stored beside the
  data, and its `hkdf-sha256` arm derived the key from the stored salt alone --
  as both the secret and the salt -- without ever reading the password. Every
  passphrase produced the same key, so data naming that algorithm would have
  opened under an empty one. That arm is refused now, and the unknown-algorithm
  arm is held to returning no key material rather than a short one. Nothing
  reached it: the only caller writes `argon2id` into the parameters itself and
  never takes the algorithm from the data, and the one function that would have
  read an algorithm name out of a stored blob has no callers and cannot parse
  what its own encoder writes. So this closes a trap for the next caller rather
  than a hole for the current one, and it carries no identifier for the same
  reason -- [docs/advisories/README.md](docs/advisories/README.md) says which
  test it fails. (M26-SEC-009)

- **The toolchain moves to Go 1.26.6, and `golang.org/x/crypto` to v0.56.0.**
  Under go1.26.2, govulncheck found 18 standard-library vulnerabilities the code
  reaches, several through parsers that read evidence: XML inside an E01 image
  and in plists, certificates, email addresses. go1.26.6 fixes all of them. A
  release binary compiles the standard library in, so the move matters to
  anyone who runs a released `mutant`, and anyone building from source needs
  go1.26.6 or newer. `go test ./policy/` refuses a `go.mod` that goes back
  below either version. These are upstream defects that already carry
  upstream identifiers, which `govulncheck` names; this project does not
  rename other people's vulnerabilities, so there is no MVF for them.
  (M26-RUN-003)

- **`sqlite_query` and `sqlite_query_bytes` could modify the evidence they
  read.** Both copy the database first and promised the original is never
  touched, but ran the script's SQL on a writable connection to that copy, so
  `ATTACH` opened any other path read-write. A plain `SELECT` through an
  attached WAL-mode database checkpointed its write-ahead log into it and
  deleted the log -- uncheckpointed and deleted records with it -- and a bound
  parameter, classified plaintext included, could be written to a file the
  script named. The copy is now opened read-only and may attach nothing, so
  `ATTACH` and `VACUUM INTO` are refused with a reason and no statement writes
  any file. Joining two databases takes two queries. The `browser_*` parsers
  read through the same confined connection. (M26-DAT-001, MVF-2026-0007)

- **`audit_verify` passed two kinds of doctored log.** A log with entries
  deleted from the front verified as intact, anchored and complete against the
  head sealed into the case manifest, because the head is the last entry's hash
  and the verifier never checked where the chain began; and an entry with no
  sequence number, or a sequence number that was not a positive integer, ended
  the walk as though nothing had broken, so forged entries appended after the
  last genuine one verified too. The last entry's sequence number is inside its
  hash and the memory cap drops entries by a fixed rule, so the verifier now
  knows which entry a log of that length must start with, and refuses any other;
  every entry needs a positive, consecutive sequence number; `entries`,
  `dropped` and `chain_complete` are recomputed from the entries rather than
  copied from the document; and a break carries its position in the new
  `broken_index`. (M26-CUS-005 and M26-CUS-006, MVF-2026-0003 and
  MVF-2026-0004)

- **A script could redact the disclosure ledger's own records.** The
  `ledger_redact_*` builtins checked the handle, the id and the reason but not
  what they were removing, and a redaction deletes a record's index entries with
  it -- which is how every `disclose_*` builtin finds a withdrawal, a disclosure
  or a reclassification. Redacting a Withdrawal re-enabled grants to the
  recipient it had withdrawn; redacting a Disclosure took it out of
  `disclose_history`. The four redaction builtins now remove only what a script
  wrote: any node or edge of the disclosure schema, and any node whose cascade
  would take such an edge, is refused with the reason, and
  `ledger_redaction_impact` reports `protected` and `protected_reason` before
  anything is attempted. A disclosure record is corrected by appending a new
  one, never by removing an old one. (M26-CUS-001, MVF-2026-0002)

- **`disclose_verify` verified a genuine package that had been relabelled or
  given another disclosure's grant.** Its ledger check proved the manifest's
  copy of the ledger record was in the snapshot, but never held that record to
  the package around it, and the manifest is signed by whatever key it carries.
  So a genuine package re-labelled for another recipient, or holding another
  disclosure's grant beside this one's ledger record, re-signed with any key,
  verified against the genuine root. A new check, `ledger_matches_package`,
  compares what the ledger recorded with the manifest's recipient, examiner and
  view and with the record and grant files themselves -- digest, uid, runs,
  descriptors root -- and names every disagreement; a package now takes eleven
  checks to verify. The result also gives `manifest_public_key` and
  `record_public_key`, because a signature means something only once its key is
  compared with one the recipient already trusts. (M26-REC-005,
  MVF-2026-0006)

- **A refused disclosure was refused too late.** `disclose_to_passphrase`
  derived the grant's key material and asked the examiner to choose and
  confirm its passphrase before checking whether the recipient's earlier
  disclosure of the record had been withdrawn, or whether the record had been
  reclassified. The refusal still came and nothing was issued, but
  DISCLOSURE_POLICY promises the withdrawal is checked before any new key is
  issued. Both refusals now come first, and are asked again inside the ledger
  write for a withdrawal recorded in between. The refusal always came and
  nothing was ever issued, so what broke was the documented order rather
  than a security property: this is a conformance fix and carries no MVF.
  (M26-REC-001)

- **Two different strings could be one hash key.** A string or buffer used as
  a hash key was identified by its 64-bit FNV digest alone, and lookups never
  compared the key itself, so two values with one digest -- a pair takes under
  a minute to find -- were one entry in both engines: a count lost one of them,
  and a lookup of either returned the other's value. Hash keys chosen from
  evidence, such as file or account names, could be merged that way on purpose.
  A string key is now the whole string, and a buffer key its SHA-256.
  (M26-EVL-003, MVF-2026-0005)

- **A classified buffer put in a report table was written out whole.**
  `report_table` and `report_list` render each cell to text as it is added --
  a buffer as its hex -- so by the time the report reached `report_render` or
  `report_write`, both of which refuse classified plaintext, there was no
  marked buffer left for them to find. Both builders now refuse one where it
  goes in, and the editor warns at the call. (M26-DAT-002, MVF-2026-0008)

- **`HOME` or `USERPROFILE` chose the signing key, and the key `--signer-auth`
  trusts.** The local keystore -- the key pair that signs every `.mu` artifact,
  case manifest, ledger commit and `.mrec` record, and whose public half
  `--signer-auth` trusts when no `--trusted-key` is named -- sat under the home
  directory `os.UserHomeDir` returned, and that function reads those variables.
  So one command line could sign with, and trust, a different key depending on
  something the recorded invocation never shows. The home directory now comes
  from the account database: the process token's profile directory on Windows,
  the directory service on macOS, and `/etc/passwd` on Linux, read directly
  because `os/user` built without cgo answers from `HOME` for an account that
  file does not list. Such an account -- one only NSS or LDAP knows, or an
  unnamed container uid -- is refused rather than guessed at. Anyone who pointed
  either variable elsewhere to reach a keystore should move `.mutant/keys` under
  the account's own home. The policy guard now also catches `os.UserHomeDir` and
  the other standard-library calls that read the environment inside themselves,
  and CONFIGURATION_POLICY lists every variable the Go runtime and Mutant's
  libraries still read. (M26-DOC3-001, MVF-2026-0009)

- **A ledger redacted by an older build could have lost a withdrawal without a
  trace.** The redaction builtins refuse every record of the disclosure schema,
  but a ledger redacted by a build from before that refusal may hold a redaction
  that removed one -- a withdrawal, a disclosure or a reclassification -- and a
  redaction record names what it removed by id and hash, never by label. A
  withdrawal removed that way let its record be disclosed again to the recipient
  it was withdrawn from, and the history no longer counted it. Every redaction
  recorded with no role is now in question (every build that records a role also
  refuses the schema), unless it only stripped the properties of a node or an
  edge a script wrote that the ledger still holds; `disclose_to_passphrase`
  issues no grant from a ledger holding one until `ledger_redactions_review`
  records that an examiner has answered for it. A withdrawal is now also found by
  the record and the recipient it names, so one whose disclosure was removed
  still stops a new grant. No released version is affected: the ledger family is
  new in 2.6.0. (M26-CUS-021, MVF-2026-0011)

- **A macro body ran whatever it liked, while the compiler was running.**
  A macro is expanded before any code is generated, and expansion evaluated its body
  against the whole builtin registry. So compiling somebody else's source wrote files,
  ran programs and read the host -- before the program was started, before a password
  was asked for, and before any of the run time's controls existed. Compiling is not
  running. Three separate paths reached the registry, not one: the plain name; the
  namespaced spelling, because `fs.write` folds to the same builtin through a second
  lookup that a fix aimed at the first would have left open; and `with_resource`, which
  resolves what it calls from a string while it runs, where no rule that reads names can
  see it. Expansion now resolves only the builtins listed as macro-safe -- pure
  computation over values the body already holds -- and refuses every other one by name,
  saying which of reading a file, reaching the network, running a program, opening a
  handle, drawing entropy, reading the clock or writing state the program would later
  read back it would have done. Seven are refused for none of those: `aes_encrypt`,
  `aes_decrypt`, `aes_decrypt_bytes`, `x509_parse`, `der_parse`, `jwt_decode` and
  `pem_decode` decode cryptographic material, and a compile is the wrong place to run a
  cipher or a certificate parser over bytes the source carries; parsers of ordinary
  structure such as `json_parse` and `csv_parse` stay available, because writing code
  from a table the macro carries is one of the reasons to have macros. The reach was
  wider than the file anybody typed:
  expansion covers every module in the linked graph, so a macro in an imported library
  ran at the importer's compile; `mutant test` with no arguments compiles every test
  program it can find, and filters by name only afterwards; and a debug launch compiled
  before `stopOnEntry` applied, so "load it and stop at the first line" had already
  expanded it. The language server never expanded macros, so opening or saving a file
  ran nothing. One thing changes for programs that worked before: a macro body that
  called a builtin outside the macro-safe list is now a compile error that names the
  builtin and says why. Reported by **Pranjal**, a BTech student in his fifth
  semester at the National Forensic Sciences University (NFSU). He asked to be
  credited publicly, and the name and affiliation are printed at his request.
  (M26-EVL-012, MVF-2026-0001)

- **The editor extension's release task put the password in the argument
  list.** The packaged task that builds a signed artifact passed it with
  `--password`, so for as long as the build ran the password could be read
  from the process list by anything running as the same user. The task now
  sets its `password` field, which reaches the binary the way the example
  sweep does, and a bare `--password` is refused outright -- see Changed.
  mutant itself wrote the credential nowhere, but the route required it on
  disk: the `password` property is part of a task definition, which lives in
  `.vscode/tasks.json` in the workspace and is commonly committed with the case
  scripts, so the exposure is that file as well as the argument list for the
  life of the build. (M26-LSP-017, MVF-2026-0010)


- **A crafted ledger property blob could end the process.** Reading a node's
  or an edge's properties back pre-sized its map from the entry count the blob
  declares, and a msgpack `map32` header is five bytes that can claim
  4,294,967,295 entries. So a stored blob with no body at all made Go allocate
  buckets for four billion properties -- about 96 bytes each, measured, so
  something near 400 GB -- and the process died on a fatal runtime
  out-of-memory, which no script can catch and which takes any unflushed work
  with it. The decode did reach an error about the missing body; it reached it
  after allocating. A declared count is now checked against the blob that
  declares it before anything is sized from it: a blob of n bytes cannot hold
  more than n/2 entries, which needs no new limit and rejects nothing the
  encoder can write, since every entry it writes takes at least three bytes.
  No released version is affected: the ledger family is new in 2.6.0.
  (M26-CUS-030)

## [2.5.0] — 2026-09-17

The v2.5 line — *trustworthy: structural correctness*. The theme is that every
claim the README makes becomes verifiable.

### Added

- **Sigma rules, evaluated here.** Four builtins in the `detection` category:
  `sigma_parse` and `sigma_parse_all` compile a rule or a multi-document
  ruleset, `sigma_match` asks one rule about one event, and `sigma_scan` runs a
  ruleset over an `events_from` timeline, compiling each rule once.

  Supported: search identifiers as mappings, lists of mappings or keyword lists;
  `and`/`or`/`not`, parentheses and the `all of`/`N of`/`any of` quantifiers over
  `them` and over identifier patterns; and the value modifiers `contains`,
  `startswith`, `endswith`, `all`, `cased`, `re` (with `i`/`m`/`s`), `base64`,
  `base64offset`, `utf16`/`utf16le`/`utf16be`/`wide`, `windash`, `cidr`,
  `lt`/`lte`/`gt`/`gte`, `exists` and `fieldref`, with Sigma's `*` and `?`
  wildcards and its case-insensitive default.

  This is possible where a YARA engine is not, and the difference is worth
  stating: YARA needs libyara, libyara needs cgo, and everything here builds
  under `CGO_ENABLED=0`. A Sigma rule is YAML and a matching model, and the two
  things it needed already existed -- `yaml_parse_all`, because a ruleset is a
  multi-document YAML file, and `events_from`, because a rule needs something
  uniform to match against.

  Field names are looked up on the event and then inside `extra`, where
  `events_from` keeps the parser's entry verbatim, so a rule written in a
  source's own taxonomy runs against a normalized Mutant event with no
  field-mapping configuration in between.

  **A rule this engine cannot evaluate is a compile error, never a silent
  non-match.** Aggregations, `near`, `timeframe`, rule collections, `|expand`
  and unknown modifiers are all refused by name, as are a condition naming an
  undefined search identifier and an `all of filter*` that matches none. A rule
  that quietly never fires counts toward coverage and finds nothing, and nobody
  goes looking for it. For the same reason `sigma_parse_all` fails the whole
  ruleset when one rule in it does not compile.

  `sigma_match` and `sigma_scan` also report the fields a rule read that the
  evidence never carried -- `fields_missing` and `unmatched_fields`. A ruleset
  pointed at an artifact without its fields returns zero hits and is correct
  about it, and that zero is a rule that never ran rather than a clean host.

  See [DETECTION_RULES.md](docs/DETECTION_RULES.md),
  `examples/detection/sigma_rules.mut` and cookbook recipe 15.
  `docs/COMPARISON.md` said "there is no Sigma support at all"; it no longer
  does, and it still says what a rule engine is better at.

- **A probe that checks the field names in a return contract.** A contract's
  shape (bare or `(value, err)`) and the kind of its success value were both
  verified against a real call; its **field names** were not, and those are what
  the editor renders on hover and what a program types. `{path, bytes, format,
  sha256}` is declared in `builtin/metadata.go` and spelled again wherever the
  builtin builds its result, with nothing linking the two.

  `TestEveryFieldAnImplementationReturnsIsDeclared` calls a builtin for real and
  requires every key it returns to be declared -- which catches a typo in either
  copy, since a renamed key is undeclared and a renamed declaration leaves the
  real key undeclared. It reuses the existing purity gate, so it reaches only
  the builtins that compute rather than touch the world: **4 of the 162 that
  declare fields**. It logs that number rather than implying coverage it does
  not have, and widens for free as the pure-probe categories do.

- **Every build script writes a `SHA256SUMS` beside what it produced.**
  `scripts/build.sh` and `scripts/build.ps1` write one next to the six binaries
  and another next to the wasm REPL artifacts; `lsp/build.sh` and
  `lsp/build.ps1` write one next to the six language servers; both VS Code
  packaging wrappers write one next to the vsix, and `npm run package` writes
  one covering all six per-platform vsix files.

  It is the format `sha256sum -c` reads -- lowercase hex, two spaces, the
  file's bare name -- so someone who downloads a binary verifies it with a tool
  they already have and nothing from this project. The same format
  `case_bundle` has always written, for the same reason. Names are bare and
  each file sits beside what it covers, so checking is
  `cd <dir> && sha256sum -c SHA256SUMS`. Lines are sorted under `LC_ALL=C` and
  the PowerShell scripts sort to match, so the shell and PowerShell halves emit
  byte-identical files; a script refuses rather than recording a digest for a
  file the build did not produce, and the bootstrap binary is deleted before
  the sums are taken rather than sitting unlisted in the output directory.

  This is not a substitute for signed binaries, which is still open. A checksum
  published beside the file it covers proves the download arrived intact, not
  that it came from us.

- **One event vocabulary across every parser, and three ways out of it.** Five
  of the seven builtins in a new `schema interchange` category.
  `events_from(artifact, kind_or_mapping)` normalizes any parsed artifact into a
  fixed set of event fields and `event_kinds()` reports what each supported
  artifact maps; `ecs_event`, `ocsf_event` and `timesketch_event` write that
  vocabulary out as Elastic Common Schema documents, OCSF events, or the plaso
  records Timesketch ingests.

  The parsers each hand back their own shape, because each artifact *is* its own
  shape -- an `$MFT` record carries eight timestamps, a Prefetch file carries a
  list of run times, a syslog line carries one. That is right for a parser and
  wrong for a timeline, and wrong for anything downstream that wants one row
  format. The alternative to normalizing was a table per (artifact, schema) pair:
  thirteen artifacts and three interchange schemas is thirty-nine tables, each of
  which drifts the moment either side changes. With one hop in between it is
  thirteen plus three, and a new parser reaches every schema by writing one
  mapping.

  Thirteen source kinds are mapped: `mft`, `prefetch`, `evtx`, `lnk`, `amcache`,
  `shimcache`, `jumplist`, `syslog`, `browser_history`, `browser_cookies`,
  `browser_downloads`, `bodyfile` and `mactime`. Every kind produces the same
  shape, so a supertimeline across all of them is a `timeline_merge` of the
  results.

  Three rules keep the output honest. **An unknown field is absent, not empty**
  -- an empty string in a forensic record reads as "the artifact recorded nothing
  here", which is usually a claim the parser never made; a `size` of zero is kept
  because an empty file has a real size of zero. **A zero timestamp produces no
  event**, because these artifacts use 0 for "not recorded" and an `$MFT` has
  plenty; emitting them would bury the real rows under thousands of 1970 ones.
  **`extra` carries the source entry verbatim**, so normalizing is additive and
  nothing the parser found is lost -- a normalized view of evidence that quietly
  drops fields is a view an examiner cannot testify from.

  `severity` is a word (`informational` through `fatal`) rather than a number,
  because the numeric scales disagree about direction: syslog counts down from 0
  Emergency, Windows event Levels count up from 1 Critical. Converting once in
  the source mapping means each downstream schema converts from one known thing.
  Windows Level 0 (`LogAlways`) asserts nothing about severity, so it produces
  none rather than a guessed `informational`.

  `$FILE_NAME` timestamps are described apart from `$STANDARD_INFORMATION` ones,
  because the disagreement between the two sets is the timestomping tell and a
  timeline that merged them would hide it. Amcache and Shimcache are categorised
  as `execution` with the action `present`, not `run`: both record that a program
  was on the host, which is evidence of execution rather than proof of it.

  **The three emitters each take one event or a whole timeline** and hand back
  the same shape, so an `$MFT` normalized and handed to Timesketch is two calls
  and an `ndjson_stringify` rather than a map over three hundred thousand rows
  with a `(value, err)` pair on each. All three take the same options: `host` and
  `user` fill in what an artifact structurally cannot record -- an `$MFT` knows
  every path on the volume and nothing about which host the volume came out of --
  without ever overwriting what the artifact did record; `tags` lands in each
  schema's own tag field; `extra: false` leaves the verbatim source entry out. An
  unknown option key is an error, and so is a hash that did not come out of
  `events_from`: emitting a raw parser entry would produce a document with no
  timestamp and every mapped field missing, which looks like a real document and
  indexes like one.

  **The emitters carry the envelope's honesty into each schema** rather than
  filling required fields with guesses. ECS `event.type` is read off what the
  timestamp records rather than off the artifact's kind, and `event.category` is
  omitted where ECS has no honest value instead of filing a log line under
  something it is not; severity is emitted as both the word (`log.level`) and a
  syslog-direction number (`event.severity`), so nothing downstream has to know
  which way the scale runs. OCSF classes say where a record belongs, not that
  Mutant observed it happen: `execution` stays on the Base Event rather than
  taking 1007 Process Activity, because Amcache records presence and a detection
  written against 1007 would fire on it, and `registry` stays there rather than
  borrowing the `win` extension's uid, which means nothing to a consumer that has
  not loaded it; `severity_id` 0 and `file.type_id` 0 are OCSF's own way of
  saying the source did not report one. Timesketch's three required fields --
  `message`, `datetime` and `timestamp_desc` -- are never left empty, because
  Timesketch drops such a record on ingest rather than flagging it, and a kind
  with no plaso equivalent gets `mutant:<kind>:event` rather than a borrowed
  `data_type` that an analyzer would then run over and report on.

  An artifact Mutant does not parse is described with a mapping hash --
  timestamps, their meanings and formats, and which source field fills which
  event field -- rather than waiting for a source kind to be added. It is the
  same mechanism the built-in kinds use; there is no privileged path. See
  [docs/INTERCHANGE_SCHEMAS.md](docs/INTERCHANGE_SCHEMAS.md).

- **Investigations end in a report.** Seven builtins in a new `reporting`
  category. `report_new` starts one and `report_section`, `report_text`,
  `report_list` and `report_table` fill it in; `report_render` renders it as
  HTML, Markdown or CSV, and `report_write` renders and writes it in one step. The report is a plain hash, so it can be JSON-encoded,
  stored, diffed against the last one or written by hand, and every builder
  returns a new document rather than changing the one it was given. `generated`
  defaults to now and is pinnable, so two renders of one investigation are the
  same bytes.

  **The escaping is the substance of it.** Nearly every string in a report came
  from the evidence, which is to say it was written by the subject of the
  investigation, so the model holds values and each format is escaped for the
  thing that actually goes wrong in it. HTML is the boundary: every string is
  escaped, the stylesheet is inlined, and the document carries no script, font,
  image or link -- a report that fetches something tells whoever serves it that
  the examiner opened it, and evidence text is never made clickable, because a
  report that links to the attacker's URL is one that can be clicked. Markdown
  is escaped for structure, since a pipe in a filename ends a table cell and
  shifts every column after it, and a line-leading `#` turns a finding into a
  heading. CSV is guarded against formula injection: a cell beginning `=`, `+`,
  `-` or `@` is executed by a spreadsheet when the file is opened, so it is
  written with the leading apostrophe spreadsheets strip on display -- unless it
  is simply a signed number, because a report whose numbers all gained an
  apostrophe is one nobody can sort.

  **A block nothing renders is an error rather than a gap.** `report_render`
  validates the whole document before writing any of it and refuses by section
  and block index; a renderer that stepped over what it did not understand would
  hand back a report that looks complete and is missing a finding. A CSV of a
  report with several tables is refused for the same reason until one is named:
  two different headers stacked into one file is not something a spreadsheet
  reads the way it was meant.

- **The handover: `case_report` and `case_bundle`.** `case_report()` renders the
  open case as a report value -- the header, the evidence with its digests, what
  each builtin touched and how often, the timeline, the integrity statement and
  the security counters. It is built from the manifest rather than from the
  session, so the report a person reads and the document a machine verifies
  cannot disagree about what was examined; and because it is a value, an
  examiner's conclusions go in with `report_section` and `report_text` before
  anything is rendered.

  `case_bundle(dir)` writes what actually gets handed over: `manifest.json`,
  `report.html`, `report.md`, and a `SHA256SUMS` any `sha256sum -c` can check.

  **Which document vouches for which, and why it only works one way.** The
  reports are written first and the manifest records what they hashed to, so the
  seal over the manifest -- the SHA-256 over every other field, plus the Ed25519
  signature over the same bytes -- covers the reports as well. Edit one byte of
  `report.html` and it no longer matches a digest inside a document whose own
  integrity still verifies, which is a thing the recipient can establish with the
  file alone. The reverse ordering cannot be made honest: a report quoting the
  manifest's hash would have to quote it before the manifest was written, and
  would be quoting a document that was about to change. `SHA256SUMS` is the
  convenience on top of that, not the guarantee underneath it.

- **`report_write(report, path)`** renders and writes in one step, taking the
  format from the path's extension -- `.html`, `.htm`, `.md`, `.markdown`,
  `.csv` -- or from `{"format": ...}` for a name that says nothing. It returns
  `{path, bytes, format, sha256}`.

  The digest is the reason it exists. A report is written to be given to
  somebody, and the only useful thing to say about a file that has left your
  hands is what it hashed to when it left them. So the digest is read back off
  the disk and checked against the document that was meant to be there: a short
  write, a full disk or a filter driver that rewrote the bytes on the way past is
  a refusal rather than a hash of something nobody can reproduce. When a case is
  open, the write becomes a timeline entry carrying the path and that digest --
  the whole of the link between an investigation and the documents it produced.

- **Indicators out as STIX 2.1.** `stix_bundle` renders indicators as a bundle
  of Cyber-observable Objects, taking `extract_iocs` output directly, and
  `stix_pattern` renders the pattern that matches one of them for a query.
  Addresses, domains, URLs and email addresses each become their own observable;
  each MD5, SHA-1 and SHA-256 digest becomes a file observable carrying that one
  algorithm, because nothing in a list of digests says they describe the same
  file, and merging them on the guess that they do would invent a file nobody
  observed.

  **Every id is derived from the object rather than generated.** An observable's
  id is the UUIDv5 over the canonical form of its identifying properties that
  STIX specifies, so the same indicator is the same object wherever it is seen --
  twice in one case, or here and in someone else's platform. The bundle and the
  indicators get derived ids too, which the specification would let be random: a
  random id is a new id on every run, and two bundles built from one body of
  evidence would then differ in every identifier while describing exactly the
  same findings, which is impossible to diff and impossible to testify from.
  Values are normalized before they are hashed for the same reason -- a digest in
  upper case and the same digest in lower case are one object, not two.

  `indicators: true` adds an Indicator beside each observable, typed `unknown`
  rather than `malicious-activity`: the extraction found a value written in a
  document and concluded nothing about it, and a bundle that says otherwise
  carries that conclusion into every platform it is shared with. The three
  timestamps an Indicator requires come from a `created` option rather than a
  clock, so pinning it to when the case was collected makes the bundle
  byte-identical between runs. A key no indicator type claims is an error, and so
  is a value that is not what its key says: a forty-character digest filed under
  `sha256` would become an observable whose id nothing else computes, and a STIX
  object nothing matches produces no report at all.

- **Chain of custody.** Eight builtins in a new `chain of custody` capability
  category -- `case_open`, `case_note`, `case_evidence`, `case_verify`,
  `case_manifest`, `case_write`, `case_manifest_verify`, `case_close` -- and the
  discipline that ties the pieces this language already had (digests,
  timestamps, a deterministic compiler, Ed25519 signing) to one investigation.

  `case_open(id, examiner)` starts a session. From there every evidence opener
  (`raw_open`, `ewf_open`, `vhdi_open`, the six filesystem parsers, `table_open`,
  `hive_open`, `reg_open`, `zip_open`, `tar_open`) records its source into the
  manifest, and every builtin that reads or closes an evidence handle is counted
  against that source. `case_close` returns a document naming the examiner, the
  tool build, every source with its size and digest, every builtin that touched
  each one, the timeline, and the run's security telemetry.

  Four decisions shape it. **Nothing is recorded until a case is opened** -- the
  hooks sit on the hot path of every forensic program ever written in this
  language, so not using the feature costs one atomic load and changes nothing.
  **Hashing is opt-in and the manifest says which it was**: `{"hash": "sha256"}`
  digests each source as it is opened, and the default is no digest, because the
  alternative is `raw_open` on a 500 GB image silently reading the whole thing
  before it returns a handle. A case without digests records size and
  modification time and states `"hash_policy": "none"`; `case_verify` then
  reports `"basis": "size and mod time"` per source, so a weaker check is never
  mistaken for a stronger one. **The touch record is aggregated, not logged** --
  first touch, last touch and a count per builtin per source -- because a program
  that reads a hundred thousand files must not produce a hundred-thousand-line
  manifest. **The seal is checkable by someone else**: `case_write` puts a
  SHA-256 over every field but the seal, an Ed25519 signature over the same
  bytes, and the public key that verifies it into the document, and
  `case_manifest_verify(path)` is a function of the file alone. Reformatting the
  JSON does not break it; altering a character does.

  The manifest also carries the reproducibility record -- the path and digest of
  the exact `.mu` that produced it, taken by the runner from the signed bytecode
  before any of it executed. Not "a tool wrote this" but "this bytecode wrote
  this".

- **Evidence is read-only, and now provably.** A second machine-checked policy
  in `policy/`, alongside the environment-variable guard.
  `policy/evidence_guard_test.go` parses every file that reads evidence and
  fails the build on any call that asks the operating system to create,
  truncate, rename, delete or chmod anything, or to open a file with a writable
  flag. Two reviewed exceptions, both writing somewhere other than the evidence:
  the temp file libxfat demands, and the temp copy `withSQLiteCopy` takes
  precisely so an evidence database is never opened by something that wants to
  write a journal beside it. Each is pinned to an exact line count, so a new
  write inside an already-permitted function still fails.

  The invariant already held. Writing it down is what lets a manifest assert
  `integrity.evidence_read_only: true` and have that mean something -- a
  manifest that claims what nobody checks is worse than one that stays quiet.
  The rule, its reasoning and what the guard deliberately does not look for are
  in `docs/EVIDENCE_HANDLING_POLICY.md`.

- **Seven security lint rules.** `commandInjection`, `pathTraversal`,
  `weakCrypto`, `tlsVerificationDisabled`, `hardcodedSecret`,
  `evidenceMutation` and `unboundedResource`, each settable through
  `mutant.lint.rules.<name>.severity` like every rule before them. They take
  the editor from 16 rules to 23, and they are the rules only a language that
  knows what a disk image is can write.

  The rules that shipped before these are right by construction: each compares
  a call site against a fact the builtin registry states. These read *intent*,
  which cannot be stated, so each carries its own answer to what makes a
  finding certain enough to interrupt someone. The shared principle is that
  **what the program does with a value decides the finding, not what the value
  looks like** -- and the corpus is what forced it. `examples/` already held
  three literals a textbook secret scanner flags first, all three legitimate
  teaching material, and the one that separates them from a real leak is
  whether the program *uses* the value or takes it apart. A JWT handed to
  `jwt_decode` is a sample; the same string put in an `Authorization` header is
  a credential. `weakCrypto` draws the same line for MD5, which in a forensic
  tool is daily work: matching an artifact against a known-file set wants MD5
  specifically, so the rule reports only a digest compared against one written
  into the program, and never `imphash`, `nt_hash` or `lm_hash`.

  `evidenceMutation` is the one no general-purpose linter has: elsewhere a path
  is a path, but `raw_open` and `ewf_open` say out loud that the file is an
  exhibit, and `fs_write` to that same path is a hash that no longer matches
  the one in the notes. `unboundedResource` turned out not to be about
  unboundedness at all -- `cidr_hosts` refuses more than 20 host bits and
  `range` more than 10,000,000 elements, so `cidr_hosts("10.0.0.0/8")` is not a
  memory risk but a call that reads as a reasonable network sweep and simply
  fails. The rule evaluates exactly the predicate the builtin evaluates.

  Running the rules over the corpus found three real defects in shipped
  examples: `phishing_url_analyzer.mut` and `ioc_fetcher.mut` spliced values --
  one of them an attacker-authored URL -- straight into Lua single-quoted
  strings, where a `'` ends the string and the rest is read as Lua. All three
  are fixed.

- **A real test framework: `mutant test`.** Named tests and subtests,
  assertions that report the file and line they failed on, fixtures, name
  filtering, a `--json` reporter for CI, and line coverage with an LCOV
  profile. The command existed before this and did one thing: run each
  `*_test.mut` and call it passed unless it errored or its last expression was
  `false`. There were no `*_test.mut` files in the repository, which is the
  usual sign.

  The fix underneath all of it: a test file is now compiled through the same
  build every other program goes through. It used to have its own pipeline,
  which never walked the module graph -- so an `import` in a test file resolved
  to nothing and the namespace it bound was an undefined variable. A test
  framework that could not cross a file boundary could not test the feature
  files exist for.

  `test(name, fn)` runs the test where it is written, so a file reads top to
  bottom and a test declared inside another is a subtest. A failed assertion is
  recorded and the test carries on -- the language has no exceptions and this
  does not invent one -- and every assertion also returns its verdict, so a
  failure is an ordinary value. A test that dies of a runtime error is caught
  at its own boundary, so one broken test costs the file no other test.

  Ten builtins: `test`, `before_each`, `after_each`, `assert`, `assert_eq`,
  `assert_ne`, `assert_contains`, `assert_err`, `assert_ok`, `fail`. Deferred
  and said so: parallel test files (the task registry behind `spawn` is
  process-wide), benchmarks, mocking, and asserting on a crash. See
  [docs/TESTING.md](docs/TESTING.md).

- **A debugger: `mutant debug`.** Breakpoints, stepping, the call stack and
  variable inspection, delivered as a Debug Adapter Protocol server, so VS Code
  (press F5 on a `.mut`), Neovim's `nvim-dap` and anything else that speaks DAP
  get it from one implementation. For a language whose programs run for minutes
  over multi-terabyte images, `putln` debugging was not viable.

  It launches rather than attaches: `mutant debug` is the program's own
  process. A Mutant program carries anti-debugging probes that end a
  secure-mode run when an OS debugger is present, so attaching one would have
  meant the language's own tooling tripping its own tamper response.

  Debugging runs from source at mutation level 0. A release artifact has had
  its positions stripped -- there is nothing to step through, and the values
  held by a program that left this machine are not this machine's to render.

  Three things are deliberately absent and say so rather than half-working:
  watch expressions beyond a plain variable name, conditional breakpoints, and
  stepping into `spawn` or `pmap`. Evaluating an expression means compiling it
  in the frame's scope, and a compiled program does not carry its scopes; a
  breakpoint carrying a condition stays armed with a message rather than
  silently never firing. Hit counts do work. See
  [docs/DEBUGGING.md](docs/DEBUGGING.md).

- **`while`, `for (item in collection)` and `match`.** The counting `for` was
  the only loop the language had, and the only way to branch on a value was a
  chain of `if`s.

  `while (c) { ... }` is its own construct rather than sugar for `for (; c; )`,
  so the formatter prints back the loop that was written; `break` and
  `continue` work in it unchanged.

  `for (v in xs)` walks arrays, hashes, strings and bytes. One binding yields
  the thing the collection is made of -- an array's element, but a hash's key
  -- and two bindings yield the index or key alongside the value. A hash is
  visited in the order printing it shows, because both the printer and the loop
  sort with the same comparison: a program that prints a hash and a program
  that loops over one must agree about what order it is in. Iteration is two
  opcodes rather than a desugar to `len()` plus indexing -- a program that
  declared its own `len` would otherwise change what every loop in the file
  means, and a hash has no ordered index to desugar to. There is no range
  syntax: `range(0, 10)` is an ordinary builtin returning an array, and looping
  over it is a `for…in` like any other.

  `match` is an **expression**, so it binds, returns and nests like any other
  value: `let label = match (code) { 0 => "clean", 1 | 2 | 3 => "a few", _ =>
  "many" };`. A pattern is a literal, a negated number, an enum variant such as
  `Status.Ok`, or `_`; alternatives are joined with `|`. Patterns have their
  own grammar rather than going through the expression parser, which is what
  makes `1 | 2 | 3` those three values instead of the number `3` -- `|` is the
  bitwise-or operator everywhere else. An arm body is one expression or a block
  whose value is its last expression, and the parentheses around the subject
  are required, since `match x { ... }` without them is a struct literal.

  Because a match must produce a value, a subject no arm matches is a run-time
  error naming the value rather than a `null` flowing onward. The case that is
  about is adding a variant to an enum, which leaves every existing match over
  it one arm short and nothing else notices; the language server now reports
  that gap before the program runs (`matchExhaustiveness`, settable like every
  other rule), and reports an arm written after `_` as unreachable. All three
  constructs run identically on the tree-walking evaluator and the VM, the
  formatter round-trips them, and editor grammar, snippets, hover help and
  completion cover them. See
  [examples/basics/control_flow.mut](examples/basics/control_flow.mut).

- **String interpolation, raw strings and triple-quoted strings.** `"${...}"`
  puts an expression in a string: `"host=${h}:${p}"` where `h` is a string and
  `p` an integer. A piece that is already a string contributes its own text,
  anything else contributes what it would print, so there is no conversion to
  write and no value a hole cannot take. A hole holds one expression -- a call,
  an index, arithmetic, another interpolated string -- and it is compiled where
  it stands, so nothing is re-scanned at runtime and a `%` in the text is a
  percent sign.

  Only the two characters `${` open a hole. A lone `$` is unchanged, so
  `"cost: $5"` and `"$PATH"` mean what they always meant; `\${` writes the two
  characters literally. A hole is parsed in place: a broken one is reported at
  its own line and column inside the string, a traceback through a call in a
  hole underlines that call, and go-to-definition and every builtin diagnostic
  reach into holes exactly as they reach into any other expression.

  `r"..."` decodes nothing -- no escapes, no interpolation -- so
  `r"C:\Users\Public"` and `r"\d{4}-\d{2}"` say what they look like. It ends at
  the first quote, so it cannot contain one.

  `"""..."""` spans lines, with escapes and interpolation still live;
  `r"""..."""` is its raw form, and either may hold a lone `"` or `""`. A
  newline right after the opening delimiter is dropped and the smallest
  indentation of any non-blank line -- counting the closing delimiter's own
  line -- is removed, so a block reads as the text it is rather than as the
  text plus the surrounding code's indentation. CRLF becomes LF inside one:
  the line endings in a multi-line literal come from how the file was checked
  out, and the same source must not mean two things in two clones.

  A literal with no hole is still an ordinary string token, so nothing in a
  program that does not interpolate changes -- not the AST, not the bytecode.
  Interpolation compiles to its own opcode rather than to a call, so a module
  that declares a name like `str_format` cannot change what every interpolated
  string in the program means. The formatter reprints a raw or triple-quoted
  literal as written instead of re-quoting its value, which would have doubled
  the backslashes it exists to avoid.

- **Modules and imports.** A program can be more than one file. `import
  "lib/stats.mut";` binds the namespace `stats`, and `import s
  "lib/stats.mut";` binds `s` instead; the namespace is otherwise the file's
  base name with the extension removed. An import binds that one name and
  nothing else -- the imported file's own names are not visible unqualified, so
  two modules may each declare `helper` without one silently overwriting the
  other. A top-level name beginning with `_` is private to the file that
  declares it, and reaching for it through a namespace is a compile error
  naming both the module and the name: there is no export list to keep in step
  with the code.

  Paths resolve relative to the importing file's own directory first, then
  against each `--module-path <dir>` directory in the order the flags were
  given. The flag repeats rather than taking a separator-joined list, and it is
  the only thing that widens the search: no manifest, no lockfile, no config
  file, no environment variable (see
  [docs/CONFIGURATION_POLICY.md](docs/CONFIGURATION_POLICY.md)). The extension
  is written out rather than guessed, a cycle is reported as the chain that
  closed it (`main.mut -> a.mut -> b.mut -> a.mut`), a module reached two ways
  is compiled and run once, and a path that names no file lists every directory
  that was tried.

  `struct` and `enum` names stay program-wide, because that is how they travel
  in the bytecode: one declaration is visible from every module with no
  qualification, and two modules declaring the same type name is an error
  naming both files. Values are per-module, types are per-program.

  Modules link into one instruction stream, one constant pool and one global
  slot space -- the bytecode format leaves no choice, since the polymorphic
  engine shuffles the whole constant pool, the opcode permutation ships as one
  table for the entire program, and jumps carry absolute offsets. None of that
  is visible in a failure: each traceback frame names the file it came from and
  quotes that file's line, from a new `ModuleSpans` table that `StripDebugInfo`
  removes with the rest of the debug information, so a released artifact does
  not carry the layout of your source tree. See
  [docs/MODULES.md](docs/MODULES.md) and
  [examples/modules/](examples/modules/).

- **Builtin namespaces.** Every builtin family is now addressable with a dot:
  `fs.read` is `fs_read`, `str.upper` is `str_upper`, `base64url.encode` is
  `base64url_encode`. Nothing is imported and nothing is declared -- the flat
  name is derived by joining the halves with `_`, so all 44 families worked the
  day this landed and none has a list to maintain. Both spellings are one
  function with one contract: one arity check, one argument-type check, one
  deprecation notice, one entry in the traceback. A variable, parameter, field
  or import that already binds the name wins, so no program written before this
  changes meaning. Flat names keep working unchanged.

- **Bitwise operators.** `&`, `|`, `^`, `<<`, `>>` and the prefix complement
  `~`, with the compound forms `&= |= ^= <<= >>=`. A language whose brochure
  leads with disk-image parsing could not express a mask, a flag test or a
  shift; the workaround was arithmetic or a builtin call. Semantics and
  precedence are Go's: `<< >> &` bind as tightly as `* / %` and `| ^` as `+ -`,
  so `flags & MASK == 0` reads as `(flags & MASK) == 0` rather than C's
  `flags & (MASK == 0)`. `>>` is an arithmetic shift over the signed 64-bit
  integers the VM has. Non-integer operands are refused rather than truncated,
  and a negative shift count is a runtime error instead of the panic Go would
  raise. Six new opcodes, appended so existing opcode values are unchanged.
- **A real `bytes` type.** `BYTES` is a first-class object: it indexes to an
  integer 0–255, concatenates with `+`, compares by content, measures with
  `len`, and hashes in a keyspace disjoint from strings. Every disk sector, PE
  section, memory page and socket read previously travelled in a Go string, and
  nothing in the language could tell a binary value from text — so `str_reverse`
  turned every non-UTF-8 byte into U+FFFD and `str_substr` indexed by rune while
  `bytes_get` indexed by byte, both without failing.
- `string_to_bytes(s, encoding)` and `bytes_to_string(b, encoding)`, with
  `"raw"`, `"utf8"` (validated, not substituted), `"latin1"`, `"hex"` and
  `"base64"`. Because every pre-existing producer already returned byte-exact
  data in a string, `string_to_bytes(x, "raw")` bridges all of them losslessly.
- 16 native `*_bytes` producers — `fs_read_bytes`, `hex_decode_bytes`,
  `base64_decode_bytes`, `gunzip_bytes`, `zlib_decompress_bytes`,
  `aes_decrypt_bytes`, `net_conn_read_bytes`, six `*_read_file_bytes` filesystem
  readers and three `*_read_at_bytes` image readers. **Builtin count 409 → 427**
  across 33 categories.
- **Runtime tracebacks with source positions.** A fault used to print one
  sentence with no way back to a line. The VM now prints every frame with the
  arguments it received, the line it is on, and an underline beneath the failing
  span; deep recursion collapses to "N frames repeated M more times". Positions
  ride in a delta-encoded line table costing single-digit percent of the
  instruction stream it annotates, and the program's source text travels with
  the artifact so a failing `.mu` can quote the line it died on.
- **Builtin stability tiers.** Metadata declares `stable` (the unwritten
  default), `experimental` or `deprecated`; a deprecated builtin names its
  replacement. Surfaced as an LSP hover footer and a new `builtinDeprecated`
  diagnostic.
- `--timing` for stage timing, `--trusted-key <path>` for the verification key,
  and `--target` for release cross-builds — replacing the environment variables
  that used to carry them.
- Credential handling that never records the secret: interactive prompt (the
  default), `--password-file <path>`, and `--password-stdin`.
- **A documentation path from nothing to a shipped binary.**
  `docs/TUTORIAL_30_MIN.md` ("Mutant in 30 minutes") goes from install to a
  signed standalone executable; `docs/COOKBOOK.md` is fourteen complete
  programs organised by investigation rather than by builtin category, ending
  with the traps that actually bit while writing them; `docs/COMPARISON.md`
  places Mutant against Python+plaso, Velociraptor, osquery and YARA+Sigma,
  including a section naming eight cases where it is the wrong tool. Every
  command and output in the tutorial and the cookbook was run against a binary
  built from this tree.
- `docs/CONFIGURATION_POLICY.md`, `docs/WHAT_IS_MUTANT.md`,
  `docs/WASM_REPL_REFERENCE.md`, and this file, plus
  [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md) and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- `examples/data/autoruns_hive.json` and `examples/data/phish.eml` — synthetic
  fixtures so two of the cookbook recipes run unchanged.

- **`docs/EXECUTION_MODES.md`** — the definitive statement of what each mode
  changes, every row traced to the code that implements it. The distinction it
  exists to write down is that **`--compat` weakens the response and `--dev`
  weakens the key**: compat still requires your password and still verifies the
  artifact, while an artifact built or run under `--dev` has no confidentiality
  at all, because the development key is a compile-time constant shared by every
  Mutant binary. That sentence was in no help text and no document.

- **`mlsp --version`** — the language server now says which release it was built
  from and how many builtins it linked (`mlsp 2.5.0 (493 builtins)`). It ships
  as a binary inside the editor extension, built from a checkout that can be
  older than the language it is asked to teach, and until now nothing it
  reported distinguished a current server from one cut months earlier. Both
  numbers are read from the same source as everything else: `global.Version` and
  `builtin.Builtins`.

### Changed

- **A builtin no longer spells its own name as a literal.** The name was
  declared once in `builtin/names.go` and said twice more as a constant -- by
  the dispatch table and by the return contract -- but the error messages a user
  actually reads spelled it a fourth way, as a string literal inside the
  implementation: `requireArrayArg("sort", args[0], 1)`. Renaming a builtin was
  already caught three ways, and none of them looked at what its errors say, so
  every message it raised would have gone on quoting a name that no longer
  existed. The same literal reached the chain of custody, where
  `custodyRecordOpen("zip_open", ...)` is the name that ends up in a case
  manifest.

  **456 literals across 56 files** now say the constant. The rewrite was scoped
  to the function each name is registered to rather than matched across the
  tree, because short builtin names collide with ordinary hash keys -- `"sort"`,
  `"slice"`, `"error"` and `"count"` are all both -- and a literal is only
  suspicious inside the function that owns it.
  `TestNoBuiltinSpellsItsOwnNameAsALiteral` walks the AST the way `policy/`
  does and fails if one comes back.

- **`case_report` and `case_bundle` passed the builtin's name to the same
  function twice**, once inside the options value and once as a parameter the
  function ignored -- so the options and the document it built could have been
  labelled differently. The dead parameter is gone.

- **The GitHub Actions workflow is gone, and the docs no longer claim it runs.**
  `.github/workflows/ci.yml` built, vetted and tested on Linux, Windows and
  macOS, cross-compiled six targets and ran `go mod verify`. Those are still
  the gates -- they are now commands a contributor runs, listed in
  [CONTRIBUTING.md](CONTRIBUTING.md), and nothing runs them automatically.

  Four documents asserted otherwise and have been corrected:
  `CONTRIBUTING.md`, `docs/CONFIGURATION_POLICY.md`, `docs/SECURITY_LLD.md` and
  `docs/SECURITY_LLD_TRACEABILITY.md`. Two claims in them were already false
  before this change: `SECURITY_LLD.md` §16.2 described a
  `.github/workflows/security-profile.yml` that was never written, and the
  traceability matrix's `C` evidence level meant "CI wired" -- it now means
  wired into the repository-wide `go test ./...` gate, which is what those rows
  were actually describing. SEC-015 ("the security suites must run on every
  supported OS") drops from `I/C` to `I/P`, because nothing automates the
  "every OS" half any more.

- **Enum equality is typed rather than textual.** Comparing an enum value with
  anything that was not an enum fell through to comparing what the two would
  print, and an enum prints as `Status.Ok(0)` -- so `Status.Ok ==
  "Status.Ok(0)"` answered **true**, in both engines. Bytes and errors each
  already had a typed comparison arm for exactly this class of accident; enums
  never did, and `match` made it reachable in a way plain `==` rarely was. Two
  enum values are now equal when they share a type and a variant, and an enum
  is equal to nothing else. A program that relied on the old answer changes
  behaviour.

- **Contradictory mode flags are an error instead of a silent resolution.**
  `--secure --compat`, `--secure --dev` and `--signer-auth --no-signer-auth`
  each exit non-zero naming both flags and why they conflict. Every flag scanner
  was last-flag-wins, and `--dev` did not even need to come last — it forced
  compatibility mode wherever it appeared — so `mutant prog.mu --dev --secure`
  ran unsecured having been asked in the same breath to run secured, and said
  nothing about it. `--dev --compat` is still accepted: dev mode implies compat
  mode, so naming both is redundant rather than contradictory, and repeating a
  flag stays harmless. Validation runs before any other work, so the embedded
  standalone path and the CLI reject the same command line identically.
- **A terminating security event says what fired and what to do about it.** The
  run used to stop on one sentence — `sandbox detected, execution halted for
  security` — that named no probe, no reason and no way forward, on a check
  that fires on ordinary containers, VMs and CI runners, which is where forensic
  tooling normally runs. It now prints the detector, its classification and
  confidence, the signals behind it, and the remedy. `--compat` is named for the
  host-probe events and deliberately **not** for a failed signature or a failed
  integrity check: those are statements about the artifact, and offering
  `--compat` there would be advice to run a modified file anyway. The VM's
  security opcodes return their error directly rather than through the response
  policy, so they call the same explainer.
- Help text for the modes was rewritten: `--dev` now says the fallback key is a
  compile-time constant shared by every Mutant binary, `--signer-auth` says it
  upgrades verification rather than enabling it, and the compat-weakens-response
  versus dev-weakens-key distinction is stated in the help itself.
- **Builtins resolve by name, not by registry ordinal.** `OpGetBuiltin` carried
  an index into the global registry, which made that registry append-only
  forever — nothing could be renamed, retired or reordered without silently
  repointing every artifact ever compiled. The compiler now interns the builtins
  a program references and ships that table in the artifact; the VM binds every
  name before an instruction runs, so a missing builtin fails by name at load.
  `ByteCode.Version` is **2**.
- Binary-accepting builtins widen rather than fork: the whole `bytes_*` family,
  the hash and encoding families, `fs_write`, `fs_append` and `net_conn_write`
  take `BYTES` **or** `STRING` and hand back the representation they were given.
  No existing builtin changed its return type — the `bytes` work is additive,
  and every `.mut` program written before it behaves identically.
- Debug information is unconditional in development artifacts and stripped only
  by `mutant release`, rather than being gated on a mode flag. Gating would have
  coupled debuggability to a security downgrade.
- The polymorphic engine carries line tables through the offset remap it already
  builds for jump targets, so mutated builds keep their positions.
- **The editor's builtin highlighting is generated from the registry.** The
  TextMate grammar carried a hand-copied list of builtin names, and a
  hand-copied list of 490 names is a list that falls behind: it had 76 of them,
  missing every `report_*`, `case_*`, `stix_*`, `ocsf_*` and `ecs_*` builtin
  along with 25 of the 26 `net_*`. `cmd/gendocs` now writes that one rule from
  `builtin.Builtins`, and `TestGrammarHighlightsEveryBuiltin` fails when the
  grammar and the registry disagree — because a generator nobody runs is the
  same drift one step further away. Only the builtin rule is generated; the
  rest of the grammar stays hand-written.

  Hover, completion, signature help and every diagnostic already covered all
  490, since those come from the language server and it derives them from
  `builtin/metadata.go`. What was actually wrong was narrower and still worth
  fixing: a `report_new` call read as an unknown identifier next to a
  highlighted `putln`, which tells the reader the wrong thing about what the
  language knows.
- `cmd/gendocs` writes each document with the line endings the file already
  had, instead of always writing LF into a tree checked out with CRLF.
- **The staleness check on the shipped language server was looking in the wrong
  place, and nothing ran it.** `check:lsp-bins` compared the staged `mlsp`
  binaries against the Go files under `lsp/` — but the analyzer derives arity,
  parameter kinds, result types and deprecation from `builtin/metadata.go` in
  the parent module, so registering a builtin changes what the server teaches
  and leaves every file under `lsp/` untouched. A server could fall a release
  behind the language and the check would call it current. It now compares
  against the whole module, requires all six binaries rather than passing on
  whichever ones happen to be present, and — for the one target the machine
  running it can execute — asks the binary for `--version` and compares that
  with what the sources build, because mtimes lie after a fresh clone. The check
  had also never been wired into anything; `scripts/package-targets.mjs`, which
  stages from `lsp/dist` without building, now runs it before it publishes.

### Removed

- **All environment-variable configuration.** Mutant takes no configuration from
  the environment, in code or in documentation: the environment is part of the
  untrusted thing a forensic tool examines, and an environment switch is an
  unlogged control channel absent from the command line an analyst records.
  Ten dead exported `*Env` constants across five files were deleted and 16
  documents purged of the variables they described — several of which named
  knobs the code had already collapsed to constants.
- The environment-driven builtin capability allowlist. *Capability
  configuration is under design; no interface is specified.*

### Fixed

- **A test compared an evidence path against the spelling it typed, not the
  one custody records.** `case_evidence` stores the resolved path -- that is
  how two handles on one file become one exhibit -- and Windows hands back an
  8.3 short path for a `TEMP` under a username longer than eight characters, so
  `TestCaseReportSaysOnlyWhatTheManifestSays` looked for
  `C:\Users\RUNNER~1\...` in a report that carried
  `C:\Users\runneradmin\...`. It failed on that one kind of host and passed
  on every other, including every machine this was developed on.

  The helper now returns the path as custody will record it. The product
  behaviour was correct and is unchanged; what was missing was a test saying
  so, and `TestTwoSpellingsOfOneFileAreOneEvidenceEntry` now registers one file
  under two names and fails if the manifest grows two entries.

- **A write through more than one container was silently lost.**
  `grid[0][1] = 9`, `h["a"]["b"] = 2`, `rows[0]["n"] = 99`, `o.inner.v = 42` --
  every shape with more than one hop in its target -- compiled, ran, changed
  nothing and reported nothing. The compiler emitted the store back into the
  variable only when the container expression was a plain identifier; anything
  deeper mutated a value nothing stored back. Globals and locals are held
  encrypted, so a load hands back a copy, and the write went into the copy.

  For a tool that reports on evidence this is the worst failure available: the
  report is wrong and looks right. The idiom it breaks is the ordinary one --
  `counts[host]["n"] = counts[host]["n"] + 1` over a timeline.

  The compiler now flattens an assignment target to the variable under it plus
  its hops, and stores every container it passed through back where it came
  from. What it still cannot emit correctly it refuses by name: a target with no
  variable under it (`[1, 2][0] = 9`) has nowhere to store its result, and an
  index before the last one is loaded again on the way out, so it has to be a
  name or a literal rather than something with a side effect. The last index is
  compiled once and is free to be a call.

  The two engines now agree on ten shapes that used to diverge
  (`TestNestedIndexAssignmentParity`, previously skipped as a known divergence),
  and the editor reports both refusals where they are written, under a new
  `assignmentTarget` lint rule whose answers are pinned against the compiler's
  so the two cannot drift.

- **Index assignment evaluated to the container instead of the value assigned.**
  `arr[0] = 42` answered with `[42, 2, 3]`, and `h["k"] = 7` with the whole hash,
  while `x = 5`, `p.x = 9` and `x += 1` all answered with the value -- and so did
  the evaluator, in every case. `let bound = arr[0] = 42` bound the array.

  Every language where assignment is an expression yields the assigned value and
  none yields the container, so this was an unfinished implementation rather than
  a choice: index assignment simply left whatever `OpSetIndex` had put on the
  stack. The compiler now spills the value to storage of its own, where the value
  expression was already being compiled, and reads it back after the stores.
  Nothing is re-evaluated, no opcode was added, and the last index stays free to
  be a call -- `counts[etld1(url)] = 1` still compiles.

  `TestIndexAssignmentValueParity` was skipped as a known divergence and is now
  `TestAssignmentYieldsTheValueAssigned`, covering all five forms at three
  depths.

- **The two engines evaluated an assignment's parts in different orders.** The
  compiler emits the container, then the index, then the value; the evaluator
  read the value first, and folded a compound assignment's right-hand side
  before its target. Invisible until both halves have side effects --
  `a[note("index")] = note("value")` recorded them in opposite orders -- and it
  reached real programs through macros, since the evaluator is what computes
  `unquote(...)` at expansion time. The evaluator now follows source order.
  Found by the test written for the change above.

- **Twenty-one example programs were in no README.** Among them workshop step 6,
  a whole numbered lesson in a sequence the reader is told to follow in order.
  The ten filesystem format demos, the two `net_serve` server pairs and every
  macro example were likewise unlisted. All of them are now described where they
  live, and `TestEveryExampleIsListedInItsReadme` fails when a directory that
  has a README gains a program it does not mention.

- **Workshop step 6 warned about a defect that had been fixed.** Its style note
  said a closure writing an outer variable does not write back. It does, and has
  since captured locals became cells; the one case that still does not is a
  callback running on its own VM, which the editor already reports. A false
  caveat is worse than none: it teaches a reader to avoid something that works.

- **An example pointed at someone's dev machine.** `ext_example.mut` opened
  `N:\dev\dataset\img6_ext4.dd` where every one of its nine siblings uses a
  relative placeholder. It is `./disk.ext4` now, like the rest.

- **Four documents described a standard library three releases old.**
  `WHAT_IS_MUTANT.md`, `WASM_REPL_REFERENCE.md` and `COMPARISON.md` each said
  459 builtins, `TUTORIAL_30_MIN.md` said 469, against 497; the category counts
  (33, 34, 35) were all wrong too, and two documents undercounted `examples/` by
  twelve programs. Corrected, and gated: `TestProseCountsMatchTheRegistry` and
  `TestProseExampleCountsMatchTheTree` in `cmd/gendocs` now fail when a document
  claims a number the registry or the tree does not support.

  This is ED-1's defect in a different file type -- a hand-written claim about
  the registry with nothing that fails when the registry moves -- so it gets
  ED-1's answer. Counts in `CHANGELOG.md`, `CONTRIBUTING.md` and the roadmap are
  deliberately outside the gate: those record what was true at a past release,
  and correcting history would be the untruth.

- **The debugger refused to run on a virtual machine.** A debug session built
  its VM in secure mode, so the injected sandbox probe fired on launch and the
  security policy ended the session before the first line could be stepped.
  Every CI runner is a virtual machine and so is every malware-analysis
  workstation, which is to say the debugger stopped exactly where a forensic
  tool is most likely to be pointed at something.

  A session now runs in the posture `--compat` gives a run, the same one
  `mutant test` already used: the probes are still compiled into the bytecode
  being stepped and still execute, but a hit warns instead of terminating.
  `VM.SecureMode()` reports which posture a machine was built with, so a caller
  that chose the advisory one can say so rather than imply it.

- **A frame's unassigned local slots held the previous call's values.** The
  calling convention never cleared the region between a new frame's arguments
  and the end of its locals, so those slots held whatever the last call left on
  the stack. No program could see it -- every local is assigned before it is
  read -- but a debugger reads them all, and would have shown a dead value from
  an unrelated frame under the name of a variable whose declaration had not run
  yet. The slots are cleared when a debugger is attached, so no ordinary run
  pays for it.

- **An `if` used as a value left the stack wrong in two cases.** The compiler
  decided whether a branch had produced a value by looking at the last
  instruction it had emitted. A branch ending in a `let` emits no pop, so that
  branch pushed nothing where its sibling pushed one and the VM underflowed; a
  branch ending in a `for (v in xs)` ends in the pop that drops the loop
  *cursor*, which looks identical to a value being discarded, so that pop was
  removed and the cursor became the branch's value -- `if (true) { for (v in
  []) {} } else { 4 }` evaluated to `<iterator>`. Both branches now decide from
  the syntax, the same rule `match` arms use.

- `docs/SECURITY_LLD.md` claimed in two places that the VM forced
  `secureMode=true` for integrity failures, making integrity the one check no
  mode could downgrade. It does not: `vm.secureMode` carries the launch mode
  into both integrity checks, so under `--compat` and `--dev` a mismatch warns
  and the run continues. The documents now state what the code does. Whether
  integrity *should* be the exception to the mode rule -- "the host looks
  suspicious" is a guess about the environment, "this bytecode is not what was
  signed" is not -- is recorded as an open question rather than settled here.
- The test helpers that capture stdout and stderr wrote everything before
  reading anything, so they deadlocked once the captured output outgrew the pipe
  buffer (4 KiB on Windows). `mutant --help` crossed that line when the mode
  section was rewritten. They now drain concurrently.
- **Assignment to a captured variable corrupted the frame.** The compiler
  branched on two of `SymbolScope`'s five values at its three assignment sites,
  so a write to a free variable was emitted as `OpSetLocal` against the *free*
  index -- a position in the closure's capture list, not a frame slot. Writing
  free 0 landed on local 0, which is usually the first parameter:
  `fn(x) { let acc = 0; let inner = fn(p) { acc = 7; return p; }; return inner(x); }`
  called with 42 answered **7**, and two captures over two parameters answered
  `[777, 888]` for `(10, 20)`. Silent argument corruption, with no diagnostic
  from any stage. The tree-walking evaluator was correct throughout, so this was
  a defect against a reference implementation rather than a semantics question.

  A captured local now lives in a cell that the frame slot and every closure over
  it point at, so a write through any of them is a write all of them see. An
  accumulator over a callback works, a counter outlives the frame that made it,
  and two closures over one variable agree about its value. Adding `OpSetFree`
  over the existing by-value capture list was rejected rather than deferred: it
  would have stopped the corruption and left the accumulator answering 0, trading
  a findable bug for a quiet one.

  Five new opcodes, appended so existing opcode values are unchanged. Bytecode
  compiled before this runs unchanged, including its by-value capture.
  `pmap`, `peach` and `spawn` hand each worker its own copy of the captured
  cells, so a callback's writes stay local -- the rule those builtins already
  documented for globals, and without which the sharing would be a data race.
  Assigning to a builtin's name or to the name a function literal was bound to
  is still refused at compile time; neither is storage.
- **The VM skipped opcodes it did not recognise.** The dispatch switch had no
  default arm, so bytecode built by a newer toolchain ran to completion and
  answered with nonsense: the unknown instruction matched nothing, the
  instruction pointer advanced by one, and its operand bytes were executed as
  opcodes. It now stops and names the opcode. Opcodes are append-only, so this
  is the only direction that can fail -- old bytecode has always run on a new
  runtime, and still does.
- `mutil.EncryptObject`'s default arm returns an error both call sites discard,
  so an object type without an explicit arm travelled **unencrypted with nothing
  said**. `BYTES` has arms in both directions, with a test asserting the sealed
  type rather than trusting the suite.
- The parameter-kind conformance probe drew from a fixed candidate list that
  never exercised the new kind. Making it reachable immediately caught **15
  under-declared builtins**, including `len` and `json_stringify`, that a hand
  audit had missed.
- The evaluator has never indexed strings while the VM has. Bytes indexing was
  implemented in **both** engines so the new type does not inherit the
  divergence.
- A missing or malformed trusted-key file now fails hard instead of silently
  falling back to the local keystore.
- LSP: the type lattice, the function-parameter solver, inlay hints and
  signature help all know `bytes`; `builtinArgType` reports binary passed into a
  text builtin and names the conversion.
- `email_urls` declared `[]STRING` elements over an implementation that returns
  a `{host, scheme, url}` hash per link, so the published signature, the hover
  and the argument-type diagnostic were all confidently wrong about
  `u["host"]`. The contract now matches the code. **The conformance probe could
  not have caught it:** it checked only the top-level returned kind, never the
  declared element kind. It now checks both, verified by mis-declaring
  `text_split` and watching it fail.
- The generated `docs/CAPABILITY_REFERENCE.md` still told every reader that
  Mutant "has no separate bytes type" — untrue since `BYTES` shipped, and
  contradicted by a signature on the same page. Fixed in `cmd/gendocs`, which
  is where generated prose lives.

### Security

- `go test ./policy/...` — an AST guard, part of the ordinary `go test ./...` —
  fails the build on a `MUTANT_`-prefixed string literal anywhere in the module,
  on an environment read outside ten allowlisted functions with pinned line
  budgets, and on an environment write outside a build-time child `go build`.
  Sandbox, VM and debugger detection is unchanged: those probes read variables
  set by Sandboxie, WSL, a debugger or an injector — never by a Mutant user —
  and the only outcome they can produce is a refusal to run.
- `SecureStack.clearObject`'s `*String` arm zeroes `[]byte(v.Value)`, a copy Go
  makes at the conversion, so it has never wiped anything and cannot: Go strings
  are immutable. It is documented in place. Key material belongs in a `bytes`,
  whose backing array `Zero()` genuinely clears.

## [2.4.0] — 2026-08-25 — "Legion"

One compiled program, many minds running it.

### Added

- **Concurrency.** The unit is a whole VM, not a goroutine sharing one: a worker
  gets its own stack and frames and a *snapshot* of the globals over the same
  bytecode, so nothing is shared and nothing needs a lock. `spawn`, channels,
  and `pmap`/`peach`, up to 1024 workers. 10 new builtins; **399 → 409**.
- Compound assignment operators.
- Struct and enum hover in the language server; SSA-based analysis and ghost-code
  resolution in the extension.

### Changed

- **The polymorphic engine went live.** Previously 1 of 5 transforms, active only
  at level ≥ 6; now 4 of 4 from level 1.
- Execution engines reduced from three to two — the separate WASM REPL
  interpreter was deleted rather than kept in sync.
- LSP diagnostics 7 → 12. The VS Code extension moved to 0.1.0 with per-platform
  packaging.
- **A failing run now exits non-zero.** It previously exited `0`.

### Fixed

- Hash literal and LSP formatter fixes; operator parity between the two engines;
  nopsled and polymorphic correctness fixes.

## [2.3.0] — 2026-08-11

### Added

- The forensic suite in depth: MFT, prefetch, registry, `fs_deleted`, syslog,
  SQLite and regex builtins, link builtins, process listing, and process
  injection detection.
- Higher-order collection functions; `&&` and `||` operators.
- Workshop functions and example programs.

### Changed

- Parser, formatter and extension updates; SQLite excluded from the WASM build.

## [2.2.0] — 2026-07-14

### Added

- Interactive REPL tab completion with context-aware ranking; shared help docs
  across the REPL and web surfaces.
- The WASM REPL and automatic WASM builds; LSP build scripts and extension
  packaging.

### Changed

- Compiled bytecode is compressed. Multi-value returns were reworked, and `len`
  returns a single object.
- Sandbox detection updated; macro fixes.
- Moved to the `aoiflux` domain and the AGPL-3.0 licence.

### Removed

- An earlier round of environment variables, and large files from the tree.

## [2.1.0] — 2026-06-28

### Added

- The polymorphic bytecode engine; sandbox, VM and debugger detection; deep
  binary protection and randomised in-code security checks.
- Sandboxed Lua: a bytecode integration, an executor with timeouts and scrubbed
  errors, and pre-VM Lua patch execution under tamper policy.
- Structs, enums, loops, float types and the modulo operator; encrypted structs
  and enums; command execution; many builtins.
- Dynamic stack size, global size and frame limits.

### Changed

- Moved to a pure-Go implementation; improved runtime encryption and security
  logging.

## [2.0.1] — 2022-06-26

### Added

- Graceful exit handling.

### Changed

- Go version upgrade.

## [2.0.0] — 2021-06-02

### Added

- `mutant release` — standalone compiled binaries for multiple platforms, with
  per-platform binary formats and extensions.
- A basic CLI with help and argument validation.

## [1.0.1] — 2021-03-29

Documentation only.

## [1.0.0] — 2021-03-22

Initial release: the language, the compiler, the VM, and encrypted bytecode.

[Unreleased]: https://github.com/aoiflux/mutant/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/aoiflux/mutant/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/aoiflux/mutant/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/aoiflux/mutant/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/aoiflux/mutant/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/aoiflux/mutant/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/aoiflux/mutant/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/aoiflux/mutant/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/aoiflux/mutant/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/aoiflux/mutant/releases/tag/v1.0.0
