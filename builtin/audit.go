package builtin

// The security audit log.
//
// `security.SecurityTelemetrySnapshot` counts what tripped while a program ran:
// eleven debugger detections, two integrity failures. The counters have been in
// every case manifest for as long as there have been case manifests, and they
// are the wrong shape for the question an examiner actually asks. "Eleven" does
// not say whether they were eleven checks of one loop in the first second or
// one check a minute for eleven minutes while an image was being hashed, and it
// cannot be made to say it afterwards, because a counter keeps no order.
//
// So `security.auditEvent`, the hook every Record* function already called and
// which did nothing, is filled in here with an append-only hash chain: each
// entry carries the hash of the one before it, so the chain's head is a
// 32-byte commitment to every event in order. Editing an entry changes its
// hash, which was the `prev` of the next entry, which changes that entry's
// hash, and so on to the head -- the property the whole construction exists
// for, and the only one it has.
//
// **What it cannot do, stated here because a log that is quiet about its limits
// invites a reader to assume it has none.** A chain proves nothing about a
// document nobody kept the head of. Delete the log and there is no log; that is
// not detectable from inside the log. What makes the head hard to replace is
// that it is written into the case manifest, whose seal is a SHA-256 over every
// other field and, on a machine with a key, an Ed25519 signature over those
// same bytes. A log whose head does not match the one in the manifest is not
// the log that manifest was written beside. `audit_verify(path, head)` is how a
// reader asks that question, and a verify with no head to check against says so
// in its answer rather than quietly passing.
//
// **Why this is in memory and not fsync'd per event.** These events fire from
// anti-debug and anti-tamper paths, which is to say from the paths that run
// when something is already wrong, and often from inside a loop. A synchronous
// write per event would make a program under a debugger crawl, and an audit log
// that makes the tool unusable is an audit log that gets switched off. The
// chain lives in memory and is written out when a document is produced.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"mutant/object"
	"mutant/security"
)

const (
	// auditChainVersion is hashed into every link. A future change to what an
	// entry contains gets a new version string, so an old log cannot be checked
	// under new rules and quietly fail, nor a new log under old ones and
	// quietly pass.
	auditChainVersion = "mutant-audit-1"

	// auditGenesis is the `prev` of the first entry. Sixty-four zeros rather
	// than an empty string: it is visibly not a digest, so nobody reads it as
	// one, and it still occupies the field so the first link is computed the
	// same way as every other.
	auditGenesis = "0000000000000000000000000000000000000000000000000000000000000000"

	// auditRetained caps what the chain keeps in memory. OpChkDbg is emitted
	// inside loops, so a program run under a debugger can record the same event
	// hundreds of thousands of times, and an audit log that exhausts memory has
	// denied the examiner the tool as surely as any tamper response.
	//
	// The head is not capped -- it is 32 bytes and covers every event ever
	// recorded. Only the readable entries are dropped, oldest first, and both
	// the count dropped and the sequence number the retained run starts at are
	// reported, so a truncated log is never mistaken for a short one.
	auditRetained = 4096
)

// auditEntry is one link.
type auditEntry struct {
	Seq   int64
	At    time.Time
	Event string
	Stage string
	Prev  string
	Hash  string
}

// auditChain is the append-only log. The zero value is an empty chain.
type auditChain struct {
	mu      sync.Mutex
	head    string
	total   int64
	dropped int64
	entries []auditEntry
}

// auditLog is the process-wide chain, for the same reason `custodyStore` is
// process-wide: a `spawn`ed task gets its own VM but shares this package, and a
// debugger detected on a task's goroutine is a debugger detected on this run.
var auditLog auditChain

// auditNow is the clock, indirected so tests can pin it, as `custodyNow` is.
var auditNow = time.Now

// init installs the chain as the process's audit sink.
//
// It is done here rather than by the runner because every entry point that can
// execute a program -- the CLI, the REPL, the test runner, an embedding host --
// links this package, and an audit log that depended on the caller remembering
// to switch it on would be missing from exactly the runs nobody planned.
func init() {
	security.SetAuditSink(&auditLog)
}

// AuditEvent implements security.AuditSink.
func (c *auditChain) AuditEvent(event, stage string) {
	c.appendEntry(event, stage, auditNow())
}

// appendEntry adds one link and returns it.
func (c *auditChain) appendEntry(event, stage string, at time.Time) auditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()

	prev := c.head
	if prev == "" {
		prev = auditGenesis
	}

	c.total++
	entry := auditEntry{
		Seq:   c.total,
		At:    at.UTC(),
		Event: event,
		Stage: stage,
		Prev:  prev,
	}
	entry.Hash = auditLink(prev, entry.Seq, entry.At.UnixNano(), entry.Event, entry.Stage)
	c.head = entry.Hash

	// Drop a quarter at a time rather than one per append: shifting a
	// 4096-entry slice on every event once the cap is reached is O(n) per event
	// in exactly the loop this cap exists to survive.
	if len(c.entries) >= auditRetained {
		drop := auditRetained / 4
		c.entries = append(c.entries[:0], c.entries[drop:]...)
		c.dropped += int64(drop)
	}
	c.entries = append(c.entries, entry)

	return entry
}

// auditLink computes one entry's hash.
//
// Every field is written length-prefixed rather than joined with a separator,
// because `stage` is free text that arrives from the caller -- "runner:"+stage
// in one place, an opcode name in another -- and a separator a caller can spell
// is a separator a caller can forge across. Length prefixes have no such
// spelling.
func auditLink(prev string, seq, unixNano int64, event, stage string) string {
	sum := sha256.New()
	field := func(s string) {
		fmt.Fprintf(sum, "%d:%s", len(s), s)
	}
	field(auditChainVersion)
	field(prev)
	field(strconv.FormatInt(seq, 10))
	field(strconv.FormatInt(unixNano, 10))
	field(event)
	field(stage)
	return hex.EncodeToString(sum.Sum(nil))
}

// auditSnapshot is the chain as it stood at one moment, with the lock released.
type auditSnapshot struct {
	Head    string
	Total   int64
	Dropped int64
	Entries []auditEntry
}

func (c *auditChain) snapshot() auditSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	snapshot := auditSnapshot{
		Head:    c.head,
		Total:   c.total,
		Dropped: c.dropped,
		Entries: make([]auditEntry, len(c.entries)),
	}
	if snapshot.Head == "" {
		snapshot.Head = auditGenesis
	}
	copy(snapshot.Entries, c.entries)
	return snapshot
}

// reset empties the chain. Tests only; there is no builtin for it, because a
// program that could clear its own audit log has no audit log.
func (c *auditChain) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.head, c.total, c.dropped, c.entries = "", 0, 0, nil
}

// complete reports whether the retained entries are the whole log.
func (s auditSnapshot) complete() bool {
	return s.Dropped == 0
}

// firstRetainedSeq is the sequence number the readable run starts at, or 0 when
// nothing has been recorded. It is what tells a reader of a capped log where
// their evidence begins.
func (s auditSnapshot) firstRetainedSeq() int64 {
	if len(s.Entries) == 0 {
		return 0
	}
	return s.Entries[0].Seq
}

// auditDoesNotCover is the sentence every audit document carries. It is the
// same discipline as the disclosure manifest's field of the same name: the
// limits are part of the document, not a footnote in the manual.
const auditDoesNotCover = "a log that was deleted or truncated as a whole. Editing an entry breaks the " +
	"link to every entry after it, so this document can show that an entry changed; no document can show " +
	"that a document is missing. That needs the head from somewhere its writer did not control -- the seal " +
	"of the case manifest written beside it, or an external anchor."

// auditManifestRecord renders the chain for the case manifest.
//
// This is the binding. The head goes inside a document that is hashed and, when
// the machine has a key, signed -- so the manifest is the anchor the chain
// otherwise lacks, and it is an anchor that already existed rather than one
// this feature had to invent.
func auditManifestRecord() map[string]any {
	snapshot := auditLog.snapshot()
	return map[string]any{
		"head":               snapshot.Head,
		"entries":            snapshot.Total,
		"retained":           int64(len(snapshot.Entries)),
		"dropped":            snapshot.Dropped,
		"chain_complete":     snapshot.complete(),
		"first_retained_seq": snapshot.firstRetainedSeq(),
		"recording":          security.AuditSinkInstalled(),
		"algorithm":          auditChainVersion,
		"covers": "the security events this run recorded, in the order they happened. The head is inside " +
			"this manifest's seal, so a log written by `audit_write` whose head does not match this one is " +
			"not the log this case was examined under.",
		"does_not_cover": auditDoesNotCover,
	}
}

// AuditHead returns the chain head and what it covers: audit_head().
func AuditHead(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	snapshot := auditLog.snapshot()
	return resultAndError(makeHashObject(map[string]object.Object{
		"head":               stringObj(snapshot.Head),
		"entries":            intObj(snapshot.Total),
		"retained":           intObj(int64(len(snapshot.Entries))),
		"dropped":            intObj(snapshot.Dropped),
		"chain_complete":     boolObj(snapshot.complete()),
		"first_retained_seq": intObj(snapshot.firstRetainedSeq()),
		"recording":          boolObj(security.AuditSinkInstalled()),
		"status":             stringObj("ok"),
	}), nil)
}

// AuditWrite writes the log to disk: audit_write(path).
func AuditWrite(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameAuditWrite, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("audit_write: the path must not be empty"))
	}

	snapshot := auditLog.snapshot()
	document, err := json.MarshalIndent(auditDocument(snapshot), "", "  ")
	if err != nil {
		return resultAndError(nil, newError("audit_write: the log cannot be written as JSON: %s", err.Error()))
	}
	document = append(document, '\n')

	artifact, errObj := writeArtifact(BuiltinNameAuditWrite, path, document)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyRecordArtifact(BuiltinNameAuditWrite,
		fmt.Sprintf("wrote the security audit log to %s (%d entries, head %s)", path, snapshot.Total, snapshot.Head),
		map[string]any{
			"path":           path,
			"head":           snapshot.Head,
			"entries":        snapshot.Total,
			"chain_complete": snapshot.complete(),
			"sha256":         artifact.digest,
		})

	return resultAndError(makeHashObject(map[string]object.Object{
		"path":           stringObj(path),
		"bytes":          intObj(artifact.bytes),
		"sha256":         stringObj(artifact.digest),
		"head":           stringObj(snapshot.Head),
		"entries":        intObj(snapshot.Total),
		"retained":       intObj(int64(len(snapshot.Entries))),
		"dropped":        intObj(snapshot.Dropped),
		"chain_complete": boolObj(snapshot.complete()),
		"status":         stringObj("ok"),
	}), nil)
}

// auditDocument renders the log as the native document `audit_write` writes and
// `audit_verify` reads.
//
// `unix_nano` is what the hash covers and `at` is what a person reads. They are
// both in the document and `audit_verify` checks that they agree, because a
// display field outside the hash is a field an editor can change without
// breaking a link -- which is the whole trick a hash chain exists to prevent.
func auditDocument(snapshot auditSnapshot) map[string]any {
	log := make([]any, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		log = append(log, map[string]any{
			"seq":       entry.Seq,
			"at":        entry.At.UTC().Format(time.RFC3339Nano),
			"unix_nano": entry.At.UnixNano(),
			"event":     entry.Event,
			"stage":     entry.Stage,
			"prev":      entry.Prev,
			"hash":      entry.Hash,
		})
	}

	return map[string]any{
		"algorithm":          auditChainVersion,
		"genesis":            auditGenesis,
		"head":               snapshot.Head,
		"entries":            snapshot.Total,
		"retained":           int64(len(snapshot.Entries)),
		"dropped":            snapshot.Dropped,
		"chain_complete":     snapshot.complete(),
		"first_retained_seq": snapshot.firstRetainedSeq(),
		"written_at":         auditNow().UTC().Format(time.RFC3339Nano),
		"does_not_cover":     auditDoesNotCover,
		"log":                log,
	}
}

// AuditVerify re-walks a written log: audit_verify(path, head?).
func AuditVerify(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	path, errObj := requireStringArg(BuiltinNameAuditVerify, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	expected := ""
	if len(args) == 2 {
		expected, errObj = requireStringArg(BuiltinNameAuditVerify, args[1], 2)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		expected = strings.ToLower(strings.TrimSpace(expected))
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return resultAndError(nil, newError("audit_verify: %s", err.Error()))
	}

	// UseNumber for the same reason the manifest verifier uses it: every number
	// in this document is an integer, and a sequence number that came back as
	// 4096.0 would recompute a different hash for a log nobody had touched.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return resultAndError(nil, newError("audit_verify: %s is not an audit log: %s", path, err.Error()))
	}

	algorithm := stringField(document, "algorithm")
	if algorithm != auditChainVersion {
		return resultAndError(nil, newError(
			"audit_verify: %s is version %q and this build checks %q; a chain checked under rules it was not written under would pass or fail for the wrong reason",
			path, algorithm, auditChainVersion))
	}

	entries, ok := document["log"].([]any)
	if !ok {
		return resultAndError(nil, newError("audit_verify: %s has no log", path))
	}

	recorded := strings.ToLower(stringField(document, "head"))
	result, computed := auditWalk(entries)
	result["path"] = path
	result["head"] = recorded
	result["entries"] = manifestInt(document, "entries")
	result["dropped"] = manifestInt(document, "dropped")
	result["chain_complete"] = manifestBool(document, "chain_complete")
	result["head_matches"] = recorded != "" && recorded == computed
	result["does_not_cover"] = auditDoesNotCover

	// Two bits, never one, for the same reason the *_verify family reports
	// `checked` beside `passed`: a log checked against the head stored inside
	// it has been checked against a value its own writer chose. `anchored` says
	// whether a head came from outside the document; `anchor_matches` says
	// whether it agreed. An unanchored verify is not a failure -- it is a
	// weaker check, and the answer has to say which one was run.
	result["anchored"] = expected != ""
	result["anchor_matches"] = expected != "" && expected == computed
	result["status"] = "ok"

	return custodyManifestResult(BuiltinNameAuditVerify, result)
}

// auditWalk recomputes every link in a decoded log and reports where it first
// stops agreeing.
//
// It stops at the first break rather than reporting every mismatch, because
// after a broken link every later entry is unverifiable for a reason that has
// nothing to do with that entry -- listing them all would be a page of findings
// describing one edit.
func auditWalk(entries []any) (map[string]any, string) {
	previous := ""
	computed := ""
	checked := int64(0)
	var firstBroken int64
	detail := ""

	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			firstBroken, detail = checked+1, "an entry in the log is not an object"
			break
		}

		seq := manifestInt(entry, "seq")
		unixNano := manifestInt(entry, "unix_nano")
		prev := strings.ToLower(stringField(entry, "prev"))
		hash := strings.ToLower(stringField(entry, "hash"))

		// The first retained entry's `prev` is a claim, not something this
		// document can check: on a capped log the entry it names was dropped.
		// So the chain is followed from here rather than from the genesis.
		if previous != "" && prev != previous {
			firstBroken = seq
			detail = fmt.Sprintf("entry %d follows %s but the entry before it hashes to %s", seq, prev, previous)
			break
		}

		recomputed := auditLink(prev, seq, unixNano, stringField(entry, "event"), stringField(entry, "stage"))
		if recomputed != hash {
			firstBroken = seq
			detail = fmt.Sprintf("entry %d hashes to %s and records %s", seq, recomputed, hash)
			break
		}

		// The rendered time is outside the hash, so it is checked against the
		// number that is inside it.
		if rendered := stringField(entry, "at"); rendered != time.Unix(0, unixNano).UTC().Format(time.RFC3339Nano) {
			firstBroken = seq
			detail = fmt.Sprintf("entry %d reads %s and its sealed timestamp is %s",
				seq, rendered, time.Unix(0, unixNano).UTC().Format(time.RFC3339Nano))
			break
		}

		previous, computed = hash, hash
		checked++
	}

	result := map[string]any{
		"links_checked": checked,
		"computed_head": computed,
		"links_intact":  firstBroken == 0,
		"broken_at":     firstBroken,
		"detail":        detail,
	}
	if firstBroken == 0 {
		if checked == 0 {
			result["detail"] = "the log is empty; there is nothing to check"
		} else {
			result["detail"] = fmt.Sprintf("%d links recomputed, all intact", checked)
		}
	}
	return result, computed
}
