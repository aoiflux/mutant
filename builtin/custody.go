package builtin

// Chain of custody (F-1).
//
// Everything a forensic report needs in order to be defensible was already in
// this language -- digests, timestamps, a deterministic compiler, signing --
// except the discipline that ties them to one investigation. This file is that
// discipline: a case session that records who opened what, when, with which
// build of the tool, and what every builtin subsequently did to it.
//
// Three properties shape the whole design.
//
// The first is that **nothing happens until `case_open` is called**. The hooks
// live in fourteen evidence openers and eleven handle resolvers, on the hot path
// of every forensic program ever written in this language, so the cost of not
// using this feature has to be one atomic load and nothing else. A program that
// never opens a case behaves exactly as it did before.
//
// The second is that **the record is aggregated rather than logged**. A program
// that reads a hundred thousand files must not produce a hundred-thousand-line
// manifest, because then nobody turns it on. Per evidence source, per builtin:
// first touch, last touch, and a count. That is bounded by sources x builtins,
// and it answers the question that is actually asked -- what did this program do
// to this image?
//
// The third is that **a manifest says what it did, not what it wishes it had
// done**. Hashing a source at open is opt-in, because the alternative is
// `raw_open` silently reading half a terabyte before it returns a handle. A case
// opened without hashing produces a manifest that states `"hash_policy": "none"`
// and marks each source `"hashed": false`. Saying nothing is honest; guessing is
// not.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mutant/global"
	"mutant/object"
	"mutant/security"
)

// custodyHashPolicies are the values `case_open`'s `hash` option accepts. They
// are the algorithms fsHashAlgorithm knows, plus "none".
var custodyHashPolicies = map[string]bool{
	"none":   true,
	"md5":    true,
	"sha1":   true,
	"sha256": true,
}

// custodyTouch is what one builtin did to one evidence source, collapsed. The
// count is the number of calls; first and last bracket them.
type custodyTouch struct {
	Builtin string
	First   time.Time
	Last    time.Time
	Count   int64
}

// custodyOpen is one call to an evidence opener.
type custodyOpen struct {
	Builtin string
	Handle  string
	At      time.Time
	Elapsed time.Duration
}

// custodyEvidence is one source file under custody, however many handles were
// opened over it.
type custodyEvidence struct {
	// Path is absolute and symlink-resolved where the filesystem allowed it, so
	// two handles over the same file are one entry rather than two.
	Path string
	// Size and ModTime are what os.Stat said at first registration. They are
	// recorded even when no digest was taken, because they are free and they are
	// still evidence of drift. OnDisk is false for a source that is not a file
	// -- a live registry path, say -- where Size is -1 and there is nothing to
	// re-measure later.
	Size    int64
	ModTime time.Time
	OnDisk  bool
	// Digest is empty when the case's hash policy is "none" or when hashing
	// failed; Algo names the policy that produced it. HashError records why a
	// requested digest is missing rather than leaving the reader to guess.
	Digest    string
	Algo      string
	HashError string
	// Registered is when this source first came under custody.
	Registered time.Time
	Elapsed    time.Duration
	Opens      []custodyOpen
	Touches    map[string]*custodyTouch
}

// custodyEvent is one entry in the case timeline. The timeline is bounded by
// what the analyst did -- opens, notes, verifications, the close -- and never
// grows with what the program read.
type custodyEvent struct {
	At      time.Time
	Elapsed time.Duration
	Event   string
	Detail  string
	// Data is the optional second argument to `case_note`, already converted to
	// native Go values so the manifest can be marshalled without reaching back
	// into the object system.
	Data any
}

// custodySession is one investigation.
type custodySession struct {
	ID         string
	Examiner   string
	HashPolicy string
	OpenedAt   time.Time
	ClosedAt   time.Time
	Closed     bool

	// evidence is keyed by resolved path; order preserves registration order so
	// the manifest reads the way the investigation ran.
	evidence map[string]*custodyEvidence
	order    []string
	// handles maps a live evidence handle to the resolved paths behind it. EWF
	// takes a list of segments, which is why this is a slice.
	handles  map[string][]string
	timeline []custodyEvent
}

// custodyStore holds the one open case. A case is process-wide on purpose: a
// `spawn`ed task gets its own VM but shares this package, so evidence a task
// reads lands in the same manifest -- which is what an examiner means by "the
// case".
var custodyStore = struct {
	sync.RWMutex
	session *custodySession
}{}

// custodyActive is the fast path. Every evidence opener and every handle
// resolver consults it, so when no case is open the whole feature costs one
// atomic load.
var custodyActive atomic.Bool

// custodyNow is the clock, indirected so tests can pin it. time.Now carries a
// monotonic reading, which is what makes the elapsed figures in the manifest
// immune to a wall clock that jumps mid-investigation.
var custodyNow = time.Now

func CaseOpen(args ...object.Object) object.Object {
	if len(args) < 2 || len(args) > 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}

	idObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `case_open` must be STRING, got %s", args[0].Type()))
	}
	examinerObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `case_open` must be STRING, got %s", args[1].Type()))
	}

	id := strings.TrimSpace(idObj.Value)
	examiner := strings.TrimSpace(examinerObj.Value)
	if id == "" {
		return resultAndError(nil, newError("case_open: the case id must not be empty"))
	}
	if examiner == "" {
		return resultAndError(nil, newError("case_open: the examiner must not be empty; a manifest nobody signed for is not a chain of custody"))
	}

	policy := "none"
	if len(args) == 3 {
		policy = strings.ToLower(strings.TrimSpace(optString(args[2], "hash", "none")))
		if !custodyHashPolicies[policy] {
			return resultAndError(nil, newError(
				"case_open: unknown hash policy %q; want \"none\", \"md5\", \"sha1\" or \"sha256\"", policy))
		}
	}

	custodyStore.Lock()
	if custodyStore.session != nil && !custodyStore.session.Closed {
		open := custodyStore.session.ID
		custodyStore.Unlock()
		return resultAndError(nil, newError(
			"case_open: case %q is still open; close it with `case_close()` before opening another", open))
	}

	now := custodyNow()
	session := &custodySession{
		ID:         id,
		Examiner:   examiner,
		HashPolicy: policy,
		OpenedAt:   now,
		evidence:   map[string]*custodyEvidence{},
		handles:    map[string][]string{},
	}
	session.timeline = append(session.timeline, custodyEvent{
		At:    now,
		Event: BuiltinNameCaseOpen,
		Detail: fmt.Sprintf("case %s opened by %s; hash policy %s",
			id, examiner, policy),
	})
	custodyStore.session = session
	custodyStore.Unlock()
	custodyActive.Store(true)

	return resultAndError(makeHashObject(map[string]object.Object{
		"id":          stringObj(id),
		"examiner":    stringObj(examiner),
		"hash_policy": stringObj(policy),
		"opened_at":   stringObj(now.UTC().Format(time.RFC3339Nano)),
		"status":      stringObj("open"),
	}), nil)
}

func CaseNote(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	textObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `case_note` must be STRING, got %s", args[0].Type()))
	}

	var data any
	if len(args) == 2 {
		native, err := objectToNative(args[1], false)
		if err != nil {
			return resultAndError(nil, newError("case_note: argument 2 cannot be recorded: %s", err.Error()))
		}
		data = native
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()

	session, errObj := openSessionLocked(BuiltinNameCaseNote)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	now := custodyNow()
	session.timeline = append(session.timeline, custodyEvent{
		At:      now,
		Elapsed: now.Sub(session.OpenedAt),
		Event:   "note",
		Detail:  textObj.Value,
		Data:    data,
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"event":      stringObj("note"),
		"text":       stringObj(textObj.Value),
		"at":         stringObj(now.UTC().Format(time.RFC3339Nano)),
		"elapsed_ms": intObj(now.Sub(session.OpenedAt).Milliseconds()),
		"status":     stringObj("ok"),
	}), nil)
}

// custodyRecordArtifact records that the program wrote a document out of the
// case: the path, the format, and what the file hashed to.
//
// It is the other direction of the chain. Evidence comes in and is measured on
// the way; a report goes out and is measured on the way, and the manifest is the
// one place both measurements meet. An examiner holding a report and a manifest
// can then ask whether they belong together, without holding the machine that
// produced either.
//
// Like every other custody recorder this does nothing when no case is open, and
// nothing when the case is closed -- a timeline that grew after its own
// `case_close` event would be a document that contradicts itself.
func custodyRecordArtifact(event, detail string, data map[string]any) {
	if !custodyActive.Load() {
		return
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()

	session := custodyStore.session
	if session == nil || session.Closed {
		return
	}

	now := custodyNow()
	session.timeline = append(session.timeline, custodyEvent{
		At:      now,
		Elapsed: now.Sub(session.OpenedAt),
		Event:   event,
		Detail:  detail,
		Data:    data,
	})
}

// CaseEvidence brings a file under custody that no evidence opener will ever
// touch: a carved file, an export, a hash list handed over with the drive.
func CaseEvidence(args ...object.Object) object.Object {
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}

	pathObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `case_evidence` must be STRING, got %s", args[0].Type()))
	}
	if strings.TrimSpace(pathObj.Value) == "" {
		return resultAndError(nil, newError("case_evidence: the path must not be empty"))
	}

	custodyStore.RLock()
	session := custodyStore.session
	policy, closed := "", false
	if session != nil {
		policy, closed = session.HashPolicy, session.Closed
	}
	custodyStore.RUnlock()
	if session == nil {
		return resultAndError(nil, newError("case_evidence: no case is open; call `case_open(id, examiner)` first"))
	}
	if closed {
		return resultAndError(nil, newError("case_evidence: case %s is already closed", session.ID))
	}

	// An explicit registration may ask for a digest the case as a whole did not,
	// because an examiner who names one file is willing to wait for it.
	if len(args) == 2 {
		requested := strings.ToLower(strings.TrimSpace(optString(args[1], "hash", policy)))
		if !custodyHashPolicies[requested] {
			return resultAndError(nil, newError(
				"case_evidence: unknown hash policy %q; want \"none\", \"md5\", \"sha1\" or \"sha256\"", requested))
		}
		policy = requested
	}

	source := custodyStatSource(pathObj.Value)
	if !source.onDisk {
		return resultAndError(nil, newError("case_evidence: %s cannot be read: no such file", pathObj.Value))
	}

	digest, hashError := "", ""
	if policy != "none" {
		value, err := custodyHashFile(source.path, policy)
		if err != nil {
			hashError = err.Error()
		} else {
			digest = value
		}
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	if custodyStore.session != session || session.Closed {
		return resultAndError(nil, newError("case_evidence: the case closed while the file was being read"))
	}

	now := custodyNow()
	record, exists := session.evidence[source.path]
	if !exists {
		record = &custodyEvidence{
			Path:       source.path,
			Size:       source.size,
			ModTime:    source.modTime,
			OnDisk:     true,
			Algo:       policy,
			Registered: now,
			Elapsed:    now.Sub(session.OpenedAt),
			Touches:    map[string]*custodyTouch{},
		}
		session.evidence[source.path] = record
		session.order = append(session.order, source.path)
		session.timeline = append(session.timeline, custodyEvent{
			At:      now,
			Elapsed: now.Sub(session.OpenedAt),
			Event:   "evidence_registered",
			Detail:  fmt.Sprintf("case_evidence registered %s", source.path),
		})
	}
	if digest != "" && record.Digest == "" {
		record.Digest = digest
		record.Algo = policy
		record.HashError = ""
	}
	if hashError != "" && record.Digest == "" {
		record.HashError = hashError
	}

	return custodyManifestResult(BuiltinNameCaseEvidence, record.render())
}

// CaseVerify re-measures every source under custody and reports what moved.
//
// What it can compare depends on what was recorded: a case opened with a hash
// policy compares digests, and one opened without compares size and
// modification time. The report says which, per source, rather than letting the
// reader assume the stronger answer.
func CaseVerify(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	custodyStore.RLock()
	session := custodyStore.session
	custodyStore.RUnlock()
	if session == nil {
		return resultAndError(nil, newError("case_verify: no case is open; call `case_open(id, examiner)` first"))
	}

	// Snapshot what to check, then check it outside the lock: re-hashing a set of
	// disk images is the slowest thing this package does.
	custodyStore.RLock()
	type pending struct {
		path   string
		size   int64
		mod    time.Time
		onDisk bool
		digest string
		algo   string
	}
	checks := make([]pending, 0, len(session.order))
	for _, path := range session.order {
		record := session.evidence[path]
		if record == nil {
			continue
		}
		checks = append(checks, pending{
			path: record.Path, size: record.Size, mod: record.ModTime,
			onDisk: record.OnDisk, digest: record.Digest, algo: record.Algo,
		})
	}
	custodyStore.RUnlock()

	results := make([]any, 0, len(checks))
	counts := map[string]int64{"unchanged": 0, "changed": 0, "missing": 0, "not_on_disk": 0}

	for _, check := range checks {
		entry := map[string]any{"path": check.path}

		if !check.onDisk {
			entry["status"] = "not_on_disk"
			entry["basis"] = "none"
			entry["detail"] = "this source was not a file when it was opened, so there is nothing to re-measure"
			counts["not_on_disk"]++
			results = append(results, entry)
			continue
		}

		now := custodyStatSource(check.path)
		if !now.onDisk {
			entry["status"] = "missing"
			entry["basis"] = "existence"
			entry["detail"] = "the source is no longer readable at this path"
			counts["missing"]++
			results = append(results, entry)
			continue
		}

		if check.digest != "" {
			entry["basis"] = "digest"
			entry["hash_algo"] = check.algo
			entry["hash_at_open"] = check.digest
			current, err := custodyHashFile(check.path, check.algo)
			switch {
			case err != nil:
				entry["status"] = "missing"
				entry["detail"] = err.Error()
				counts["missing"]++
			case current == check.digest:
				entry["status"] = "unchanged"
				entry["hash_now"] = current
				counts["unchanged"]++
			default:
				entry["status"] = "changed"
				entry["hash_now"] = current
				entry["detail"] = "the digest does not match the one taken when this source was opened"
				counts["changed"]++
			}
			results = append(results, entry)
			continue
		}

		// No digest was taken, so this is the weaker check, and it says so.
		entry["basis"] = "size and mod time"
		entry["size_at_open"] = check.size
		entry["size_now"] = now.size
		if now.size == check.size && now.modTime.Equal(check.mod) {
			entry["status"] = "unchanged"
			counts["unchanged"]++
		} else {
			entry["status"] = "changed"
			entry["detail"] = "size or modification time moved; open the case with a hash policy to compare digests instead"
			counts["changed"]++
		}
		results = append(results, entry)
	}

	report := map[string]any{
		"checked":     int64(len(checks)),
		"unchanged":   counts["unchanged"],
		"changed":     counts["changed"],
		"missing":     counts["missing"],
		"not_on_disk": counts["not_on_disk"],
		"sources":     results,
	}

	custodyStore.Lock()
	if custodyStore.session == session && !session.Closed {
		now := custodyNow()
		session.timeline = append(session.timeline, custodyEvent{
			At:      now,
			Elapsed: now.Sub(session.OpenedAt),
			Event:   "verify",
			Detail: fmt.Sprintf("%d sources checked: %d unchanged, %d changed, %d missing",
				len(checks), counts["unchanged"], counts["changed"], counts["missing"]),
			Data: report,
		})
	}
	custodyStore.Unlock()

	return custodyManifestResult(BuiltinNameCaseVerify, report)
}

func CaseManifest(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	// The read lock is held across the render rather than only long enough to
	// pick the session up: a `spawn`ed task reading evidence is writing into
	// these maps, and a manifest torn halfway through that is worse than a
	// manifest that waited.
	custodyStore.RLock()
	defer custodyStore.RUnlock()

	session := custodyStore.session
	if session == nil {
		return resultAndError(nil, newError(
			"case_manifest: no case has been opened; call `case_open(id, examiner)` first"))
	}

	return custodyManifestResult(BuiltinNameCaseManifest, session.manifest())
}

func CaseClose(args ...object.Object) object.Object {
	if len(args) != 0 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0", len(args)))
	}

	custodyStore.Lock()
	session, errObj := openSessionLocked(BuiltinNameCaseClose)
	if errObj != nil {
		custodyStore.Unlock()
		return resultAndError(nil, errObj)
	}

	now := custodyNow()
	session.Closed = true
	session.ClosedAt = now
	session.timeline = append(session.timeline, custodyEvent{
		At:      now,
		Elapsed: now.Sub(session.OpenedAt),
		Event:   BuiltinNameCaseClose,
		Detail:  fmt.Sprintf("case %s closed after %s", session.ID, now.Sub(session.OpenedAt).Round(time.Millisecond)),
	})
	manifest := session.manifest()
	custodyStore.Unlock()
	custodyActive.Store(false)

	return custodyManifestResult(BuiltinNameCaseClose, manifest)
}

// custodyManifestResult hands a rendered manifest back to the program.
//
// The conversion can fail only on a document that outgrows the native
// converter's node budget, which for a manifest means an investigation with
// millions of evidence sources. Reporting it beats returning a truncated
// document that looks complete.
func custodyManifestResult(op string, manifest map[string]any) object.Object {
	converted, err := nativeToObject(manifest)
	if err != nil {
		return resultAndError(nil, newError("%s: the manifest cannot be represented: %s", op, err.Error()))
	}
	return resultAndError(converted, nil)
}

// openSessionLocked returns the open session, or the error the caller should
// hand back. The custody lock must be held.
func openSessionLocked(op string) (*custodySession, *object.Error) {
	session := custodyStore.session
	if session == nil {
		return nil, newError("%s: no case is open; call `case_open(id, examiner)` first", op)
	}
	if session.Closed {
		return nil, newError("%s: case %s is already closed", op, session.ID)
	}
	return session, nil
}

// custodyRecordOpen registers the sources behind a newly created evidence
// handle. It is called by every evidence opener and does nothing when no case is
// open.
//
// A source is hashed here, under the case's policy, because this is the one
// moment at which the program has said what it considers evidence and has not
// yet done anything with it.
func custodyRecordOpen(builtinName, handle string, paths ...string) {
	if !custodyActive.Load() || len(paths) == 0 {
		return
	}

	// Resolve and stat outside the lock: a digest over a disk image can take
	// minutes, and holding the case lock for it would serialise every other
	// evidence read in the program.
	entries := make([]custodySource, 0, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		entries = append(entries, custodyStatSource(p))
	}
	if len(entries) == 0 {
		return
	}

	custodyStore.RLock()
	session := custodyStore.session
	policy, recording := "", false
	if session != nil && !session.Closed {
		policy, recording = session.HashPolicy, true
	}
	custodyStore.RUnlock()
	if !recording {
		return
	}

	// Hashing is done before the write lock is taken, and only for sources this
	// case has not already hashed.
	digests := make(map[string]string, len(entries))
	hashErrors := make(map[string]string, len(entries))
	if policy != "none" {
		custodyStore.RLock()
		pending := make([]string, 0, len(entries))
		for _, entry := range entries {
			if existing, ok := session.evidence[entry.path]; ok && (existing.Digest != "" || existing.HashError != "") {
				continue
			}
			pending = append(pending, entry.path)
		}
		custodyStore.RUnlock()

		for _, path := range pending {
			digest, err := custodyHashFile(path, policy)
			if err != nil {
				hashErrors[path] = err.Error()
				continue
			}
			digests[path] = digest
		}
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	if custodyStore.session != session || session.Closed {
		return
	}

	now := custodyNow()
	registered := make([]string, 0, len(entries))
	for _, entry := range entries {
		record, exists := session.evidence[entry.path]
		if !exists {
			record = &custodyEvidence{
				Path:       entry.path,
				Size:       entry.size,
				ModTime:    entry.modTime,
				OnDisk:     entry.onDisk,
				Algo:       policy,
				Registered: now,
				Elapsed:    now.Sub(session.OpenedAt),
				Touches:    map[string]*custodyTouch{},
			}
			session.evidence[entry.path] = record
			session.order = append(session.order, entry.path)
			registered = append(registered, entry.path)
		}
		if digest, ok := digests[entry.path]; ok && record.Digest == "" {
			record.Digest = digest
			record.HashError = ""
		}
		if reason, ok := hashErrors[entry.path]; ok && record.Digest == "" {
			record.HashError = reason
		}
		record.Opens = append(record.Opens, custodyOpen{
			Builtin: builtinName,
			Handle:  handle,
			At:      now,
			Elapsed: now.Sub(session.OpenedAt),
		})
	}

	if handle != "" {
		paths := make([]string, 0, len(entries))
		for _, entry := range entries {
			paths = append(paths, entry.path)
		}
		session.handles[handle] = paths
	}

	for _, path := range registered {
		session.timeline = append(session.timeline, custodyEvent{
			At:      now,
			Elapsed: now.Sub(session.OpenedAt),
			Event:   "evidence_registered",
			Detail:  fmt.Sprintf("%s opened %s", builtinName, path),
		})
	}
}

// custodyRecordTouch records that builtinName worked on the evidence behind
// handle. It is called by every handle resolver, which already knows both.
//
// A handle opened before the case was is not in the map, and nothing is
// recorded: the manifest would otherwise claim custody of something it never
// saw opened.
func custodyRecordTouch(builtinName, handle string) {
	if !custodyActive.Load() || handle == "" {
		return
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()

	session := custodyStore.session
	if session == nil || session.Closed {
		return
	}
	paths, known := session.handles[handle]
	if !known {
		return
	}

	now := custodyNow()
	for _, path := range paths {
		record, ok := session.evidence[path]
		if !ok {
			continue
		}
		touch, ok := record.Touches[builtinName]
		if !ok {
			touch = &custodyTouch{Builtin: builtinName, First: now}
			record.Touches[builtinName] = touch
		}
		touch.Last = now
		touch.Count++
	}
}

// custodySource is what os.Stat said about a source, before the case lock is
// taken.
type custodySource struct {
	path    string
	size    int64
	modTime time.Time
	onDisk  bool
}

// custodyStatSource resolves and measures one source.
//
// A path that does not name a file is recorded exactly as it was written, with
// onDisk false. `reg_open("HKLM\\SOFTWARE")` reads the live registry, and
// running `filepath.Abs` over that would invent a filesystem path that never
// existed and put it in a court document.
func custodyStatSource(path string) custodySource {
	info, err := os.Stat(path)
	if err != nil {
		return custodySource{path: path, size: -1}
	}

	resolved := custodyResolvePath(path)
	if resolvedInfo, err := os.Stat(resolved); err == nil {
		info = resolvedInfo
	}
	return custodySource{
		path:    resolved,
		size:    info.Size(),
		modTime: info.ModTime(),
		onDisk:  true,
	}
}

// custodyResolvePath is how two handles over one file become one evidence entry.
// Symlinks are followed when the filesystem allows it, because the examiner's
// question is which bytes were read, not which name was typed.
func custodyResolvePath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		if abs, err := filepath.Abs(resolved); err == nil {
			return filepath.Clean(abs)
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}

// custodyHashFile streams a digest over a file. Streaming rather than
// os.ReadFile because the subject is routinely a disk image.
func custodyHashFile(path, algo string) (string, error) {
	hasher, errObj := fsHashAlgorithm(algo)
	if errObj != nil {
		return "", fmt.Errorf("%s", errObj.Message)
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// manifest renders the session as native Go values: the one representation that
// both `encoding/json` and the object system can be built from, so the document
// a program reads and the document written to disk cannot drift apart.
//
// The caller must hold at least a read lock, or own the session outright.
func (s *custodySession) manifest() map[string]any {
	now := custodyNow()
	end := now
	status := "open"
	if s.Closed {
		end = s.ClosedAt
		status = "closed"
	}

	hashed := 0
	evidence := make([]any, 0, len(s.order))
	for _, path := range s.order {
		record := s.evidence[path]
		if record == nil {
			continue
		}
		if record.Digest != "" {
			hashed++
		}
		evidence = append(evidence, record.render())
	}

	timeline := make([]any, 0, len(s.timeline))
	for _, event := range s.timeline {
		entry := map[string]any{
			"at":         event.At.UTC().Format(time.RFC3339Nano),
			"elapsed_ms": event.Elapsed.Milliseconds(),
			"event":      event.Event,
			"detail":     event.Detail,
		}
		if event.Data != nil {
			entry["data"] = event.Data
		}
		timeline = append(timeline, entry)
	}

	// The security counters belong in the manifest because "was anything
	// abnormal while this ran?" is a question asked of every forensic tool, and
	// the honest answer is a number rather than a reassurance.
	telemetry := map[string]any{}
	for name, count := range security.SecurityTelemetrySnapshot() {
		telemetry[name] = int64(count)
	}

	rendered := map[string]any{
		"case": map[string]any{
			"id":          s.ID,
			"examiner":    s.Examiner,
			"opened_at":   s.OpenedAt.UTC().Format(time.RFC3339Nano),
			"closed_at":   custodyOptionalTime(s.Closed, s.ClosedAt),
			"status":      status,
			"duration_ms": end.Sub(s.OpenedAt).Milliseconds(),
		},
		"tool": map[string]any{
			"version":    global.Version,
			"go_version": runtime.Version(),
			"os":         runtime.GOOS,
			"arch":       runtime.GOARCH,
		},
		"integrity": map[string]any{
			"hash_policy":    s.HashPolicy,
			"sources_total":  int64(len(s.order)),
			"sources_hashed": int64(hashed),
			// Not a promise: every evidence backend opens its source with
			// os.Open, and policy/evidence_guard_test.go fails the build if any
			// of that code asks the operating system to change something. A
			// manifest that asserted this without anything checking it would be
			// worse than one that said nothing, because it would look checked.
			"evidence_read_only": true,
			"read_only_policy":   "docs/EVIDENCE_HANDLING_POLICY.md",
		},
		"program":            custodyProgramRecord(),
		"evidence":           evidence,
		"timeline":           timeline,
		"security_telemetry": telemetry,
	}

	// The hash is part of every rendering, because a manifest a program looked
	// at and a manifest on disk should be the same document. The signature is
	// not: reading the key store, and creating a key pair on a machine with
	// none, is not a side effect `case_manifest()` should have.
	_ = custodySeal(rendered, false)
	return rendered
}

func (e *custodyEvidence) render() map[string]any {
	opens := make([]any, 0, len(e.Opens))
	for _, open := range e.Opens {
		opens = append(opens, map[string]any{
			"builtin":    open.Builtin,
			"handle":     open.Handle,
			"at":         open.At.UTC().Format(time.RFC3339Nano),
			"elapsed_ms": open.Elapsed.Milliseconds(),
		})
	}

	names := make([]string, 0, len(e.Touches))
	for name := range e.Touches {
		names = append(names, name)
	}
	sort.Strings(names)

	touches := make([]any, 0, len(names))
	for _, name := range names {
		touch := e.Touches[name]
		touches = append(touches, map[string]any{
			"builtin": touch.Builtin,
			"count":   touch.Count,
			"first":   touch.First.UTC().Format(time.RFC3339Nano),
			"last":    touch.Last.UTC().Format(time.RFC3339Nano),
		})
	}

	rendered := map[string]any{
		"path":          e.Path,
		"on_disk":       e.OnDisk,
		"size":          e.Size,
		"mod_time":      custodyOptionalTime(!e.ModTime.IsZero(), e.ModTime),
		"registered_at": e.Registered.UTC().Format(time.RFC3339Nano),
		"elapsed_ms":    e.Elapsed.Milliseconds(),
		"hashed":        e.Digest != "",
		"hash":          e.Digest,
		"hash_algo":     e.Algo,
		"opens":         opens,
		"touches":       touches,
	}
	if e.HashError != "" {
		rendered["hash_error"] = e.HashError
	}
	return rendered
}

// custodyOptionalTime renders a timestamp that may not have happened yet. An
// empty string rather than a zero time, because "0001-01-01T00:00:00Z" in a
// court document is worse than a blank.
func custodyOptionalTime(present bool, at time.Time) string {
	if !present || at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339Nano)
}

// resetCustodyForTesting drops any open case. Tests in this package share a
// process, and a case left open by one would be recorded into by the next.
func resetCustodyForTesting() {
	custodyStore.Lock()
	custodyStore.session = nil
	custodyStore.Unlock()
	custodyActive.Store(false)
}
