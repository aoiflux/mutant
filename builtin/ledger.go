package builtin

// The forensic ledger: a graphene store opened in the one posture that can
// carry evidence, and kept apart from the one that cannot.
//
// Mutant has had a graph database since long before it had a case file.
// `db_open_disk` opens a graphene store with a memory ceiling and nothing else,
// and `builtin/db.go` says in as many words why the rest was left alone:
//
//	"The store has a large options surface -- signing, audit, retention,
//	 redaction, roles -- and every one of those is a forensic-integrity
//	 decision that belongs in its own builtin with its own contract, not in
//	 an untyped hash a script assembles."
//
// This file is that builtin. `ledger_open` takes a path and an actor and
// nothing else, because every remaining knob is a decision about what the
// resulting document is allowed to claim, and a script that can turn signing
// off is a script whose store cannot be relied upon to have had it on.
//
// # What the posture is, and why each part of it
//
// `disk.StrictOptions` sets three of them -- sign every commit, refuse to
// replay a log containing an unsigned one, and verify the image before loading
// it. Three more are set here:
//
//   - **Redaction.** Without it `RedactNode` refuses rather than degrading to
//     an unrecorded delete, so the ledger that records who removed what has to
//     exist from the first open. It is a separate file that compaction never
//     truncates.
//   - **Retention.** The zero value keeps nothing, and graphene says plainly
//     what that costs: "compaction discards the log along with every commit's
//     actor, timestamp, signature, and every key rotation it held." A store
//     that is compacted once under the default has attribution for nothing
//     before that compaction, and nothing anywhere reports the loss. Evidence
//     keeps everything, so the one rule set here keeps every retired segment.
//   - **Roles is deliberately left off**, which is the one place this posture
//     declines graphene's advice. See below.
//
// # The roles gap is on purpose, and custody will keep reporting it
//
// `CustodyFor` returns a gap reading "no role grants are recorded, so nothing
// says who was permitted to write, redact or compact. Set Options.Roles to
// record it." Turning the grant ledger on does not close it -- an empty grant
// ledger still records no grants -- and filling it would mean Mutant issuing
// credentials, which is the thing this design settled on not doing. The
// identity here is examiner-asserted and recorded, exactly as the free-text
// `examiner` string already is. A grant ledger would manufacture the appearance
// of an authorisation model behind a name somebody typed, and graphene is blunt
// that it would not be one either: "an audit mechanism, not a security
// boundary. Nothing in the engine consults it."
//
// So the gap stands, and `ledger_custody` reports it rather than hiding it. A
// custody report that never says "nothing establishes who was allowed to do
// this" on a tool with no authentication would be claiming the opposite of the
// truth.
//
// # The property blob is not the property index, and redaction only knows one
//
// This is the trap that would have shipped silently.
//
// A graphene node carries `Properties []byte` -- an opaque blob -- and,
// separately, index entries registered through `IndexNodeProperties`. They are
// different storage. `db_add_artifact` and `db_index_prop` write only the
// second: `dbAddIndexedNode` adds a node with labels and no blob, then
// registers the attributes as index entries.
//
// `RedactNodeProperties` reads the first. On a node written the way Mutant has
// always written them it finds an empty blob and refuses:
//
//	disk: node 1 carries no properties to redact
//
// The redaction does not happen, the caller gets an error rather than a
// removal, and the values -- which are sitting in the property index, indexed
// precisely so they can be searched for -- stay exactly where they were. The
// operation that exists to destroy content reports failure and destroys
// nothing.
//
// (Graphene is not at fault and does the harder half correctly: when a
// property redaction does run, it purges the index unconditionally, outside
// its own reindex policy, because "the property index holds the values
// themselves; leaving its entries behind would keep the redacted content
// queryable". The gap is entirely in how the blob gets written.)
//
// So `ledger_add_node` writes **both**, from one map, in one transaction: a
// deterministic msgpack blob and the index entries. `redactable` comes back on
// every write saying whether that node can ever be property-redacted, because
// the answer is fixed at write time and discovering it at redaction time is
// discovering it too late.
//
// # The actor is asserted, and zero is not an actor
//
// `store.TxContext.Unattributed()` is true when `ActorID == 0`, so an actor id
// that happens to be zero is not a commit by actor zero -- it is a commit by
// nobody, recorded as such. The id here is the first eight bytes of
// SHA-256 over the actor's name, forced non-zero, so it is reproducible by
// anyone holding the name and can never land on the unattributed value.
//
// It authenticates nothing. It is a name somebody typed, hashed so it fits in
// the field graphene records. Every rendering says `actor` beside `actor_id`
// for that reason.
//
// # Why a ledger directory refuses to open as an ordinary graph
//
// Handles are the obvious collision and the plan named it: `dbGet` resolves any
// int64 in `dbHandles`, so a shared handle space would let `db_add_node(ledger,
// 5)` write an untyped node into the custody ledger inside a signed,
// attributed commit. Ledger handles therefore live in their own map with their
// own counter, and no `db_*` builtin can resolve one.
//
// The path is the same collision by another route, and the consequence is
// worse. `db_open_disk(ledger_path)` opens the store with no signer -- graphene
// allows it and says nothing, because an unsigned posture is a valid posture --
// and a write through that handle commits unsigned. The store is not silently
// corrupted; it is worse than that. The next strict open refuses the whole
// store:
//
//	disk.Open: replay WAL: wal replay: commit 2 carries no signature and
//	signed commits are required
//
// which is detection rather than prevention, and what it detects is that the
// ledger can no longer be opened at all. So `ledger_open` writes a marker file
// into the directory and `db_open_disk` refuses any directory carrying one,
// naming this family instead.
//
// What that does and does not buy, stated plainly: it stops Mutant opening its
// own ledger in the wrong posture, which is the mistake a script can actually
// make. It stops nothing outside this process. A second Mutant is stopped by
// graphene's own lock while the ledger is open, and by nothing once it is
// closed.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/signing"
	"github.com/aoiflux/graphene/store"
	"github.com/vmihailenco/msgpack/v5"

	"mutant/object"
	"mutant/security"
)

const (
	// ledgerMarkerName is written into a ledger directory so db_open_disk can
	// recognise one. The name is not hidden and the contents are readable: a
	// tripwire nobody can see is one somebody removes wondering what it was.
	ledgerMarkerName = "mutant.ledger"

	// ledgerMarkerBody explains the file to whoever finds it in a directory
	// listing, which is the only audience it has.
	ledgerMarkerBody = "mutant-forensic-ledger 1\n" +
		"\n" +
		"This directory is a Mutant forensic ledger: a graphene store whose every\n" +
		"commit is signed and whose log refuses to replay if one is not. Open it\n" +
		"with ledger_open, never with db_open_disk -- an unsigned write through an\n" +
		"ordinary handle leaves a store that no strict open will ever accept again.\n"

	// ledgerRetainedSegments is the retention policy's only rule, and it is set
	// high enough to mean "all of them". Graphene applies its three rules
	// together and ignores any left at zero, so a count on its own keeps every
	// retired segment and bounds neither bytes nor age -- which is what
	// evidence wants and what the zero value, keeping nothing, is the opposite
	// of.
	ledgerRetainedSegments = math.MaxInt32
)

var (
	ledgerHandleCounter int64

	// ledgerHandles maps int64 -> *ledgerSession, in a map of its own.
	//
	// Separate from dbHandles so that no db_* builtin can resolve a ledger, and
	// so that a ledger handle and a graph handle with the same numeric value
	// are two different things rather than one. See the file header.
	ledgerHandles sync.Map
)

// ledgerSession is one open ledger, and the record of the posture it was
// opened under. The posture is carried rather than re-derived because it is
// reported in several places and a second derivation is a second chance to
// disagree with the first.
type ledgerSession struct {
	graph *graphene.Graph
	store *disk.Store
	path  string

	// actor is what the examiner asserted; actorID is that name hashed into
	// the field graphene records. Neither is authenticated.
	actor   string
	actorID uint64

	keyID     uint64
	publicKey ed25519.PublicKey

	// verifier is the keyring this ledger was opened with, held so the custody
	// report can check the snapshot's attestation. graphene accepts a nil
	// verifier and downgrades every signature-dependent layer to
	// "unestablished", which would report an unchecked attestation on a store
	// whose key is in this process.
	verifier store.Verifier

	// keyCreatedForThisRun is true when the signing key did not exist until
	// this process asked for one, which makes every signature under it a
	// signature by a key born seconds before the evidence it vouches for.
	// Surfaced everywhere it can be, for the same reason custody_seal.go
	// surfaces it.
	keyCreatedForThisRun bool

	openedAt time.Time
}

// ledgerIDFrom derives a non-zero 64-bit id from arbitrary bytes.
//
// Non-zero because zero is not a small id, it is the absence of one:
// store.TxContext.Unattributed() reads ActorID == 0 as "no actor was given",
// so a name that hashed to zero would be committed as unattributed while the
// caller believed it was attributed. Flipping the low bit costs nothing and
// removes the case entirely.
func ledgerIDFrom(data []byte) uint64 {
	sum := sha256.Sum256(data)
	id := binary.BigEndian.Uint64(sum[:8])
	if id == 0 {
		id = 1
	}
	return id
}

func ledgerHash(h [32]byte) string {
	return hex.EncodeToString(h[:])
}

func ledgerGet(handle int64) (*ledgerSession, bool) {
	value, ok := ledgerHandles.Load(handle)
	if !ok {
		return nil, false
	}
	session, ok := value.(*ledgerSession)
	return session, ok
}

// ledgerHandleArg resolves argument one of every builtin in this family.
//
// The refusal names the ledger family rather than saying "invalid handle",
// because the likeliest reason a handle does not resolve here is that it is a
// db_open_disk handle, and a script that mixed them up needs to be told which
// of the two spaces it is in.
func ledgerHandleArg(arg object.Object, op string) (*ledgerSession, *object.Error) {
	handle, ok := arg.(*object.Integer)
	if !ok {
		return nil, newError("argument 1 to `%s` must be INTEGER, got %s", op, arg.Type())
	}
	session, found := ledgerGet(handle.Value)
	if !found {
		return nil, newError("%s: unknown ledger handle %d; ledger handles come from ledger_open and are not graph handles", op, handle.Value)
	}
	return session, nil
}

// ledgerMarkerPath is where the marker lives inside a store directory.
func ledgerMarkerPath(dir string) string {
	return filepath.Join(dir, ledgerMarkerName)
}

// ledgerIsMarked reports whether a directory has been opened as a ledger.
//
// A read error is reported as "not a ledger" rather than propagated: this is
// consulted from db_open_disk, and failing an ordinary open because a stat of
// an unrelated file failed would make the guard more disruptive than the thing
// it guards against.
func ledgerIsMarked(dir string) bool {
	info, err := os.Stat(ledgerMarkerPath(dir))
	return err == nil && !info.IsDir()
}

// ledgerWriteMarker records that this directory is a ledger, and reports
// whether it had to be written.
//
// Called after a successful open, never before: a directory that failed to
// open strict is not a ledger, and marking it would lock an ordinary store out
// of db_open_disk on the strength of an attempt.
func ledgerWriteMarker(dir string) (bool, error) {
	if ledgerIsMarked(dir) {
		return false, nil
	}
	if err := os.WriteFile(ledgerMarkerPath(dir), []byte(ledgerMarkerBody), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// ledgerProperties converts the property hash every write takes into the one
// map that becomes both the blob and the index entries.
//
// Values are STRING or BYTES and nothing else. The property index matches on
// exact bytes, so a value whose encoding Mutant chose -- an integer rendered
// as decimal, a float rendered at some precision -- would be searchable only
// by a caller who guessed the same rendering. Making the caller spell it
// removes the guess.
func ledgerProperties(arg object.Object, op string) (map[string][]byte, *object.Error) {
	hash, ok := arg.(*object.Hash)
	if !ok {
		return nil, newError("argument to `%s` must be HASH, got %s", op, arg.Type())
	}

	props := make(map[string][]byte, len(hash.Pairs))
	for _, pair := range hash.Pairs {
		key, ok := pair.Key.(*object.String)
		if !ok {
			return nil, newError("%s: property keys must be STRING, got %s", op, pair.Key.Type())
		}
		if strings.TrimSpace(key.Value) == "" {
			return nil, newError("%s: a property key must not be empty", op)
		}
		switch value := pair.Value.(type) {
		case *object.String:
			props[key.Value] = []byte(value.Value)
		case *object.Bytes:
			// Copied: the buffer belongs to the script and may be mutated
			// after this returns, and the blob is about to be hashed into a
			// version the store commits to.
			buf := make([]byte, len(value.Value))
			copy(buf, value.Value)
			props[key.Value] = buf
		default:
			return nil, newError("%s: property %q must be STRING or BYTES, got %s", op, key.Value, pair.Value.Type())
		}
	}
	return props, nil
}

// ledgerPropertyBlob encodes the properties as the opaque blob graphene stores
// on the entity itself.
//
// Deterministic, because the version hash is derived from these bytes and that
// hash is what a redaction record names as the identity of the content it
// destroyed. A party holding a copy proves it is that content by re-deriving
// the hash, which only works if the encoding is a function of the properties
// and nothing else.
//
// **The keys are sorted here rather than by the encoder's flag, which does not
// cover this map type.** `SetSortMapKeys` reaches map[string]string,
// map[string]bool and map[string]interface{}; every other map, including
// map[string][]byte, falls through to the reflection path and is written in Go
// map order, which is deliberately randomised per run. Setting the flag and
// trusting it produced a blob whose bytes -- and therefore whose version hash
// -- differed between two encodings of the same properties in the same
// process. (`msgpack_encode` is unaffected: objectToNative hands it
// map[string]any, which is one of the three.)
func ledgerPropertyBlob(props map[string][]byte) ([]byte, error) {
	if len(props) == 0 {
		return nil, nil
	}

	keys := make([]string, 0, len(props))
	for key := range props {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	encoder := msgpack.NewEncoder(&buf)
	encoder.UseCompactInts(true)
	if err := encoder.EncodeMapLen(len(keys)); err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := encoder.EncodeString(key); err != nil {
			return nil, err
		}
		if err := encoder.EncodeBytes(props[key]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// LedgerOpen opens a forensic ledger in the fixed strict posture.
func LedgerOpen(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	pathArg, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be STRING, got %s", BuiltinNameLedgerOpen, args[0].Type()))
	}
	actorArg, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be STRING, got %s", BuiltinNameLedgerOpen, args[1].Type()))
	}
	path := strings.TrimSpace(pathArg.Value)
	if path == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", BuiltinNameLedgerOpen))
	}
	actor := strings.TrimSpace(actorArg.Value)
	if actor == "" {
		// An unattributed ledger is the one thing this family exists to
		// prevent, so the name is required rather than defaulted. A default
		// would put a plausible string in the attribution field of every
		// commit made by a script that forgot to say who was running it.
		return resultAndError(nil, newError("%s: the actor must not be empty; a ledger records who wrote it and there is no default", BuiltinNameLedgerOpen))
	}
	// actor_id is a hash of these exact bytes and the name is also stored as
	// JSON, so an actor that is not valid UTF-8 attributes commits to an id
	// nobody can rederive from the name the ledger reports.
	if errObj := custodyDocumentName(BuiltinNameLedgerOpen, "actor name", actor); errObj != nil {
		return resultAndError(nil, errObj)
	}

	privateKey, publicKey, generated, _, err := security.EnsureLocalSigningKeyPair()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerOpen, err.Error()))
	}

	keyID := ledgerIDFrom(publicKey)
	signer, err := signing.NewKey(keyID, privateKey)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerOpen, err.Error()))
	}
	keyring := signing.NewKeyring()
	if err := keyring.Add(keyID, publicKey); err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerOpen, err.Error()))
	}

	actorID := ledgerIDFrom([]byte(actor))

	opts := disk.StrictOptions(signer, keyring, actorID)
	opts.Redaction = true
	opts.Retention = disk.RetentionPolicy{MaxSegments: ledgerRetainedSegments}

	graph, err := graphene.OpenWithOptions(path, opts)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerOpen, err.Error()))
	}
	diskStore, ok := graph.Forensics()
	if !ok {
		// Unreachable through this path -- OpenWithOptions builds a disk store
		// -- but the whole family is calls on this pointer, and a nil here
		// would be a panic several builtins later rather than an error now.
		_ = graph.Close()
		return resultAndError(nil, newError("%s: the store opened without a forensic layer", BuiltinNameLedgerOpen))
	}

	created, err := ledgerWriteMarker(path)
	if err != nil {
		_ = graph.Close()
		return resultAndError(nil, newError("%s: the store opened but could not be marked as a ledger: %s", BuiltinNameLedgerOpen, err.Error()))
	}

	session := &ledgerSession{
		graph:                graph,
		store:                diskStore,
		path:                 path,
		actor:                actor,
		actorID:              actorID,
		keyID:                keyID,
		publicKey:            publicKey,
		verifier:             keyring,
		keyCreatedForThisRun: generated,
		openedAt:             time.Now(),
	}

	handle := atomic.AddInt64(&ledgerHandleCounter, 1)
	ledgerHandles.Store(handle, session)

	custodyRecordArtifact(BuiltinNameLedgerOpen,
		fmt.Sprintf("opened forensic ledger %s as %q", path, actor),
		map[string]any{
			"path":                     path,
			"actor":                    actor,
			"actor_id":                 fmt.Sprintf("%d", actorID),
			"key_id":                   fmt.Sprintf("%d", keyID),
			"key_created_for_this_run": generated,
		})

	return resultAndError(makeHashObject(map[string]object.Object{
		"handle": intObj(handle),
		"path":   stringObj(path),
		// The asserted name and the number derived from it, always together.
		"actor":      stringObj(actor),
		"actor_id":   stringObj(fmt.Sprintf("%d", actorID)),
		"key_id":     stringObj(fmt.Sprintf("%d", keyID)),
		"public_key": stringObj(hex.EncodeToString(publicKey)),
		// A signature by a key this run generated vouches for nothing that
		// happened before this run.
		"key_created_for_this_run": boolObj(generated),
		// Whether this directory had been opened as a ledger before.
		"created": boolObj(created),
		// The posture, reported rather than assumed, so a manifest can quote it.
		"signed_commits_required": boolObj(true),
		"verified_on_open":        boolObj(true),
		"redaction_ledger":        boolObj(true),
		"audit_log":               boolObj(true),
		// Deliberately false; see the file header and ledger_custody's gaps.
		"role_grants":       boolObj(false),
		"retained_segments": stringObj("all"),
	}), nil)
}

// LedgerClose closes a ledger handle.
func LedgerClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	handle, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `%s` must be INTEGER, got %s", BuiltinNameLedgerClose, args[0].Type()))
	}
	// Claimed atomically, so two concurrent closes cannot both reach Close on
	// the same store -- the same reason db_close uses LoadAndDelete.
	value, found := ledgerHandles.LoadAndDelete(handle.Value)
	if !found {
		return resultAndError(nil, newError("%s: unknown ledger handle %d", BuiltinNameLedgerClose, handle.Value))
	}
	session, ok := value.(*ledgerSession)
	if !ok {
		return resultAndError(nil, newError("%s: unknown ledger handle %d", BuiltinNameLedgerClose, handle.Value))
	}
	if err := session.graph.Close(); err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerClose, err.Error()))
	}
	return resultAndError(boolObj(true), nil)
}

// ledgerCounts reads the figures that describe a ledger's current state.
//
// Errors are folded into zero counts rather than propagated, because these are
// reported alongside an operation that has already succeeded and failing a
// compaction because the audit log could not be counted would be the tail
// wagging the dog. The counts are instrumentation; the roots are the evidence.
func ledgerCounts(session *ledgerSession) (auditEntries, redactions int) {
	if entries, err := session.store.AuditEntries(); err == nil {
		auditEntries = len(entries)
	}
	if records, err := session.store.Redactions(); err == nil {
		redactions = len(records)
	}
	return auditEntries, redactions
}

// ledgerRootFields renders the snapshot roots, or says why there are none.
//
// A store that has never been compacted has no roots at all, and that is not
// an error: it is a store whose contents are entirely in the log. Reporting
// empty strings with `compacted: false` beside them says so, where an error
// would make "nothing has been compacted yet" indistinguishable from "the
// roots could not be read".
func ledgerRootFields(session *ledgerSession, out map[string]object.Object) {
	roots, err := session.store.SnapshotRoots()
	if err != nil {
		out["compacted"] = boolObj(false)
		out["snapshot_root"] = stringObj("")
		out["prev_root"] = stringObj("")
		out["tombstone_root"] = stringObj("")
		out["body_version"] = intObj(0)
		return
	}
	out["compacted"] = boolObj(true)
	out["snapshot_root"] = stringObj(ledgerHash(roots.Snapshot))
	out["prev_root"] = stringObj(ledgerHash(roots.PrevRoot))
	out["tombstone_root"] = stringObj(ledgerHash(roots.TombstoneRoot))
	out["body_version"] = intObj(int64(roots.BodyVersion))
}

// LedgerStats reports what a ledger currently holds and what it commits to.
func LedgerStats(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerStats)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	out := map[string]object.Object{
		"path":     stringObj(session.path),
		"actor":    stringObj(session.actor),
		"actor_id": stringObj(fmt.Sprintf("%d", session.actorID)),
	}
	ledgerRootFields(session, out)

	auditEntries, redactions := ledgerCounts(session)
	out["audit_entries"] = intObj(int64(auditEntries))
	out["redactions"] = intObj(int64(redactions))

	stats, err := session.graph.Stats()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerStats, err.Error()))
	}
	out["nodes"] = intObj(int64(stats.NodeCount))
	out["edges"] = intObj(int64(stats.EdgeCount))
	if stats.HasStorage {
		// delta_records and wal_bytes are what say a compaction is due; a
		// ledger that is never compacted has no snapshot root, and without one
		// nothing in it can be proved to anybody.
		out["delta_records"] = intObj(int64(stats.Storage.DeltaRecords()))
		out["wal_bytes"] = intObj(stats.Storage.WALBytes)
		out["commit_seq"] = intObj(int64(stats.Storage.CommitSeq))
		out["last_compact"] = stringObj(formatTime(stats.Storage.LastCompact))
	} else {
		out["delta_records"] = intObj(0)
		out["wal_bytes"] = intObj(0)
		out["commit_seq"] = intObj(0)
		out["last_compact"] = stringObj("")
	}

	if segments, err := disk.ListSegments(session.path); err == nil {
		out["retained_segments"] = intObj(int64(len(segments)))
	} else {
		out["retained_segments"] = intObj(0)
	}

	return resultAndError(makeHashObject(out), nil)
}

// LedgerCompact merges the delta layer into a new signed image.
//
// This is the operation that makes a ledger provable: an entity written but
// never compacted is live and in no snapshot, so ProveNode has nothing to
// resolve against and CustodyFor reports it as unaccounted for. Everything in
// this family that produces a proof needs a compaction to have happened first,
// which is why the snapshot root comes back from here rather than having to be
// asked for separately.
func LedgerCompact(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerCompact)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	before, _ := dbDeltaRecords(session.graph)

	if err := session.graph.Compact(); err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerCompact, err.Error()))
	}

	after, _ := dbDeltaRecords(session.graph)
	out := map[string]object.Object{
		"delta_records_before": intObj(before),
		"delta_records_after":  intObj(after),
	}
	ledgerRootFields(session, out)

	auditEntries, redactions := ledgerCounts(session)
	out["audit_entries"] = intObj(int64(auditEntries))
	out["redactions"] = intObj(int64(redactions))

	// The retained segments are the commit history the default posture would
	// have discarded here. Reporting the count is how a manifest shows the
	// retention actually took effect rather than being merely configured.
	if segments, err := disk.ListSegments(session.path); err == nil {
		out["retained_segments"] = intObj(int64(len(segments)))
	} else {
		out["retained_segments"] = intObj(0)
	}

	return resultAndError(makeHashObject(out), nil)
}

// ledgerWriteResult is the shape both writes return.
//
// `redactable` is the field worth the extra shape. A node or edge written with
// no properties carries no blob, and RedactNodeProperties refuses on an empty
// blob -- so whether this entity can ever be property-redacted is decided here,
// at write time, and is not visible again until somebody tries to redact it
// and is told no. Saying it now is the only moment it can still be acted on.
func ledgerWriteResult(id int64, props map[string][]byte, blob []byte) object.Object {
	return makeHashObject(map[string]object.Object{
		"id":             intObj(id),
		"property_count": intObj(int64(len(props))),
		"property_bytes": intObj(int64(len(blob))),
		"redactable":     boolObj(len(blob) > 0),
	})
}

// LedgerAddNode writes one attributed node, with its properties in both the
// blob and the index.
func LedgerAddNode(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerAddNode)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	props, errObj := ledgerProperties(args[1], BuiltinNameLedgerAddNode)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	nodeType := store.CustomNodeType(uint16(DATA))
	if len(args) == 3 {
		parsed, errObj := dbNodeTypeFromObject(args[2])
		if errObj != nil {
			return resultAndError(nil, newError("argument 3 to `%s`: %s", BuiltinNameLedgerAddNode, errObj.Inspect()))
		}
		nodeType = parsed
	}

	blob, err := ledgerPropertyBlob(props)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerAddNode, err.Error()))
	}

	tx := session.graph.Begin().As(store.TxContext{ActorID: session.actorID, KeyID: session.keyID})
	nodeID := tx.AddNode(&store.Node{
		Labels:     []store.NodeType{nodeType},
		Properties: blob,
	})
	if len(props) > 0 {
		tx.IndexNodeProperties(nodeID, props)
	}
	if err := tx.Commit(); err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerAddNode, err.Error()))
	}

	return resultAndError(ledgerWriteResult(int64(nodeID), props, blob), nil)
}

// LedgerAddEdge writes one attributed edge, with its properties in both the
// blob and the index.
func LedgerAddEdge(args ...object.Object) object.Object {
	if len(args) != 4 && len(args) != 5 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4 or 5", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerAddEdge)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	src, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", BuiltinNameLedgerAddEdge, args[1].Type()))
	}
	dst, ok := args[2].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 3 to `%s` must be INTEGER, got %s", BuiltinNameLedgerAddEdge, args[2].Type()))
	}
	props, errObj := ledgerProperties(args[3], BuiltinNameLedgerAddEdge)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	edgeType := store.CustomEdgeType(uint16(DATA))
	if len(args) == 5 {
		parsed, errObj := dbEdgeTypeFromObject(args[4])
		if errObj != nil {
			return resultAndError(nil, newError("argument 5 to `%s`: %s", BuiltinNameLedgerAddEdge, errObj.Inspect()))
		}
		edgeType = parsed
	}

	blob, err := ledgerPropertyBlob(props)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerAddEdge, err.Error()))
	}

	tx := session.graph.Begin().As(store.TxContext{ActorID: session.actorID, KeyID: session.keyID})
	edgeID := tx.AddEdge(&store.Edge{
		Src:        store.NodeID(src.Value),
		Dst:        store.NodeID(dst.Value),
		Labels:     []store.EdgeType{edgeType},
		Properties: blob,
	})
	if len(props) > 0 {
		tx.IndexEdgeProperties(edgeID, props)
	}
	if err := tx.Commit(); err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerAddEdge, err.Error()))
	}

	return resultAndError(ledgerWriteResult(int64(edgeID), props, blob), nil)
}

// resetLedgerForTesting drops every open ledger handle.
//
// Mirrors resetCustodyForTesting: the handle map is process-global, so a test
// that opens a ledger and does not close it would otherwise leave a store
// holding a lock on a temp directory the test framework is about to remove.
func resetLedgerForTesting() {
	ledgerHandles.Range(func(key, value any) bool {
		if session, ok := value.(*ledgerSession); ok {
			_ = session.graph.Close()
		}
		ledgerHandles.Delete(key)
		return true
	})
}
