package builtin

// Erasure: destroying the key a record opens under -- in one copy of the
// record, or the case's own key -- and the disposal of a case once nothing in
// it is left to keep.
//
// # Two erasures, and only one of them reaches every copy
//
// A record's key is random and is kept in one place: wrapped under the case
// key, in the record's own header. record_erase overwrites it there, in place,
// with zeros as wide as what was there, forces the write to the disk, and
// checks that the header now holds nothing the case key unwraps. That destroys
// this copy's key and nothing else. Every other copy of the record carries the
// same wrapped key in its own header and still opens with the case key; a
// grant already issued still opens the segments it names, in any copy; and the
// storage under the file may still hold the bytes the overwrite replaced. The
// result says each of those in `does_not_erase`, because an erasure that did
// not say what it missed would be read as one that missed nothing.
//
// case_key_erase is the erasure that reaches every copy: with the case key
// gone, no copy of any record wrapped under it opens for anybody who relies on
// the case key. It erases every generation -- the key file overwritten with
// zeros and removed -- or, with {"generation": n}, one earlier generation,
// whose wrapped key is overwritten in the file under a MAC the passphrase
// recomputes. It does not reach a copy of the key file kept anywhere else, or
// a grant, which carries its segments' keys and not the case key.
//
// # What an erased record says about itself
//
// The record's signature covered the bytes the erasure overwrote, so it cannot
// hold for an erased copy, and record_verify says `signature_valid: false` and
// `erased: true` side by side. The file alone cannot show that nothing else in
// its header changed. The ledger can: an erasure records the file's digest and
// its header's digest before and after, so a copy that hashes to the digest
// recorded after is the copy that erasure left.
//
// # Prepared before, recorded after
//
// Everything that can refuse an erasure runs before a byte is overwritten --
// the case, its state, its holds, the role, the key that must unwrap the
// record, the file opened for writing, and the ledger record of the erasure,
// built but not committed. Then the key is overwritten and the overwrite is
// read back, and only then is the record committed, so the ledger never says a
// key was erased that was not. A commit that fails after that is reported as
// what it is -- the key erased and the ledger silent -- and the case's timeline
// records the erasure.
//
// # Disposal
//
// case_transition(ledger, "disposed", reason) disposes of a retained case, and
// only when the ledger shows everything a disposal needs: no legal hold in
// force, the retention period run, every exhibit returned or disposed of, and
// every generation of the case key erased. A refusal names all of what is
// missing at once. A disposal deletes nothing: like an exhibit's, it is a
// record, and a disposed case takes no further writes.
//
// # The chain
//
// A case's erasures are one chain (case_chain.go), keyed by the case, and every
// reader walks it: each event must be the case's, of a kind this program
// records and in the form it writes, and none may follow the erasure of every
// generation of the case key, after which nothing is left to erase.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// What an erasure destroys.
const (
	erasureKindRecord  = "record"
	erasureKindCaseKey = "case_key"
)

// How much of the case key an erasure destroys.
const (
	erasureScopeAll        = "all"
	erasureScopeGeneration = "generation"
)

var erasureChain = caseChainSpec{label: disclosureNodeErasure, prefix: "erasure"}

// The options record_erase, case_key_erase and erasure_list take.
var (
	recordEraseOptions  = []string{"preview"}
	caseKeyEraseOptions = []string{"generation"}
	erasureListOptions  = []string{"case_uid"}
)

// caseKeyErasingSuffix names the copy of a key file's new contents that the
// erasure of one generation writes beside the file before overwriting it, and
// removes once the overwrite is on the disk.
const caseKeyErasingSuffix = ".erasing"

// What each erasure says it did not reach.
var (
	recordEraseDoesNotErase = []string{
		"any other copy of this record: each carries the same wrapped key in its own header, and opens with the " +
			"case key",
		"a disclosure package holding a copy of the record, which is another copy",
		"a grant already issued: it opens the segments it names in any copy, this one included",
		"the bytes the overwrite replaced, which the storage under this file may still hold",
		"the evidence the record was sealed from",
		"what the ledger records about the record",
	}
	caseKeyEraseDoesNotErase = []string{
		"a copy of the key file kept anywhere else, which still opens every record wrapped under what it holds",
		"a grant already issued: it carries its segments' keys, not the case key",
		"plaintext already read out of a record, or released",
		"the bytes the overwrite replaced, which the storage under the key file may still hold",
		"the records, which stay sealed and signed: record_verify still checks each, and none opens with this key",
	}
)

// ---------------------------------------------------------------------------
// Reading the erasures back
// ---------------------------------------------------------------------------

// caseErasures is a case's erasure chain, and the erasure of every generation
// of its key when there has been one.
type caseErasures struct {
	events []caseChainEvent
	key    *caseChainEvent
}

// erasureRead reads one case's erasure chain. It refuses an event that names
// another case, erases something this program does not erase or names it in a
// form this program does not write, or follows the erasure of every
// generation of the case key.
func erasureRead(g *graphene.Graph, caseUID string) (caseErasures, error) {
	events, err := caseChainRead(g, erasureChain, caseUID)
	if err != nil {
		return caseErasures{}, err
	}
	out := caseErasures{events: events}
	for i, event := range events {
		if out.key != nil {
			return caseErasures{}, fmt.Errorf("erasure event node %d follows the erasure of every generation of "+
				"the case key (erasure %s), after which nothing is left to erase", event.id, out.key.uid)
		}
		if err := erasureCheck(event, caseUID); err != nil {
			return caseErasures{}, err
		}
		if event.get("erasure.kind") == erasureKindCaseKey && event.get("erasure.scope") == erasureScopeAll {
			out.key = &events[i]
		}
	}
	return out, nil
}

// erasureCheck refuses an event this program would not have written.
func erasureCheck(event caseChainEvent, caseUID string) error {
	if event.get("erasure.case_uid") != caseUID {
		return fmt.Errorf("erasure event node %d names case %s, in the chain of case %s", event.id,
			event.get("erasure.case_uid"), caseUID)
	}
	switch kind := event.get("erasure.kind"); kind {
	case erasureKindRecord:
		if raw, err := hex.DecodeString(event.get("erasure.record_uid")); err != nil || len(raw) != security.RecordUIDSize {
			return fmt.Errorf("erasure event node %d erases record %q, which is not a record's uid", event.id,
				event.get("erasure.record_uid"))
		}
	case erasureKindCaseKey:
		scope := event.get("erasure.scope")
		if scope != erasureScopeAll && scope != erasureScopeGeneration {
			return fmt.Errorf("erasure event node %d erases %q of the case key, which is neither every generation "+
				"nor one", event.id, scope)
		}
		if generations, err := erasureGenerations(event.get("erasure.generations")); err != nil ||
			(scope == erasureScopeGeneration && len(generations) != 1) {
			return fmt.Errorf("erasure event node %d erases %s of the case key and names generations %q", event.id,
				erasureScopeText(scope), event.get("erasure.generations"))
		}
	default:
		return fmt.Errorf("erasure event node %d records the erasure of a %q, which this program does not erase",
			event.id, kind)
	}
	return nil
}

func erasureScopeText(scope string) string {
	if scope == erasureScopeAll {
		return "every generation"
	}
	return "one generation"
}

// erasureGenerations reads the generations an erasure of the case key names,
// written as erasureGenerationsText writes them.
func erasureGenerations(text string) ([]uint32, error) {
	if text == "" {
		return nil, errors.New("an erasure of the case key names at least one generation")
	}
	var out []uint32
	for _, part := range strings.Split(text, ",") {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("%q is not a generation", part)
		}
		out = append(out, uint32(n))
	}
	return out, nil
}

func erasureGenerationsText(numbers []uint32) string {
	parts := make([]string, 0, len(numbers))
	for _, n := range numbers {
		parts = append(parts, strconv.FormatUint(uint64(n), 10))
	}
	return strings.Join(parts, ",")
}

// erasureReadAll reads the erasures of every case in the ledger that has any,
// ordered by case, or of one case when caseUID is given.
func erasureReadAll(g *graphene.Graph, caseUID string) ([]caseErasures, error) {
	var chains []string
	if caseUID != "" {
		chains = []string{caseUID}
	} else {
		nodes, err := disclosureAll(g, disclosureNodeErasure)
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, node := range nodes {
			seen[node.get("erasure.chain")] = true
		}
		chains = slices.Sorted(maps.Keys(seen))
	}
	var out []caseErasures
	for _, chain := range chains {
		erasures, err := erasureRead(g, chain)
		if err != nil {
			return nil, err
		}
		if len(erasures.events) > 0 {
			out = append(out, erasures)
		}
	}
	return out, nil
}

// erasedKeyRefusal is the refusal of an erasure in a case the ledger records
// every generation of the key of as erased.
func erasedKeyRefusal(caseID string, key caseChainEvent) error {
	return fmt.Errorf("the ledger records every generation of case %s's key erased at %s (erasure %s), after which "+
		"nothing in the case is erased again: a key that still opens something is a copy that erasure did not reach",
		caseID, key.get("erasure.at"), key.uid)
}

// erasureAppend writes one erasure event after the chain's head, with its
// ERASES edge to what it erased and its IN_CASE and PERFORMED_BY edges. It
// does not commit.
func (w *caseWriter) erasureAppend(erasures caseErasures, kind string, erased store.NodeID,
	props map[string]string) (caseChainEvent, error) {
	all := map[string]string{
		"erasure.case_uid":  w.caseUID,
		"erasure.case_id":   w.caseID,
		"erasure.kind":      kind,
		"erasure.by":        w.ledger.actor,
		"erasure.by_role":   w.ledger.role.Name,
		"erasure.at":        w.at.UTC().Format(time.RFC3339Nano),
		"erasure.unix_nano": strconv.FormatInt(w.at.UnixNano(), 10),
	}
	maps.Copy(all, props)
	id, event, err := w.tx.chainAppend(erasureChain, w.caseUID, caseChainHead(erasures.events), all)
	if err != nil {
		return caseChainEvent{}, err
	}
	for _, e := range []caseEdge{{erased, disclosureEdgeErases, nil}, {w.caseN, disclosureEdgeInCase, nil},
		{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger)}} {
		if err := w.tx.edge(id, e.dst, e.label, e.props); err != nil {
			return caseChainEvent{}, err
		}
	}
	return event, nil
}

// recordHandlesWhere returns the open record handles whose record keep holds
// to, in handle order.
func recordHandlesWhere(keep func(*recordSession) bool) []int64 {
	var out []int64
	recordHandles.Range(func(key, value any) bool {
		handle, ok := key.(int64)
		if session, isRecord := value.(*recordSession); ok && isRecord && keep(session) {
			out = append(out, handle)
		}
		return true
	})
	slices.Sort(out)
	return out
}

// ---------------------------------------------------------------------------
// record_erase
// ---------------------------------------------------------------------------

// recordEraseTarget is the record file an erasure acts on, as it was read
// before anything was written. Its record's file is closed.
type recordEraseTarget struct {
	path   string
	record *recordSession
	uid    string
	// erasedRaw is the header as the erasure leaves it: the header read, with
	// the wrapped key and its nonce replaced by zeros as wide.
	erasedRaw []byte
	size      int64
}

// recordEraseDigests are the file's digest and its header's, as they are and
// as the erasure leaves them.
type recordEraseDigests struct {
	fileBefore, fileAfter, headerBefore, headerAfter string
}

// RecordErase destroys the record key in one copy of a record:
// record_erase(ledger, path, reason, options?).
func RecordErase(args ...object.Object) object.Object {
	op := BuiltinNameRecordErase
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 4, recordEraseOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", op))
	}
	reason, errObj := caseTextArg(op, args[2], 3, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	preview, errObj := opts.boolean("preview", false)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := disposerRefusal(op, ledger, "an erasure"); errObj != nil {
		return resultAndError(nil, errObj)
	}

	identity, errObj := recordCaseIdentity(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	defer security.SecureZero(identity.caseKey)
	target, errObj := recordEraseLoad(op, path, identity)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := recordEraseOpenHandle(op, target.uid); errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Opened for writing and hashed before any lock is taken: a record can be
	// gigabytes, and nothing else in the case should wait while it is read.
	file, digests, errObj := recordEraseMeasure(op, target)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer func() { _ = closeFile() }()

	custodyStore.Lock()
	defer custodyStore.Unlock()
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	session, errObj := caseLedgerWrite(op, ledger)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	g := ledger.graph
	caseUID := strings.ToLower(session.caseUID)
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := caseLedgerStateRefusal(g, caseUID, caseActErase); err != nil {
		return fail(err)
	}
	if errObj := retentionHoldRefusal(op, session, g); errObj != nil {
		return resultAndError(nil, errObj)
	}
	erasures, err := erasureRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	if erasures.key != nil {
		return fail(erasedKeyRefusal(session.ID, *erasures.key))
	}
	if err := recordEraseKnown(g, target, digests); err != nil {
		return fail(err)
	}
	// Asked again with the locks held and the file about to be written: the
	// header is still the one that was hashed, and no handle has opened the
	// record since it was last asked.
	if errObj := recordEraseUnchanged(op, file, target); errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := recordEraseOpenHandle(op, target.uid); errObj != nil {
		return resultAndError(nil, errObj)
	}
	now := custodyNow()
	if preview {
		return recordEraseResult(session, ledger, target, digests, caseChainEvent{}, reason, true, now)
	}

	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	labels := make(map[string]string, len(session.classes))
	for _, class := range session.classes {
		labels[strings.ToLower(class.Tag)] = class.Label
	}
	split := viewPartition(target.record, nil)
	tallies := make([]disclosureClassTally, 0, len(split.order))
	for _, tag := range split.order {
		tallies = append(tallies, disclosureClassTally{tag: tag, segments: split.tallies[tag].segments,
			bytes: split.tallies[tag].bytes})
	}
	recordN, err := w.tx.recordNode(g, disclosureRecordFacts{record: target.record, sha256: digests.fileBefore,
		bytes: target.size, headerSHA256: digests.headerBefore, classes: tallies}, w.caseN, w.tx.classNodes(g, labels))
	if err != nil {
		return fail(err)
	}
	event, err := w.erasureAppend(erasures, erasureKindRecord, recordN, map[string]string{
		"erasure.record_uid":           target.uid,
		"erasure.generation":           strconv.FormatUint(uint64(target.record.header.WrappedUnderGeneration), 10),
		"erasure.file_sha256_before":   digests.fileBefore,
		"erasure.file_sha256_after":    digests.fileAfter,
		"erasure.header_sha256_before": digests.headerBefore,
		"erasure.header_sha256_after":  digests.headerAfter,
		"erasure.bytes":                strconv.FormatInt(target.size, 10),
		"erasure.reason":               reason,
	})
	if err != nil {
		return fail(err)
	}

	if err := recordEraseWrite(file, target); err != nil {
		return fail(fmt.Errorf("overwriting the key in %s: %w. What was written of it is on the disk, the ledger "+
			"records nothing, and record_verify says whether the key is still there", path, err))
	}
	if err := closeFile(); err != nil {
		return fail(fmt.Errorf("closing %s after its key was overwritten: %w. The ledger records nothing", path, err))
	}
	if err := recordEraseCheck(op, target, identity); err != nil {
		return fail(fmt.Errorf("the key in %s was overwritten and the file does not read back as erased: %w. The "+
			"ledger records nothing", path, err))
	}
	data := map[string]any{
		"record_uid":         target.uid,
		"path":               path,
		"uid":                event.uid,
		"seq":                int64(event.seq),
		"file_sha256_before": digests.fileBefore,
		"file_sha256_after":  digests.fileAfter,
	}
	if err := w.tx.commit(); err != nil {
		session.appendEvent(now, op, fmt.Sprintf("the key in %s, a copy of record %s, erased; the ledger did not "+
			"record it: %s", path, target.uid, err.Error()), data)
		return fail(fmt.Errorf("the key in %s was erased, and the ledger did not record it: %w. The case's "+
			"timeline records the erasure", path, err))
	}
	session.appendEvent(now, op, fmt.Sprintf("the key in %s, a copy of record %s, erased: %s", path, target.uid,
		reason), data)
	return recordEraseResult(session, ledger, target, digests, event, reason, false, now)
}

// recordEraseLoad reads the record at path with no key, and refuses what an
// erasure cannot act on honestly: a copy already erased, another case's
// record, one wrapped under a generation other than the open one, one whose
// header is not in the form record_seal writes -- so that the bytes the
// erasure overwrites are exactly the wrapped key and its nonce -- and one whose
// key the open case key does not unwrap, which this case's key never sealed.
func recordEraseLoad(op, path string, identity recordIdentity) (*recordEraseTarget, *object.Error) {
	record, errObj := recordLoad(op, path)
	if errObj != nil {
		return nil, errObj
	}
	defer func() { _ = record.file.Close() }()
	header := record.header
	uid := strings.ToLower(header.RecordUID)
	switch {
	case record.erased:
		return nil, newError("%s: the key in %s was erased already, and nothing opens that copy of record %s", op,
			path, uid)
	case !strings.EqualFold(header.CaseUID, identity.caseUID):
		return nil, newError("%s: %s is a record of case %s, and the open case is %s", op, path, header.CaseUID,
			identity.caseUID)
	case header.WrappedUnderGeneration != identity.generation:
		return nil, newError("%s: record %s is wrapped under generation %d of the case key, and the open key is "+
			"generation %d; open the key at generation %d to erase it", op, uid, header.WrappedUnderGeneration,
			identity.generation, header.WrappedUnderGeneration)
	}
	if canonical, err := security.MarshalRecordHeader(header); err != nil || !bytes.Equal(canonical, record.headerRaw) {
		return nil, newError("%s: the header of %s is not in the form record_seal writes it, so which of its bytes "+
			"hold the record key is not something an erasure can be sure of. It was written by something else, or "+
			"edited", op, path)
	}
	recordUID, err := security.RecordUIDFromSlice(mustHexBytes(header.RecordUID))
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	nonce, err := security.XNonceFromSlice(mustHexBytes(header.RecordKeyNonce))
	if err != nil {
		return nil, newError("%s: the record's wrapping nonce is not a nonce: %s", op, err.Error())
	}
	key, err := security.UnwrapRecordKey(identity.caseKey, recordUID, nonce, mustHexBytes(header.RecordKeyWrapped))
	if err != nil {
		return nil, newError("%s: the open case key unwraps no key in %s, so it is not a record this key sealed: %s",
			op, path, err.Error())
	}
	security.SecureZero(key)

	erased := *header
	erased.EraseRecordKey()
	erasedRaw, err := security.MarshalRecordHeader(&erased)
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	if len(erasedRaw) != len(record.headerRaw) {
		return nil, newError("%s: the erased header of %s would be %d bytes and the header is %d; an erasure "+
			"overwrites in place or not at all", op, path, len(erasedRaw), len(record.headerRaw))
	}
	info, err := record.file.Stat()
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	return &recordEraseTarget{path: path, record: record, uid: uid, erasedRaw: erasedRaw, size: info.Size()}, nil
}

// recordEraseOpenHandle refuses while a handle in this process holds the key
// schedule of the record: the erasure destroys the key in a file, and a handle
// keeps what it derived from it.
func recordEraseOpenHandle(op, uid string) *object.Error {
	handles := recordHandlesWhere(func(s *recordSession) bool {
		return s.keys != nil && strings.EqualFold(s.header.RecordUID, uid)
	})
	if len(handles) == 0 {
		return nil
	}
	return newError("%s: record %s is open as handle %d, which holds the key the erasure destroys; "+
		"record_close(%d) first", op, uid, handles[0], handles[0])
}

// recordEraseMeasure opens the record for writing -- so that a file the
// erasure could not write is refused before anything is written -- and hashes
// it as it is and as the erasure will leave it, in one pass.
func recordEraseMeasure(op string, target *recordEraseTarget) (*os.File, recordEraseDigests, *object.Error) {
	file, err := os.OpenFile(target.path, os.O_RDWR, 0)
	if err != nil {
		return nil, recordEraseDigests{}, newError("%s: %s cannot be written, so the key in it cannot be erased: %s",
			op, target.path, err.Error())
	}
	if errObj := recordEraseUnchanged(op, file, target); errObj != nil {
		_ = file.Close()
		return nil, recordEraseDigests{}, errObj
	}
	headerRaw := target.record.headerRaw
	prefix := security.RecordFilePrefix(len(headerRaw))
	before, after := sha256.New(), sha256.New()
	before.Write(prefix)
	before.Write(headerRaw)
	after.Write(prefix)
	after.Write(target.erasedRaw)
	rest := int64(len(prefix) + len(headerRaw))
	if _, err := io.Copy(io.MultiWriter(before, after), io.NewSectionReader(file, rest, target.size-rest)); err != nil {
		_ = file.Close()
		return nil, recordEraseDigests{}, newError("%s: reading %s: %s", op, target.path, err.Error())
	}
	return file, recordEraseDigests{
		fileBefore:   hex.EncodeToString(before.Sum(nil)),
		fileAfter:    hex.EncodeToString(after.Sum(nil)),
		headerBefore: ledgerHash(sha256.Sum256(headerRaw)),
		headerAfter:  ledgerHash(sha256.Sum256(target.erasedRaw)),
	}, nil
}

// recordEraseUnchanged refuses a record whose prefix, header or length is no
// longer what was read: it changed while its erasure was being prepared.
func recordEraseUnchanged(op string, file *os.File, target *recordEraseTarget) *object.Error {
	want := append(security.RecordFilePrefix(len(target.record.headerRaw)), target.record.headerRaw...)
	info, err := file.Stat()
	if err != nil {
		return newError("%s: %s", op, err.Error())
	}
	got := make([]byte, len(want))
	if _, err := file.ReadAt(got, 0); err != nil || info.Size() != target.size || !bytes.Equal(got, want) {
		return newError("%s: %s changed while its erasure was being prepared, and nothing was written", op,
			target.path)
	}
	return nil
}

// recordEraseKnown refuses a file the ledger knows by another digest. A
// Record node under the record's uid names the file a disclosure, a
// redaction or an earlier erasure found, and every copy of a record is that
// file byte for byte.
func recordEraseKnown(g *graphene.Graph, target *recordEraseTarget, digests recordEraseDigests) error {
	node, found, err := disclosureFind(g, disclosureNodeRecord, "record.uid", target.uid)
	if err != nil || !found {
		return err
	}
	if node.get("record.sha256") != digests.fileBefore || node.get("record.header_sha256") != digests.headerBefore {
		return fmt.Errorf("the ledger records record %s as a file with digest %s, and %s has digest %s. It is not "+
			"the record the ledger knows, and its erasure would be recorded as the erasure of a file that was "+
			"never sealed", target.uid, node.get("record.sha256"), target.path, digests.fileBefore)
	}
	return nil
}

// recordEraseWrite writes the erased header over the one in the file and
// forces it to the disk. The header is written whole: it differs from what is
// there only in the wrapped key and its nonce, and one range is one thing to
// get right where two would be two.
func recordEraseWrite(file *os.File, target *recordEraseTarget) error {
	if _, err := file.WriteAt(target.erasedRaw, int64(security.RecordFilePrefixSize)); err != nil {
		return err
	}
	return file.Sync()
}

// recordEraseCheck reads the record back with nothing but the file: its
// header must be the one the erasure wrote, and the open case key must unwrap
// nothing in it.
func recordEraseCheck(op string, target *recordEraseTarget, identity recordIdentity) error {
	record, errObj := recordLoad(op, target.path)
	if errObj != nil {
		return errors.New(strings.TrimPrefix(errObj.Message, op+": "))
	}
	defer func() { _ = record.file.Close() }()
	if !record.erased || !bytes.Equal(record.headerRaw, target.erasedRaw) {
		return errors.New("its header is not the one the erasure wrote")
	}
	recordUID, err := security.RecordUIDFromSlice(mustHexBytes(record.header.RecordUID))
	if err != nil {
		return err
	}
	nonce, err := security.XNonceFromSlice(mustHexBytes(record.header.RecordKeyNonce))
	if err != nil {
		return err
	}
	if key, err := security.UnwrapRecordKey(identity.caseKey, recordUID, nonce,
		mustHexBytes(record.header.RecordKeyWrapped)); err == nil {
		security.SecureZero(key)
		return errors.New("the case key still unwraps a key in it")
	}
	return nil
}

func recordEraseResult(session *custodySession, ledger *ledgerSession, target *recordEraseTarget,
	digests recordEraseDigests, event caseChainEvent, reason string, preview bool, at time.Time) object.Object {
	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":              stringObj(session.ID),
		"uid":                  stringObj(event.uid),
		"seq":                  intObj(int64(event.seq)),
		"kind":                 stringObj(erasureKindRecord),
		"record_uid":           stringObj(target.uid),
		"path":                 stringObj(target.path),
		"generation":           intObj(int64(target.record.header.WrappedUnderGeneration)),
		"reason":               stringObj(reason),
		"preview":              boolObj(preview),
		"erased":               boolObj(!preview),
		"file_sha256_before":   stringObj(digests.fileBefore),
		"file_sha256_after":    stringObj(digests.fileAfter),
		"header_sha256_before": stringObj(digests.headerBefore),
		"header_sha256_after":  stringObj(digests.headerAfter),
		"bytes":                intObj(target.size),
		"by":                   stringObj(ledger.actor),
		"by_role":              stringObj(ledger.role.Name),
		"at":                   stringObj(at.UTC().Format(time.RFC3339Nano)),
		"role_authenticated":   boolObj(false),
		"does_not_erase":       stringArrayObj(recordEraseDoesNotErase),
	}), nil)
}

// ---------------------------------------------------------------------------
// case_key_erase
// ---------------------------------------------------------------------------

// caseKeyRewrite is a key file with one generation erased, sealed again under
// the passphrase and ready to be written over the file it came from.
type caseKeyRewrite struct {
	file       *security.CaseKeyFile
	before     []security.CaseKeyGeneration
	document   []byte
	wrapKey    []byte
	generation uint32
}

func (r *caseKeyRewrite) zero() {
	if r != nil {
		security.SecureZero(r.wrapKey)
	}
}

// CaseKeyErase destroys the case key -- every generation, or one:
// case_key_erase(ledger, key_path, reason, options?).
func CaseKeyErase(args ...object.Object) object.Object {
	op := BuiltinNameCaseKeyErase
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 4, caseKeyEraseOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(path) == "" {
		return resultAndError(nil, newError("%s: the path must not be empty", op))
	}
	reason, errObj := caseTextArg(op, args[2], 3, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Zero is "every generation" here, where case_key_open reads it as "the
	// current one": this erasure takes one generation only when it is named.
	generation, errObj := caseKeyGenerationOption(op, opts)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := disposerRefusal(op, ledger, "an erasure"); errObj != nil {
		return resultAndError(nil, errObj)
	}
	file, errObj := readKeyFile(op, path)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	custodyStore.RLock()
	session, errObj := openSessionLocked(op)
	if errObj == nil {
		errObj = caseKeyEraseOfCase(op, path, file, session)
	}
	custodyStore.RUnlock()
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Taken before the erasure of one generation rewrites the file in memory:
	// the ledger names the version of the file that held what was erased.
	macBefore := file.FileMAC
	// One generation is erased in a file that stays, whose MAC the passphrase
	// recomputes, and the passphrase is asked for before any lock is held.
	var rewrite *caseKeyRewrite
	if generation != 0 {
		if rewrite, errObj = caseKeyErasePrepare(op, path, file, generation); errObj != nil {
			return resultAndError(nil, errObj)
		}
		defer rewrite.zero()
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	session, errObj = caseLedgerWrite(op, ledger)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := caseKeyEraseOfCase(op, path, file, session); errObj != nil {
		return resultAndError(nil, errObj)
	}
	// Asked again with the locks held: the key file is still the version that
	// was read, which is the one the erasure acts on and records.
	if errObj := caseKeyEraseUnchanged(op, path, macBefore); errObj != nil {
		return resultAndError(nil, errObj)
	}
	g := ledger.graph
	caseUID := strings.ToLower(session.caseUID)
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := caseLedgerStateRefusal(g, caseUID, caseActErase); err != nil {
		return fail(err)
	}
	if errObj := retentionHoldRefusal(op, session, g); errObj != nil {
		return resultAndError(nil, errObj)
	}
	erasures, err := erasureRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	if erasures.key != nil {
		return fail(erasedKeyRefusal(session.ID, *erasures.key))
	}
	handles := recordHandlesWhere(func(s *recordSession) bool {
		return s.keys != nil && strings.EqualFold(s.header.CaseUID, caseUID) &&
			(generation == 0 || s.header.WrappedUnderGeneration == generation)
	})
	if len(handles) > 0 {
		return resultAndError(nil, newError("%s: a record wrapped under the key being erased is open as handle %d, "+
			"which holds the key the case key unwrapped for it; record_close(%d) first", op, handles[0], handles[0]))
	}

	scope, erased := erasureScopeAll, file.Generations
	if generation != 0 {
		one, _ := file.Generation(generation)
		scope, erased = erasureScopeGeneration, []security.CaseKeyGeneration{one}
	}
	numbers := make([]uint32, 0, len(erased))
	fingerprints := make([]string, 0, len(erased))
	for _, each := range erased {
		numbers = append(numbers, each.Generation)
		fingerprints = append(fingerprints, each.Fingerprint)
	}
	props := map[string]string{
		"erasure.scope":        scope,
		"erasure.generations":  erasureGenerationsText(numbers),
		"erasure.fingerprints": strings.Join(fingerprints, ","),
		"erasure.key_file_mac": macBefore,
		"erasure.file_removed": strconv.FormatBool(generation == 0),
		"erasure.reason":       reason,
	}
	current := uint32(0)
	if rewrite != nil {
		props["erasure.key_file_mac_after"] = rewrite.file.FileMAC
		current = rewrite.file.Current
	}
	now := custodyNow()
	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.erasureAppend(erasures, erasureKindCaseKey, w.caseN, props)
	if err != nil {
		return fail(err)
	}

	if rewrite == nil {
		if err := caseKeyFileDestroy(path); err != nil {
			return fail(fmt.Errorf("destroying %s: %w. The ledger records nothing, and the file may be partly "+
				"overwritten", path, err))
		}
	} else {
		if err := caseKeyFileRewrite(path, rewrite.document); err != nil {
			return fail(fmt.Errorf("rewriting %s without generation %d: %w. The ledger records nothing", path,
				generation, err))
		}
		if err := rewrite.check(op, path); err != nil {
			return fail(fmt.Errorf("%s was rewritten without generation %d and does not read back as that: %w. The "+
				"ledger records nothing", path, generation, err))
		}
	}
	zeroed := session.eraseKeyLocked(generation)
	data := map[string]any{
		"scope":        scope,
		"generations":  erasureGenerationsText(numbers),
		"fingerprints": strings.Join(fingerprints, ","),
		"file_removed": generation == 0,
		"uid":          event.uid,
		"seq":          int64(event.seq),
	}
	what := "every generation of the case key of case " + session.ID + " erased, the key file overwritten and removed"
	if rewrite != nil {
		what = fmt.Sprintf("generation %d of the case key of case %s erased", generation, session.ID)
	}
	if err := w.tx.commit(); err != nil {
		session.appendEvent(now, op, fmt.Sprintf("%s; the ledger did not record it: %s", what, err.Error()), data)
		return fail(fmt.Errorf("%s, and the ledger did not record it: %w. The case's timeline records the erasure",
			what, err))
	}
	session.appendEvent(now, op, fmt.Sprintf("%s: %s", what, reason), data)

	generations := make([]object.Object, 0, len(numbers))
	for _, n := range numbers {
		generations = append(generations, intObj(int64(n)))
	}
	// fingerprints is in the order of generations, each naming the one beside
	// it, so it is not built with stringArrayObj, which sorts.
	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"uid":                stringObj(event.uid),
		"seq":                intObj(int64(event.seq)),
		"kind":               stringObj(erasureKindCaseKey),
		"scope":              stringObj(scope),
		"generations":        &object.Array{Elements: generations},
		"fingerprints":       stringArrayLiteral(fingerprints),
		"path":               stringObj(path),
		"file_removed":       boolObj(generation == 0),
		"current":            intObj(int64(current)),
		"session_key_zeroed": boolObj(zeroed),
		"reason":             stringObj(reason),
		"by":                 stringObj(ledger.actor),
		"by_role":            stringObj(ledger.role.Name),
		"at":                 stringObj(now.UTC().Format(time.RFC3339Nano)),
		"role_authenticated": boolObj(false),
		"does_not_erase":     stringArrayObj(caseKeyEraseDoesNotErase),
	}), nil)
}

// caseKeyEraseOfCase refuses a key file that is not the open case's. Asked
// before a passphrase is asked for, and again with the locks held.
func caseKeyEraseOfCase(op, path string, file *security.CaseKeyFile, session *custodySession) *object.Error {
	if !strings.EqualFold(file.CaseUID, session.caseUID) || file.CaseID != session.ID {
		return newError("%s: %s is the key file of case %s (uid %s), and the open case is %s (uid %s); a case's "+
			"erasure is recorded in its own ledger", op, path, file.CaseID, file.CaseUID, session.ID, session.caseUID)
	}
	return nil
}

// caseKeyEraseUnchanged refuses a key file that is no longer the version that
// was read -- something rotated or rewrote it while its erasure was being
// prepared -- because what the erasure records is of the file as it was read.
func caseKeyEraseUnchanged(op, path, macBefore string) *object.Error {
	file, errObj := readKeyFile(op, path)
	if errObj != nil {
		return errObj
	}
	if file.FileMAC != macBefore {
		return newError("%s: %s changed while its erasure was being prepared, and nothing was written", op, path)
	}
	return nil
}

// caseKeyErasePrepare reads the passphrase and builds the key file with one
// generation erased, refusing the generation the file seals under now, one
// already erased, and a file an interrupted erasure left a copy beside.
func caseKeyErasePrepare(op, path string, file *security.CaseKeyFile, generation uint32) (*caseKeyRewrite,
	*object.Error) {
	g, err := file.Generation(generation)
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	switch {
	case g.Erased():
		return nil, newError("%s: generation %d of %s was erased already", op, generation, path)
	case generation == file.Current:
		return nil, newError("%s: generation %d is the one %s seals under now, and it is erased with every other "+
			"generation or not at all. case_key_rotate(path, {\"mode\": \"case_key\"}) makes a new one current; "+
			"leaving generation out erases every one", op, generation, path)
	}
	if _, err := os.Stat(path + caseKeyErasingSuffix); err == nil {
		return nil, newError("%s: an erasure of %s was interrupted and left %s, which holds what the key file was "+
			"becoming. Compare the two, keep the one that opens, and remove the copy before erasing again", op, path,
			path+caseKeyErasingSuffix)
	}
	request := security.PassphraseRequest{Purpose: op, Path: path, Confirm: false}
	passphrase, err := security.RequestPassphrase(request)
	if err != nil {
		return nil, passphraseError(op, err)
	}
	defer security.SecureZero(passphrase)
	caseKey, wrapKey, err := security.OpenCaseKeyFile(file, passphrase, file.Current)
	if err != nil {
		security.ForgetPassphrase(request)
		return nil, newError("%s: %s", op, err.Error())
	}
	security.SecureZero(caseKey)
	rewrite := &caseKeyRewrite{file: file, before: slices.Clone(file.Generations), wrapKey: wrapKey,
		generation: generation}
	if err := file.EraseGeneration(generation); err != nil {
		rewrite.zero()
		return nil, newError("%s: %s", op, err.Error())
	}
	// Signed again when it was signed before, so an erasure does not quietly
	// take a signature off a file.
	if _, _, err := security.SealCaseKeyFile(file, wrapKey, strings.TrimSpace(file.Signer) != ""); err != nil {
		rewrite.zero()
		return nil, newError("%s: %s", op, err.Error())
	}
	if rewrite.document, err = security.MarshalCaseKeyFile(file); err != nil {
		rewrite.zero()
		return nil, newError("%s: %s", op, err.Error())
	}
	return rewrite, nil
}

// check reads the rewritten key file back: the erased generation must hold
// the zeros, every other generation what it held before, and the file's MAC
// must hold under the passphrase.
func (r *caseKeyRewrite) check(op, path string) error {
	file, errObj := readKeyFile(op, path)
	if errObj != nil {
		return errors.New(strings.TrimPrefix(errObj.Message, op+": "))
	}
	if len(file.Generations) != len(r.before) {
		return fmt.Errorf("it holds %d generations and held %d", len(file.Generations), len(r.before))
	}
	for i, g := range file.Generations {
		switch {
		case g.Generation == r.generation && !g.Erased():
			return fmt.Errorf("generation %d is not erased in it", g.Generation)
		case g.Generation != r.generation && g != r.before[i]:
			return fmt.Errorf("generation %d changed in it", g.Generation)
		}
	}
	return security.VerifyCaseKeyFile(file, r.wrapKey)
}

// caseKeyFileDestroy overwrites a key file with zeros, forces them to the
// disk, and removes it.
func caseKeyFileDestroy(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		if _, err = file.WriteAt(make([]byte, info.Size()), 0); err == nil {
			err = file.Sync()
		}
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return fmt.Errorf("%s is still there after it was removed", path)
	}
	return nil
}

// caseKeyFileRewrite writes a key file's new contents over the old ones, in
// place, so that the bytes which held the erased generation are overwritten
// rather than left in a file the directory no longer names -- which is what a
// write to a new file and a rename would leave. The new contents are written
// beside the file first, and that copy is removed once the overwrite is on the
// disk: an overwrite interrupted half way leaves a torn key file, and the copy
// is what it was becoming.
func caseKeyFileRewrite(path string, document []byte) error {
	pending := path + caseKeyErasingSuffix
	copied, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = copied.Write(document)
	if err == nil {
		err = copied.Sync()
	}
	if closeErr := copied.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(pending)
		return err
	}
	if err := caseKeyOverwrite(path, document); err != nil {
		return fmt.Errorf("%w; %s holds what the key file was becoming", err, pending)
	}
	return os.Remove(pending)
}

// caseKeyOverwrite writes document over the file at path from its first byte,
// padded with spaces to the old length so that every byte of the old contents
// is overwritten, forces that to the disk, and then cuts the padding off. A key
// file is read as one JSON document, so the padding is never read as anything.
func caseKeyOverwrite(path string, document []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err == nil {
		padded := document
		if old := info.Size(); old > int64(len(document)) {
			padded = append(slices.Clone(document), bytes.Repeat([]byte{' '}, int(old)-len(document))...)
		}
		if _, err = file.WriteAt(padded, 0); err == nil {
			err = file.Sync()
		}
		if err == nil && len(padded) > len(document) {
			if err = file.Truncate(int64(len(document))); err == nil {
				err = file.Sync()
			}
		}
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

// eraseKeyLocked zeroes the case key the session holds when an erasure
// destroyed it -- every generation, or the one it was opened at -- and says
// whether it did. Every generation erased is kept as a fact of the case, as
// keyed is. The caller holds the custody lock.
func (s *custodySession) eraseKeyLocked(generation uint32) bool {
	if generation == 0 {
		s.keyErased = true
	}
	if s.caseKey == nil || (generation != 0 && s.keyGeneration != generation) {
		return false
	}
	security.SecureZero(s.caseKey)
	security.SecureZero(s.classTagKey)
	s.caseKey, s.classTagKey = nil, nil
	return true
}

// ---------------------------------------------------------------------------
// Disposal
// ---------------------------------------------------------------------------

// caseDisposalRefusal refuses the disposal of a retained case until the
// ledger shows everything a disposal needs, naming all of what it does not
// show, and returns the erasure of the case key the disposal rests on. The
// caller holds disclosureLedgerMu.
func caseDisposalRefusal(g *graphene.Graph, caseUID, caseID string, now time.Time) (string, error) {
	caseUID = strings.ToLower(caseUID)
	var missing []string
	retention, err := retentionRead(g, caseUID)
	if err != nil {
		return "", err
	}
	if n := len(retention.holds); n > 0 {
		first, holds := retention.holds[0], "a legal hold is"
		if n > 1 {
			holds = fmt.Sprintf("%d legal holds are", n)
		}
		missing = append(missing, fmt.Sprintf("%s in force -- the first placed at %s by %s: %q -- and "+
			"retention_release(ledger, %q, reason) lifts one", holds, first.get("retention.at"),
			first.get("retention.by"), first.get("retention.reason"), first.uid))
	}
	switch {
	case retention.period == nil:
		missing = append(missing, "no retention period is recorded for it")
	case !retention.lapsed(now):
		missing = append(missing, fmt.Sprintf("it is kept until %s, which has not come",
			retention.period.get("retention.until")))
	}
	exhibits, err := evidenceReadAll(g, caseUID)
	if err != nil {
		return "", err
	}
	var kept []evidenceItem
	for _, item := range exhibits {
		if state := item.state(); state != evidenceReturned && state != evidenceDisposed {
			kept = append(kept, item)
		}
	}
	switch len(kept) {
	case 0:
	case 1:
		missing = append(missing, fmt.Sprintf("exhibit %q is %s", kept[0].exhibit(), evidenceWhere(kept[0])))
	default:
		missing = append(missing, fmt.Sprintf("%d exhibits are neither returned nor disposed of -- the first, %q, "+
			"is %s -- and evidence_history lists them", len(kept), kept[0].exhibit(), evidenceWhere(kept[0])))
	}
	erasures, err := erasureRead(g, caseUID)
	if err != nil {
		return "", err
	}
	if erasures.key == nil {
		missing = append(missing, "its case key is not erased: case_key_erase(ledger, key_path, reason) erases "+
			"every generation of it, and a case is disposed of after its key")
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("case %s cannot be disposed of yet: %s", caseID, strings.Join(missing, "; "))
	}
	return erasures.key.uid, nil
}

// ---------------------------------------------------------------------------
// erasure_list
// ---------------------------------------------------------------------------

// ErasureList reads the erasures a ledger records, in every case or in one:
// erasure_list(ledger, options?). It needs no case open, so an auditor reads
// it with the ledger alone.
func ErasureList(args ...object.Object) object.Object {
	op := BuiltinNameErasureList
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 2, erasureListOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	caseUID, errObj := opts.str("case_uid", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	cases, err := erasureReadAll(ledger.graph, strings.ToLower(strings.TrimSpace(caseUID)))
	disclosureLedgerMu.Unlock()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	var rows []object.Object
	records, keys := 0, 0
	for _, erasures := range cases {
		for _, event := range erasures.events {
			if event.get("erasure.kind") == erasureKindRecord {
				records++
			} else {
				keys++
			}
			rows = append(rows, erasureRow(event))
		}
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"erasures":  &object.Array{Elements: rows},
		"count":     intObj(int64(len(rows))),
		"records":   intObj(int64(records)),
		"case_keys": intObj(int64(keys)),
		"source":    stringObj("ledger"),
	}), nil)
}

// erasureRow is one erasure as erasure_list reports it. A field an erasure of
// the other kind records is "", 0 or empty.
func erasureRow(event caseChainEvent) object.Object {
	generations := []object.Object{}
	if numbers, err := erasureGenerations(event.get("erasure.generations")); err == nil {
		for _, n := range numbers {
			generations = append(generations, intObj(int64(n)))
		}
	}
	fingerprints := []string{}
	if text := event.get("erasure.fingerprints"); text != "" {
		fingerprints = strings.Split(text, ",")
	}
	generation, _ := strconv.ParseInt(event.get("erasure.generation"), 10, 64)
	size, _ := strconv.ParseInt(event.get("erasure.bytes"), 10, 64)
	return makeHashObject(map[string]object.Object{
		"seq":                  intObj(int64(event.seq)),
		"uid":                  stringObj(event.uid),
		"case_uid":             stringObj(event.get("erasure.case_uid")),
		"case_id":              stringObj(event.get("erasure.case_id")),
		"kind":                 stringObj(event.get("erasure.kind")),
		"record_uid":           stringObj(event.get("erasure.record_uid")),
		"generation":           intObj(generation),
		"file_sha256_before":   stringObj(event.get("erasure.file_sha256_before")),
		"file_sha256_after":    stringObj(event.get("erasure.file_sha256_after")),
		"header_sha256_before": stringObj(event.get("erasure.header_sha256_before")),
		"header_sha256_after":  stringObj(event.get("erasure.header_sha256_after")),
		"bytes":                intObj(size),
		"scope":                stringObj(event.get("erasure.scope")),
		"generations":          &object.Array{Elements: generations},
		"fingerprints":         stringArrayLiteral(fingerprints),
		"key_file_mac":         stringObj(event.get("erasure.key_file_mac")),
		"key_file_mac_after":   stringObj(event.get("erasure.key_file_mac_after")),
		"file_removed":         boolObj(event.get("erasure.file_removed") == "true"),
		"reason":               stringObj(event.get("erasure.reason")),
		"by":                   stringObj(event.get("erasure.by")),
		"by_role":              stringObj(event.get("erasure.by_role")),
		"at":                   stringObj(event.get("erasure.at")),
	})
}
