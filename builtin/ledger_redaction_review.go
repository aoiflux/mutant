package builtin

// Redactions made before the disclosure schema was out of a redaction's
// reach, and an examiner's review of them (M26-CUS-021).
//
// The redaction builtins remove only what a script wrote: a record of the
// ledger's disclosure schema -- a Withdrawal, a Disclosure, a ReclassEvent --
// is refused (M26-CUS-001). A ledger redacted by a build from before that had
// no such guard, and graphene's redaction record names what it removed by id
// and hash, never by label, so it cannot say afterwards whether a node it
// removed was a withdrawal. Every disclose_* read finds its records by index,
// and a node redacted outright takes its index entries with it: a withdrawal
// removed then lets the record be disclosed again to the recipient it was
// withdrawn from, and nothing in the ledger says so.
//
// # Which redactions are in question
//
// Every one recorded with no role. Roles were first recorded by a build that
// already refused the schema, and every build that records a role gives
// every redaction one -- "unasserted" is a role id of its own, never zero --
// so a record with role id zero was made by a build that may not have refused
// a schema record. Of those, a property redaction of a node or an edge a
// script wrote that is still in the ledger is not in question: its labels are
// there to read. Every other one is. A node or an edge removed outright leaves
// no label behind, and a property redaction of a schema record, or of an
// entity that has since gone, cannot be told from one of a withdrawal.
//
// # What a review is, and is not
//
// ledger_redactions_review records that an examiner has read the redactions
// in question up to a sequence number and answers for them: the next event of
// the ledger's one chain of reviews, bound to the hash of the redaction record
// it names. Until every redaction in question is answered for,
// disclose_to_passphrase issues no grant from the ledger, and each disclose_*
// answer read from it names them in unguarded_redactions.
//
// The review checks nothing. Whether a redaction removed a withdrawal is known
// to whoever made it and to their notes, not to the ledger. What the ledger
// can still do is recorded again before the review: a withdrawal a redaction
// removed, with disclose_withdraw while its disclosure is in the ledger, and a
// reclassification, with disclose_reclassified. A withdrawal whose disclosure
// was removed needs neither: it names the record and the recipient itself,
// and still stops a new grant (disclosureWithdrawnFor).

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// redactionReviewChain is a ledger's chain of reviews. There is one per
// ledger, not per case: a redaction record is the ledger's, and one made
// before the schema was guarded could have removed a record of any case in it.
var redactionReviewChain = caseChainSpec{label: disclosureNodeRedactionReview, prefix: "redaction_review"}

// redactionReviewChainKey names that one chain.
const redactionReviewChainKey = "redactions"

// ledgerRedactionUnguarded reports whether a redaction record is in question:
// recorded with no role, and not a property redaction of a script's node or
// edge still in the ledger.
func ledgerRedactionUnguarded(session *ledgerSession, record disk.RedactionRecord) (bool, error) {
	if record.RoleID != 0 {
		return false, nil
	}
	if record.Scope != disk.ScopeProperties {
		return true, nil
	}
	var notFound *store.ErrNotFound
	if record.EdgeID != 0 {
		edge, err := session.graph.GetEdge(record.EdgeID)
		switch {
		case errors.As(err, &notFound):
			return true, nil
		case err != nil:
			return false, err
		}
		return !ledgerScriptEdgeLabels(edge.Labels), nil
	}
	node, err := session.graph.GetNode(record.NodeID)
	switch {
	case errors.As(err, &notFound):
		return true, nil
	case err != nil:
		return false, err
	}
	return !ledgerScriptNodeLabels(node.Labels), nil
}

// ledgerRedactionReviews is what a ledger says about its redactions in
// question and the reviews of them.
type ledgerRedactionReviews struct {
	records []disk.RedactionRecord
	// unguarded holds the sequence number of every redaction in question.
	unguarded map[uint64]bool
	reviews   []caseChainEvent
	// through is the last sequence number a review answers for, 0 when none
	// does.
	through uint64
	// pending is every redaction in question after through, ascending.
	pending []uint64
	// chainErr says why the reviews cannot be read, and is nil when they can.
	// No review is counted then, so pending is every redaction in question.
	// ledger_redactions reports it and lists the redactions anyway; everything
	// that acts on the reviews refuses.
	chainErr error
}

// ledgerRedactionReviewsRead reads the redaction records, decides which are in
// question, and reads the chain of reviews. A chain that forks, goes
// backwards, or names a redaction record the ledger does not hold as it was
// when the review was made is not counted, and chainErr says why.
func ledgerRedactionReviewsRead(session *ledgerSession) (ledgerRedactionReviews, error) {
	records, err := session.store.Redactions()
	if err != nil {
		return ledgerRedactionReviews{}, err
	}
	out := ledgerRedactionReviews{records: records, unguarded: map[uint64]bool{}}
	bySeq := make(map[uint64]disk.RedactionRecord, len(records))
	for _, record := range records {
		bySeq[record.Seq] = record
		unguarded, err := ledgerRedactionUnguarded(session, record)
		if err != nil {
			return ledgerRedactionReviews{}, err
		}
		if unguarded {
			out.unguarded[record.Seq] = true
		}
	}
	out.reviews, out.through, out.chainErr = ledgerRedactionReviewChain(session, bySeq)
	// In ledger order, which is sequence order.
	for _, record := range records {
		if out.unguarded[record.Seq] && record.Seq > out.through {
			out.pending = append(out.pending, record.Seq)
		}
	}
	return out, nil
}

// ledgerRedactionReviewChain reads the chain of reviews and returns it with
// the last sequence number it answers for, after checking that each review
// reaches further than the one before it and names a redaction record the
// ledger holds, by the hash the record had when it was reviewed. With an
// error it returns no reviews, and so answers for nothing.
func ledgerRedactionReviewChain(session *ledgerSession, bySeq map[uint64]disk.RedactionRecord) ([]caseChainEvent,
	uint64, error) {
	reviews, err := caseChainRead(session.graph, redactionReviewChain, redactionReviewChainKey)
	if err != nil {
		return nil, 0, err
	}
	var reached uint64
	for _, review := range reviews {
		named := review.get("redaction_review.through_seq")
		through, err := strconv.ParseUint(named, 10, 64)
		if err != nil || through <= reached {
			return nil, 0, fmt.Errorf("review %d of this ledger's redactions answers for them through %q, which "+
				"is not after the review before it (%d)", review.seq, named, reached)
		}
		record, held := bySeq[through]
		if want := review.get("redaction_review.through_hash"); !held || ledgerHash(record.Hash) != want {
			return nil, 0, fmt.Errorf("review %d of this ledger's redactions answers for them through redaction "+
				"%d, whose record hashed to %s when it was reviewed, and the ledger holds no such record now: the "+
				"review was not made of the redactions this ledger holds", review.seq, through, want)
		}
		reached = through
	}
	return reviews, reached, nil
}

// trusted returns the reviews, or the reason they cannot be acted on.
func (r ledgerRedactionReviews) trusted() (ledgerRedactionReviews, error) {
	if r.chainErr != nil {
		return ledgerRedactionReviews{}, r.chainErr
	}
	return r, nil
}

func ledgerSeqStrings(seqs []uint64) []string {
	parts := make([]string, 0, len(seqs))
	for _, seq := range seqs {
		parts = append(parts, strconv.FormatUint(seq, 10))
	}
	return parts
}

// ledgerSeqList renders sequence numbers for a message: "3, 5 and 9".
func ledgerSeqList(seqs []uint64) string {
	parts := ledgerSeqStrings(seqs)
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// ledgerSeqArray renders sequence numbers as an ARRAY of INTEGER.
func ledgerSeqArray(seqs []uint64) *object.Array {
	elements := make([]object.Object, 0, len(seqs))
	for _, seq := range seqs {
		elements = append(elements, intObj(int64(seq)))
	}
	return &object.Array{Elements: elements}
}

// ledgerUnguardedRedactions is the unguarded_redactions field of a disclose_*
// answer read from the ledger: the redactions in question that no review
// answers for, each of which could have removed a record the answer is made
// from.
func ledgerUnguardedRedactions(session *ledgerSession) (*object.Array, error) {
	read, err := ledgerRedactionReviewsRead(session)
	if err != nil {
		return nil, err
	}
	reviews, err := read.trusted()
	if err != nil {
		return nil, err
	}
	return ledgerSeqArray(reviews.pending), nil
}

// ledgerUnreviewedRefusal refuses a grant from a ledger holding redactions in
// question that no review answers for.
func ledgerUnreviewedRefusal(session *ledgerSession) error {
	read, err := ledgerRedactionReviewsRead(session)
	if err != nil {
		return err
	}
	reviews, err := read.trusted()
	if err != nil || len(reviews.pending) == 0 {
		return err
	}
	last := reviews.pending[len(reviews.pending)-1]
	return fmt.Errorf("this ledger holds redactions recorded with no role (%s), made by a build that may not "+
		"have refused a redaction of the disclosure schema, and no review answers for them. A redaction record "+
		"does not say what it removed, so one of them could have removed a withdrawal, a disclosure or a "+
		"reclassification this refusal is asked from. Read them with ledger_redactions, record again what they "+
		"removed that can be recorded again, and then record the review with ledger_redactions_review(ledger, "+
		"%d, reason). No grant is issued from this ledger until then", ledgerSeqList(reviews.pending), last)
}

// ---------------------------------------------------------------------------
// ledger_redactions_review
// ---------------------------------------------------------------------------

// LedgerRedactionsReview records that the redactions in question were read and
// are answered for: ledger_redactions_review(ledger, through_seq, reason).
func LedgerRedactionsReview(args ...object.Object) object.Object {
	op := BuiltinNameLedgerRedactionsReview
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	throughArg, errObj := requireIntArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if throughArg < 1 {
		return resultAndError(nil, newError("%s: redaction records are numbered from 1, and %d is not one", op,
			throughArg))
	}
	through := uint64(throughArg)
	reason, errObj := caseTextArg(op, args[2], 3, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := disclosureDeclareNames(ledger); err != nil {
		return fail(err)
	}
	read, err := ledgerRedactionReviewsRead(ledger)
	if err != nil {
		return fail(err)
	}
	reviews, err := read.trusted()
	if err != nil {
		return fail(err)
	}
	var named *disk.RedactionRecord
	for i := range reviews.records {
		if reviews.records[i].Seq == through {
			named = &reviews.records[i]
		}
	}
	switch {
	case named == nil && len(reviews.records) == 0:
		return resultAndError(nil, newError("%s: this ledger records no redactions, so there is nothing to review",
			op))
	case named == nil:
		return resultAndError(nil, newError("%s: this ledger records no redaction %d; its last is %d", op, through,
			reviews.records[len(reviews.records)-1].Seq))
	case through <= reviews.through:
		head := caseChainHead(reviews.reviews)
		return resultAndError(nil, newError("%s: the redactions through %d were answered for by review %d, "+
			"recorded at %s by %s: %q. A review answers for the redactions after the last one reviewed", op,
			reviews.through, head.seq, head.get("redaction_review.at"), head.get("redaction_review.by"),
			head.get("redaction_review.reason")))
	}
	var covered []uint64
	for _, seq := range reviews.pending {
		if seq <= through {
			covered = append(covered, seq)
		}
	}
	if len(covered) == 0 {
		return resultAndError(nil, newError("%s: no redaction after %d up to %d is in question: each was "+
			"recorded under a role, by a build that refused redactions of the disclosure schema, or stripped the "+
			"properties of a node or an edge a script wrote that the ledger still holds. A review of none would "+
			"be a record that something was reviewed", op, reviews.through, through))
	}

	now := custodyNow()
	props := map[string]string{
		"redaction_review.through_seq":  strconv.FormatUint(through, 10),
		"redaction_review.through_hash": ledgerHash(named.Hash),
		"redaction_review.redactions":   strings.Join(ledgerSeqStrings(covered), ","),
		"redaction_review.reason":       reason,
		"redaction_review.by":           ledger.actor,
		"redaction_review.by_role":      ledger.role.Name,
		"redaction_review.at":           now.UTC().Format(time.RFC3339Nano),
		"redaction_review.unix_nano":    strconv.FormatInt(now.UnixNano(), 10),
	}
	tx := disclosureBegin(ledger)
	actorN, err := tx.actorNode(ledger.graph, ledger.actor)
	if err != nil {
		return fail(err)
	}
	id, event, err := tx.chainAppend(redactionReviewChain, redactionReviewChainKey, caseChainHead(reviews.reviews),
		props)
	if err != nil {
		return fail(err)
	}
	if err := tx.edge(id, actorN, disclosureEdgePerformedBy, disclosurePerformedBy(ledger)); err != nil {
		return fail(err)
	}
	if err := tx.commit(); err != nil {
		return fail(fmt.Errorf("the review could not be recorded: %w", err))
	}
	remaining := reviews.pending[len(covered):]

	custodyRecordArtifact(op, fmt.Sprintf("redactions %s of ledger %s reviewed: %s", ledgerSeqList(covered),
		ledger.path, reason), map[string]any{
		"path":        ledger.path,
		"actor":       ledger.actor,
		"through_seq": int64(through),
		"reviewed":    int64(len(covered)),
		"remaining":   int64(len(remaining)),
		"review_uid":  event.uid,
		"reason":      reason,
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"seq":                  intObj(int64(event.seq)),
		"uid":                  stringObj(event.uid),
		"through_seq":          intObj(int64(through)),
		"through_hash":         stringObj(props["redaction_review.through_hash"]),
		"previous_through":     intObj(int64(reviews.through)),
		"reviewed":             ledgerSeqArray(covered),
		"unguarded_redactions": ledgerSeqArray(remaining),
		"reason":               stringObj(reason),
		"by":                   stringObj(ledger.actor),
		"by_role":              stringObj(ledger.role.Name),
		"at":                   stringObj(props["redaction_review.at"]),
		"ledger":               stringObj(ledger.path),
		"role_authenticated":   boolObj(false),
		"does_not_say": stringListObj([]string{
			"what any reviewed redaction removed: a redaction record names what it removed by id and hash, " +
				"never by label, and this review is the examiner's word, not a check",
			"that a withdrawal, a disclosure or a reclassification a reviewed redaction removed has been " +
				"recorded again: that is done with disclose_withdraw and disclose_reclassified, before the review",
		}),
	}), nil)
}
