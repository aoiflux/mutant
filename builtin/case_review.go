package builtin

// Reviews: an examiner asks for a second pair of eyes on the case, on one of
// its records or on one of its redactions, and a reviewer answers. Both are
// recorded in the case's ledger, and the answer is bound to what was asked
// about.
//
// # What a request binds
//
// review_request names its subject -- "case", a record's uid or a redaction
// version's uid -- and binds it by a hash anybody holding a copy can check
// theirs against: a record by the SHA-256 of the record file the ledger
// holds, a redaction version by the digest of what it releases
// (redaction.partition), and the case by a manifest written with case_write
// and named by path. The manifest has to be this case's, still hash to its
// seal, carry a signature that holds if it carries one, and have been written
// with the case's lifecycle where it is now. The manifest a run renders in
// memory would not do: an open case's manifest carries the time since the case
// was opened and the security counters, so its hash is different every time
// it is looked at, and a review bound to it would be bound to nothing anybody
// could produce again.
//
// # What a review moves
//
// review_request moves an active case to in_review, where the lifecycle
// refuses what would change what the reviewer was shown (case_lifecycle.go),
// and review_decide moves it on: approved to concluded, changes_requested or
// rejected back to active. A review of a record or of a redaction version
// moves nothing: it is a record of the question and the answer, and
// review_list reports both. One request is open at a time for one subject, so
// a question asked twice is answered once.
//
// # The one refusal a role makes here
//
// A review is decided by an examiner acting as reviewer who is not the one who
// asked for it. Roles are asserted, not authenticated (role.go), so this keeps
// the record consistent with what it says -- that somebody else looked -- and
// is not access control; the refusal says so. Anybody assigned in the case may
// ask for a review.
//
// # The chains
//
// A case's requests are one chain (case_chain.go), keyed by the case. Each
// request's decision is a chain of its own, keyed by the request, that holds
// one event: a request is decided once, a second decision is refused by the
// writer and by every reader, and a new request asks again.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// What a review is of.
const (
	reviewSubjectCase      = "case"
	reviewSubjectRecord    = "record"
	reviewSubjectRedaction = "redaction_version"
)

var reviewSubjects = []string{reviewSubjectCase, reviewSubjectRecord, reviewSubjectRedaction}

// What a reviewer decides.
const (
	reviewApproved         = "approved"
	reviewChangesRequested = "changes_requested"
	reviewRejected         = "rejected"
)

// reviewDecisions are the words review_decide's decision takes.
var reviewDecisions = []string{reviewApproved, reviewChangesRequested, reviewRejected}

// reviewDecider is the role a decision is recorded under.
const reviewDecider = "reviewer"

var (
	reviewRequestChain  = caseChainSpec{label: disclosureNodeReviewRequest, prefix: "review"}
	reviewDecisionChain = caseChainSpec{label: disclosureNodeReviewDecision, prefix: "decision"}
)

// The options review_request and review_list take.
var (
	reviewRequestOptions = []string{"manifest"}
	reviewListOptions    = []string{"case_uid"}
)

// caseReview is one request as read back, and its decision when it has one.
type caseReview struct {
	request  caseChainEvent
	decision *caseChainEvent
}

func (r caseReview) kind() string    { return r.request.get("review.subject_kind") }
func (r caseReview) subject() string { return r.request.get("review.subject") }

// reviewSubjectText names what a review is of, in words.
func reviewSubjectText(kind, key string) string {
	switch kind {
	case reviewSubjectCase:
		return "the case"
	case reviewSubjectRecord:
		return "record " + key
	}
	return "redaction version " + key
}

// ---------------------------------------------------------------------------
// Reading the reviews back
// ---------------------------------------------------------------------------

// reviewsRead reads one case's requests, first to last, each with its
// decision. It refuses a request that names another case or a subject of a
// kind this program does not review, and a decision that names another case
// or request, records a decision this program does not record, or is one of
// two for one request.
func reviewsRead(g *graphene.Graph, caseUID string) ([]caseReview, error) {
	requests, err := caseChainRead(g, reviewRequestChain, caseUID)
	if err != nil {
		return nil, err
	}
	out := make([]caseReview, 0, len(requests))
	for _, request := range requests {
		kind := request.get("review.subject_kind")
		switch {
		case request.get("review.case_uid") != caseUID:
			return nil, fmt.Errorf("review request node %d names case %s, in the chain of case %s", request.id,
				request.get("review.case_uid"), caseUID)
		case !slices.Contains(reviewSubjects, kind):
			return nil, fmt.Errorf("review request node %d asks for a review of a %q, which this program does not "+
				"review", request.id, kind)
		case kind == reviewSubjectCase && request.get("review.subject") != caseUID:
			return nil, fmt.Errorf("review request node %d asks for a review of case %s, in the chain of case %s",
				request.id, request.get("review.subject"), caseUID)
		}
		decisions, err := caseChainRead(g, reviewDecisionChain, request.uid)
		if err != nil {
			return nil, err
		}
		review := caseReview{request: request}
		switch len(decisions) {
		case 0:
		case 1:
			decision := decisions[0]
			switch {
			case decision.get("decision.request_uid") != request.uid || decision.get("decision.case_uid") != caseUID:
				return nil, fmt.Errorf("decision node %d answers request %s of case %s, in the chain of request %s "+
					"of case %s", decision.id, decision.get("decision.request_uid"), decision.get("decision.case_uid"),
					request.uid, caseUID)
			case !slices.Contains(reviewDecisions, decision.get("decision.decision")):
				return nil, fmt.Errorf("decision node %d records %q, which is not a decision this program records",
					decision.id, decision.get("decision.decision"))
			}
			review.decision = &decision
		default:
			return nil, fmt.Errorf("review request %s of case %s is decided %d times (decision nodes %d and %d). A "+
				"request is decided once, and a new request asks again", request.uid, caseUID, len(decisions),
				decisions[0].id, decisions[1].id)
		}
		out = append(out, review)
	}
	return out, nil
}

// reviewsReadAll reads the requests of every case in the ledger, ordered by
// case, or of one case when caseUID is given.
func reviewsReadAll(g *graphene.Graph, caseUID string) ([]caseReview, error) {
	if caseUID != "" {
		return reviewsRead(g, caseUID)
	}
	nodes, err := disclosureAll(g, disclosureNodeReviewRequest)
	if err != nil {
		return nil, err
	}
	chains := map[string]bool{}
	for _, node := range nodes {
		chains[node.get("review.chain")] = true
	}
	var out []caseReview
	for _, chain := range slices.Sorted(maps.Keys(chains)) {
		reviews, err := reviewsRead(g, chain)
		if err != nil {
			return nil, err
		}
		out = append(out, reviews...)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// What a request binds
// ---------------------------------------------------------------------------

// reviewSubjectArg reads what a review is of: "case", or a record's or a
// redaction version's uid, which are told apart by their length.
func reviewSubjectArg(op string, arg object.Object) (string, string, *object.Error) {
	given, errObj := requireStringArg(op, arg, 2)
	if errObj != nil {
		return "", "", errObj
	}
	word := choiceFold(given)
	if word == reviewSubjectCase {
		return reviewSubjectCase, "", nil
	}
	if _, err := hex.DecodeString(word); err == nil {
		switch len(word) {
		case 2 * security.RecordUIDSize:
			return reviewSubjectRecord, word, nil
		case 2 * sha256.Size:
			return reviewSubjectRedaction, word, nil
		}
	}
	return "", "", newError("%s: %q is not something a review is of. A review is of \"case\", a record's uid "+
		"(%d hex digits, from record_open) or a redaction version's uid (%d, from redaction_commit or "+
		"redaction_versions)", op, given, 2*security.RecordUIDSize, 2*sha256.Size)
}

// reviewManifest is the written manifest a request for a review of the case
// binds.
type reviewManifest struct {
	path, hash, caseID, lifecycleHead string
	signed                            bool
}

// reviewManifestRead reads a manifest case_write wrote, and refuses one that
// no longer hashes to its seal or carries a signature that does not hold.
func reviewManifestRead(op, path string) (reviewManifest, *object.Error) {
	document, errObj := custodyManifestDocument(op, path)
	if errObj != nil {
		return reviewManifest{}, errObj
	}
	verified := custodyVerifyDocument(document)
	if text, failed := verified["error"].(string); failed {
		return reviewManifest{}, newError("%s: %s", op, text)
	}
	matches, _ := verified["hash_matches"].(bool)
	signed, _ := verified["signed"].(bool)
	valid, _ := verified["signature_valid"].(bool)
	switch {
	case !matches:
		return reviewManifest{}, newError("%s: manifest %s does not hash to its seal: it was changed after case_write "+
			"wrote it, and a review is bound to what was written", op, path)
	case signed && !valid:
		return reviewManifest{}, newError("%s: manifest %s is signed, and its signature does not hold: %s", op, path,
			stringField(verified, "signature_detail"))
	}
	m := reviewManifest{path: path, hash: stringField(verified, "manifest_hash"), signed: signed}
	if caseInfo, ok := document["case"].(map[string]any); ok {
		m.caseID = stringField(caseInfo, "id")
	}
	if state, ok := document["ledger_state"].(map[string]any); ok {
		m.lifecycleHead = stringField(state, "lifecycle_head")
	}
	return m, nil
}

// reviewSubject is what a request binds: the node it REVIEWS -- zero for the
// case, whose node the writer holds -- what it names, and the hash it is bound
// by.
type reviewSubject struct {
	node store.NodeID
	key  string
	hash string
}

// reviewSubjectOf finds the subject of a request in the attached case's
// ledger, and refuses one the case does not hold or, for the case itself, a
// manifest that is not of the case as it stands. The caller holds
// disclosureLedgerMu.
func reviewSubjectOf(op string, session *custodySession, g *graphene.Graph, kind, uid string,
	manifest reviewManifest, lifecycle []caseChainEvent) (reviewSubject, *object.Error) {
	caseUID := strings.ToLower(session.caseUID)
	fail := func(err error) (reviewSubject, *object.Error) {
		return reviewSubject{}, newError("%s: %s", op, err.Error())
	}
	switch kind {
	case reviewSubjectRecord:
		record, found, err := disclosureFind(g, disclosureNodeRecord, "record.uid", uid)
		switch {
		case err != nil:
			return fail(err)
		case !found:
			return reviewSubject{}, newError("%s: the ledger holds no record %s. A record enters it with its first "+
				"disclosure, reclassification or redaction_commit", op, uid)
		case record.get("record.case_uid") != caseUID:
			return reviewSubject{}, newError("%s: record %s is case %s's, and the case attached is %s (%s)", op, uid,
				record.get("record.case_uid"), session.ID, caseUID)
		}
		return reviewSubject{node: record.id, key: uid, hash: record.get("record.sha256")}, nil
	case reviewSubjectRedaction:
		version, found, err := disclosureFind(g, disclosureNodeRedactionVersion, "redaction.uid", uid)
		switch {
		case err != nil:
			return fail(err)
		case !found:
			return reviewSubject{}, newError("%s: the ledger holds no redaction version %s; redaction_commit records "+
				"one, and redaction_versions lists them", op, uid)
		case version.get("redaction.case_uid") != caseUID:
			return reviewSubject{}, newError("%s: redaction version %s is case %s's, and the case attached is %s (%s)",
				op, uid, version.get("redaction.case_uid"), session.ID, caseUID)
		}
		// Read through its chain, so a version whose chain does not add up is
		// refused rather than reviewed as if it did.
		chain, err := redactionChainOf(g, caseUID, version.get("redaction.line"),
			version.get("redaction.view_canonical"))
		if err != nil {
			return fail(err)
		}
		if !slices.ContainsFunc(chain, func(e caseChainEvent) bool { return e.uid == uid }) {
			return reviewSubject{}, newError("%s: redaction version %s is not in the chain its line and view name",
				op, uid)
		}
		return reviewSubject{node: version.id, key: uid, hash: version.get("redaction.partition")}, nil
	}
	head := caseChainHead(lifecycle)
	switch {
	case manifest.caseID != session.ID:
		return reviewSubject{}, newError("%s: manifest %s is case %q's, and the case attached is %s", op,
			manifest.path, manifest.caseID, session.ID)
	case manifest.lifecycleHead == "":
		return reviewSubject{}, newError("%s: manifest %s was written by a run in which case %s was attached to no "+
			"ledger, so it does not say where the case's lifecycle stood. Write it again while the case is attached",
			op, manifest.path, session.ID)
	case manifest.lifecycleHead != head.uid:
		return reviewSubject{}, newError("%s: manifest %s was written when case %s's lifecycle stood at %s, and it "+
			"stands at %s (%s) now. Write it again, so the review is of the case as it is", op, manifest.path,
			session.ID, manifest.lifecycleHead, head.uid, head.get("lifecycle.state"))
	}
	return reviewSubject{key: caseUID, hash: manifest.hash}, nil
}

// ---------------------------------------------------------------------------
// review_request
// ---------------------------------------------------------------------------

// ReviewRequest asks for a review of the attached case, of one of its records
// or of one of its redaction versions: review_request(ledger, subject, note,
// options?).
func ReviewRequest(args ...object.Object) object.Object {
	op := BuiltinNameReviewRequest
	if len(args) < 3 || len(args) > 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 4, reviewRequestOptions...)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	kind, uid, errObj := reviewSubjectArg(op, args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	note, errObj := caseTextArg(op, args[2], 3, "note")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	path, errObj := opts.str("manifest", "")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	_, given := opts.pairs["manifest"]
	var manifest reviewManifest
	switch {
	case kind != reviewSubjectCase && given:
		what := strings.ReplaceAll(kind, "_", " ")
		return resultAndError(nil, newError("%s: a manifest is what a case is reviewed as, and a review of a %s is "+
			"bound to the %s itself", op, what, what))
	case kind == reviewSubjectCase && strings.TrimSpace(path) == "":
		return resultAndError(nil, newError("%s: a case is reviewed as a manifest shows it. Write one with "+
			"case_write(path) and name it: {\"manifest\": path}", op))
	case kind == reviewSubjectCase:
		if manifest, errObj = reviewManifestRead(op, path); errObj != nil {
			return resultAndError(nil, errObj)
		}
	}

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
	if err := caseLedgerStateRefusal(g, caseUID, caseActReview); err != nil {
		return fail(err)
	}
	lifecycle, from, err := caseLifecycleRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	if kind == reviewSubjectCase && from != caseStateActive {
		return resultAndError(nil, newError("%s: case %s is %s, and a case is submitted for review when it is "+
			"active", op, session.ID, from))
	}
	subject, errObj := reviewSubjectOf(op, session, g, kind, uid, manifest, lifecycle)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reviews, err := reviewsRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	for _, open := range reviews {
		if open.decision == nil && open.kind() == kind && open.subject() == subject.key {
			return resultAndError(nil, newError("%s: %s asked for a review of %s at %s (request %s), and it has not "+
				"been decided. One request is open at a time for one subject; review_decide answers it", op,
				open.request.get("review.by"), reviewSubjectText(kind, subject.key), open.request.get("review.at"),
				open.request.uid))
		}
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	props := map[string]string{
		"review.case_uid":     caseUID,
		"review.case_id":      session.ID,
		"review.subject_kind": kind,
		"review.subject":      subject.key,
		"review.subject_hash": subject.hash,
		"review.note":         note,
		"review.by":           ledger.actor,
		"review.by_role":      ledger.role.Name,
		"review.at":           now.UTC().Format(time.RFC3339Nano),
		"review.unix_nano":    strconv.FormatInt(now.UnixNano(), 10),
	}
	if kind == reviewSubjectCase {
		props["review.manifest"] = manifest.path
		props["review.manifest_signed"] = strconv.FormatBool(manifest.signed)
		props["review.lifecycle_uid"] = caseChainHead(lifecycle).uid
		subject.node = w.caseN
	}
	var head *caseChainEvent
	if len(reviews) > 0 {
		head = &reviews[len(reviews)-1].request
	}
	id, event, err := w.tx.chainAppend(reviewRequestChain, caseUID, head, props)
	if err != nil {
		return fail(err)
	}
	for _, e := range []caseEdge{
		{w.caseN, disclosureEdgeInCase, nil},
		{subject.node, disclosureEdgeReviews, nil},
		{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(ledger)},
	} {
		if err := w.tx.edge(id, e.dst, e.label, e.props); err != nil {
			return fail(err)
		}
	}
	to := from
	var moved caseChainEvent
	if kind == reviewSubjectCase {
		to = caseStateInReview
		if moved, err = w.lifecycleFor(caseChainHead(lifecycle), from, to, note,
			map[string]string{"lifecycle.review_uid": event.uid}); err != nil {
			return fail(err)
		}
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	if to != from {
		session.attached.state, session.attached.head = to, moved
	}
	session.appendEvent(now, op, fmt.Sprintf("review of %s asked for by %s: %s", reviewSubjectText(kind, subject.key),
		ledger.actor, note), map[string]any{
		"subject_kind": kind, "subject": subject.key, "subject_hash": subject.hash, "seq": int64(event.seq),
		"uid": event.uid, "state": to,
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"uid":                stringObj(event.uid),
		"seq":                intObj(int64(event.seq)),
		"subject_kind":       stringObj(kind),
		"subject":            stringObj(subject.key),
		"subject_hash":       stringObj(subject.hash),
		"note":               stringObj(note),
		"manifest":           stringObj(manifest.path),
		"manifest_signed":    boolObj(manifest.signed),
		"from":               stringObj(from),
		"state":              stringObj(to),
		"moved":              boolObj(to != from),
		"by":                 stringObj(ledger.actor),
		"by_role":            stringObj(ledger.role.Name),
		"at":                 stringObj(props["review.at"]),
		"role_authenticated": boolObj(false),
	}), nil)
}

// ---------------------------------------------------------------------------
// review_decide
// ---------------------------------------------------------------------------

// ReviewDecide records a reviewer's answer to a request for a review, and
// moves a case in review on: review_decide(ledger, request, decision, reason).
func ReviewDecide(args ...object.Object) object.Object {
	op := BuiltinNameReviewDecide
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	requestArg, errObj := requireStringArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	requestUID := choiceFold(requestArg)
	decisionArg, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decision := choiceFold(decisionArg)
	if !slices.Contains(reviewDecisions, decision) {
		return resultAndError(nil, newError("%s: %q is not a decision; a review is %s", op, decisionArg,
			strings.Join(reviewDecisions, ", ")))
	}
	reason, errObj := caseTextArg(op, args[3], 4, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if ledger.role.Name != reviewDecider {
		return resultAndError(nil, newError("%s: %s is acting as %s, and a review is decided by a %s. %s", op,
			ledger.actor, ledger.role.Name, reviewDecider, roleNotAccessControl))
	}

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
	if err := caseLedgerStateRefusal(g, caseUID, caseActReview); err != nil {
		return fail(err)
	}
	reviews, err := reviewsRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	var review *caseReview
	for i := range reviews {
		if reviews[i].request.uid == requestUID {
			review = &reviews[i]
		}
	}
	switch {
	case review == nil:
		return resultAndError(nil, newError("%s: case %s has no review request %s; review_list lists them", op,
			session.ID, requestUID))
	case review.decision != nil:
		d := review.decision
		return resultAndError(nil, newError("%s: request %s was decided at %s by %s: %s, %q. A request is decided "+
			"once, and a new request asks again", op, requestUID, d.get("decision.at"), d.get("decision.by"),
			d.get("decision.decision"), d.get("decision.reason")))
	case review.request.get("review.by") == ledger.actor:
		return resultAndError(nil, newError("%s: %s asked for this review, and a review is decided by a reviewer "+
			"other than whoever asked for it. %s", op, ledger.actor, roleNotAccessControl))
	}
	lifecycle, from, err := caseLifecycleRead(g, caseUID)
	if err != nil {
		return fail(err)
	}
	to := from
	if review.kind() == reviewSubjectCase {
		if from != caseStateInReview || caseChainHead(lifecycle).get("lifecycle.review_uid") != requestUID {
			return resultAndError(nil, newError("%s: case %s is %s, not in review under request %s, and "+
				"review_decide moves only a case its request put in review", op, session.ID, from, requestUID))
		}
		to = caseStateActive
		if decision == reviewApproved {
			to = caseStateConcluded
		}
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	props := map[string]string{
		"decision.request_uid":  requestUID,
		"decision.case_uid":     caseUID,
		"decision.subject_kind": review.kind(),
		"decision.subject":      review.subject(),
		"decision.subject_hash": review.request.get("review.subject_hash"),
		"decision.requested_by": review.request.get("review.by"),
		"decision.decision":     decision,
		"decision.reason":       reason,
		"decision.by":           ledger.actor,
		"decision.by_role":      ledger.role.Name,
		"decision.at":           now.UTC().Format(time.RFC3339Nano),
		"decision.unix_nano":    strconv.FormatInt(now.UnixNano(), 10),
	}
	id, event, err := w.tx.chainAppend(reviewDecisionChain, requestUID, nil, props)
	if err != nil {
		return fail(err)
	}
	for _, e := range []caseEdge{
		{review.request.id, disclosureEdgeReviews, nil},
		{w.caseN, disclosureEdgeInCase, nil},
		{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(ledger)},
	} {
		if err := w.tx.edge(id, e.dst, e.label, e.props); err != nil {
			return fail(err)
		}
	}
	var moved caseChainEvent
	if to != from {
		if moved, err = w.lifecycleFor(caseChainHead(lifecycle), from, to, reason,
			map[string]string{"lifecycle.review_uid": requestUID}); err != nil {
			return fail(err)
		}
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	if to != from {
		session.attached.state, session.attached.head = to, moved
	}
	session.appendEvent(now, op, fmt.Sprintf("review of %s decided by %s: %s, %s",
		reviewSubjectText(review.kind(), review.subject()), ledger.actor, decision, reason), map[string]any{
		"request_uid": requestUID, "decision": decision, "uid": event.uid, "state": to,
	})

	return resultAndError(makeHashObject(map[string]object.Object{
		"case_id":            stringObj(session.ID),
		"request_uid":        stringObj(requestUID),
		"uid":                stringObj(event.uid),
		"decision":           stringObj(decision),
		"reason":             stringObj(reason),
		"subject_kind":       stringObj(review.kind()),
		"subject":            stringObj(review.subject()),
		"subject_hash":       stringObj(props["decision.subject_hash"]),
		"requested_by":       stringObj(props["decision.requested_by"]),
		"from":               stringObj(from),
		"state":              stringObj(to),
		"moved":              boolObj(to != from),
		"by":                 stringObj(ledger.actor),
		"by_role":            stringObj(ledger.role.Name),
		"at":                 stringObj(props["decision.at"]),
		"role_authenticated": boolObj(false),
	}), nil)
}

// ---------------------------------------------------------------------------
// review_list
// ---------------------------------------------------------------------------

// ReviewList reads the review requests in a ledger, each with its decision:
// review_list(ledger, options?). It needs no case open, so an auditor reads it
// with the ledger alone.
func ReviewList(args ...object.Object) object.Object {
	op := BuiltinNameReviewList
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	opts, errObj := secretOptionsArg(op, args, 2, reviewListOptions...)
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
	reviews, err := reviewsReadAll(ledger.graph, strings.ToLower(strings.TrimSpace(caseUID)))
	disclosureLedgerMu.Unlock()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	counts := map[string]int64{}
	rows := make([]object.Object, 0, len(reviews))
	for _, review := range reviews {
		if review.decision == nil {
			counts["pending"]++
		} else {
			counts[review.decision.get("decision.decision")]++
		}
		rows = append(rows, reviewRow(review))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"requests":             &object.Array{Elements: rows},
		"count":                intObj(int64(len(rows))),
		"pending":              intObj(counts["pending"]),
		reviewApproved:         intObj(counts[reviewApproved]),
		reviewChangesRequested: intObj(counts[reviewChangesRequested]),
		reviewRejected:         intObj(counts[reviewRejected]),
		"source":               stringObj("ledger"),
	}), nil)
}

func reviewRow(review caseReview) object.Object {
	r := review.request
	fields := map[string]object.Object{
		"seq":             intObj(int64(r.seq)),
		"uid":             stringObj(r.uid),
		"case_uid":        stringObj(r.get("review.case_uid")),
		"case_id":         stringObj(r.get("review.case_id")),
		"subject_kind":    stringObj(r.get("review.subject_kind")),
		"subject":         stringObj(r.get("review.subject")),
		"subject_hash":    stringObj(r.get("review.subject_hash")),
		"note":            stringObj(r.get("review.note")),
		"manifest":        stringObj(r.get("review.manifest")),
		"manifest_signed": boolObj(r.get("review.manifest_signed") == "true"),
		"by":              stringObj(r.get("review.by")),
		"by_role":         stringObj(r.get("review.by_role")),
		"at":              stringObj(r.get("review.at")),
		"decided":         boolObj(review.decision != nil),
	}
	// An undecided request answers "" to each of these rather than leaving
	// them out: a field that appears only sometimes is one a report template
	// learns to leave out.
	var d caseChainEvent
	if review.decision != nil {
		d = *review.decision
	}
	fields["decision"] = stringObj(d.get("decision.decision"))
	fields["decision_uid"] = stringObj(d.uid)
	fields["decision_reason"] = stringObj(d.get("decision.reason"))
	fields["decided_by"] = stringObj(d.get("decision.by"))
	fields["decided_by_role"] = stringObj(d.get("decision.by_role"))
	fields["decided_at"] = stringObj(d.get("decision.at"))
	return makeHashObject(fields)
}
