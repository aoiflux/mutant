package builtin

// The `disclose_*` family: handing part of a record to somebody, and letting
// them check what they were handed.
//
// A disclosure is purely a key grant. The record the recipient receives is
// byte-for-byte the record under custody -- every ciphertext, every boundary --
// and what differs between two recipients is only which segments they were
// given material for. Re-encrypting per recipient would give every copy a
// different digest, and then no document could tie any of them to the original.
//
// # The order, and why it is the order
//
// `disclose_to_passphrase` decides what a view grants from a record, issues the
// grant, seals it under a passphrase typed at the terminal, and writes the
// disclosure into the ledger -- in that order, and the grant is handed back only
// after the ledger commit has succeeded. A disclosure that was granted and not
// recorded is the one outcome this family exists to prevent: the recipient
// would hold the keys and nothing would say so.
//
// `disclose_bundle` then lays the package down the way `case_bundle` does:
// the record, the grant, the ledger proof and the report first; their digests
// into the manifest; the manifest sealed; SHA256SUMS last. The snapshot root
// the proof resolves against is NOT in the package. A recipient checking a
// proof against a root from the same package would be checking it against a
// root its author chose.
//
// `disclose_verify` is the recipient's side, and it is a function of the
// directory and of a root the recipient obtained some other way. The root is a
// required argument that may be null, and null is a finding, never a pass.
//
// # What none of this can promise
//
// That a disclosure can be taken back. Once the recipient holds the ciphertext
// and the material, both halves are theirs; see docs/DISCLOSURE_POLICY.md.
// That the classification was right. That the record is all the evidence
// there is. Every document this family writes says those three things in a
// field, not in a footnote.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/merkle"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// Package members. Fixed names, for the reason case_bundle gives: a handover
// whose file names vary is a handover whose reader has to be told what to
// look at.
const (
	discloseManifestName  = "disclosure.json"
	discloseRecordName    = "record.mrec"
	discloseGrantName     = "grant.json"
	discloseProofName     = "ledger-proof.bin"
	discloseReportName    = "report.md"
	discloseChecksumsName = "SHA256SUMS"

	discloseManifestFormat         = "mutant-disclosure"
	discloseManifestVersion  int64 = 1
	maxDiscloseManifest            = 16 << 20
	maxDiscloseProof               = 1 << 20
	discloseMethodPassphrase       = "passphrase"

	// graphenePropertyHashTag is graphene's §11.2 domain byte: a v3 node leaf
	// commits to SHA256(0x07 || properties). A recipient checking that the
	// proven node is THIS disclosure recomputes that hash from the manifest.
	// TestTheLedgerProofCommitsToTheManifestsRecord pins it against a real
	// proof, so a graphene that changed it would fail the build rather than
	// every recipient's verification.
	graphenePropertyHashTag = 0x07
	// grapheneNodeLeafV2 is the tag of a node leaf that carries a property
	// hash rather than the properties themselves.
	grapheneNodeLeafV2 = 0x05
)

// discloseDoesNotCover is said in every manifest, every report and every
// verification. Three sentences, and each one is a claim a reader would
// otherwise be entitled to infer.
var discloseDoesNotCover = []string{
	"that the classification applied to any byte was the correct one: a grant carries out a decision, it does not make one",
	"that this record is all the evidence there is",
	"that the disclosure can be taken back: once the recipient holds the record and the grant, both are theirs, and a later withdrawal stops further grants without reaching this copy",
}

// discloseSignatureNote goes beside every signature this family reports.
const discloseSignatureNote = "the signature authenticates the document, not the names in it: examiner and recipient are asserted and recorded, and nothing here verified either"

// caseDisclosure is one disclosure issued in this case, as the session holds
// it until it is bundled.
//
// The sealed grant is kept here and nowhere else. It is ciphertext -- the
// material inside it is sealed under a passphrase this process no longer
// holds -- but it is still a copy of key material, so it is never written into
// the ledger, and it does not outlive the process. A disclosure issued in one
// run is bundled in that run.
type caseDisclosure struct {
	UID       string
	Issued    time.Time
	Recipient string
	View      caseView
	Labels    map[string]string // tag -> label, for every tag the record carries

	RecordUID    string
	RecordPath   string
	RecordSHA256 string
	RecordBytes  int64
	// Total is the record's segment count: granted and withheld together.
	Total int64

	Grant       []byte
	GrantSHA256 string
	Runs        [][2]uint64

	Split  viewSplit
	Header *security.RecordHeader
	Footer *security.RecordFooter
	Signed bool

	LedgerPath   string
	LedgerNode   int64
	LedgerProps  map[string]string
	Actor        string
	ActorID      uint64
	LedgerKeyNew bool

	Bundles []string
	// Withdrawn is when disclose_withdraw recorded a withdrawal, or "".
	Withdrawn string
}

// render is the disclosure's row in the case manifest.
func (d *caseDisclosure) render() map[string]any {
	bundles := make([]any, 0, len(d.Bundles))
	for _, dir := range d.Bundles {
		bundles = append(bundles, dir)
	}
	return map[string]any{
		"uid":               d.UID,
		"issued_at":         d.Issued.UTC().Format(time.RFC3339Nano),
		"recipient":         d.Recipient,
		"view":              d.View.Label,
		"record_uid":        d.RecordUID,
		"record_sha256":     d.RecordSHA256,
		"grant_sha256":      d.GrantSHA256,
		"segments":          d.Total,
		"granted_segments":  d.Split.grantedCount,
		"withheld_segments": d.Total - d.Split.grantedCount,
		"granted_bytes":     int64(d.Split.grantedBytes),
		"withheld_bytes":    int64(d.Split.withheldBytes),
		"granted_runs":      disclosureRunsText(d.Runs),
		"method":            discloseMethodPassphrase,
		"ledger":            d.LedgerPath,
		"ledger_node":       d.LedgerNode,
		"bundled_to":        bundles,
		"withdrawn_at":      d.Withdrawn,
		"bytes_recoverable": false,
	}
}

func sha256Of(s string) [sha256.Size]byte { return sha256.Sum256([]byte(s)) }

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

// disclosureRecordArg resolves a record handle at any position.
func disclosureRecordArg(op string, arg object.Object, position int) (*recordSession, *object.Error) {
	handle, ok := arg.(*object.Integer)
	if !ok {
		return nil, newError("argument %d to `%s` must be INTEGER, got %s", position, op, arg.Type())
	}
	session, found := recordGet(handle.Value)
	if !found {
		return nil, newError("%s: %d is not an open record handle. Record handles come from `%s` and are "+
			"not ledger or database handles, which are numbered in spaces of their own",
			op, handle.Value, BuiltinNameRecordOpen)
	}
	return session, nil
}

// disclosureUIDArg reads a disclosure uid: 32 hex characters, lowercased.
func disclosureUIDArg(op string, arg object.Object, position int) (string, *object.Error) {
	text, errObj := requireStringArg(op, arg, position)
	if errObj != nil {
		return "", errObj
	}
	uid := strings.ToLower(strings.TrimSpace(text))
	if raw, err := hex.DecodeString(uid); err != nil || len(raw) != security.DisclosureUIDSize {
		return "", newError("%s: %q is not a disclosure uid; a disclosure uid is the %d hex characters "+
			"`%s` returned", op, text, security.DisclosureUIDSize*2, BuiltinNameDiscloseToPassphrase)
	}
	return uid, nil
}

// disclosureReadGrantFile reads and parses a grant file, bounded before the
// read rather than after it.
func disclosureReadGrantFile(op, path string) (*security.GrantFile, *object.Error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	if info.IsDir() {
		return nil, newError("%s: %s is a directory, not a grant file", op, path)
	}
	if info.Size() > security.MaxGrantFile {
		return nil, newError("%s: %s is %d bytes and a grant file is at most %d", op, path, info.Size(), security.MaxGrantFile)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newError("%s: %s", op, err.Error())
	}
	file, err := security.ParseGrantFile(data)
	if err != nil {
		return nil, newError("%s: %s: %s", op, path, err.Error())
	}
	return file, nil
}

// disclosureGrantNamesRecord refuses a grant for a different record, naming
// both, before anything asks for a passphrase.
func disclosureGrantNamesRecord(op string, file *security.GrantFile, session *recordSession) *object.Error {
	header := session.header
	switch {
	case !strings.EqualFold(file.RecordUID, header.RecordUID):
		return newError("%s: this grant is for record %s and the file is record %s", op, file.RecordUID, header.RecordUID)
	case !strings.EqualFold(file.CaseUID, header.CaseUID):
		return newError("%s: this grant is for a record of case %s and the file belongs to case %s",
			op, file.CaseUID, header.CaseUID)
	case file.SealedUnderGeneration != header.SealedUnderGeneration:
		return newError("%s: this grant is for a record sealed under generation %d and the file was sealed under %d",
			op, file.SealedUnderGeneration, header.SealedUnderGeneration)
	case file.Segments != uint64(len(session.segments)):
		return newError("%s: this grant is for a record of %d segments and the file has %d",
			op, file.Segments, len(session.segments))
	}
	return nil
}

// disclosureCaseFacts is what a disclosure needs from the open case.
type disclosureCaseFacts struct {
	id       string
	caseUID  string
	examiner string
}

func disclosureCase(op string) (disclosureCaseFacts, *object.Error) {
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return disclosureCaseFacts{}, errObj
	}
	if session.caseUID == "" {
		return disclosureCaseFacts{}, newError("%s: no case key has been opened in this case; a disclosure "+
			"names classes, and a class is tagged under the case key. Call `case_key_open(path)` first", op)
	}
	return disclosureCaseFacts{id: session.ID, caseUID: session.caseUID, examiner: session.Examiner}, nil
}

// disclosureFileDigest hashes a whole file and reports its size, so the record
// a disclosure names is the record on disk at the moment of the grant.
func disclosureFileDigest(path string) (string, int64, error) {
	digest, err := custodyHashFile(path, "sha256")
	if err != nil {
		return "", 0, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	return digest, info.Size(), nil
}

// disclosureSegmentRuns turns ascending indices into maximal runs.
func disclosureSegmentRuns(indices []uint64) [][2]uint64 {
	runs := [][2]uint64{}
	for _, index := range indices {
		if n := len(runs); n > 0 && runs[n-1][1]+1 == index {
			runs[n-1][1] = index
			continue
		}
		runs = append(runs, [2]uint64{index, index})
	}
	return runs
}

// ---------------------------------------------------------------------------
// disclose_to_passphrase
// ---------------------------------------------------------------------------

// DiscloseToPassphrase issues a grant under a view and records it:
// disclose_to_passphrase(ledger, record, view, recipient).
func DiscloseToPassphrase(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseToPassphrase
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	record, errObj := disclosureRecordArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	viewName, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	recipientArg, errObj := requireStringArg(op, args[3], 4)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	recipient := strings.TrimSpace(recipientArg)
	if recipient == "" {
		return resultAndError(nil, newError("%s: the recipient must not be empty; a disclosure to nobody "+
			"in particular is a disclosure nobody can be asked about", op))
	}
	if errObj := custodyDocumentName(op, "recipient", recipient); errObj != nil {
		return resultAndError(nil, errObj)
	}
	if record.keys == nil {
		return resultAndError(nil, newError("%s: this record was opened under a grant, and a grant opens "+
			"segments without being able to issue them. Only the case that sealed a record can disclose it", op))
	}

	facts, errObj := disclosureCase(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if !strings.EqualFold(record.header.CaseUID, facts.caseUID) {
		return resultAndError(nil, newError("%s: the record belongs to case %s and the open case is %s; a "+
			"view is a posture over one case's classes and cannot grant another's", op,
			record.header.CaseUID, facts.caseUID))
	}
	view, labels, errObj := viewResolve(op, viewName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// The same partition view_preview reports, so the preview an examiner
	// read is the disclosure that happens.
	split := viewPartition(record, viewGrantedTags(view))
	total := uint64(len(record.segments))
	descriptors := make([]security.SegmentAAD, 0, len(split.granted))
	for _, index := range split.granted {
		aad, err := record.header.SegmentAAD(record.segments[index], total)
		if err != nil {
			return resultAndError(nil, newError("%s: %s", op, err.Error()))
		}
		descriptors = append(descriptors, aad)
	}
	grant, err := record.keys.IssueGrant(descriptors)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	defer grant.Zero()

	recordSHA, recordBytes, err := disclosureFileDigest(record.path)
	if err != nil {
		return resultAndError(nil, newError("%s: hashing %s: %s", op, record.path, err.Error()))
	}
	uid, err := security.RandomDisclosureUID()
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	uidHex := hex.EncodeToString(uid[:])

	// Asked for last among the things that can fail for a reason the
	// examiner can see, and before the ledger write: a disclosure recorded in
	// the ledger for which no grant was ever sealed would be the reverse of
	// the failure this ordering prevents, and only slightly less wrong.
	passphrase, err := security.RequestPassphrase(security.PassphraseRequest{
		Purpose: op,
		Path:    "a grant to " + recipient,
		Confirm: true,
	})
	if err != nil {
		return resultAndError(nil, passphraseError(op, err))
	}
	sealed, err := security.SealGrant(grant, uid, passphrase)
	security.SecureZero(passphrase)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	grantBytes, err := security.MarshalGrantFile(sealed)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	grantSum := sha256.Sum256(grantBytes)
	root := grant.DescriptorsRoot()

	classLabel := map[string]string{}
	for tag, class := range labels {
		classLabel[strings.ToLower(tag)] = class.Label
	}
	tallies := make([]disclosureClassTally, 0, len(split.order))
	for _, tag := range split.order {
		tallies = append(tallies, disclosureClassTally{
			tag:      tag,
			segments: split.tallies[tag].segments,
			bytes:    split.tallies[tag].bytes,
		})
	}
	now := custodyNow()
	issue := &disclosureIssue{
		uid:             uidHex,
		caseUID:         strings.ToLower(facts.caseUID),
		caseID:          facts.id,
		examiner:        facts.examiner,
		recipient:       recipient,
		recipientFP:     disclosureRecipientFingerprint(recipient),
		view:            view,
		viewFP:          disclosureViewFingerprint(view),
		classLabel:      classLabel,
		record:          record,
		recordSHA256:    recordSHA,
		recordBytes:     recordBytes,
		headerSHA256:    ledgerHash(sha256.Sum256(record.headerRaw)),
		recordClasses:   tallies,
		runs:            disclosureSegmentRuns(split.granted),
		grantedSegments: split.grantedCount,
		grantedBytes:    split.grantedBytes,
		withheldBytes:   split.withheldBytes,
		grantSHA256:     hex.EncodeToString(grantSum[:]),
		descriptorsRoot: hex.EncodeToString(root[:]),
		at:              now.UTC().Format(time.RFC3339Nano),
		ns:              now.UnixNano(),
	}
	nodeID, err := disclosureWriteIssue(ledger, issue)
	if err != nil {
		// Nothing has left the process: the sealed grant is discarded with
		// this frame, and no document says it exists.
		return resultAndError(nil, newError("%s: the disclosure could not be recorded in the ledger, so it "+
			"was not issued: %s", op, err.Error()))
	}

	disclosure := &caseDisclosure{
		UID:          uidHex,
		Issued:       now,
		Recipient:    recipient,
		View:         view,
		Labels:       classLabel,
		RecordUID:    record.header.RecordUID,
		RecordPath:   record.path,
		RecordSHA256: recordSHA,
		RecordBytes:  recordBytes,
		Total:        int64(total),
		Grant:        grantBytes,
		GrantSHA256:  issue.grantSHA256,
		Runs:         issue.runs,
		Split:        split,
		Header:       record.header,
		Footer:       record.footer,
		Signed:       record.signed && record.signatureValid,
		LedgerPath:   ledger.path,
		LedgerNode:   int64(nodeID),
		LedgerProps:  disclosureNodeProps(issue),
		Actor:        ledger.actor,
		ActorID:      ledger.actorID,
		LedgerKeyNew: ledger.keyCreatedForThisRun,
	}
	if errObj := disclosureRemember(op, disclosure); errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"disclosure_uid":    stringObj(uidHex),
		"recipient":         stringObj(recipient),
		"view":              stringObj(view.Label),
		"record_uid":        stringObj(record.header.RecordUID),
		"record_sha256":     stringObj(recordSHA),
		"segments":          intObj(int64(total)),
		"granted_segments":  intObj(split.grantedCount),
		"withheld_segments": intObj(int64(total) - split.grantedCount),
		"granted_bytes":     intObj(int64(split.grantedBytes)),
		"withheld_bytes":    intObj(int64(split.withheldBytes)),
		"granted_runs":      viewRunRows(split.grantedRuns, labels),
		"withheld_runs":     viewRunRows(split.withheldRuns, labels),
		"grant_sha256":      stringObj(issue.grantSHA256),
		"grant_bytes":       intObj(int64(len(grantBytes))),
		"ledger_node":       intObj(int64(nodeID)),
		"method":            stringObj(discloseMethodPassphrase),
		// Said on the way out, where the script author will see it: nothing
		// that happens after this call reaches the recipient's copy.
		"bytes_recoverable": boolObj(false),
		"status":            stringObj("issued"),
		"next":              stringObj(fmt.Sprintf("ledger_compact, then %s(ledger, %q, dir)", BuiltinNameDiscloseBundle, uidHex)),
	}), nil)
}

// disclosureRemember hangs a disclosure on the open case and records it in the
// timeline, under the one lock.
func disclosureRemember(op string, d *caseDisclosure) *object.Error {
	custodyStore.Lock()
	defer custodyStore.Unlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		// The ledger holds it; the session does not. Said, rather than
		// returning success for a disclosure this run can no longer bundle.
		return newError("%s: the disclosure %s is recorded in the ledger, but the case was closed before it "+
			"could be held for bundling: %s", op, d.UID, errObj.Message)
	}
	session.disclosures = append(session.disclosures, d)
	session.timeline = append(session.timeline, custodyEvent{
		At:      d.Issued,
		Elapsed: d.Issued.Sub(session.OpenedAt),
		Event:   op,
		Detail: fmt.Sprintf("disclosure %s issued to %q under view %q: %d of %d segments of record %s",
			d.UID, d.Recipient, d.View.Label, d.Split.grantedCount, d.Total, d.RecordUID),
		Data: map[string]any{
			"disclosure_uid":   d.UID,
			"recipient":        d.Recipient,
			"view":             d.View.Label,
			"record_uid":       d.RecordUID,
			"granted_segments": d.Split.grantedCount,
			"grant_sha256":     d.GrantSHA256,
			"ledger_node":      d.LedgerNode,
		},
	})
	return nil
}

// disclosureLookup finds a disclosure issued in this run.
func disclosureLookup(op, uid string) (*caseDisclosure, *object.Error) {
	custodyStore.RLock()
	defer custodyStore.RUnlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return nil, errObj
	}
	for _, d := range session.disclosures {
		if d.UID == uid {
			return d, nil
		}
	}
	return nil, newError("%s: disclosure %s was not issued in this case in this run. The sealed grant is "+
		"held only by the process that issued it -- it is copied key material and is never written to the "+
		"ledger -- so a disclosure is bundled by the run that issued it", op, uid)
}

// ---------------------------------------------------------------------------
// disclose_bundle
// ---------------------------------------------------------------------------

// DiscloseBundle writes the disclosure package: disclose_bundle(ledger, disclosure, dir).
func DiscloseBundle(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseBundle
	if len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	uid, errObj := disclosureUIDArg(op, args[1], 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	dir, errObj := requireStringArg(op, args[2], 3)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if strings.TrimSpace(dir) == "" {
		return resultAndError(nil, newError("%s: the directory must not be empty", op))
	}
	d, errObj := disclosureLookup(op, uid)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if ledger.path != d.LedgerPath {
		return resultAndError(nil, newError("%s: disclosure %s is recorded in the ledger at %s, and this handle "+
			"is the ledger at %s", op, uid, d.LedgerPath, ledger.path))
	}

	// The ledger's record of the disclosure is read back and compared with
	// what this run holds. They were written together, so a difference means
	// the ledger or the session is not what it was.
	node, found, err := disclosureFind(ledger.graph, disclosureNodeDisclosure, "disclosure.uid", uid)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	if !found || int64(node.id) != d.LedgerNode {
		return resultAndError(nil, newError("%s: the ledger has no Disclosure node %d for %s; it is not the "+
			"ledger this disclosure was recorded in, or the node has been redacted", op, d.LedgerNode, uid))
	}
	for key, want := range d.LedgerProps {
		if node.get(key) != want {
			return resultAndError(nil, newError("%s: the ledger records %s = %q for this disclosure and this run "+
				"issued it with %q", op, key, node.get(key), want))
		}
	}
	// A withdrawn disclosure is not packaged. Asked of the ledger rather than
	// of this run's copy, because a withdrawal may have been recorded by
	// another run against the same ledger.
	if withdrawal, withdrawn, err := disclosureWithdrawalOf(ledger.graph, uid); err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	} else if withdrawn {
		return resultAndError(nil, newError("%s: disclosure %s was withdrawn at %s (%q), and a withdrawn "+
			"disclosure is not packaged: a withdrawal is how further grants are stopped", op, uid,
			withdrawal.get("withdrawal.at"), withdrawal.get("withdrawal.reason")))
	}
	proof, err := ledger.store.ProveNode(node.id)
	if err != nil {
		errObj := ledgerProveRefusal(ledger, node.id, err)
		return resultAndError(nil, newError("%s: the package carries a proof that the disclosure is in the "+
			"ledger, and there is none to carry yet: %s", op, strings.TrimPrefix(errObj.Message,
			BuiltinNameLedgerProveNode+": ")))
	}
	proofBytes, err := ledger.store.ExportNodeProof(node.id)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}

	if errObj := disclosureClaimDir(op, dir); errObj != nil {
		return resultAndError(nil, errObj)
	}
	written := map[string]writtenArtifact{}
	abandon := func(errObj *object.Error) object.Object {
		for name := range written {
			_ = os.Remove(filepath.Join(dir, name))
		}
		return resultAndError(nil, errObj)
	}

	// The record, byte for byte, checked against the digest taken when the
	// grant was issued. A record that changed since is not the record that
	// was disclosed, whatever its name.
	recordArtifact, errObj := disclosureCopyFile(op, d.RecordPath, filepath.Join(dir, discloseRecordName))
	if errObj != nil {
		return abandon(errObj)
	}
	written[discloseRecordName] = recordArtifact
	if recordArtifact.digest != d.RecordSHA256 {
		return abandon(newError("%s: %s hashes to %s now and hashed to %s when the grant was issued; the "+
			"record on disk is not the record that was disclosed", op, d.RecordPath, recordArtifact.digest,
			d.RecordSHA256))
	}
	for name, data := range map[string][]byte{discloseGrantName: d.Grant, discloseProofName: proofBytes} {
		artifact, errObj := writeArtifact(op, filepath.Join(dir, name), data)
		if errObj != nil {
			return abandon(errObj)
		}
		written[name] = artifact
	}

	manifest := disclosureManifest(d, uid, node.id)
	report := disclosureReport(manifest)
	reportArtifact, errObj := writeArtifact(op, filepath.Join(dir, discloseReportName), []byte(report))
	if errObj != nil {
		return abandon(errObj)
	}
	written[discloseReportName] = reportArtifact

	files := make([]any, 0, len(written))
	for _, name := range []string{discloseRecordName, discloseGrantName, discloseProofName, discloseReportName} {
		files = append(files, bundleFileRecord(name, written[name]))
	}
	manifest["files"] = files
	manifest["checksums"] = discloseChecksumsName
	if err := custodySeal(manifest, true); err != nil {
		return abandon(newError("%s: %s", op, err.Error()))
	}
	document, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return abandon(newError("%s: the manifest cannot be written as JSON: %s", op, err.Error()))
	}
	document = append(document, '\n')
	manifestArtifact, errObj := writeArtifact(op, filepath.Join(dir, discloseManifestName), document)
	if errObj != nil {
		return abandon(errObj)
	}
	written[discloseManifestName] = manifestArtifact
	sums, errObj := writeArtifact(op, filepath.Join(dir, discloseChecksumsName), []byte(bundleChecksums(written)))
	if errObj != nil {
		return abandon(errObj)
	}
	written[discloseChecksumsName] = sums

	seal, _ := manifest["seal"].(map[string]any)
	signed, _ := seal["signed"].(bool)
	manifestHash := stringField(seal, "manifest_hash")
	snapshotRoot := ledgerHash(proof.Roots.Snapshot)

	custodyStore.Lock()
	d.Bundles = append(d.Bundles, dir)
	custodyStore.Unlock()
	custodyRecordArtifact(op, fmt.Sprintf("wrote the package for disclosure %s to %s (manifest sha256 %s, signed %t)",
		uid, dir, manifestHash, signed), map[string]any{
		"disclosure_uid": uid,
		"dir":            dir,
		"manifest_hash":  manifestHash,
		"signed":         signed,
		"snapshot_root":  snapshotRoot,
	})

	names := make([]string, 0, len(written))
	for name := range written {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([]object.Object, 0, len(names))
	for _, name := range names {
		rows = append(rows, makeHashObject(map[string]object.Object{
			"name":   stringObj(name),
			"bytes":  intObj(written[name].bytes),
			"sha256": stringObj(written[name].digest),
		}))
	}
	result := map[string]object.Object{
		"dir":            stringObj(dir),
		"disclosure_uid": stringObj(uid),
		"files":          &object.Array{Elements: rows},
		"manifest":       stringObj(discloseManifestName),
		"manifest_hash":  stringObj(manifestHash),
		"signed":         boolObj(signed),
		// The value the recipient checks the proof against, and the one thing
		// that must NOT travel in the package. Retain it, publish it, or send
		// it by another route; ledger_root_export returns it as well.
		"snapshot_root":         stringObj(snapshotRoot),
		"snapshot_root_bundled": boolObj(false),
		"status":                stringObj("ok"),
	}
	if reason, ok := seal["signature_error"].(string); ok {
		result["signature_error"] = stringObj(reason)
	}
	return resultAndError(makeHashObject(result), nil)
}

// disclosureClaimDir makes the package directory, refusing one that already
// holds anything. A disclosure package written over another is two packages'
// files under one manifest, and nothing downstream could say which were which.
func disclosureClaimDir(op, dir string) *object.Error {
	entries, err := os.ReadDir(dir)
	switch {
	case err == nil && len(entries) > 0:
		return newError("%s: %s is not empty. A disclosure package is written into a directory of its own, "+
			"and never over another one", op, dir)
	case err == nil:
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return newError("%s: %s", op, err.Error())
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return newError("%s: %s", op, err.Error())
	}
	return nil
}

// disclosureCopyFile streams a file into a new one it creates exclusively, and
// reports the digest of what landed -- read back from the destination, for
// the reason writeArtifact gives.
func disclosureCopyFile(op, source, dest string) (writtenArtifact, *object.Error) {
	in, err := os.Open(source)
	if err != nil {
		return writtenArtifact{}, newError("%s: %s", op, err.Error())
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return writtenArtifact{}, newError("%s: %s", op, err.Error())
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(dest)
		return writtenArtifact{}, newError("%s: copying %s: %s", op, source, err.Error())
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(dest)
		return writtenArtifact{}, newError("%s: %s", op, err.Error())
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dest)
		return writtenArtifact{}, newError("%s: %s", op, err.Error())
	}
	digest, size, err := disclosureFileDigest(dest)
	if err != nil {
		return writtenArtifact{}, newError("%s: %s was written but cannot be read back to hash it: %s", op, dest, err.Error())
	}
	return writtenArtifact{bytes: size, digest: digest}, nil
}

// disclosureRunRows renders byte runs for the manifest, naming the class where
// the case can.
func disclosureRunRows(runs []viewRun, labels map[string]string) []any {
	rows := make([]any, 0, len(runs))
	for _, run := range runs {
		label, named := labels[run.tag]
		rows = append(rows, map[string]any{
			"offset":        int64(run.offset),
			"length":        int64(run.length),
			"first_segment": int64(run.first),
			"last_segment":  int64(run.last),
			"class":         run.tag,
			"label":         label,
			"declared":      named,
		})
	}
	return rows
}

// disclosureManifest builds the package's manifest: every fact a recipient is
// asked to rely on, and the three it is not.
func disclosureManifest(d *caseDisclosure, uid string, nodeID store.NodeID) map[string]any {
	total := d.Total
	grants := make([]any, 0, len(d.View.Tags))
	for i, tag := range d.View.Tags {
		grants = append(grants, map[string]any{"label": d.View.Classes[i], "tag": strings.ToLower(tag)})
	}
	ledgerRecord := make(map[string]any, len(d.LedgerProps))
	for key, value := range d.LedgerProps {
		ledgerRecord[key] = value
	}
	header := d.Header
	rounding := map[string]any{
		"quantised":       header.Quantum != 0,
		"quantum":         int64(header.Quantum),
		"quantised_extra": int64(header.QuantisedExtra),
		"rounds_to":       strings.ToLower(header.RoundsTo),
		"rounds_to_label": d.Labels[strings.ToLower(header.RoundsTo)],
		"rounds_to_granted": header.Quantum != 0 &&
			viewGrantedTags(d.View)[strings.ToLower(header.RoundsTo)],
	}
	return map[string]any{
		"format":  discloseManifestFormat,
		"version": discloseManifestVersion,
		"disclosure": map[string]any{
			"uid":          uid,
			"issued_at":    d.Issued.UTC().Format(time.RFC3339Nano),
			"method":       discloseMethodPassphrase,
			"recipient":    d.Recipient,
			"recipient_fp": disclosureRecipientFingerprint(d.Recipient),
			"examiner":     d.LedgerProps["disclosure.examiner"],
			"case_uid":     d.LedgerProps["disclosure.case_uid"],
		},
		"view": map[string]any{
			"label":  d.View.Label,
			"fp":     disclosureViewFingerprint(d.View),
			"grants": grants,
		},
		"record": map[string]any{
			"file":                     discloseRecordName,
			"uid":                      d.RecordUID,
			"sha256":                   d.RecordSHA256,
			"bytes":                    d.RecordBytes,
			"segments":                 total,
			"plaintext_length":         int64(header.PlaintextLength),
			"segment_size":             int64(header.SegmentSize),
			"signed":                   d.Signed,
			"public_key":               d.Footer.PublicKey,
			"key_created_for_this_run": d.Footer.KeyCreatedForThisRun,
		},
		"grant": map[string]any{
			"file":             discloseGrantName,
			"sha256":           d.GrantSHA256,
			"granted_segments": int64(len(d.Split.granted)),
			"runs":             disclosureRunsText(d.Runs),
			"opens_with":       "a passphrase the examiner gives the recipient separately from this package",
		},
		"granted":           disclosureRunRows(d.Split.grantedRuns, d.Labels),
		"withheld":          disclosureRunRows(d.Split.withheldRuns, d.Labels),
		"granted_segments":  int64(len(d.Split.granted)),
		"withheld_segments": total - int64(len(d.Split.granted)),
		"granted_bytes":     int64(d.Split.grantedBytes),
		"withheld_bytes":    int64(d.Split.withheldBytes),
		"rounding":          rounding,
		"ledger": map[string]any{
			"proof":                    discloseProofName,
			"node_id":                  int64(nodeID),
			"actor":                    d.Actor,
			"actor_id":                 strconv.FormatUint(d.ActorID, 10),
			"key_created_for_this_run": d.LedgerKeyNew,
			// The root the proof resolves against is deliberately absent. The
			// proof file names it, as every proof must, and verifying against
			// that would be verifying a proof against a root its author chose;
			// putting it here as well would make the circular check the
			// convenient one. The root travels by another route.
			"record": ledgerRecord,
		},
		"bytes_recoverable": false,
		"does_not_cover":    stringsToAny(discloseDoesNotCover),
		"signature_note":    discloseSignatureNote,
	}
}

func stringsToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

// disclosureReport renders the manifest for a person. It reads the manifest
// and nothing else, for the reason case_report does: a report that could say
// something the manifest does not is a second account of one disclosure.
func disclosureReport(m map[string]any) string {
	disclosure := manifestMap(m, "disclosure")
	view := manifestMap(m, "view")
	record := manifestMap(m, "record")
	var out strings.Builder
	fmt.Fprintf(&out, "# Disclosure %s\n\n", stringField(disclosure, "uid"))
	fmt.Fprintf(&out, "Issued %s by %s to %s, under the view \"%s\".\n\n", stringField(disclosure, "issued_at"),
		stringField(disclosure, "examiner"), stringField(disclosure, "recipient"), stringField(view, "label"))
	fmt.Fprintf(&out, "The record `%s` (%s, sha256 `%s`) is in this package byte for byte as it is held under "+
		"custody. The grant beside it opens %v of its %v segments -- %v bytes -- and nothing else. %v bytes are "+
		"withheld: they are in the record, and no material in this package opens them.\n\n",
		discloseRecordName, stringField(record, "uid"), stringField(record, "sha256"),
		m["granted_segments"], record["segments"], m["granted_bytes"], m["withheld_bytes"])

	out.WriteString("## What is released\n\n")
	disclosureReportRuns(&out, m["granted"])
	out.WriteString("\n## What is withheld\n\n")
	disclosureReportRuns(&out, m["withheld"])

	rounding := manifestMap(m, "rounding")
	if quantised, _ := rounding["quantised"].(bool); quantised {
		direction := "withheld"
		if granted, _ := rounding["rounds_to_granted"].(bool); granted {
			direction = "released"
		}
		fmt.Fprintf(&out, "\n## Rounding\n\nThe record's boundaries were rounded to %v bytes, moving %v bytes into "+
			"the class \"%s\". This view %s those bytes, which the examiner's own boundaries placed elsewhere.\n",
			rounding["quantum"], rounding["quantised_extra"], stringField(rounding, "rounds_to_label"), direction)
	}

	out.WriteString("\n## How to check this package\n\n")
	out.WriteString("`disclose_verify(dir, root)` checks the manifest's seal and signature, every file's digest, the " +
		"record's own signature with no key at all, that the grant was issued against this record exactly as it " +
		"stands, that it opens exactly the classes the view names, and -- with the passphrase -- that every " +
		"granted segment opens with its tag holding. `root` is the ledger snapshot root, obtained from the " +
		"examiner by a route other than this package; without it the ledger proof is not checked, and the " +
		"verification says so.\n\n")
	out.WriteString("## What this package does not establish\n\n")
	for _, line := range discloseDoesNotCover {
		fmt.Fprintf(&out, "- %s\n", line)
	}
	fmt.Fprintf(&out, "\nAnd, of every signature in it: %s.\n", discloseSignatureNote)
	return out.String()
}

func disclosureReportRuns(out *strings.Builder, runs any) {
	rows, _ := runs.([]any)
	if len(rows) == 0 {
		out.WriteString("Nothing.\n")
		return
	}
	out.WriteString("| Bytes | Segments | Class |\n| --- | --- | --- |\n")
	for _, row := range rows {
		r, _ := row.(map[string]any)
		label := stringField(r, "label")
		if label == "" {
			label = "(a class this case could not name) `" + stringField(r, "class")[:16] + "`"
		}
		fmt.Fprintf(out, "| %v+%v | %v-%v | %s |\n", r["offset"], r["length"], r["first_segment"], r["last_segment"], label)
	}
}

// ---------------------------------------------------------------------------
// disclose_verify
// ---------------------------------------------------------------------------

// discloseCheck is one line of a verification.
type discloseCheck struct {
	name   string
	passed bool
	detail string
}

// DiscloseVerify checks a disclosure package: disclose_verify(dir, root).
func DiscloseVerify(args ...object.Object) object.Object {
	op := BuiltinNameDiscloseVerify
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	dir, errObj := requireStringArg(op, args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var root *merkle.Hash
	switch value := args[1].(type) {
	case *object.Null:
	case *object.String:
		parsed, errObj := ledgerRootFromHex(value.Value, "the snapshot root", op)
		if errObj != nil {
			return resultAndError(nil, errObj)
		}
		root = &parsed
	default:
		return resultAndError(nil, newError("argument 2 to `%s` must be STRING or NULL, got %s. The root is "+
			"required and may be null, and null is recorded as a finding rather than read as a pass", op, args[1].Type()))
	}

	manifestPath := filepath.Join(dir, discloseManifestName)
	raw, err := disclosureReadBounded(manifestPath, maxDiscloseManifest)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var manifest map[string]any
	if err := decoder.Decode(&manifest); err != nil {
		return resultAndError(nil, newError("%s: %s is not a disclosure manifest: %s", op, manifestPath, err.Error()))
	}
	if stringField(manifest, "format") != discloseManifestFormat {
		return resultAndError(nil, newError("%s: %s is not a disclosure manifest; its format is %q", op,
			manifestPath, stringField(manifest, "format")))
	}
	if version, _ := manifest["version"].(json.Number); version.String() != strconv.FormatInt(discloseManifestVersion, 10) {
		return resultAndError(nil, newError("%s: %s is version %s and this build reads version %d", op,
			manifestPath, version.String(), discloseManifestVersion))
	}

	v := &discloseVerification{op: op, dir: dir, manifest: manifest}
	v.checkSeal()
	v.checkFiles()
	v.checkRecord()
	v.checkGrant()
	v.checkAuthorised()
	v.checkGrantOpens()
	v.checkLedger(root)
	if v.record != nil {
		v.record.file.Close()
	}
	return resultAndError(v.result(root != nil), nil)
}

func disclosureReadBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s is %d bytes, more than the %d this reads", path, info.Size(), limit)
	}
	return os.ReadFile(path)
}

// discloseVerification carries one verification's state between its checks.
type discloseVerification struct {
	op       string
	dir      string
	manifest map[string]any

	checks   []discloseCheck
	findings []string

	record    *recordSession
	grantFile *security.GrantFile
	indices   []uint64
	opened    bool
}

func (v *discloseVerification) add(name string, passed bool, detail string) {
	v.checks = append(v.checks, discloseCheck{name: name, passed: passed, detail: detail})
	if !passed {
		v.findings = append(v.findings, name+": "+detail)
	}
}

func (v *discloseVerification) checkSeal() {
	result := custodyVerifyDocument(v.manifest)
	hashMatches, _ := result["hash_matches"].(bool)
	v.add("manifest_seal", hashMatches, map[bool]string{
		true:  "the manifest hashes to the value in its seal",
		false: "the manifest does not hash to the value in its seal, so it has been edited",
	}[hashMatches])
	signed, _ := result["signed"].(bool)
	valid, _ := result["signature_valid"].(bool)
	detail, _ := result["signature_detail"].(string)
	if !signed {
		v.add("manifest_signature", false, "the manifest carries no signature: "+detail)
		return
	}
	v.add("manifest_signature", valid, detail)
}

func (v *discloseVerification) checkFiles() {
	files, _ := v.manifest["files"].([]any)
	if len(files) == 0 {
		v.add("files", false, "the manifest lists no files")
		return
	}
	want := map[string]string{}
	var problems []string
	for _, entry := range files {
		row, _ := entry.(map[string]any)
		name := stringField(row, "name")
		expected := stringField(row, "sha256")
		if name == "" || name != filepath.Base(name) {
			problems = append(problems, fmt.Sprintf("%q is not a file name in this directory", name))
			continue
		}
		want[name] = expected
		got, err := custodyHashFile(filepath.Join(v.dir, name), "sha256")
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("%s cannot be read: %s", name, err.Error()))
		case got != expected:
			problems = append(problems, fmt.Sprintf("%s hashes to %s and the manifest says %s", name, got, expected))
		}
	}
	for _, name := range []string{discloseRecordName, discloseGrantName, discloseProofName} {
		if _, ok := want[name]; !ok {
			problems = append(problems, name+" is not listed in the manifest")
		}
	}
	// SHA256SUMS is the convenience on top, and it is checked to agree: a
	// checksum file that disagrees with the manifest it sits beside is a
	// package somebody assembled from two different ones.
	if sums, err := disclosureReadBounded(filepath.Join(v.dir, discloseChecksumsName), 1<<20); err != nil {
		problems = append(problems, "SHA256SUMS cannot be read: "+err.Error())
	} else {
		for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
			fields := strings.SplitN(strings.TrimRight(line, "\r"), "  ", 2)
			if len(fields) != 2 {
				problems = append(problems, fmt.Sprintf("SHA256SUMS line %q is not a checksum line", line))
				continue
			}
			if expected, listed := want[fields[1]]; listed && expected != fields[0] {
				problems = append(problems, fmt.Sprintf("SHA256SUMS gives %s for %s and the manifest gives %s",
					fields[0], fields[1], expected))
			}
		}
	}
	if len(problems) > 0 {
		v.add("files", false, strings.Join(problems, "; "))
		return
	}
	v.add("files", true, fmt.Sprintf("all %d files hash to the digests the manifest names", len(want)))
}

func (v *discloseVerification) checkRecord() {
	record := manifestMap(v.manifest, "record")
	session, errObj := recordLoad(v.op, filepath.Join(v.dir, discloseRecordName))
	if errObj != nil {
		v.add("record_signature", false, errObj.Message)
		v.add("record_identity", false, "the record could not be read")
		return
	}
	v.record = session
	switch {
	case !session.signed:
		v.add("record_signature", false, "the record carries no signature: "+session.signatureNote)
	default:
		v.add("record_signature", session.signatureValid, session.signatureNote)
	}
	var problems []string
	if !strings.EqualFold(session.header.RecordUID, stringField(record, "uid")) {
		problems = append(problems, fmt.Sprintf("the record is %s and the manifest names %s",
			session.header.RecordUID, stringField(record, "uid")))
	}
	if n, _ := record["segments"].(json.Number); n.String() != strconv.Itoa(len(session.segments)) {
		problems = append(problems, fmt.Sprintf("the record has %d segments and the manifest says %s",
			len(session.segments), n.String()))
	}
	if len(problems) > 0 {
		v.add("record_identity", false, strings.Join(problems, "; "))
		return
	}
	v.add("record_identity", true, "the record is the one the manifest names, verified with no key")
}

func (v *discloseVerification) checkGrant() {
	file, errObj := disclosureReadGrantFile(v.op, filepath.Join(v.dir, discloseGrantName))
	if errObj != nil {
		v.add("grant_names_record", false, errObj.Message)
		v.add("grant_describes_record", false, "the grant could not be read")
		return
	}
	v.grantFile = file
	disclosure := manifestMap(v.manifest, "disclosure")
	grant := manifestMap(v.manifest, "grant")
	var problems []string
	if !strings.EqualFold(file.DisclosureUID, stringField(disclosure, "uid")) {
		problems = append(problems, fmt.Sprintf("the grant is for disclosure %s and the manifest is %s",
			file.DisclosureUID, stringField(disclosure, "uid")))
	}
	runs := make([][2]uint64, 0, len(file.Runs))
	for _, run := range file.Runs {
		runs = append(runs, [2]uint64{run.First, run.Last})
	}
	if disclosureRunsText(runs) != stringField(grant, "runs") {
		problems = append(problems, fmt.Sprintf("the grant opens segments %s and the manifest says %s",
			disclosureRunsText(runs), stringField(grant, "runs")))
	}
	if v.record != nil {
		if errObj := disclosureGrantNamesRecord(v.op, file, v.record); errObj != nil {
			problems = append(problems, errObj.Message)
		}
	}
	if len(problems) > 0 {
		v.add("grant_names_record", false, strings.Join(problems, "; "))
	} else {
		v.add("grant_names_record", true, "the grant is for this disclosure and this record")
	}
	indices, err := file.Indices()
	if err != nil {
		v.add("grant_describes_record", false, err.Error())
		return
	}
	v.indices = indices
	if v.record == nil {
		v.add("grant_describes_record", false, "there is no readable record to check the grant against")
		return
	}
	if err := file.MatchesHeader(recordDescriber(v.record)); err != nil {
		v.add("grant_describes_record", false, err.Error())
		return
	}
	v.add("grant_describes_record", true, "every granted segment is described by the record's header exactly as "+
		"it was when the grant was issued")
}

// checkAuthorised is "complete as authorised": the segments whose class the
// view names are exactly the segments the grant opens, and the manifest's
// released and withheld lists are exactly those two sides.
func (v *discloseVerification) checkAuthorised() {
	if v.record == nil || v.indices == nil {
		v.add("complete_as_authorised", false, "the record or the grant could not be read")
		return
	}
	view := manifestMap(v.manifest, "view")
	granted := map[string]bool{}
	grants, _ := view["grants"].([]any)
	for _, entry := range grants {
		row, _ := entry.(map[string]any)
		granted[strings.ToLower(stringField(row, "tag"))] = true
	}
	split := viewPartition(v.record, granted)
	var problems []string
	if fmt.Sprint(split.granted) != fmt.Sprint(v.indices) {
		problems = append(problems, fmt.Sprintf("the view's classes select segments %s of this record and the "+
			"grant opens %s", disclosureRunsText(disclosureSegmentRuns(split.granted)),
			disclosureRunsText(disclosureSegmentRuns(v.indices))))
	}
	if !disclosureRunsAgree(v.manifest["granted"], split.grantedRuns) {
		problems = append(problems, "the manifest's list of released bytes is not what the view selects from this record")
	}
	if !disclosureRunsAgree(v.manifest["withheld"], split.withheldRuns) {
		problems = append(problems, "the manifest's list of withheld bytes is not everything the view does not select")
	}
	if len(problems) > 0 {
		v.add("complete_as_authorised", false, strings.Join(problems, "; "))
		return
	}
	v.add("complete_as_authorised", true, fmt.Sprintf("the grant opens exactly the %d segments whose class the "+
		"view names, and the manifest's withheld list is every other segment", len(v.indices)))
}

// disclosureRunsAgree compares a manifest run list with a computed one.
func disclosureRunsAgree(listed any, computed []viewRun) bool {
	rows, _ := listed.([]any)
	if len(rows) != len(computed) {
		return false
	}
	for i, entry := range rows {
		row, _ := entry.(map[string]any)
		run := computed[i]
		for key, want := range map[string]uint64{
			"offset": run.offset, "length": run.length,
			"first_segment": run.first, "last_segment": run.last,
		} {
			if n, _ := row[key].(json.Number); n.String() != strconv.FormatUint(want, 10) {
				return false
			}
		}
		if !strings.EqualFold(stringField(row, "class"), run.tag) {
			return false
		}
	}
	return true
}

// checkGrantOpens is the only check that needs the passphrase, and the only
// one that can establish that the material in the grant is real: every
// granted segment is decrypted and its tag must hold. Without a passphrase it
// is recorded as not done, not as failed-and-hidden.
func (v *discloseVerification) checkGrantOpens() {
	if v.record == nil || v.grantFile == nil {
		v.add("grant_opens", false, "the record or the grant could not be read")
		return
	}
	grantPath := filepath.Join(v.dir, discloseGrantName)
	request := security.PassphraseRequest{Purpose: v.op, Path: grantPath, Confirm: false}
	passphrase, err := security.RequestPassphrase(request)
	if err != nil {
		v.add("grant_opens", false, "the grant was not opened, so no granted segment was decrypted: "+
			passphraseError(v.op, err).Message)
		return
	}
	grant, err := security.OpenGrantFile(v.grantFile, passphrase)
	security.SecureZero(passphrase)
	if err != nil {
		security.ForgetPassphrase(request)
		v.add("grant_opens", false, err.Error())
		return
	}
	defer grant.Zero()
	total := uint64(len(v.record.segments))
	buffer := make([]byte, 0, v.record.header.SegmentSize+64)
	for _, index := range grant.Indices() {
		segment := v.record.segments[index]
		if uint64(cap(buffer)) < segment.StoredLength {
			buffer = make([]byte, segment.StoredLength)
		}
		chunk := buffer[:segment.StoredLength]
		if _, err := v.record.file.ReadAt(chunk, int64(v.record.dataOffset+segment.StoredOffset)); err != nil {
			v.add("grant_opens", false, fmt.Sprintf("segment %d could not be read: %s", index, err.Error()))
			return
		}
		aad, err := v.record.header.SegmentAAD(segment, total)
		if err != nil {
			v.add("grant_opens", false, err.Error())
			return
		}
		plaintext, err := grant.OpenSegment(aad, chunk)
		if err != nil {
			v.add("grant_opens", false, fmt.Sprintf("granted segment %d does not open under the material "+
				"granted for it", index))
			return
		}
		security.SecureZero(plaintext)
	}
	v.opened = true
	v.add("grant_opens", true, fmt.Sprintf("every one of the %d granted segments opened with its tag holding, "+
		"and no plaintext was kept", grant.Count()))
}

// checkLedger checks the ledger proof against the root the caller supplied,
// and that the node it proves is this disclosure.
func (v *discloseVerification) checkLedger(root *merkle.Hash) {
	ledger := manifestMap(v.manifest, "ledger")
	if root == nil {
		v.add("ledger_inclusion", false, "no snapshot root was supplied, so the ledger proof was not checked. "+
			"A root from inside this package would be a root its author chose; obtain it from the examiner by "+
			"another route")
		return
	}
	blob, err := disclosureReadBounded(filepath.Join(v.dir, discloseProofName), maxDiscloseProof)
	if err != nil {
		v.add("ledger_inclusion", false, err.Error())
		return
	}
	decoded, err := disk.UnmarshalProof(blob)
	if err != nil {
		v.add("ledger_inclusion", false, "the ledger proof cannot be read: "+err.Error())
		return
	}
	if decoded.Kind != disk.ProofKindNodeInclusion || decoded.Node == nil {
		v.add("ledger_inclusion", false, "the ledger proof is not a node inclusion proof")
		return
	}
	if err := disk.VerifyExportedProof(*root, decoded); err != nil {
		v.add("ledger_inclusion", false, "the ledger proof does not verify against the supplied root: "+err.Error())
		return
	}
	if detail := disclosureLeafNames(decoded.Node.LeafData, ledger); detail != "" {
		v.add("ledger_inclusion", false, "the proof verifies, but not for this disclosure: "+detail)
		return
	}
	v.add("ledger_inclusion", true, "the ledger snapshot with the supplied root contains this disclosure's "+
		"record, property for property")
}

// disclosureLeafNames checks that a proven node leaf is the Disclosure node the
// manifest describes. It returns "" when it is, and says why when it is not.
//
// The leaf is graphene's canonical encoding: tag, node id, labels, and --
// since body version 3 -- SHA256(0x07 || properties) in place of the
// properties. So the manifest's copy of the node's properties is encoded the
// way the ledger encoded them, hashed the way graphene hashes them, and
// compared. A proof for some other node of the same ledger verifies against
// the root just as well, and this is the check that tells the two apart.
func disclosureLeafNames(leaf []byte, ledger map[string]any) string {
	if len(leaf) < 11 || leaf[0] != grapheneNodeLeafV2 {
		return "the proven leaf is not a node leaf this build can read"
	}
	id := binary.LittleEndian.Uint64(leaf[1:9])
	count := int(binary.LittleEndian.Uint16(leaf[9:11]))
	if len(leaf) != 11+2*count+sha256.Size {
		return "the proven leaf has the wrong length for its label count"
	}
	if n, _ := ledger["node_id"].(json.Number); n.String() != strconv.FormatUint(id, 10) {
		return fmt.Sprintf("the proof is for node %d and the manifest names node %s", id, n.String())
	}
	labelled := false
	for i := 0; i < count; i++ {
		if store.NodeType(binary.LittleEndian.Uint16(leaf[11+2*i:])) == disclosureNodeDisclosure {
			labelled = true
		}
	}
	if !labelled {
		return "the proven node is not labelled Disclosure"
	}
	record, _ := ledger["record"].(map[string]any)
	props := make(map[string][]byte, len(record))
	for key, value := range record {
		text, ok := value.(string)
		if !ok {
			return fmt.Sprintf("the manifest's ledger record has a non-string %s", key)
		}
		props[key] = []byte(text)
	}
	blob, err := ledgerPropertyBlob(props)
	if err != nil {
		return err.Error()
	}
	h := sha256.New()
	h.Write([]byte{graphenePropertyHashTag})
	h.Write(blob)
	if !bytes.Equal(h.Sum(nil), leaf[len(leaf)-sha256.Size:]) {
		return "the proven node's properties are not the ones the manifest records"
	}
	return ""
}

func (v *discloseVerification) result(rootGiven bool) object.Object {
	rows := make([]object.Object, 0, len(v.checks))
	passed := 0
	for _, check := range v.checks {
		if check.passed {
			passed++
		}
		rows = append(rows, makeHashObject(map[string]object.Object{
			"check":  stringObj(check.name),
			"passed": boolObj(check.passed),
			"detail": stringObj(check.detail),
		}))
	}
	disclosure := manifestMap(v.manifest, "disclosure")
	view := manifestMap(v.manifest, "view")
	record := manifestMap(v.manifest, "record")
	numberOf := func(value any) int64 {
		n, _ := value.(json.Number)
		i, _ := n.Int64()
		return i
	}
	return makeHashObject(map[string]object.Object{
		"dir": stringObj(v.dir),
		// True only when every check ran and passed. A package verified with
		// no root, or without the passphrase, is not verified: it is a package
		// of which some things were checked, and `checks` says which.
		"verified":          boolObj(passed == len(v.checks) && rootGiven && v.opened),
		"checks":            &object.Array{Elements: rows},
		"checks_passed":     intObj(int64(passed)),
		"checks_run":        intObj(int64(len(v.checks))),
		"findings":          stringArrayObj(v.findings),
		"root_supplied":     boolObj(rootGiven),
		"grant_opened":      boolObj(v.opened),
		"disclosure_uid":    stringObj(stringField(disclosure, "uid")),
		"recipient":         stringObj(stringField(disclosure, "recipient")),
		"examiner":          stringObj(stringField(disclosure, "examiner")),
		"view":              stringObj(stringField(view, "label")),
		"record_uid":        stringObj(stringField(record, "uid")),
		"granted_segments":  intObj(numberOf(v.manifest["granted_segments"])),
		"withheld_segments": intObj(numberOf(v.manifest["withheld_segments"])),
		"bytes_recoverable": boolObj(false),
		"does_not_cover":    stringArrayObj(discloseDoesNotCover),
		"signature_note":    stringObj(discloseSignatureNote),
	})
}

// disclosureRows renders the case's disclosures for the manifest. The caller
// holds the store lock.
func (s *custodySession) disclosureRows() []any {
	rows := make([]any, 0, len(s.disclosures))
	for _, d := range s.disclosures {
		rows = append(rows, d.render())
	}
	return rows
}
