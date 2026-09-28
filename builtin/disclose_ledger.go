package builtin

// The disclosure schema: what a disclosure writes into the forensic ledger, and
// how the disclose_* family reads it back.
//
// The ledger is where a disclosure outlives the process. The case session is a
// process-global in-memory structure, so a disclosure recorded only there is
// lost by a crash between the grant and case_close -- while the recipient keeps
// the keys. Every disclosure is therefore written into the ledger in its own
// signed, attributed transaction at the moment it is issued, and the grant is
// not handed back to the program until that commit has succeeded.
//
// # The labels are out of a script's reach
//
// `ledger_add_node` takes a node type from 0 to 127, and the symbol graph
// `mutant graph export` writes uses 0 to 10. This schema's labels start at
// 4096. A script can write a node with a property called `disclosure.uid` --
// the property index is shared -- but it cannot write one labelled
// Disclosure, and every read in this family filters on the label. So the
// history this family reports is the history this family wrote, and a node a
// script forged into the same ledger is not in it.
//
// # One deviation from the design, and why
//
// The design called for a Segment node per segment "classified above open",
// so that the graph's size followed the sensitive surface rather than the data
// volume. That condition cannot be evaluated: nothing in the record format or
// the class table orders one class above another, which the rounding work
// established the hard way (see docs/DISCLOSURE_POLICY.md, section 5). A
// Segment node per GRANTED segment would put a 16384-node write into every
// disclosure of a 1 GiB record. So the granted set is written as runs of
// segment indices on the Disclosure node and on its GRANTS edge to the Record
// -- a handful of rows, one per span at most -- and the per-segment question
// (`disclose_for_segment`) is answered by reading the runs. The graph's size
// follows the number of spans, which is what the design wanted.
//
// # Nodes are written once
//
// Every node here is written by AddNode and never updated. A Record, a View, a
// Recipient, a RoleBundle or a Classification that is already in the ledger is
// found and reused; a Disclosure and a Withdrawal are always new, and a
// RedactionVersion is new only when what it records has changed. graphene
// keeps no history of an update and the next compaction would erase the prior
// value, so an update would be a way to change what a disclosure record says
// with no trace -- and a Record found under the same uid with a different file
// digest is refused rather than reconciled.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// disclosureTypeBase is the schema's first custom type offset.
const disclosureTypeBase = 4096

// Node labels.
//
// The Case node is graphene's own built-in Case type rather than a custom one:
// graphene reserves the name, and a case is exactly what its built-in type is
// for. A script cannot spell it either -- ledger_add_node maps 0..127 into the
// custom range and nowhere else.
var (
	disclosureNodeCase       = store.NodeTypeCase
	disclosureNodeActor      = store.CustomNodeType(disclosureTypeBase + 1)
	disclosureNodeRecord     = store.CustomNodeType(disclosureTypeBase + 2)
	disclosureNodeClass      = store.CustomNodeType(disclosureTypeBase + 3)
	disclosureNodeView       = store.CustomNodeType(disclosureTypeBase + 4)
	disclosureNodeRecipient  = store.CustomNodeType(disclosureTypeBase + 5)
	disclosureNodeDisclosure = store.CustomNodeType(disclosureTypeBase + 6)
	disclosureNodeWithdrawal = store.CustomNodeType(disclosureTypeBase + 7)
	disclosureNodeReclass    = store.CustomNodeType(disclosureTypeBase + 8)

	// The case-management labels, appended after the disclosure family's.
	// A label's number is written into every ledger that holds one, so it is
	// a format: TestTheLedgerLabelsAreAFormat pins each.
	disclosureNodeRole             = store.CustomNodeType(disclosureTypeBase + 9)
	disclosureNodeRoleBundle       = store.CustomNodeType(disclosureTypeBase + 10)
	disclosureNodeAssignment       = store.CustomNodeType(disclosureTypeBase + 11)
	disclosureNodeLifecycle        = store.CustomNodeType(disclosureTypeBase + 12)
	disclosureNodeCustodyEvent     = store.CustomNodeType(disclosureTypeBase + 13)
	disclosureNodeReviewRequest    = store.CustomNodeType(disclosureTypeBase + 14)
	disclosureNodeReviewDecision   = store.CustomNodeType(disclosureTypeBase + 15)
	disclosureNodeRetention        = store.CustomNodeType(disclosureTypeBase + 16)
	disclosureNodeErasure          = store.CustomNodeType(disclosureTypeBase + 17)
	disclosureNodeClassEvent       = store.CustomNodeType(disclosureTypeBase + 18)
	disclosureNodeRedactionVersion = store.CustomNodeType(disclosureTypeBase + 19)
	disclosureNodeRedactionReview  = store.CustomNodeType(disclosureTypeBase + 20)

	// Evidence is graphene's own built-in EvidenceFile, for the reason Case
	// is: the name is reserved, and it is what the built-in type is for.
	disclosureNodeEvidence = store.NodeTypeEvidenceFile
)

// Edge labels.
var (
	disclosureEdgeInCase       = store.CustomEdgeType(disclosureTypeBase + 0)
	disclosureEdgeClassifiedAs = store.CustomEdgeType(disclosureTypeBase + 1)
	disclosureEdgeGrants       = store.CustomEdgeType(disclosureTypeBase + 2)
	disclosureEdgeDisclosedTo  = store.CustomEdgeType(disclosureTypeBase + 3)
	disclosureEdgeAuthorisedBy = store.CustomEdgeType(disclosureTypeBase + 4)
	disclosureEdgePerformedBy  = store.CustomEdgeType(disclosureTypeBase + 5)
	disclosureEdgeWithdrew     = store.CustomEdgeType(disclosureTypeBase + 6)
	disclosureEdgeSupersedes   = store.CustomEdgeType(disclosureTypeBase + 7)

	disclosureEdgeHoldsRole   = store.CustomEdgeType(disclosureTypeBase + 8)
	disclosureEdgeAssignedTo  = store.CustomEdgeType(disclosureTypeBase + 9)
	disclosureEdgeBundles     = store.CustomEdgeType(disclosureTypeBase + 10)
	disclosureEdgeIssuedUnder = store.CustomEdgeType(disclosureTypeBase + 11)
	disclosureEdgeRedactedAs  = store.CustomEdgeType(disclosureTypeBase + 12)
	disclosureEdgeRevises     = store.CustomEdgeType(disclosureTypeBase + 13)
	disclosureEdgeTransitions = store.CustomEdgeType(disclosureTypeBase + 14)
	disclosureEdgeCustodian   = store.CustomEdgeType(disclosureTypeBase + 15)
	disclosureEdgeReviews     = store.CustomEdgeType(disclosureTypeBase + 16)
	disclosureEdgeErases      = store.CustomEdgeType(disclosureTypeBase + 17)

	// EvidenceFile -> Case, graphene's built-in edge for exactly that.
	disclosureEdgeBelongsTo = store.EdgeTypeBelongsTo
)

// disclosureTypeNames is what DeclareTypeNames writes beside the ledger, so
// the store says what 36870 means to anybody who opens it without this
// program -- which, for a ledger handed to a court, is everybody.
func disclosureTypeNames() (map[store.NodeType]string, map[store.EdgeType]string) {
	return map[store.NodeType]string{
			disclosureNodeActor:      "Actor",
			disclosureNodeRecord:     "Record",
			disclosureNodeClass:      "Classification",
			disclosureNodeView:       "View",
			disclosureNodeRecipient:  "Recipient",
			disclosureNodeDisclosure: "Disclosure",
			disclosureNodeWithdrawal: "Withdrawal",
			disclosureNodeReclass:    "ReclassEvent",

			disclosureNodeRole:             "Role",
			disclosureNodeRoleBundle:       "RoleBundle",
			disclosureNodeAssignment:       "Assignment",
			disclosureNodeLifecycle:        "LifecycleEvent",
			disclosureNodeCustodyEvent:     "CustodyEvent",
			disclosureNodeReviewRequest:    "ReviewRequest",
			disclosureNodeReviewDecision:   "ReviewDecision",
			disclosureNodeRetention:        "RetentionEvent",
			disclosureNodeErasure:          "ErasureEvent",
			disclosureNodeClassEvent:       "ClassEvent",
			disclosureNodeRedactionVersion: "RedactionVersion",
			disclosureNodeRedactionReview:  "RedactionReview",
		}, map[store.EdgeType]string{
			disclosureEdgeInCase:       "IN_CASE",
			disclosureEdgeClassifiedAs: "CLASSIFIED_AS",
			disclosureEdgeGrants:       "GRANTS",
			disclosureEdgeDisclosedTo:  "DISCLOSED_TO",
			disclosureEdgeAuthorisedBy: "AUTHORISED_BY",
			disclosureEdgePerformedBy:  "PERFORMED_BY",
			disclosureEdgeWithdrew:     "WITHDREW",
			disclosureEdgeSupersedes:   "SUPERSEDES",

			disclosureEdgeHoldsRole:   "HOLDS_ROLE",
			disclosureEdgeAssignedTo:  "ASSIGNED_TO",
			disclosureEdgeBundles:     "BUNDLES",
			disclosureEdgeIssuedUnder: "ISSUED_UNDER",
			disclosureEdgeRedactedAs:  "REDACTED_AS",
			disclosureEdgeRevises:     "REVISES",
			disclosureEdgeTransitions: "TRANSITIONS",
			disclosureEdgeCustodian:   "CUSTODIAN",
			disclosureEdgeReviews:     "REVIEWS",
			disclosureEdgeErases:      "ERASES",
		}
}

// disclosureDeclareNames writes the family's label names beside the ledger on
// the first disclosure write of a session, and not again: graphene rewrites
// and fsyncs the whole table on every declaration, and nothing this program
// does while the ledger is open takes a name out of it. The caller holds
// disclosureLedgerMu.
func disclosureDeclareNames(session *ledgerSession) error {
	if session.disclosureNamesDeclared {
		return nil
	}
	nodes, edges := disclosureTypeNames()
	if err := session.graph.DeclareTypeNames(nodes, edges); err != nil {
		return err
	}
	session.disclosureNamesDeclared = true
	return nil
}

// disclosureLedgerMu serialises this family's ledger writes within the
// process. A find-then-add is two calls, and two spawned tasks disclosing the
// same record at once would otherwise both find no Record node and both add
// one. graphene's own lock already keeps a second PROCESS out of the store.
var disclosureLedgerMu sync.Mutex

// disclosureKeys are the properties the index holds for each label: the ones
// a lookup is made by. Everything else is in the blob only, which is where a
// property redaction reads -- so every property stays redactable, and the
// index does not carry the spans of every record ever disclosed.
var disclosureKeys = map[store.NodeType][]string{
	disclosureNodeCase:       {"case.uid"},
	disclosureNodeActor:      {"actor.id"},
	disclosureNodeRecord:     {"record.uid"},
	disclosureNodeClass:      {"class.tag"},
	disclosureNodeView:       {"view.fp"},
	disclosureNodeRecipient:  {"recipient.fp"},
	disclosureNodeDisclosure: {"disclosure.uid", "disclosure.record_uid", "disclosure.recipient_fp"},
	disclosureNodeWithdrawal: {"withdrawal.uid", "withdrawal.disclosure_uid"},
	disclosureNodeReclass:    {"reclass.uid", "reclass.pair", "reclass.superseded_uid"},

	disclosureNodeRole:             {"role.name"},
	disclosureNodeRoleBundle:       {"bundle.fp"},
	disclosureNodeLifecycle:        {"lifecycle.uid", "lifecycle.chain"},
	disclosureNodeAssignment:       {"assignment.uid", "assignment.chain", "assignment.case_uid"},
	disclosureNodeEvidence:         {"evidence.uid", "evidence.case_uid"},
	disclosureNodeCustodyEvent:     {"custody.uid", "custody.chain"},
	disclosureNodeRedactionVersion: {"redaction.uid", "redaction.chain", "redaction.line"},
	disclosureNodeClassEvent:       {"classify.uid", "classify.chain", "classify.case_uid", "classify.target"},
	disclosureNodeRedactionReview:  {"redaction_review.uid", "redaction_review.chain"},
	disclosureNodeReviewRequest:    {"review.uid", "review.chain"},
	disclosureNodeReviewDecision:   {"decision.uid", "decision.chain"},
	disclosureNodeRetention:        {"retention.uid", "retention.chain"},
}

// disclosureNode is one node of this schema as read back: its id and its
// properties as strings, which is the only kind this schema writes.
type disclosureNode struct {
	id    store.NodeID
	props map[string]string
}

func (n disclosureNode) get(key string) string { return n.props[key] }

func disclosureStringProps(props map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(props))
	for key, value := range props {
		out[key] = []byte(value)
	}
	return out
}

// disclosureDecode reads a node's blob back into strings.
func disclosureDecode(node *store.Node) (disclosureNode, error) {
	raw, err := ledgerDecodeProperties(node.Properties)
	if err != nil {
		return disclosureNode{}, err
	}
	props := make(map[string]string, len(raw))
	for key, value := range raw {
		props[key] = string(value)
	}
	return disclosureNode{id: node.ID, props: props}, nil
}

// disclosureFind returns the node carrying label whose key property is value.
//
// Filtered on the label, so a node a script wrote with the same property is
// not found. More than one match is an error and not a choice: this schema
// writes each key once, so two nodes for one key mean the ledger holds
// something this family did not write, and picking one would be deciding
// which of two records of a disclosure is the true one.
func disclosureFind(g *graphene.Graph, label store.NodeType, key, value string) (disclosureNode, bool, error) {
	ids, err := g.NodesByProperty(key, []byte(value))
	if err != nil {
		return disclosureNode{}, false, err
	}
	if len(ids) == 0 {
		return disclosureNode{}, false, nil
	}
	nodes, _, err := g.GetNodes(ids)
	if err != nil {
		return disclosureNode{}, false, err
	}
	var matches []*store.Node
	for _, node := range nodes {
		if node.HasLabel(label) {
			matches = append(matches, node)
		}
	}
	switch len(matches) {
	case 0:
		return disclosureNode{}, false, nil
	case 1:
		decoded, err := disclosureDecode(matches[0])
		return decoded, err == nil, err
	default:
		return disclosureNode{}, false, fmt.Errorf("the ledger holds %d %s nodes for %s = %s, and this family "+
			"writes each one once; the ledger has been written to by something other than disclose_*",
			len(matches), label.String(), key, value)
	}
}

// disclosureAll returns every node carrying a label, decoded, in id order.
func disclosureAll(g *graphene.Graph, label store.NodeType) ([]disclosureNode, error) {
	nodes, err := g.QueryNodes(store.NodeQuery{Types: []store.NodeType{label}})
	if err != nil {
		return nil, err
	}
	out := make([]disclosureNode, 0, len(nodes))
	for _, node := range nodes {
		decoded, err := disclosureDecode(node)
		if err != nil {
			return nil, fmt.Errorf("node %d: %w", node.ID, err)
		}
		out = append(out, decoded)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

// disclosureTx buffers one transaction's worth of this schema's writes.
type disclosureTx struct {
	tx *graphene.Tx
	// added is every node findOrAdd has buffered in this transaction, by
	// label, key and value. The graph cannot see a buffered node until the
	// commit, so without it a second findOrAdd of the same key in the same
	// transaction -- an examiner who is both the actor and the authority,
	// or both the assigner and the assignee -- adds a second node, and every
	// later lookup of that key refuses the ledger (M26-REC-021).
	added map[string]disclosureNode
}

func disclosureBegin(session *ledgerSession) *disclosureTx {
	return &disclosureTx{tx: session.graph.Begin().As(session.txContext()), added: map[string]disclosureNode{}}
}

// actorNode finds or adds the Actor node for an asserted name. The id is the
// one ledger_open derives, so the actor who opened the ledger and an authority
// named by the same string are the same node.
func (d *disclosureTx) actorNode(g *graphene.Graph, name string) (store.NodeID, error) {
	id, _, err := d.findOrAdd(g, disclosureNodeActor, "actor.id", map[string]string{
		"actor.id":   strconv.FormatUint(ledgerIDFrom([]byte(name)), 10),
		"actor.name": name,
	})
	return id, err
}

// disclosurePerformedBy is what every PERFORMED_BY edge carries: the role the
// actor said they were acting under. On the edge, because one Actor node
// stands for one name across every act, and the role belongs to the act.
func disclosurePerformedBy(session *ledgerSession) map[string]string {
	return map[string]string{"role": session.role.Name}
}

// node adds one node, its whole property map in the blob and only its lookup
// keys in the index.
func (d *disclosureTx) node(label store.NodeType, props map[string]string) (store.NodeID, error) {
	raw := disclosureStringProps(props)
	blob, err := ledgerPropertyBlob(raw)
	if err != nil {
		return 0, err
	}
	id := d.tx.AddNode(&store.Node{Labels: []store.NodeType{label}, Properties: blob})
	indexed := map[string][]byte{}
	for _, key := range disclosureKeys[label] {
		if value, ok := raw[key]; ok {
			indexed[key] = value
		}
	}
	if len(indexed) > 0 {
		d.tx.IndexNodeProperties(id, indexed)
	}
	return id, nil
}

// edge adds one edge. Edge properties are in the blob only; nothing looks an
// edge up by them.
func (d *disclosureTx) edge(src, dst store.NodeID, label store.EdgeType, props map[string]string) error {
	var blob []byte
	if len(props) > 0 {
		var err error
		if blob, err = ledgerPropertyBlob(disclosureStringProps(props)); err != nil {
			return err
		}
	}
	d.tx.AddEdge(&store.Edge{Src: src, Dst: dst, Labels: []store.EdgeType{label}, Properties: blob})
	return nil
}

// findOrAdd reuses a node this schema already wrote under the same key, or
// buffers a new one.
//
// When one is found, the properties named in mustMatch are compared with the
// ones about to be written, and a disagreement is refused. The rest are not
// compared: they are documentary -- a class's label, a view's description --
// and a node written once keeps the words it was first written with.
func (d *disclosureTx) findOrAdd(g *graphene.Graph, label store.NodeType, key string, props map[string]string,
	mustMatch ...string) (store.NodeID, bool, error) {
	buffered := fmt.Sprintf("%d|%s|%s", label, key, props[key])
	found, ok := d.added[buffered]
	if !ok {
		var err error
		if found, ok, err = disclosureFind(g, label, key, props[key]); err != nil {
			return 0, false, err
		}
	}
	if ok {
		for _, field := range mustMatch {
			if found.get(field) != props[field] {
				return 0, false, fmt.Errorf("the ledger already records %s %s with %s = %q, and this one has %q. "+
					"A node here is written once and never updated, so the two cannot be reconciled by "+
					"overwriting either", label.String(), props[key], field, found.get(field), props[field])
			}
		}
		return found.id, false, nil
	}
	id, err := d.node(label, props)
	if err == nil {
		d.added[buffered] = disclosureNode{id: id, props: props}
	}
	return id, true, err
}

func (d *disclosureTx) commit() error { return d.tx.Commit() }

// classNodes returns a finder for Classification nodes that reuses each one
// within the transaction, so a class that appears in a record and in a view
// is one node and not two.
func (d *disclosureTx) classNodes(g *graphene.Graph, labels map[string]string) func(string) (store.NodeID, error) {
	ids := map[string]store.NodeID{}
	return func(tag string) (store.NodeID, error) {
		if id, ok := ids[tag]; ok {
			return id, nil
		}
		id, _, err := d.findOrAdd(g, disclosureNodeClass, "class.tag", map[string]string{
			"class.tag":   tag,
			"class.label": labels[tag],
		})
		if err == nil {
			ids[tag] = id
		}
		return id, err
	}
}

// viewNode finds or adds a view's node, and on adding it writes one GRANTS edge
// per class the view grants.
func (d *disclosureTx) viewNode(g *graphene.Graph, view caseView, fp string,
	classNode func(string) (store.NodeID, error)) (store.NodeID, error) {
	viewID, viewNew, err := d.findOrAdd(g, disclosureNodeView, "view.fp", map[string]string{
		"view.fp":          fp,
		"view.label":       view.Label,
		"view.canonical":   view.Canonical,
		"view.classes":     strings.Join(view.Classes, ", "),
		"view.tags":        strings.Join(view.Tags, ","),
		"view.description": view.Description,
	})
	if err != nil || !viewNew {
		return viewID, err
	}
	for _, tag := range view.Tags {
		id, err := classNode(strings.ToLower(tag))
		if err != nil {
			return 0, err
		}
		if err := d.edge(viewID, id, disclosureEdgeGrants, nil); err != nil {
			return 0, err
		}
	}
	return viewID, nil
}

// disclosureRecordFacts is what a Record node says about a record file.
type disclosureRecordFacts struct {
	record       *recordSession
	sha256       string
	bytes        int64
	headerSHA256 string
	classes      []disclosureClassTally
}

// recordNode finds or adds a record's node, and on adding it writes the
// record's IN_CASE edge and one CLASSIFIED_AS edge per class it carries.
//
// A Record node already in the ledger under the same uid must name the same
// file digest and the same header digest. Anything else is a different file
// claiming the same identity, and the ledger's account of the first is not
// overwritten to make room for it.
func (d *disclosureTx) recordNode(g *graphene.Graph, facts disclosureRecordFacts, caseID store.NodeID,
	classNode func(string) (store.NodeID, error)) (store.NodeID, error) {
	header := facts.record.header
	spans, err := disclosureSpansText(facts.record)
	if err != nil {
		return 0, err
	}
	recordID, recordNew, err := d.findOrAdd(g, disclosureNodeRecord, "record.uid", map[string]string{
		"record.uid":              strings.ToLower(header.RecordUID),
		"record.case_uid":         strings.ToLower(header.CaseUID),
		"record.sha256":           facts.sha256,
		"record.header_sha256":    facts.headerSHA256,
		"record.bytes":            strconv.FormatInt(facts.bytes, 10),
		"record.segments":         strconv.Itoa(len(facts.record.segments)),
		"record.segment_size":     strconv.FormatUint(uint64(header.SegmentSize), 10),
		"record.plaintext_length": strconv.FormatUint(header.PlaintextLength, 10),
		"record.spans":            spans,
		"record.created":          header.Created,
		"record.examiner":         header.Examiner,
		"record.signed":           strconv.FormatBool(facts.record.signed),
		"record.public_key":       facts.record.footer.PublicKey,
	}, "record.sha256", "record.header_sha256")
	if err != nil || !recordNew {
		return recordID, err
	}
	if err := d.edge(recordID, caseID, disclosureEdgeInCase, nil); err != nil {
		return 0, err
	}
	for _, tally := range facts.classes {
		id, err := classNode(tally.tag)
		if err != nil {
			return 0, err
		}
		if err := d.edge(recordID, id, disclosureEdgeClassifiedAs, map[string]string{
			"segments": strconv.FormatInt(tally.segments, 10),
			"bytes":    strconv.FormatUint(tally.bytes, 10),
		}); err != nil {
			return 0, err
		}
	}
	return recordID, nil
}

// ---------------------------------------------------------------------------
// Runs: the granted set as text
// ---------------------------------------------------------------------------

// disclosureRunsText renders segment runs as "0-2,5,9-11": short enough to sit
// in a node property, exact enough to be parsed back, and readable in a
// listing by somebody who has never seen this code.
func disclosureRunsText(runs [][2]uint64) string {
	parts := make([]string, 0, len(runs))
	for _, run := range runs {
		if run[0] == run[1] {
			parts = append(parts, strconv.FormatUint(run[0], 10))
			continue
		}
		parts = append(parts, strconv.FormatUint(run[0], 10)+"-"+strconv.FormatUint(run[1], 10))
	}
	return strings.Join(parts, ",")
}

// disclosureParseRuns reads runs back, refusing anything but the one canonical
// spelling disclosureRunsText produces: ascending, disjoint, maximal.
func disclosureParseRuns(text string) ([][2]uint64, error) {
	runs := [][2]uint64{}
	if text == "" {
		return runs, nil
	}
	for i, part := range strings.Split(text, ",") {
		first, last := part, part
		if dash := strings.IndexByte(part, '-'); dash >= 0 {
			first, last = part[:dash], part[dash+1:]
		}
		a, err := strconv.ParseUint(first, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("run %d %q is not a segment index", i, part)
		}
		b, err := strconv.ParseUint(last, 10, 64)
		if err != nil || b < a {
			return nil, fmt.Errorf("run %d %q is not a run of segment indices", i, part)
		}
		if n := len(runs); n > 0 && a <= runs[n-1][1]+1 {
			return nil, fmt.Errorf("run %d %q overlaps or adjoins the run before it", i, part)
		}
		runs = append(runs, [2]uint64{a, b})
	}
	return runs, nil
}

// disclosureRunsContain reports whether a segment index is in a run list.
func disclosureRunsContain(runs [][2]uint64, index uint64) bool {
	i := sort.Search(len(runs), func(i int) bool { return runs[i][1] >= index })
	return i < len(runs) && runs[i][0] <= index
}

// ---------------------------------------------------------------------------
// Writing a disclosure
// ---------------------------------------------------------------------------

// disclosureIssue is everything a disclosure writes, gathered before the
// transaction starts so that nothing in the transaction can fail on a lookup
// half way through.
type disclosureIssue struct {
	uid      string
	caseUID  string
	caseID   string
	examiner string
	// actorRole is the role of the ledger's actor, who records the disclosure.
	actorRole string

	recipient   string
	recipientFP string
	// basis is the recipient's assignment and the bundle of the role it
	// names, as the preflight read them.
	basis disclosureBasis

	view       caseView
	viewFP     string
	classLabel map[string]string // tag -> label, for every tag written
	partition  redactionPartition
	// redactionUID and redactionVersion name the version of the record's
	// redaction the disclosure is issued under. disclosureWriteIssue sets
	// them, reusing the version in force or writing the next.
	redactionUID     string
	redactionVersion uint64

	record        *recordSession
	recordSHA256  string
	recordBytes   int64
	headerSHA256  string
	recordClasses []disclosureClassTally

	runs            [][2]uint64
	grantedSegments int64
	grantedBytes    uint64
	withheldBytes   uint64
	grantSHA256     string
	descriptorsRoot string

	at string
	ns int64
}

// disclosureClassTally is one class as it appears in one record.
type disclosureClassTally struct {
	tag      string
	segments int64
	bytes    uint64
}

// disclosureNodeProps is the Disclosure node's property map. It is a function
// of the issue alone, so the manifest can carry the same map and a recipient
// can recompute the hash a ledger proof commits to.
func disclosureNodeProps(issue *disclosureIssue) map[string]string {
	total := int64(len(issue.record.segments))
	return map[string]string{
		"disclosure.uid":               issue.uid,
		"disclosure.case_uid":          issue.caseUID,
		"disclosure.record_uid":        strings.ToLower(issue.record.header.RecordUID),
		"disclosure.record_sha256":     issue.recordSHA256,
		"disclosure.recipient":         issue.recipient,
		"disclosure.recipient_fp":      issue.recipientFP,
		"disclosure.view":              issue.view.Label,
		"disclosure.view_fp":           issue.viewFP,
		"disclosure.method":            "passphrase",
		"disclosure.granted_runs":      disclosureRunsText(issue.runs),
		"disclosure.segments":          strconv.FormatInt(total, 10),
		"disclosure.granted_segments":  strconv.FormatInt(issue.grantedSegments, 10),
		"disclosure.withheld_segments": strconv.FormatInt(total-issue.grantedSegments, 10),
		"disclosure.granted_bytes":     strconv.FormatUint(issue.grantedBytes, 10),
		"disclosure.withheld_bytes":    strconv.FormatUint(issue.withheldBytes, 10),
		"disclosure.grant_sha256":      issue.grantSHA256,
		"disclosure.descriptors_root":  issue.descriptorsRoot,
		"disclosure.examiner":          issue.examiner,
		"disclosure.actor_role":        issue.actorRole,
		"disclosure.at":                issue.at,
		"disclosure.unix_nano":         strconv.FormatInt(issue.ns, 10),
		// The recipient's side: the role the ledger assigned them, the
		// assignment that says so, the bundle the view was found in, and the
		// version of the record's redaction the grant carries out.
		"disclosure.role":              issue.basis.role.Name,
		"disclosure.assignment_uid":    issue.basis.assignment.head.uid,
		"disclosure.role_bundle_fp":    issue.basis.bundle.fingerprint(),
		"disclosure.redaction_uid":     issue.redactionUID,
		"disclosure.redaction_version": strconv.FormatUint(issue.redactionVersion, 10),
	}
}

// disclosureViewFingerprint names a posture by what it grants, not by its
// label. Two sessions can declare "counsel" over different classes, and those
// are two postures; keying the View node by label would make the second
// disclosure under the name point at the first posture's grant list.
func disclosureViewFingerprint(view caseView) string {
	tags := append([]string(nil), view.Tags...)
	for i := range tags {
		tags[i] = strings.ToLower(tags[i])
	}
	sort.Strings(tags)
	return ledgerHash(sha256Of("mutant-view-v1|" + view.Canonical + "|" + strings.Join(tags, ",")))
}

// disclosureRecipientFingerprint names a recipient by the exact string the
// examiner asserted. It authenticates nothing: it is how the ledger says "the
// same name" without a reader having to compare free text.
func disclosureRecipientFingerprint(name string) string {
	return ledgerHash(sha256Of("mutant-recipient-v1|" + name))
}

// disclosureRefusal says why the ledger rules out disclosing this record to
// this recipient, or returns the recipient's assignment in force: the case's
// lifecycle state takes no disclosure; the ledger holds redactions made before
// its disclosure schema was guarded that no review answers for, any of which
// could have removed what the checks after it read (M26-CUS-021); the record
// was reclassified, so its classification is not the one in force; an earlier
// disclosure of it to them was withdrawn; or the ledger assigns them no
// recipient role in the case.
func disclosureRefusal(session *ledgerSession, record *recordSession, recipient string) (caseAssignment, error) {
	g := session.graph
	if err := caseLedgerStateRefusal(g, record.header.CaseUID, caseActDisclose); err != nil {
		return caseAssignment{}, err
	}
	if err := ledgerUnreviewedRefusal(session); err != nil {
		return caseAssignment{}, err
	}
	recordUID := strings.ToLower(record.header.RecordUID)
	if event, superseded, err := disclosureFind(g, disclosureNodeReclass, "reclass.superseded_uid", recordUID); err != nil {
		return caseAssignment{}, err
	} else if superseded {
		return caseAssignment{}, fmt.Errorf("record %s was reclassified by record %s at %s, so its "+
			"classification is not the one in force. Disclose the record that superseded it",
			record.header.RecordUID, event.get("reclass.record_uid"), event.get("reclass.at"))
	}
	if withdrawn, err := disclosureWithdrawnFor(g, recordUID, disclosureRecipientFingerprint(recipient)); err != nil {
		return caseAssignment{}, err
	} else if withdrawn != "" {
		return caseAssignment{}, fmt.Errorf("an earlier disclosure of record %s to %q was withdrawn (%s), and a "+
			"withdrawal is how further grants are stopped. To disclose to them again, seal a new record -- "+
			"which is what a changed classification is anyway -- and disclose that",
			record.header.RecordUID, recipient, withdrawn)
	}
	assignment, found, err := recipientAssignmentOf(g, record.header.CaseUID, recipient)
	switch {
	case err != nil:
		return caseAssignment{}, err
	case !found:
		return caseAssignment{}, fmt.Errorf("the ledger assigns %q no recipient role in this case, and a grant "+
			"is issued against the bundle of the role its recipient holds, so a recipient nobody assigned is "+
			"granted nothing. role_assign(ledger, recipient, role, reason) records one, for the name exactly "+
			"as it is given here. %s", recipient, roleNotAccessControl)
	case assignment.role == caseAssignmentEnded:
		return caseAssignment{}, fmt.Errorf("%q's recipient role in this case was ended at %s (%q), and a "+
			"recipient who holds none is granted nothing. %s", recipient, assignment.head.get("assignment.at"),
			assignment.head.get("assignment.reason"), roleNotAccessControl)
	}
	return assignment, nil
}

// disclosurePreflight asks for every refusal before anything is spent on the
// disclosure: before a grant's key material is derived, and before the
// examiner is asked to choose a passphrase for it. DISCLOSURE_POLICY promises
// that a withdrawal is checked before any new key is issued, and a recipient
// whose role may not be given the view is refused at the same point.
func disclosurePreflight(op string, session *ledgerSession, record *recordSession, recipient string,
	view caseView) (disclosureBasis, *object.Error) {
	bundles, errObj := disclosureRecipientTerms(op, session)
	if errObj != nil {
		return disclosureBasis{}, errObj
	}
	disclosureLedgerMu.Lock()
	assignment, err := disclosureRefusal(session, record, recipient)
	if err == nil {
		// Read now for the reason the rest is: a version chain the ledger
		// cannot give an account of refuses the disclosure at the write, and
		// is found here instead, before the key.
		_, _, _, err = redactionResolve(session, record.header.CaseUID, record.header.RecordUID, view,
			redactionPartition{})
	}
	disclosureLedgerMu.Unlock()
	if err != nil {
		return disclosureBasis{}, newError("%s: %s", op, err.Error())
	}
	return disclosureBasisFor(op, recipient, assignment, view, bundles)
}

// disclosureWriteIssue commits one disclosure: the Disclosure node; whatever
// Case, Actor, Record, Classification, View, Recipient and RoleBundle nodes
// the ledger does not already hold; the version of the record's redaction it
// is issued under, when the one in force does not divide the record as this
// grant does; and the edges between them, in one signed transaction.
func disclosureWriteIssue(session *ledgerSession, issue *disclosureIssue) (store.NodeID, error) {
	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()

	g := session.graph
	if err := disclosureDeclareNames(session); err != nil {
		return 0, err
	}
	// disclosurePreflight asked this before the grant was issued; asked again
	// under the lock for a withdrawal, a reclassification or a change to the
	// recipient's assignment recorded since.
	assignment, err := disclosureRefusal(session, issue.record, issue.recipient)
	if err != nil {
		return 0, err
	}
	if assignment.head.uid != issue.basis.assignment.head.uid {
		return 0, fmt.Errorf("the ledger's assignment of %q changed while this disclosure was prepared: it now "+
			"names them %s, recorded at %s, and the disclosure was checked against %s. Nothing was issued; "+
			"disclose again", issue.recipient, assignment.role, assignment.head.get("assignment.at"),
			issue.basis.assignment.role)
	}
	recordUID := strings.ToLower(issue.record.header.RecordUID)
	line, versions, version, err := redactionResolve(session, issue.caseUID, recordUID, issue.view, issue.partition)
	if err != nil {
		return 0, err
	}

	w, err := caseBeginWrite(session, issue.caseUID, issue.caseID, time.Unix(0, issue.ns))
	if err != nil {
		return 0, err
	}
	tx := w.tx
	classNode := tx.classNodes(g, issue.classLabel)
	recordID, err := tx.recordNode(g, disclosureRecordFacts{
		record:       issue.record,
		sha256:       issue.recordSHA256,
		bytes:        issue.recordBytes,
		headerSHA256: issue.headerSHA256,
		classes:      issue.recordClasses,
	}, w.caseN, classNode)
	if err != nil {
		return 0, err
	}

	viewID, err := tx.viewNode(g, issue.view, issue.viewFP, classNode)
	if err != nil {
		return 0, err
	}

	recipientID, _, err := tx.findOrAdd(g, disclosureNodeRecipient, "recipient.fp", map[string]string{
		"recipient.fp":   issue.recipientFP,
		"recipient.name": issue.recipient,
	})
	if err != nil {
		return 0, err
	}
	bundleID, err := tx.bundleNode(g, issue.basis.bundle, classNode)
	if err != nil {
		return 0, err
	}
	if version == nil {
		next, err := w.redactionAppend(caseChainHead(versions), redactionTerms{
			line:      line,
			view:      issue.view,
			record:    issue.record,
			partition: issue.partition,
			runs:      issue.runs,
			reason:    "issued with disclosure " + issue.uid,
		}, recordID, viewID)
		if err != nil {
			return 0, err
		}
		version = &next
	}
	issue.redactionUID, issue.redactionVersion = version.uid, version.seq

	disclosureID, err := tx.node(disclosureNodeDisclosure, disclosureNodeProps(issue))
	if err != nil {
		return 0, err
	}
	for _, e := range []struct {
		dst   store.NodeID
		label store.EdgeType
		props map[string]string
	}{
		{w.caseN, disclosureEdgeInCase, nil},
		{recordID, disclosureEdgeGrants, map[string]string{"granted_runs": disclosureRunsText(issue.runs)}},
		{recipientID, disclosureEdgeDisclosedTo, nil},
		{viewID, disclosureEdgeAuthorisedBy, nil},
		{w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(session)},
		{bundleID, disclosureEdgeIssuedUnder, nil},
		{version.id, disclosureEdgeRedactedAs, nil},
	} {
		if err := tx.edge(disclosureID, e.dst, e.label, e.props); err != nil {
			return 0, err
		}
	}
	if err := tx.commit(); err != nil {
		return 0, err
	}
	return disclosureID, nil
}

// disclosureSpansText renders a record's spans as "offset+length:tag;..." for
// the Record node, so that what a record classified where is in the ledger
// with the record rather than only in a file that may not be there later.
func disclosureSpansText(record *recordSession) (string, error) {
	parts := make([]string, 0, len(record.header.Spans))
	for _, span := range record.header.Spans {
		if _, err := hex.DecodeString(span.Class); err != nil {
			return "", errors.New("a span's class is not a tag")
		}
		parts = append(parts, fmt.Sprintf("%d+%d:%s", span.Offset, span.Length, strings.ToLower(span.Class)))
	}
	return strings.Join(parts, ";"), nil
}

// ---------------------------------------------------------------------------
// Withdrawals
// ---------------------------------------------------------------------------

// disclosureWithdrawalOf returns the withdrawal of a disclosure, if there is one.
func disclosureWithdrawalOf(g *graphene.Graph, uid string) (disclosureNode, bool, error) {
	return disclosureFind(g, disclosureNodeWithdrawal, "withdrawal.disclosure_uid", uid)
}

// disclosureWithdrawnFor reports the uid and time of a withdrawn disclosure of
// this record to this recipient, or "" when there is none.
//
// Asked of the Withdrawal nodes, which name the record and the recipient
// themselves, and not through the Disclosure each withdraws: a disclosure a
// redaction removed before the schema was guarded (M26-CUS-021) took its
// index entries with it, and its withdrawal, still in the ledger, still stops
// a new grant.
func disclosureWithdrawnFor(g *graphene.Graph, recordUID, recipientFP string) (string, error) {
	withdrawals, err := disclosureAll(g, disclosureNodeWithdrawal)
	if err != nil {
		return "", err
	}
	for _, withdrawal := range withdrawals {
		if withdrawal.get("withdrawal.record_uid") == recordUID &&
			disclosureRecipientFingerprint(withdrawal.get("withdrawal.recipient")) == recipientFP {
			return fmt.Sprintf("disclosure %s, withdrawn at %s", withdrawal.get("withdrawal.disclosure_uid"),
				withdrawal.get("withdrawal.at")), nil
		}
	}
	return "", nil
}
