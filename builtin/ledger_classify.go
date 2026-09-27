package builtin

// Classifying what a script wrote into the ledger, so that a read under a view
// can show it.
//
// A record's segments carry their classes inside the record. A node a script
// wrote with ledger_add_node carries none, and `ledger_classify` gives it some
// in the open case: the case's declared classes, named by label and recorded
// by tag, so a classification made under one case's key means nothing under
// another's. A read under a view (ledger_view.go) shows a script node only when
// its classification is within the classes the view grants. A node nobody
// classified is shown by no view, and neither is one classified as holding
// nothing -- which is legal, and says so, because "examined, and nothing here
// is for anybody" is a decision worth recording.
//
// # A chain per node, naming the node by property and never by edge
//
// Each node's classifications in a case are one hash-linked chain of ClassEvent
// nodes (case_chain.go): the head is the classification in force, and a
// reclassification is the next event. The event names the node it classifies
// by id, in a property, and no edge joins the two. An edge would make the
// node's redaction reach into the schema: graphene takes a node's edges with
// it, and ledger_redact_node refuses a node whose removal would take an edge of
// the schema (ledgerSchemaSubject) -- so a classified node could never be
// redacted, which is the one thing a classification must not cost. An id names
// one node for good: graphene hands each out once, and its image carries the
// high-water mark, so a deleted node's id is never given to another.
//
// # Not access control
//
// A classification decides what a read under a view shows, and the program
// reading under a view holds the ledger's own handle too. It is recorded,
// signed and attributed like every case record, and it limits what a report
// built through a view can carry; it keeps nothing from anyone with the ledger.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
	"mutant/security"
)

// classifyChain is the chain of one node's classifications in one case.
var classifyChain = caseChainSpec{disclosureNodeClassEvent, "classify"}

// classifyChainKey names the chain of one node's classifications in one case.
func classifyChainKey(caseUID string, node store.NodeID) string {
	return strings.ToLower(caseUID) + "|" + strconv.FormatUint(uint64(node), 10)
}

// classifyChainParts reads a chain key back into its case and node, and
// refuses one this program would not have written.
func classifyChainParts(chain string) (string, store.NodeID, bool) {
	cut := strings.LastIndexByte(chain, '|')
	if cut <= 0 {
		return "", 0, false
	}
	id, err := strconv.ParseUint(chain[cut+1:], 10, 64)
	if err != nil || id == 0 || classifyChainKey(chain[:cut], store.NodeID(id)) != chain {
		return "", 0, false
	}
	return chain[:cut], store.NodeID(id), true
}

// classifyEvent is one classification as read back: the event, and the
// classes it records -- tags and their labels, index for index, in tag order.
type classifyEvent struct {
	caseChainEvent
	tags   []string
	labels []string
}

// ledgerClassification is one node's classifications in one case, first to
// head.
type ledgerClassification struct {
	caseUID string
	node    store.NodeID
	events  []classifyEvent
}

func (c ledgerClassification) head() *classifyEvent {
	if len(c.events) == 0 {
		return nil
	}
	return &c.events[len(c.events)-1]
}

// tags and labels are the classes in force: none for a node never classified,
// and none for one classified as holding nothing.
func (c ledgerClassification) tags() []string {
	if head := c.head(); head != nil {
		return head.tags
	}
	return nil
}

func (c ledgerClassification) labels() []string {
	if head := c.head(); head != nil {
		return head.labels
	}
	return nil
}

// classifyTerms reads the classes one event records, and refuses terms this
// program does not write: a tag that is not the lower-case hex of a class tag,
// tags out of order or repeated, or labels that are not a JSON list as long as
// the tags.
func classifyTerms(event caseChainEvent) (tags, labels []string, err error) {
	if text := event.get("classify.tags"); text != "" {
		tags = strings.Split(text, ",")
	}
	for i, tag := range tags {
		if _, decodeErr := hex.DecodeString(tag); decodeErr != nil || len(tag) != 2*len(security.ClassTag{}) ||
			strings.ToLower(tag) != tag {
			return nil, nil, fmt.Errorf("it records %q as a class tag", tag)
		}
		if i > 0 && tags[i-1] >= tag {
			return nil, nil, fmt.Errorf("its class tags are not in ascending order, each once")
		}
	}
	if err := json.Unmarshal([]byte(event.get("classify.classes")), &labels); err != nil {
		return nil, nil, fmt.Errorf("its class labels are not a list: %w", err)
	}
	if len(labels) != len(tags) {
		return nil, nil, fmt.Errorf("it records %d class labels for %d class tags", len(labels), len(tags))
	}
	return tags, labels, nil
}

// classificationRead reads one node's classifications in one case. Beyond the
// chain's own checks (caseChainRead), every event must say it classifies this
// node in this case, in terms classifyTerms accepts. A node never classified
// is no events and no error.
func classificationRead(g caseChainSource, caseUID string, node store.NodeID) (ledgerClassification, error) {
	caseUID = strings.ToLower(caseUID)
	out := ledgerClassification{caseUID: caseUID, node: node}
	events, err := caseChainRead(g, classifyChain, classifyChainKey(caseUID, node))
	if err != nil {
		return out, err
	}
	target := strconv.FormatUint(uint64(node), 10)
	for _, event := range events {
		if event.get("classify.case_uid") != caseUID || event.get("classify.target") != target {
			return out, fmt.Errorf("classification event node %d is kept with node %d's classifications in case %s, "+
				"and says it classifies node %s in case %s", event.id, node, caseUID, event.get("classify.target"),
				event.get("classify.case_uid"))
		}
		tags, labels, err := classifyTerms(event)
		if err != nil {
			return out, fmt.Errorf("classification event node %d: %w", event.id, err)
		}
		out.events = append(out.events, classifyEvent{caseChainEvent: event, tags: tags, labels: labels})
	}
	return out, nil
}

// classificationsRead reads the classifications of every node classified in a
// case, or in every case when caseUID is empty -- or of node alone, when node
// is not zero -- sorted by case and then node.
func classificationsRead(g *graphene.Graph, caseUID string, node store.NodeID) ([]ledgerClassification, error) {
	caseUID = strings.ToLower(caseUID)
	var ids []store.NodeID
	var err error
	switch {
	case node != 0:
		ids, err = g.NodesByProperty("classify.target", []byte(strconv.FormatUint(uint64(node), 10)))
	case caseUID != "":
		ids, err = g.NodesByProperty("classify.case_uid", []byte(caseUID))
	default:
		ids, err = g.QueryNodeIDs(store.NodeQuery{Types: []store.NodeType{disclosureNodeClassEvent}})
	}
	if err != nil {
		return nil, err
	}
	nodes, _, err := g.GetNodes(ids)
	if err != nil {
		return nil, err
	}
	chains := map[string]bool{}
	for _, n := range nodes {
		if !n.HasLabel(disclosureNodeClassEvent) {
			continue
		}
		decoded, err := disclosureDecode(n)
		if err != nil {
			return nil, fmt.Errorf("classification event node %d: %w", n.ID, err)
		}
		chains[decoded.get("classify.chain")] = true
	}
	out := make([]ledgerClassification, 0, len(chains))
	for chain := range chains {
		chainCase, chainNode, ok := classifyChainParts(chain)
		if !ok {
			return nil, fmt.Errorf("the ledger holds a classification event kept under %q, which names a case and "+
				"a node in no way this program names them", chain)
		}
		// An event found by the node or the case it names, kept in another's
		// chain, is read -- and refused -- with that one.
		if (caseUID != "" && chainCase != caseUID) || (node != 0 && chainNode != node) {
			continue
		}
		classification, err := classificationRead(g, chainCase, chainNode)
		if err != nil {
			return nil, err
		}
		out = append(out, classification)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].caseUID != out[j].caseUID {
			return out[i].caseUID < out[j].caseUID
		}
		return out[i].node < out[j].node
	})
	return out, nil
}

// classifyLabelsText is the labels as the JSON list a ClassEvent keeps: a label
// may hold a comma, so no separator would do.
func classifyLabelsText(labels []string) (string, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(append([]string{}, labels...)); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// classifyTargetLabels is the labels a script wrote a node under, as the
// offsets it wrote them as. Documentary: the event names its node by id.
func classifyTargetLabels(labels []store.NodeType) string {
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		parts = append(parts, strconv.Itoa(int(label-store.NodeTypeCustomBase)))
	}
	return strings.Join(parts, ",")
}

// classify appends node's classification after head: the classes' tags and
// labels, index for index, in tag order, a CLASSIFIED_AS edge to each class,
// and no edge to the node.
func (w *caseWriter) classify(head *classifyEvent, node *store.Node, tags, labels []string, reason string) (classifyEvent, error) {
	classes, err := classifyLabelsText(labels)
	if err != nil {
		return classifyEvent{}, err
	}
	var previous *caseChainEvent
	if head != nil {
		previous = &head.caseChainEvent
	}
	id, event, err := w.tx.chainAppend(classifyChain, classifyChainKey(w.caseUID, node.ID), previous, map[string]string{
		"classify.case_uid":      w.caseUID,
		"classify.case_id":       w.caseID,
		"classify.target":        strconv.FormatUint(uint64(node.ID), 10),
		"classify.target_labels": classifyTargetLabels(node.Labels),
		"classify.tags":          strings.Join(tags, ","),
		"classify.classes":       classes,
		"classify.reason":        reason,
		"classify.by":            w.ledger.actor,
		"classify.by_role":       w.ledger.role.Name,
		"classify.at":            w.at.UTC().Format(time.RFC3339Nano),
		"classify.unix_nano":     strconv.FormatInt(w.at.UnixNano(), 10),
	})
	if err != nil {
		return classifyEvent{}, err
	}
	if err := w.tx.edge(id, w.caseN, disclosureEdgeInCase, nil); err != nil {
		return classifyEvent{}, err
	}
	if err := w.tx.edge(id, w.actorN, disclosureEdgePerformedBy, disclosurePerformedBy(w.ledger)); err != nil {
		return classifyEvent{}, err
	}
	byTag := make(map[string]string, len(tags))
	for i, tag := range tags {
		byTag[tag] = labels[i]
	}
	classNode := w.tx.classNodes(w.g, byTag)
	for _, tag := range tags {
		classID, err := classNode(tag)
		if err != nil {
			return classifyEvent{}, err
		}
		if err := w.tx.edge(id, classID, disclosureEdgeClassifiedAs, nil); err != nil {
			return classifyEvent{}, err
		}
	}
	return classifyEvent{caseChainEvent: event, tags: tags, labels: labels}, nil
}

// ---------------------------------------------------------------------------
// ledger_classify
// ---------------------------------------------------------------------------

// classifyClassesArg reads ledger_classify's classes: one label, or an ARRAY
// of them, which may be empty.
func classifyClassesArg(op string, arg object.Object) ([]string, *object.Error) {
	switch value := arg.(type) {
	case *object.String:
		return []string{value.Value}, nil
	case *object.Array:
		out := make([]string, 0, len(value.Elements))
		for i, element := range value.Elements {
			text, ok := element.(*object.String)
			if !ok {
				return nil, newError("%s: entry %d of the class list must be STRING, got %s. A node is classified "+
					"by the labels `class_define` declared", op, i+1, element.Type())
			}
			out = append(out, text.Value)
		}
		return out, nil
	default:
		return nil, newError("argument 3 to `%s` must be STRING or ARRAY, got %s", op, arg.Type())
	}
}

// classifyResolveLocked resolves the labels a classification names to the
// case's declared classes, and returns their tags and labels in tag order.
// The caller holds the store lock.
func classifyResolveLocked(op string, session *custodySession, names []string) (tags, labels []string, errObj *object.Error) {
	seen := make(map[string]string, len(names))
	type class struct{ tag, label string }
	classes := make([]class, 0, len(names))
	for i, name := range names {
		canonical, errObj := canonicalClassLabel(op, name)
		if errObj != nil {
			return nil, nil, errObj
		}
		if first, repeated := seen[canonical]; repeated {
			return nil, nil, newError("%s: entry %d names %q, which this classification already holds as %q. A "+
				"repeated class is a list whose author lost track of it, and collapsing it quietly would hide "+
				"exactly that", op, i+1, name, first)
		}
		declared, found := classByCanonicalLocked(session, canonical)
		if !found {
			return nil, nil, classifyUndeclaredClass(op, session, i+1, name)
		}
		seen[canonical] = name
		classes = append(classes, class{strings.ToLower(declared.Tag), declared.Label})
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].tag < classes[j].tag })
	tags, labels = make([]string, 0, len(classes)), make([]string, 0, len(classes))
	for _, c := range classes {
		tags, labels = append(tags, c.tag), append(labels, c.label)
	}
	return tags, labels, nil
}

// classifyUndeclaredClass is the refusal for a classification naming a class
// nobody declared, at the position that named it.
func classifyUndeclaredClass(op string, session *custodySession, position int, label string) *object.Error {
	declared := make([]string, 0, len(session.classes))
	for _, class := range session.classes {
		declared = append(declared, class.Label)
	}
	if len(declared) == 0 {
		return newError("%s: entry %d names %q, which is not a declared classification -- this case has declared "+
			"none. Call `class_define(label)` first, so that a typo is an error rather than a node no view shows",
			op, position, label)
	}
	return newError("%s: entry %d names %q, which is not a declared classification. This case declares %s",
		op, position, label, strings.Join(declared, ", "))
}

// classifyShownUnder names the declared views that show a node classified as
// tags: every view granting each of them. A node holding no class is shown by
// none.
func classifyShownUnder(views []caseView, tags []string) []string {
	out := []string{}
	if len(tags) == 0 {
		return out
	}
	for _, view := range views {
		grants := viewGrantedTags(view)
		shown := true
		for _, tag := range tags {
			if !grants[tag] {
				shown = false
				break
			}
		}
		if shown {
			out = append(out, view.Label)
		}
	}
	return out
}

// classifyLabelsProse renders a class list for a sentence.
func classifyLabelsProse(labels []string) string {
	if len(labels) == 0 {
		return "holding nothing"
	}
	quoted := make([]string, 0, len(labels))
	for _, label := range labels {
		quoted = append(quoted, strconv.Quote(label))
	}
	return strings.Join(quoted, ", ")
}

// LedgerClassify records which of the open case's classes a node a script
// wrote holds: ledger_classify(ledger, node, classes, reason).
func LedgerClassify(args ...object.Object) object.Object {
	op := BuiltinNameLedgerClassify
	if len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=4", len(args)))
	}
	ledger, errObj := ledgerWriteHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	nodeID, errObj := ledgerNodeArg(args[1], op, 2)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	names, errObj := classifyClassesArg(op, args[2])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	reason, errObj := caseTextArg(op, args[3], 4, "reason")
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	custodyStore.Lock()
	defer custodyStore.Unlock()
	session, errObj := openSessionLocked(op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if session.caseUID == "" {
		return resultAndError(nil, newError("%s: no case key is open; a node is classified under a case's classes, "+
			"which are tagged under its key, and a case is found in its ledger by the identity its key file carries. "+
			"Call `case_key_open(path)` first", op))
	}
	tags, labels, errObj := classifyResolveLocked(op, session, names)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	if errObj := session.ledgerElsewhereLocked(op, ledger); errObj != nil {
		return resultAndError(nil, errObj)
	}

	disclosureLedgerMu.Lock()
	defer disclosureLedgerMu.Unlock()
	g := ledger.graph
	fail := func(err error) object.Object { return resultAndError(nil, newError("%s: %s", op, err.Error())) }
	if err := disclosureDeclareNames(ledger); err != nil {
		return fail(err)
	}
	if err := caseLedgerStateRefusal(g, session.caseUID, caseActDefine); err != nil {
		return fail(err)
	}
	node, err := g.GetNode(nodeID)
	if err != nil {
		return resultAndError(nil, ledgerReadRefusal(ledger, err, nodeID, 0, op))
	}
	if !ledgerScriptNodeLabels(node.Labels) {
		return resultAndError(nil, newError("%s: node %d is a %s record, which this program writes; a script's "+
			"node is what is classified. A read under a view shows the case's Case and Record nodes by the case "+
			"they belong to, and a Classification node when the view grants its class", op, nodeID,
			ledgerSchemaNodeName(node.Labels)))
	}
	current, err := classificationRead(g, session.caseUID, nodeID)
	if err != nil {
		return fail(err)
	}
	head := current.head()
	if head != nil && slices.Equal(head.tags, tags) {
		return resultAndError(nil, newError("%s: node %d is already classified as %s in case %s", op, nodeID,
			classifyLabelsProse(labels), session.ID))
	}

	now := custodyNow()
	w, err := caseBeginWrite(ledger, session.caseUID, session.ID, now)
	if err != nil {
		return fail(err)
	}
	event, err := w.classify(head, node, tags, labels, reason)
	if err != nil {
		return fail(err)
	}
	if err := w.tx.commit(); err != nil {
		return fail(err)
	}
	session.appendEvent(now, op, fmt.Sprintf("node %d of ledger %s classified as %s in case %s (was %s): %s", nodeID,
		ledger.path, classifyLabelsProse(labels), session.ID, classifyLabelsProse(current.labels()), reason),
		map[string]any{
			"node":    int64(nodeID),
			"ledger":  ledger.path,
			"classes": strings.Join(labels, ", "),
			"tags":    strings.Join(tags, ","),
			"seq":     int64(event.seq),
			"uid":     event.uid,
		})

	return resultAndError(makeHashObject(map[string]object.Object{
		"node":               intObj(int64(nodeID)),
		"case_id":            stringObj(session.ID),
		"classes":            stringListObj(labels),
		"tags":               stringListObj(tags),
		"previous_classes":   stringListObj(current.labels()),
		"shown_under":        stringListObj(classifyShownUnder(session.views, tags)),
		"seq":                intObj(int64(event.seq)),
		"uid":                stringObj(event.uid),
		"reason":             stringObj(reason),
		"at":                 stringObj(now.UTC().Format(time.RFC3339Nano)),
		"by":                 stringObj(ledger.actor),
		"by_role":            stringObj(ledger.role.Name),
		"role_authenticated": boolObj(false),
	}), nil)
}

// ---------------------------------------------------------------------------
// ledger_classifications
// ---------------------------------------------------------------------------

// classificationRow is one node's classifications in one case: the classes in
// force, and every event that put them there.
func classificationRow(c ledgerClassification, present bool, shownUnder []string) object.Object {
	events := make([]object.Object, 0, len(c.events))
	for _, event := range c.events {
		events = append(events, makeHashObject(map[string]object.Object{
			"seq":     intObj(int64(event.seq)),
			"uid":     stringObj(event.uid),
			"classes": stringListObj(event.labels),
			"tags":    stringListObj(event.tags),
			"reason":  stringObj(event.get("classify.reason")),
			"by":      stringObj(event.get("classify.by")),
			"by_role": stringObj(event.get("classify.by_role")),
			"at":      stringObj(event.get("classify.at")),
		}))
	}
	head := c.head()
	return makeHashObject(map[string]object.Object{
		"node":        intObj(int64(c.node)),
		"case_uid":    stringObj(c.caseUID),
		"present":     boolObj(present),
		"classes":     stringListObj(c.labels()),
		"tags":        stringListObj(c.tags()),
		"shown_under": stringListObj(shownUnder),
		"seq":         intObj(int64(head.seq)),
		"uid":         stringObj(head.uid),
		"reason":      stringObj(head.get("classify.reason")),
		"by":          stringObj(head.get("classify.by")),
		"by_role":     stringObj(head.get("classify.by_role")),
		"at":          stringObj(head.get("classify.at")),
		"events":      &object.Array{Elements: events},
	})
}

// LedgerClassifications reports how the nodes a script wrote are classified:
// ledger_classifications(ledger, node?).
//
// With a keyed case open, that case's classifications; without one, every
// case's, so an auditor reads them with the ledger alone.
func LedgerClassifications(args ...object.Object) object.Object {
	op := BuiltinNameLedgerClassifications
	if len(args) < 1 || len(args) > 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	ledger, errObj := ledgerHandleArg(args[0], op)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	var node store.NodeID
	if len(args) == 2 {
		if node, errObj = ledgerNodeArg(args[1], op, 2); errObj != nil {
			return resultAndError(nil, errObj)
		}
	}

	custodyStore.RLock()
	session := custodyStore.session
	caseID, caseUID := "", ""
	var views []caseView
	if session != nil && !session.Closed && session.caseUID != "" {
		caseID, caseUID = session.ID, strings.ToLower(session.caseUID)
		views = append(views, session.views...)
	}
	custodyStore.RUnlock()

	classifications, err := classificationsRead(ledger.graph, caseUID, node)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", op, err.Error()))
	}
	// The views are the open keyed case's, and with none open there are none:
	// a keyed case lists only its own classifications.
	rows := make([]object.Object, 0, len(classifications))
	for _, c := range classifications {
		_, err := ledger.graph.GetNode(c.node)
		rows = append(rows, classificationRow(c, err == nil, classifyShownUnder(views, c.tags())))
	}
	return resultAndError(makeHashObject(map[string]object.Object{
		"classifications": &object.Array{Elements: rows},
		"count":           intObj(int64(len(rows))),
		"case_id":         stringObj(caseID),
		"keyed":           boolObj(caseUID != ""),
		"node":            intObj(int64(node)),
		"ledger":          stringObj(ledger.path),
	}), nil)
}
