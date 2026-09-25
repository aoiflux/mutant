package builtin

import (
	"strings"
	"testing"

	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// M26-CUS-001. The redaction builtins checked the handle, the id, the reason
// and the leak, but not what the node was. graphene's RedactNode deletes the
// node and its index entries, and every disclose_* read finds its records by
// index -- so a script holding the ledger could redact a Withdrawal and issue a
// new grant to the recipient it withdrew, redact a Disclosure out of the
// history, or strip a ReclassEvent's properties and disclose a superseded
// record. The redaction builtins now remove only what a script wrote.
func TestNoSchemaNodeOrEdgeIsRedactable(t *testing.T) {
	f := newDiscloseFixture(t)
	uid := keyFieldString(t, f.issue(t, "counsel", "Counsel"), "disclosure_uid")
	mustHash(t, DiscloseWithdraw(intObj(f.ledger), stringObj(uid), stringObj("classification under review")))

	session, errObj := ledgerHandleArg(intObj(f.ledger), "test")
	if errObj != nil {
		t.Fatal(errObj.Message)
	}
	nodeNames, _ := disclosureTypeNames()
	nodeNames[disclosureNodeCase] = "Case"

	var schemaNodes []store.NodeID
	schemaEdges := map[store.EdgeID]bool{}
	for label, name := range nodeNames {
		nodes, err := disclosureAll(session.graph, label)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, node := range nodes {
			schemaNodes = append(schemaNodes, node.id)
			edges, err := session.graph.EdgesOf(node.id, store.DirectionBoth, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, edge := range edges {
				schemaEdges[edge.ID] = true
			}
		}
	}
	if len(schemaNodes) < 7 || len(schemaEdges) < 6 {
		t.Fatalf("the fixture wrote %d schema nodes and %d edges; the test proves nothing about a ledger this thin", len(schemaNodes), len(schemaEdges))
	}

	reason := strings.Repeat("court order 12 ", 2)
	for _, id := range schemaNodes {
		for name, fn := range map[string]func(...object.Object) object.Object{
			BuiltinNameLedgerRedactNode:           LedgerRedactNode,
			BuiltinNameLedgerRedactNodeProperties: LedgerRedactNodeProperties,
		} {
			_, errObj := unwrapPairNoFatal(fn(intObj(f.ledger), intObj(int64(id)), stringObj(reason)))
			if errObj == nil {
				t.Errorf("%s redacted schema node %d", name, id)
			} else if !strings.Contains(errObj.Message, "disclosure schema") {
				t.Errorf("%s refused schema node %d without saying why: %s", name, id, errObj.Message)
			}
		}
		impact := mustLedgerHash(t, BuiltinNameLedgerRedactionImpact, LedgerRedactionImpact(intObj(f.ledger), intObj(int64(id))))
		if !discloseBool(t, impact, "protected") {
			t.Errorf("ledger_redaction_impact does not say schema node %d is protected", id)
		}
	}
	for id := range schemaEdges {
		for name, fn := range map[string]func(...object.Object) object.Object{
			BuiltinNameLedgerRedactEdge:           LedgerRedactEdge,
			BuiltinNameLedgerRedactEdgeProperties: LedgerRedactEdgeProperties,
		} {
			if _, errObj := unwrapPairNoFatal(fn(intObj(f.ledger), intObj(int64(id)), stringObj(reason))); errObj == nil {
				t.Errorf("%s redacted schema edge %d", name, id)
			}
		}
	}

	// What the attempts were for: the withdrawal still stops a new grant.
	purposeStub(t, map[string]string{BuiltinNameDiscloseToPassphrase: testGrantPassphrase})
	_, errObj = unwrapPairNoFatal(DiscloseToPassphrase(intObj(f.ledger), f.record, stringObj("counsel"), stringObj("Counsel")))
	if errObj == nil || !strings.Contains(errObj.Message, "was withdrawn") {
		t.Fatalf("after the redaction attempts the record was disclosed again to a withdrawn recipient: %v", errObj)
	}
	history := mustHash(t, DiscloseHistory(intObj(f.ledger)))
	if got := mustHashIntValue(t, history, "withdrawn"); got != 1 {
		t.Errorf("disclose_history counts %d withdrawals, want 1", got)
	}

	// What a script wrote stays redactable, including a script edge that
	// touches a schema node: the edge is the script's, the node is not.
	written := mustLedgerHash(t, BuiltinNameLedgerAddNode, LedgerAddNode(intObj(f.ledger),
		ledgerProps(map[string]string{"note": "an examiner's own node"}), intObj(3)))
	scriptNode := mustHashIntValue(t, written, "id")
	joined := mustLedgerHash(t, BuiltinNameLedgerAddEdge, LedgerAddEdge(intObj(f.ledger), intObj(scriptNode),
		intObj(int64(schemaNodes[0])), ledgerProps(map[string]string{"why": "cross-reference"})))
	impact := mustLedgerHash(t, BuiltinNameLedgerRedactionImpact, LedgerRedactionImpact(intObj(f.ledger), intObj(scriptNode)))
	if discloseBool(t, impact, "protected") {
		t.Error("ledger_redaction_impact calls a script's own node protected")
	}
	mustLedgerHash(t, BuiltinNameLedgerRedactEdgeProperties, LedgerRedactEdgeProperties(intObj(f.ledger),
		intObj(mustHashIntValue(t, joined, "id")), stringObj(reason)))
	mustLedgerHash(t, BuiltinNameLedgerRedactNode, LedgerRedactNode(intObj(f.ledger), intObj(scriptNode), stringObj(reason)))
}
