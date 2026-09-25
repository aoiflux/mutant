package cli

import (
	"strings"
	"testing"

	"mutant/builtin"
	"mutant/object"

	"github.com/aoiflux/graphene/store"
)

// graphene keeps one name per label number for the whole process. Two of this
// program's graph families declare names -- the symbol graph `graph export`
// writes and the disclosure ledger's schema -- and a number both used under
// different names would make whichever declared second fail. Neither may
// reuse the other's numbers under another name.
func TestNoTwoGraphFamiliesNameOneLabelTwoWays(t *testing.T) {
	symbolNodes, symbolEdges := labelNames()
	disclosureNodes, disclosureEdges := builtin.DisclosureLabelNames()
	for label, name := range symbolNodes {
		if other, both := disclosureNodes[label]; both && other != name {
			t.Errorf("node label %d is %q in the symbol graph and %q in the disclosure schema", label, name, other)
		}
	}
	for label, name := range symbolEdges {
		if other, both := disclosureEdges[label]; both && other != name {
			t.Errorf("edge label %d is %q in the symbol graph and %q in the disclosure schema", label, name, other)
		}
	}
}

// M26-TOOL-004. db_open_disk opened an exported symbol graph for writing, and
// db_add_node wrote a node under custom label 0 -- which the symbol graph names
// Module -- so the next `graph query modules` failed to decode it. db_open_disk
// now refuses a store whose table names the labels db_* writes unnamed, and
// every label the symbol graph declares is one of those, so every exported
// store is refused.
func TestAnExportedSymbolGraphIsNotOpenedByDbOpenDisk(t *testing.T) {
	nodes, edges := labelNames()
	for label, name := range nodes {
		if label < store.NodeTypeCustomBase || label >= store.NodeTypeCustomBase+128 {
			t.Errorf("node label %s (%d) is outside the custom labels db_* writes, so db_open_disk would not refuse a store for naming it", name, label)
		}
	}
	for label, name := range edges {
		if label < store.EdgeTypeCustomBase || label >= store.EdgeTypeCustomBase+128 {
			t.Errorf("edge label %s (%d) is outside the custom labels db_* writes, so db_open_disk would not refuse a store for naming it", name, label)
		}
	}

	_, out, _ := exportFixtureTo(t, exportFixture, "main.mut")
	result, ok := builtin.DbOpenDisk(&object.String{Value: out}).(*object.MultiValue)
	if !ok || len(result.Values) != 2 {
		t.Fatalf("db_open_disk returned %T", result)
	}
	refusal, refused := result.Values[1].(*object.Error)
	if !refused {
		builtin.DbClose(result.Values[0])
		t.Fatal("db_open_disk opened an exported symbol graph for writing")
	}
	if !strings.Contains(refusal.Message, "Module") || !strings.Contains(refusal.Message, "graph query") {
		t.Errorf("the refusal does not say what the store is or how to read it: %s", refusal.Message)
	}

	// The store still answers, because nothing opened it.
	answer, err := QueryGraph(QueryOptions{Store: out, Question: "modules"})
	if err != nil || answer.Headline == "" {
		t.Fatalf("the store no longer answers: %v", err)
	}
}
