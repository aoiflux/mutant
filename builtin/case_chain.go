package builtin

// Event chains: how the case records in the ledger say what order they
// happened in, without trusting the order graphene gave them ids in.
//
// # Not node ids, and not time
//
// graphene allocates ids in commit order, so ids happen to order one ledger's
// events, but that is a fact about the allocator and not about the case, and
// nothing in a node says which node came before it. Wall-clock time
// is worse: it is what the examiner's machine said, and two machines with
// drifting clocks order two events wrongly with nobody lying.
//
// So each event names the one before it. An event carries its chain, its
// position (seq, from 1) and its predecessor's uid (prev_uid, empty for the
// first), and its uid is a SHA-256 over those and every other property it
// carries. The head -- the event no other event names -- is what is in force.
// Each event also has a REVISES edge to its predecessor, so the graph says what
// the properties say.
//
// # A fork is refused, not resolved
//
// This process appends to a chain under disclosureLedgerMu, and graphene's lock
// keeps every other process out of the store, so two events naming the same
// predecessor are not something this program writes. A reader that finds them
// anyway has found a record something else made, and picking one would be
// deciding which of two histories of a case is the true one. Every reader
// refuses and names both. So does an event whose uid does not recompute from
// what it says, and one that no walk from the first event reaches.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strconv"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/store"
)

// caseChainSpec names one kind of chain: the label its events carry and the
// prefix of their properties.
type caseChainSpec struct {
	label  store.NodeType
	prefix string
}

func (c caseChainSpec) key(name string) string { return c.prefix + "." + name }

// caseChainEvent is one event of a chain as read back.
type caseChainEvent struct {
	disclosureNode
	seq  uint64
	uid  string
	prev string
}

// caseChainUID is the hash an event's uid must equal. Every property but the
// uid itself goes in, length-prefixed and in key order, so no two property
// maps hash alike by moving a separator.
func caseChainUID(spec caseChainSpec, props map[string]string) string {
	uidKey := spec.key("uid")
	keys := make([]string, 0, len(props))
	for key := range props {
		if key != uidKey {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	write := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	write("mutant-case-chain-v1")
	write(spec.prefix)
	for _, key := range keys {
		write(key)
		write(props[key])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// caseChainRead returns a chain's events in order, first to head, or refuses
// one that forks, holds an event with no position or out of its position,
// holds one whose uid does not recompute, or holds one no walk from its first
// event reaches. An empty chain is no events and no error.
func caseChainRead(g *graphene.Graph, spec caseChainSpec, chain string) ([]caseChainEvent, error) {
	ids, err := g.NodesByProperty(spec.key("chain"), []byte(chain))
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	nodes, _, err := g.GetNodes(ids)
	if err != nil {
		return nil, err
	}
	byPrev := map[string][]caseChainEvent{}
	count := 0
	for _, node := range nodes {
		if !node.HasLabel(spec.label) {
			continue
		}
		decoded, err := disclosureDecode(node)
		if err != nil {
			return nil, fmt.Errorf("%s event node %d: %w", spec.label.String(), node.ID, err)
		}
		event := caseChainEvent{disclosureNode: decoded, uid: decoded.get(spec.key("uid")),
			prev: decoded.get(spec.key("prev_uid"))}
		if event.seq, err = strconv.ParseUint(decoded.get(spec.key("seq")), 10, 64); err != nil || event.seq == 0 {
			return nil, fmt.Errorf("%s event node %d has no position in its chain (seq %q)", spec.prefix,
				node.ID, decoded.get(spec.key("seq")))
		}
		if want := caseChainUID(spec, decoded.props); event.uid != want {
			return nil, fmt.Errorf("%s event node %d says its uid is %s, and what it records hashes to %s: "+
				"the event is not the one that was written", spec.prefix, node.ID, event.uid, want)
		}
		byPrev[event.prev] = append(byPrev[event.prev], event)
		count++
	}
	out := make([]caseChainEvent, 0, count)
	for prev := ""; ; {
		next := byPrev[prev]
		if len(next) == 0 {
			break
		}
		if len(next) > 1 {
			sort.Slice(next, func(i, j int) bool { return next[i].id < next[j].id })
			return nil, fmt.Errorf("the ledger holds two %s events after %s: node %d (uid %s, at %s) and node %d "+
				"(uid %s, at %s). This program writes one event after another under one lock, so one of them "+
				"was written by something else, and which of two histories is this case's is not a question "+
				"this program answers", spec.prefix, caseChainPosition(prev), next[0].id, next[0].uid,
				next[0].get(spec.key("at")), next[1].id, next[1].uid, next[1].get(spec.key("at")))
		}
		event := next[0]
		delete(byPrev, prev)
		if event.seq != uint64(len(out))+1 {
			return nil, fmt.Errorf("%s event node %d says it is event %d of its chain and it is event %d",
				spec.prefix, event.id, event.seq, len(out)+1)
		}
		out = append(out, event)
		prev = event.uid
	}
	if len(out) != count {
		for _, stray := range byPrev {
			return nil, fmt.Errorf("%s event node %d names a predecessor (%s) that no walk from the chain's "+
				"first event reaches, so the ledger holds an event this program did not write", spec.prefix,
				stray[0].id, caseChainPosition(stray[0].prev))
		}
	}
	return out, nil
}

func caseChainPosition(prev string) string {
	if prev == "" {
		return "the start of the chain"
	}
	return "uid " + prev
}

// chainAppend buffers the event after head -- or the first event, when head is
// nil -- and its REVISES edge to head. props are the event's own properties;
// the chain, position, predecessor and uid are added here.
func (d *disclosureTx) chainAppend(spec caseChainSpec, chain string, head *caseChainEvent,
	props map[string]string) (store.NodeID, caseChainEvent, error) {
	all := make(map[string]string, len(props)+4)
	maps.Copy(all, props)
	seq, prev := uint64(1), ""
	if head != nil {
		seq, prev = head.seq+1, head.uid
	}
	all[spec.key("chain")] = chain
	all[spec.key("seq")] = strconv.FormatUint(seq, 10)
	all[spec.key("prev_uid")] = prev
	uid := caseChainUID(spec, all)
	all[spec.key("uid")] = uid
	id, err := d.node(spec.label, all)
	if err != nil {
		return 0, caseChainEvent{}, err
	}
	if head != nil {
		if err := d.edge(id, head.id, disclosureEdgeRevises, nil); err != nil {
			return 0, caseChainEvent{}, err
		}
	}
	return id, caseChainEvent{disclosureNode: disclosureNode{id: id, props: all}, seq: seq, uid: uid, prev: prev}, nil
}

// caseChainHead is the last event of a chain, or nil for an empty one.
func caseChainHead(events []caseChainEvent) *caseChainEvent {
	if len(events) == 0 {
		return nil
	}
	return &events[len(events)-1]
}
