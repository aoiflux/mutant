package builtin

// Inclusion proofs: what a ledger can hand to somebody who does not have it.
//
// A ledger that can only be checked by opening it is a ledger only its holder
// can check, and the holder is the party whose claims are in question. A proof
// is the way out: a few hundred bytes that let a third party confirm one entity
// was in one snapshot, using the bytes and a root and nothing else -- not the
// store, not the other entities, not anything about them.
//
// Graphene builds these; this family is about the four places where handing one
// to a person rather than to another Go program changes what has to be said.
//
// # The root is an argument, and there is no form that takes it from the proof
//
// An exported proof states the roots it claims. It has to -- a verifier needs
// the component roots to check that the node root belongs to the snapshot being
// asserted. But checking a proof against the root inside it is circular: whoever
// wrote the file supplied both the evidence and the standard, and an attacker
// supplying both can always make them agree.
//
// So `ledger_verify_proof` takes the root as its second argument, refuses an
// empty one, and refuses an all-zero one -- which is what an empty value looks
// like after it has been padded to thirty-two bytes, and which graphene defines
// as "this snapshot has no roots" rather than as a root. `ledger_root_export`
// exists to produce the value the examiner retains out of band so that the
// argument has something true to be.
//
// # "Not in the snapshot" is two different situations with one error
//
// `ProveNode` returns `ErrNotInSnapshot` for an entity written since the last
// compaction and for an entity that was never written at all. They are not the
// same problem and they do not have the same fix: the first is answered by
// compacting, the second means the caller has the wrong id, and a script told
// only "entity is not in the compacted snapshot" will compact a ledger over and
// over in response to a typo.
//
// Graphene's comment says as much -- "an entity written since the last
// compaction is live but unproven, which is a different thing from absent" --
// but the error cannot tell them apart, because proving reads the compacted
// image and the compacted image is where neither of them is. The graph can.
// `ledger_prove_node` asks it before reporting, and returns one of three
// refusals instead of one.
//
// # A proof is bound to a snapshot, and every compaction makes a new one
//
// Compacting a ledger does not invalidate a proof, but it does move the root
// the proof resolves against. A proof exported before a compaction still
// verifies -- against the root it names, forever. It does not verify against
// the root the ledger has now, and a fresh proof for the same unchanged entity
// is different bytes.
//
// This is the right behaviour and it has a consequence worth stating where the
// script author will see it: a proof is only as useful as the recipient's
// ability to obtain *that* root. Exporting proofs without retaining the roots
// beside them produces files nobody can ever check. `ledger_prove_node` returns
// the snapshot root next to the proof for that reason, and `ledger_root_export`
// refuses to return an empty one.
//
// # Decoding is not verifying, and malformed is not false
//
// `ledger_proof_describe` reads a proof without a root. Everything it reports
// about roots is prefixed `stated_`, because none of it has been checked
// against anything -- it is the file's own account of itself. A byte flipped
// inside the roots region of a proof file still decodes cleanly and then fails
// verification, so "it parsed" is not a weaker form of "it verified".
//
// The two failures stay separate in the return shape too. A file that is not a
// readable proof comes back as an error; a readable proof that is not true
// comes back as a value with `verified: false` and a reason. Graphene makes the
// same split and says why: "The two call for different responses and collapsing
// them loses that." A script that treats a corrupt download as a forgery, or a
// forgery as a corrupt download, has drawn the wrong conclusion either way.
//
// # There is no edge inclusion proof
//
// Graphene has `ProveNode`, `ProveRedaction`, `ProveEdgeRedaction` and
// `ProvePropertyRedaction`. An edge can be proven *removed* and cannot be
// proven *present*. The edge root is computed and committed to like the others,
// so this is a gap in the API and not in the format -- but it is the API this
// builds on, so there is no `ledger_prove_edge` and inventing one that proved
// something weaker under that name would be worse than its absence.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/merkle"
	"github.com/aoiflux/graphene/store"

	"mutant/object"
)

// ledgerRootHexLen is how long a root is written as text.
const ledgerRootHexLen = merkle.Size * 2

// ledgerProofArg reads the proof bytes every verifier-side builtin takes.
//
// BYTES or STRING, through the same widening helper the rest of the tree uses:
// a proof arrives from fs_read as one or the other depending on which builtin
// read it, and refusing the wrong one would make the verifier's first act be a
// complaint about how its input was loaded.
func ledgerProofArg(arg object.Object, op string, pos int) ([]byte, *object.Error) {
	data, errObj := requireBinaryArg(op, arg, pos)
	if errObj != nil {
		return nil, errObj
	}
	if len(data) == 0 {
		return nil, newError("%s: the proof is empty", op)
	}
	return data, nil
}

// ledgerRootFromHex parses a root supplied by the caller.
//
// The refusals are worded for the situation that produces them. An empty root
// means the caller had nowhere to get one, and an all-zero root means they had
// an empty value that something padded -- graphene reads a zero snapshot as
// "there are no roots", so it is never a root a store produced. Both would fail
// verification anyway, with a message about component roots that says nothing
// about what went wrong.
func ledgerRootFromHex(value, field, op string) (merkle.Hash, *object.Error) {
	var out merkle.Hash
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return out, newError("%s: %s must not be empty; a proof is checked against a root obtained independently of it, and there is no form of this call that reads the root out of the proof", op, field)
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return out, newError("%s: %s is not hexadecimal: %s", op, field, err.Error())
	}
	if len(raw) != merkle.Size {
		return out, newError("%s: %s must be %d hex characters, got %d", op, field, ledgerRootHexLen, len(trimmed))
	}
	copy(out[:], raw)
	if out == (merkle.Hash{}) {
		return merkle.Hash{}, newError("%s: %s is all zeroes, which graphene records as \"this snapshot has no roots\" rather than as a root; a ledger that has been compacted reports its root through ledger_root_export", op, field)
	}
	return out, nil
}

// ledgerRootsInto renders a set of snapshot roots under a field prefix.
//
// The prefix is what keeps `ledger_proof_describe` honest: the same six values
// are `stated_` there, where nothing has been checked, and bare in
// `ledger_root_export`, where they came out of the store.
func ledgerRootsInto(roots disk.SnapshotRoots, prefix string, out map[string]object.Object) {
	out[prefix+"snapshot_root"] = stringObj(ledgerHash(roots.Snapshot))
	out[prefix+"node_root"] = stringObj(ledgerHash(roots.NodeRoot))
	out[prefix+"edge_root"] = stringObj(ledgerHash(roots.EdgeRoot))
	out[prefix+"index_root"] = stringObj(ledgerHash(roots.IndexRoot))
	out[prefix+"prev_root"] = stringObj(ledgerHash(roots.PrevRoot))
	out[prefix+"tombstone_root"] = stringObj(ledgerHash(roots.TombstoneRoot))
	out[prefix+"body_version"] = intObj(int64(roots.BodyVersion))
}

// ledgerProofShape is what a decoded proof looks like from the outside,
// whichever kind it is.
//
// One shape for all three kinds because the verifier is handed whatever the
// other party produced. A recipient given a redaction proof by a later version
// of this family, or by graphene directly, should get a verdict from the
// verifier rather than "unsupported" from the tool whose job is verifying.
type ledgerProofShape struct {
	roots     disk.SnapshotRoots
	nodeID    int64
	edgeID    int64
	leafBytes int
	leafIndex int
	treeSize  int
	siblings  int
}

// ledgerDescribeProof reads the shape out of any of the three proof kinds.
//
// A property-redaction proof carries two inclusion proofs; the surviving one is
// what its roots and tree position are read from, because that is the proof
// that places the entity in the snapshot being verified against.
func ledgerDescribeProof(e disk.ExportedProof) (ledgerProofShape, *object.Error) {
	var shape ledgerProofShape
	switch {
	case e.Node != nil:
		shape.nodeID = int64(e.Node.NodeID)
		shape.roots = e.Node.Roots
		shape.leafBytes = len(e.Node.LeafData)
		shape.leafIndex = e.Node.Proof.Index
		shape.treeSize = e.Node.Proof.Size
		shape.siblings = len(e.Node.Proof.Siblings)
	case e.Property != nil:
		shape.nodeID = int64(e.Property.NodeID)
		shape.roots = e.Property.Surviving.Roots
		shape.leafBytes = len(e.Property.Surviving.LeafData)
		shape.leafIndex = e.Property.Surviving.Proof.Index
		shape.treeSize = e.Property.Surviving.Proof.Size
		shape.siblings = len(e.Property.Surviving.Proof.Siblings)
	case e.Removal != nil:
		shape.nodeID = int64(e.Removal.Tombstone.NodeID)
		shape.edgeID = int64(e.Removal.Tombstone.EdgeID)
		shape.roots = e.Removal.Roots
		shape.leafBytes = len(e.Removal.LeafData)
		shape.leafIndex = e.Removal.Proof.Index
		shape.treeSize = e.Removal.Proof.Size
		shape.siblings = len(e.Removal.Proof.Siblings)
	default:
		// UnmarshalProof rejects an unknown kind, so reaching here means a
		// known kind arrived with its payload absent. Refused rather than
		// reported as an empty proof about entity zero.
		return shape, newError("the proof declares kind %s but carries no proof of that kind", e.Kind)
	}
	return shape, nil
}

// ledgerProofFieldsInto writes the shape out under a root prefix.
func ledgerProofFieldsInto(e disk.ExportedProof, shape ledgerProofShape, prefix string, out map[string]object.Object) {
	out["kind"] = stringObj(e.Kind.String())
	out["subject"] = stringObj(e.Subject())
	out["node_id"] = intObj(shape.nodeID)
	out["edge_id"] = intObj(shape.edgeID)
	out["leaf_bytes"] = intObj(int64(shape.leafBytes))
	out["leaf_index"] = intObj(int64(shape.leafIndex))
	out["tree_size"] = intObj(int64(shape.treeSize))
	out["siblings"] = intObj(int64(shape.siblings))
	ledgerRootsInto(shape.roots, prefix, out)
}

// LedgerProveNode builds and exports an inclusion proof for one node.
func LedgerProveNode(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerProveNode)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	idArg, ok := args[1].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be INTEGER, got %s", BuiltinNameLedgerProveNode, args[1].Type()))
	}
	if idArg.Value <= 0 {
		return resultAndError(nil, newError("%s: node ids start at 1, got %d", BuiltinNameLedgerProveNode, idArg.Value))
	}
	nodeID := store.NodeID(idArg.Value)

	proof, err := session.store.ProveNode(nodeID)
	if err != nil {
		return resultAndError(nil, ledgerProveRefusal(session, nodeID, err))
	}
	blob, err := session.store.ExportNodeProof(nodeID)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerProveNode, err.Error()))
	}

	out := map[string]object.Object{
		"node_id": intObj(int64(nodeID)),
		// The bytes, ready for fs_write. Everything else in this hash is
		// derived from them and is here to be read, not to be re-assembled
		// into a proof: there is no builtin that takes these fields back.
		"proof":       &object.Bytes{Value: blob},
		"proof_bytes": intObj(int64(len(blob))),
		"kind":        stringObj(disk.ProofKindNodeInclusion.String()),
		"subject":     stringObj(fmt.Sprintf("node %d", nodeID)),
		"leaf_bytes":  intObj(int64(len(proof.LeafData))),
		"leaf_index":  intObj(int64(proof.Proof.Index)),
		"tree_size":   intObj(int64(proof.Proof.Size)),
		"siblings":    intObj(int64(len(proof.Proof.Siblings))),
	}
	// Unprefixed: these came out of the store, not out of a file somebody
	// handed over. snapshot_root is the one to retain or publish -- without it
	// the proof is a file nobody can check.
	ledgerRootsInto(proof.Roots, "", out)

	custodyRecordArtifact(BuiltinNameLedgerProveNode,
		fmt.Sprintf("exported an inclusion proof for node %d", nodeID),
		map[string]any{
			"path":          session.path,
			"actor":         session.actor,
			"node_id":       fmt.Sprintf("%d", nodeID),
			"snapshot_root": ledgerHash(proof.Roots.Snapshot),
			"proof_bytes":   len(blob),
		})

	return resultAndError(makeHashObject(out), nil)
}

// ledgerProveRefusal turns graphene's two proof errors into the three answers
// they actually stand for.
//
// See the file header. The extra read is a point lookup against the live graph
// and happens only on the failure path, so the cost is paid by the caller who
// is about to be told something wrong otherwise.
func ledgerProveRefusal(session *ledgerSession, nodeID store.NodeID, err error) *object.Error {
	switch {
	case errors.Is(err, disk.ErrNoSnapshotRoots):
		return newError("%s: this ledger has never been compacted, so it has no snapshot for a proof to resolve against; call ledger_compact first", BuiltinNameLedgerProveNode)
	case errors.Is(err, disk.ErrNotInSnapshot):
		found, _, lookupErr := session.graph.GetNodes([]store.NodeID{nodeID})
		switch {
		case lookupErr != nil:
			// The distinction could not be made, so it is not claimed.
			return newError("%s: node %d is not in the compacted snapshot, and the live graph could not be consulted to say whether it exists at all: %s", BuiltinNameLedgerProveNode, nodeID, lookupErr.Error())
		case len(found) == 0:
			return newError("%s: this ledger has no node %d", BuiltinNameLedgerProveNode, nodeID)
		default:
			return newError("%s: node %d is live but was written after the last compaction, so it is in no snapshot yet and nothing can be proved about it; call ledger_compact to bring it into one", BuiltinNameLedgerProveNode, nodeID)
		}
	default:
		return newError("%s: %s", BuiltinNameLedgerProveNode, err.Error())
	}
}

// LedgerVerifyProof checks an exported proof against a root the caller supplies.
func LedgerVerifyProof(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	blob, errObj := ledgerProofArg(args[0], BuiltinNameLedgerVerifyProof, 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	rootArg, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `%s` must be STRING, got %s", BuiltinNameLedgerVerifyProof, args[1].Type()))
	}
	root, errObj := ledgerRootFromHex(rootArg.Value, "the snapshot root", BuiltinNameLedgerVerifyProof)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	// A file that is not a readable proof is an error, not a false verdict.
	decoded, err := disk.UnmarshalProof(blob)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerVerifyProof, err.Error()))
	}
	shape, errObj := ledgerDescribeProof(decoded)
	if errObj != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerVerifyProof, errObj.Message))
	}

	out := map[string]object.Object{
		"proof_bytes": intObj(int64(len(blob))),
		// Both roots, always. On a pass they are equal by construction --
		// graphene refuses a proof stating a root other than the one it is
		// checked against -- and on a failure the pair is what says whether
		// the proof is about a different snapshot or is simply false.
		"checked_against": stringObj(ledgerHash(root)),
	}
	ledgerProofFieldsInto(decoded, shape, "stated_", out)

	// A readable proof that is not true is a value, not an error.
	if verifyErr := disk.VerifyExportedProof(root, decoded); verifyErr != nil {
		out["verified"] = boolObj(false)
		out["reason"] = stringObj(verifyErr.Error())
	} else {
		out["verified"] = boolObj(true)
		out["reason"] = stringObj("")
	}

	return resultAndError(makeHashObject(out), nil)
}

// LedgerProofDescribe reads a proof without checking it against anything.
func LedgerProofDescribe(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	blob, errObj := ledgerProofArg(args[0], BuiltinNameLedgerProofDescribe, 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	decoded, err := disk.UnmarshalProof(blob)
	if err != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerProofDescribe, err.Error()))
	}
	shape, errObj := ledgerDescribeProof(decoded)
	if errObj != nil {
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerProofDescribe, errObj.Message))
	}

	out := map[string]object.Object{
		"proof_bytes": intObj(int64(len(blob))),
	}
	// Every root here is `stated_`: this builtin was given no root and checked
	// nothing. The prefix is the whole contract, and it is why there is no
	// `verified` field to be read as false rather than as absent.
	ledgerProofFieldsInto(decoded, shape, "stated_", out)
	return resultAndError(makeHashObject(out), nil)
}

// LedgerRootExport returns the roots worth retaining outside the store.
func LedgerRootExport(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	session, errObj := ledgerHandleArg(args[0], BuiltinNameLedgerRootExport)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	roots, err := session.store.SnapshotRoots()
	if err != nil {
		// ledger_stats reports "no roots" as a state, with empty strings and
		// compacted:false, because its job is to say what the ledger is. This
		// builtin's job is to produce the value an examiner retains, and an
		// empty one retained now is an empty one quoted later in a manifest as
		// though it were a root. So this refuses where stats reports.
		if errors.Is(err, disk.ErrNoSnapshotRoots) {
			return resultAndError(nil, newError("%s: this ledger has never been compacted, so there is no snapshot root to retain; call ledger_compact first", BuiltinNameLedgerRootExport))
		}
		return resultAndError(nil, newError("%s: %s", BuiltinNameLedgerRootExport, err.Error()))
	}

	out := map[string]object.Object{
		"path":     stringObj(session.path),
		"actor":    stringObj(session.actor),
		"actor_id": stringObj(fmt.Sprintf("%d", session.actorID)),
	}
	ledgerRootsInto(roots, "", out)

	custodyRecordArtifact(BuiltinNameLedgerRootExport,
		fmt.Sprintf("exported snapshot root %s", ledgerHash(roots.Snapshot)),
		map[string]any{
			"path":          session.path,
			"actor":         session.actor,
			"snapshot_root": ledgerHash(roots.Snapshot),
			"prev_root":     ledgerHash(roots.PrevRoot),
		})

	return resultAndError(makeHashObject(out), nil)
}

// ledgerRootsFromHash reads a root set back out of a ledger_root_export result.
//
// Every component is required rather than defaulted. The snapshot root binds
// them, so a missing one silently read as zero would produce a set that fails
// its own binding check and report the chain as broken when what was broken was
// the argument.
func ledgerRootsFromHash(arg object.Object, which, op string) (disk.SnapshotRoots, *object.Error) {
	var out disk.SnapshotRoots
	hash, ok := arg.(*object.Hash)
	if !ok {
		return out, newError("%s: %s must be a HASH from ledger_root_export, got %s", op, which, arg.Type())
	}
	fields := []struct {
		key string
		dst *merkle.Hash
	}{
		{"snapshot_root", &out.Snapshot},
		{"node_root", &out.NodeRoot},
		{"edge_root", &out.EdgeRoot},
		{"index_root", &out.IndexRoot},
		{"prev_root", &out.PrevRoot},
		{"tombstone_root", &out.TombstoneRoot},
	}
	for _, field := range fields {
		text, err := hashStringField(hash, field.key)
		if err != nil {
			return disk.SnapshotRoots{}, newError("%s: %s is missing %s -- these come from ledger_root_export, which returns all of them together", op, which, field.key)
		}
		// prev_root is all zeroes on a ledger's first snapshot, which is a real
		// value and not an absent one, so it is parsed here rather than through
		// ledgerRootFromHex and its refusal of a zero root.
		trimmed := strings.TrimSpace(text)
		raw, decodeErr := hex.DecodeString(trimmed)
		if decodeErr != nil || len(raw) != merkle.Size {
			return disk.SnapshotRoots{}, newError("%s: %s has a %s that is not %d hex characters", op, which, field.key, ledgerRootHexLen)
		}
		copy(field.dst[:], raw)
	}
	version, err := hashIntField(hash, "body_version")
	if err != nil {
		return disk.SnapshotRoots{}, newError("%s: %s is missing body_version -- it comes from ledger_root_export with the roots, and it decides how many components bind into the snapshot root, so a chain cannot be checked without it", op, which)
	}
	if version < 0 || version > 255 {
		return disk.SnapshotRoots{}, newError("%s: %s has body_version %d, which is not a byte", op, which, version)
	}
	out.BodyVersion = uint8(version)
	return out, nil
}

// LedgerVerifyChain checks that one retained snapshot extends another.
func LedgerVerifyChain(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}
	earlier, errObj := ledgerRootsFromHash(args[0], "the earlier snapshot", BuiltinNameLedgerVerifyChain)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	later, errObj := ledgerRootsFromHash(args[1], "the later snapshot", BuiltinNameLedgerVerifyChain)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	out := map[string]object.Object{
		"earlier_snapshot_root": stringObj(ledgerHash(earlier.Snapshot)),
		"later_snapshot_root":   stringObj(ledgerHash(later.Snapshot)),
		"later_prev_root":       stringObj(ledgerHash(later.PrevRoot)),
	}
	// Same split as ledger_verify_proof: an argument that is not a root set is
	// an error above, and two well-formed root sets that do not link are a
	// value with a reason.
	if err := disk.VerifyChain(earlier, later); err != nil {
		out["chained"] = boolObj(false)
		out["reason"] = stringObj(err.Error())
	} else {
		out["chained"] = boolObj(true)
		out["reason"] = stringObj("")
	}
	return resultAndError(makeHashObject(out), nil)
}
