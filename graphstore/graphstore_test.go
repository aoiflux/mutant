package graphstore

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/graphene"
	"github.com/aoiflux/graphene/disk"
	"github.com/aoiflux/graphene/store"
)

// writtenStore makes a real store with one node in it and closes it, so the
// directory holds what a finished writer leaves: an image, a label table if
// anything was named, and a clean lock record.
func writtenStore(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	g, err := graphene.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.AddNode(&store.Node{Labels: []store.NodeType{store.CustomNodeType(0)}}); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAPathThatDoesNotExistIsRefusedAndNotCreated(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if _, _, err := OpenForReading(dir); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("a missing path was not refused as missing: %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refusing a missing path created it: %v", err)
	}
}

func TestAFileIsRefusedAsNotAStore(t *testing.T) {
	file := filepath.Join(t.TempDir(), "store")
	if err := os.WriteFile(file, []byte("not a store"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenForReading(file); err == nil || !strings.Contains(err.Error(), "is a file") {
		t.Fatalf("a file was not refused as a file: %v", err)
	}
}

func TestAStoreWithALockIsReadUnderIt(t *testing.T) {
	dir := writtenStore(t)
	g, lockFree, err := OpenForReading(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if lockFree != "" {
		t.Fatalf("a store with its lock file was read lock-free: %s", lockFree)
	}
}

// A restore through graphene's own Backup arrives without graphene.lock, and a
// read must neither create one nor pretend it took one.
func TestAStoreWithNoLockIsReadWithoutOneAndGivenNone(t *testing.T) {
	dir := writtenStore(t)
	lock := filepath.Join(dir, LockFileName)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	g, lockFree, err := OpenForReading(dir)
	if err != nil {
		t.Fatal(err)
	}
	stats, statsErr := g.Stats()
	_ = g.Close()
	if statsErr != nil || stats.NodeCount != 1 {
		t.Fatalf("the lock-free read did not see the store's one node: %v %+v", statsErr, stats)
	}
	if !strings.Contains(lockFree, LockFileName) {
		t.Fatalf("the lock-free read did not say why it took no lock: %q", lockFree)
	}
	if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading the store created %s: %v", LockFileName, err)
	}
}

func TestAStoreAWriterHoldsIsRefusedRatherThanReadAround(t *testing.T) {
	dir := writtenStore(t)
	writer, err := graphene.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()
	g, _, err := OpenForReading(dir)
	if err == nil {
		_ = g.Close()
		t.Fatal("a store held by a writer was opened for reading")
	}
	if !errors.Is(err, disk.ErrStoreLocked) {
		t.Fatalf("the refusal is not graphene's locked-store error: %v", err)
	}
}

// lockRecord is the owner record graphene writes, built here byte by byte from
// the layout the reader assumes.
func lockRecord(pid uint64, clean bool) []byte {
	record := make([]byte, lockRecordSize)
	copy(record, lockMagic)
	record[lockVersionOffset] = lockVersion
	binary.LittleEndian.PutUint64(record[lockPIDOffset:], pid)
	if clean {
		record[lockCleanOffset] = 1
	}
	return record
}

func TestTheLockOwnerRecordIsReadAsGrapheneWritesIt(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name     string
		raw      []byte
		want     lockOwner
		readable bool
	}{
		{"clean", lockRecord(4242, true), lockOwner{present: true, pid: 4242, clean: true}, true},
		{"dirty", lockRecord(77, false), lockOwner{present: true, pid: 77}, true},
		{"short", lockRecord(77, false)[:lockRecordSize-1], lockOwner{}, false},
		{"foreign", append([]byte("GLK2"), make([]byte, lockRecordSize)...), lockOwner{}, false},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name)
		if err := os.WriteFile(path, c.raw, 0o644); err != nil {
			t.Fatal(err)
		}
		got, readable := readLockOwner(path)
		if got != c.want || readable != c.readable {
			t.Errorf("%s: got %+v readable=%v, want %+v readable=%v", c.name, got, readable, c.want, c.readable)
		}
	}
	if _, readable := readLockOwner(filepath.Join(dir, "absent")); readable {
		t.Error("a lock file that does not exist was read as a record")
	}

	// And the layout is the one graphene actually writes: a store it closed
	// carries a clean record naming this process.
	written := writtenStore(t)
	got, readable := readLockOwner(filepath.Join(written, LockFileName))
	if !readable || !got.present || !got.clean || got.pid != uint64(os.Getpid()) {
		t.Fatalf("the record graphene wrote read as %+v readable=%v, want a clean one for pid %d",
			got, readable, os.Getpid())
	}
}

type keyList struct {
	keys  []string
	known bool
}

func (k keyList) NodePropKeys() ([]string, bool) { return k.keys, k.known }

func TestUnindexedKeysKeepsTheQuestionsOrderAndNamesEachOnce(t *testing.T) {
	index := keyList{keys: []string{"id", "name"}, known: true}
	got, known := UnindexedKeys(index, []string{"zeta", "name", "alpha", "zeta"})
	if !known || !reflect.DeepEqual(got, []string{"zeta", "alpha"}) {
		t.Fatalf("got %v known=%v, want [zeta alpha] known=true", got, known)
	}
	if got, known := UnindexedKeys(index, []string{"id"}); !known || got != nil {
		t.Fatalf("an indexed key was named: %v known=%v", got, known)
	}
	if got, known := UnindexedKeys(keyList{}, []string{"id"}); known || got != nil {
		t.Fatalf("a store that cannot list its keys was answered for: %v known=%v", got, known)
	}
}

func TestReversedHopsMarksTheHopsThatRanAgainstTheirEdge(t *testing.T) {
	a, b, c := &store.Node{ID: 1}, &store.Node{ID: 2}, &store.Node{ID: 3}
	ab := &store.Edge{Src: 1, Dst: 2}
	bc := &store.Edge{Src: 2, Dst: 3}
	if got := ReversedHops([]*store.Node{a, b, c}, []*store.Edge{ab, bc}); len(got) != 0 {
		t.Fatalf("a forward path has reversed hops %v", got)
	}
	if got := ReversedHops([]*store.Node{c, b, a}, []*store.Edge{bc, ab}); !reflect.DeepEqual(got, []int{0, 1}) {
		t.Fatalf("the path back has reversed hops %v, want [0 1]", got)
	}
	if got := ReversedHops([]*store.Node{a, b, a}, []*store.Edge{ab, ab}); !reflect.DeepEqual(got, []int{1}) {
		t.Fatalf("there and back along one edge has reversed hops %v, want [1]", got)
	}
	if got := ReversedHops([]*store.Node{b}, []*store.Edge{ab}); len(got) != 0 {
		t.Fatalf("a path with no node past the first hop marked %v", got)
	}
}

// walkGraph builds a graph from src->dst pairs over nodes 1..n, returning the
// ids graphene gave the nodes (index i holds node i+1) and the edge ids in the
// order the pairs were given.
func walkGraph(t *testing.T, g *graphene.Graph, n int, pairs [][2]int) ([]store.NodeID, []store.EdgeID) {
	t.Helper()
	nodes := make([]store.NodeID, n)
	for i := range nodes {
		id, err := g.AddNode(&store.Node{Labels: []store.NodeType{store.CustomNodeType(0)}})
		if err != nil {
			t.Fatal(err)
		}
		nodes[i] = id
	}
	edges := make([]store.EdgeID, len(pairs))
	for i, pair := range pairs {
		id, err := g.AddEdge(&store.Edge{Src: nodes[pair[0]-1], Dst: nodes[pair[1]-1],
			Labels: []store.EdgeType{store.CustomEdgeType(0)}})
		if err != nil {
			t.Fatal(err)
		}
		edges[i] = id
	}
	return nodes, edges
}

func TestAWalkKeepsEveryParallelEdgeGrapheneDrops(t *testing.T) {
	g := graphene.NewInMemory()
	defer func() { _ = g.Close() }()
	// Three edges from 1 to 2, then one on to 3.
	nodes, edges := walkGraph(t, g, 3, [][2]int{{1, 2}, {1, 2}, {1, 2}, {2, 3}})

	reach, err := Walk(g, nodes[0], 2, store.DirectionOutbound, nil, WalkBudget())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(reach.Nodes, nodes) || !reflect.DeepEqual(reach.Edges, edges) {
		t.Fatalf("walk reached %v over %v, want %v over %v", reach.Nodes, reach.Edges, nodes, edges)
	}

	// And the reason this exists: graphene's own walk keeps one of the three.
	bfs, err := g.BFS(nodes[0], 2, store.DirectionOutbound, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(bfs.Edges) != 2 {
		t.Fatalf("graphene's BFS kept %d edges; this test assumes it keeps one per neighbour (2)", len(bfs.Edges))
	}
}

// Every direction and depth over a graph with parallel edges, self-loops, a
// cycle and an edge back to the origin, on both backends: the same nodes in the
// same order as graphene's walk, and every edge graphene returns among ours,
// the rest being edges parallel to one of graphene's -- joining the same two
// nodes, in either direction when the walk goes both ways.
func TestAWalkReachesWhatGraphenesBFSReachesInItsOrder(t *testing.T) {
	pairs := [][2]int{
		{1, 2}, {1, 2}, {2, 3}, {3, 1}, {3, 4}, {4, 4}, {4, 5}, {5, 2}, {2, 5},
		{6, 1}, {6, 7}, {7, 8}, {8, 6}, {5, 9}, {9, 10}, {10, 9}, {10, 9},
	}
	backends := map[string]func(t *testing.T) *graphene.Graph{
		"memory": func(*testing.T) *graphene.Graph { return graphene.NewInMemory() },
		"disk": func(t *testing.T) *graphene.Graph {
			g, err := graphene.Open(filepath.Join(t.TempDir(), "store"))
			if err != nil {
				t.Fatal(err)
			}
			return g
		},
	}
	for name, open := range backends {
		t.Run(name, func(t *testing.T) {
			g := open(t)
			defer func() { _ = g.Close() }()
			nodes, _ := walkGraph(t, g, 10, pairs)
			for _, dir := range []store.Direction{store.DirectionOutbound, store.DirectionInbound, store.DirectionBoth} {
				for depth := 0; depth <= 5; depth++ {
					for _, origin := range []store.NodeID{nodes[0], nodes[3], nodes[5]} {
						reach, err := Walk(g, origin, depth, dir, nil, WalkBudget())
						if err != nil {
							t.Fatal(err)
						}
						bfs, err := g.BFS(origin, depth, dir, nil)
						if err != nil {
							t.Fatal(err)
						}
						want := make([]store.NodeID, 0, len(bfs.Nodes))
						for _, node := range bfs.Nodes {
							want = append(want, node.ID)
						}
						if !reflect.DeepEqual(reach.Nodes, want) {
							t.Fatalf("dir %v depth %d from %d: nodes %v, graphene %v", dir, depth, origin, reach.Nodes, want)
						}
						ours := map[store.EdgeID]bool{}
						for _, id := range reach.Edges {
							if ours[id] {
								t.Fatalf("dir %v depth %d from %d: edge %d listed twice", dir, depth, origin, id)
							}
							ours[id] = true
						}
						ends := map[[2]store.NodeID]bool{}
						for _, edge := range bfs.Edges {
							if !ours[edge.ID] {
								t.Fatalf("dir %v depth %d from %d: graphene crossed edge %d and the walk did not", dir, depth, origin, edge.ID)
							}
							ends[pairOf(edge, dir)] = true
						}
						for _, id := range reach.Edges {
							edge, err := g.GetEdge(id)
							if err != nil {
								t.Fatal(err)
							}
							if !ends[pairOf(edge, dir)] {
								t.Fatalf("dir %v depth %d from %d: edge %d (%d->%d) is not parallel to any edge graphene crossed",
									dir, depth, origin, id, edge.Src, edge.Dst)
							}
						}
					}
				}
			}
		})
	}
}

// pairOf is the two ends an edge joins, as the walk in dir sees them: in a walk
// both ways, a->b and b->a join the same two nodes and are parallel.
func pairOf(edge *store.Edge, dir store.Direction) [2]store.NodeID {
	if dir == store.DirectionBoth && edge.Dst < edge.Src {
		return [2]store.NodeID{edge.Dst, edge.Src}
	}
	return [2]store.NodeID{edge.Src, edge.Dst}
}

func TestAWalkRefusesWhatItCannotAnswer(t *testing.T) {
	g := graphene.NewInMemory()
	defer func() { _ = g.Close() }()
	nodes, _ := walkGraph(t, g, 3, [][2]int{{1, 2}, {1, 2}, {2, 3}})

	var notFound *store.ErrNotFound
	if _, err := Walk(g, 999, 1, store.DirectionOutbound, nil, WalkBudget()); !errors.As(err, &notFound) {
		t.Fatalf("a missing origin was not refused as missing: %v", err)
	}
	if _, err := Walk(g, nodes[0], -1, store.DirectionOutbound, nil, WalkBudget()); err == nil {
		t.Fatal("a negative depth was walked")
	}
	if reach, err := Walk(g, nodes[0], 0, store.DirectionOutbound, nil, WalkBudget()); err != nil ||
		!reflect.DeepEqual(reach.Nodes, nodes[:1]) || len(reach.Edges) != 0 {
		t.Fatalf("a walk of depth 0 gave %+v, %v; want the origin alone", reach, err)
	}
	for _, budget := range []store.Budget{{MaxNodes: 2}, {MaxEdges: 2}, {MaxTime: -time.Second}} {
		if _, err := Walk(g, nodes[0], 2, store.DirectionOutbound, nil, budget); !errors.Is(err, store.ErrBudgetExceeded) {
			t.Errorf("budget %+v: the walk was not refused: %v", budget, err)
		}
	}
	// Exactly at the limit is inside it.
	if _, err := Walk(g, nodes[0], 2, store.DirectionOutbound, nil, store.Budget{MaxNodes: 3, MaxEdges: 3}); err != nil {
		t.Fatalf("a walk inside its budget was refused: %v", err)
	}
}

// The options reach the store whichever way in is taken: a memory ceiling no
// store fits under is refused both under the lock and without one, and a
// store opened either way refuses a write.
func TestOptionsReachTheStoreEitherWayIn(t *testing.T) {
	for _, lockFree := range []bool{false, true} {
		dir := writtenStore(t)
		if lockFree {
			if err := os.Remove(filepath.Join(dir, LockFileName)); err != nil {
				t.Fatal(err)
			}
		}
		if g, _, err := OpenForReadingWith(dir, disk.Options{MemoryBudget: 1}); err == nil {
			_ = g.Close()
			t.Fatalf("lock-free=%v: a one-byte memory budget was not carried to the store", lockFree)
		}
		g, reason, err := OpenForReadingWith(dir, disk.Options{VerifyOnOpen: true})
		if err != nil {
			t.Fatalf("lock-free=%v: %v", lockFree, err)
		}
		if (reason != "") != lockFree {
			t.Errorf("lock-free=%v: the read reported %q", lockFree, reason)
		}
		_, addErr := g.AddNode(&store.Node{Labels: []store.NodeType{store.CustomNodeType(0)}})
		_ = g.Close()
		if !errors.Is(addErr, disk.ErrReadOnly) {
			t.Errorf("lock-free=%v: a write through a reading handle was not refused as read-only: %v", lockFree, addErr)
		}
	}
}
