package graphstore

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
