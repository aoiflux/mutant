package builtin

import (
	"fmt"
	"testing"

	"mutant/object"
)

// Nothing in this repo measured graphene. `grep "func Benchmark" builtin/`
// returned nothing, so every figure about the graph builtins came from
// upstream's benchmark suite -- run on upstream's hardware, against upstream's
// API rather than through the marshalling layer a Mutant script actually pays
// for.
//
// These measure that layer. Read B/op and allocs/op: those are deterministic
// and comparable between runs. ns/op is not, and no claim about a change in it
// is supported by a single run of this file -- compare arms by interleaving
// them (-count=6 and alternating the trees), which is the method upstream
// documents and the only one that survived its own scrutiny.

// benchHandle opens a graph for a benchmark and closes it afterwards. The
// b.TempDir form is used for the disk arm so the WAL and image are real files.
func benchHandle(b *testing.B, onDisk bool) *object.Integer {
	b.Helper()

	var result object.Object
	if onDisk {
		result = DbOpenDisk(stringObj(b.TempDir()))
	} else {
		result = DbOpen()
	}

	pair, ok := result.(*object.MultiValue)
	if !ok || len(pair.Values) != 2 {
		b.Fatalf("open did not return a pair: %T", result)
	}
	handle, ok := pair.Values[0].(*object.Integer)
	if !ok {
		b.Fatalf("open payload type: %T", pair.Values[0])
	}
	b.Cleanup(func() { DbClose(handle) })
	return handle
}

func eachBackend(b *testing.B, run func(b *testing.B, handle *object.Integer)) {
	b.Helper()
	for _, backend := range []struct {
		name   string
		onDisk bool
	}{{"memory", false}, {"disk", true}} {
		b.Run(backend.name, func(b *testing.B) {
			handle := benchHandle(b, backend.onDisk)
			b.ReportAllocs()
			b.ResetTimer()
			run(b, handle)
		})
	}
}

func BenchmarkDbAddNode(b *testing.B) {
	eachBackend(b, func(b *testing.B, handle *object.Integer) {
		for i := 0; i < b.N; i++ {
			DbAddNode(handle)
		}
	})
}

// BenchmarkDbAddArtifact is the one worth watching. It is the call a forensic
// script makes per artifact, and it was one AddNode plus one IndexNodeProperty
// per attribute -- each its own commit -- before it became one transaction.
func BenchmarkDbAddArtifact(b *testing.B) {
	attrs := makeHashObject(map[string]object.Object{
		"path":   stringObj("/evidence/sample.bin"),
		"sha256": stringObj("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		"size":   intObj(4096),
		"mtime":  stringObj("2026-09-17T00:00:00Z"),
	})
	artifactType := stringObj("file")

	eachBackend(b, func(b *testing.B, handle *object.Integer) {
		for i := 0; i < b.N; i++ {
			DbAddArtifact(handle, artifactType, attrs)
		}
	})
}

func BenchmarkDbIndexProp(b *testing.B) {
	eachBackend(b, func(b *testing.B, handle *object.Integer) {
		b.StopTimer()
		nodeID := benchNode(b, handle)
		key := stringObj("indexed_key")
		b.StartTimer()

		for i := 0; i < b.N; i++ {
			DbIndexProp(handle, nodeID, key, stringObj(fmt.Sprintf("v%d", i)))
		}
	})
}

// BenchmarkDbQueryNodes reads rather than writes, over a graph built once. The
// build is outside the timer because it is not what is being measured.
func BenchmarkDbQueryNodes(b *testing.B) {
	eachBackend(b, func(b *testing.B, handle *object.Integer) {
		b.StopTimer()
		for i := 0; i < 1000; i++ {
			DbAddNode(handle)
		}
		b.StartTimer()

		for i := 0; i < b.N; i++ {
			DbQueryNodes(handle)
		}
	})
}

// BenchmarkDbBFS walks a 1,000-node chain to a depth of 12, which is the shape
// upstream measures the traversal on and so the one whose figures are
// comparable.
func BenchmarkDbBFS(b *testing.B) {
	depth := intObj(12)
	direction := stringObj("out")

	eachBackend(b, func(b *testing.B, handle *object.Integer) {
		b.StopTimer()
		origin := benchNode(b, handle)
		previous := origin
		for i := 0; i < 1000; i++ {
			next := benchNode(b, handle)
			DbAddEdge(handle, previous, next)
			previous = next
		}
		b.StartTimer()

		for i := 0; i < b.N; i++ {
			DbBFS(handle, origin, depth, direction)
		}
	})
}

// BenchmarkDbCompact measures the call that gives the memory back. Each
// iteration rebuilds the delta it then merges, because compacting an already
// compacted store measures nothing.
func BenchmarkDbCompact(b *testing.B) {
	handle := benchHandle(b, true)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for n := 0; n < 200; n++ {
			DbAddNode(handle)
		}
		b.StartTimer()

		DbCompact(handle)
	}
}

func benchNode(b *testing.B, handle *object.Integer) *object.Integer {
	b.Helper()
	pair, ok := DbAddNode(handle).(*object.MultiValue)
	if !ok || len(pair.Values) != 2 {
		b.Fatal("db_add_node did not return a pair")
	}
	id, ok := pair.Values[0].(*object.Integer)
	if !ok {
		b.Fatalf("db_add_node payload type: %T", pair.Values[0])
	}
	return id
}
