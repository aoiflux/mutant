package vm

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

// The point of pmap is wall-clock, so measure it rather than assert it in the
// abstract. The callback here sleeps, standing in for the per-element I/O that
// dominates real collection work: hashing a file, resolving a domain, reading a
// registry hive.
//
// This is a test rather than only a benchmark because "pmap compiles and returns
// the right answers" is worth nothing if it silently runs one element at a time.
// The margin is deliberately loose -- sequential would be ~8x the parallel time,
// so requiring merely a 2x improvement leaves plenty of room on a loaded
// machine while still failing outright if the work is not overlapping.
func TestPMapActuallyOverlapsWork(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("needs more than one CPU to overlap work")
	}
	if testing.Short() {
		t.Skip("timing test; skipped under -short")
	}

	const (
		elements  = 8
		sleepMs   = 60
		sequenceM = elements * sleepMs
	)

	source := func(op string) string {
		return fmt.Sprintf(`%s(range(0, %d), fn(x) { sleep_ms(%d); return x; }, %d)`,
			op, elements, sleepMs, elements)
	}

	start := time.Now()
	if _, err := runEncryptedVM(source("pmap")); err != nil {
		t.Fatalf("pmap failed: %s", err)
	}
	parallel := time.Since(start)

	// The whole sequential cost, for the comparison to be meaningful.
	sequentialBudget := time.Duration(sequenceM) * time.Millisecond

	if parallel > sequentialBudget/2 {
		t.Fatalf("pmap of %d x %dms took %s; sequential would be about %s, so the work is not overlapping",
			elements, sleepMs, parallel, sequentialBudget)
	}
	t.Logf("pmap of %d x %dms took %s (sequential would be about %s)",
		elements, sleepMs, parallel, sequentialBudget)
}

// BenchmarkMapVsPMap reports the speedup on a CPU-bound callback. Run with:
//
//	go test ./vm/ -run '^$' -bench 'MapVsPMap' -benchtime 5x
func BenchmarkMapVsPMap(b *testing.B) {
	// Enough arithmetic per element that the callback, not the VM's dispatch
	// overhead, dominates.
	const source = `
		let work = fn(n) {
			let total = 0;
			for (let i = 0; i < 3000; i++) { total += (i * n) %% 7; }
			return total;
		};
		let xs = range(0, 64);
		%s(xs, fn(x) { work(x) })
	`

	for _, op := range []string{"map", "pmap"} {
		b.Run(op, func(b *testing.B) {
			program := fmt.Sprintf(source, op)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := runEncryptedVM(program); err != nil {
					b.Fatalf("%s failed: %s", op, err)
				}
			}
		})
	}
}
