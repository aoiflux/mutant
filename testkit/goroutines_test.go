package testkit

import (
	"strings"
	"testing"
	"time"
)

func TestCheckGoroutinesAcceptsGoroutinesThatFinish(t *testing.T) {
	CheckGoroutines(t)
	done := make(chan struct{})
	go func() {
		time.Sleep(goroutinePollInterval)
		close(done)
	}()
	<-done
}

// The detection itself, exercised directly: testing.TB cannot be implemented
// outside the testing package, so the failing path is checked through the
// function CheckGoroutines' cleanup calls.
func TestNewGoroutinesNamesALeak(t *testing.T) {
	before := goroutineIDs()
	release := make(chan struct{})
	go leakUntilReleased(release)
	defer close(release)

	deadline := time.Now().Add(GoroutineSettleTimeout)
	for time.Now().Before(deadline) {
		for _, stack := range newGoroutines(before) {
			if strings.Contains(stack, "leakUntilReleased") {
				return
			}
		}
		time.Sleep(goroutinePollInterval)
	}
	t.Fatal("a goroutine blocked on a channel was not reported as new")
}

func leakUntilReleased(release chan struct{}) { <-release }
