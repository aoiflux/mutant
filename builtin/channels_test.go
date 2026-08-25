package builtin

import (
	"strings"
	"sync"
	"testing"
	"time"

	"mutant/object"
)

// newTestChannel opens a channel and returns its handle, failing the test if the
// open itself reports a problem.
func newTestChannel(t *testing.T, capacity int64) *object.Integer {
	t.Helper()
	result, err := unwrapPair(t, ChanNew(&object.Integer{Value: capacity}))
	if err != nil {
		t.Fatalf("chan_new(%d) failed: %s", capacity, err.Message)
	}
	handle, ok := result.(*object.Integer)
	if !ok {
		t.Fatalf("chan_new returned %T, want *object.Integer", result)
	}
	return handle
}

// recvFields reads the four fields chan_recv reports.
func recvFields(t *testing.T, value object.Object) (object.Object, bool, bool, bool) {
	t.Helper()
	hash, ok := value.(*object.Hash)
	if !ok {
		t.Fatalf("receive returned %T, want *object.Hash", value)
	}
	field := func(name string) object.Object {
		key := (&object.String{Value: name}).HashKey()
		pair, present := hash.Pairs[key]
		if !present {
			t.Fatalf("receive result has no %q field", name)
		}
		return pair.Value
	}
	asBool := func(name string) bool {
		b, isBool := field(name).(*object.Boolean)
		if !isBool {
			t.Fatalf("receive field %q is %T, want *object.Boolean", name, field(name))
		}
		return b.Value
	}
	return field("value"), asBool("ok"), asBool("closed"), asBool("timeout")
}

// A buffered channel takes values without a receiver waiting, and gives them
// back in the order they were sent.
func TestChannelBufferedRoundTrip(t *testing.T) {
	handle := newTestChannel(t, 3)

	for _, want := range []int64{1, 2, 3} {
		sent, err := unwrapPair(t, ChanSend(handle, &object.Integer{Value: want}))
		if err != nil {
			t.Fatalf("chan_send(%d) failed: %s", want, err.Message)
		}
		if b, ok := sent.(*object.Boolean); !ok || !b.Value {
			t.Fatalf("chan_send(%d) returned %s, want true", want, sent.Inspect())
		}
	}

	for _, want := range []int64{1, 2, 3} {
		result, err := unwrapPair(t, ChanRecv(handle))
		if err != nil {
			t.Fatalf("chan_recv failed: %s", err.Message)
		}
		value, ok, closed, timedOut := recvFields(t, result)
		if !ok || closed || timedOut {
			t.Fatalf("chan_recv reported ok=%v closed=%v timeout=%v, want a plain value", ok, closed, timedOut)
		}
		got, isInt := value.(*object.Integer)
		if !isInt || got.Value != want {
			t.Fatalf("chan_recv returned %s, want %d", value.Inspect(), want)
		}
	}
}

// An unbuffered send waits for a receiver, which is the whole point of capacity
// zero: it is a handoff, not a queue.
func TestChannelUnbufferedHandsOff(t *testing.T) {
	handle := newTestChannel(t, 0)

	// The send cannot complete on its own, so a zero timeout must report that
	// rather than block or claim success.
	sent, err := unwrapPair(t, ChanSend(handle, &object.Integer{Value: 7}, &object.Integer{Value: 0}))
	if err != nil {
		t.Fatalf("chan_send with a zero timeout failed: %s", err.Message)
	}
	if b, ok := sent.(*object.Boolean); !ok || b.Value {
		t.Fatalf("chan_send on an empty unbuffered channel returned %s, want false", sent.Inspect())
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ChanSend(handle, &object.Integer{Value: 42})
	}()

	result, err := unwrapPair(t, ChanRecv(handle, &object.Integer{Value: 5000}))
	if err != nil {
		t.Fatalf("chan_recv failed: %s", err.Message)
	}
	value, ok, _, _ := recvFields(t, result)
	if !ok {
		t.Fatal("chan_recv did not receive the handed-off value")
	}
	if got, isInt := value.(*object.Integer); !isInt || got.Value != 42 {
		t.Fatalf("chan_recv returned %s, want 42", value.Inspect())
	}
	wg.Wait()
}

// Closing must not discard what was already sent: a receive loop has to see
// every queued value before it sees closed.
func TestChannelCloseDrainsQueuedValues(t *testing.T) {
	handle := newTestChannel(t, 4)
	for i := int64(0); i < 4; i++ {
		ChanSend(handle, &object.Integer{Value: i})
	}

	closed, err := unwrapPair(t, ChanClose(handle))
	if err != nil {
		t.Fatalf("chan_close failed: %s", err.Message)
	}
	if b, ok := closed.(*object.Boolean); !ok || !b.Value {
		t.Fatalf("chan_close returned %s, want true for the first close", closed.Inspect())
	}

	for i := int64(0); i < 4; i++ {
		result, recvErr := unwrapPair(t, ChanRecv(handle))
		if recvErr != nil {
			t.Fatalf("chan_recv after close failed: %s", recvErr.Message)
		}
		value, ok, isClosed, _ := recvFields(t, result)
		if !ok {
			t.Fatalf("value %d was dropped by the close (closed=%v)", i, isClosed)
		}
		if got, isInt := value.(*object.Integer); !isInt || got.Value != i {
			t.Fatalf("drained %s, want %d", value.Inspect(), i)
		}
	}

	result, err := unwrapPair(t, ChanRecv(handle))
	if err != nil {
		t.Fatalf("chan_recv on a drained closed channel failed: %s", err.Message)
	}
	_, ok, isClosed, _ := recvFields(t, result)
	if ok || !isClosed {
		t.Fatalf("a drained closed channel reported ok=%v closed=%v, want ok=false closed=true", ok, isClosed)
	}
}

// A second close reports rather than aborting, so a cleanup path that runs twice
// is not a crash.
func TestChannelDoubleCloseReports(t *testing.T) {
	handle := newTestChannel(t, 0)
	ChanClose(handle)

	closed, err := unwrapPair(t, ChanClose(handle))
	if err != nil {
		t.Fatalf("the second chan_close failed: %s", err.Message)
	}
	if b, ok := closed.(*object.Boolean); !ok || b.Value {
		t.Fatalf("the second chan_close returned %s, want false", closed.Inspect())
	}
}

// Sending into a closed channel loses the value, so it is an error rather than a
// quiet false that a caller could mistake for a timeout worth retrying.
func TestChannelSendOnClosedIsAnError(t *testing.T) {
	handle := newTestChannel(t, 1)
	ChanClose(handle)

	_, err := unwrapPair(t, ChanSend(handle, &object.Integer{Value: 1}))
	if err == nil {
		t.Fatal("chan_send on a closed channel reported success")
	}
	if err.Message != "chan_send: channel is closed" {
		t.Fatalf("error = %q, want it to name the closed channel", err.Message)
	}
}

// Closing while a receiver is parked must wake it, not leave it waiting for a
// value that will never come.
func TestChannelCloseWakesAWaitingReceiver(t *testing.T) {
	handle := newTestChannel(t, 0)

	done := make(chan object.Object, 1)
	go func() {
		result, _ := unwrapPairNoFatal(ChanRecv(handle))
		done <- result
	}()

	// Give the receiver a moment to park before closing, so the test exercises
	// the wake path rather than the already-closed shortcut.
	time.Sleep(50 * time.Millisecond)
	ChanClose(handle)

	select {
	case result := <-done:
		_, ok, isClosed, _ := recvFields(t, result)
		if ok || !isClosed {
			t.Fatalf("the woken receiver reported ok=%v closed=%v, want ok=false closed=true", ok, isClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("chan_close did not wake the waiting receiver")
	}
}

// A receive that runs out of time says so, and says it distinctly from a closed
// channel, because the two call for different responses.
func TestChannelRecvTimeoutIsDistinctFromClosed(t *testing.T) {
	handle := newTestChannel(t, 0)

	start := time.Now()
	result, err := unwrapPair(t, ChanRecv(handle, &object.Integer{Value: 60}))
	if err != nil {
		t.Fatalf("chan_recv failed: %s", err.Message)
	}
	elapsed := time.Since(start)

	_, ok, isClosed, timedOut := recvFields(t, result)
	if ok || isClosed || !timedOut {
		t.Fatalf("reported ok=%v closed=%v timeout=%v, want timeout alone", ok, isClosed, timedOut)
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("chan_recv returned after %s, so it did not actually wait for its 60ms", elapsed)
	}
}

// chan_try_recv never blocks, whether or not a value is waiting.
func TestChannelTryRecv(t *testing.T) {
	handle := newTestChannel(t, 1)

	result, err := unwrapPair(t, ChanTryRecv(handle))
	if err != nil {
		t.Fatalf("chan_try_recv on an empty channel failed: %s", err.Message)
	}
	if _, ok, isClosed, timedOut := recvFields(t, result); ok || isClosed || timedOut {
		t.Fatalf("an empty chan_try_recv reported ok=%v closed=%v timeout=%v, want all false", ok, isClosed, timedOut)
	}

	ChanSend(handle, &object.String{Value: "ready"})
	result, err = unwrapPair(t, ChanTryRecv(handle))
	if err != nil {
		t.Fatalf("chan_try_recv failed: %s", err.Message)
	}
	value, ok, _, _ := recvFields(t, result)
	if !ok {
		t.Fatal("chan_try_recv missed a value that was waiting")
	}
	if got, isStr := value.(*object.String); !isStr || got.Value != "ready" {
		t.Fatalf("chan_try_recv returned %s, want \"ready\"", value.Inspect())
	}
}

// null is a sendable value, which is exactly why the receive reports arrival in
// a field instead of by returning null.
func TestChannelCarriesNullAsAValue(t *testing.T) {
	handle := newTestChannel(t, 1)
	ChanSend(handle, &object.Null{})

	result, err := unwrapPair(t, ChanRecv(handle))
	if err != nil {
		t.Fatalf("chan_recv failed: %s", err.Message)
	}
	value, ok, _, _ := recvFields(t, result)
	if !ok {
		t.Fatal("a sent null was reported as nothing received")
	}
	if value.Type() != object.NULL_OBJ {
		t.Fatalf("received %s, want NULL", value.Type())
	}
}

// Many senders and many receivers on one channel must lose nothing and duplicate
// nothing. Run with -race for the rest.
func TestChannelUnderConcurrentSendersAndReceivers(t *testing.T) {
	const (
		senders          = 8
		valuesPerSender  = 200
		receivers        = 8
		expectedReceived = senders * valuesPerSender
	)

	handle := newTestChannel(t, 16)

	var sendWG sync.WaitGroup
	for s := 0; s < senders; s++ {
		sendWG.Add(1)
		go func(base int64) {
			defer sendWG.Done()
			for i := int64(0); i < valuesPerSender; i++ {
				ChanSend(handle, &object.Integer{Value: base + i})
			}
		}(int64(s * valuesPerSender))
	}

	var (
		mu       sync.Mutex
		seen     = map[int64]int{}
		received int
		recvWG   sync.WaitGroup
	)
	for r := 0; r < receivers; r++ {
		recvWG.Add(1)
		go func() {
			defer recvWG.Done()
			for {
				result, err := unwrapPairNoFatal(ChanRecv(handle, &object.Integer{Value: 2000}))
				if err != nil {
					return
				}
				hash, isHash := result.(*object.Hash)
				if !isHash {
					return
				}
				okPair := hash.Pairs[(&object.String{Value: "ok"}).HashKey()]
				if b, isBool := okPair.Value.(*object.Boolean); !isBool || !b.Value {
					return // closed or timed out
				}
				valuePair := hash.Pairs[(&object.String{Value: "value"}).HashKey()]
				n, isInt := valuePair.Value.(*object.Integer)
				if !isInt {
					return
				}
				mu.Lock()
				seen[n.Value]++
				received++
				mu.Unlock()
			}
		}()
	}

	sendWG.Wait()
	ChanClose(handle)
	recvWG.Wait()

	if received != expectedReceived {
		t.Fatalf("received %d values, want %d", received, expectedReceived)
	}
	for i := 0; i < expectedReceived; i++ {
		if count := seen[int64(i)]; count != 1 {
			t.Fatalf("value %d was received %d times, want exactly once", i, count)
		}
	}
}

// Argument problems come back as catchable errors, not aborts.
func TestChannelArgumentValidation(t *testing.T) {
	handle := newTestChannel(t, 1)

	cases := []struct {
		name string
		call func() object.Object
		want string
	}{
		{"unknown handle", func() object.Object { return ChanRecv(&object.Integer{Value: 999999}) },
			"chan_recv: unknown channel handle 999999"},
		{"handle is not an integer", func() object.Object { return ChanSend(&object.String{Value: "x"}, &object.Integer{Value: 1}) },
			"argument 1 to chan_send must be INTEGER, got STRING"},
		{"timeout is not an integer", func() object.Object { return ChanRecv(handle, &object.String{Value: "soon"}) },
			"argument 2 to chan_recv must be INTEGER, got STRING"},
		{"negative capacity", func() object.Object { return ChanNew(&object.Integer{Value: -1}) },
			"chan_new: capacity must not be negative, got -1"},
		{"capacity beyond the cap", func() object.Object { return ChanNew(&object.Integer{Value: maxChannelCapacity + 1}) },
			"chan_new: capacity 1048577 exceeds the maximum of 1048576"},
		{"too many arguments", func() object.Object { return ChanClose(handle, handle) },
			"wrong number of arguments. got=2, want=1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := unwrapPair(t, tc.call())
			if err == nil {
				t.Fatal("expected an error")
			}
			if err.Message != tc.want {
				t.Fatalf("error = %q, want %q", err.Message, tc.want)
			}
		})
	}
}

// A channel that is opened and never closed is a live resource; a channel that
// is closed is a bounded amount of memory that a later close will reclaim.
// Neither used to be true -- the registry only ever grew.

func TestClosingAChannelStopsCountingItAsOpen(t *testing.T) {
	before := LiveChannelCount()

	handle := newTestChannel(t, 1)
	if got := LiveChannelCount(); got != before+1 {
		t.Fatalf("opening a channel moved the live count %d -> %d, want +1", before, got)
	}

	if _, err := unwrapPair(t, ChanClose(handle)); err != nil {
		t.Fatalf("chan_close failed: %s", err.Message)
	}
	if got := LiveChannelCount(); got != before {
		t.Fatalf("closing a channel left the live count at %d, want %d", got, before)
	}

	// A second close is a no-op and must not decrement twice, or a program that
	// closes defensively would drive the count negative and buy itself extra
	// channels past the ceiling.
	if _, err := unwrapPair(t, ChanClose(handle)); err != nil {
		t.Fatalf("second chan_close failed: %s", err.Message)
	}
	if got := LiveChannelCount(); got != before {
		t.Fatalf("a repeated close moved the live count to %d, want %d", got, before)
	}
}

func TestOpeningPastTheCeilingIsAnError(t *testing.T) {
	opened := make([]*object.Integer, 0, maxLiveChannels)
	defer func() {
		for _, handle := range opened {
			ChanClose(handle)
		}
	}()

	var ceilingErr string
	for i := 0; i < maxLiveChannels+1; i++ {
		result, err := unwrapPair(t, ChanNew(&object.Integer{Value: 0}))
		if err != nil {
			ceilingErr = err.Message
			break
		}
		opened = append(opened, result.(*object.Integer))
	}

	if ceilingErr == "" {
		t.Fatalf("opened %d channels with no ceiling; the registry is unbounded", len(opened))
	}
	if !strings.Contains(ceilingErr, "too many channels open at once") {
		t.Fatalf("the ceiling error does not say what happened: %s", ceilingErr)
	}
}

// Retention is the backstop for fire-and-forget code that closes channels and
// never looks at them again. A closed handle stays addressable -- that is what
// lets a receiver drain what was queued -- until enough others have been closed
// after it.
func TestClosedChannelsAreReclaimedOnceRetentionFills(t *testing.T) {
	first := newTestChannel(t, 1)
	if _, err := unwrapPair(t, ChanSend(first, &object.Integer{Value: 7})); err != nil {
		t.Fatalf("chan_send failed: %s", err.Message)
	}
	if _, err := unwrapPair(t, ChanClose(first)); err != nil {
		t.Fatalf("chan_close failed: %s", err.Message)
	}

	// Still addressable straight after the close, with its queued value intact.
	value, err := unwrapPair(t, ChanRecv(first, &object.Integer{Value: 0}))
	if err != nil {
		t.Fatalf("draining a just-closed channel failed: %s", err.Message)
	}
	if got, ok, _, _ := recvFields(t, value); !ok || got.Inspect() != "7" {
		t.Fatalf("a just-closed channel did not hand back its queued value, got %s (ok=%v)", got.Inspect(), ok)
	}

	for i := 0; i < maxRetainedChannels; i++ {
		handle := newTestChannel(t, 0)
		if _, err := unwrapPair(t, ChanClose(handle)); err != nil {
			t.Fatalf("chan_close failed on filler %d: %s", i, err.Message)
		}
	}

	if _, err := unwrapPair(t, ChanRecv(first, &object.Integer{Value: 0})); err == nil {
		t.Fatal("the oldest closed channel survived retention; closed handles are never reclaimed")
	} else if !strings.Contains(err.Message, "unknown channel handle") {
		t.Fatalf("an evicted handle reported something else: %s", err.Message)
	}
}
