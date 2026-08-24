package builtin

// Channels are how concurrently running Mutant code hands values across. A
// spawned task, a net_serve handler and a pmap worker each run on their own VM
// with their own globals, so there is no shared variable for them to meet in; a
// channel is that meeting point.
//
// A channel is a Go channel behind an INTEGER handle, the same shape net_listen,
// bytes_cursor_new and db_open already use. That keeps the whole feature inside
// this package: no new object type for mutil.EncryptObject/DecryptObject, the
// gob registrations and the polymorphic engine to learn, and no new opcode.
//
// Values need no copying on the way through. Every argument a builtin receives
// has already been rebuilt by mutil.DecryptObject -- arrays, hashes, structs and
// enum values are all reconstructed element by element -- and every value a VM
// receives back is rebuilt again when it is pushed. Neither side can hold a
// reference into the other, which is the same share-nothing guarantee pmap
// relies on.

import (
	"sync"
	"time"

	"mutant/object"
)

// maxChannelCapacity bounds the buffer a single chan_new may allocate, so a
// script cannot request a multi-gigabyte channel. It mirrors the cap
// net_conn_read puts on a single read.
const maxChannelCapacity = 1 << 20

// maxLiveChannels bounds how many channels may be open at once, and
// maxRetainedChannels how many closed ones stay addressable afterwards. Both
// mirror the task registry deliberately: they are the same resource with the
// same failure mode. Channels were the one handle registry in this package that
// never released anything at all -- chan_close keeps a handle valid so a
// receiver can drain what was already queued, and nothing ever reclaimed it, so
// a chan_new per connection leaked a Go channel, a map entry and every value
// still buffered in it for the life of the process.
//
// Reaching the ceiling is an error rather than a wait, for the reason
// RegisterTask gives: blocking is backpressure for an accept loop but a deadlock
// for code waiting on a sibling it cannot create.
const maxLiveChannels = 1024
const maxRetainedChannels = 4096

// managedChannel carries its closed state in a second channel rather than a
// boolean, because a sender may be blocked inside a send when chan_close runs.
// A mutex around the send would deadlock against exactly that case; a done
// channel lets both the send and the receive select on "closed" while they wait.
type managedChannel struct {
	ch        chan object.Object
	done      chan struct{}
	closeOnce sync.Once
}

// closeChannel reports whether this call was the one that closed the channel, so
// chan_close can tell a caller its close was a no-op.
func (mc *managedChannel) closeChannel() bool {
	first := false
	mc.closeOnce.Do(func() {
		close(mc.done)
		first = true
	})
	return first
}

// drain takes a buffered value without waiting, if one is there.
func (mc *managedChannel) drain() (object.Object, bool) {
	select {
	case v := <-mc.ch:
		return v, true
	default:
		return nil, false
	}
}

var channelRegistry = struct {
	sync.Mutex
	channels map[int64]*managedChannel
	nextID   int64
	live     int
	// closed lists handles in close order, so the oldest closed channel is the
	// one dropped once retention fills. An entry stays here after its handle is
	// deleted; evicting it again is a no-op delete, which keeps both closing and
	// evicting constant-time. taskRegistry.finished works the same way.
	closed []int64
}{
	channels: map[int64]*managedChannel{},
	nextID:   1,
}

// registerChannel reserves a handle and counts the channel as open.
func registerChannel(mc *managedChannel) (int64, *object.Error) {
	channelRegistry.Lock()
	if channelRegistry.live >= maxLiveChannels {
		channelRegistry.Unlock()
		return 0, newError("chan_new: too many channels open at once (limit %d); close some with chan_close", maxLiveChannels)
	}
	id := channelRegistry.nextID
	channelRegistry.nextID++
	channelRegistry.live++
	channelRegistry.channels[id] = mc
	channelRegistry.Unlock()
	return id, nil
}

// retireChannel records a channel as no longer open and evicts the oldest
// closed handles once retention fills.
//
// It deliberately does not delete the handle that was just closed. A receiver
// is allowed to keep draining values queued before the close, which is what
// makes closing a channel a way to end a receive loop rather than a way to
// discard whatever was still in flight.
func retireChannel(id int64) {
	channelRegistry.Lock()
	channelRegistry.live--
	channelRegistry.closed = append(channelRegistry.closed, id)
	for len(channelRegistry.closed) > maxRetainedChannels {
		delete(channelRegistry.channels, channelRegistry.closed[0])
		channelRegistry.closed = channelRegistry.closed[1:]
	}
	channelRegistry.Unlock()
}

// LiveChannelCount reports how many channels are open but not yet closed. It
// mirrors LiveTaskCount.
func LiveChannelCount() int {
	channelRegistry.Lock()
	defer channelRegistry.Unlock()
	return channelRegistry.live
}

func lookupChannel(id int64) (*managedChannel, bool) {
	channelRegistry.Lock()
	mc, ok := channelRegistry.channels[id]
	channelRegistry.Unlock()
	return mc, ok
}

// channelArg resolves argument 1 of every chan_* builtin: an INTEGER handle that
// names a live channel.
func channelArg(op string, arg object.Object) (*managedChannel, *object.Error) {
	handle, ok := arg.(*object.Integer)
	if !ok {
		return nil, newError("argument 1 to %s must be INTEGER, got %s", op, arg.Type())
	}
	mc, found := lookupChannel(handle.Value)
	if !found {
		return nil, newError("%s: unknown channel handle %d", op, handle.Value)
	}
	return mc, nil
}

// timeoutArg reads an optional trailing milliseconds argument. A negative or
// absent timeout means "wait indefinitely"; zero means "do not wait at all".
func timeoutArg(op string, position int, arg object.Object) (int64, *object.Error) {
	ms, ok := arg.(*object.Integer)
	if !ok {
		return 0, newError("argument %d to %s must be INTEGER, got %s", position, op, arg.Type())
	}
	return ms.Value, nil
}

// ChanNew creates a channel and returns its handle.
// chan_new(capacity?) -> (INTEGER handle, err)
//
// Capacity 0 (the default) is unbuffered: a send waits for a receive. A positive
// capacity lets that many values queue before a send starts waiting.
func ChanNew(args ...object.Object) object.Object {
	if len(args) > 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=0 or 1", len(args)))
	}

	capacity := int64(0)
	if len(args) == 1 {
		sizeObj, ok := args[0].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 1 to chan_new must be INTEGER, got %s", args[0].Type()))
		}
		if sizeObj.Value < 0 {
			return resultAndError(nil, newError("chan_new: capacity must not be negative, got %d", sizeObj.Value))
		}
		if sizeObj.Value > maxChannelCapacity {
			return resultAndError(nil, newError("chan_new: capacity %d exceeds the maximum of %d", sizeObj.Value, maxChannelCapacity))
		}
		capacity = sizeObj.Value
	}

	mc := &managedChannel{
		ch:   make(chan object.Object, capacity),
		done: make(chan struct{}),
	}
	handle, errObj := registerChannel(mc)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	return resultAndError(intObj(handle), nil)
}

// ChanSend puts a value on a channel.
// chan_send(handle, value, timeoutMs?) -> (BOOLEAN sent, err)
//
// It returns true once the value is handed over, and false if the timeout ran
// out first. Sending on a closed channel is an error rather than a false: the
// value had nowhere to go, and reporting that as a plain timeout would hide lost
// work behind a retry.
func ChanSend(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	mc, errObj := channelArg("chan_send", args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	timeoutMs := int64(-1)
	if len(args) == 3 {
		var terr *object.Error
		if timeoutMs, terr = timeoutArg("chan_send", 3, args[2]); terr != nil {
			return resultAndError(nil, terr)
		}
	}

	// Report an already-closed channel before waiting, so a closed channel fails
	// immediately rather than after the full timeout.
	select {
	case <-mc.done:
		return resultAndError(boolObj(false), newError("chan_send: channel is closed"))
	default:
	}

	if timeoutMs == 0 {
		select {
		case mc.ch <- args[1]:
			return resultAndError(boolObj(true), nil)
		case <-mc.done:
			return resultAndError(boolObj(false), newError("chan_send: channel is closed"))
		default:
			return resultAndError(boolObj(false), nil)
		}
	}

	var timeout <-chan time.Time
	if timeoutMs > 0 {
		timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case mc.ch <- args[1]:
		return resultAndError(boolObj(true), nil)
	case <-mc.done:
		return resultAndError(boolObj(false), newError("chan_send: channel is closed"))
	case <-timeout:
		return resultAndError(boolObj(false), nil)
	}
}

// receiveResult renders the outcome of a receive. Whether a value arrived is a
// field rather than a null return, because null is itself a sendable value:
// reading result["ok"] is the only way to tell "received null" from "received
// nothing". net_accept reports itself the same way.
func receiveResult(value object.Object, ok, closed, timedOut bool) object.Object {
	if value == nil {
		value = &object.Null{}
	}
	return makeHashObject(map[string]object.Object{
		"ok":      boolObj(ok),
		"value":   value,
		"closed":  boolObj(closed),
		"timeout": boolObj(timedOut),
	})
}

// ChanRecv takes the next value off a channel.
// chan_recv(handle, timeoutMs?) -> ({ok, value, closed, timeout}, err)
//
// Values already queued are delivered even after the channel is closed, so a
// receive loop drains a closed channel before it ever sees closed=true.
func ChanRecv(args ...object.Object) object.Object {
	if len(args) != 1 && len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1 or 2", len(args)))
	}
	mc, errObj := channelArg("chan_recv", args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	timeoutMs := int64(-1)
	if len(args) == 2 {
		var terr *object.Error
		if timeoutMs, terr = timeoutArg("chan_recv", 2, args[1]); terr != nil {
			return resultAndError(nil, terr)
		}
	}

	// A queued value outranks a closed channel, so closing never discards what
	// was already sent.
	if v, ok := mc.drain(); ok {
		return resultAndError(receiveResult(v, true, false, false), nil)
	}

	if timeoutMs == 0 {
		select {
		case <-mc.done:
			if v, ok := mc.drain(); ok {
				return resultAndError(receiveResult(v, true, false, false), nil)
			}
			return resultAndError(receiveResult(nil, false, true, false), nil)
		default:
			return resultAndError(receiveResult(nil, false, false, false), nil)
		}
	}

	var timeout <-chan time.Time
	if timeoutMs > 0 {
		timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case v := <-mc.ch:
		return resultAndError(receiveResult(v, true, false, false), nil)
	case <-mc.done:
		// A sender may have queued a value in the moment before the close, and
		// select picks among ready cases at random, so re-check the buffer.
		if v, ok := mc.drain(); ok {
			return resultAndError(receiveResult(v, true, false, false), nil)
		}
		return resultAndError(receiveResult(nil, false, true, false), nil)
	case <-timeout:
		return resultAndError(receiveResult(nil, false, false, true), nil)
	}
}

// ChanTryRecv takes a value only if one is already waiting, and never blocks.
// chan_try_recv(handle) -> ({ok, value, closed, timeout}, err)
func ChanTryRecv(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	if _, errObj := channelArg("chan_try_recv", args[0]); errObj != nil {
		return resultAndError(nil, errObj)
	}
	return ChanRecv(args[0], intObj(0))
}

// ChanClose closes a channel, waking every waiting sender and receiver.
// chan_close(handle) -> (BOOLEAN, err)
//
// It returns true when this call did the closing and false when the channel was
// already closed, so a double close reports rather than aborting. The handle
// stays valid afterwards so receivers can still drain what was queued.
func ChanClose(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	mc, errObj := channelArg("chan_close", args[0])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	first := mc.closeChannel()
	if first {
		retireChannel(args[0].(*object.Integer).Value)
	}
	return resultAndError(boolObj(first), nil)
}
