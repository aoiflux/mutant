package security

// The audit sink.
//
// Every Record* function in telemetry.go increments a counter and calls
// auditEvent. For most of this project's life auditEvent did nothing, so the
// manifest could say the debugger check had tripped eleven times and nothing
// anywhere could say when, at which stage, or in what order relative to the
// evidence that was open at the time. A count answers "how many". An
// investigation asks "what happened, and in what order", and a counter cannot
// be asked that question afterwards.
//
// The sink is an interface and not a writer because the code that knows how to
// record a security event forensically -- hash-chained, bound into the case
// manifest it has to travel beside -- lives in `builtin`, and `security` cannot
// import `builtin` without a cycle. So `security` publishes the hole and
// `builtin` fills it at init. Nothing in this package knows what a case is.
//
// The cost when no sink is installed is one atomic load and a nil check, which
// is deliberate: RecordDebuggerDetected is reachable from OpChkDbg, an opcode
// the compiler emits inside loops, and an audit hook that made a checked loop
// measurably slower is an audit hook somebody would find a way to switch off.

import "sync/atomic"

// AuditSink receives every security event at the moment it is recorded.
//
// Implementations are called from whichever goroutine tripped the check --
// including the VM's own execution loop and a spawned task's -- so AuditEvent
// must be safe for concurrent use and must not block. It must also not call
// back into this package: a sink that recorded an event by running a command
// would record its own recording, forever.
type AuditSink interface {
	AuditEvent(event, stage string)
}

// auditSink holds a *AuditSink rather than an AuditSink because atomic.Pointer
// needs something addressable; the extra indirection is one load either way.
var auditSink atomic.Pointer[AuditSink]

// SetAuditSink installs sink and returns whatever it replaced, so a caller that
// borrows the seam -- a test, an embedding host -- can put back what was there.
// A nil sink uninstalls, returning the package to the state in which events are
// counted and nothing is logged.
//
// There is no locking around the swap. An event racing an install lands in
// exactly one of the two sinks and is never lost from both, which is the most a
// swap can promise; installing once at startup, as `builtin` does, avoids the
// question entirely.
func SetAuditSink(sink AuditSink) AuditSink {
	var previous AuditSink
	if old := auditSink.Load(); old != nil {
		previous = *old
	}
	if sink == nil {
		auditSink.Store(nil)
		return previous
	}
	auditSink.Store(&sink)
	return previous
}

// AuditSinkInstalled reports whether security events are being recorded
// anywhere. It exists so a document can say "no audit log was kept" rather than
// print an empty one and let a reader assume nothing happened.
func AuditSinkInstalled() bool {
	return auditSink.Load() != nil
}

// auditEvent hands one security event to the installed sink.
//
// event is the stable name the counter uses; stage is the free-text location
// the caller passed, which is why the sink length-prefixes both rather than
// joining them with a delimiter a caller could spell.
func auditEvent(event, stage string) {
	sink := auditSink.Load()
	if sink == nil {
		return
	}
	(*sink).AuditEvent(event, stage)
}
