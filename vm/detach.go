package vm

// The worker boundary: what a pmap/peach worker or a spawned task may write.
//
// A worker gets its own VM, its own stack and a snapshot of globals, and the
// parallel builtins document the consequence: a callback reads what existed at
// the call, and its writes stay local (docs/MUTANT_LANGUAGE_REFERENCE.md, the
// pmap and spawn sections). Every value that crosses into a worker is already a
// copy, because every push seals and every pop opens, rebuilding arrays, hashes,
// structs and closures on the way -- with exactly one exception, and it is a
// deliberate one. A *object.Cell passes through mutil.EncryptObject and
// mutil.DecryptObject by pointer, because a cell is the one storage location a
// frame slot and every closure over it share, and handing back a copy would
// break the aliasing boxing exists to establish.
//
// So the cells are the whole boundary, and they are the whole of M26-VM-004.
// Replacing only the callback's own top-level cells -- which is what this file
// used to do, one level deep -- leaves every cell reached through something else
// shared and unsynchronised between the caller and every worker:
//
//   - a closure held in a captured variable, the `bump` in
//     `let n = 0; let bump = fn() { n = n + 1; }; pmap(xs, fn(x) { bump(); })`;
//   - a closure held in a global, which snapshotGlobals copies by pointer;
//   - a closure inside a captured array, hash, struct, enum or multi-value;
//   - a closure passed as a pmap element, or as spawn's argument.
//
// All five were measured writing the caller's cell from eight workers at once.
// The documented promise was true of one shape and false of five.
//
// The fix is to detach transitively: find every cell reachable from what crosses
// into the worker and give the worker its own, rebuilding only what holds one.
// Two properties make it a replacement rather than a deep copy:
//
//   - One memo per worker, so a cell reached twice becomes one copy. A counter
//     that is both a global and a capture is one counter inside the worker, as
//     it is in the program. Two copies would be a different bug: a program whose
//     own aliasing changed because it was run in parallel.
//   - The memo is filled before the walk descends, so a closure that captures
//     itself terminates -- `let rec = fn(k) { ... rec(k - 1) ... }` is an
//     ordinary thing to write, and its cell holds the closure that holds the
//     cell.
//
// What it does not copy is the value a cell holds, beyond the closures in it:
// the worker gets its own binding, not a deep copy of what the binding points
// at. That is the rule snapshotGlobals already follows, and for values it is
// invisible, because the seal/open round trip on every push and pop hands the
// worker a copy of any container it reads.
//
// The walk reaches exactly what mutil.DecryptObject reaches, which is what makes
// it total: a cell can only be reached along a path the seal walk also follows,
// and this one terminates wherever that one does. A rebuilt container is copied
// from the original value rather than listed field by field, so a field added to
// one of these types later cannot be silently dropped here -- the trap that
// makes a new field on a stored object vanish through EncryptObject.
//
// Two types are passed through for stated reasons rather than by default:
//
//   - *object.Iterator is advanced in place by OpIterNext, so a copy would reset
//     the loop; it is also unreachable here, because no expression produces one
//     and no name can be bound to one (see object.Iterator's own comment).
//   - *object.Error carries its Related values, but its stored form is a gob
//     blob -- mutil.EncryptObject encodes the whole struct -- so an error that
//     crosses into a worker is decoded fresh and shares nothing. Its arm is here
//     anyway, because an invariant with no exceptions is cheaper to state than
//     one with an exception to defend.

import "mutant/object"

// workerBoundary carries one worker's replacements. It is not safe for
// concurrent use and is not meant to be: each worker builds its own, which is
// the point of it.
type workerBoundary struct {
	cells    map[*object.Cell]*object.Cell
	closures map[*object.Closure]*object.Closure
}

func newWorkerBoundary() *workerBoundary {
	return &workerBoundary{
		cells:    make(map[*object.Cell]*object.Cell),
		closures: make(map[*object.Closure]*object.Closure),
	}
}

// closure detaches the callback or task a worker will run.
func (b *workerBoundary) closure(cl *object.Closure) *object.Closure {
	if cl == nil {
		return nil
	}
	if detached, ok := b.value(cl).(*object.Closure); ok {
		return detached
	}
	return cl
}

// slice detaches a globals snapshot or an argument list. It returns the original
// slice when there is nothing under it to detach, so the common case -- a
// program with no closure in a global -- allocates nothing.
func (b *workerBoundary) slice(objects []object.Object) []object.Object {
	detached, changed := b.elements(objects)
	if !changed {
		return objects
	}
	return detached
}

// detachAt replaces one slot of a globals snapshot in place. It is for the
// caller that already knows which slots can reach a cell; see
// (*VM).globalsHoldingCells.
func (b *workerBoundary) detachAt(globals []object.Object, index int) {
	if index < 0 || index >= len(globals) {
		return
	}
	globals[index] = b.value(globals[index])
}

// globalsHoldingCells reports which global slots can reach a cell at all.
//
// It exists to be hoisted. A worker has to detach the globals it starts from,
// and walking all 65,536 slots (global.GlobalSize) once per worker costs 34us
// on an empty program and 170-200us on one whose globals hold a 10,000-element
// array -- a third of the 782us a worker already spends being built, paid again
// for every worker of every call. Walking once per call and handing each worker
// the handful of slots that matter costs the same walk once, and for a program
// with no closure in any global -- almost every program -- it leaves the workers
// with nothing to do.
//
// The scan is the detach: it runs the same value() over each slot and asks only
// whether anything moved. Two walks that had to agree could drift; one walk
// cannot. The copies it makes on the way are discarded, which is why the
// boundary it uses is its own and not a worker's.
//
// The caller must be the goroutine that owns these globals, and must not be
// running while the result is used -- which is exactly where runParallel sits,
// blocked until its workers finish.
func (vm *VM) globalsHoldingCells() []int {
	var holding []int
	scan := newWorkerBoundary()
	for index, value := range vm.globals {
		if value == nil {
			continue
		}
		if scan.value(value) != value {
			holding = append(holding, index)
		}
	}
	return holding
}

// value returns obj with every cell reachable from it replaced by this worker's
// own, or obj itself when there is no cell under it.
func (b *workerBoundary) value(obj object.Object) object.Object {
	switch o := obj.(type) {
	// A cell is the thing being detached. The replacement is registered before
	// its contents are walked, so a cycle through it resolves to the
	// replacement instead of recursing forever.
	case *object.Cell:
		if replacement, seen := b.cells[o]; seen {
			return replacement
		}
		replacement := &object.Cell{}
		b.cells[o] = replacement
		replacement.Value = b.value(o.Value)
		return replacement

	// A closure is registered before its captures are walked for the same
	// reason, and it is always rebuilt rather than compared: a closure reached
	// from two places must be one closure inside the worker, and the memo is
	// what keeps that identity. Fn is shared deliberately -- the compiled
	// instructions are read-only, and every worker already runs them.
	case *object.Closure:
		if replacement, seen := b.closures[o]; seen {
			return replacement
		}
		// Registered before its captures are walked, so a cycle through it
		// resolves here instead of recursing forever. Fn is shared
		// deliberately: the compiled instructions are read-only, and every
		// worker already runs them.
		replacement := &object.Closure{Fn: o.Fn}
		b.closures[o] = replacement
		free, changed := b.elements(o.Free)
		if !changed {
			// Nothing under this closure is a cell, so there is nothing for a
			// worker to share and the original can stand. The registration is
			// corrected rather than left pointing at a copy nobody needs -- and
			// the copy cannot already have been handed out, because a cycle back
			// to this closure can only run through a cell, and no cell was
			// found.
			b.closures[o] = o
			return o
		}
		// A fresh Free slice, which is what elements returns once something
		// under it moved. Sharing the original's would matter: the slice is
		// never written after construction, but CleanupRuntimeSensitiveData
		// nils its entries at program end, and a worker's closure must not be
		// emptied by the caller's teardown.
		replacement.Free = free
		return replacement

	case *object.Array:
		elements, changed := b.elements(o.Elements)
		if !changed {
			return o
		}
		replacement := *o
		replacement.Elements = elements
		return &replacement

	case *object.MultiValue:
		values, changed := b.elements(o.Values)
		if !changed {
			return o
		}
		replacement := *o
		replacement.Values = values
		return &replacement

	case *object.Hash:
		var pairs map[object.HashKey]object.HashPair
		for key, pair := range o.Pairs {
			detachedKey, detachedValue := b.value(pair.Key), b.value(pair.Value)
			if detachedKey == pair.Key && detachedValue == pair.Value {
				continue
			}
			if pairs == nil {
				pairs = make(map[object.HashKey]object.HashPair, len(o.Pairs))
				for k, v := range o.Pairs {
					pairs[k] = v
				}
			}
			pairs[key] = object.HashPair{Key: detachedKey, Value: detachedValue}
		}
		if pairs == nil {
			return o
		}
		replacement := *o
		replacement.Pairs = pairs
		return &replacement

	case *object.Struct:
		fields, changed := b.fields(o.Fields)
		if !changed {
			return o
		}
		replacement := *o
		replacement.Fields = fields
		return &replacement

	case *object.EnumValue:
		if o.Value == nil {
			return o
		}
		detached := b.value(o.Value)
		if detached == o.Value {
			return o
		}
		replacement := *o
		replacement.Value = detached
		return &replacement

	case *object.Error:
		related, changed := b.fields(o.Related)
		if !changed {
			return o
		}
		replacement := *o
		replacement.Related = related
		return &replacement

	// Everything else is a leaf: a sealed value, a buffer, a scalar, a compiled
	// function, a builtin, a loop cursor. None of them can hold a cell.
	default:
		return obj
	}
}

// elements walks a slice and reports whether anything under it was replaced.
//
// The copy is made on the first replacement rather than up front, which is what
// keeps the common case free: a worker's globals slice is 65,536 entries long
// (global.GlobalSize) and almost all of them are nil, so allocating one per
// worker per call would cost more than the walk it was there to support.
func (b *workerBoundary) elements(values []object.Object) ([]object.Object, bool) {
	var detached []object.Object
	for i, value := range values {
		// An unused global slot is the overwhelmingly common entry here, and
		// skipping it before the type switch is what makes walking a 65,536-slot
		// slice cheaper than copying one.
		if value == nil {
			continue
		}
		replacement := b.value(value)
		if replacement == value {
			continue
		}
		if detached == nil {
			detached = make([]object.Object, len(values))
			copy(detached, values)
		}
		detached[i] = replacement
	}
	if detached == nil {
		return values, false
	}
	return detached, true
}

// fields is elements for the name-keyed containers: a struct's fields and an
// error's related values. It copies on the first replacement for the same
// reason.
func (b *workerBoundary) fields(values map[string]object.Object) (map[string]object.Object, bool) {
	var detached map[string]object.Object
	for name, value := range values {
		replacement := b.value(value)
		if replacement == value {
			continue
		}
		if detached == nil {
			detached = make(map[string]object.Object, len(values))
			for n, v := range values {
				detached[n] = v
			}
		}
		detached[name] = replacement
	}
	if detached == nil {
		return values, false
	}
	return detached, true
}
