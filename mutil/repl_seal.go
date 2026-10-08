package mutil

import (
	"errors"
	"fmt"
	"mutant/compiler"
	"mutant/object"
	"mutant/security"
)

// ReplSealer encrypts one REPL session's bytecode, line after line, over a
// constant pool that the session carries forward.
//
// It exists because a REPL is the one caller that hands EncryptByteCode a pool
// it has already encrypted. EncryptByteCode is written for a one-shot artifact:
// a program is compiled once, its whole pool is plaintext, and every compiled
// function in it is XORed with a keystream seeded by the length of that
// program's own instruction stream -- the number the VM recovers as
// len(bc.Instructions) and uses to derive the one key it decrypts every
// instruction byte with.
//
// A REPL breaks both of those assumptions at once. Each line is its own
// program with its own instruction length, so each line's VM derives a
// different key; and the constant pool is shared, so a function compiled on an
// earlier line is still sitting in it, already encrypted. Calling
// EncryptByteCode per line therefore XORed such a function a second time under
// the new line's key, and the VM then decrypted it under that same new key and
// got the first line's ciphertext back as opcodes. Defining a helper and
// calling it on the next line -- the basic REPL workflow -- failed in both the
// terminal and the browser REPL, and the VM reported it as bytecode from a
// newer version of mutant.
//
// Re-keying is the fix, not skipping. Encrypting only the constants a line
// added would leave the earlier function under the earlier line's key while
// the VM still decrypts with this line's, which is the same wrong answer by a
// shorter route. Keeping the pool in plaintext between lines would work for
// the constants slice alone, but not for what else points into it: a closure
// stored in a global holds the *object.CompiledFunction itself, so handing the
// VM an encrypted copy leaves the global pointing at the copy made for the line
// that created it. Re-keying the function objects in place is what makes every
// one of those aliases agree, because there is only ever one of each.
//
// Scalar constants need none of this. EncryptObject wraps them in an
// *object.Encrypted that records the seed it used, DecryptObject prefers that
// recorded seed over the caller's, and EncryptObject passes an already-wrapped
// value straight through -- which is why an integer bound on line one has
// always read back correctly on line three while a function has not.
type ReplSealer struct {
	password string

	// seed is the instruction length the already-sealed prefix of the pool was
	// encrypted under, and 0 before the first line is sealed. It is the seed a
	// carried-over compiled function has to be decrypted with before it can be
	// re-encrypted under this line's.
	seed int64

	// sealed is how many leading constants Seal has already encrypted. The
	// compiler only ever appends, so the pool's first `sealed` entries are the
	// same objects this sealer saw last time and everything past them is
	// plaintext from this line's compile.
	sealed int
}

// ErrReplSealerPoolShrank reports a constant pool smaller than the one already
// sealed. The compiler only appends to the pool it is seeded with, so this means
// the caller handed over a different session's pool, and re-keying it would
// decrypt entries with a key they were never encrypted under.
var ErrReplSealerPoolShrank = errors.New("mutil: repl constant pool shrank between lines")

// ErrReplSealerNoPassword reports an empty password. Every line of a session
// must be sealed under the same password or nothing carried forward decrypts,
// and EncryptByteCode's empty-password fallback derives one from the line's own
// instructions -- a different password per line, which is exactly what a session
// cannot have.
var ErrReplSealerNoPassword = errors.New("mutil: repl sealer needs a non-empty password")

// NewReplSealer returns a sealer for one session, keyed by password.
func NewReplSealer(password string) *ReplSealer {
	return &ReplSealer{password: password}
}

// Seal encrypts byteCode in place for the VM that is about to run it, re-keying
// the compiled functions carried over from earlier lines, and returns it.
//
// It checks everything before it writes anything. Every re-keyed instruction
// stream is computed into a new buffer first; only when all of them have
// succeeded are they assigned. A failure therefore leaves the pool exactly as
// it was, still sealed under the previous line's seed and still consistent with
// what this sealer records about it, so the caller can report the line as
// refused and the session continues. A half-re-keyed pool would have been
// unrecoverable: the functions are shared with globals, and there is no record
// per function of which key it currently holds.
func (s *ReplSealer) Seal(byteCode *compiler.ByteCode) (*compiler.ByteCode, error) {
	if s == nil {
		return nil, errors.New("mutil: nil repl sealer")
	}
	if byteCode == nil {
		return nil, errors.New("mutil: nil bytecode")
	}
	if s.password == "" {
		return nil, ErrReplSealerNoPassword
	}
	if s.sealed > len(byteCode.Constants) {
		return nil, fmt.Errorf("%w: have %d sealed, pool holds %d",
			ErrReplSealerPoolShrank, s.sealed, len(byteCode.Constants))
	}

	next := int64(len(byteCode.Instructions))

	// Phase one: compute the re-keyed body of every carried-over compiled
	// function. Nothing is written yet.
	type rekey struct {
		fn           *object.CompiledFunction
		instructions []byte
	}
	var rekeyed []rekey
	if next != s.seed {
		for i := 0; i < s.sealed; i++ {
			fn, ok := byteCode.Constants[i].(*object.CompiledFunction)
			if !ok {
				continue
			}
			if len(fn.Instructions) == 0 {
				continue
			}
			plain, err := security.SecureXOR(fn.Instructions, s.seed, s.password)
			if err != nil {
				return nil, fmt.Errorf("mutil: re-keying repl constant %d: %w", i, err)
			}
			sealed, err := security.SecureXOR(plain, next, s.password)
			if err != nil {
				security.SecureZero(plain)
				return nil, fmt.Errorf("mutil: re-keying repl constant %d: %w", i, err)
			}
			security.SecureZero(plain)
			rekeyed = append(rekeyed, rekey{fn: fn, instructions: sealed})
		}
	}

	// Phase two: nothing above can fail any more, so write.
	for _, entry := range rekeyed {
		copy(entry.fn.Instructions, entry.instructions)
	}

	if xored, err := security.SecureXOR(byteCode.Instructions, next, s.password); err == nil {
		byteCode.Instructions = xored
	}

	for i := range byteCode.Constants {
		// A nil slot cannot be sealed, and is not worth an error. The pool a
		// REPL carries is only ever appended to by the compiler, so this is
		// unreachable as the tree stands -- but EncryptByteCode reaches
		// Constants[i].Type() on it and panics, and a sealer that runs once per
		// line for the length of a session is the wrong place to inherit that.
		if byteCode.Constants[i] == nil {
			continue
		}

		if i < s.sealed {
			// Already sealed. A compiled function has just been re-keyed above;
			// anything else is an *object.Encrypted that EncryptObject passes
			// through untouched, and this call is what still encrypts the rare
			// constant whose type EncryptObject had no arm for last line.
			if _, isFn := byteCode.Constants[i].(*object.CompiledFunction); isFn {
				continue
			}
			if encConst, err := EncryptObject(byteCode.Constants[i], int(next), s.password); err == nil {
				byteCode.Constants[i] = encConst
			}
			continue
		}

		if byteCode.Constants[i].Type() == object.COMPILED_FN_OBJ {
			fn := byteCode.Constants[i].(*object.CompiledFunction)
			if len(fn.Instructions) == 0 {
				continue
			}
			if xored, err := security.SecureXOR(fn.Instructions, next, s.password); err == nil {
				fn.Instructions = xored
			}
			continue
		}

		if encConst, err := EncryptObject(byteCode.Constants[i], int(next), s.password); err == nil {
			byteCode.Constants[i] = encConst
		}
	}

	s.seed = next
	s.sealed = len(byteCode.Constants)

	return byteCode, nil
}
