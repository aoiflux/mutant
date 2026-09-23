package object

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"

	"mutant/security"
)

// Bytes is a byte buffer -- a disk sector, a PE section, a memory page, a
// socket read.
//
// It exists because the alternative was a String. A Go string holds arbitrary
// bytes perfectly well, so nothing was ever corrupted at rest; the damage was
// that no builtin could tell binary from text. str_reverse rune-reverses, so
// every byte that is not valid UTF-8 came back as U+FFFD. str_substr and
// str_char_at index by rune, so their offsets disagreed with bytes_get's on the
// same buffer. The regex family reads invalid bytes as U+FFFD. None of those
// failed -- they returned a plausible wrong answer, which in a language whose
// job is disk images is the worst way to be wrong.
//
// The type is what lets a builtin declare which one it wants, and the analyzer
// warn when the two are mixed.
type Bytes struct {
	Value []byte

	// Classified is set on plaintext read out of a classified record, and nil
	// on every other buffer. It is checked where a value leaves the process --
	// printing, writing a file, sending on a socket, writing a report, a note,
	// a cache entry or a ledger node -- and nowhere else.
	//
	// It is deliberately NOT consulted by Inspect. Inspect is the identity
	// function for equality, dedup, containment and hash ordering (see below),
	// and a classification-aware Inspect would make two different buffers
	// compare equal in all of those at once.
	//
	// It survives being held: a variable is stored encrypted at rest, and
	// Encrypted.Classified carries the mark beside the ciphertext so that
	// reading the variable back returns a buffer that still has it.
	//
	// Its limits, stated as loudly as its existence: it travels through
	// bytes_slice and concatenation (`a + b` of two buffers) and nothing else,
	// so any conversion -- to a string, to hex, to JSON, a loop that rebuilds
	// the buffer byte by byte -- produces a value without it. It catches
	// accidents, not adversaries.
	Classified *Classification
}

// Classification says where classified plaintext came from: the record it was
// read out of, and the classes of the segments the read touched. It names the
// classes by tag and, where the reading case could, by label; it never holds
// any of the plaintext.
type Classification struct {
	RecordUID string
	Tags      []string
	Labels    []string
}

// JoinClassification is the mark of a buffer built from two others: nil when
// neither was marked, the one mark when only one was, and when both were, one
// mark naming every record and every class either came from. Classified
// plaintext joined to anything is classified plaintext, whichever side it was
// on, and a later release must record all of what it let go.
//
// A class is identified by its tag, so a class both sides carry is named
// once. Neither mark is modified: a Classification is shared, never mutated.
func JoinClassification(a, b *Classification) *Classification {
	switch {
	case a == nil:
		return b
	case b == nil || a == b:
		return a
	}
	joined := &Classification{RecordUID: a.RecordUID}
	if b.RecordUID != a.RecordUID {
		joined.RecordUID = a.RecordUID + " and " + b.RecordUID
	}
	seen := map[string]bool{}
	for _, c := range []*Classification{a, b} {
		for i, tag := range c.Tags {
			if seen[tag] {
				continue
			}
			seen[tag] = true
			label := ""
			if i < len(c.Labels) {
				label = c.Labels[i]
			}
			joined.Tags = append(joined.Tags, tag)
			joined.Labels = append(joined.Labels, label)
		}
	}
	return joined
}

func (b *Bytes) Type() ObjectType { return BYTES_OBJ }

// Inspect renders the buffer as contiguous lowercase hex.
//
// It is deliberately lossless and deliberately untruncated, because Inspect is
// not only a display function here: it is the de-facto identity function for
// equality in both engines, for unique's dedup key, for contains and index_of,
// and for hash-key ordering. A preview -- "bytes(4096) 4d5a..." -- would make
// two distinct buffers sharing a prefix compare equal, and would do it silently
// in six subsystems at once.
//
// The cost is that rendering a large buffer materialises twice its size. The one
// caller that only ever wanted a preview, the traceback's argument renderer,
// special-cases this type rather than paying for it.
func (b *Bytes) Inspect() string { return hex.EncodeToString(b.Value) }

// HashKey lets a bytes value be a hash key. The key carries the type, so bytes
// and strings occupy disjoint keyspaces: {"4d5a": 1}[some_bytes] does not hit.
func (b *Bytes) HashKey() HashKey {
	h := fnv.New64a()
	h.Write(b.Value)
	return HashKey{Type: b.Type(), Value: h.Sum64()}
}

// Preview renders at most limit bytes of the buffer, with the length in front,
// for the places that want to show what a value is without printing all of it.
// Unlike Inspect it never materialises the whole buffer as hex.
func (b *Bytes) Preview(limit int) string {
	if limit < 0 {
		limit = 0
	}

	shown := b.Value
	elided := false
	if len(shown) > limit {
		shown, elided = shown[:limit], true
	}

	rendered := fmt.Sprintf("bytes(%d)", len(b.Value))
	if len(shown) > 0 {
		rendered += " " + hex.EncodeToString(shown)
	}
	if elided {
		rendered += "..."
	}
	return rendered
}

// Zero wipes the buffer in place.
//
// This is the difference the type makes to key material. The String arm of the
// same code path zeroes []byte(v.Value) -- a copy Go makes at the conversion --
// and has therefore always been a no-op. A []byte can actually be cleared.
func (b *Bytes) Zero() {
	if b == nil {
		return
	}
	security.SecureZero(b.Value)
	b.Value = nil
}
