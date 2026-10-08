package object

import "unicode/utf8"

// Indexing, in one place, because there are two engines and six containers and
// the language is supposed to mean one thing.
//
// Two rules live here. Both were already decided elsewhere in this tree; what
// was missing was a single statement of them that every indexing site reads.
//
// The first is that a negative index counts from the end, -1 being the last
// element. Seven places indexed an ordered container and exactly one of them had
// the whole rule. The VM counted from the end for arrays and strings but had no
// lower bound, so an index past the start reached element -1 of a Go slice. The
// evaluator answered null to every negative index on an array and could not
// index a string at all. Both engines answered null to every negative index on a
// multi-value. Buffers were the exception -- bounded, in both engines -- so this
// is execBytesIndex's rule extended to the rest rather than a new one, which is
// also why b[-1] is the one answer below that nothing changes. The practical
// effect was that `xs[-1]` meant the last element when a program was compiled
// and nothing when the same program was interpreted. IndexOf is the rule; the
// engines differ now only in what they do with the answer.
//
// The second is that a string is a sequence of runes and a buffer is a sequence
// of bytes. That one is not new either: NewIterator says it outright ("iterating
// text by byte would hand back half a rune"), and str_char_at, str_substr and
// str_reverse all work in runes. s[i] was the single place that worked in bytes,
// and because Go converts a byte to the rune of the same number, it did not
// return a byte either -- it returned the character at that code point, which
// for any byte above 0x7f is a character the string does not contain. RuneAt is
// what the other three already do, without materialising []rune(s) to do it.

// IndexOf resolves an index against a container holding n elements, counting a
// negative index from the end: -1 is the last element, -n the first. ok is false
// when i names no element, which every caller here turns into null.
//
// It is deliberately total: there is no index, however large or negative, for
// which it panics or reports an element that is not there. That is the whole
// point -- a negative index one past the start used to reach element -1 of a Go
// slice, and the panic was recovered as a VM integrity fault, which named the
// interpreter rather than the program.
//
// The arithmetic cannot overflow. n is the length of something already in
// memory, so int64(n) is small and positive; a zero-length container returns
// early, and for any other n the sum int64(n)+i is nearer zero than i was. The
// older form of this check, max+i+1 < 0, was right only because int64 wraps the
// way it does -- it read as arithmetic on a value that had already overflowed.
func IndexOf(i int64, n int) (int, bool) {
	if n <= 0 {
		return 0, false
	}
	if i >= 0 {
		if i >= int64(n) {
			return 0, false
		}
		return int(i), true
	}
	at := int64(n) + i
	if at < 0 {
		return 0, false
	}
	return int(at), true
}

// RuneAt returns the i-th rune of s as a string of that one rune, counting a
// negative i from the end as IndexOf does. ok is false when s holds no such
// rune.
//
// It walks rather than converting to []rune, which costs four bytes per rune of
// the whole string to read one of them. Walking is O(|i|) in time and nothing in
// space, and for the overwhelmingly common s[0] and s[-1] it decodes exactly one
// rune. The two directions are separate loops because utf8 can be walked from
// either end but not indexed from either.
//
// There is no arithmetic on i here at all, so the index that breaks arithmetic
// breaks nothing: the most negative int64 simply walks off the front of the
// string and reports that it found no rune.
//
// A byte that begins no valid sequence decodes to U+FFFD, one byte at a time,
// which is what the for-in iterator and str_char_at already report for it. That
// is the answer for text that is not text; a program that means the bytes should
// be holding a buffer, which is what the Bytes type is for.
func RuneAt(s string, i int64) (string, bool) {
	if i >= 0 {
		for pos := 0; pos < len(s); {
			r, size := utf8.DecodeRuneInString(s[pos:])
			if i == 0 {
				return string(r), true
			}
			i--
			pos += size
		}
		return "", false
	}

	for end := len(s); end > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:end])
		if i == -1 {
			return string(r), true
		}
		i++
		end -= size
	}
	return "", false
}
