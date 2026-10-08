package builtin

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
)

// shortReaderAt returns what it holds and then the given error, the way the
// libraries do when the image ends before a file does.
type shortReaderAt struct {
	data []byte
	err  error
}

func (s shortReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(s.data)) {
		return 0, s.err
	}
	n := copy(p, s.data[off:])
	if n < len(p) {
		return n, s.err
	}
	return n, nil
}

// The seam M26-FS1-003 added: stopping short inside the length is an error
// whether the reader said io.EOF or, against io.ReaderAt's contract, nothing
// at all, and stopping at the length is the ordinary end.
func TestAShortReadInsideTheLengthIsAnError(t *testing.T) {
	data := rampBytes(100)
	for _, tc := range []struct {
		name    string
		r       io.ReaderAt
		length  int64
		off     int64
		n       int
		wantErr bool
	}{
		{"stops short with io.EOF", shortReaderAt{data, io.EOF}, 200, 50, 100, true},
		{"stops short with no error", shortReaderAt{data, nil}, 200, 50, 100, true},
		{"starts past what the reader holds", shortReaderAt{data, io.EOF}, 200, 150, 10, true},
		{"reaches the length exactly", shortReaderAt{data, io.EOF}, 100, 50, 50, false},
		{"reads inside the length", shortReaderAt{data, io.EOF}, 200, 10, 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, tc.n)
			_, err := fsExactReader{r: tc.r, length: tc.length}.ReadAt(p, tc.off)
			isShort := err != nil && err != io.EOF
			if isShort != tc.wantErr {
				t.Fatalf("ReadAt(%d bytes at %d) under a length of %d: err = %v, want an error: %v",
					tc.n, tc.off, tc.length, err, tc.wantErr)
			}
		})
	}

	// A library's own error passes through untouched.
	boom := errors.New("the device stopped answering")
	if _, err := (fsExactReader{r: shortReaderAt{data, boom}, length: 200}).ReadAt(make([]byte, 10), 95); err != boom {
		t.Fatalf("a library's error was replaced: %v", err)
	}
}

// M26-FS2-005's arithmetic on its own, at the edges: a run straddling the end,
// one past it, one before it, and offsets near the top of int64 where a sum
// would wrap.
func TestOnlyTheImageDecidesWhatOfARunIsLocated(t *testing.T) {
	const extent = 4096
	for _, tc := range []struct {
		name          string
		run           fsDeletedRun
		skip, n, want int64
	}{
		{"wholly inside", fsDeletedRun{Offset: 0, Length: 512}, 0, 512, 512},
		{"straddling the end", fsDeletedRun{Offset: 3840, Length: 512}, 0, 512, 256},
		{"straddling, read from partway in", fsDeletedRun{Offset: 3840, Length: 512}, 100, 412, 156},
		{"starting at the end", fsDeletedRun{Offset: extent, Length: 512}, 0, 512, 0},
		{"partway in, past the end", fsDeletedRun{Offset: 3840, Length: 512}, 300, 212, 0},
		{"an offset near the top of int64", fsDeletedRun{Offset: math.MaxInt64 - 10, Length: 512}, 0, 512, 0},
		{"a skip near the top of int64", fsDeletedRun{Offset: 1024, Length: math.MaxInt64}, math.MaxInt64 - 5, 5, 0},
	} {
		if got := fsRunInImage(tc.run, tc.skip, tc.n, extent); got != tc.want {
			t.Errorf("%s: %d of %d bytes in the image, want %d", tc.name, got, tc.n, tc.want)
		}
	}
}

// The three counts still sum to the output, with the past-the-image part of
// unlocated_bytes carried apart so its caveat can say what it is.
func TestBytesPastTheImageAreAPartOfTheUnlocatedCount(t *testing.T) {
	image := bytes.NewReader(bytes.Repeat([]byte{0xAA}, 4096))
	recovery, err := recoveryFromRuns(image, fsDeletedEntry{Size: 1536}, []fsDeletedRun{
		{FileOffset: 0, Offset: 3840, Length: 512},
		{FileOffset: 512, Offset: -1, Length: 512},
		{FileOffset: 1024, Offset: 8192, Length: 512},
	})
	if err != nil {
		t.Fatalf("recoveryFromRuns: %v", err)
	}
	if recovery.LocatedBytes != 256 || recovery.PastImageBytes != 768 || recovery.UnlocatedBytes != 1280 {
		t.Fatalf("located %d, past the image %d, unlocated %d; want 256, 768, 1280",
			recovery.LocatedBytes, recovery.PastImageBytes, recovery.UnlocatedBytes)
	}
	if recovery.ImageEnd != 4096 {
		t.Fatalf("the image's end is recorded as %d, want 4096", recovery.ImageEnd)
	}
	if sum := recovery.LocatedBytes + recovery.SparseBytes + recovery.UnlocatedBytes; sum != recovery.Length {
		t.Fatalf("the counts sum to %d and the output is %d bytes", sum, recovery.Length)
	}
}

// A run reader asked for bytes the image should hold and does not is an error,
// not zeros: with the runs clipped at the image's end beforehand, a short read
// means the image changed or lied about its length.
func TestARunReaderTurnsAShortImageReadIntoAnError(t *testing.T) {
	reader := &fsRunReader{
		image:  shortReaderAt{rampBytes(100), io.EOF},
		size:   64,
		extent: 4096,
		runs:   []fsDeletedRun{{FileOffset: 0, Offset: 80, Length: 64}},
	}
	if _, err := reader.ReadAt(make([]byte, 64), 0); err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a run the image could not produce read as %v, want io.ErrUnexpectedEOF", err)
	}
}

// Only the two readers openVolumeRegion returns, and the bytes.Reader tests
// build sessions on, have a length this can learn; anything else is refused
// rather than treated as an image of length zero.
func TestTheImageExtentComesFromTheReaderItself(t *testing.T) {
	if n, err := fsImageExtent(bytes.NewReader(make([]byte, 777))); err != nil || n != 777 {
		t.Fatalf("a bytes.Reader of 777 bytes: %d, %v", n, err)
	}
	if n, err := fsImageExtent(io.NewSectionReader(bytes.NewReader(make([]byte, 4096)), 0, 1000)); err != nil || n != 1000 {
		t.Fatalf("a section of 1000 bytes: %d, %v", n, err)
	}
	if _, err := fsImageExtent(shortReaderAt{}); err == nil {
		t.Fatalf("a reader with no length was given one")
	}
}
