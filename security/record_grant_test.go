package security

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// grantFixture is a sealed record held in memory with everything a grant test
// needs to reach: the header the descriptors come from, the ciphertext per
// segment, the plaintext it should open to, and the record key -- kept, unlike
// buildRecord, because a rotation test has to rewrap it.
type grantFixture struct {
	header    *RecordHeader
	segments  []RecordSegment
	plaintext []byte
	cts       [][]byte
	recordKey []byte
	sealSalt  []byte
	cuid      CaseUID
	ruid      RecordUID
	tags      map[string]ClassTag
	opener    *RecordKeys
}

func (f *grantFixture) aad(t *testing.T, index uint64) SegmentAAD {
	t.Helper()
	aad, err := f.header.SegmentAAD(f.segments[index], uint64(len(f.segments)))
	if err != nil {
		t.Fatalf("segment %d aad: %v", index, err)
	}
	return aad
}

func (f *grantFixture) want(index uint64) []byte {
	s := f.segments[index]
	return f.plaintext[s.Offset : s.Offset+uint64(s.Length)]
}

// descriptorsOf returns the descriptors of every segment carrying one of the
// named classes: the set a view granting those classes would issue.
func (f *grantFixture) descriptorsOf(t *testing.T, classes ...string) []SegmentAAD {
	t.Helper()
	wanted := map[ClassTag]bool{}
	for _, c := range classes {
		wanted[f.tags[c]] = true
	}
	var out []SegmentAAD
	for _, s := range f.segments {
		if wanted[s.Class] {
			out = append(out, f.aad(t, s.Index))
		}
	}
	return out
}

// newGrantFixture seals 400 bytes in five spans over three classes at a
// segment size of 48, so that spans split, a class recurs, and adjacent spans
// of different classes sit side by side.
func newGrantFixture(t *testing.T) *grantFixture {
	t.Helper()
	tagKey := bytes.Repeat([]byte{0x5a}, 32)
	tags := map[string]ClassTag{}
	for _, label := range []string{"open", "pii", "restricted"} {
		tag, err := TagForClass(tagKey, label)
		if err != nil {
			t.Fatal(err)
		}
		tags[label] = tag
	}
	plaintext := make([]byte, 400)
	for i := range plaintext {
		plaintext[i] = byte('A' + i%26)
	}
	span := func(offset, length uint64, class string) RecordSpan {
		tag := tags[class]
		return RecordSpan{Offset: offset, Length: length, Class: hex.EncodeToString(tag[:])}
	}
	spans := []RecordSpan{
		span(0, 100, "open"),
		span(100, 60, "pii"),
		span(160, 90, "restricted"),
		span(250, 50, "pii"),
		span(300, 100, "open"),
	}
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	ruid, err := RandomRecordUID()
	if err != nil {
		t.Fatal(err)
	}
	header := &RecordHeader{
		RecordUID:              hex.EncodeToString(ruid[:]),
		CaseUID:                hex.EncodeToString(cuid[:]),
		SealedUnderGeneration:  1,
		WrappedUnderGeneration: 1,
		PlaintextLength:        uint64(len(plaintext)),
		SegmentSize:            48,
		Spans:                  spans,
	}
	segments, err := header.Segments()
	if err != nil {
		t.Fatal(err)
	}
	sealer, recordKey, sealSalt, err := NewRecordKeysForSeal(cuid, ruid, 1, uint64(len(segments)))
	if err != nil {
		t.Fatal(err)
	}
	f := &grantFixture{header: header, segments: segments, plaintext: plaintext, recordKey: recordKey,
		sealSalt: sealSalt, cuid: cuid, ruid: ruid, tags: tags}
	for _, s := range segments {
		ct, _, err := sealer.SealSegment(f.aad(t, s.Index), f.want(s.Index))
		if err != nil {
			t.Fatalf("sealing %d: %v", s.Index, err)
		}
		f.cts = append(f.cts, ct)
	}
	sealer.Zero()
	f.opener, err = OpenRecordKeys(cuid, ruid, 1, uint64(len(segments)), recordKey, sealSalt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.opener.Zero)
	return f
}

// Each recipient decrypts exactly their granted segments, and every denied
// segment fails its Poly1305 tag -- not merely because the API declines, but
// because no material the grant holds opens it.
func TestAGrantOpensExactlyWhatItGrants(t *testing.T) {
	f := newGrantFixture(t)
	postures := map[string][]string{
		"counsel":   {"open", "pii"},
		"public":    {"open"},
		"regulator": {"restricted"},
	}
	for name, classes := range postures {
		t.Run(name, func(t *testing.T) {
			grant, err := f.opener.IssueGrant(f.descriptorsOf(t, classes...))
			if err != nil {
				t.Fatal(err)
			}
			defer grant.Zero()

			granted := map[ClassTag]bool{}
			for _, c := range classes {
				granted[f.tags[c]] = true
			}
			var opened, refused int
			for _, s := range f.segments {
				aad := f.aad(t, s.Index)
				pt, err := grant.OpenSegment(aad, f.cts[s.Index])
				if granted[s.Class] {
					if err != nil {
						t.Fatalf("granted segment %d did not open: %v", s.Index, err)
					}
					if !bytes.Equal(pt, f.want(s.Index)) {
						t.Fatalf("granted segment %d opened to the wrong bytes", s.Index)
					}
					opened++
					continue
				}
				if !errors.Is(err, ErrSegmentNotGranted) {
					t.Fatalf("withheld segment %d: got %v, want ErrSegmentNotGranted", s.Index, err)
				}
				// The cryptographic half. Every slot of material this grant
				// holds is tried against the withheld segment directly, below
				// the API, and every one must fail the tag.
				encoded := aad.encode()
				for slot := 0; slot < grant.Count(); slot++ {
					m := grant.material[slot*GrantMaterialSize : (slot+1)*GrantMaterialSize]
					var nonce XNonce
					copy(nonce[:], m[KeySize:])
					if _, err := openWith(m[:KeySize], nonce, f.cts[s.Index], encoded[:], ErrSegmentAuth); err == nil {
						t.Fatalf("material for granted segment %d opened WITHHELD segment %d", grant.indices[slot], s.Index)
					}
				}
				refused++
			}
			if opened != grant.Count() {
				t.Fatalf("opened %d segments with a grant of %d", opened, grant.Count())
			}
			t.Logf("%s grants %v: %d of %d segments open, %d withheld each fail the tag under all %d slots "+
				"of granted material (%d bytes)", name, classes, opened, len(f.segments), refused,
				grant.Count(), len(grant.material))
		})
	}
}

// A granted segment's ciphertext moved to another offset, another index or
// another record fails closed.
func TestAGrantRefusesAMovedSegment(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(f.descriptorsOf(t, "open", "pii"))
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	indices := grant.Indices()
	a, b := indices[0], indices[1]

	// Another index: segment a's bytes presented as segment b, which is also
	// granted, so the only thing that can stop it is the tag.
	if _, err := grant.OpenSegment(f.aad(t, b), f.cts[a]); !errors.Is(err, ErrSegmentAuth) {
		t.Errorf("segment %d's ciphertext opened as segment %d: %v", a, b, err)
	}

	// Another offset: the header's descriptor for a, with the offset moved.
	moved := f.aad(t, a)
	moved.offset += 7
	if _, err := grant.OpenSegment(moved, f.cts[a]); !errors.Is(err, ErrSegmentAuth) {
		t.Errorf("segment %d opened at a moved offset: %v", a, err)
	}

	// Another class: the header says the segment is restricted.
	reclassed := f.aad(t, a)
	reclassed.classTag = f.tags["restricted"]
	if _, err := grant.OpenSegment(reclassed, f.cts[a]); !errors.Is(err, ErrSegmentAuth) {
		t.Errorf("segment %d opened under another class: %v", a, err)
	}

	// Another record: the same index in a record with a different uid.
	grafted := f.aad(t, a)
	grafted.recordUID[0] ^= 1
	if _, err := grant.OpenSegment(grafted, f.cts[a]); !errors.Is(err, ErrGrantRecordMismatch) {
		t.Errorf("a descriptor for another record reached the cipher: %v", err)
	}

	// A flipped byte.
	flipped := append([]byte(nil), f.cts[a]...)
	flipped[3] ^= 0x80
	if _, err := grant.OpenSegment(f.aad(t, a), flipped); !errors.Is(err, ErrSegmentAuth) {
		t.Errorf("a flipped ciphertext byte opened: %v", err)
	}
}

func TestIssueGrantRefusesWhatIsNotThisRecords(t *testing.T) {
	f := newGrantFixture(t)
	total := uint64(len(f.segments))

	other := f.aad(t, 2)
	other.recordUID[5] ^= 0xff
	if _, err := f.opener.IssueGrant([]SegmentAAD{other}); !errors.Is(err, ErrGrantRecordMismatch) {
		t.Errorf("a descriptor from another record was granted: %v", err)
	}
	wrongCount := f.aad(t, 2)
	wrongCount.total = total + 1
	if _, err := f.opener.IssueGrant([]SegmentAAD{wrongCount}); !errors.Is(err, ErrGrantRecordMismatch) {
		t.Errorf("a descriptor naming another segment count was granted: %v", err)
	}
	if _, err := f.opener.IssueGrant([]SegmentAAD{f.aad(t, 1), f.aad(t, 3), f.aad(t, 1)}); err == nil ||
		!strings.Contains(err.Error(), "named twice") {
		t.Errorf("a repeated index was granted: %v", err)
	}
	outOfRange := f.aad(t, 0)
	outOfRange.index = total
	if _, err := f.opener.IssueGrant([]SegmentAAD{outOfRange}); err == nil {
		t.Error("an index past the record was granted")
	}

	// Out of order in, ascending out: the caller's order is not the grant's.
	grant, err := f.opener.IssueGrant([]SegmentAAD{f.aad(t, 5), f.aad(t, 0), f.aad(t, 3)})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(grant.Indices()); got != "[0 3 5]" {
		t.Errorf("indices = %s, want [0 3 5]", got)
	}
	grant.Zero()

	// A handle still sealing grants nothing.
	sealer, _, _, err := NewRecordKeysForSeal(f.cuid, f.ruid, 1, total)
	if err != nil {
		t.Fatal(err)
	}
	defer sealer.Zero()
	if _, err := sealer.IssueGrant(nil); err == nil || !strings.Contains(err.Error(), "sealed 0 of") {
		t.Errorf("a record with nothing sealed issued a grant: %v", err)
	}

	zeroed, err := OpenRecordKeys(f.cuid, f.ruid, 1, total, f.recordKey, f.sealSalt)
	if err != nil {
		t.Fatal(err)
	}
	zeroed.Zero()
	if _, err := zeroed.IssueGrant(nil); err == nil {
		t.Error("a zeroed schedule issued a grant")
	}
}

// A grant of nothing is a posture, and it is spelled like one.
func TestAGrantOfNothing(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	if grant.Count() != 0 || len(grant.Runs()) != 0 || grant.Runs() == nil {
		t.Fatalf("count=%d runs=%v", grant.Count(), grant.Runs())
	}
	if _, err := grant.OpenSegment(f.aad(t, 0), f.cts[0]); !errors.Is(err, ErrSegmentNotGranted) {
		t.Fatalf("a grant of nothing opened something: %v", err)
	}
	key := bytes.Repeat([]byte{3}, KeySize)
	sealed := grantFileFor(t, grant, key)
	if sealed.Granted != 0 || len(sealed.Runs) != 0 {
		t.Fatalf("granted=%d runs=%v", sealed.Granted, sealed.Runs)
	}
	raw, err := MarshalGrantFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"runs": []`)) {
		t.Fatalf("an empty grant must carry an empty run list, not a missing one:\n%s", raw)
	}
	parsed, err := ParseGrantFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	back, err := openGrantWithKey(parsed, key)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Zero()
	if back.Count() != 0 {
		t.Fatalf("a grant of nothing came back granting %d", back.Count())
	}
}

// Rotation rewraps the record key and changes nothing a grant depends on.
func TestAGrantSurvivesRotation(t *testing.T) {
	f := newGrantFixture(t)
	before, err := f.opener.IssueGrant(f.descriptorsOf(t, "pii"))
	if err != nil {
		t.Fatal(err)
	}
	defer before.Zero()

	oldCase, _ := randomBytes(KeySize)
	newCase, _ := randomBytes(KeySize)
	nonce, wrapped, err := WrapRecordKey(oldCase, f.ruid, f.recordKey)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := UnwrapRecordKey(oldCase, f.ruid, nonce, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	nonce2, wrapped2, err := WrapRecordKey(newCase, f.ruid, recovered)
	if err != nil {
		t.Fatal(err)
	}
	after, err := UnwrapRecordKey(newCase, f.ruid, nonce2, wrapped2)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := OpenRecordKeys(f.cuid, f.ruid, 1, uint64(len(f.segments)), after, f.sealSalt)
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Zero()
	reissued, err := rotated.IssueGrant(f.descriptorsOf(t, "pii"))
	if err != nil {
		t.Fatal(err)
	}
	defer reissued.Zero()

	if !bytes.Equal(before.material, reissued.material) || before.descriptorsRoot != reissued.descriptorsRoot {
		t.Fatal("a case-key rotation changed the material a grant carries")
	}
	for _, index := range before.Indices() {
		if _, err := before.OpenSegment(f.aad(t, index), f.cts[index]); err != nil {
			t.Fatalf("the pre-rotation grant stopped opening segment %d: %v", index, err)
		}
	}
	t.Logf("rotation: %d granted segments, %d bytes of material, byte-identical before and after; "+
		"disclosures_invalidated = 0", before.Count(), len(before.material))
}

func TestMatchesRecordNamesADisagreementAsOne(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(f.descriptorsOf(t, "pii"))
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	describe := func(h *RecordHeader) func(uint64) (SegmentAAD, error) {
		segments, err := h.Segments()
		if err != nil {
			t.Fatal(err)
		}
		return func(i uint64) (SegmentAAD, error) {
			if i >= uint64(len(segments)) {
				return SegmentAAD{}, errors.New("no such segment")
			}
			return h.SegmentAAD(segments[i], uint64(len(segments)))
		}
	}
	if err := grant.MatchesRecord(describe(f.header)); err != nil {
		t.Fatalf("the header the grant was issued against does not match it: %v", err)
	}

	// Two spans' boundary moved by one byte: same segment count, same classes,
	// a different description of the granted segments.
	edited := *f.header
	edited.Spans = append([]RecordSpan(nil), f.header.Spans...)
	edited.Spans[1].Length--
	edited.Spans[2].Offset--
	edited.Spans[2].Length++
	err = grant.MatchesRecord(describe(&edited))
	if err == nil || !strings.Contains(err.Error(), "describes the granted segments differently") {
		t.Fatalf("an edited header was accepted: %v", err)
	}

	other := *f.header
	other.RecordUID = strings.Repeat("ab", RecordUIDSize)
	if err := grant.MatchesRecord(describe(&other)); !errors.Is(err, ErrGrantRecordMismatch) {
		t.Fatalf("another record's header was accepted: %v", err)
	}
}

func grantFileFor(t *testing.T, g *RecordGrant, key []byte) *GrantFile {
	t.Helper()
	uid, err := RandomDisclosureUID()
	if err != nil {
		t.Fatal(err)
	}
	profile := grantFileProfiles[GrantFileVersion]
	file := &GrantFile{
		Format:                GrantFileFormat,
		Version:               GrantFileVersion,
		DisclosureUID:         hex.EncodeToString(uid[:]),
		CaseUID:               hex.EncodeToString(g.caseUID[:]),
		RecordUID:             hex.EncodeToString(g.recordUID[:]),
		SealedUnderGeneration: g.generation,
		Segments:              g.total,
		Granted:               uint64(g.Count()),
		Runs:                  g.Runs(),
		DescriptorsRoot:       hex.EncodeToString(g.descriptorsRoot[:]),
		KDF: CaseKeyKDF{Algorithm: profile.algorithm, Salt: strings.Repeat("11", CaseKeySaltSize),
			Time: profile.time, MemoryKiB: profile.memoryKiB, Threads: profile.threads, KeyLen: profile.keyLen},
	}
	if err := sealGrantWithKey(file, g, key); err != nil {
		t.Fatal(err)
	}
	return file
}

// Every public field of a grant file is bound: an edit to any of them is
// refused at the parse or fails the one AEAD, and never yields a grant.
func TestEveryGrantFileFieldIsBound(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(f.descriptorsOf(t, "open", "restricted"))
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	key := bytes.Repeat([]byte{7}, KeySize)
	sealed := grantFileFor(t, grant, key)
	raw, err := MarshalGrantFile(sealed)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseGrantFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	back, err := openGrantWithKey(parsed, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.material, grant.material) || fmt.Sprint(back.indices) != fmt.Sprint(grant.indices) ||
		back.descriptorsRoot != grant.descriptorsRoot || back.caseUID != grant.caseUID ||
		back.recordUID != grant.recordUID || back.total != grant.total || back.generation != grant.generation {
		t.Fatal("the grant did not survive the round trip intact")
	}
	for _, index := range back.Indices() {
		if _, err := back.OpenSegment(f.aad(t, index), f.cts[index]); err != nil {
			t.Fatalf("the recovered grant does not open segment %d: %v", index, err)
		}
	}
	back.Zero()
	t.Logf("round trip: %d granted in %d runs %v, %d bytes of file", grant.Count(), len(sealed.Runs), sealed.Runs, len(raw))

	if _, err := openGrantWithKey(parsed, bytes.Repeat([]byte{8}, KeySize)); !errors.Is(err, ErrGrantAuth) {
		t.Errorf("the wrong key opened the grant: %v", err)
	}

	flipHex := func(s string) string {
		b := []byte(s)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		return string(b)
	}
	// Each edit is one a parse accepts, so that the refusal can only come from
	// the binding.
	edits := map[string]func(g *GrantFile){
		"disclosure_uid":          func(g *GrantFile) { g.DisclosureUID = flipHex(g.DisclosureUID) },
		"case_uid":                func(g *GrantFile) { g.CaseUID = flipHex(g.CaseUID) },
		"record_uid":              func(g *GrantFile) { g.RecordUID = flipHex(g.RecordUID) },
		"sealed_under_generation": func(g *GrantFile) { g.SealedUnderGeneration = 2 },
		"segments":                func(g *GrantFile) { g.Segments++ },
		"descriptors_root":        func(g *GrantFile) { g.DescriptorsRoot = flipHex(g.DescriptorsRoot) },
		"kdf.salt":                func(g *GrantFile) { g.KDF.Salt = flipHex(g.KDF.Salt) },
		// The same count, a different set: the middle run shifted along by
		// one. The parse cannot tell; only the binding can.
		"runs":  func(g *GrantFile) { g.Runs[1].First++; g.Runs[1].Last++ },
		"blob":  func(g *GrantFile) { g.Blob = flipHex(g.Blob) },
		"nonce": func(g *GrantFile) { g.Nonce = flipHex(g.Nonce) },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			var copyOf GrantFile
			if err := json.Unmarshal(raw, &copyOf); err != nil {
				t.Fatal(err)
			}
			edit(&copyOf)
			text, err := MarshalGrantFile(&copyOf)
			if err != nil {
				t.Fatal(err)
			}
			reparsed, err := ParseGrantFile(text)
			if err != nil {
				t.Fatalf("the edit was refused at the parse, which proves nothing about the binding: %v", err)
			}
			if g, err := openGrantWithKey(reparsed, key); !errors.Is(err, ErrGrantAuth) {
				if g != nil {
					g.Zero()
				}
				t.Fatalf("an edited %s opened: %v", name, err)
			}
		})
	}
}

func TestParseGrantFileRefusesWhatItCannotRead(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(f.descriptorsOf(t, "pii"))
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	sealed := grantFileFor(t, grant, bytes.Repeat([]byte{9}, KeySize))
	if len(sealed.Runs) != 2 {
		t.Fatalf("the fixture was meant to grant two runs, got %v", sealed.Runs)
	}

	cases := map[string]struct {
		edit func(g *GrantFile)
		want string
	}{
		"format":          {func(g *GrantFile) { g.Format = "mutant-case-key" }, "its format is"},
		"version":         {func(g *GrantFile) { g.Version = 2 }, "version 2"},
		"hostile cost":    {func(g *GrantFile) { g.KDF.MemoryKiB = 4 << 20 }, "fixed by its version"},
		"generation zero": {func(g *GrantFile) { g.SealedUnderGeneration = 0 }, "numbered from 1"},
		"no segments":     {func(g *GrantFile) { g.Segments = 0 }, "a record has 1 to"},
		"too many":        {func(g *GrantFile) { g.Segments = MaxRecordSegments + 1 }, "a record has 1 to"},
		"granted > total": {func(g *GrantFile) { g.Granted = g.Segments + 1 }, "opens"},
		"null runs":       {func(g *GrantFile) { g.Runs = nil }, "no run list"},
		"inverted run":    {func(g *GrantFile) { g.Runs[0] = GrantRun{First: 3, Last: 2} }, "starts at segment 3"},
		"past the end":    {func(g *GrantFile) { g.Runs[1].Last = g.Segments }, "numbered 0 to"},
		"adjoining": {func(g *GrantFile) {
			g.Runs = []GrantRun{{First: 0, Last: 1}, {First: 2, Last: 2}}
			g.Granted = 3
		}, "adjoins"},
		"overlapping": {func(g *GrantFile) {
			g.Runs = []GrantRun{{First: 0, Last: 2}, {First: 2, Last: 3}}
			g.Granted = 5
		}, "overlaps"},
		"miscounted":  {func(g *GrantFile) { g.Granted-- }, "the runs cover"},
		"short blob":  {func(g *GrantFile) { g.Blob = g.Blob[:len(g.Blob)-2] }, "hex characters"},
		"bad root":    {func(g *GrantFile) { g.DescriptorsRoot = "zz" }, "descriptors_root"},
		"short uid":   {func(g *GrantFile) { g.DisclosureUID = "abcd" }, "disclosure_uid"},
		"short nonce": {func(g *GrantFile) { g.Nonce = g.Nonce[:10] }, "nonce"},
	}
	base, err := MarshalGrantFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var g GrantFile
			if err := json.Unmarshal(base, &g); err != nil {
				t.Fatal(err)
			}
			c.edit(&g)
			text, err := MarshalGrantFile(&g)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseGrantFile(text); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}

	t.Run("unknown field", func(t *testing.T) {
		text := bytes.Replace(base, []byte(`"format"`), []byte(`"recipient": "counsel", "format"`), 1)
		if _, err := ParseGrantFile(text); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("an unknown field was accepted: %v", err)
		}
	})
	t.Run("trailing document", func(t *testing.T) {
		if _, err := ParseGrantFile(append(append([]byte(nil), base...), []byte("{}")...)); err == nil {
			t.Fatal("a second document after the grant was accepted")
		}
	})
	t.Run("oversize", func(t *testing.T) {
		if _, err := ParseGrantFile(make([]byte, MaxGrantFile+1)); err == nil ||
			!strings.Contains(err.Error(), "at most") {
			t.Fatalf("an oversize file was read: %v", err)
		}
	})
}

// The one test that pays for Argon2id: the passphrase path end to end, and the
// separation between a grant's key and a case key's under the same secret.
func TestSealGrantUnderAPassphrase(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(f.descriptorsOf(t, "open"))
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Zero()
	uid, err := RandomDisclosureUID()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("correct horse battery staple")
	sealed, err := SealGrant(grant, uid, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalGrantFile(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, passphrase) {
		t.Fatal("the passphrase is in the grant file")
	}
	parsed, err := ParseGrantFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	back, err := OpenGrantFile(parsed, passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.material, grant.material) {
		t.Fatal("the recovered material differs")
	}
	back.Zero()
	if _, err := OpenGrantFile(parsed, []byte("correct horse battery stapler")); !errors.Is(err, ErrGrantAuth) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	if _, err := SealGrant(grant, uid, nil); !errors.Is(err, ErrEmptyPassphrase) {
		t.Fatalf("an empty passphrase: %v", err)
	}

	salt := bytes.Repeat([]byte{0x42}, CaseKeySaltSize)
	caseWrap, err := DeriveWrappingKey(passphrase, salt, CaseKeyFileVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(caseWrap)
	grantWrap, err := grantWrapKey(passphrase, salt, GrantFileVersion)
	if err != nil {
		t.Fatal(err)
	}
	defer SecureZero(grantWrap)
	if bytes.Equal(caseWrap, grantWrap) {
		t.Fatal("one passphrase and one salt derive the same key for a case-key file and a grant")
	}
}

func TestZeroedGrantOpensNothingAndStillSaysWhatItWas(t *testing.T) {
	f := newGrantFixture(t)
	grant, err := f.opener.IssueGrant(f.descriptorsOf(t, "pii"))
	if err != nil {
		t.Fatal(err)
	}
	material := grant.material
	count := grant.Count()
	grant.Zero()
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Fatal("Zero left material behind")
	}
	if _, err := grant.OpenSegment(f.aad(t, grant.Indices()[0]), f.cts[grant.Indices()[0]]); err == nil {
		t.Fatal("a zeroed grant opened a segment")
	}
	if grant.Count() != count {
		t.Fatal("a zeroed grant forgot what it granted")
	}
	if _, err := SealGrant(grant, DisclosureUID{}, []byte("x")); err == nil {
		t.Fatal("a zeroed grant was sealed")
	}
}

// TestCaseKeyProfileIsInBand is the check caseKeyProfiles' comment has always
// cited: every fixed passphrase cost in this package is one the rest of the
// tree agrees is sane.
func TestCaseKeyProfileIsInBand(t *testing.T) {
	tables := map[string]map[uint32]argon2Profile{
		"case key file": caseKeyProfiles,
		"grant file":    grantFileProfiles,
	}
	for name, table := range tables {
		for version, p := range table {
			if err := ValidateArgon2Params(p.time, p.memoryKiB, p.threads); err != nil {
				t.Errorf("%s version %d: %v", name, version, err)
			}
			if p.algorithm != "argon2id" || p.keyLen != KeySize {
				t.Errorf("%s version %d: %s keylen %d", name, version, p.algorithm, p.keyLen)
			}
		}
	}
	if _, ok := caseKeyProfiles[CaseKeyFileVersion]; !ok {
		t.Error("the case-key version this build writes has no profile")
	}
	if _, ok := grantFileProfiles[GrantFileVersion]; !ok {
		t.Error("the grant version this build writes has no profile")
	}
}
