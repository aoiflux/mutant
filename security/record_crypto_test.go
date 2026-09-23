package security

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type stubSource struct {
	secret []byte
	calls  int
	err    error
}

func (s *stubSource) Passphrase(PassphraseRequest) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.secret...), nil
}

func mustKeys(t *testing.T, total uint64) (*RecordKeys, CaseUID, RecordUID, []byte, []byte) {
	t.Helper()
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	ruid, err := RandomRecordUID()
	if err != nil {
		t.Fatal(err)
	}
	keys, rk, salt, err := NewRecordKeysForSeal(cuid, ruid, 1, total)
	if err != nil {
		t.Fatal(err)
	}
	return keys, cuid, ruid, rk, salt
}

// sealUpTo seals every segment below index, so that a test wanting to exercise
// one segment in the middle of a record can get to it.
//
// A record is sealed in order and every segment exactly once -- see
// TestARecordIsSealedInOrderAndCompletely for why -- so "just seal segment 17"
// is not a thing a caller can do, and a test that did it was testing a handle
// no real record ever has. The filler is distinct per index so that a segment
// opened by mistake reads as obviously the wrong one.
func sealUpTo(t *testing.T, keys *RecordKeys, index uint64) {
	t.Helper()
	for i := uint64(0); i < index; i++ {
		filler := []byte(fmt.Sprintf("filler-%04d", i))
		aad := keys.SegmentAAD(i, i*64, uint32(len(filler)), UnclassifiedTag)
		if _, _, err := keys.SealSegment(aad, filler); err != nil {
			t.Fatalf("filling segment %d: %v", i, err)
		}
	}
}

func TestSegmentRoundTrip(t *testing.T) {
	keys, _, _, _, _ := mustKeys(t, 4)
	defer keys.Zero()
	sealUpTo(t, keys, 2)
	aad := keys.SegmentAAD(2, 128, 11, UnclassifiedTag)
	ct, digest, err := keys.SealSegment(aad, []byte("hello world"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(ct) != 11+16 {
		t.Fatalf("ciphertext is %d bytes, want %d", len(ct), 27)
	}
	pt, err := keys.OpenSegment(aad, ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(pt) != "hello world" {
		t.Fatalf("got %q", pt)
	}
	t.Logf("SEAL/OPEN ok: ct=%d bytes (pt+16), aad=%d bytes, digest=%s", len(ct), SegmentAADSize, hex.EncodeToString(digest[:8]))
}

// TestSegmentMaterialSeparatesOnEveryAADField is the test Design 1 and Design 2
// both failed: two seals differing only in a non-index AAD field shared a key
// and a nonce, which is a two-time pad.
func TestSegmentMaterialSeparatesOnEveryAADField(t *testing.T) {
	keys, _, _, _, _ := mustKeys(t, 8)
	defer keys.Zero()
	pii, err := TagForClass(bytes.Repeat([]byte{7}, 32), "pii")
	if err != nil {
		t.Fatal(err)
	}
	public, err := TagForClass(bytes.Repeat([]byte{7}, 32), "public")
	if err != nil {
		t.Fatal(err)
	}
	base := keys.SegmentAAD(3, 0, 8, pii)
	cases := map[string]SegmentAAD{
		"class":  keys.SegmentAAD(3, 0, 8, public),
		"offset": keys.SegmentAAD(3, 4096, 8, pii),
		"length": keys.SegmentAAD(3, 0, 4, pii),
		"index":  keys.SegmentAAD(4, 0, 8, pii),
	}
	bk, bn, err := keys.segmentMaterial(base.encode())
	if err != nil {
		t.Fatal(err)
	}
	for name, aad := range cases {
		k, n, err := keys.segmentMaterial(aad.encode())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(bk, k) {
			t.Errorf("%s: the segment KEY is identical to the base; a two-time pad is reachable", name)
		}
		if bn == n {
			t.Errorf("%s: the segment NONCE is identical to the base; a two-time pad is reachable", name)
		}
	}
	t.Logf("every AAD field separates key AND nonce (class, offset, length, index); base key=%s nonce=%s",
		hex.EncodeToString(bk[:8]), hex.EncodeToString(bn[:8]))
}

func TestSegmentAttacksAreRefused(t *testing.T) {
	keys, cuid, ruid, rk, salt := mustKeys(t, 5)
	defer keys.Zero()
	tagKey := bytes.Repeat([]byte{9}, 32)
	pii, _ := TagForClass(tagKey, "pii")
	public, _ := TagForClass(tagKey, "public")

	sealUpTo(t, keys, 3)
	good := keys.SegmentAAD(3, 3*64, 9, pii)
	ct, _, err := keys.SealSegment(good, []byte("informant"))
	if err != nil {
		t.Fatal(err)
	}

	other, err := RandomRecordUID()
	if err != nil {
		t.Fatal(err)
	}
	graftKeys, err := OpenRecordKeys(cuid, other, 1, 5, rk, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer graftKeys.Zero()
	otherCase, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	crossCase, err := OpenRecordKeys(otherCase, ruid, 1, 5, rk, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer crossCase.Zero()
	genTwo, err := OpenRecordKeys(cuid, ruid, 2, 5, rk, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer genTwo.Zero()
	truncated, err := OpenRecordKeys(cuid, ruid, 1, 3, rk, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer truncated.Zero()

	attacks := []struct {
		name string
		k    *RecordKeys
		aad  SegmentAAD
	}{
		{"reorder (index 3 presented as 4)", keys, keys.SegmentAAD(4, 3*64, 9, pii)},
		{"splice (same index, different offset)", keys, keys.SegmentAAD(3, 9*64, 9, pii)},
		{"length lie", keys, keys.SegmentAAD(3, 3*64, 8, pii)},
		{"reclassification pii -> public", keys, keys.SegmentAAD(3, 3*64, 9, public)},
		{"cross-record graft", graftKeys, graftKeys.SegmentAAD(3, 3*64, 9, pii)},
		{"cross-case graft", crossCase, crossCase.SegmentAAD(3, 3*64, 9, pii)},
		{"generation re-attribution", genTwo, genTwo.SegmentAAD(3, 3*64, 9, pii)},
		{"truncation (5 segments presented as 3)", truncated, truncated.SegmentAAD(3, 3*64, 9, pii)},
	}
	for _, a := range attacks {
		if _, err := a.k.OpenSegment(a.aad, ct); err == nil {
			t.Errorf("%s: ACCEPTED", a.name)
		} else {
			t.Logf("%-42s refused: %v", a.name, err)
		}
	}
	flipped := append([]byte(nil), ct...)
	flipped[0] ^= 1
	if _, err := keys.OpenSegment(good, flipped); err == nil {
		t.Error("flipped byte: ACCEPTED")
	}
}

// TestASealHandleCannotBeRebuiltFromStoredMaterial is the two-time-pad guard.
func TestASealHandleCannotBeRebuiltFromStoredMaterial(t *testing.T) {
	keys, cuid, ruid, rk, salt := mustKeys(t, 2)
	defer keys.Zero()
	reopened, err := OpenRecordKeys(cuid, ruid, 1, 2, rk, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Zero()
	if reopened.CanSeal() {
		t.Fatal("a handle rebuilt from stored material reports that it can seal")
	}
	_, _, err = reopened.SealSegment(reopened.SegmentAAD(0, 0, 3, UnclassifiedTag), []byte("abc"))
	if err == nil {
		t.Fatal("re-sealing from stored material was ACCEPTED; a two-time pad is reachable")
	}
	t.Logf("re-seal refused: %v", err)
}

// The same defence one level down: a handle that CAN seal must still refuse to
// seal a position twice.
//
// The test above proves a second handle cannot seal over a first. It proves
// nothing about one handle, and for a while nothing did. Sealing index 0 twice
// produced two ciphertexts under one keystream, because a segment's key and
// nonce are derived from its descriptor and a descriptor names the position
// rather than the content -- so XOR returned both plaintexts with no key.
//
// The assertion is that the second message is UNRECOVERABLE and not merely
// that the API declined, which is why the failure path does the XOR and prints
// what it got.
func TestSealingAPositionTwiceIsRefused(t *testing.T) {
	keys, _, _, _, _ := mustKeys(t, 4)
	defer keys.Zero()

	first := []byte("informant A")
	second := []byte("[REDACTED!]")
	if len(first) != len(second) {
		t.Fatal("this test needs two messages of one length to XOR them")
	}
	aad := keys.SegmentAAD(0, 0, uint32(len(first)), UnclassifiedTag)

	c1, _, err := keys.SealSegment(aad, first)
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := keys.SealSegment(aad, second)
	if err == nil {
		recovered := make([]byte, len(first))
		for i := range recovered {
			recovered[i] = c1[i] ^ c2[i] ^ first[i]
		}
		t.Fatalf("sealing index 0 twice was accepted, and c1^c2^p1 recovers %q with no key at all",
			recovered)
	}
	t.Logf("refused: %v", err)

	// The refusal must not have consumed the index either: the record still has
	// segment 1 to seal next and has not lost a slot to a rejected call.
	if got := keys.SealedCount(); got != 1 {
		t.Fatalf("a refused seal moved the count to %d", got)
	}
}

// A record is sealed in order and completely, and both are checkable where the
// sealing happens.
//
// Per-segment authentication cannot see a segment that is missing: the ones
// that exist are each individually valid, which is the blind spot that makes
// the count worth keeping. SealComplete is what item 2's footer has to ask
// before it signs a claim about a whole record.
func TestARecordIsSealedInOrderAndCompletely(t *testing.T) {
	const total = 3
	keys, cuid, ruid, rk, salt := mustKeys(t, total)
	defer keys.Zero()

	if keys.SealComplete() {
		t.Fatal("a record with nothing sealed reports a complete seal")
	}
	if _, _, err := keys.SealSegment(keys.SegmentAAD(1, 0, 1, UnclassifiedTag), []byte("b")); err == nil {
		t.Fatal("segment 1 was sealed before segment 0, which leaves a record with a gap in it")
	}

	for i := uint64(0); i < total; i++ {
		aad := keys.SegmentAAD(i, i, 1, UnclassifiedTag)
		if _, _, err := keys.SealSegment(aad, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		if got := keys.SealedCount(); got != i+1 {
			t.Fatalf("after sealing segment %d the count is %d", i, got)
		}
		if keys.SealComplete() != (i+1 == total) {
			t.Fatalf("after sealing segment %d complete=%t", i, keys.SealComplete())
		}
	}

	// A handle that cannot seal has sealed nothing, and says so rather than
	// reporting the record it was rebuilt from as complete.
	reopened, err := OpenRecordKeys(cuid, ruid, 1, total, rk, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Zero()
	if reopened.SealComplete() || reopened.SealedCount() != 0 {
		t.Fatalf("an opening handle reports complete=%t count=%d",
			reopened.SealComplete(), reopened.SealedCount())
	}
}

// TestNoSegmentCap is the 145-segment cap, gone.
func TestNoSegmentCap(t *testing.T) {
	const total = 200000
	keys, _, _, _, _ := mustKeys(t, total)
	defer keys.Zero()
	seen := make(map[[16]byte]struct{}, 40000)
	start := time.Now()
	for i := uint64(0); i < total; i++ {
		aad := keys.SegmentAAD(i, i*65536, 64, UnclassifiedTag)
		k, n, err := keys.segmentMaterial(aad.encode())
		if err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
		if i < 40000 {
			var fp [16]byte
			copy(fp[:8], k[:8])
			copy(fp[8:], n[:8])
			if _, dup := seen[fp]; dup {
				t.Fatalf("segment %d repeats key||nonce", i)
			}
			seen[fp] = struct{}{}
		}
	}
	d := time.Since(start)
	t.Logf("%d segments derived, 0 errors, %v (%.0f ns/segment); %d sampled key||nonce prefixes all distinct; "+
		"at 64 KiB/segment that is %.1f GiB of record",
		total, d.Round(time.Millisecond), float64(d.Nanoseconds())/total, len(seen), float64(total)*65536/(1<<30))
}

func TestPassphraseSeam(t *testing.T) {
	if _, err := RequestPassphrase(PassphraseRequest{Purpose: "x"}); err != ErrNoPassphraseSource {
		t.Fatalf("with nothing installed, got %v, want ErrNoPassphraseSource", err)
	}
	t.Logf("no source installed -> %v  (this is the state every `go test` run is in)", ErrNoPassphraseSource)

	stub := &stubSource{secret: []byte("hunter2hunter2")}
	prev := SetPassphraseSource(stub)
	defer SetPassphraseSource(prev)
	got, err := RequestPassphrase(PassphraseRequest{Purpose: "case_key_open", Path: "k.mkey"})
	if err != nil || string(got) != "hunter2hunter2" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !PassphraseSourceInstalled() {
		t.Fatal("PassphraseSourceInstalled reports false with a source installed")
	}
	SetPassphraseSource(&stubSource{secret: nil})
	if _, err := RequestPassphrase(PassphraseRequest{}); err != ErrEmptyPassphrase {
		t.Fatalf("empty answer: got %v", err)
	}
	t.Logf("stub answered (calls=%d), empty answer refused, previous source restorable -- no t.Setenv anywhere", stub.calls)
}

func TestCaseKeyFileLifecycle(t *testing.T) {
	pass := []byte("correct horse battery staple")
	cuid, err := RandomCaseUID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 22, 11, 4, 19, 0, time.UTC)

	start := time.Now()
	f, caseKey, err := NewCaseKeyFile(pass, cuid, "IR-2026-0031", now)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("create cost %v (argon2id t=%d m=%d KiB p=%d)", time.Since(start).Round(time.Millisecond),
		f.KDF.Time, f.KDF.MemoryKiB, f.KDF.Threads)

	salt, _ := f.SaltBytes()
	wrapKey, err := DeriveWrappingKey(pass, salt, f.Version)
	if err != nil {
		t.Fatal(err)
	}
	signed, reason, err := SealCaseKeyFile(f, wrapKey, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sealed: signed=%v reason=%q file_mac=%s...", signed, reason, f.FileMAC[:16])

	document, err := MarshalCaseKeyFile(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("document is %d bytes, wrapped blob is %d hex chars (%d bytes)", len(document), len(f.Generations[0].Wrapped), WrappedKeySize)

	parsed, err := ParseCaseKeyFile(document)
	if err != nil {
		t.Fatal(err)
	}
	reopened, wk2, err := OpenCaseKeyFile(parsed, pass, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reopened, caseKey) {
		t.Fatal("round trip did not recover the case key")
	}
	SecureZero(wk2)
	t.Logf("round trip recovered the case key byte for byte; fingerprint %s", parsed.Generations[0].Fingerprint[:16])

	sgn, valid, detail := VerifyCaseKeyFileSignature(parsed)
	t.Logf("signature: signed=%v valid=%v detail=%q", sgn, valid, detail)

	// The file MAC catches what no AEAD tag covers.
	rolled := *parsed
	rolled.Current = 1
	rolled.Generations = append([]CaseKeyGeneration(nil), parsed.Generations...)
	if _, err := f.Generation(9); err == nil {
		t.Error("Generation(9) should not exist")
	}

	// Case-key rotation: a new generation, old ones still open.
	caseKey2, err := parsed.RotateCaseKey(pass, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(caseKey2, caseKey) {
		t.Fatal("rotation produced the same case key")
	}
	salt2, _ := parsed.SaltBytes()
	wk3, _ := DeriveWrappingKey(pass, salt2, parsed.Version)
	if _, _, err := SealCaseKeyFile(parsed, wk3, false); err != nil {
		t.Fatal(err)
	}
	g1, err := parsed.UnwrapGeneration(wk3, 1)
	if err != nil {
		t.Fatalf("generation 1 after a case-key rotation: %v", err)
	}
	if !bytes.Equal(g1, caseKey) {
		t.Fatal("generation 1 changed across a case-key rotation")
	}
	t.Logf("case-key rotation: current=%d, generations=%d, generation 1 still opens and is unchanged, previous_file_mac=%s...",
		parsed.Current, len(parsed.Generations), parsed.PreviousFileMAC[:16])
	SecureZero(wk3)

	// current flipped back: the MAC catches it.
	tampered := *parsed
	tampered.Current = 1
	wk4, _ := DeriveWrappingKey(pass, salt2, parsed.Version)
	if err := VerifyCaseKeyFile(&tampered, wk4); err == nil {
		t.Error("a rollback of `current` inside the file was ACCEPTED")
	} else {
		t.Logf("current 2->1 in place: refused (%v)", err)
	}

	// Passphrase rotation: new salt, same case keys, old passphrase dead.
	newPass := []byte("a different passphrase entirely")
	if err := parsed.RotatePassphrase(pass, newPass, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	salt3, _ := parsed.SaltBytes()
	wk5, _ := DeriveWrappingKey(newPass, salt3, parsed.Version)
	if _, _, err := SealCaseKeyFile(parsed, wk5, false); err != nil {
		t.Fatal(err)
	}
	after, err := parsed.UnwrapGeneration(wk5, 1)
	if err != nil || !bytes.Equal(after, caseKey) {
		t.Fatalf("generation 1 after a passphrase rotation: %v", err)
	}
	if _, _, err := OpenCaseKeyFile(parsed, pass, 1); err == nil {
		t.Error("the OLD passphrase still opens the file after a passphrase rotation")
	} else {
		t.Logf("passphrase rotation: salt changed, every case key byte-identical, old passphrase refused (%v)", err)
	}
	SecureZero(wk5)
	SecureZero(wrapKey)
}

// TestRotationInvalidatesNoGrant is the property the task asked to be proven.
func TestRotationInvalidatesNoGrant(t *testing.T) {
	keys, cuid, ruid, rk, salt := mustKeys(t, 32)
	defer keys.Zero()
	sealUpTo(t, keys, 17)
	aad := keys.SegmentAAD(17, 17*64, 12, UnclassifiedTag)
	ct, _, err := keys.SealSegment(aad, []byte("grant target"))
	if err != nil {
		t.Fatal(err)
	}
	grantKey, grantNonce, err := keys.segmentMaterial(aad.encode())
	if err != nil {
		t.Fatal(err)
	}

	// Rotation rewraps the record key under a new case key. The record key, the
	// uid, the seal salt and the case uid are all unchanged, so the grant is too.
	oldCase, _ := randomBytes(KeySize)
	newCase, _ := randomBytes(KeySize)
	nonce, wrapped, err := WrapRecordKey(oldCase, ruid, rk)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := UnwrapRecordKey(oldCase, ruid, nonce, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	nonce2, wrapped2, err := WrapRecordKey(newCase, ruid, recovered)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrapped, wrapped2) {
		t.Fatal("the rewrap produced identical ciphertext; the nonce was reused")
	}
	after, err := UnwrapRecordKey(newCase, ruid, nonce2, wrapped2)
	if err != nil || !bytes.Equal(after, rk) {
		t.Fatalf("rewrap lost the record key: %v", err)
	}

	post, err := OpenRecordKeys(cuid, ruid, 1, 32, after, salt)
	if err != nil {
		t.Fatal(err)
	}
	defer post.Zero()
	k2, n2, err := post.segmentMaterial(post.SegmentAAD(17, 17*64, 12, UnclassifiedTag).encode())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(grantKey, k2) || grantNonce != n2 {
		t.Fatal("the grant's segment material changed across a rotation")
	}
	pt, err := post.OpenSegment(post.SegmentAAD(17, 17*64, 12, UnclassifiedTag), ct)
	if err != nil || string(pt) != "grant target" {
		t.Fatalf("the segment stopped opening after a rotation: %v", err)
	}
	t.Logf("rotation rewrapped %d bytes of record key (%d on disk + a fresh %d-byte nonce); "+
		"segment 17's key and nonce are byte-identical and the ciphertext still opens",
		KeySize, len(wrapped2), len(nonce2))

	// And the wrap is bound: the new case key does not open the old wrap.
	if _, err := UnwrapRecordKey(newCase, ruid, nonce, wrapped); err == nil {
		t.Error("the new case key opened the OLD wrap")
	}
	if _, err := UnwrapRecordKey(oldCase, RecordUID{}, nonce, wrapped); err == nil {
		t.Error("the wrap opened under another record's uid")
	}
}

func TestClassTagIsKeyedToTheCase(t *testing.T) {
	a, _ := randomBytes(KeySize)
	b, _ := randomBytes(KeySize)
	ka, err := ClassTagKey(a)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := ClassTagKey(b)
	ta, _ := TagForClass(ka, "pii")
	tb, _ := TagForClass(kb, "pii")
	if ta == tb {
		t.Fatal("the same label produces the same tag in two different cases")
	}
	again, _ := TagForClass(ka, "pii")
	if again != ta {
		t.Fatal("the tag is not deterministic within a case")
	}
	if _, err := TagForClass(ka, ""); err == nil {
		t.Error("an empty label was tagged")
	}
	if _, err := TagForClass(ka, strings.Repeat("x", MaxClassLabel+1)); err == nil {
		t.Error("an over-long label was tagged")
	}
	t.Logf("pii in case A = %s..., in case B = %s... -- an attacker with only the record cannot dictionary it",
		hex.EncodeToString(ta[:8]), hex.EncodeToString(tb[:8]))
}

func TestParseRefusesHostileCostAndUnknownFields(t *testing.T) {
	pass := []byte("pp")
	cuid, _ := RandomCaseUID()
	f, ck, err := NewCaseKeyFile(pass, cuid, "C", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	SecureZero(ck)
	salt, _ := f.SaltBytes()
	wk, _ := DeriveWrappingKey(pass, salt, f.Version)
	if _, _, err := SealCaseKeyFile(f, wk, false); err != nil {
		t.Fatal(err)
	}
	SecureZero(wk)
	document, _ := MarshalCaseKeyFile(f)

	var raw map[string]any
	if err := json.Unmarshal(document, &raw); err != nil {
		t.Fatal(err)
	}
	reserialise := func(mutate func(map[string]any)) []byte {
		copyOf := map[string]any{}
		_ = json.Unmarshal(document, &copyOf)
		mutate(copyOf)
		out, _ := json.Marshal(copyOf)
		return out
	}

	hostile := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"kdf memory raised to 4 GiB", func(m map[string]any) {
			m["kdf"].(map[string]any)["memory_kib"] = 4194304.0
		}},
		{"kdf time raised to 8", func(m map[string]any) {
			m["kdf"].(map[string]any)["time"] = 8.0
		}},
		{"kdf algorithm switched to hkdf-sha256", func(m map[string]any) {
			m["kdf"].(map[string]any)["algorithm"] = "hkdf-sha256"
		}},
		{"kdf memory lowered to 8 MiB", func(m map[string]any) {
			m["kdf"].(map[string]any)["memory_kib"] = 8192.0
		}},
		{"an unknown field", func(m map[string]any) { m["surprise"] = "hello" }},
		{"version 2", func(m map[string]any) { m["version"] = 2.0 }},
		{"current out of range", func(m map[string]any) { m["current"] = 7.0 }},
	}
	for _, h := range hostile {
		start := time.Now()
		if _, err := ParseCaseKeyFile(reserialise(h.mutate)); err == nil {
			t.Errorf("%s: ACCEPTED", h.name)
		} else {
			t.Logf("%-38s refused in %v: %.90s", h.name, time.Since(start).Round(time.Microsecond), err.Error())
		}
	}
}
