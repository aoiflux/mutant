package security

import "testing"

// TestAnArtifactMayAskForNoMoreThanTheTreeDerives is M26-LIM-010's regression
// test. An artifact's header names the Argon2id cost its password key was
// derived with, and the runner pays that cost before anything in the artifact
// has been authenticated. The header could ask for four gibibytes at eight
// passes in sixteen lanes, which no Mutant build has ever written; the band now
// stops at the costliest derivation in the tree.
func TestAnArtifactMayAskForNoMoreThanTheTreeDerives(t *testing.T) {
	var costliest argon2Profile
	for _, table := range []map[uint32]argon2Profile{caseKeyProfiles, grantFileProfiles} {
		for _, p := range table {
			costliest.time = max(costliest.time, p.time)
			costliest.memoryKiB = max(costliest.memoryKiB, p.memoryKiB)
			costliest.threads = max(costliest.threads, p.threads)
		}
	}
	if err := ValidateArgon2Params(costliest.time, costliest.memoryKiB, costliest.threads); err != nil {
		t.Fatalf("the costliest derivation in the tree is refused: %v", err)
	}
	if err := ValidateArgon2Params(DefaultArgon2Time, DefaultArgon2Memory, DefaultArgon2Threads); err != nil {
		t.Fatalf("the cost the generator writes is refused: %v", err)
	}
	if err := ValidateArgon2Params(DefaultArgon2Time, DefaultArgon2Memory-1, DefaultArgon2Threads); err == nil {
		t.Error("a header asking for less memory than the generator writes is accepted")
	}

	for _, c := range []struct {
		name         string
		time, memory uint32
		threads      uint8
	}{
		{"one more pass", costliest.time + 1, costliest.memoryKiB, costliest.threads},
		{"one more kibibyte", costliest.time, costliest.memoryKiB + 1, costliest.threads},
		{"one more lane", costliest.time, costliest.memoryKiB, costliest.threads + 1},
		{"the old ceiling", 8, 4 * 1024 * 1024, 16},
	} {
		if err := ValidateArgon2Params(c.time, c.memory, c.threads); err == nil {
			t.Errorf("%s: a header asking for %d passes over %d KiB in %d lanes is accepted", c.name, c.time, c.memory, c.threads)
		}
	}

	// The same header, met where the runner meets it: in an artifact's
	// encryption metadata, before any key exists to check it with.
	crafted := serializeMetadata(EncryptionMetadata{
		Ciphertext:     "AAAA",
		Salt:           "00",
		UsePasswordKDF: true,
		IterationCount: 8,
		Memory:         4 * 1024 * 1024,
		Parallelism:    16,
	})
	if _, err := deserializeMetadata(crafted); err == nil {
		t.Error("an artifact whose metadata asks Argon2id for 4 GiB is read without complaint")
	}
}
