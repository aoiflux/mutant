package builtin

import "testing"

func TestBuiltinsHaveTeachingCoverage(t *testing.T) {
	for _, entry := range Builtins {
		if entry.Name == "" {
			t.Fatalf("builtin entry has empty name")
		}
		if !HasTeachingCoverage(entry.Name) {
			t.Fatalf("builtin %q is missing teaching coverage", entry.Name)
		}
	}
}

func TestParserAndDiskImageFamiliesHaveTeachingCoverage(t *testing.T) {
	required := []string{
		"ntfs_open",
		"fat_open",
		"xfat_open",
		"ext_open",
		"hfs_open",
		"xfs_open",
		"vhdi_open",
		"ewf_open",
		"raw_open",
		"table_open",
	}

	for _, name := range required {
		if !HasTeachingCoverage(name) {
			t.Fatalf("expected teaching coverage for %q", name)
		}
	}
}
