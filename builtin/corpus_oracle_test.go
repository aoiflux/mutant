package builtin

// Real-image tests: the shared plumbing.
//
// Every other filesystem test in this package installs a fake backend. Those
// tests pin the plumbing -- argument handling, handle format, refusal paths,
// the shape of a result hash -- and they are worth having, but there is one
// question they cannot answer: whether a builtin reports the truth about a
// volume someone else wrote. A fake session answers whatever the fixture was
// told to answer, and a fixture is built from the same reading of the spec as
// the parser, so it cannot catch a misreading. The fake FAT fixture in
// filesystem_parsers_test.go shows what that costs in practice: its directory
// listing says one file is 12 bytes, its metadata says 14, its content is 14,
// and nothing in the suite notices.
//
// The tests in this file's companions compare the builtins against volumes
// written by implementations that share no code and no reasoning with the
// libraries underneath mutant -- dosfstools, mtools, hfsprogs, hfsutils -- and
// against oracle files recorded by third-party readers: 7-Zip for FAT,
// hfsutils for classic HFS. Where mutant and an independent reader agree about
// a field, the agreement means something.
//
// WHY A FLAG AND NOT AN ENVIRONMENT VARIABLE. The corpus does not live in this
// repository: it is tens of gigabytes of disk images, and it is the owner's
// reference data. Its location therefore has to be told to the test rather
// than derived. The sibling libraries take it from the environment
// (LIBFAT_TEST_IMAGES, LIBHFS_CORPUS_IMAGE). Mutant must not: this project
// takes no configuration from the environment anywhere, and the rule is
// enforced by an AST guard in policy/, not left to discipline. So the path
// arrives as -corpus.dir, following -handles.forgetchild and -procscan.child.
//
// Every test here SKIPS when the flag is absent, which is every ordinary
// `go test ./...` and every release gate. Nothing in this file changes what
// the default suite measures.

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var corpusDir = flag.String("corpus.dir", "",
	"directory holding the forensic disk images and their oracle files; the real-image tests skip when it is empty")

// corpusFile resolves one path inside the corpus, or skips.
//
// A missing file is a skip and not a failure because the corpus is large and a
// partial copy of it is an ordinary thing to have. A missing file is still
// named in the skip, so a volume silently dropping out of the comparison shows
// up in the test log rather than passing as coverage. The tests that iterate
// over volumes count how many they actually reached and fail if that is none,
// which is what stops a wrong -corpus.dir reading as a green suite.
func corpusFile(t *testing.T, rel string) (string, bool) {
	t.Helper()

	if *corpusDir == "" {
		t.Skip("no -corpus.dir: the real-image comparison needs the forensic corpus")
	}
	path := filepath.Join(*corpusDir, filepath.FromSlash(rel))
	info, err := os.Stat(path)
	if err != nil {
		t.Logf("not in this copy of the corpus, skipped: %s (%v)", rel, err)
		return "", false
	}
	if info.IsDir() {
		t.Fatalf("%s is a directory, and an image was expected", path)
	}
	return path, true
}

// oracleRow is one record of an oracle file, with the line it came from.
//
// The line number is carried rather than derived from the row's position in
// the slice, because blank lines are dropped: a message naming the wrong line
// of a file this suite exists to read exactly would be its own small version
// of the problem.
type oracleRow struct {
	line   int
	fields []string
}

// corpusOracleLines reads an oracle file into its tab-separated fields.
//
// The fields are returned as raw bytes converted to a Go string without any
// decoding: a name on an HFS volume is recorded by the generator as the bytes
// hfsutils printed, and deciding what those bytes mean is the caller's job.
// Blank lines are dropped; nothing else is.
func corpusOracleLines(t *testing.T, path string) []oracleRow {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open oracle %s: %v", path, err)
	}
	defer file.Close()

	var rows []oracleRow
	scanner := bufio.NewScanner(file)
	// An oracle row carries a path and a digest and is comfortably under 64 KB,
	// but the default Scanner buffer is the kind of silent limit this whole
	// file exists to catch, so it is raised and a too-long line is an error.
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		rows = append(rows, oracleRow{line: line, fields: strings.Split(text, "\t")})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read oracle %s: %v", path, err)
	}
	if len(rows) == 0 {
		t.Fatalf("oracle %s holds no rows, so there is nothing to compare against", path)
	}
	return rows
}

// macRomanHighBytes maps the non-ASCII bytes this corpus uses to the runes
// Apple's MacRoman table gives them.
//
// The HFS oracle records a name as the raw bytes hfsutils printed, with no
// escaping, while mutant returns UTF-8 decoded through libhfs's own MacRoman
// table. Comparing the two therefore needs a decode on the oracle side, and
// doing it with libhfs's table would make the comparison circular -- the thing
// being measured would supply the answer. These two entries are transcribed
// from the published MacRoman code page instead, so the oracle side is an
// independent reading:
//
//	0xA9 -> U+00A9 COPYRIGHT SIGN
//	0xE9 -> U+00C8 LATIN CAPITAL LETTER E WITH GRAVE
//
// The table is deliberately partial. Those are the only two high bytes in the
// whole corpus, and decodeMacRoman FAILS on any byte it does not cover rather
// than passing the byte through: a silent pass-through would turn a name the
// table cannot read into a mismatch blamed on the parser, and a new image with
// a third high byte should stop the test and be looked at.
var macRomanHighBytes = map[byte]rune{
	0xA9: 0x00A9,
	0xE9: 0x00C8,
}

func decodeMacRoman(t *testing.T, raw string) string {
	t.Helper()

	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x80 {
			out.WriteByte(b)
			continue
		}
		r, ok := macRomanHighBytes[b]
		if !ok {
			t.Fatalf("the oracle holds byte 0x%02X in %q and this test's MacRoman table does not "+
				"cover it: add it from the published code page rather than letting the name through undecoded", b, raw)
		}
		out.WriteRune(r)
	}
	return out.String()
}

// --- FAT oracles ------------------------------------------------------------

// A FAT oracle is written by make_fat_oracle.py in the libfat repository from
// a 7-Zip listing and extraction. Its own documented format is:
//
//	V <filesystem> <label> <physical size> <cluster size> <sector size>
//	d <path>
//	f <path> <size> <short name> <modified> <created> <sha256 or ->
type fatOracleFile struct {
	Path      string
	Size      int64
	ShortName string
	Modified  string
	Created   string
	// SHA256 is "-" when the oracle was generated with --no-content, which
	// skips extraction. The content comparison is skipped for such a row and
	// says so, rather than treating "-" as a digest that failed to match.
	SHA256 string
}

type fatOracle struct {
	FileSystem   string
	Label        string
	PhysicalSize int64
	ClusterSize  int64
	SectorSize   int64
	Dirs         []string
	Files        []fatOracleFile
}

func readFATOracle(t *testing.T, path string) fatOracle {
	t.Helper()

	var oracle fatOracle
	volumeRows := 0
	for _, row := range corpusOracleLines(t, path) {
		fields := row.fields
		switch fields[0] {
		case "V":
			requireOracleFields(t, path, row.line, fields, 6)
			volumeRows++
			oracle.FileSystem = fields[1]
			oracle.Label = fields[2]
			oracle.PhysicalSize = oracleInt(t, path, row.line, fields[3])
			oracle.ClusterSize = oracleInt(t, path, row.line, fields[4])
			oracle.SectorSize = oracleInt(t, path, row.line, fields[5])
		case "d":
			requireOracleFields(t, path, row.line, fields, 2)
			oracle.Dirs = append(oracle.Dirs, fields[1])
		case "f":
			requireOracleFields(t, path, row.line, fields, 7)
			oracle.Files = append(oracle.Files, fatOracleFile{
				Path:      fields[1],
				Size:      oracleInt(t, path, row.line, fields[2]),
				ShortName: fields[3],
				Modified:  fields[4],
				Created:   fields[5],
				SHA256:    fields[6],
			})
		default:
			t.Fatalf("%s line %d: unknown record tag %q; the oracle format has V, d and f, "+
				"and a tag this test does not understand must not be skipped", path, row.line, fields[0])
		}
	}
	if volumeRows != 1 {
		t.Fatalf("%s holds %d V records, want exactly 1", path, volumeRows)
	}
	if len(oracle.Files) == 0 {
		t.Fatalf("%s lists no files, so a comparison against it would assert nothing", path)
	}
	sort.Strings(oracle.Dirs)
	sort.Slice(oracle.Files, func(i, j int) bool { return oracle.Files[i].Path < oracle.Files[j].Path })
	return oracle
}

// fatDeletedTruth is one row of fat_synth/deleted.tsv: what a deletion removed.
//
// It is the only thing in the corpus that can say what a deleted file WAS.
// Nothing recoverable from the volume itself can, because the deletion is what
// destroyed the record of it.
type fatDeletedTruth struct {
	Image  string
	Path   string
	Size   int64
	SHA256 string
}

func readFATDeletedTruth(t *testing.T, path, image string) []fatDeletedTruth {
	t.Helper()

	var rows []fatDeletedTruth
	for _, row := range corpusOracleLines(t, path) {
		fields := row.fields
		requireOracleFields(t, path, row.line, fields, 4)
		if fields[0] != image {
			continue
		}
		rows = append(rows, fatDeletedTruth{
			Image:  fields[0],
			Path:   fields[1],
			Size:   oracleInt(t, path, row.line, fields[2]),
			SHA256: fields[3],
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Size < rows[j].Size })
	return rows
}

// --- HFS oracles ------------------------------------------------------------

// An HFS oracle is written by gen_oracle.sh in the libhfs repository from an
// hfsutils listing. Its own documented format is:
//
//	V <volume name> <free bytes>
//	d <path> <item count>
//	f <path> <data size> <rsrc size> <type/creator>
//
// Classic HFS only, and the generator says why: hfsutils cannot read HFS+ at
// all, and on a wrapped volume it reads the HFS WRAPPER while libhfs reads the
// embedded HFS+ volume inside it -- two different filesystems with different
// contents. So the HFS+ and HFSX volumes in the corpus carry no oracle, and
// comparing against one would be comparing two different things.
type hfsOracleEntry struct {
	Path string
	// Items is the child count of a directory. mutant has no field for it, so
	// it is checked against the number of entries hfs_list_files returns.
	Items int64
	// DataSize and RsrcSize are the two forks. A classic HFS file has both,
	// and conflating them is a way to be wrong that only a real volume with a
	// resource fork can show.
	DataSize    int64
	RsrcSize    int64
	TypeCreator string
}

type hfsOracle struct {
	VolumeName string
	FreeBytes  int64
	Dirs       []hfsOracleEntry
	Files      []hfsOracleEntry
}

func readHFSOracle(t *testing.T, path string) hfsOracle {
	t.Helper()

	var oracle hfsOracle
	volumeRows := 0
	for _, row := range corpusOracleLines(t, path) {
		fields := row.fields
		switch fields[0] {
		case "V":
			requireOracleFields(t, path, row.line, fields, 3)
			volumeRows++
			oracle.VolumeName = decodeMacRoman(t, fields[1])
			oracle.FreeBytes = oracleInt(t, path, row.line, fields[2])
		case "d":
			requireOracleFields(t, path, row.line, fields, 3)
			oracle.Dirs = append(oracle.Dirs, hfsOracleEntry{
				Path:  decodeMacRoman(t, fields[1]),
				Items: oracleInt(t, path, row.line, fields[2]),
			})
		case "f":
			requireOracleFields(t, path, row.line, fields, 5)
			oracle.Files = append(oracle.Files, hfsOracleEntry{
				Path:        decodeMacRoman(t, fields[1]),
				DataSize:    oracleInt(t, path, row.line, fields[2]),
				RsrcSize:    oracleInt(t, path, row.line, fields[3]),
				TypeCreator: fields[4],
			})
		default:
			t.Fatalf("%s line %d: unknown record tag %q; the oracle format has V, d and f, "+
				"and a tag this test does not understand must not be skipped", path, row.line, fields[0])
		}
	}
	if volumeRows != 1 {
		t.Fatalf("%s holds %d V records, want exactly 1", path, volumeRows)
	}
	// An HFS oracle with no file rows is not malformed: the corpus holds an
	// empty classic volume, and its name and free space are still worth
	// comparing. The tests that need files skip such a volume by name and say
	// so, which is why this is not refused the way the FAT parser refuses it.
	sort.Slice(oracle.Dirs, func(i, j int) bool { return oracle.Dirs[i].Path < oracle.Dirs[j].Path })
	sort.Slice(oracle.Files, func(i, j int) bool { return oracle.Files[i].Path < oracle.Files[j].Path })
	return oracle
}

// --- shared helpers ---------------------------------------------------------

func requireOracleFields(t *testing.T, path string, line int, fields []string, want int) {
	t.Helper()

	if len(fields) != want {
		t.Fatalf("%s line %d: %d tab-separated fields, want %d: %q",
			path, line, len(fields), want, strings.Join(fields, "\t"))
	}
}

func oracleInt(t *testing.T, path string, line int, field string) int64 {
	t.Helper()

	value, err := strconv.ParseInt(strings.TrimSpace(field), 10, 64)
	if err != nil {
		t.Fatalf("%s line %d: %q is not a number: %v", path, line, field, err)
	}
	return value
}

// comparePathSets reports what one side holds and the other does not.
//
// It reports both directions and names the paths, because "47 entries, want
// 48" says nothing about which volume was misread, and a count that matches
// while the paths differ is the interesting failure.
func comparePathSets(t *testing.T, what string, got, want []string) {
	t.Helper()

	gotSet := make(map[string]bool, len(got))
	for _, p := range got {
		if gotSet[p] {
			t.Errorf("%s: mutant listed %q twice", what, p)
		}
		gotSet[p] = true
	}
	wantSet := make(map[string]bool, len(want))
	for _, p := range want {
		wantSet[p] = true
	}

	var missing, extra []string
	for _, p := range want {
		if !gotSet[p] {
			missing = append(missing, p)
		}
	}
	for _, p := range got {
		if !wantSet[p] {
			extra = append(extra, p)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%s: %d of %d not found by mutant: %s", what, len(missing), len(want), sampleOf(missing))
	}
	if len(extra) > 0 {
		t.Errorf("%s: %d reported by mutant that the independent reader did not see: %s",
			what, len(extra), sampleOf(extra))
	}
}

// sampleOf prints at most eight paths and says how many it left out, so a
// volume-wide disagreement is readable instead of two thousand lines long.
func sampleOf(paths []string) string {
	const show = 8
	if len(paths) <= show {
		return strings.Join(paths, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(paths[:show], ", "), len(paths)-show)
}
