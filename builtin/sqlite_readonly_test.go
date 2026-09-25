package builtin

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mutant/object"
)

// buildLiveWALEvidence writes evidence.db as an acquisition of a live database
// would find it: WAL mode, with committed rows still in evidence.db-wal that
// were never checkpointed into the main file. The files are copied while the
// writer still holds the database open, because closing it would checkpoint.
// other.db beside it is a second, ordinary database.
func buildLiveWALEvidence(t *testing.T) (dir, evidence, other string) {
	t.Helper()
	dir = t.TempDir()
	live := filepath.Join(t.TempDir(), "live.db")

	db, err := sql.Open("sqlite", live)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA wal_autocheckpoint=0",
		"CREATE TABLE t (x TEXT)",
		"INSERT INTO t VALUES ('checkpointed')",
		"PRAGMA wal_checkpoint(TRUNCATE)",
		"INSERT INTO t VALUES ('only in the wal 1')",
		"INSERT INTO t VALUES ('only in the wal 2')",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	evidence = filepath.Join(dir, "evidence.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(live + suffix)
		if err != nil {
			t.Fatalf("acquiring %s: %v", live+suffix, err)
		}
		if err := os.WriteFile(evidence+suffix, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	other = filepath.Join(dir, "other.db")
	odb, err := sql.Open("sqlite", other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := odb.Exec("CREATE TABLE t (x TEXT); INSERT INTO t VALUES ('other')"); err != nil {
		t.Fatal(err)
	}
	if err := odb.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, evidence, other
}

// directoryDigests is every file under dir and its SHA-256.
func directoryDigests(t *testing.T, dir string) map[string]string {
	t.Helper()
	digests := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		digests[path] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return digests
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// M26-DAT-001. sqlite_query copies the database it is given and promises the
// original is never modified. It ran the script's SQL on a writable connection
// to that copy, so ATTACH opened any other path read-write: a SELECT through an
// attached WAL-mode database checkpointed its WAL into it and deleted the WAL,
// a DELETE emptied the original, and an INSERT wrote a classified buffer to a
// file of the script's choosing. No statement may reach a file other than the
// copy, and the copy is read-only.
func TestSqliteQueryCannotReachAnyFileButItsCopy(t *testing.T) {
	secret := &object.Bytes{Value: []byte("classified plaintext"), Classified: &object.Classification{
		RecordUID: "r", Tags: []string{strings.Repeat("ab", 16)}, Labels: []string{"pii"}}}

	for _, builtin := range []struct {
		name string
		fn   func(...object.Object) object.Object
	}{
		{"sqlite_query", SqliteQuery},
		{"sqlite_query_bytes", SqliteQueryBytes},
	} {
		t.Run(builtin.name, func(t *testing.T) {
			dir, evidence, other := buildLiveWALEvidence(t)
			vacuumed := filepath.Join(dir, "vacuumed.db")
			before := directoryDigests(t, dir)

			refused := []struct {
				name   string
				sql    string
				params []object.Object
			}{
				{"attach the original and read it", "ATTACH ?1 AS o; SELECT count(*) AS n FROM o.t", []object.Object{stringObj(evidence)}},
				{"attach another database and read it", "ATTACH ?1 AS o; SELECT count(*) AS n FROM o.t", []object.Object{stringObj(other)}},
				{"attach the original and delete from it", "ATTACH ?1 AS o; DELETE FROM o.t; SELECT 1 AS x", []object.Object{stringObj(evidence)}},
				{"write a classified buffer to a new file", "ATTACH ?1 AS o; CREATE TABLE o.leak (x); INSERT INTO o.leak VALUES (?2); SELECT 1 AS x",
					[]object.Object{stringObj(filepath.Join(dir, "leak.db")), secret}},
				{"vacuum into a new file", "VACUUM INTO ?1", []object.Object{stringObj(vacuumed)}},
				{"delete from the copy", "DELETE FROM t; SELECT 1 AS x", nil},
				{"insert a classified buffer into the copy", "INSERT INTO t VALUES (?1); SELECT 1 AS x", []object.Object{secret}},
				{"turn query_only off and delete", "PRAGMA query_only=0; DELETE FROM t; SELECT 1 AS x", nil},
			}
			for _, query := range refused {
				args := []object.Object{stringObj(evidence), stringObj(query.sql)}
				if query.params != nil {
					args = append(args, &object.Array{Elements: query.params})
				}
				if _, errObj := unwrapPair(t, builtin.fn(args...)); errObj == nil {
					t.Errorf("%s: the statement ran", query.name)
				}
			}

			// The copy still answers what it was taken to answer, WAL included.
			payload, errObj := unwrapPair(t, builtin.fn(stringObj(evidence), stringObj("SELECT count(*) AS n FROM t")))
			if errObj != nil {
				t.Fatalf("an ordinary SELECT failed: %s", errObj.Inspect())
			}
			rows := hashValueByKey(payload.(*object.Hash), "rows").(*object.Array)
			if n := hInt(t, rows.Elements[0].(*object.Hash), "n"); n != 3 {
				t.Errorf("count(*) = %d, want 3: the rows still in the WAL must be read", n)
			}

			after := directoryDigests(t, dir)
			for _, path := range sortedKeys(before) {
				if after[path] != before[path] {
					t.Errorf("%s changed (or vanished): %s -> %q", filepath.Base(path), before[path][:12], after[path])
				}
			}
			for _, path := range sortedKeys(after) {
				if _, existed := before[path]; !existed {
					t.Errorf("%s was created", filepath.Base(path))
				}
			}
		})
	}
}
