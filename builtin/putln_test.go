package builtin

import (
	"io"
	"os"
	"testing"

	"mutant/object"
)

func TestPutlnCompactsDelimiterSpacing(t *testing.T) {
	output := captureStdout(t, func() {
		Putln(
			&object.String{Value: "  -"},
			&object.String{Value: "/bash"},
			&object.String{Value: "(dir="},
			&object.Boolean{Value: true},
			&object.String{Value: ", inode="},
			&object.Integer{Value: 13},
			&object.String{Value: ")"},
		)
	})

	want := "  - /bash (dir=true, inode=13)\n"
	if output != want {
		t.Fatalf("unexpected putln output. got=%q want=%q", output, want)
	}
}

func TestPutfRawConcatenation(t *testing.T) {
	output := captureStdout(t, func() {
		Putf(
			&object.String{Value: "inode="},
			&object.Integer{Value: 13},
			&object.String{Value: ",dir="},
			&object.Boolean{Value: true},
		)
	})

	want := "inode=13,dir=true"
	if output != want {
		t.Fatalf("unexpected putf output. got=%q want=%q", output, want)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	fn()

	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close stdout writer: %v", err)
	}

	out, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("failed to close stdout reader: %v", err)
	}

	return string(out)
}
