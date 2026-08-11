package builtin

import (
	"bufio"
	"io"
	"os"
	"strings"

	"mutant/object"
)

// stdinReader buffers os.Stdin across calls so multiple gets() invocations don't
// drop data between reads.
var stdinReader = bufio.NewReader(os.Stdin)

// Gets reads a full line of input from stdin and returns it as a STRING (without
// the trailing newline). Use to_int/to_float/parse_int/parse_float to convert.
func Gets(args ...object.Object) object.Object {
	if len(args) != 0 {
		return newError("wrong number of arguments. got=%d, want=0", len(args))
	}
	line, err := readStdinLine(stdinReader)
	if err != nil {
		return newError("gets: %s", err.Error())
	}
	return stringObj(line)
}

// readStdinLine reads through the next newline and returns the line without its
// trailing CR/LF. A final line that has data but no newline (EOF) is still
// returned; EOF with no data is reported as an error.
func readStdinLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if err == io.EOF && line != "" {
			return strings.TrimRight(line, "\r\n"), nil
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
