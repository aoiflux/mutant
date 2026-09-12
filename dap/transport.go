// Package dap is the Debug Adapter Protocol front end for `mutant debug`.
//
// It is a translation layer and nothing more: every decision about what the
// program does lives in vm.Debugger, and this package turns protocol messages
// into calls on it. That split is deliberate -- a protocol bug and an engine
// bug are then never the same bug, and a second front end (nvim-dap, a test
// harness) costs nothing.
//
// The protocol is implemented here rather than pulled in, because the message
// set a source-level debugger needs is small and stable, and the alternative is
// a dependency carrying the whole specification into a tool whose users care
// about what it links.
package dap

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
)

// maxMessageBytes caps one incoming message. The header is attacker-controlled
// in the sense that anything may be on the other end of a pipe, and a
// Content-Length of four gigabytes should be refused rather than allocated.
const maxMessageBytes = 16 << 20

// conn is the framed message channel. DAP frames every message the way HTTP
// does a body: a Content-Length header, a blank line, then that many bytes of
// JSON.
type conn struct {
	reader *bufio.Reader

	// writeMu serialises writes, because two goroutines produce them: the
	// request loop answering the client, and the event pump publishing stops.
	// A frame interleaved with another is not recoverable by the far end.
	writeMu sync.Mutex
	writer  io.Writer
	seq     int
}

func newConn(in io.Reader, out io.Writer) *conn {
	return &conn{reader: bufio.NewReader(in), writer: out}
}

// read returns the next request.
//
// A message that is not a request is skipped rather than refused: DAP allows a
// client to send events and reverse-request responses, and an adapter that fell
// over on one would be brittle for no gain.
func (c *conn) read() (*request, error) {
	for {
		payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}

		var msg request
		if err := json.Unmarshal(payload, &msg); err != nil {
			return nil, fmt.Errorf("malformed message: %w", err)
		}
		if msg.Type != "request" {
			continue
		}
		return &msg, nil
	}
}

func (c *conn) readFrame() ([]byte, error) {
	length := -1

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}

		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("header line has no colon: %q", line)
		}
		if !strings.EqualFold(strings.TrimSpace(name), "content-length") {
			// Content-Type is the only other header the protocol defines and
			// its single legal value adds nothing, so anything else is ignored
			// rather than refused.
			continue
		}

		length, err = strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("unreadable content length %q: %w", value, err)
		}
	}

	switch {
	case length < 0:
		return nil, fmt.Errorf("message has no Content-Length header")
	case length > maxMessageBytes:
		return nil, fmt.Errorf("message of %d bytes is larger than this adapter accepts", length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// send frames and writes one message, stamping it with the next sequence
// number. The stamp happens under the same lock as the write so the numbers
// arrive in order.
func (c *conn) send(msg any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.seq++
	switch typed := msg.(type) {
	case *response:
		typed.Seq = c.seq
	case *event:
		typed.Seq = c.seq
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintf(c.writer, "Content-Length: %d\r\n\r\n", len(payload)); err != nil {
		return err
	}
	if _, err := c.writer.Write(payload); err != nil {
		return err
	}

	if flusher, ok := c.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}
