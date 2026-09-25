// Package graphstore holds what more than one of Mutant's graph families needs
// to know about a graphene store: its label table, how to open it without
// changing it, the budget a walk over it runs under, which hops of a path ran
// backwards, and which keys its index never held -- so that two families asking
// the same question of a store get the same answer.
//
// graphene keeps the names of a store's node and edge labels in a text file
// beside the image, graphene.labels, and registers them process-wide when the
// store is opened: one name per number for the life of the process, and a
// conflicting name is an error for whoever declares second. So what a
// directory's table says has to be read before the directory is opened, by the
// symbol graph's query side and by db_open_disk alike, and both read it here.
package graphstore

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// LabelTableName is the file graphene writes a store's label names to.
const LabelTableName = "graphene.labels"

// ErrNoLabelTable is what ReadLabelTable returns for a directory with no
// label table. It is an answer as well as an error: a store written by the
// db_* family names none of its labels, and a directory that holds no store
// has no table either.
var ErrNoLabelTable = errors.New("it has no graphene.labels, so nothing says what its numbers mean")

// ReadLabelTable parses a graphene.labels file into its node and edge names,
// keyed by label number.
//
// graphene's own parser is unexported, and reimplementing it is the point
// rather than a workaround: this one is stricter where the engine is lenient,
// because the engine is deciding what to register and this is deciding whether
// to believe a directory at all. A table truncated inside its last name parses
// as a shorter name there and is accepted; here a file whose last byte is not a
// newline is torn, because the writer always ends with one.
func ReadLabelTable(path string) (map[uint16]string, map[uint16]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, ErrNoLabelTable
		}
		return nil, nil, err
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("its graphene.labels is empty")
	}
	if raw[len(raw)-1] != '\n' {
		return nil, nil, errors.New("its graphene.labels does not end in a newline, so it is torn")
	}

	nodes := make(map[uint16]string)
	edges := make(map[uint16]string)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	if !scanner.Scan() {
		return nil, nil, errors.New("its graphene.labels is empty")
	}
	if header := scanner.Text(); header != "graphene-labels v1" {
		return nil, nil, fmt.Errorf("its graphene.labels begins %q, not %q",
			header, "graphene-labels v1")
	}

	for line := 2; scanner.Scan(); line++ {
		text := scanner.Text()
		if text == "" {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) != 3 {
			return nil, nil, fmt.Errorf("graphene.labels line %d: want three tab-separated fields, got %d",
				line, len(fields))
		}
		value, convErr := strconv.ParseUint(fields[1], 10, 16)
		if convErr != nil {
			return nil, nil, fmt.Errorf("graphene.labels line %d: %q is not a label number", line, fields[1])
		}
		// Last-wins is what the engine does with a repeated number, silently. A
		// table that names one number twice has drifted from whatever wrote it,
		// and that is enough to stop trusting the rest of it.
		switch fields[0] {
		case "node":
			if _, twice := nodes[uint16(value)]; twice {
				return nil, nil, fmt.Errorf("graphene.labels names node label %d twice", value)
			}
			nodes[uint16(value)] = fields[2]
		case "edge":
			if _, twice := edges[uint16(value)]; twice {
				return nil, nil, fmt.Errorf("graphene.labels names edge label %d twice", value)
			}
			edges[uint16(value)] = fields[2]
		default:
			return nil, nil, fmt.Errorf("graphene.labels line %d: unknown kind %q", line, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return nodes, edges, nil
}
