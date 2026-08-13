package builtin

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mutant/object"
)

// rfc3164Re matches a BSD-syslog line (RFC 3164), with an optional <PRI> prefix
// (often already stripped in /var/log/syslog) and an optional [pid].
//   [<PRI>]Mmm dd hh:mm:ss host tag[pid]: message
var rfc3164Re = regexp.MustCompile(
	`^(?:<(\d{1,3})>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[\s]+)(?:\[(\d+)\])?:\s?(.*)$`)

// SyslogParse parses a Unix syslog file into structured entries. Each line is
// auto-detected as RFC 5424 (IETF, ISO-8601 timestamp) or RFC 3164 (BSD); a line
// matching neither is kept as a raw message. Every entry carries a `ts` unix
// field so the result composes with timeline_merge/timeline_sort. Pure-Go, no
// dependency. Returns {count, entries:[...]} paired with an error.
func SyslogParse(args ...object.Object) (result object.Object) {
	defer func() {
		if r := recover(); r != nil {
			result = resultAndError(nil, newError("syslog_parse: panic during parse: %v", r))
		}
	}()

	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	path, errObj := requireStringArg("syslog_parse", args[0], 1)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}
	f, err := os.Open(path)
	if err != nil {
		return resultAndError(nil, newError("syslog_parse: %s", err.Error()))
	}
	defer f.Close()

	// Assume the current year for RFC 3164 lines, which omit it.
	year := time.Now().Year()

	entries := make([]object.Object, 0)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tolerate long lines
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		entries = append(entries, makeHashObject(parseSyslogLine(line, year)))
	}
	if err := sc.Err(); err != nil {
		return resultAndError(nil, newError("syslog_parse: %s", err.Error()))
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"count":   intObj(int64(len(entries))),
		"entries": &object.Array{Elements: entries},
	}), nil)
}

func parseSyslogLine(line string, year int) map[string]object.Object {
	if m, ok := parseSyslog5424(line); ok {
		return m
	}
	if m, ok := parseSyslog3164(line, year); ok {
		return m
	}
	return map[string]object.Object{
		"format":  stringObj("raw"),
		"message": stringObj(line),
		"ts":      intObj(0),
	}
}

// parseSyslog5424 parses an RFC 5424 line:
//   <PRI>1 TIMESTAMP HOST APP-NAME PROCID MSGID [SD] MSG
func parseSyslog5424(line string) (map[string]object.Object, bool) {
	if !strings.HasPrefix(line, "<") {
		return nil, false
	}
	gt := strings.IndexByte(line, '>')
	if gt < 0 {
		return nil, false
	}
	pri, err := strconv.Atoi(line[1:gt])
	if err != nil || pri < 0 || pri > 191 {
		return nil, false
	}
	rest := line[gt+1:]
	if !strings.HasPrefix(rest, "1 ") { // VERSION must be 1
		return nil, false
	}
	parts := strings.SplitN(rest[2:], " ", 6)
	if len(parts) < 6 {
		return nil, false
	}
	timestamp, host, app, procid, msgid := parts[0], parts[1], parts[2], parts[3], parts[4]
	sd, msg := splitStructuredData(parts[5])

	ts := int64(0)
	if timestamp != "-" {
		if t, e := time.Parse(time.RFC3339, timestamp); e == nil {
			ts = t.Unix()
		} else if t, e := time.Parse(time.RFC3339Nano, timestamp); e == nil {
			ts = t.Unix()
		}
	}

	m := map[string]object.Object{
		"format":    stringObj("rfc5424"),
		"priority":  intObj(int64(pri)),
		"facility":  intObj(int64(pri / 8)),
		"severity":  intObj(int64(pri % 8)),
		"timestamp": stringObj(nilDash(timestamp)),
		"ts":        intObj(ts),
		"host":      stringObj(nilDash(host)),
		"app_name":  stringObj(nilDash(app)),
		"msgid":     stringObj(nilDash(msgid)),
		"structured_data": stringObj(nilDash(sd)),
		"message":   stringObj(msg),
		"pid":       intObj(0),
	}
	if p, e := strconv.Atoi(procid); e == nil {
		m["pid"] = intObj(int64(p))
	}
	return m, true
}

// parseSyslog3164 parses a BSD-syslog line (RFC 3164).
func parseSyslog3164(line string, year int) (map[string]object.Object, bool) {
	g := rfc3164Re.FindStringSubmatch(line)
	if g == nil {
		return nil, false
	}
	priStr, tsStr, host, tag, pidStr, msg := g[1], g[2], g[3], g[4], g[5], g[6]

	ts := int64(0)
	if t, e := time.Parse("Jan 2 15:04:05", normalizeMonthDay(tsStr)); e == nil {
		t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
		ts = t.Unix()
	}

	m := map[string]object.Object{
		"format":    stringObj("rfc3164"),
		"timestamp": stringObj(tsStr),
		"ts":        intObj(ts),
		"host":      stringObj(host),
		"app_name":  stringObj(tag),
		"message":   stringObj(msg),
		"pid":       intObj(0),
	}
	if priStr != "" {
		if pri, e := strconv.Atoi(priStr); e == nil {
			m["priority"] = intObj(int64(pri))
			m["facility"] = intObj(int64(pri / 8))
			m["severity"] = intObj(int64(pri % 8))
		}
	}
	if pidStr != "" {
		if p, e := strconv.Atoi(pidStr); e == nil {
			m["pid"] = intObj(int64(p))
		}
	}
	return m, true
}

// splitStructuredData separates the RFC 5424 STRUCTURED-DATA field ("-" or one or
// more bracketed elements) from the trailing message.
func splitStructuredData(s string) (sd, msg string) {
	if s == "-" {
		return "-", ""
	}
	if strings.HasPrefix(s, "- ") {
		return "-", s[2:]
	}
	if !strings.HasPrefix(s, "[") {
		return "-", s
	}
	i := 0
	for i < len(s) && s[i] == '[' {
		depth := 0
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				i += 2
				continue
			}
			if c == '[' {
				depth++
			} else if c == ']' {
				depth--
				if depth == 0 {
					i++
					break
				}
			}
			i++
		}
	}
	return s[:i], strings.TrimPrefix(s[i:], " ")
}

func nilDash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// normalizeMonthDay collapses the runs of spaces RFC 3164 uses to pad a
// single-digit day ("Oct  1") to the single space Go's reference layout expects.
func normalizeMonthDay(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
