package builtin

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"mutant/object"
)

func TestSyslogParse(t *testing.T) {
	content := "" +
		`<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su 1234 ID47 [exampleSDID@32473 iut="3"] 'su root' failed for lonvick` + "\n" +
		`<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed` + "\n" +
		`Oct 11 22:14:15 host01 sshd[567]: Failed password for root` + "\n" +
		`<13>1 2023-06-15T10:00:00Z web01 nginx 4321 - - request served` + "\n" +
		`this is just a raw line` + "\n"

	path := filepath.Join(t.TempDir(), "messages")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	payload, errObj := unwrapPair(t, SyslogParse(stringObj(path)))
	if errObj != nil {
		t.Fatalf("syslog_parse error: %s", errObj.Inspect())
	}
	h := payload.(*object.Hash)
	if got := hInt(t, h, "count"); got != 5 {
		t.Fatalf("count = %d, want 5", got)
	}
	entries := hashValueByKey(h, "entries").(*object.Array)
	e := func(i int) *object.Hash { return entries.Elements[i].(*object.Hash) }

	// [0] RFC 5424 with structured data + pid.
	want5424, _ := time.Parse(time.RFC3339Nano, "2003-10-11T22:14:15.003Z")
	e0 := e(0)
	if hStr(t, e0, "format") != "rfc5424" {
		t.Errorf("e0 format = %q", hStr(t, e0, "format"))
	}
	if hInt(t, e0, "priority") != 34 || hInt(t, e0, "facility") != 4 || hInt(t, e0, "severity") != 2 {
		t.Errorf("e0 pri/fac/sev = %d/%d/%d", hInt(t, e0, "priority"), hInt(t, e0, "facility"), hInt(t, e0, "severity"))
	}
	if hInt(t, e0, "ts") != want5424.Unix() {
		t.Errorf("e0 ts = %d, want %d", hInt(t, e0, "ts"), want5424.Unix())
	}
	if hStr(t, e0, "host") != "mymachine.example.com" || hStr(t, e0, "app_name") != "su" {
		t.Errorf("e0 host/app = %q/%q", hStr(t, e0, "host"), hStr(t, e0, "app_name"))
	}
	if hInt(t, e0, "pid") != 1234 || hStr(t, e0, "msgid") != "ID47" {
		t.Errorf("e0 pid/msgid = %d/%q", hInt(t, e0, "pid"), hStr(t, e0, "msgid"))
	}
	if hStr(t, e0, "structured_data") != `[exampleSDID@32473 iut="3"]` {
		t.Errorf("e0 structured_data = %q", hStr(t, e0, "structured_data"))
	}
	if hStr(t, e0, "message") != `'su root' failed for lonvick` {
		t.Errorf("e0 message = %q", hStr(t, e0, "message"))
	}

	// [1] RFC 3164 with PRI + pid — year is inferred.
	wantYear := time.Now().Year()
	want3164 := time.Date(wantYear, time.October, 11, 22, 14, 15, 0, time.UTC).Unix()
	e1 := e(1)
	if hStr(t, e1, "format") != "rfc3164" {
		t.Errorf("e1 format = %q", hStr(t, e1, "format"))
	}
	if hInt(t, e1, "priority") != 34 {
		t.Errorf("e1 priority = %d", hInt(t, e1, "priority"))
	}
	if hInt(t, e1, "ts") != want3164 {
		t.Errorf("e1 ts = %d, want %d", hInt(t, e1, "ts"), want3164)
	}
	if hStr(t, e1, "host") != "mymachine" || hStr(t, e1, "app_name") != "su" || hInt(t, e1, "pid") != 1234 {
		t.Errorf("e1 host/app/pid = %q/%q/%d", hStr(t, e1, "host"), hStr(t, e1, "app_name"), hInt(t, e1, "pid"))
	}
	if hStr(t, e1, "message") != `'su root' failed` {
		t.Errorf("e1 message = %q", hStr(t, e1, "message"))
	}

	// [2] RFC 3164 without PRI (common /var/log/syslog form).
	e2 := e(2)
	if hStr(t, e2, "format") != "rfc3164" {
		t.Errorf("e2 format = %q", hStr(t, e2, "format"))
	}
	if hStr(t, e2, "host") != "host01" || hStr(t, e2, "app_name") != "sshd" || hInt(t, e2, "pid") != 567 {
		t.Errorf("e2 host/app/pid = %q/%q/%d", hStr(t, e2, "host"), hStr(t, e2, "app_name"), hInt(t, e2, "pid"))
	}
	if hashValueByKey(e2, "priority") != nil {
		t.Error("e2 should have no priority (no PRI in line)")
	}

	// [3] RFC 5424 with nil ("-") structured data and msgid.
	e3 := e(3)
	if hStr(t, e3, "app_name") != "nginx" || hInt(t, e3, "pid") != 4321 {
		t.Errorf("e3 app/pid = %q/%d", hStr(t, e3, "app_name"), hInt(t, e3, "pid"))
	}
	if hStr(t, e3, "msgid") != "" || hStr(t, e3, "structured_data") != "" {
		t.Errorf("e3 msgid/sd should be empty, got %q/%q", hStr(t, e3, "msgid"), hStr(t, e3, "structured_data"))
	}
	if hStr(t, e3, "message") != "request served" {
		t.Errorf("e3 message = %q", hStr(t, e3, "message"))
	}

	// [4] Unparseable line → raw.
	e4 := e(4)
	if hStr(t, e4, "format") != "raw" || hStr(t, e4, "message") != "this is just a raw line" {
		t.Errorf("e4 = %q / %q", hStr(t, e4, "format"), hStr(t, e4, "message"))
	}
	if hInt(t, e4, "ts") != 0 {
		t.Errorf("e4 ts = %d, want 0", hInt(t, e4, "ts"))
	}
}

func TestSyslogParseArgErrors(t *testing.T) {
	if _, errObj := unwrapPair(t, SyslogParse()); errObj == nil {
		t.Error("expected arg-count error")
	}
	if _, errObj := unwrapPair(t, SyslogParse(intObj(5))); errObj == nil {
		t.Error("expected type error for non-string arg")
	}
	if _, errObj := unwrapPair(t, SyslogParse(stringObj(filepath.Join(t.TempDir(), "nope")))); errObj == nil {
		t.Error("expected error for missing file")
	}
}
