package builtin

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"mutant/object"
)

// luaRun runs one chunk through lua_run_string and returns the result hash's
// ok, result and error fields, plus how long the call took.
//
// Every assertion in this file is about the call returning, so the helper
// never runs the builtin on a goroutine and waits with a select: a test that
// times out on a channel would pass on a tree where the cap works and hang on
// one where it does not, which is the wrong way round. `go test -timeout`
// catches a wedged call, and the elapsed time catches a slow one.
func luaRun(t *testing.T, source string) (ok bool, result, errText string, took time.Duration) {
	t.Helper()

	started := time.Now()
	got := LuaRunString(stringObj(source))
	took = time.Since(started)

	// lua_run_string returns a (value, err) pair, and the result hash is the
	// value half. The err half is for an argument mistake, not for a failing
	// script: a script that fails is reported inside the hash, as ok=false.
	multi, isPair := got.(*object.MultiValue)
	if !isPair || len(multi.Values) != 2 {
		t.Fatalf("lua_run_string returned %T, want a (value, err) pair", got)
	}
	if errObj, isErr := multi.Values[1].(*object.Error); isErr {
		t.Fatalf("lua_run_string errored on the call itself: %s", errObj.Inspect())
	}
	hash, isHash := multi.Values[0].(*object.Hash)
	if !isHash {
		t.Fatalf("lua_run_string's value is %T, want a hash", multi.Values[0])
	}

	for _, pair := range hash.Pairs {
		key, _ := pair.Key.(*object.String)
		if key == nil {
			continue
		}
		switch key.Value {
		case "ok":
			boolean, _ := pair.Value.(*object.Boolean)
			if boolean != nil {
				ok = boolean.Value
			}
		case "result":
			if str, isStr := pair.Value.(*object.String); isStr {
				result = str.Value
			}
		case "error":
			if str, isStr := pair.Value.(*object.String); isStr {
				errText = str.Value
			}
		}
	}
	return ok, result, errText, took
}

// TestLuaRunStringCapStopsPatternBacktracking is M26-TOOL-010.
//
// The sandbox's 5-second cap was a `context` handed to `state.SetContext`, and
// gopher-lua consults that only between VM instructions. A Lua pattern search
// runs entirely inside one Go function call and reaches no instruction
// boundary, so the cap did not apply to the one thing a hostile script would
// obviously do. `string.find(string.rep("a", 400), ".-.-.-b")` ran for 43
// seconds on the machine this was reported from and noticed its deadline only
// once the search had finished; at 1600 it did not return within a minute.
//
// 400 is deliberate. It is the smallest size from the report that is
// unambiguously past the cap -- 200 completes inside it -- and the abandoned
// search still ends on its own in well under a minute, which matters because
// the goroutine it is left running on outlives this test.
func TestLuaRunStringCapStopsPatternBacktracking(t *testing.T) {
	const subject = 400
	source := fmt.Sprintf(`local s = string.rep("a", %d) return tostring(string.find(s, ".-.-.-b"))`, subject)

	ok, _, errText, took := luaRun(t, source)

	if took > luaScriptTimeout+2*time.Second {
		t.Errorf("lua_run_string took %s, over its %s cap", took.Round(time.Millisecond), luaScriptTimeout)
	}
	if ok {
		t.Errorf("a script stopped by the cap reported ok=true after %s", took.Round(time.Millisecond))
	}
	if !strings.Contains(errText, luaScriptTimeout.String()) {
		t.Errorf("the error does not name the cap: %q", errText)
	}
	t.Logf("returned after %s: %s", took.Round(time.Millisecond), errText)
}

// TestLuaRunStringStillStopsAPureLuaInfiniteLoop is the shape the context
// always did stop, kept as a guard: `while true do end` reaches an instruction
// boundary on every iteration. If this starts failing, the fix has replaced
// one mechanism with the other instead of adding to it.
func TestLuaRunStringStillStopsAPureLuaInfiniteLoop(t *testing.T) {
	ok, _, errText, took := luaRun(t, "while true do end")

	if took > luaScriptTimeout+2*time.Second {
		t.Errorf("lua_run_string took %s, over its %s cap", took.Round(time.Millisecond), luaScriptTimeout)
	}
	if ok {
		t.Error("an infinite loop reported ok=true")
	}
	if errText == "" {
		t.Error("an infinite loop was stopped without saying why")
	}
}

// TestLuaRepRefusesMoreThanTheSandboxAllows covers the second half of the fix.
//
// string.rep is the one call that turns a few characters of script into an
// arbitrarily large string, and a large string is what makes a backtracking
// pattern expensive. It refuses rather than truncating: a script that asked
// for eight million bytes and silently got eight thousand goes on to measure,
// hash or compare the wrong thing.
func TestLuaRepRefusesMoreThanTheSandboxAllows(t *testing.T) {
	ok, _, errText, took := luaRun(t, `return #string.rep("ab", 1000000000)`)

	if took > luaScriptTimeout {
		t.Errorf("a refusal took %s; it should not have allocated anything", took.Round(time.Millisecond))
	}
	if ok {
		t.Error("string.rep built a string over the sandbox limit")
	}
	if !strings.Contains(errText, "string.rep") {
		t.Errorf("the error does not name string.rep: %q", errText)
	}
}

// TestLuaRepStillBuildsWhatTheSandboxAllows is the control for the limit, at
// both ends: a repeat well inside it works, and Lua 5.1's zero and negative
// counts are the empty string rather than an error.
func TestLuaRepStillBuildsWhatTheSandboxAllows(t *testing.T) {
	for _, tt := range []struct {
		source string
		want   string
	}{
		{`return string.rep("ab", 3)`, "ababab"},
		{`return #string.rep("a", 1048576)`, "1.048576e+06"},
		{`return "[" .. string.rep("a", 0) .. "]"`, "[]"},
		{`return "[" .. string.rep("a", -5) .. "]"`, "[]"},
		{`return "[" .. string.rep("", 1000000000) .. "]"`, "[]"},
	} {
		ok, result, errText, _ := luaRun(t, tt.source)
		if !ok {
			t.Errorf("%s: ok=false, error=%q", tt.source, errText)
			continue
		}
		if result != tt.want {
			t.Errorf("%s = %q, want %q", tt.source, result, tt.want)
		}
	}
}

// TestLuaRunStringStillRunsAnOrdinaryScript is the broad control: moving the
// call onto a goroutine must not change what a chunk returns, what it prints,
// or how an error inside it is reported.
func TestLuaRunStringStillRunsAnOrdinaryScript(t *testing.T) {
	for _, tt := range []struct {
		name   string
		source string
		wantOK bool
		want   string
	}{
		{"a returned value", `return 1 + 1`, true, "2"},
		{"a returned string", `return string.upper("abc")`, true, "ABC"},
		{"a pattern that matches", `return tostring(string.find("hello world", "o w"))`, true, "5"},
		{"printed output", `print("one") print("two")`, true, "one\ntwo"},
		{"no value and no output", `local x = 1`, true, "nil"},
		{"an error raised by the script", `error("deliberate")`, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ok, result, errText, took := luaRun(t, tt.source)
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t (error %q)", ok, tt.wantOK, errText)
			}
			if tt.wantOK && result != tt.want {
				t.Errorf("result = %q, want %q", result, tt.want)
			}
			if !tt.wantOK && errText == "" {
				t.Error("a failing script reported no error")
			}
			if took > luaScriptTimeout {
				t.Errorf("an ordinary script took %s", took.Round(time.Millisecond))
			}
		})
	}
}
