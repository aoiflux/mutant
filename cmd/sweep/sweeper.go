package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"mutant/global"
	"mutant/sweep"
)

type status int

const (
	statusOK status = iota
	statusFail
)

type result struct {
	file   string
	mode   sweep.Mode
	status status
	note   string
	detail string
	// verified is set when the output matched the example's .golden file --
	// the only runs whose output, and not just their exit status, was checked.
	verified bool
}

func (r result) String() string {
	label := "ok  "
	if r.status == statusFail {
		label = "FAIL"
	}

	line := strings.TrimRight(fmt.Sprintf("%s  %-56s %s", label, r.file, r.note), " ")
	if r.detail == "" {
		return line
	}
	return line + "\n" + indent(r.detail)
}

func indent(text string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		lines[i] = "        " + line
	}
	return strings.Join(lines, "\n")
}

type sweeper struct {
	opts    options
	binary  string
	scratch *scratch

	// run stands in for runAt when set, so the decisions runAcrossLevels makes
	// about outputs can be tested without compiling anything.
	run func(file string, marker sweep.Marker, level int) (string, *result)
}

func (s *sweeper) sweepOne(file string) result {
	source, err := os.ReadFile(file)
	if err != nil {
		return result{file: file, status: statusFail, note: "unreadable", detail: err.Error()}
	}

	marker, err := sweep.ParseMarker(string(source))
	if err != nil {
		return result{file: file, status: statusFail, note: "bad marker", detail: err.Error()}
	}
	if err := sweep.Check(string(source)); err != nil {
		return result{file: file, mode: marker.Mode, status: statusFail, note: "marker", detail: err.Error()}
	}

	switch marker.Mode {
	case sweep.ModeServeHandler:
		return s.compileOnly(file, marker)
	case sweep.ModeNeedsInput:
		res := s.compileOnly(file, marker)
		if res.status == statusOK {
			res.note = "needs input    " + marker.Reason
		}
		return res
	case sweep.ModeServer:
		return s.startAndStop(file, marker)
	default:
		return s.runAcrossLevels(file, marker)
	}
}

// compileOnly is the whole check for a handler: it is dispatched by net_serve
// and has no connection of its own, so compiling is as far as a sweep can take
// it. That it compiles is still worth knowing -- a handler that stops building
// takes its server down with it, and nothing else would catch that.
func (s *sweeper) compileOnly(file string, marker sweep.Marker) result {
	if err := s.reset(file, marker); err != nil {
		return *err
	}

	if _, err := s.compile(file, s.opts.levels[0]); err != nil {
		return result{file: file, mode: marker.Mode, status: statusFail, note: "compile-only", detail: err.Error()}
	}
	return result{file: file, mode: marker.Mode, note: "compile-only   " + marker.Reason}
}

// startAndStop is how a server passes: it has to still be running after --alive.
// Exiting early is the failure, which inverts the usual check -- and is exactly
// the distinction a plain sweep cannot draw, since to that sweep a server doing
// its job and a program wedged in a loop look identical.
func (s *sweeper) startAndStop(file string, marker sweep.Marker) result {
	if err := s.reset(file, marker); err != nil {
		return *err
	}

	compiled, err := s.compile(file, s.opts.levels[0])
	if err != nil {
		return result{file: file, mode: marker.Mode, status: statusFail, note: "server", detail: err.Error()}
	}

	command := exec.Command(s.binary, compiled, "--dev", "--password-insecure", s.opts.password)
	command.Dir = s.scratch.root
	output := &bytes.Buffer{}
	command.Stdout, command.Stderr = output, output

	if err := command.Start(); err != nil {
		return result{file: file, mode: marker.Mode, status: statusFail, note: "server", detail: err.Error()}
	}

	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()

	select {
	case waitErr := <-exited:
		return result{
			file: file, mode: marker.Mode, status: statusFail,
			note:   fmt.Sprintf("server exited within %s", s.opts.alive),
			detail: describeExit(waitErr) + "\n" + trim(output.String()),
		}
	case <-time.After(s.opts.alive):
		_ = command.Process.Kill()
		<-exited
		return result{
			file: file, mode: marker.Mode,
			note: fmt.Sprintf("server, alive %s   %s", s.opts.alive, marker.Reason),
		}
	}
}

// runAcrossLevels is the ordinary case. With one level it is compile-and-run;
// with several it also asserts the levels agree, which is what turns the sweep
// into a check on the polymorphic engine rather than only on the examples.
//
// Whether an example can be compared across levels is measured, not declared. A
// good many of them print a timestamp, walk a live filesystem or reach the
// network, so their output differs between two runs of identical bytecode. The
// probe is to run the first level twice: an example that cannot reproduce itself
// cannot say anything about mutation, and demanding a marker for that would put
// the burden on every author to know which builtins are pure.
func (s *sweeper) runAcrossLevels(file string, marker sweep.Marker) result {
	first := s.opts.levels[0]

	baseline, failure := s.runLevel(file, marker, first)
	if failure != nil {
		return *failure
	}
	// A golden file is only meaningful for output that reproduces, so the
	// golden options need the same probe as a comparison across levels.
	checkingGolden := s.opts.golden || s.opts.updateGolden
	if len(s.opts.levels) == 1 && !checkingGolden {
		return s.ranWell(file, marker, "run", baseline)
	}

	repeat, failure := s.runLevel(file, marker, first)
	if failure != nil {
		return *failure
	}
	reproducible := repeat == baseline

	for _, level := range s.opts.levels[1:] {
		output, failure := s.runLevel(file, marker, level)
		if failure != nil {
			return *failure
		}
		if !reproducible || output == baseline {
			continue
		}
		defect, failure := s.confirmDifference(file, marker, first, level, baseline, output)
		if failure != nil {
			return *failure
		}
		if defect {
			return result{
				file: file, mode: marker.Mode, status: statusFail,
				note:   fmt.Sprintf("mutation %d differs from mutation %d", level, first),
				detail: firstDifference(baseline, output),
			}
		}
		reproducible = false
	}

	note := fmt.Sprintf("run, identical across %d levels", len(s.opts.levels))
	switch {
	case len(s.opts.levels) == 1 && reproducible:
		note = "run, reproducible"
	case len(s.opts.levels) == 1:
		note = "run, output varies between runs"
	case !reproducible:
		note = fmt.Sprintf("run, %d levels, output varies between runs so it was not compared",
			len(s.opts.levels))
	}
	if !checkingGolden {
		return s.ranWell(file, marker, note, baseline)
	}

	verdict, verified, failure := s.checkGolden(file, marker, baseline, reproducible)
	if failure != nil {
		return *failure
	}
	res := s.ranWell(file, marker, note+"; "+verdict, baseline)
	res.verified = verified
	return res
}

// confirmDifference takes a second look before calling two levels' outputs a
// mutation defect. The probe that found the output reproducible ran the first
// level twice back to back, and output carrying a clock reading or a timing
// measurement can agree with itself for that long and still differ by the time
// the next level runs: a timestamp crossing a second boundary, a microsecond
// timer. That was reported as the polymorphic engine changing what a program
// prints, on a different example each run. Running both levels again separates
// the cases. A defect is deterministic -- each level prints what it printed
// before, and the two still disagree -- where output that varies does not print
// the same thing twice.
func (s *sweeper) confirmDifference(file string, marker sweep.Marker, first, level int, baseline, output string) (bool, *result) {
	baselineAgain, failure := s.runLevel(file, marker, first)
	if failure != nil {
		return false, failure
	}
	if baselineAgain != baseline {
		return false, nil
	}
	outputAgain, failure := s.runLevel(file, marker, level)
	if failure != nil {
		return false, failure
	}
	return outputAgain == output, nil
}

// checkGolden compares one example's normalized output with the .golden file
// beside it, or rewrites that file under --update-golden. Output that varies
// between two runs of the same bytecode has no golden: recording one would
// write down a single sample of something that is not a single value.
func (s *sweeper) checkGolden(file string, marker sweep.Marker, output string, reproducible bool) (string, bool, *result) {
	path := sweep.GoldenPath(file)
	got := sweep.NormalizeOutput(output, s.scratch.root)
	recorded, err := os.ReadFile(path)
	has := err == nil
	want := ""
	if has {
		want = sweep.NormalizeOutput(string(recorded), "")
	}

	if s.opts.updateGolden {
		switch {
		case !reproducible && has:
			if err := os.Remove(path); err != nil {
				return "", false, &result{file: file, mode: marker.Mode, status: statusFail, note: "golden", detail: err.Error()}
			}
			return "golden removed: output varies", false, nil
		case !reproducible:
			return "no golden: output varies", false, nil
		case has && strings.ReplaceAll(string(recorded), "\r\n", "\n") == got:
			// Compared as stored, not as normalized, so a golden recorded
			// before a normalization existed is rewritten in the form that
			// normalization produces. CRLF is ignored: a Windows checkout
			// adds it and git removes it again.
			return "golden unchanged", true, nil
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			return "", false, &result{file: file, mode: marker.Mode, status: statusFail, note: "golden", detail: err.Error()}
		}
		return "golden written", true, nil
	}

	switch {
	case !has && reproducible:
		return "no golden", false, nil
	case !has:
		return "no golden: output varies", false, nil
	case !reproducible:
		return "", false, &result{
			file: file, mode: marker.Mode, status: statusFail,
			note:   "has a golden file but its output varies between runs",
			detail: "delete " + filepath.ToSlash(path) + " or make the example's output deterministic",
		}
	case want != got:
		return "", false, &result{
			file: file, mode: marker.Mode, status: statusFail,
			note:   "output differs from " + filepath.ToSlash(path),
			detail: firstDifference(want, got),
		}
	}
	return "matches golden", true, nil
}

func (s *sweeper) ranWell(file string, marker sweep.Marker, note, output string) result {
	if s.opts.verbose {
		return result{file: file, mode: marker.Mode, note: note, detail: trim(output)}
	}
	return result{file: file, mode: marker.Mode, note: note}
}

func (s *sweeper) runLevel(file string, marker sweep.Marker, level int) (string, *result) {
	if s.run != nil {
		return s.run(file, marker, level)
	}
	return s.runAt(file, marker, level)
}

// runAt compiles and runs one example at one mutation level from a clean tree.
// It reports a failure result rather than an error so every way a run can go
// wrong is presented to the reader in the same shape.
func (s *sweeper) runAt(file string, marker sweep.Marker, level int) (string, *result) {
	if failure := s.reset(file, marker); failure != nil {
		return "", failure
	}

	compiled, err := s.compile(file, level)
	if err != nil {
		return "", &result{
			file: file, mode: marker.Mode, status: statusFail,
			note: fmt.Sprintf("compile at mutation %d", level), detail: err.Error(),
		}
	}

	stdout, err := s.execute(compiled)
	if err != nil {
		return "", &result{
			file: file, mode: marker.Mode, status: statusFail,
			note: fmt.Sprintf("run at mutation %d", level), detail: err.Error(),
		}
	}
	return stdout, nil
}

// reset returns a failure result rather than an error so that a scratch problem
// is reported against the example it interrupted, in the same shape as any other
// failure, instead of aborting the whole sweep.
func (s *sweeper) reset(file string, marker sweep.Marker) *result {
	if err := s.scratch.reset(); err != nil {
		return &result{file: file, mode: marker.Mode, status: statusFail, note: "scratch", detail: err.Error()}
	}
	return nil
}

func (s *sweeper) compile(file string, level int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.timeout)
	defer cancel()

	command := exec.CommandContext(ctx, s.binary, "gen",
		"--src", file,
		"--password-insecure", s.opts.password,
		"--mutation", strconv.Itoa(level),
		"--seed", strconv.FormatInt(s.opts.seed, 10),
	)
	command.Dir = s.scratch.root

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s\n%s", describeExit(err), trim(string(output)))
	}

	compiled := strings.TrimSuffix(file, global.MutantSourceCodeFileExtention) +
		global.MutantByteCodeCompiledFileExtension
	if _, err := os.Stat(filepath.Join(s.scratch.root, compiled)); err != nil {
		return "", fmt.Errorf("gen reported success but produced no %s\n%s", compiled, trim(string(output)))
	}
	return compiled, nil
}

func (s *sweeper) execute(compiled string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.timeout)
	defer cancel()

	command := exec.CommandContext(ctx, s.binary, compiled, "--dev", "--password-insecure", s.opts.password)
	command.Dir = s.scratch.root
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	command.Stdout, command.Stderr = stdout, stderr

	err := command.Run()
	if ctx.Err() != nil {
		return "", fmt.Errorf("still running after %s; if it is meant to be, mark it %s\n%s",
			s.opts.timeout, sweep.ModeServer, trim(stdout.String()))
	}
	if err != nil {
		return "", fmt.Errorf("%s\n%s", describeExit(err), trim(stdout.String()+stderr.String()))
	}
	return stdout.String(), nil
}

func describeExit(err error) string {
	if err == nil {
		return "exited 0"
	}

	exitErr := &exec.ExitError{}
	if errors.As(err, &exitErr) {
		return fmt.Sprintf("exited %d", exitErr.ExitCode())
	}
	return err.Error()
}

// trim keeps failure output readable: the whole of a long program's output is
// rarely what tells you what went wrong, and the last few lines usually are.
func trim(text string) string {
	lines := strings.Split(strings.TrimRight(text, "\r\n"), "\n")
	if len(lines) > 12 {
		elided := fmt.Sprintf("... %d earlier lines", len(lines)-12)
		lines = append([]string{elided}, lines[len(lines)-12:]...)
	}
	return strings.Join(lines, "\n")
}

func firstDifference(baseline, other string) string {
	base, next := strings.Split(baseline, "\n"), strings.Split(other, "\n")

	for i := 0; i < len(base) || i < len(next); i++ {
		left, right := lineAt(base, i), lineAt(next, i)
		if left != right {
			return fmt.Sprintf("line %d\n  first level: %q\n  this level:  %q", i+1, left, right)
		}
	}
	return "outputs differ only in trailing whitespace"
}

func lineAt(lines []string, index int) string {
	if index < len(lines) {
		return lines[index]
	}
	return ""
}

func report(results []result) int {
	byMode := map[string]int{}
	failed, verified := 0, 0

	for _, res := range results {
		if res.status == statusFail {
			failed++
			continue
		}
		byMode[string(res.mode)]++
		if res.verified {
			verified++
		}
	}
	if verified > 0 {
		fmt.Printf("\n%d of %d examples printed exactly what their .golden file records\n", verified, len(results))
	}

	modes := make([]string, 0, len(byMode))
	for mode := range byMode {
		modes = append(modes, mode)
	}
	sort.Strings(modes)

	parts := make([]string, 0, len(modes)+1)
	for _, mode := range modes {
		parts = append(parts, fmt.Sprintf("%d %s", byMode[mode], mode))
	}
	parts = append(parts, fmt.Sprintf("%d failed", failed))

	fmt.Printf("\n%s\n", strings.Join(parts, "  |  "))
	if failed > 0 {
		return 1
	}
	return 0
}
