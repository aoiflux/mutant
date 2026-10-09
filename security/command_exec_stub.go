//go:build !windows && !unix

package security

import "os/exec"

// commandProcessTree is nothing on a system that has neither a Windows job
// object nor a Unix process group.
//
// js/wasm is the one such system Mutant builds for: scripts/build.sh and
// scripts/release_gate.sh both build ./cmd/replwasm, which reaches this
// package. os/exec cannot start a process there at all, so there is no tree to
// bound and no group to put it in.
//
// The file exists so that the three platform shapes are a closed set rather
// than a default. cmd.WaitDelay is set in command_exec.go whatever the
// platform, so the one guarantee that does not depend on an OS feature -- that
// the call is bounded -- holds here too.
type commandProcessTree struct{}

func newProcessTree(cmd *exec.Cmd) (*commandProcessTree, error) {
	_ = cmd
	return &commandProcessTree{}, nil
}

func (t *commandProcessTree) adopt(cmd *exec.Cmd) {
	_ = cmd
}

func (t *commandProcessTree) release() {}

func setRawCommandLine(cmd *exec.Cmd, rawCommandLine string) {
	_, _ = cmd, rawCommandLine
}
