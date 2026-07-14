package security

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	defaultCommandExecTimeout = 3000
	defaultCommandMaxOutput   = 8192

	policyBlockedEmpty    = "blocked_empty"
	policyBlockedDisabled = "blocked_disabled"
	policyBlockedShell    = "blocked_shell"
	policyAllowed         = "allowed"

	errorCommandEmpty     = "command is empty"
	errorCommandDisabled  = "command execution disabled"
	errorCommandTimedOut  = "command timed out"
	truncatedOutputSuffix = "\n...[truncated]"

	defaultShellName = "powershell"
	shellPowerShell  = "powershell"
	shellPwsh        = "pwsh"
	shellCmd         = "cmd"
	shellBatch       = "batch"

	powershellExecutable = "powershell.exe"
	cmdExecutable        = "cmd.exe"
	cmdFlagExec          = "/C"

	pwshFlagNoLogo         = "-NoLogo"
	pwshFlagNoProfile      = "-NoProfile"
	pwshFlagNonInteractive = "-NonInteractive"
	pwshFlagCommand        = "-Command"
)

type CommandResult struct {
	Allowed        bool
	PolicyDecision string
	ExitCode       int
	Stdout         string
	Stderr         string
	TimedOut       bool
	ErrorMessage   string
}

func ExecuteCommand(shell, command, stage string) CommandResult {
	RecordCommandAttempt(stage)

	trimmedCommand := strings.TrimSpace(command)
	if trimmedCommand == "" {
		RecordCommandBlocked(stage)
		return CommandResult{
			Allowed:        false,
			PolicyDecision: policyBlockedEmpty,
			ErrorMessage:   errorCommandEmpty,
		}
	}

	if true {
		RecordCommandBlocked(stage)
		return CommandResult{
			Allowed:        false,
			PolicyDecision: policyBlockedDisabled,
			ErrorMessage:   errorCommandDisabled,
		}
	}

	normalizedShell := normalizeShell(shell)
	execName, execArgs, err := buildShellCommand(normalizedShell, trimmedCommand)
	if err != nil {
		RecordCommandBlocked(stage)

		return CommandResult{
			Allowed:        false,
			PolicyDecision: policyBlockedShell,
			ErrorMessage:   err.Error(),
		}
	}

	timeout := resolveCommandExecTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, execName, execArgs...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	result := CommandResult{
		Allowed:        true,
		PolicyDecision: policyAllowed,

		ExitCode: 0,
		Stdout:   truncateOutput(stdout.String(), resolveCommandExecMaxOutput()),
		Stderr:   truncateOutput(stderr.String(), resolveCommandExecMaxOutput()),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ErrorMessage = errorCommandTimedOut
		result.ExitCode = -1
		RecordCommandFailed(stage)
		return result
	}

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.ErrorMessage = runErr.Error()
		RecordCommandFailed(stage)
		return result
	}

	RecordCommandSucceeded(stage)

	return result
}

func normalizeShell(shell string) string {
	normalized := strings.ToLower(strings.TrimSpace(shell))
	if normalized == "" {
		return defaultShellName
	}
	return normalized
}

func buildShellCommand(shell, command string) (string, []string, error) {
	switch shell {
	case shellPowerShell, shellPwsh:
		return powershellExecutable, []string{pwshFlagNoLogo, pwshFlagNoProfile, pwshFlagNonInteractive, pwshFlagCommand, command}, nil
	case shellCmd, shellBatch:
		return cmdExecutable, []string{cmdFlagExec, command}, nil
	default:
		return "", nil, fmt.Errorf("unsupported shell %q", shell)
	}
}

func resolveCommandExecTimeout() time.Duration {
	return time.Duration(defaultCommandExecTimeout) * time.Millisecond
}

func resolveCommandExecMaxOutput() int {
	return defaultCommandMaxOutput
}

func truncateOutput(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + truncatedOutputSuffix
}
