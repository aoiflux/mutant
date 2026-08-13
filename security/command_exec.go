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
	ExitCode     int
	Stdout       string
	Stderr       string
	TimedOut     bool
	ErrorMessage string
}

func ExecuteCommand(shell, command, stage string) CommandResult {
	RecordCommandAttempt(stage)

	trimmedCommand := strings.TrimSpace(command)
	normalizedShell := normalizeShell(shell)
	execName, execArgs, err := buildShellCommand(normalizedShell, trimmedCommand)
	if err != nil {
		return CommandResult{
			ErrorMessage: err.Error(),
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
