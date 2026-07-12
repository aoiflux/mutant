package security

import (
	"os"
	"strconv"
	"strings"
)

const (
	RemoteProcessScanEnabledEnv   = "MUTANT_ENABLE_REMOTE_PROCESS_SCAN"
	RemoteProcessScanModeEnv      = "MUTANT_REMOTE_SCAN_MODE"
	RemoteProcessScanMaxEnv       = "MUTANT_REMOTE_SCAN_MAX_PROCESSES"
	RemoteProcessScanIntervalEnv  = "MUTANT_REMOTE_SCAN_INTERVAL_MS"
	RemoteProcessScanAllowlistEnv = "MUTANT_REMOTE_SCAN_ALLOWLIST"

	defaultRemoteScanMaxProcesses = 32
	defaultRemoteScanIntervalMs   = 1000
	defaultRemoteScanHighRisk     = 70
	defaultRemoteScanCritical     = 85
)

func ResolveRemoteScanConfig() RemoteScanConfig {
	cfg := RemoteScanConfig{
		Enabled:       isRemoteProcessScanEnabled(),
		Mode:          resolveRemoteProcessScanMode(),
		MaxProcesses:  parsePositiveInt(RemoteProcessScanMaxEnv, defaultRemoteScanMaxProcesses),
		IntervalMs:    parsePositiveInt(RemoteProcessScanIntervalEnv, defaultRemoteScanIntervalMs),
		Allowlist:     parseRemoteProcessAllowlist(),
		HighRiskScore: defaultRemoteScanHighRisk,
		CriticalScore: defaultRemoteScanCritical,
	}
	if cfg.CriticalScore < cfg.HighRiskScore {
		cfg.CriticalScore = cfg.HighRiskScore
	}
	return cfg
}

func isRemoteProcessScanEnabled() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(RemoteProcessScanEnabledEnv)))
	if raw == "" {
		return false
	}
	switch raw {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

func resolveRemoteProcessScanMode() string {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(RemoteProcessScanModeEnv)))
	switch raw {
	case RemoteScanModeObserve, RemoteScanModeEnforce, RemoteScanModeOff:
		return raw
	case "":
		return RemoteScanModeObserve
	default:
		return RemoteScanModeObserve
	}
}

func parsePositiveInt(env string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(env))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func parseRemoteProcessAllowlist() map[string]struct{} {
	allow := map[string]struct{}{}
	raw := strings.TrimSpace(os.Getenv(RemoteProcessScanAllowlistEnv))
	if raw == "" {
		return allow
	}
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(strings.ToLower(part))
		if name == "" {
			continue
		}
		allow[name] = struct{}{}
	}
	return allow
}
