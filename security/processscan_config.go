package security

import (
	"strings"
)

const (
	defaultRemoteScanMaxProcesses = 32
	defaultRemoteScanIntervalMs   = 1000
	defaultRemoteScanHighRisk     = 70
	defaultRemoteScanCritical     = 85
)

func ResolveRemoteScanConfig() RemoteScanConfig {
	cfg := RemoteScanConfig{
		Enabled:       isRemoteProcessScanEnabled(),
		Mode:          resolveRemoteProcessScanMode(),
		MaxProcesses:  defaultRemoteScanMaxProcesses,
		IntervalMs:    defaultRemoteScanIntervalMs,
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
	return false
}

func resolveRemoteProcessScanMode() string {
	return RemoteScanModeObserve
}

func parseRemoteProcessAllowlist() map[string]struct{} {
	allow := map[string]struct{}{}
	raw := ""
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
