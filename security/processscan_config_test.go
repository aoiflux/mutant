package security

import "testing"

func TestResolveRemoteScanConfigDefaults(t *testing.T) {
	ResetRemoteScanConfigForTesting()
	cfg := ResolveRemoteScanConfig()
	if cfg.Enabled {
		t.Fatalf("expected remote scan disabled by default")
	}
	if cfg.Mode != RemoteScanModeObserve {
		t.Fatalf("expected default mode observe, got %q", cfg.Mode)
	}
	if cfg.MaxProcesses != defaultRemoteScanMaxProcesses {
		t.Fatalf("unexpected max processes default: got=%d", cfg.MaxProcesses)
	}
	if cfg.IntervalMs != defaultRemoteScanIntervalMs {
		t.Fatalf("unexpected interval default: got=%d", cfg.IntervalMs)
	}
	if len(cfg.Allowlist) != 0 {
		t.Fatalf("expected empty allowlist by default")
	}
}

func TestResolveRemoteScanConfigInvalidValuesFallback(t *testing.T) {
	ResetRemoteScanConfigForTesting()
	SetRemoteScanConfigForTesting(RemoteScanConfig{
		Enabled:      true,
		Mode:         "invalid-mode",
		MaxProcesses: -1,
		IntervalMs:   0,
		Allowlist: map[string]struct{}{
			"mutant.exe":  {},
			"mlsp":        {},
			"procmon.exe": {},
		},
	})
	defer ResetRemoteScanConfigForTesting()

	cfg := ResolveRemoteScanConfig()
	if !cfg.Enabled {
		t.Fatalf("expected remote scan enabled")
	}
	if cfg.Mode != RemoteScanModeObserve {
		t.Fatalf("expected invalid mode to fallback to observe, got %q", cfg.Mode)
	}
	if cfg.MaxProcesses != defaultRemoteScanMaxProcesses {
		t.Fatalf("expected max fallback, got %d", cfg.MaxProcesses)
	}
	if cfg.IntervalMs != defaultRemoteScanIntervalMs {
		t.Fatalf("expected interval fallback, got %d", cfg.IntervalMs)
	}
	if len(cfg.Allowlist) != 3 {
		t.Fatalf("expected 3 allowlist entries, got %d", len(cfg.Allowlist))
	}
	if _, ok := cfg.Allowlist["mutant.exe"]; !ok {
		t.Fatalf("expected mutant.exe in allowlist")
	}
}
