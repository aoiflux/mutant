package security

const (
	RemoteScanModeOff     = "off"
	RemoteScanModeObserve = "observe"
	RemoteScanModeEnforce = "enforce"
)

type RemoteProcessTarget struct {
	PID        uint32
	Name       string
	Executable string
}

type RemoteProcessSignal struct {
	Name       string
	Detected   bool
	Weight     int
	Confidence int
	Detail     string
	Evidence   map[string]string
}

type ProcessRiskVerdict struct {
	PID        uint32
	Name       string
	FinalScore int
	RiskBand   string
	Signals    []RemoteProcessSignal
}

type RemoteScanConfig struct {
	Enabled       bool
	Mode          string
	MaxProcesses  int
	IntervalMs    int
	Allowlist     map[string]struct{}
	HighRiskScore int
	CriticalScore int
}
