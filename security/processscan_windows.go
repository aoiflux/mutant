//go:build windows

package security

func ScanRemoteProcessesWindows(cfg RemoteScanConfig) ([]ProcessRiskVerdict, error) {
	_ = cfg
	return nil, nil
}
