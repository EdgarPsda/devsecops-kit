package scanners

import scanreport "github.com/edgarpsda/devsecops-kit/internal/report"

// normalizeSeverity converts severity strings to standard format
func normalizeSeverity(severity string) string {
	return scanreport.NormalizeSeverity(severity)
}

// LoadConfigFromFile loads security configuration from security-config.yml
// This will be used later when we implement the scan command
func LoadConfigFromFile(configPath string) (map[string]interface{}, error) {
	// TODO: Implement YAML config loading
	return make(map[string]interface{}), nil
}
