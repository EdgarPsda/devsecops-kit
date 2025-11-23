package scanners

import (
	"strings"
)

// normalizeSeverity converts severity strings to standard format
func normalizeSeverity(severity string) string {
	s := strings.ToUpper(severity)
	switch s {
	case "CRITICAL", "CRITICAL,HIGH", "FATAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW", "INFO":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

// LoadConfigFromFile loads security configuration from security-config.yml
// This will be used later when we implement the scan command
func LoadConfigFromFile(configPath string) (map[string]interface{}, error) {
	// TODO: Implement YAML config loading
	return make(map[string]interface{}), nil
}
