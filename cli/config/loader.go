package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SecurityConfig represents the security-config.yml structure
type SecurityConfig struct {
	Version           string            `yaml:"version"`
	Language          string            `yaml:"language"`
	Framework         string            `yaml:"framework"`
	SeverityThreshold string            `yaml:"severity_threshold"`
	Tools             ToolsConfig       `yaml:"tools"`
	ExcludePaths      []string          `yaml:"exclude_paths"`
	FailOn            map[string]int    `yaml:"fail_on"`
	Licenses          LicensesConfig    `yaml:"licenses"`
	Notifications     NotificationsConfig `yaml:"notifications"`
}

// ToolsConfig represents the tools section
type ToolsConfig struct {
	Semgrep  bool `yaml:"semgrep"`
	Trivy    bool `yaml:"trivy"`
	Gitleaks bool `yaml:"gitleaks"`
}

// LicensesConfig represents the licenses section
type LicensesConfig struct {
	Enabled bool     `yaml:"enabled"`
	Deny    []string `yaml:"deny"`
	Allow   []string `yaml:"allow"`
}

// NotificationsConfig represents the notifications section
type NotificationsConfig struct {
	PRComment bool `yaml:"pr_comment"`
	Slack     bool `yaml:"slack"`
	Email     bool `yaml:"email"`
}

// LoadConfig loads and parses security-config.yml
func LoadConfig(configPath string) (*SecurityConfig, error) {
	// Check if file exists
	_, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return getDefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}

	// Read file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	config := &SecurityConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Set defaults for unset values
	setConfigDefaults(config)

	return config, nil
}

// getDefaultConfig returns the default configuration
func getDefaultConfig() *SecurityConfig {
	return &SecurityConfig{
		Version:           "0.3.0",
		SeverityThreshold: "high",
		Tools: ToolsConfig{
			Semgrep:  true,
			Gitleaks: true,
			Trivy:    true,
		},
		ExcludePaths: []string{},
		FailOn: map[string]int{
			"gitleaks":       0,
			"semgrep":        10,
			"trivy_critical": 0,
			"trivy_high":     5,
			"trivy_medium":   -1,
			"trivy_low":      -1,
		},
		Notifications: NotificationsConfig{
			PRComment: true,
			Slack:     false,
			Email:     false,
		},
	}
}

// setConfigDefaults fills in missing values with sensible defaults
func setConfigDefaults(config *SecurityConfig) {
	// Ensure FailOn map exists and has all keys
	if config.FailOn == nil {
		config.FailOn = make(map[string]int)
	}

	defaults := map[string]int{
		"gitleaks":           0,
		"semgrep":            10,
		"trivy_critical":     0,
		"trivy_high":         5,
		"trivy_medium":       -1,
		"trivy_low":          -1,
		"license_violations": -1,
	}

	for key, defaultValue := range defaults {
		if _, exists := config.FailOn[key]; !exists {
			config.FailOn[key] = defaultValue
		}
	}

	// Set default threshold if not specified
	if config.SeverityThreshold == "" {
		config.SeverityThreshold = "high"
	}

	// Set default tools if all are false
	if !config.Tools.Semgrep && !config.Tools.Gitleaks && !config.Tools.Trivy {
		config.Tools.Semgrep = true
		config.Tools.Gitleaks = true
		config.Tools.Trivy = true
	}
}
