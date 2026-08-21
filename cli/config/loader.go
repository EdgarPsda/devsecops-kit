package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SecurityConfig represents the security-config.yml structure
type SecurityConfig struct {
	Version           string              `yaml:"version"`
	Language          string              `yaml:"language"`
	Framework         string              `yaml:"framework"`
	SeverityThreshold string              `yaml:"severity_threshold"`
	Tools             ToolsConfig         `yaml:"tools"`
	ExcludePaths      []string            `yaml:"exclude_paths"`
	FailOn            map[string]int      `yaml:"fail_on"`
	Licenses          LicensesConfig      `yaml:"licenses"`
	Notifications     NotificationsConfig `yaml:"notifications"`
	Policy            PolicyConfig        `yaml:"policy"`
	AI                AIConfig            `yaml:"ai"`
}

// PolicyConfig holds optional enterprise policy settings.
type PolicyConfig struct {
	Profile string    `yaml:"profile"`
	SLA     SLAConfig `yaml:"sla"`
}

// SLAConfig holds optional age-based vulnerability gates.
type SLAConfig struct {
	Enabled bool           `yaml:"enabled"`
	Warn    map[string]int `yaml:"warn"`
	Fail    map[string]int `yaml:"fail"`
}

// AIConfig holds AI fix suggestion settings
type AIConfig struct {
	Enabled                 bool     `yaml:"enabled"`
	Provider                string   `yaml:"provider"` // "ollama", "openai", "anthropic"
	Model                   string   `yaml:"model"`
	Endpoint                string   `yaml:"endpoint"`                  // custom endpoint or approved gateway
	APIKey                  string   `yaml:"api_key"`                   // for openai/anthropic (prefer env vars)
	RequireApprovedProvider bool     `yaml:"require_approved_provider"` // fail if provider is not allowlisted
	AllowedProviders        []string `yaml:"allowed_providers"`         // optional provider allowlist
}

// ValidateAIConfig checks optional governance controls for AI usage.
func ValidateAIConfig(ai AIConfig) error {
	if !ai.Enabled || !ai.RequireApprovedProvider {
		return nil
	}
	if len(ai.AllowedProviders) == 0 {
		return fmt.Errorf("ai.require_approved_provider=true requires ai.allowed_providers")
	}
	provider := strings.ToLower(strings.TrimSpace(ai.Provider))
	for _, allowed := range ai.AllowedProviders {
		if provider == strings.ToLower(strings.TrimSpace(allowed)) {
			return nil
		}
	}
	return fmt.Errorf("AI provider %q is not in ai.allowed_providers", ai.Provider)
}

// ToolsConfig represents the tools section
type ToolsConfig struct {
	Semgrep  bool `yaml:"semgrep"`
	Trivy    bool `yaml:"trivy"`
	Gitleaks bool `yaml:"gitleaks"`
	Checkov  bool `yaml:"checkov"`
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
		Policy: PolicyConfig{
			Profile: "default",
			SLA: SLAConfig{
				Enabled: false,
				Warn:    map[string]int{},
				Fail:    map[string]int{},
			},
		},
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
		"checkov":            -1,
	}

	for key, defaultValue := range defaults {
		if _, exists := config.FailOn[key]; !exists {
			config.FailOn[key] = defaultValue
		}
	}
	// Ensure optional policy maps exist when policy is configured.
	if config.Policy.Profile == "" {
		config.Policy.Profile = "default"
	}
	if config.Policy.SLA.Warn == nil {
		config.Policy.SLA.Warn = make(map[string]int)
	}
	if config.Policy.SLA.Fail == nil {
		config.Policy.SLA.Fail = make(map[string]int)
	}
	if config.AI.AllowedProviders == nil {
		config.AI.AllowedProviders = []string{}
	}

	// Set default threshold if not specified
	if config.SeverityThreshold == "" {
		config.SeverityThreshold = "high"
	}

	// Set default tools if all core tools are false (Checkov is opt-in, excluded from this check)
	if !config.Tools.Semgrep && !config.Tools.Gitleaks && !config.Tools.Trivy {
		config.Tools.Semgrep = true
		config.Tools.Gitleaks = true
		config.Tools.Trivy = true
	}
}
