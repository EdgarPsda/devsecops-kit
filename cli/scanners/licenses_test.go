package scanners

import (
	"testing"
)

func TestMatchLicense(t *testing.T) {
	tests := []struct {
		licenseName string
		pattern     string
		expected    bool
	}{
		{"mit", "mit", true},
		{"apache-2.0", "apache-2.0", true},
		{"gpl-3.0", "gpl-3.0", true},
		{"bsd-2-clause", "bsd-*", true},
		{"bsd-3-clause", "bsd-*", true},
		{"mit", "apache-2.0", false},
		{"gpl-3.0", "mit", false},
	}

	for _, tt := range tests {
		got := matchLicense(tt.licenseName, tt.pattern)
		if got != tt.expected {
			t.Errorf("matchLicense(%q, %q) = %v, want %v", tt.licenseName, tt.pattern, got, tt.expected)
		}
	}
}

func TestClassifyLicenseSeverity(t *testing.T) {
	tests := []struct {
		licenseName string
		category    string
		expected    string
	}{
		{"AGPL-3.0", "", "HIGH"},
		{"SSPL-1.0", "", "HIGH"},
		{"GPL-3.0", "", "MEDIUM"},
		{"GPL-2.0", "", "MEDIUM"},
		{"LGPL-2.1", "", "LOW"},
		{"MIT", "", "MEDIUM"},
		{"Apache-2.0", "restricted", "HIGH"},
	}

	for _, tt := range tests {
		got := classifyLicenseSeverity(tt.licenseName, tt.category)
		if got != tt.expected {
			t.Errorf("classifyLicenseSeverity(%q, %q) = %q, want %q", tt.licenseName, tt.category, got, tt.expected)
		}
	}
}

func TestIsLicenseViolation_DenyList(t *testing.T) {
	o := &Orchestrator{
		options: ScanOptions{
			LicenseConfig: LicenseConfig{
				Enabled: true,
				Deny:    []string{"GPL-3.0", "AGPL-*"},
			},
		},
	}

	tests := []struct {
		license  string
		expected bool
	}{
		{"GPL-3.0", true},
		{"AGPL-3.0", true},
		{"MIT", false},
		{"Apache-2.0", false},
	}

	for _, tt := range tests {
		got := o.isLicenseViolation(tt.license)
		if got != tt.expected {
			t.Errorf("isLicenseViolation(%q) with deny list = %v, want %v", tt.license, got, tt.expected)
		}
	}
}

func TestIsLicenseViolation_AllowList(t *testing.T) {
	o := &Orchestrator{
		options: ScanOptions{
			LicenseConfig: LicenseConfig{
				Enabled: true,
				Allow:   []string{"MIT", "Apache-2.0", "BSD-*"},
			},
		},
	}

	tests := []struct {
		license  string
		expected bool
	}{
		{"MIT", false},
		{"Apache-2.0", false},
		{"BSD-3-Clause", false},
		{"GPL-3.0", true},
		{"AGPL-3.0", true},
	}

	for _, tt := range tests {
		got := o.isLicenseViolation(tt.license)
		if got != tt.expected {
			t.Errorf("isLicenseViolation(%q) with allow list = %v, want %v", tt.license, got, tt.expected)
		}
	}
}

func TestIsLicenseViolation_DefaultCopyleft(t *testing.T) {
	o := &Orchestrator{
		options: ScanOptions{
			LicenseConfig: LicenseConfig{
				Enabled: true,
			},
		},
	}

	tests := []struct {
		license  string
		expected bool
	}{
		{"GPL-3.0", true},
		{"AGPL-3.0", true},
		{"LGPL-2.1", true},
		{"MIT", false},
		{"Apache-2.0", false},
		{"BSD-3-Clause", false},
	}

	for _, tt := range tests {
		got := o.isLicenseViolation(tt.license)
		if got != tt.expected {
			t.Errorf("isLicenseViolation(%q) with defaults = %v, want %v", tt.license, got, tt.expected)
		}
	}
}
