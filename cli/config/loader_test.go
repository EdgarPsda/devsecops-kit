package config

import "testing"

func TestValidateAIConfigAllowsConfiguredProvider(t *testing.T) {
	err := ValidateAIConfig(AIConfig{
		Enabled:                 true,
		Provider:                "OpenAI",
		RequireApprovedProvider: true,
		AllowedProviders:        []string{"ollama", "openai"},
	})
	if err != nil {
		t.Fatalf("expected approved provider to pass: %v", err)
	}
}

func TestValidateAIConfigRejectsUnapprovedProvider(t *testing.T) {
	err := ValidateAIConfig(AIConfig{
		Enabled:                 true,
		Provider:                "anthropic",
		RequireApprovedProvider: true,
		AllowedProviders:        []string{"ollama", "openai"},
	})
	if err == nil {
		t.Fatal("expected unapproved provider to fail")
	}
}

func TestValidateAIConfigIgnoresAllowlistWhenNotRequired(t *testing.T) {
	err := ValidateAIConfig(AIConfig{Enabled: true, Provider: "anthropic"})
	if err != nil {
		t.Fatalf("expected non-strict AI config to pass: %v", err)
	}
}
