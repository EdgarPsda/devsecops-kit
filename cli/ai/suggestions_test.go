package ai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

func TestNewClientDefaults(t *testing.T) {
	c := NewClient(Config{Provider: "ollama"})
	if c.cfg.Model != "llama3" {
		t.Errorf("expected default ollama model 'llama3', got %q", c.cfg.Model)
	}
	if c.cfg.Endpoint != "http://localhost:11434" {
		t.Errorf("expected default endpoint, got %q", c.cfg.Endpoint)
	}

	c2 := NewClient(Config{Provider: "openai"})
	if c2.cfg.Model != "gpt-4o-mini" {
		t.Errorf("expected default openai model 'gpt-4o-mini', got %q", c2.cfg.Model)
	}

	c3 := NewClient(Config{Provider: "anthropic"})
	if c3.cfg.Model != "claude-haiku-4-5-20251001" {
		t.Errorf("expected default anthropic model, got %q", c3.cfg.Model)
	}
}

func TestEnrichFindingsOnlyHighCritical(t *testing.T) {
	// Mock server that returns a suggestion
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"response": "Use parameterized queries."})
	}))
	defer srv.Close()

	c := NewClient(Config{Provider: "ollama", Endpoint: srv.URL})

	findings := []scanners.Finding{
		{RuleID: "r1", Severity: "CRITICAL", Message: "SQL injection", Tool: "semgrep", File: "a.go"},
		{RuleID: "r2", Severity: "HIGH", Message: "Hardcoded secret", Tool: "gitleaks", File: "b.go"},
		{RuleID: "r3", Severity: "MEDIUM", Message: "Missing header", Tool: "semgrep", File: "c.go"},
		{RuleID: "r4", Severity: "LOW", Message: "Info leak", Tool: "semgrep", File: "d.go"},
	}

	c.EnrichFindings(findings)

	if findings[0].AISuggestion == "" {
		t.Error("CRITICAL finding should have a suggestion")
	}
	if findings[1].AISuggestion == "" {
		t.Error("HIGH finding should have a suggestion")
	}
	if findings[2].AISuggestion != "" {
		t.Error("MEDIUM finding should NOT have a suggestion")
	}
	if findings[3].AISuggestion != "" {
		t.Error("LOW finding should NOT have a suggestion")
	}
}

func TestEnrichFindingsCachesResults(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]string{"response": "Fix suggestion."})
	}))
	defer srv.Close()

	c := NewClient(Config{Provider: "ollama", Endpoint: srv.URL})

	// Two findings with identical rule+message — should only call API once
	findings := []scanners.Finding{
		{RuleID: "r1", Severity: "HIGH", Message: "SQL injection", Tool: "semgrep", File: "a.go"},
		{RuleID: "r1", Severity: "HIGH", Message: "SQL injection", Tool: "semgrep", File: "b.go"},
	}

	c.EnrichFindings(findings)

	if callCount != 1 {
		t.Errorf("expected 1 API call due to caching, got %d", callCount)
	}
	if findings[0].AISuggestion == "" || findings[1].AISuggestion == "" {
		t.Error("both findings should have suggestions")
	}
}

func TestBuildPromptContainsKeyFields(t *testing.T) {
	f := &scanners.Finding{
		Tool:     "trivy",
		Severity: "HIGH",
		RuleID:   "CVE-2024-1234",
		File:     "go.sum",
		Message:  "Vulnerable dependency",
	}

	prompt := buildPrompt(f)

	for _, expected := range []string{"trivy", "HIGH", "CVE-2024-1234", "go.sum", "Vulnerable dependency"} {
		if !contains(prompt, expected) {
			t.Errorf("prompt missing %q", expected)
		}
	}
}

func TestCacheKeyStable(t *testing.T) {
	k1 := cacheKey("rule1", "message1")
	k2 := cacheKey("rule1", "message1")
	k3 := cacheKey("rule1", "message2")

	if k1 != k2 {
		t.Error("same inputs should produce same cache key")
	}
	if k1 == k3 {
		t.Error("different inputs should produce different cache keys")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
