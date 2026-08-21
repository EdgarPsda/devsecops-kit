package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/edgarpsda/devsecops-kit/cli/config"
	"github.com/edgarpsda/devsecops-kit/cli/detectors"
)

func TestRemediationAuditWrite(t *testing.T) {
	root := t.TempDir()
	audit := newRemediationAudit(root, "snyk", "snyk", &config.SecurityConfig{
		AI: config.AIConfig{Enabled: true, Provider: "openai", Model: "gpt-4o-mini"},
	}, &detectors.ProjectInfo{Language: "java", Framework: "spring", PackageFile: "pom.xml"})
	audit.OriginalBranch = "main"
	audit.Branch = "security/remediation-test"
	audit.record(remediationAuditEvent{Type: "scan", Status: "completed", BeforeFindings: 2})
	audit.complete("completed", remediationAuditSummary{Scanned: 2, Fixed: 1, Failed: 1, Remaining: 1, ModifiedFiles: []string{"pom.xml"}})

	path, err := audit.write(root)
	if err != nil {
		t.Fatalf("expected audit report to write: %v", err)
	}
	if filepath.Base(filepath.Dir(filepath.Dir(path))) != "remediation-runs" {
		t.Fatalf("expected remediation-runs directory, got %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected audit report to be readable: %v", err)
	}
	var parsed remediationAuditReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("expected valid JSON audit report: %v", err)
	}
	if parsed.Summary.Fixed != 1 || parsed.AI.Provider != "openai" || len(parsed.Events) != 1 {
		t.Fatalf("unexpected parsed audit report: %+v", parsed)
	}
}

func TestAITraceUsesHashesWithoutRawContent(t *testing.T) {
	trace := aiTrace("openai", "gpt-4o-mini", "secret prompt", "secret response")
	if trace.PromptSHA256 == "" || trace.ResponseSHA256 == "" {
		t.Fatal("expected hashes to be populated")
	}
	if trace.PromptSHA256 == "secret prompt" || trace.ResponseSHA256 == "secret response" {
		t.Fatal("expected trace to avoid storing raw prompt or response")
	}
	if trace.PromptBytes == 0 || trace.ResponseBytes == 0 {
		t.Fatal("expected byte counts to be populated")
	}
}
