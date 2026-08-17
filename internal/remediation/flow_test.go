package remediation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type fakeValidationEngine struct {
	result *ValidationResult
	err    error
	calls  int
}

func (v *fakeValidationEngine) Validate(ctx context.Context, request ValidationRequest) (*ValidationResult, error) {
	v.calls++
	if v.err != nil {
		return nil, v.err
	}
	return v.result, nil
}

func TestRemediateAppliesPatchAndValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte("package main\n\nconst version = \"old\"\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	git := &fakeGitClient{
		changedFiles: []GitFileStatus{
			{Path: "main.go", Status: "modified"},
		},
	}
	validation := &fakeValidationEngine{
		result: &ValidationResult{
			Status: "success",
			Passed: true,
			Checks: []ValidationCheckResult{
				{Name: "build", Type: "build", Status: "success", Passed: true},
				{Name: "unit", Type: "unit_tests", Status: "success", Passed: true},
			},
		},
	}
	engine := NewEngineWithValidation(Options{}, nil, nil, nil, git, validation, nil, nil)

	result, err := engine.Remediate(context.Background(), RemediationRequest{
		RepositoryDir: dir,
		BaseBranch:    "main",
		BranchName:    "remediation/test",
		Finding: Finding{
			File:     "main.go",
			Severity: "HIGH",
			Message:  "old version",
		},
		Recommendation: Recommendation{
			Title: "Use new version",
		},
		Patch: Patch{
			File:        "main.go",
			Original:    `const version = "old"`,
			Replacement: `const version = "new"`,
		},
		Checks: []ValidationType{"build", "unit_tests", "security_rescan"},
	})
	if err != nil {
		t.Fatalf("expected remediation to succeed: %v", err)
	}

	if result.Status != "success" {
		t.Fatalf("expected success status, got %s", result.Status)
	}
	if result.Summary.VulnerabilitiesFixed != 1 || result.Summary.VulnerabilitiesPending != 0 {
		t.Fatalf("unexpected vulnerability summary: %#v", result.Summary)
	}
	if result.Summary.ValidationsPassed != 2 || result.Summary.ValidationsFailed != 0 {
		t.Fatalf("unexpected validation summary: %#v", result.Summary)
	}
	if validation.calls != 1 {
		t.Fatalf("expected validation to run once, got %d", validation.calls)
	}
	if git.rollbackCalls != 0 || git.restoreCalls != 0 {
		t.Fatalf("did not expect rollback or restore; got rollback=%d restore=%d", git.rollbackCalls, git.restoreCalls)
	}
}

func TestRemediateRollsBackWhenValidationFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	original := "package main\n\nconst version = \"old\"\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	git := &fakeGitClient{
		changedFiles: []GitFileStatus{
			{Path: "main.go", Status: "modified"},
		},
		restoreFunc: func(request GitRestoreRequest) error {
			return os.WriteFile(filepath.Join(dir, request.Files[0]), []byte(original), 0o644)
		},
	}
	validation := &fakeValidationEngine{
		result: &ValidationResult{
			Status: "failed",
			Passed: false,
			Checks: []ValidationCheckResult{
				{Name: "build", Type: "build", Status: "success", Passed: true},
				{Name: "security", Type: "security_rescan", Status: "failed", Passed: false},
			},
		},
	}
	engine := NewEngineWithValidation(Options{}, nil, nil, nil, git, validation, nil, nil)

	result, err := engine.Remediate(context.Background(), RemediationRequest{
		RepositoryDir: dir,
		BaseBranch:    "main",
		BranchName:    "remediation/test",
		Finding: Finding{
			File:     "main.go",
			Severity: "HIGH",
			Message:  "old version",
		},
		Recommendation: Recommendation{Title: "Use new version"},
		Patch: Patch{
			File:        "main.go",
			Original:    `const version = "old"`,
			Replacement: `const version = "new"`,
		},
	})
	if err == nil {
		t.Fatal("expected remediation to fail")
	}
	if result == nil {
		t.Fatal("expected failed result")
	}
	if result.Summary.VulnerabilitiesFixed != 0 || result.Summary.VulnerabilitiesPending != 1 {
		t.Fatalf("unexpected vulnerability summary: %#v", result.Summary)
	}
	if result.Summary.ValidationsPassed != 1 || result.Summary.ValidationsFailed != 1 {
		t.Fatalf("unexpected validation summary: %#v", result.Summary)
	}
	if git.rollbackCalls != 1 || git.restoreCalls != 1 {
		t.Fatalf("expected rollback and restore; got rollback=%d restore=%d", git.rollbackCalls, git.restoreCalls)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("failed to read restored file: %v", readErr)
	}
	if string(data) != original {
		t.Fatalf("expected restored content, got %s", string(data))
	}
}

func TestRemediateRollsBackWhenValidationErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	original := "package main\n\nconst version = \"old\"\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	git := &fakeGitClient{
		changedFiles: []GitFileStatus{
			{Path: "main.go", Status: "modified"},
		},
		restoreFunc: func(request GitRestoreRequest) error {
			return os.WriteFile(filepath.Join(dir, request.Files[0]), []byte(original), 0o644)
		},
	}
	validation := &fakeValidationEngine{err: fmt.Errorf("validation crashed")}
	engine := NewEngineWithValidation(Options{}, nil, nil, nil, git, validation, nil, nil)

	result, err := engine.Remediate(context.Background(), RemediationRequest{
		RepositoryDir:  dir,
		BaseBranch:     "main",
		BranchName:     "remediation/test",
		Finding:        Finding{File: "main.go", Severity: "HIGH"},
		Recommendation: Recommendation{Title: "Use new version"},
		Patch: Patch{
			File:        "main.go",
			Original:    `const version = "old"`,
			Replacement: `const version = "new"`,
		},
	})
	if err == nil {
		t.Fatal("expected remediation to fail")
	}
	if result == nil {
		t.Fatal("expected failed result")
	}
	if result.Summary.ValidationsFailed != 1 {
		t.Fatalf("expected one failed validation, got %#v", result.Summary)
	}
	if git.rollbackCalls != 1 || git.restoreCalls != 1 {
		t.Fatalf("expected rollback and restore; got rollback=%d restore=%d", git.rollbackCalls, git.restoreCalls)
	}
}
