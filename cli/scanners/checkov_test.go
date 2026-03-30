package scanners

import (
	"encoding/json"
	"testing"
)

func TestParseCheckovOutputSingleObject(t *testing.T) {
	data := checkovOutput{}
	data.Results.FailedChecks = []checkovCheck{
		{CheckID: "CKV_AWS_1", CheckName: "Ensure S3 bucket has access logging enabled", FilePath: "main.tf", FileLineRange: []int{10, 20}, Resource: "aws_s3_bucket.example"},
		{CheckID: "CKV_K8S_1", CheckName: "Do not admit root containers", FilePath: "deployment.yaml", FileLineRange: []int{5, 15}},
		{CheckID: "CKV2_AWS_5", CheckName: "Ensure SG is attached", FilePath: "sg.tf", FileLineRange: []int{1, 10}},
	}

	raw, _ := json.Marshal(data)
	findings, err := parseCheckovOutput(raw)
	if err != nil {
		t.Fatalf("parseCheckovOutput failed: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	if findings[0].RuleID != "CKV_AWS_1" {
		t.Errorf("expected rule_id CKV_AWS_1, got %s", findings[0].RuleID)
	}
	if findings[0].Line != 10 {
		t.Errorf("expected line 10, got %d", findings[0].Line)
	}
	if findings[0].Tool != "checkov" {
		t.Errorf("expected tool checkov, got %s", findings[0].Tool)
	}
}

func TestParseCheckovOutputArray(t *testing.T) {
	obj1 := checkovOutput{}
	obj1.Results.FailedChecks = []checkovCheck{
		{CheckID: "CKV_AWS_1", CheckName: "S3 logging", FilePath: "main.tf"},
	}
	obj2 := checkovOutput{}
	obj2.Results.FailedChecks = []checkovCheck{
		{CheckID: "CKV_K8S_1", CheckName: "No root containers", FilePath: "deploy.yaml"},
	}

	raw, _ := json.Marshal([]checkovOutput{obj1, obj2})
	findings, err := parseCheckovOutput(raw)
	if err != nil {
		t.Fatalf("parseCheckovOutput failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestMapCheckovSeverity(t *testing.T) {
	tests := []struct {
		checkID  string
		raw      string
		expected string
	}{
		{"CKV_AWS_1", "", "HIGH"},
		{"CKV_AZURE_1", "", "HIGH"},
		{"CKV_GCP_1", "", "HIGH"},
		{"CKV_K8S_1", "", "MEDIUM"},
		{"CKV2_AWS_5", "", "HIGH"},
		{"CKV_DOCKER_1", "", "MEDIUM"},
		{"CKV_AWS_1", "CRITICAL", "CRITICAL"},
		{"CKV_AWS_1", "LOW", "LOW"},
	}

	for _, tt := range tests {
		got := mapCheckovSeverity(tt.checkID, tt.raw)
		if got != tt.expected {
			t.Errorf("mapCheckovSeverity(%q, %q) = %q, want %q", tt.checkID, tt.raw, got, tt.expected)
		}
	}
}

func TestSummarizeFindings(t *testing.T) {
	findings := []Finding{
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
		{Severity: "HIGH"},
		{Severity: "MEDIUM"},
		{Severity: "LOW"},
	}

	s := summarizeFindings(findings)
	if s.Total != 5 {
		t.Errorf("expected Total=5, got %d", s.Total)
	}
	if s.Critical != 1 {
		t.Errorf("expected Critical=1, got %d", s.Critical)
	}
	if s.High != 2 {
		t.Errorf("expected High=2, got %d", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("expected Medium=1, got %d", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("expected Low=1, got %d", s.Low)
	}
}

func TestCheckovResourceInMessage(t *testing.T) {
	out := checkovOutput{}
	out.Results.FailedChecks = []checkovCheck{
		{CheckID: "CKV_AWS_1", CheckName: "S3 logging", FilePath: "main.tf", Resource: "aws_s3_bucket.my_bucket"},
	}

	raw, _ := json.Marshal(out)
	findings, _ := parseCheckovOutput(raw)

	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	if findings[0].Message != "S3 logging [aws_s3_bucket.my_bucket]" {
		t.Errorf("unexpected message: %s", findings[0].Message)
	}
}
