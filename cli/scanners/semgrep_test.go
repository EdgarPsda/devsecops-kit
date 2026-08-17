package scanners

import (
	"encoding/json"
	"testing"
)

func TestSemgrepJSONPayloadOnlyJSON(t *testing.T) {
	payload := []byte(`{"version":"1.155.0","results":[],"errors":[]}`)

	got, err := semgrepJSONPayload(payload)
	if err != nil {
		t.Fatalf("expected JSON payload: %v", err)
	}

	assertSemgrepJSON(t, got)
}

func TestSemgrepJSONPayloadBannerAndJSON(t *testing.T) {
	payload := []byte("┌──── ○○○ ────┐\n│ Semgrep CLI │\n└─────────────┘\n\nScanning...\n\n{\"version\":\"1.155.0\",\"results\":[],\"errors\":[]}")

	got, err := semgrepJSONPayload(payload)
	if err != nil {
		t.Fatalf("expected JSON payload after banner: %v", err)
	}

	assertSemgrepJSON(t, got)
}

func TestSemgrepJSONPayloadTextBeforeJSON(t *testing.T) {
	payload := []byte("loading rules\nscanning project\n{\"version\":\"1.155.0\",\"results\":[],\"errors\":[]}")

	got, err := semgrepJSONPayload(payload)
	if err != nil {
		t.Fatalf("expected JSON payload after text: %v", err)
	}

	assertSemgrepJSON(t, got)
}

func TestSemgrepJSONPayloadSkipsInvalidObjectsBeforeJSON(t *testing.T) {
	payload := []byte("banner {not json}\n{\"version\":\"1.155.0\",\"results\":[],\"errors\":[]}")

	got, err := semgrepJSONPayload(payload)
	if err != nil {
		t.Fatalf("expected parser to skip invalid object-like text: %v", err)
	}

	assertSemgrepJSON(t, got)
}

func TestSemgrepJSONPayloadInvalidOutput(t *testing.T) {
	if _, err := semgrepJSONPayload([]byte("not json at all")); err == nil {
		t.Fatal("expected invalid output to fail")
	}
}

func TestSemgrepJSONPayloadEmptyStdout(t *testing.T) {
	if _, err := semgrepJSONPayload(nil); err == nil {
		t.Fatal("expected empty stdout to fail")
	}
}

func TestSemgrepJSONPayloadValidStdoutWithStderrMessages(t *testing.T) {
	stdout := []byte(`{"version":"1.155.0","results":[],"errors":[]}`)
	stderr := []byte("informational warning on stderr")

	got, err := semgrepJSONPayload(stdout)
	if err != nil {
		t.Fatalf("expected stdout JSON to parse despite stderr: %v", err)
	}
	if len(stderr) == 0 {
		t.Fatal("expected test fixture stderr message")
	}

	assertSemgrepJSON(t, got)
}

func TestSemgrepFindingsCurrentJSONShape(t *testing.T) {
	payload := []byte(`{
		"version": "1.155.0",
		"results": [
			{
				"check_id": "python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host",
				"path": "app.py",
				"start": { "line": 12, "col": 5, "offset": 120 },
				"end": { "line": 12, "col": 20, "offset": 135 },
				"extra": {
					"message": "Running Flask app with an unsafe host is dangerous.",
					"severity": "WARNING",
					"metadata": {
						"cwe": ["CWE-668"]
					},
					"lines": "app.run(host='0.0.0.0')"
				}
			}
		],
		"errors": []
	}`)

	var output SemgrepOutput
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("expected semgrep output to unmarshal: %v", err)
	}

	findings := semgrepFindings(output)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.File != "app.py" {
		t.Fatalf("expected file app.py, got %s", finding.File)
	}
	if finding.Line != 12 {
		t.Fatalf("expected line 12, got %d", finding.Line)
	}
	if finding.Column != 5 {
		t.Fatalf("expected column 5, got %d", finding.Column)
	}
	if finding.Severity != "MEDIUM" {
		t.Fatalf("expected normalized WARNING severity to become MEDIUM, got %s", finding.Severity)
	}
	if finding.Message != "Running Flask app with an unsafe host is dangerous." {
		t.Fatalf("unexpected message: %s", finding.Message)
	}
	if finding.RuleID != "python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host" {
		t.Fatalf("unexpected rule id: %s", finding.RuleID)
	}
}

func TestSemgrepFindingsBlockingMetadata(t *testing.T) {
	payload := []byte(`{
		"version": "1.155.0",
		"results": [
			{
				"check_id": "custom.low.blocking",
				"path": "app.py",
				"start": { "line": 3, "col": 1 },
				"end": { "line": 3, "col": 10 },
				"extra": {
					"message": "Explicitly blocking low finding.",
					"severity": "LOW",
					"metadata": {
						"blocking": true
					}
				}
			}
		],
		"errors": []
	}`)

	var output SemgrepOutput
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("expected semgrep output to unmarshal: %v", err)
	}

	findings := semgrepFindings(output)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if !findings[0].Blocking {
		t.Fatal("expected blocking metadata to mark finding as blocking")
	}
}

func assertSemgrepJSON(t *testing.T, payload []byte) {
	t.Helper()

	var output SemgrepOutput
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("expected valid Semgrep JSON: %v", err)
	}
	if output.Results == nil {
		t.Fatal("expected results field to be present")
	}
}
