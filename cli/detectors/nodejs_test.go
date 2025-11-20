package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNodeDetector_Detect_Express(t *testing.T) {
	dir := t.TempDir()

	// Minimal package.json with express dependency
	pkgJSON := `{
  "name": "test-node-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0"
  }
}`

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o644); err != nil {
		t.Fatalf("failed to write package.json: %v", err)
	}

	d := &NodeDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "nodejs" {
		t.Errorf("expected Language=nodejs, got %s", info.Language)
	}
	if info.Framework != "express" {
		t.Errorf("expected Framework=express, got %s", info.Framework)
	}
	if info.PackageFile != "package.json" {
		t.Errorf("expected PackageFile=package.json, got %s", info.PackageFile)
	}
	if d.Confidence() <= 0 {
		t.Errorf("expected confidence > 0, got %d", d.Confidence())
	}
}
