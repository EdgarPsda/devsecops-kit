package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoDetector_Detect_Gin(t *testing.T) {
	dir := t.TempDir()

	goMod := `module example.com/testapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
)
`

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	d := &GoDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "golang" {
		t.Errorf("expected Language=golang, got %s", info.Language)
	}
	if info.Framework != "gin" {
		t.Errorf("expected Framework=gin, got %s", info.Framework)
	}
	if info.PackageFile != "go.mod" {
		t.Errorf("expected PackageFile=go.mod, got %s", info.PackageFile)
	}
	if d.Confidence() <= 0 {
		t.Errorf("expected confidence > 0, got %d", d.Confidence())
	}
}
