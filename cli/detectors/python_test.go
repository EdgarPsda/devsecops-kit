package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPythonDetector_Detect_Django(t *testing.T) {
	dir := t.TempDir()

	reqTxt := `django>=4.2
djangorestframework>=3.14
celery>=5.3
redis>=4.5
`

	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(reqTxt), 0o644); err != nil {
		t.Fatalf("failed to write requirements.txt: %v", err)
	}

	d := &PythonDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "python" {
		t.Errorf("expected Language=python, got %s", info.Language)
	}
	if info.Framework != "django" {
		t.Errorf("expected Framework=django, got %s", info.Framework)
	}
	if info.PackageFile != "requirements.txt" {
		t.Errorf("expected PackageFile=requirements.txt, got %s", info.PackageFile)
	}
	if d.Confidence() <= 0 {
		t.Errorf("expected confidence > 0, got %d", d.Confidence())
	}
	if len(info.Dependencies) != 4 {
		t.Errorf("expected 4 dependencies, got %d", len(info.Dependencies))
	}
}

func TestPythonDetector_Detect_FastAPI_Pyproject(t *testing.T) {
	dir := t.TempDir()

	pyproject := `[project]
name = "my-api"
version = "1.0.0"

[project.dependencies]
"fastapi>=0.100",
"uvicorn>=0.23",
"sqlalchemy>=2.0",
`

	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatalf("failed to write pyproject.toml: %v", err)
	}

	d := &PythonDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "python" {
		t.Errorf("expected Language=python, got %s", info.Language)
	}
	if info.Framework != "fastapi" {
		t.Errorf("expected Framework=fastapi, got %s", info.Framework)
	}
	if info.PackageFile != "pyproject.toml" {
		t.Errorf("expected PackageFile=pyproject.toml, got %s", info.PackageFile)
	}
}

func TestPythonDetector_Detect_Flask_Pipfile(t *testing.T) {
	dir := t.TempDir()

	pipfile := `[packages]
flask = ">=2.3"
gunicorn = "*"
psycopg2 = ">=2.9"

[dev-packages]
pytest = "*"
`

	if err := os.WriteFile(filepath.Join(dir, "Pipfile"), []byte(pipfile), 0o644); err != nil {
		t.Fatalf("failed to write Pipfile: %v", err)
	}

	d := &PythonDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "python" {
		t.Errorf("expected Language=python, got %s", info.Language)
	}
	if info.Framework != "flask" {
		t.Errorf("expected Framework=flask, got %s", info.Framework)
	}
	if info.PackageFile != "Pipfile" {
		t.Errorf("expected PackageFile=Pipfile, got %s", info.PackageFile)
	}
}

func TestPythonDetector_Detect_NoProject(t *testing.T) {
	dir := t.TempDir()

	d := &PythonDetector{}
	_, err := d.Detect(dir)
	if err == nil {
		t.Error("expected error for empty directory, got nil")
	}
	if d.Confidence() != 0 {
		t.Errorf("expected confidence=0, got %d", d.Confidence())
	}
}
