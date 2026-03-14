// cli/detectors/python.go
package detectors

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type PythonDetector struct {
	confidence int
}

func (d *PythonDetector) Detect(dir string) (*ProjectInfo, error) {
	// Check for Python project files in priority order
	packageFiles := []string{
		"pyproject.toml",
		"requirements.txt",
		"Pipfile",
		"setup.py",
		"setup.cfg",
	}

	var foundFile string
	for _, f := range packageFiles {
		if fileExists(filepath.Join(dir, f)) {
			foundFile = f
			break
		}
	}

	if foundFile == "" {
		d.confidence = 0
		return nil, errors.New("no Python project file found")
	}

	deps := collectPythonDeps(dir, foundFile)
	framework := detectPythonFramework(deps)

	d.confidence = 95

	return &ProjectInfo{
		Language:     "python",
		Framework:    framework,
		PackageFile:  foundFile,
		RootDir:      dir,
		Dependencies: deps,
	}, nil
}

func (d *PythonDetector) Confidence() int {
	return d.confidence
}

func detectPythonFramework(deps []string) string {
	for _, dep := range deps {
		lower := strings.ToLower(dep)
		switch {
		case lower == "django":
			return "django"
		case lower == "flask":
			return "flask"
		case lower == "fastapi":
			return "fastapi"
		case lower == "scrapy":
			return "scrapy"
		case lower == "tornado":
			return "tornado"
		case lower == "starlette":
			return "starlette"
		}
	}
	return ""
}

func collectPythonDeps(dir, packageFile string) []string {
	switch packageFile {
	case "requirements.txt":
		return parseRequirementsTxt(filepath.Join(dir, packageFile))
	case "pyproject.toml":
		return parsePyprojectToml(filepath.Join(dir, packageFile))
	case "Pipfile":
		return parsePipfile(filepath.Join(dir, packageFile))
	case "setup.py", "setup.cfg":
		return parseSetupPy(filepath.Join(dir, packageFile))
	}
	return nil
}

// parseRequirementsTxt extracts package names from requirements.txt
func parseRequirementsTxt(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and options
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Extract package name (before version specifiers)
		name := extractPythonPackageName(line)
		if name != "" {
			deps = append(deps, name)
		}
	}

	return deps
}

// parsePyprojectToml does a minimal parse to find dependency names
func parsePyprojectToml(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)
	inDependencies := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Detect [project.dependencies] or dependencies = [
		if line == "[project.dependencies]" || line == "dependencies = [" ||
			strings.HasPrefix(line, "[tool.poetry.dependencies]") {
			inDependencies = true
			continue
		}

		// End of section
		if inDependencies && (strings.HasPrefix(line, "[") || line == "]") {
			inDependencies = false
			continue
		}

		if inDependencies && line != "" && !strings.HasPrefix(line, "#") {
			// Handle both TOML formats:
			// "django>=4.0",   (PEP 621)
			// django = "^4.0"  (Poetry)
			cleaned := strings.Trim(line, `",' `)
			name := extractPythonPackageName(cleaned)
			if name != "" {
				deps = append(deps, name)
			}
		}
	}

	return deps
}

// parsePipfile does a minimal parse to find dependency names
func parsePipfile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)
	inPackages := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[packages]" || line == "[dev-packages]" {
			inPackages = true
			continue
		}

		// New section starts
		if strings.HasPrefix(line, "[") {
			inPackages = false
			continue
		}

		if inPackages && line != "" && !strings.HasPrefix(line, "#") {
			// Format: package_name = "version"
			parts := strings.SplitN(line, "=", 2)
			if len(parts) >= 1 {
				name := strings.TrimSpace(parts[0])
				if name != "" {
					deps = append(deps, name)
				}
			}
		}
	}

	return deps
}

// parseSetupPy does a minimal parse to find dependency names from setup.py/setup.cfg
func parseSetupPy(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var deps []string
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Look for common patterns in install_requires or setup.cfg
		if strings.Contains(trimmed, "install_requires") {
			continue
		}
		// Try to extract quoted package names
		name := extractPythonPackageName(strings.Trim(trimmed, `",' `))
		if name != "" && !strings.Contains(name, "(") && !strings.Contains(name, "=") &&
			!strings.HasPrefix(name, "#") && !strings.HasPrefix(name, "[") {
			deps = append(deps, name)
		}
	}

	return deps
}

// extractPythonPackageName extracts the package name before version specifiers
func extractPythonPackageName(line string) string {
	// Split on common version specifiers: >=, <=, ==, ~=, !=, >, <, ;, [
	for _, sep := range []string{">=", "<=", "==", "~=", "!=", ">", "<", ";", "["} {
		if idx := strings.Index(line, sep); idx > 0 {
			return strings.TrimSpace(line[:idx])
		}
	}

	// Handle Poetry-style: name = "version"
	if idx := strings.Index(line, "="); idx > 0 {
		candidate := strings.TrimSpace(line[:idx])
		// Make sure it looks like a package name (no spaces, not a section header)
		if !strings.Contains(candidate, " ") && !strings.HasPrefix(candidate, "[") {
			return candidate
		}
	}

	return strings.TrimSpace(line)
}
