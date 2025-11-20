// cli/detectors/golang.go
package detectors

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type GoDetector struct {
	confidence int
}

func (d *GoDetector) Detect(dir string) (*ProjectInfo, error) {
	goModPath := filepath.Join(dir, "go.mod")

	if !fileExists(goModPath) {
		d.confidence = 0
		return nil, errors.New("go.mod not found")
	}

	deps, err := parseGoMod(goModPath)
	if err != nil {
		d.confidence = 0
		return nil, err
	}

	framework := detectGoFramework(deps)

	// go.mod present + parsed successfully = high confidence
	d.confidence = 95

	return &ProjectInfo{
		Language:     "golang",
		Framework:    framework,
		PackageFile:  "go.mod",
		RootDir:      dir,
		Dependencies: deps,
	}, nil
}

func (d *GoDetector) Confidence() int {
	return d.confidence
}

// parseGoMod does a minimal parse to extract required modules.
// It is intentionally simple; we don't need full go.mod parsing for MVP.
func parseGoMod(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)

	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}
		if inRequireBlock && strings.HasPrefix(line, ")") {
			inRequireBlock = false
			continue
		}

		// Single-line require: "require github.com/foo/bar v1.2.3"
		if strings.HasPrefix(line, "require ") && !strings.Contains(line, "(") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				deps = append(deps, fields[1])
			}
			continue
		}

		// Multi-line block: "github.com/foo/bar v1.2.3"
		if inRequireBlock && line != "" && !strings.HasPrefix(line, "//") {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				deps = append(deps, fields[0])
			}
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return deps, nil
}

func detectGoFramework(deps []string) string {
	for _, dep := range deps {
		switch {
		case strings.Contains(dep, "github.com/gin-gonic/gin"):
			return "gin"
		case strings.Contains(dep, "github.com/labstack/echo"):
			return "echo"
		case strings.Contains(dep, "github.com/gofiber/fiber"):
			return "fiber"
		case strings.Contains(dep, "github.com/gorilla/mux"):
			return "gorilla-mux"
		}
	}
	return ""
}
