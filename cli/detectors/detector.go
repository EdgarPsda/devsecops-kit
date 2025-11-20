// cli/detectors/detector.go
package detectors

import (
	"errors"
	"os"
	"path/filepath"
)

// ProjectInfo contains detected project information
type ProjectInfo struct {
	Language     string   // e.g. "nodejs", "golang"
	Framework    string   // e.g. "express", "nextjs", "gin"
	PackageFile  string   // e.g. "package.json", "go.mod"
	RootDir      string   // project root directory
	Dependencies []string // coarse list of deps (for future heuristics)
}

// Detector interface for language/framework detection
type Detector interface {
	Detect(dir string) (*ProjectInfo, error)
	Confidence() int // 0-100, used to pick best match
}

// DetectProject tries all detectors and returns the best match
func DetectProject(dir string) (*ProjectInfo, error) {
	detectors := []Detector{
		&NodeDetector{},
		&GoDetector{},
		// Add more detectors here in the future
	}

	var bestMatch *ProjectInfo
	bestConfidence := 0

	for _, d := range detectors {
		info, err := d.Detect(dir)
		if err != nil {
			// Not a fatal error: just means this detector didn't match
			continue
		}

		conf := d.Confidence()
		if conf > bestConfidence && info != nil {
			bestMatch = info
			bestConfidence = conf
		}
	}

	if bestMatch == nil {
		return nil, errors.New("no supported project type detected")
	}

	return bestMatch, nil
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// findUp tries to find a file by walking up from the given directory
// (not strictly needed yet, but useful later if we want smarter detection)
func findUp(startDir, target string) (string, bool) {
	dir := startDir

	for {
		candidate := filepath.Join(dir, target)
		if fileExists(candidate) {
			return candidate, true
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			return "", false
		}
		dir = parent
	}
}
