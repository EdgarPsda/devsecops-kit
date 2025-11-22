// cli/detectors/detector.go
package detectors

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ProjectInfo contains detected project information
type ProjectInfo struct {
	Language     string   // e.g. "nodejs", "golang"
	Framework    string   // e.g. "express", "nextjs", "gin"
	PackageFile  string   // e.g. "package.json", "go.mod"
	RootDir      string   // project root directory
	Dependencies []string // coarse list of deps (for future heuristics)
	HasDocker    bool     // true if Dockerfile detected
	DockerImages []string // list of Docker image names found
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

	// Check for Docker (can coexist with any language)
	detectDocker(dir, bestMatch)

	return bestMatch, nil
}

// detectDocker checks for Dockerfile and docker-compose.yml, updates ProjectInfo in-place
func detectDocker(dir string, info *ProjectInfo) {
	// Check for Dockerfile
	dockerfilePath := filepath.Join(dir, "Dockerfile")
	if fileExists(dockerfilePath) {
		info.HasDocker = true

		// Try to extract image names from Dockerfile
		images := extractDockerImages(dockerfilePath)
		info.DockerImages = images
	}

	// Also check for docker-compose.yml (indicates Docker usage)
	composePaths := []string{
		filepath.Join(dir, "docker-compose.yml"),
		filepath.Join(dir, "docker-compose.yaml"),
	}

	for _, composePath := range composePaths {
		if fileExists(composePath) {
			info.HasDocker = true
			break
		}
	}
}

// extractDockerImages parses Dockerfile to find image references
// Returns a simple heuristic: finds lines like "FROM image:tag"
func extractDockerImages(dockerfilePath string) []string {
	data, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return nil
	}

	var images []string
	content := string(data)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for "FROM <image>"
		if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
			parts := strings.Fields(line) // Split by whitespace
			if len(parts) >= 2 {
				image := parts[1]
				// Skip build stages (FROM ... AS stage_name)
				// Check if next word is "AS"
				if len(parts) >= 3 && strings.ToUpper(parts[2]) == "AS" {
					continue // This is a build stage, skip it
				}
				images = append(images, image)
			}
		}
	}

	return images
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
