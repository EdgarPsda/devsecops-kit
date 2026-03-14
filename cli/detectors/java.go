// cli/detectors/java.go
package detectors

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type JavaDetector struct {
	confidence int
}

func (d *JavaDetector) Detect(dir string) (*ProjectInfo, error) {
	// Check for Java project files
	packageFiles := []string{
		"pom.xml",
		"build.gradle",
		"build.gradle.kts",
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
		return nil, errors.New("no Java project file found")
	}

	deps := collectJavaDeps(filepath.Join(dir, foundFile), foundFile)
	framework := detectJavaFramework(deps, dir, foundFile)

	d.confidence = 95

	return &ProjectInfo{
		Language:     "java",
		Framework:    framework,
		PackageFile:  foundFile,
		RootDir:      dir,
		Dependencies: deps,
	}, nil
}

func (d *JavaDetector) Confidence() int {
	return d.confidence
}

func detectJavaFramework(deps []string, dir, packageFile string) string {
	// Check dependencies for known frameworks
	for _, dep := range deps {
		lower := strings.ToLower(dep)
		switch {
		case strings.Contains(lower, "spring-boot"):
			return "spring-boot"
		case strings.Contains(lower, "quarkus"):
			return "quarkus"
		case strings.Contains(lower, "micronaut"):
			return "micronaut"
		case strings.Contains(lower, "jakarta.ee") || strings.Contains(lower, "javax.servlet"):
			return "jakarta-ee"
		case strings.Contains(lower, "dropwizard"):
			return "dropwizard"
		}
	}

	// Also check the file content directly for Spring Boot parent POM
	if packageFile == "pom.xml" {
		data, err := os.ReadFile(filepath.Join(dir, packageFile))
		if err == nil {
			content := strings.ToLower(string(data))
			if strings.Contains(content, "spring-boot-starter-parent") ||
				strings.Contains(content, "spring-boot-starter") {
				return "spring-boot"
			}
		}
	}

	return ""
}

func collectJavaDeps(path, packageFile string) []string {
	switch {
	case packageFile == "pom.xml":
		return parsePomXML(path)
	case strings.HasPrefix(packageFile, "build.gradle"):
		return parseGradle(path)
	}
	return nil
}

// parsePomXML does a minimal parse to extract dependency artifact IDs from pom.xml
func parsePomXML(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)
	inDependency := false
	var currentGroup, currentArtifact string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "<dependency>") {
			inDependency = true
			currentGroup = ""
			currentArtifact = ""
			continue
		}

		if strings.Contains(line, "</dependency>") {
			if inDependency && (currentGroup != "" || currentArtifact != "") {
				dep := currentGroup
				if currentArtifact != "" {
					if dep != "" {
						dep += ":"
					}
					dep += currentArtifact
				}
				deps = append(deps, dep)
			}
			inDependency = false
			continue
		}

		if inDependency {
			if groupID := extractXMLValue(line, "groupId"); groupID != "" {
				currentGroup = groupID
			}
			if artifactID := extractXMLValue(line, "artifactId"); artifactID != "" {
				currentArtifact = artifactID
			}
		}
	}

	return deps
}

// parseGradle does a minimal parse to extract dependencies from build.gradle
func parseGradle(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var deps []string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Match patterns like: implementation 'group:artifact:version'
		// or: implementation "group:artifact:version"
		for _, keyword := range []string{"implementation", "api", "compileOnly", "runtimeOnly", "testImplementation"} {
			if strings.HasPrefix(line, keyword+" ") || strings.HasPrefix(line, keyword+"(") {
				dep := extractGradleDep(line)
				if dep != "" {
					deps = append(deps, dep)
				}
			}
		}
	}

	return deps
}

// extractXMLValue extracts the text content of a simple XML element
func extractXMLValue(line, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"

	startIdx := strings.Index(line, openTag)
	endIdx := strings.Index(line, closeTag)

	if startIdx >= 0 && endIdx > startIdx {
		return strings.TrimSpace(line[startIdx+len(openTag) : endIdx])
	}
	return ""
}

// extractGradleDep extracts the dependency coordinate from a Gradle dependency line
func extractGradleDep(line string) string {
	// Find the quoted string (single or double)
	for _, quote := range []string{"'", "\""} {
		start := strings.Index(line, quote)
		if start >= 0 {
			end := strings.Index(line[start+1:], quote)
			if end >= 0 {
				return line[start+1 : start+1+end]
			}
		}
	}
	return ""
}
