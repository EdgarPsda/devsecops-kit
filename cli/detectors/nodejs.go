// cli/detectors/nodejs.go
package detectors

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type NodeDetector struct {
	confidence int
}

type PackageJSON struct {
	Name            string            `json:"name"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (d *NodeDetector) Detect(dir string) (*ProjectInfo, error) {
	pkgPath := filepath.Join(dir, "package.json")

	if !fileExists(pkgPath) {
		d.confidence = 0
		return nil, errors.New("package.json not found")
	}

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		d.confidence = 0
		return nil, err
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		d.confidence = 0
		return nil, err
	}

	framework := detectNodeFramework(&pkg)
	deps := collectNodeDeps(&pkg)

	// Heuristics: package.json present + parsed OK = high confidence.
	d.confidence = 95

	return &ProjectInfo{
		Language:     "nodejs",
		Framework:    framework,
		PackageFile:  "package.json",
		RootDir:      dir,
		Dependencies: deps,
	}, nil
}

func (d *NodeDetector) Confidence() int {
	return d.confidence
}

func detectNodeFramework(pkg *PackageJSON) string {
	// Basic heuristic:
	// - Next.js: "next"
	// - NestJS: "@nestjs/core"
	// - React SPA: "react" + no obvious backend
	// - Express: "express"
	if hasDep(pkg, "next") {
		return "nextjs"
	}
	if hasDep(pkg, "@nestjs/core") {
		return "nestjs"
	}
	if hasDep(pkg, "express") {
		return "express"
	}
	if hasDep(pkg, "react") || hasDep(pkg, "react-dom") {
		return "react"
	}
	return ""
}

func hasDep(pkg *PackageJSON, name string) bool {
	if pkg.Dependencies != nil {
		if _, ok := pkg.Dependencies[name]; ok {
			return true
		}
	}
	if pkg.DevDependencies != nil {
		if _, ok := pkg.DevDependencies[name]; ok {
			return true
		}
	}
	return false
}

func collectNodeDeps(pkg *PackageJSON) []string {
	depsSet := make(map[string]struct{})

	for dep := range pkg.Dependencies {
		depsSet[dep] = struct{}{}
	}
	for dep := range pkg.DevDependencies {
		depsSet[dep] = struct{}{}
	}

	out := make([]string, 0, len(depsSet))
	for dep := range depsSet {
		out = append(out, dep)
	}
	return out
}
