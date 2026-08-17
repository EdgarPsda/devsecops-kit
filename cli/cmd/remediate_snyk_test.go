package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSnykResultsSingleProject(t *testing.T) {
	data := []byte(`{
		"projectName": "spring-app",
		"packageManager": "maven",
		"displayTargetFile": "pom.xml",
		"vulnerabilities": [
			{
				"id": "SNYK-JAVA-ORGSPRINGFRAMEWORK-123",
				"title": "Example vuln",
				"severity": "high",
				"packageName": "org.springframework:spring-web",
				"version": "5.3.0",
				"isUpgradable": true,
				"nearestFixedInVersion": "5.3.39"
			}
		]
	}`)

	results, err := parseSnykResults(data)
	if err != nil {
		t.Fatalf("expected snyk result to parse: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one result, got %d", len(results))
	}
	if len(results[0].Vulnerabilities) != 1 {
		t.Fatalf("expected one vulnerability, got %d", len(results[0].Vulnerabilities))
	}
}

func TestParseSnykResultsAllProjectsArray(t *testing.T) {
	data := []byte(`[
		{
			"projectName": "backend",
			"packageManager": "maven",
			"displayTargetFile": "backend/pom.xml",
			"vulnerabilities": []
		},
		{
			"projectName": "frontend",
			"packageManager": "npm",
			"displayTargetFile": "frontend/package.json",
			"vulnerabilities": [
				{ "id": "SNYK-JS-LODASH-567746", "severity": "critical", "packageName": "lodash" }
			]
		}
	]`)

	results, err := parseSnykResults(data)
	if err != nil {
		t.Fatalf("expected snyk all-projects result to parse: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected two results, got %d", len(results))
	}
}

func TestSnykHighCriticalFiltersMedium(t *testing.T) {
	findings := []snykVulnerability{
		{ID: "low", Severity: "low"},
		{ID: "medium", Severity: "medium"},
		{ID: "high", Severity: "high"},
		{ID: "critical", Severity: "critical"},
	}

	targets := snykHighCritical(findings)
	if len(targets) != 2 {
		t.Fatalf("expected two high/critical targets, got %d", len(targets))
	}
}

func TestSnykManifestPathUsesProjectPathAndTarget(t *testing.T) {
	finding := snykVulnerability{
		ProjectPath: "backend",
		TargetFile:  "pom.xml",
	}

	if got := snykManifestPath(finding); got != "backend/pom.xml" {
		t.Fatalf("expected backend/pom.xml, got %s", got)
	}
}

func TestSnykManifestFileNormalizesAbsoluteProjectPath(t *testing.T) {
	root := t.TempDir()
	result := snykScanResult{
		Path:              root,
		DisplayTargetFile: "pom.xml",
		PackageManager:    "maven",
	}

	if got := snykManifestFile(root, result); got != "pom.xml" {
		t.Fatalf("expected pom.xml, got %s", got)
	}
}

func TestSnykManifestFileNormalizesAbsoluteTargetFile(t *testing.T) {
	root := t.TempDir()
	result := snykScanResult{
		DisplayTargetFile: filepath.Join(root, "pom.xml"),
		PackageManager:    "maven",
	}

	if got := snykManifestFile(root, result); got != "pom.xml" {
		t.Fatalf("expected pom.xml, got %s", got)
	}
}

func TestGroupSnykFindingsGroupsByManifestAndPackage(t *testing.T) {
	findings := []snykVulnerability{
		{ID: "one", PackageName: "org.postgresql:postgresql", TargetFile: "pom.xml"},
		{ID: "two", PackageName: "org.postgresql:postgresql", TargetFile: "pom.xml"},
		{ID: "three", PackageName: "ch.qos.logback:logback-core", TargetFile: "pom.xml"},
	}

	groups := groupSnykFindings(findings)
	if len(groups) != 2 {
		t.Fatalf("expected two remediation groups, got %d", len(groups))
	}
	if len(groups[0].Findings) != 2 {
		t.Fatalf("expected first group to contain two findings, got %d", len(groups[0].Findings))
	}
	if groups[0].PackageName != "org.postgresql:postgresql" {
		t.Fatalf("expected postgresql group first, got %s", groups[0].PackageName)
	}
}

func TestGroupSnykFindingsPrioritizesSpringBootParentCandidates(t *testing.T) {
	findings := []snykVulnerability{
		{ID: "spring-core", PackageName: "org.springframework:spring-core", TargetFile: "pom.xml"},
		{ID: "boot", PackageName: "org.springframework.boot:spring-boot", TargetFile: "pom.xml"},
		{ID: "postgres", PackageName: "org.postgresql:postgresql", TargetFile: "pom.xml"},
	}

	groups := groupSnykFindings(findings)
	if groups[0].PackageName != "org.springframework.boot:spring-boot" {
		t.Fatalf("expected spring boot group first, got %s", groups[0].PackageName)
	}
}

func TestSnykGroupFixedVersionPrefersNearestFixedVersion(t *testing.T) {
	group := snykRemediationGroup{
		PackageName:  "org.postgresql:postgresql",
		ManifestFile: "pom.xml",
		Findings: []snykVulnerability{
			{NearestFixedInVersion: "42.3.9"},
			{FixedIn: []string{"42.7.2", "42.7.7"}},
		},
	}

	if got := snykGroupFixedVersion(group); got != "42.3.9" {
		t.Fatalf("expected 42.3.9, got %s", got)
	}
}

func TestSnykGroupFixedVersionUsesHighestNearestFixedVersion(t *testing.T) {
	group := snykRemediationGroup{
		PackageName:  "ch.qos.logback:logback-core",
		ManifestFile: "pom.xml",
		Findings: []snykVulnerability{
			{NearestFixedInVersion: "1.4.12"},
			{NearestFixedInVersion: "1.5.13"},
		},
	}

	if got := snykGroupFixedVersion(group); got != "1.5.13" {
		t.Fatalf("expected 1.5.13, got %s", got)
	}
}

func TestUpdateSpringBootParentVersion(t *testing.T) {
	pom := `<project>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.3.5</version>
        <relativePath/>
    </parent>
</project>`

	updated, changed := updateSpringBootParentVersion(pom, "3.3.13")
	if !changed {
		t.Fatal("expected spring boot parent version to change")
	}
	if !strings.Contains(updated, "<version>3.3.13</version>") {
		t.Fatalf("expected updated parent version in pom, got %s", updated)
	}
}

func TestUpdateDirectMavenDependencyVersion(t *testing.T) {
	pom := `<project>
    <dependencies>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>42.3.3</version>
        </dependency>
    </dependencies>
</project>`

	updated, changed := updateDirectMavenDependencyVersion(pom, "org.postgresql", "postgresql", "42.7.7")
	if !changed {
		t.Fatal("expected dependency version to change")
	}
	if !strings.Contains(updated, "<version>42.7.7</version>") {
		t.Fatalf("expected updated version in pom, got %s", updated)
	}
}
