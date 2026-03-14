package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJavaDetector_Detect_SpringBoot_Maven(t *testing.T) {
	dir := t.TempDir()

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.2.0</version>
    </parent>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
        </dependency>
    </dependencies>
</project>`

	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pomXML), 0o644); err != nil {
		t.Fatalf("failed to write pom.xml: %v", err)
	}

	d := &JavaDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "java" {
		t.Errorf("expected Language=java, got %s", info.Language)
	}
	if info.Framework != "spring-boot" {
		t.Errorf("expected Framework=spring-boot, got %s", info.Framework)
	}
	if info.PackageFile != "pom.xml" {
		t.Errorf("expected PackageFile=pom.xml, got %s", info.PackageFile)
	}
	if d.Confidence() <= 0 {
		t.Errorf("expected confidence > 0, got %d", d.Confidence())
	}
	if len(info.Dependencies) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(info.Dependencies))
	}
}

func TestJavaDetector_Detect_Gradle(t *testing.T) {
	dir := t.TempDir()

	buildGradle := `plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa:3.2.0'
    testImplementation 'org.springframework.boot:spring-boot-starter-test:3.2.0'
    runtimeOnly 'org.postgresql:postgresql:42.7.0'
}
`

	if err := os.WriteFile(filepath.Join(dir, "build.gradle"), []byte(buildGradle), 0o644); err != nil {
		t.Fatalf("failed to write build.gradle: %v", err)
	}

	d := &JavaDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Language != "java" {
		t.Errorf("expected Language=java, got %s", info.Language)
	}
	if info.Framework != "spring-boot" {
		t.Errorf("expected Framework=spring-boot, got %s", info.Framework)
	}
	if info.PackageFile != "build.gradle" {
		t.Errorf("expected PackageFile=build.gradle, got %s", info.PackageFile)
	}
	if len(info.Dependencies) != 4 {
		t.Errorf("expected 4 dependencies, got %d", len(info.Dependencies))
	}
}

func TestJavaDetector_Detect_Quarkus(t *testing.T) {
	dir := t.TempDir()

	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project>
    <dependencies>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-resteasy</artifactId>
        </dependency>
        <dependency>
            <groupId>io.quarkus</groupId>
            <artifactId>quarkus-hibernate-orm</artifactId>
        </dependency>
    </dependencies>
</project>`

	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pomXML), 0o644); err != nil {
		t.Fatalf("failed to write pom.xml: %v", err)
	}

	d := &JavaDetector{}
	info, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect returned error: %v", err)
	}

	if info.Framework != "quarkus" {
		t.Errorf("expected Framework=quarkus, got %s", info.Framework)
	}
}

func TestJavaDetector_Detect_NoProject(t *testing.T) {
	dir := t.TempDir()

	d := &JavaDetector{}
	_, err := d.Detect(dir)
	if err == nil {
		t.Error("expected error for empty directory, got nil")
	}
	if d.Confidence() != 0 {
		t.Errorf("expected confidence=0, got %d", d.Confidence())
	}
}
