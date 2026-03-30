package generators_test

import (
	"os"
	"strings"
	"testing"

	"github.com/edgarpsda/devsecops-kit/cli/detectors"
	"github.com/edgarpsda/devsecops-kit/cli/generators"
)

func TestGenerateGitLabCI(t *testing.T) {
	languages := []string{"nodejs", "golang", "python", "java"}

	for _, lang := range languages {
		t.Run(lang, func(t *testing.T) {
			dir := t.TempDir()
			orig, _ := os.Getwd()
			defer os.Chdir(orig)
			os.Chdir(dir)

			cfg := &generators.InitConfig{
				Project: &detectors.ProjectInfo{
					Language:  lang,
					Framework: "test",
				},
				CIProvider:        "gitlab",
				SeverityThreshold: "high",
				Tools: generators.ToolsConfig{
					Semgrep:  true,
					Trivy:    true,
					Gitleaks: true,
				},
			}

			err := generators.GenerateGitLabCI(cfg)
			if err != nil {
				t.Fatalf("GenerateGitLabCI(%s) failed: %v", lang, err)
			}

			data, err := os.ReadFile(".gitlab-ci.yml")
			if err != nil {
				t.Fatalf("failed to read .gitlab-ci.yml: %v", err)
			}

			content := string(data)
			if !strings.Contains(content, "stages:") {
				t.Error("expected 'stages:' in .gitlab-ci.yml")
			}
			if !strings.Contains(content, "security-scan:") {
				t.Error("expected 'security-scan:' job in .gitlab-ci.yml")
			}
			if !strings.Contains(content, "semgrep") {
				t.Error("expected semgrep step in .gitlab-ci.yml")
			}
			if !strings.Contains(content, "gitleaks") {
				t.Error("expected gitleaks step in .gitlab-ci.yml")
			}
			if !strings.Contains(content, "trivy") {
				t.Error("expected trivy step in .gitlab-ci.yml")
			}
		})
	}
}

func TestGenerateBitbucketPipelines(t *testing.T) {
	languages := []string{"nodejs", "golang", "python", "java"}

	for _, lang := range languages {
		t.Run(lang, func(t *testing.T) {
			dir := t.TempDir()
			orig, _ := os.Getwd()
			defer os.Chdir(orig)
			os.Chdir(dir)

			cfg := &generators.InitConfig{
				Project: &detectors.ProjectInfo{
					Language:  lang,
					Framework: "test",
				},
				CIProvider:        "bitbucket",
				SeverityThreshold: "high",
				Tools: generators.ToolsConfig{
					Semgrep:  true,
					Trivy:    true,
					Gitleaks: true,
				},
			}

			err := generators.GenerateBitbucketPipelines(cfg)
			if err != nil {
				t.Fatalf("GenerateBitbucketPipelines(%s) failed: %v", lang, err)
			}

			data, err := os.ReadFile("bitbucket-pipelines.yml")
			if err != nil {
				t.Fatalf("failed to read bitbucket-pipelines.yml: %v", err)
			}

			content := string(data)
			if !strings.Contains(content, "pipelines:") {
				t.Error("expected 'pipelines:' in bitbucket-pipelines.yml")
			}
			if !strings.Contains(content, "Security Scan") {
				t.Error("expected 'Security Scan' step in bitbucket-pipelines.yml")
			}
			if !strings.Contains(content, "semgrep") {
				t.Error("expected semgrep step in bitbucket-pipelines.yml")
			}
		})
	}
}

func TestUnsupportedCILanguage(t *testing.T) {
	dir := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)
	os.Chdir(dir)

	cfg := &generators.InitConfig{
		Project: &detectors.ProjectInfo{
			Language:  "ruby",
			Framework: "rails",
		},
		CIProvider: "gitlab",
	}

	err := generators.GenerateGitLabCI(cfg)
	if err == nil {
		t.Error("expected error for unsupported language, got nil")
	}
}
