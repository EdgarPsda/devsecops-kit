package tools

import (
	"os/exec"
	"testing"
)

func TestApplyEnvironmentAddsSemgrepWindowsUTF8Env(t *testing.T) {
	cmd := exec.Command("semgrep")
	applyEnvironment(cmd, "semgrep", "windows")

	if !hasEnv(cmd.Env, "PYTHONUTF8=1") {
		t.Fatal("expected PYTHONUTF8=1 for semgrep on windows")
	}
	if !hasEnv(cmd.Env, "PYTHONIOENCODING=utf-8") {
		t.Fatal("expected PYTHONIOENCODING=utf-8 for semgrep on windows")
	}
}

func TestApplyEnvironmentDoesNotModifySemgrepNonWindows(t *testing.T) {
	cmd := exec.Command("semgrep")
	applyEnvironment(cmd, "semgrep", "linux")

	if len(cmd.Env) != 0 {
		t.Fatalf("expected env to remain unset on non-windows, got %#v", cmd.Env)
	}
}

func TestApplyEnvironmentDoesNotModifyOtherToolsOnWindows(t *testing.T) {
	cmd := exec.Command("trivy")
	applyEnvironment(cmd, "trivy", "windows")

	if len(cmd.Env) != 0 {
		t.Fatalf("expected env to remain unset for non-semgrep tools, got %#v", cmd.Env)
	}
}

func TestToolNameNormalizesPathAndExtension(t *testing.T) {
	if got := toolName(`C:\Tools\semgrep.exe`); got != "semgrep" {
		t.Fatalf("expected semgrep, got %s", got)
	}
}

func hasEnv(env []string, keyValue string) bool {
	for _, item := range env {
		if item == keyValue {
			return true
		}
	}
	return false
}
