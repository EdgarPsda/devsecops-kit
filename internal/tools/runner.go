package tools

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Command creates an external tool command with platform-specific defaults.
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	applyEnvironment(cmd, name, runtime.GOOS)
	return cmd
}

func applyEnvironment(cmd *exec.Cmd, name, goos string) {
	if goos != "windows" {
		return
	}

	if toolName(name) != "semgrep" {
		return
	}

	// Semgrep runs through Python; on Windows CP1252 can fail on Unicode paths/output.
	cmd.Env = append(os.Environ(),
		"PYTHONUTF8=1",
		"PYTHONIOENCODING=utf-8",
	)
}

func toolName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	return strings.TrimSuffix(strings.ToLower(name), ".exe")
}
