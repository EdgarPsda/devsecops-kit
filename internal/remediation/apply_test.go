package remediation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type fakeGitClient struct {
	createBranchCalls int
	changedFilesCalls int
	diffCalls         int
	rollbackCalls     int
	restoreCalls      int
	changedFilesErr   error
	diffErr           error
	changedFiles      []GitFileStatus
	restoreFunc       func(GitRestoreRequest) error
}

func (g *fakeGitClient) CreateBranch(ctx context.Context, request GitBranchRequest) (*GitBranchResult, error) {
	g.createBranchCalls++
	return &GitBranchResult{BranchName: request.BranchName, BaseBranch: request.BaseBranch}, nil
}

func (g *fakeGitClient) Diff(ctx context.Context, request GitDiffRequest) (*GitDiffResult, error) {
	g.diffCalls++
	if g.diffErr != nil {
		return nil, g.diffErr
	}
	return &GitDiffResult{
		BaseRef: request.BaseRef,
		HeadRef: request.HeadRef,
		Files: []GitFileDiff{
			{Path: request.Files[0], Status: "modified"},
		},
	}, nil
}

func (g *fakeGitClient) Rollback(ctx context.Context, request GitRollbackRequest) (*GitRollbackResult, error) {
	g.rollbackCalls++
	return &GitRollbackResult{TargetRef: request.TargetRef, Files: request.Files}, nil
}

func (g *fakeGitClient) HasChanges(ctx context.Context, request GitStatusRequest) (bool, error) {
	return len(g.changedFiles) > 0, nil
}

func (g *fakeGitClient) ChangedFiles(ctx context.Context, request GitStatusRequest) (*GitStatusResult, error) {
	g.changedFilesCalls++
	if g.changedFilesErr != nil {
		return nil, g.changedFilesErr
	}
	return &GitStatusResult{HasChanges: len(g.changedFiles) > 0, Files: g.changedFiles}, nil
}

func (g *fakeGitClient) RestoreFiles(ctx context.Context, request GitRestoreRequest) (*GitRestoreResult, error) {
	g.restoreCalls++
	if g.restoreFunc != nil {
		if err := g.restoreFunc(request); err != nil {
			return nil, err
		}
	}
	return &GitRestoreResult{Files: request.Files, SourceRef: request.SourceRef}, nil
}

func TestApplyPatchCreatesBranchAndReturnsChangedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte("package main\n\nconst version = \"old\"\n"), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	git := &fakeGitClient{
		changedFiles: []GitFileStatus{
			{Path: "main.go", Status: "modified"},
		},
	}
	engine := NewEngineWithGit(Options{}, nil, nil, nil, git, nil, nil)

	result, err := engine.ApplyPatch(context.Background(), ApplyPatchRequest{
		RepositoryDir: dir,
		BaseBranch:    "main",
		BranchName:    "remediation/test",
		Patch: Patch{
			File:        "main.go",
			Original:    `const version = "old"`,
			Replacement: `const version = "new"`,
		},
	})
	if err != nil {
		t.Fatalf("expected patch to apply: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read patched file: %v", err)
	}
	if string(data) != "package main\n\nconst version = \"new\"\n" {
		t.Fatalf("unexpected patched content: %s", string(data))
	}
	if result.BranchName != "remediation/test" {
		t.Fatalf("expected branch remediation/test, got %s", result.BranchName)
	}
	if len(result.ChangedFiles) != 1 || result.ChangedFiles[0].Path != "main.go" {
		t.Fatalf("expected exact changed file main.go, got %#v", result.ChangedFiles)
	}
	if git.createBranchCalls != 1 || git.changedFilesCalls != 1 || git.diffCalls != 1 {
		t.Fatalf("expected create, changed files, and diff calls; got create=%d changed=%d diff=%d", git.createBranchCalls, git.changedFilesCalls, git.diffCalls)
	}
	if git.rollbackCalls != 0 || git.restoreCalls != 0 {
		t.Fatalf("did not expect rollback or restore; got rollback=%d restore=%d", git.rollbackCalls, git.restoreCalls)
	}
}

func TestApplyPatchRollsBackWhenChangeDetectionFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	original := "package main\n\nconst version = \"old\"\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}

	git := &fakeGitClient{
		changedFilesErr: fmt.Errorf("status failed"),
		restoreFunc: func(request GitRestoreRequest) error {
			return os.WriteFile(filepath.Join(dir, request.Files[0]), []byte(original), 0o644)
		},
	}
	engine := NewEngineWithGit(Options{}, nil, nil, nil, git, nil, nil)

	_, err := engine.ApplyPatch(context.Background(), ApplyPatchRequest{
		RepositoryDir: dir,
		BaseBranch:    "main",
		BranchName:    "remediation/test",
		Patch: Patch{
			File:        "main.go",
			Original:    `const version = "old"`,
			Replacement: `const version = "new"`,
		},
	})
	if err == nil {
		t.Fatal("expected apply patch to fail")
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("failed to read restored file: %v", readErr)
	}
	if string(data) != original {
		t.Fatalf("expected file to be restored, got %s", string(data))
	}
	if git.rollbackCalls != 1 || git.restoreCalls != 1 {
		t.Fatalf("expected rollback and restore calls; got rollback=%d restore=%d", git.rollbackCalls, git.restoreCalls)
	}
}

func TestApplyPatchRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	git := &fakeGitClient{}
	engine := NewEngineWithGit(Options{}, nil, nil, nil, git, nil, nil)

	_, err := engine.ApplyPatch(context.Background(), ApplyPatchRequest{
		RepositoryDir: dir,
		BaseBranch:    "main",
		BranchName:    "remediation/test",
		Patch: Patch{
			File:        "../outside.go",
			Original:    "old",
			Replacement: "new",
		},
	})
	if err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
	if git.rollbackCalls != 1 || git.restoreCalls != 1 {
		t.Fatalf("expected rollback and restore after branch creation; got rollback=%d restore=%d", git.rollbackCalls, git.restoreCalls)
	}
}
