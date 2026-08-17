package remediation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ApplyPatchRequest describes a safe patch application operation.
type ApplyPatchRequest struct {
	RepositoryDir string            `json:"repository_dir"`
	BaseBranch    string            `json:"base_branch,omitempty"`
	BranchName    string            `json:"branch_name"`
	Patch         Patch             `json:"patch"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// ApplyPatchResult contains the outcome of applying a patch.
type ApplyPatchResult struct {
	BranchName   string            `json:"branch_name"`
	ChangedFiles []GitFileStatus   `json:"changed_files,omitempty"`
	Diff         *GitDiffResult    `json:"diff,omitempty"`
	Patch        Patch             `json:"patch"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ApplyPatch applies a patch on a new branch and rolls back if any step fails.
func (e *Engine) ApplyPatch(ctx context.Context, request ApplyPatchRequest) (*ApplyPatchResult, error) {
	if e.options.DryRun {
		return nil, fmt.Errorf("cannot apply patch while engine is in dry run mode")
	}
	if e.gitClient == nil {
		return nil, fmt.Errorf("git client is required to apply patches")
	}
	if request.RepositoryDir == "" {
		return nil, fmt.Errorf("repository directory is required")
	}
	if request.BranchName == "" {
		return nil, fmt.Errorf("branch name is required")
	}

	branch, err := e.gitClient.CreateBranch(ctx, GitBranchRequest{
		RepositoryDir: request.RepositoryDir,
		BaseBranch:    request.BaseBranch,
		BranchName:    request.BranchName,
		Metadata:      request.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create remediation branch: %w", err)
	}

	if err := applyPatchToFile(request.RepositoryDir, request.Patch); err != nil {
		return nil, e.rollbackPatch(ctx, request, fmt.Errorf("failed to apply patch: %w", err))
	}

	status, err := e.gitClient.ChangedFiles(ctx, GitStatusRequest{
		RepositoryDir: request.RepositoryDir,
		Files:         []string{request.Patch.File},
		Metadata:      request.Metadata,
	})
	if err != nil {
		return nil, e.rollbackPatch(ctx, request, fmt.Errorf("failed to detect changed files: %w", err))
	}
	if len(status.Files) == 0 {
		return nil, e.rollbackPatch(ctx, request, fmt.Errorf("no changed files detected after applying patch"))
	}

	diff, err := e.gitClient.Diff(ctx, GitDiffRequest{
		RepositoryDir: request.RepositoryDir,
		BaseRef:       request.BaseBranch,
		HeadRef:       branch.BranchName,
		Files:         changedFilePaths(status.Files),
		Metadata:      request.Metadata,
	})
	if err != nil {
		return nil, e.rollbackPatch(ctx, request, fmt.Errorf("failed to get remediation diff: %w", err))
	}

	return &ApplyPatchResult{
		BranchName:   branch.BranchName,
		ChangedFiles: status.Files,
		Diff:         diff,
		Patch:        request.Patch,
		Metadata:     request.Metadata,
	}, nil
}

func (e *Engine) rollbackPatch(ctx context.Context, request ApplyPatchRequest, cause error) error {
	if _, err := e.gitClient.Rollback(ctx, GitRollbackRequest{
		RepositoryDir: request.RepositoryDir,
		TargetRef:     request.BaseBranch,
		Files:         []string{request.Patch.File},
		Metadata:      request.Metadata,
	}); err != nil {
		return fmt.Errorf("%w; rollback failed: %v", cause, err)
	}

	if _, err := e.gitClient.RestoreFiles(ctx, GitRestoreRequest{
		RepositoryDir: request.RepositoryDir,
		Files:         []string{request.Patch.File},
		SourceRef:     request.BaseBranch,
		Metadata:      request.Metadata,
	}); err != nil {
		return fmt.Errorf("%w; restore failed: %v", cause, err)
	}

	return cause
}

func applyPatchToFile(repositoryDir string, patch Patch) error {
	path, err := resolvePatchPath(repositoryDir, patch.File)
	if err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat patch file: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("patch file is a directory: %s", patch.File)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read patch file: %w", err)
	}

	content := string(data)
	next, err := applyPatchContent(content, patch)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(next), info.Mode()); err != nil {
		return fmt.Errorf("failed to write patch file: %w", err)
	}

	return nil
}

func applyPatchContent(content string, patch Patch) (string, error) {
	if patch.Original != "" {
		count := strings.Count(content, patch.Original)
		if count == 0 {
			return "", fmt.Errorf("original patch content was not found")
		}
		if count > 1 {
			return "", fmt.Errorf("original patch content is ambiguous")
		}
		return strings.Replace(content, patch.Original, patch.Replacement, 1), nil
	}

	if patch.StartLine <= 0 || patch.EndLine < patch.StartLine {
		return "", fmt.Errorf("patch requires original content or a valid line range")
	}

	lines, newline := splitLines(content)
	if patch.EndLine > len(lines) {
		return "", fmt.Errorf("patch line range exceeds file length")
	}

	replacement := splitReplacement(patch.Replacement)
	next := append([]string{}, lines[:patch.StartLine-1]...)
	next = append(next, replacement...)
	next = append(next, lines[patch.EndLine:]...)

	return strings.Join(next, newline), nil
}

func resolvePatchPath(repositoryDir, patchFile string) (string, error) {
	if patchFile == "" {
		return "", fmt.Errorf("patch file is required")
	}
	if filepath.IsAbs(patchFile) {
		return "", fmt.Errorf("patch file must be relative to the repository")
	}

	root, err := filepath.Abs(repositoryDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve repository directory: %w", err)
	}

	path, err := filepath.Abs(filepath.Join(root, filepath.Clean(patchFile)))
	if err != nil {
		return "", fmt.Errorf("failed to resolve patch file: %w", err)
	}

	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("failed to validate patch file path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("patch file escapes repository directory")
	}

	return path, nil
}

func splitLines(content string) ([]string, string) {
	newline := "\n"
	if strings.Contains(content, "\r\n") {
		newline = "\r\n"
	}
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	return strings.Split(normalized, "\n"), newline
}

func splitReplacement(replacement string) []string {
	normalized := strings.ReplaceAll(replacement, "\r\n", "\n")
	return strings.Split(normalized, "\n")
}

func changedFilePaths(files []GitFileStatus) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}
	return paths
}
