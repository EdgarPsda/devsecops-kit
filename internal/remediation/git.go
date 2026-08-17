package remediation

import "context"

// GitClient defines repository operations needed by remediation workflows.
type GitClient interface {
	CreateBranch(ctx context.Context, request GitBranchRequest) (*GitBranchResult, error)
	Diff(ctx context.Context, request GitDiffRequest) (*GitDiffResult, error)
	Rollback(ctx context.Context, request GitRollbackRequest) (*GitRollbackResult, error)
	HasChanges(ctx context.Context, request GitStatusRequest) (bool, error)
	ChangedFiles(ctx context.Context, request GitStatusRequest) (*GitStatusResult, error)
	RestoreFiles(ctx context.Context, request GitRestoreRequest) (*GitRestoreResult, error)
}

// GitBranchRequest describes a branch creation request.
type GitBranchRequest struct {
	RepositoryDir string            `json:"repository_dir,omitempty"`
	BaseBranch    string            `json:"base_branch,omitempty"`
	BranchName    string            `json:"branch_name"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// GitBranchResult contains branch creation details.
type GitBranchResult struct {
	BranchName string            `json:"branch_name"`
	BaseBranch string            `json:"base_branch,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// GitDiffRequest describes which repository changes should be diffed.
type GitDiffRequest struct {
	RepositoryDir string            `json:"repository_dir,omitempty"`
	BaseRef       string            `json:"base_ref,omitempty"`
	HeadRef       string            `json:"head_ref,omitempty"`
	Files         []string          `json:"files,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// GitDiffResult contains a repository diff.
type GitDiffResult struct {
	BaseRef  string            `json:"base_ref,omitempty"`
	HeadRef  string            `json:"head_ref,omitempty"`
	Files    []GitFileDiff     `json:"files,omitempty"`
	Patch    string            `json:"patch,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// GitFileDiff contains the diff for a single file.
type GitFileDiff struct {
	Path     string            `json:"path"`
	Status   string            `json:"status,omitempty"`
	Patch    string            `json:"patch,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// GitRollbackRequest describes a rollback operation.
type GitRollbackRequest struct {
	RepositoryDir string            `json:"repository_dir,omitempty"`
	TargetRef     string            `json:"target_ref,omitempty"`
	Files         []string          `json:"files,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// GitRollbackResult contains rollback details.
type GitRollbackResult struct {
	TargetRef string            `json:"target_ref,omitempty"`
	Files     []string          `json:"files,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// GitStatusRequest describes a repository status query.
type GitStatusRequest struct {
	RepositoryDir string            `json:"repository_dir,omitempty"`
	Files         []string          `json:"files,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// GitStatusResult contains changed file information.
type GitStatusResult struct {
	HasChanges bool              `json:"has_changes"`
	Files      []GitFileStatus   `json:"files,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// GitFileStatus describes the status of a changed file.
type GitFileStatus struct {
	Path     string            `json:"path"`
	Status   string            `json:"status"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// GitRestoreRequest describes files that should be restored.
type GitRestoreRequest struct {
	RepositoryDir string            `json:"repository_dir,omitempty"`
	Files         []string          `json:"files"`
	SourceRef     string            `json:"source_ref,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// GitRestoreResult contains restore details.
type GitRestoreResult struct {
	Files     []string          `json:"files"`
	SourceRef string            `json:"source_ref,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}
