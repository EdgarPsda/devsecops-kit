package remediation

import "context"

// ValidationEngine verifies whether applied remediation changes are safe.
type ValidationEngine interface {
	Validate(ctx context.Context, request ValidationRequest) (*ValidationResult, error)
}

// ValidationRunner executes one validation check type.
type ValidationRunner interface {
	Name() string
	Type() ValidationType
	Validate(ctx context.Context, request ValidationRequest) (*ValidationCheckResult, error)
}

// ValidationType identifies a validation category.
type ValidationType string

// ValidationRequest describes changes that should be validated.
type ValidationRequest struct {
	ProjectDir     string            `json:"project_dir,omitempty"`
	Finding        Finding           `json:"finding"`
	Recommendation Recommendation    `json:"recommendation"`
	Patches        []Patch           `json:"patches,omitempty"`
	Diff           *GitDiffResult    `json:"diff,omitempty"`
	Checks         []ValidationType  `json:"checks,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// ValidationResult contains the overall validation outcome.
type ValidationResult struct {
	Status   string                  `json:"status"`
	Passed   bool                    `json:"passed"`
	Checks   []ValidationCheckResult `json:"checks,omitempty"`
	Metadata map[string]string       `json:"metadata,omitempty"`
	Error    error                   `json:"-"`
}

// ValidationCheckResult contains the outcome of a single validation check.
type ValidationCheckResult struct {
	Name     string            `json:"name"`
	Type     ValidationType    `json:"type"`
	Status   string            `json:"status"`
	Passed   bool              `json:"passed"`
	Output   string            `json:"output,omitempty"`
	Findings []Finding         `json:"findings,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    error             `json:"-"`
}
