package remediation

import (
	"context"
	"fmt"
)

// RemediationRequest describes a complete remediation workflow for one finding.
type RemediationRequest struct {
	RepositoryDir  string            `json:"repository_dir"`
	BaseBranch     string            `json:"base_branch,omitempty"`
	BranchName     string            `json:"branch_name"`
	Finding        Finding           `json:"finding"`
	Recommendation Recommendation    `json:"recommendation"`
	Patch          Patch             `json:"patch"`
	Checks         []ValidationType  `json:"checks,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

// RemediationResult contains the complete remediation workflow outcome.
type RemediationResult struct {
	Status     string             `json:"status"`
	Applied    *ApplyPatchResult  `json:"applied,omitempty"`
	Validation *ValidationResult  `json:"validation,omitempty"`
	Summary    RemediationSummary `json:"summary"`
	Error      error              `json:"-"`
}

// RemediationSummary contains counts that can be shown by the CLI.
type RemediationSummary struct {
	VulnerabilitiesFixed   int `json:"vulnerabilities_fixed"`
	VulnerabilitiesPending int `json:"vulnerabilities_pending"`
	ValidationsPassed      int `json:"validations_passed"`
	ValidationsFailed      int `json:"validations_failed"`
}

// Remediate applies a patch, validates it, and rolls back on validation failure.
func (e *Engine) Remediate(ctx context.Context, request RemediationRequest) (*RemediationResult, error) {
	if e.validationEngine == nil {
		return nil, fmt.Errorf("validation engine is required to complete remediation")
	}

	applyRequest := ApplyPatchRequest{
		RepositoryDir: request.RepositoryDir,
		BaseBranch:    request.BaseBranch,
		BranchName:    request.BranchName,
		Patch:         request.Patch,
		Metadata:      request.Metadata,
	}

	applied, err := e.ApplyPatch(ctx, applyRequest)
	if err != nil {
		result := failedRemediationResult(nil, nil, err)
		return result, err
	}

	validation, err := e.validationEngine.Validate(ctx, ValidationRequest{
		ProjectDir:     request.RepositoryDir,
		Finding:        request.Finding,
		Recommendation: request.Recommendation,
		Patches:        []Patch{request.Patch},
		Diff:           applied.Diff,
		Checks:         request.Checks,
		Metadata:       request.Metadata,
	})
	if err != nil {
		rollbackErr := e.rollbackPatch(ctx, applyRequest, fmt.Errorf("validation failed: %w", err))
		result := failedRemediationResult(applied, validation, rollbackErr)
		return result, rollbackErr
	}

	if validation == nil {
		rollbackErr := e.rollbackPatch(ctx, applyRequest, fmt.Errorf("validation engine returned no result"))
		result := failedRemediationResult(applied, nil, rollbackErr)
		return result, rollbackErr
	}

	if !validation.Passed {
		rollbackErr := e.rollbackPatch(ctx, applyRequest, fmt.Errorf("one or more validations failed"))
		result := failedRemediationResult(applied, validation, rollbackErr)
		return result, rollbackErr
	}

	return &RemediationResult{
		Status:     "success",
		Applied:    applied,
		Validation: validation,
		Summary:    buildRemediationSummary(validation, true),
	}, nil
}

func failedRemediationResult(applied *ApplyPatchResult, validation *ValidationResult, err error) *RemediationResult {
	return &RemediationResult{
		Status:     "failed",
		Applied:    applied,
		Validation: validation,
		Summary:    buildRemediationSummary(validation, false),
		Error:      err,
	}
}

func buildRemediationSummary(validation *ValidationResult, fixed bool) RemediationSummary {
	summary := RemediationSummary{}
	if fixed {
		summary.VulnerabilitiesFixed = 1
	} else {
		summary.VulnerabilitiesPending = 1
	}

	if validation == nil {
		if !fixed {
			summary.ValidationsFailed = 1
		}
		return summary
	}

	for _, check := range validation.Checks {
		if check.Passed {
			summary.ValidationsPassed++
		} else {
			summary.ValidationsFailed++
		}
	}

	if len(validation.Checks) == 0 && !validation.Passed {
		summary.ValidationsFailed = 1
	}

	return summary
}
