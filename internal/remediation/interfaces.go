package remediation

import "context"

// FindingProvider returns normalized findings from a source.
type FindingProvider interface {
	Name() string
	Source() FindingSource
	Findings(ctx context.Context, request FindingRequest) (*FindingSet, error)
}

// RecommendationProvider returns official recommendations for findings.
type RecommendationProvider interface {
	Name() string
	Source() RecommendationSource
	Supports(finding Finding) bool
	Recommendations(ctx context.Context, request RecommendationRequest) (*RecommendationSet, error)
}

// PatchProvider generates structured patches from findings and recommendations.
type PatchProvider interface {
	Name() string
	Provider() AIProvider
	Supports(request PatchRequest) bool
	GeneratePatch(ctx context.Context, request PatchRequest) (*PatchResponse, error)
}

// Provider creates remediation recommendations for supported findings.
type Provider interface {
	Name() string
	Supports(finding Finding) bool
	Recommend(ctx context.Context, finding Finding) (*Recommendation, error)
}

// Validator verifies whether a recommendation is safe to apply.
type Validator interface {
	Name() string
	Validate(ctx context.Context, recommendation Recommendation) error
}
