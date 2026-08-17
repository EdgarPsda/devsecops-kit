package remediation

// Engine coordinates remediation providers and validators.
type Engine struct {
	options                 Options
	findingProviders        []FindingProvider
	recommendationProviders []RecommendationProvider
	patchProviders          []PatchProvider
	gitClient               GitClient
	validationEngine        ValidationEngine
	providers               []Provider
	validators              []Validator
}

// NewEngine creates a remediation engine with the provided dependencies.
func NewEngine(options Options, providers []Provider, validators []Validator) *Engine {
	return &Engine{
		options:    options,
		providers:  append([]Provider(nil), providers...),
		validators: append([]Validator(nil), validators...),
	}
}

// NewEngineWithFindingProviders creates a remediation engine with finding providers.
func NewEngineWithFindingProviders(options Options, findingProviders []FindingProvider, providers []Provider, validators []Validator) *Engine {
	engine := NewEngine(options, providers, validators)
	engine.findingProviders = append([]FindingProvider(nil), findingProviders...)
	return engine
}

// NewEngineWithRecommendationProviders creates a remediation engine with recommendation providers.
func NewEngineWithRecommendationProviders(options Options, findingProviders []FindingProvider, recommendationProviders []RecommendationProvider, providers []Provider, validators []Validator) *Engine {
	engine := NewEngineWithFindingProviders(options, findingProviders, providers, validators)
	engine.recommendationProviders = append([]RecommendationProvider(nil), recommendationProviders...)
	return engine
}

// NewEngineWithPatchProviders creates a remediation engine with AI patch providers.
func NewEngineWithPatchProviders(options Options, findingProviders []FindingProvider, recommendationProviders []RecommendationProvider, patchProviders []PatchProvider, providers []Provider, validators []Validator) *Engine {
	engine := NewEngineWithRecommendationProviders(options, findingProviders, recommendationProviders, providers, validators)
	engine.patchProviders = append([]PatchProvider(nil), patchProviders...)
	return engine
}

// NewEngineWithGit creates a remediation engine with a Git client.
func NewEngineWithGit(options Options, findingProviders []FindingProvider, recommendationProviders []RecommendationProvider, patchProviders []PatchProvider, gitClient GitClient, providers []Provider, validators []Validator) *Engine {
	engine := NewEngineWithPatchProviders(options, findingProviders, recommendationProviders, patchProviders, providers, validators)
	engine.gitClient = gitClient
	return engine
}

// NewEngineWithValidation creates a remediation engine with validation support.
func NewEngineWithValidation(options Options, findingProviders []FindingProvider, recommendationProviders []RecommendationProvider, patchProviders []PatchProvider, gitClient GitClient, validationEngine ValidationEngine, providers []Provider, validators []Validator) *Engine {
	engine := NewEngineWithGit(options, findingProviders, recommendationProviders, patchProviders, gitClient, providers, validators)
	engine.validationEngine = validationEngine
	return engine
}

// Options returns the engine configuration.
func (e *Engine) Options() Options {
	return e.options
}

// FindingProviders returns the configured finding providers.
func (e *Engine) FindingProviders() []FindingProvider {
	return append([]FindingProvider(nil), e.findingProviders...)
}

// RecommendationProviders returns the configured recommendation providers.
func (e *Engine) RecommendationProviders() []RecommendationProvider {
	return append([]RecommendationProvider(nil), e.recommendationProviders...)
}

// PatchProviders returns the configured AI patch providers.
func (e *Engine) PatchProviders() []PatchProvider {
	return append([]PatchProvider(nil), e.patchProviders...)
}

// GitClient returns the configured Git client.
func (e *Engine) GitClient() GitClient {
	return e.gitClient
}

// ValidationEngine returns the configured validation engine.
func (e *Engine) ValidationEngine() ValidationEngine {
	return e.validationEngine
}

// Providers returns the configured remediation providers.
func (e *Engine) Providers() []Provider {
	return append([]Provider(nil), e.providers...)
}

// Validators returns the configured recommendation validators.
func (e *Engine) Validators() []Validator {
	return append([]Validator(nil), e.validators...)
}
