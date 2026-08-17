package remediation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AIPatchConfig holds AI patch provider configuration.
type AIPatchConfig struct {
	Provider string // "ollama", "openai", "anthropic"
	Model    string
	Endpoint string // for ollama; defaults to http://localhost:11434
	APIKey   string // for openai/anthropic
}

// AIPatchProvider generates structured patches using an AI backend.
type AIPatchProvider struct {
	cfg  AIPatchConfig
	http *http.Client
}

// NewAIPatchProvider creates an AI patch provider with the given config.
func NewAIPatchProvider(cfg AIPatchConfig) *AIPatchProvider {
	if cfg.Provider == "" {
		cfg.Provider = "ollama"
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	cfg.Endpoint = endpoint

	model := cfg.Model
	if model == "" {
		switch cfg.Provider {
		case "openai":
			model = "gpt-4o-mini"
		case "anthropic":
			model = "claude-haiku-4-5-20251001"
		default:
			model = "llama3"
		}
	}
	cfg.Model = model

	return &AIPatchProvider{
		cfg:  cfg,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// Name returns the provider name.
func (p *AIPatchProvider) Name() string {
	return "ai-patch"
}

// Provider returns the configured AI backend.
func (p *AIPatchProvider) Provider() AIProvider {
	return AIProvider(p.cfg.Provider)
}

// Supports reports whether the request has enough context to generate a patch.
func (p *AIPatchProvider) Supports(request PatchRequest) bool {
	return request.Finding.File != "" && request.Recommendation.Title != ""
}

// GeneratePatch generates a structured patch proposal without applying it.
func (p *AIPatchProvider) GeneratePatch(ctx context.Context, request PatchRequest) (*PatchResponse, error) {
	if !p.Supports(request) {
		return nil, fmt.Errorf("patch request is missing finding file or recommendation title")
	}

	prompt := buildPatchPrompt(request)
	rawPatch, err := p.call(ctx, prompt)
	if err != nil {
		return nil, err
	}

	patch, err := parsePatchResponse(rawPatch)
	if err != nil {
		return nil, err
	}
	if patch.File == "" {
		patch.File = request.Finding.File
	}

	return &PatchResponse{
		Provider: p.cfg.Provider,
		Model:    p.cfg.Model,
		Patch:    patch,
	}, nil
}

func (p *AIPatchProvider) call(ctx context.Context, prompt string) (string, error) {
	switch p.cfg.Provider {
	case "openai":
		return p.callOpenAI(ctx, prompt)
	case "anthropic":
		return p.callAnthropic(ctx, prompt)
	default:
		return p.callOllama(ctx, prompt)
	}
}

func buildPatchPrompt(request PatchRequest) string {
	var b strings.Builder
	b.WriteString("You are a security remediation agent. Generate one structured patch proposal.\n")
	b.WriteString("Do not describe steps outside the JSON response. Do not apply changes.\n")
	b.WriteString("Return only JSON with this shape: {\"file\":\"path\",\"start_line\":1,\"end_line\":1,\"original\":\"old text\",\"replacement\":\"new text\",\"metadata\":{\"reason\":\"short reason\"}}.\n\n")

	b.WriteString("Finding:\n")
	b.WriteString(fmt.Sprintf("- Tool: %s\n", request.Finding.Tool))
	b.WriteString(fmt.Sprintf("- Rule: %s\n", request.Finding.RuleID))
	b.WriteString(fmt.Sprintf("- Severity: %s\n", request.Finding.Severity))
	b.WriteString(fmt.Sprintf("- File: %s\n", request.Finding.File))
	b.WriteString(fmt.Sprintf("- Line: %d\n", request.Finding.Line))
	b.WriteString(fmt.Sprintf("- Message: %s\n\n", request.Finding.Message))

	b.WriteString("Recommendation:\n")
	b.WriteString(fmt.Sprintf("- Title: %s\n", request.Recommendation.Title))
	b.WriteString(fmt.Sprintf("- Description: %s\n", request.Recommendation.Description))
	if request.Recommendation.PackageImpact != nil {
		b.WriteString(fmt.Sprintf("- Package: %s\n", request.Recommendation.PackageImpact.Name))
		b.WriteString(fmt.Sprintf("- Current version: %s\n", request.Recommendation.PackageImpact.CurrentVersion))
		b.WriteString(fmt.Sprintf("- Fixed version: %s\n", request.Recommendation.PackageImpact.FixedVersion))
	}
	for _, step := range request.Recommendation.Steps {
		b.WriteString(fmt.Sprintf("- Step: %s %s %s\n", step.Action, step.Target, step.Value))
	}
	b.WriteString("\n")

	if len(request.Files) > 0 {
		b.WriteString("File context:\n")
		for _, file := range request.Files {
			b.WriteString(fmt.Sprintf("--- %s ---\n%s\n", file.Path, file.Content))
		}
	}

	return b.String()
}

func parsePatchResponse(response string) (Patch, error) {
	var patch Patch
	jsonResponse := extractJSONObject([]byte(response))
	if len(jsonResponse) == 0 {
		return patch, fmt.Errorf("ai patch response did not contain a JSON object")
	}
	if err := json.Unmarshal(jsonResponse, &patch); err != nil {
		return patch, fmt.Errorf("failed to parse ai patch response: %w", err)
	}
	return patch, nil
}

func extractJSONObject(data []byte) []byte {
	start := bytes.IndexByte(data, '{')
	if start == -1 {
		return nil
	}
	end := bytes.LastIndexByte(data, '}')
	if end == -1 || end < start {
		return nil
	}
	return data[start : end+1]
}

type aiPatchOllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type aiPatchOllamaResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

func (p *AIPatchProvider) callOllama(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(aiPatchOllamaRequest{
		Model:  p.cfg.Model,
		Prompt: prompt,
		Stream: false,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", p.cfg.Endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	var result aiPatchOllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ollama response decode failed: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("ollama error: %s", result.Error)
	}

	return strings.TrimSpace(result.Response), nil
}

type aiPatchOpenAIRequest struct {
	Model    string                 `json:"model"`
	Messages []aiPatchOpenAIMessage `json:"messages"`
}

type aiPatchOpenAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiPatchOpenAIResponse struct {
	Choices []struct {
		Message aiPatchOpenAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *AIPatchProvider) callOpenAI(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(aiPatchOpenAIRequest{
		Model: p.cfg.Model,
		Messages: []aiPatchOpenAIMessage{
			{Role: "user", Content: prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("openai request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.cfg.APIKey)

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	var result aiPatchOpenAIResponse
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return "", fmt.Errorf("openai response decode failed: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("openai error: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai returned no choices")
	}

	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}

type aiPatchAnthropicRequest struct {
	Model     string                    `json:"model"`
	MaxTokens int                       `json:"max_tokens"`
	Messages  []aiPatchAnthropicMessage `json:"messages"`
}

type aiPatchAnthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type aiPatchAnthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *AIPatchProvider) callAnthropic(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(aiPatchAnthropicRequest{
		Model:     p.cfg.Model,
		MaxTokens: 1024,
		Messages: []aiPatchAnthropicMessage{
			{Role: "user", Content: prompt},
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("anthropic request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := p.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	var result aiPatchAnthropicResponse
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return "", fmt.Errorf("anthropic response decode failed: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("anthropic error: %s", result.Error.Message)
	}
	if len(result.Content) == 0 {
		return "", fmt.Errorf("anthropic returned empty content")
	}

	return strings.TrimSpace(result.Content[0].Text), nil
}
