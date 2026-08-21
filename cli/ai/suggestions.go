package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/edgarpsda/devsecops-kit/cli/scanners"
)

// Config holds AI provider configuration
type Config struct {
	Enabled  bool
	Provider string // "ollama", "openai", "anthropic"
	Model    string
	Endpoint string // optional provider endpoint or approved AI gateway
	APIKey   string // for openai/anthropic; reads from env if empty
}

// Client generates fix suggestions for security findings
type Client struct {
	cfg   Config
	cache *Cache
	http  *http.Client
}

// NewClient creates an AI client with the given config
func NewClient(cfg Config) *Client {
	if cfg.Provider == "ollama" && cfg.Endpoint == "" {
		cfg.Endpoint = "http://localhost:11434"
	}

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

	return &Client{
		cfg:   cfg,
		cache: NewCache(),
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

// EnrichFindings adds AI fix suggestions to findings in-place.
// Only HIGH and CRITICAL findings are enriched to keep noise low.
// Results are cached so identical rule+message pairs are only sent once.
func (c *Client) EnrichFindings(findings []scanners.Finding) {
	for i := range findings {
		f := &findings[i]
		if f.Severity != "CRITICAL" && f.Severity != "HIGH" {
			continue
		}

		cacheKey := cacheKey(f.RuleID, f.Message)
		if suggestion, ok := c.cache.Get(cacheKey); ok {
			f.AISuggestion = suggestion
			continue
		}

		suggestion, err := c.getSuggestion(f)
		if err != nil {
			// Non-fatal: just skip this finding
			continue
		}

		c.cache.Set(cacheKey, suggestion)
		f.AISuggestion = suggestion
	}
}

// Complete sends a prompt to the configured AI provider and returns the raw response.
func (c *Client) Complete(prompt string) (string, error) {
	return c.complete(prompt)
}

func (c *Client) getSuggestion(f *scanners.Finding) (string, error) {
	prompt := buildPrompt(f)
	return c.complete(prompt)
}

func (c *Client) complete(prompt string) (string, error) {
	switch c.cfg.Provider {
	case "openai":
		return c.callOpenAI(prompt)
	case "anthropic":
		return c.callAnthropic(prompt)
	default:
		return c.callOllama(prompt)
	}
}

// buildPrompt constructs a concise, focused prompt for the finding
func buildPrompt(f *scanners.Finding) string {
	return fmt.Sprintf(
		"You are a security expert. Provide a concise fix suggestion (2-4 sentences max) for this security finding:\n\nTool: %s\nSeverity: %s\nRule: %s\nFile: %s\nIssue: %s\n\nRespond with only the fix suggestion, no preamble.",
		f.Tool, f.Severity, f.RuleID, f.File, f.Message,
	)
}

func (c *Client) openAIEndpoint() string {
	if c.cfg.Endpoint == "" {
		return "https://api.openai.com/v1/chat/completions"
	}
	return joinEndpoint(c.cfg.Endpoint, "/chat/completions")
}

func (c *Client) anthropicEndpoint() string {
	if c.cfg.Endpoint == "" {
		return "https://api.anthropic.com/v1/messages"
	}
	return joinEndpoint(c.cfg.Endpoint, "/messages")
}

func joinEndpoint(base, path string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, path) {
		return base
	}
	return base + path
}

// --- Ollama ---

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

func (c *Client) callOllama(prompt string) (string, error) {
	body, _ := json.Marshal(ollamaRequest{
		Model:  c.cfg.Model,
		Prompt: prompt,
		Stream: false,
	})

	resp, err := c.http.Post(joinEndpoint(c.cfg.Endpoint, "/api/generate"), "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("ollama request failed: %w", err)
	}
	defer resp.Body.Close()

	var result ollamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ollama response decode failed: %w", err)
	}
	if result.Error != "" {
		return "", fmt.Errorf("ollama error: %s", result.Error)
	}

	return strings.TrimSpace(result.Response), nil
}

// --- OpenAI ---

type openAIRequest struct {
	Model    string          `json:"model"`
	Messages []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *Client) callOpenAI(prompt string) (string, error) {
	body, _ := json.Marshal(openAIRequest{
		Model: c.cfg.Model,
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
	})

	req, _ := http.NewRequest("POST", c.openAIEndpoint(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	var result openAIResponse
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

// --- Anthropic ---

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *Client) callAnthropic(prompt string) (string, error) {
	body, _ := json.Marshal(anthropicRequest{
		Model:     c.cfg.Model,
		MaxTokens: 256,
		Messages: []anthropicMessage{
			{Role: "user", Content: prompt},
		},
	})

	req, _ := http.NewRequest("POST", c.anthropicEndpoint(), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	rawBody, _ := io.ReadAll(resp.Body)
	var result anthropicResponse
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
