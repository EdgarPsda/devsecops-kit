package remediation

import "testing"

func TestNewAIPatchProviderDefaults(t *testing.T) {
	provider := NewAIPatchProvider(AIPatchConfig{})

	if provider.cfg.Endpoint != "http://localhost:11434" {
		t.Fatalf("expected default endpoint, got %s", provider.cfg.Endpoint)
	}
	if provider.cfg.Model != "llama3" {
		t.Fatalf("expected default ollama model, got %s", provider.cfg.Model)
	}
	if provider.Provider() != "ollama" {
		t.Fatalf("expected default provider ollama, got %s", provider.Provider())
	}
}

func TestAIPatchProviderSupports(t *testing.T) {
	provider := NewAIPatchProvider(AIPatchConfig{Provider: "openai"})

	request := PatchRequest{
		Finding: Finding{
			File: "go.mod",
		},
		Recommendation: Recommendation{
			Title: "Upgrade vulnerable dependency",
		},
	}

	if !provider.Supports(request) {
		t.Fatal("expected provider to support request with finding file and recommendation title")
	}

	request.Recommendation.Title = ""
	if provider.Supports(request) {
		t.Fatal("expected provider not to support request without recommendation title")
	}
}

func TestParsePatchResponse(t *testing.T) {
	patch, err := parsePatchResponse(`extra text {"file":"go.mod","start_line":5,"end_line":5,"original":"old","replacement":"new"} trailing text`)
	if err != nil {
		t.Fatalf("expected patch response to parse: %v", err)
	}

	if patch.File != "go.mod" {
		t.Fatalf("expected file go.mod, got %s", patch.File)
	}
	if patch.Replacement != "new" {
		t.Fatalf("expected replacement new, got %s", patch.Replacement)
	}
}

func TestParsePatchResponseRejectsMissingJSON(t *testing.T) {
	if _, err := parsePatchResponse("no json here"); err == nil {
		t.Fatal("expected error for response without JSON object")
	}
}
