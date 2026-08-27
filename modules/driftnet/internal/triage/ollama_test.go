package triage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockOllama spins up an httptest server shaped like Ollama's /api/generate
// endpoint. This is the first time this package's HTTP request/response
// code path has been exercised at all -- every earlier smoke test pointed
// -ollama at a real Ollama URL that was never actually running in the
// sandbox, so Explain()'s request formatting and response parsing were
// unverified until now.
func mockOllama(t *testing.T, checkPrompt func(prompt string), responseText string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("expected request to /api/generate, got %s", r.URL.Path)
		}
		var req generateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("server: decode request: %v", err)
		}
		if checkPrompt != nil {
			checkPrompt(req.Prompt)
		}
		if req.Stream {
			t.Errorf("expected Stream=false (we want a single response, not SSE chunks), got true")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(generateResponse{Response: responseText})
	}))
}

func TestExplain_SendsWellFormedRequestAndParsesResponse(t *testing.T) {
	var capturedPrompt string
	srv := mockOllama(t, func(p string) { capturedPrompt = p }, "This looks like a routine sync call, no concern.")
	defer srv.Close()

	c := NewClient(srv.URL, "test-model")
	note, err := c.Explain(context.Background(), "phone1", "com.example.app", "network",
		json.RawMessage(`{"host":"api.example.com"}`), 0.3, nil)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if note != "This looks like a routine sync call, no concern." {
		t.Fatalf("unexpected response text: %q", note)
	}
	if !strings.Contains(capturedPrompt, "phone1") || !strings.Contains(capturedPrompt, "com.example.app") {
		t.Fatalf("prompt missing device/app context: %s", capturedPrompt)
	}
	if !strings.Contains(capturedPrompt, "0.300") {
		t.Fatalf("prompt missing NCD score: %s", capturedPrompt)
	}
}

func TestExplain_NoRuleMatchesRendersAsNone(t *testing.T) {
	var capturedPrompt string
	srv := mockOllama(t, func(p string) { capturedPrompt = p }, "ok")
	defer srv.Close()

	c := NewClient(srv.URL, "test-model")
	_, err := c.Explain(context.Background(), "phone1", "app", "network",
		json.RawMessage(`{}`), 0.9, nil)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if !strings.Contains(capturedPrompt, "matched rules: none") {
		t.Fatalf("expected 'matched rules: none' in prompt for empty ruleMatches, got: %s", capturedPrompt)
	}
}

func TestExplain_RuleMatchesAppearInPrompt(t *testing.T) {
	// This is the specific bug found and fixed while wiring this test:
	// Explain() previously didn't accept rule matches at all, so an event
	// flagged only by a rule (e.g. weak_cipher, with a low NCD score) got
	// a triage prompt that never mentioned WHY it was flagged.
	var capturedPrompt string
	srv := mockOllama(t, func(p string) { capturedPrompt = p }, "ok")
	defer srv.Close()

	c := NewClient(srv.URL, "test-model")
	_, err := c.Explain(context.Background(), "phone1", "app", "crypto",
		json.RawMessage(`{"transformation":"DES/ECB/NoPadding"}`), 0.05, []string{"weak_cipher"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if !strings.Contains(capturedPrompt, "matched rules: weak_cipher") {
		t.Fatalf("expected 'matched rules: weak_cipher' in prompt, got: %s", capturedPrompt)
	}
}

func TestExplain_UnreachableServerReturnsClearError(t *testing.T) {
	// Point at a port nothing is listening on -- this is the exact
	// situation every driftnetd smoke test in this sandbox was actually
	// in (no real Ollama running), so this test locks in that failure
	// mode is at least a clear, actionable error rather than a silent
	// hang or an unhelpful message.
	c := NewClient("http://127.0.0.1:1", "test-model")
	_, err := c.Explain(context.Background(), "phone1", "app", "network", json.RawMessage(`{}`), 0.5, nil)
	if err == nil {
		t.Fatal("expected an error when Ollama is unreachable, got nil")
	}
	if !strings.Contains(err.Error(), "is it running") {
		t.Fatalf("expected error to hint at the likely cause (Ollama not running), got: %v", err)
	}
}

func TestExplain_NonOKStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("model not found"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "nonexistent-model")
	_, err := c.Explain(context.Background(), "phone1", "app", "network", json.RawMessage(`{}`), 0.5, nil)
	if err == nil {
		t.Fatal("expected an error on 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "model not found") {
		t.Fatalf("expected error to include server's response body, got: %v", err)
	}
}
