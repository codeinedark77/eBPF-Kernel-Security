// Package triage sends flagged (high-NCD-novelty) events to a local
// Ollama instance for a plain-language explanation. This is deliberately
// the LAST stage of the pipeline, not the first: the NCD scorer already
// did the actual detection work cheaply and without an LLM in the loop.
// The model's job here is narrow — summarize why a specific event looks
// unusual — not to re-derive novelty itself.
package triage

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

type Client struct {
	baseURL string
	model   string
	http    *http.Client
}

// NewClient defaults to a local Ollama instance. baseURL example:
// "http://127.0.0.1:11434" or, if driftnetd runs on a different tailnet
// node than Ollama, its Tailscale address e.g. "http://laptop.tailnet-name.ts.net:11434".
func NewClient(baseURL, model string) *Client {
	if model == "" {
		model = "llama3.1:8b-instruct-q4_K_M"
	}
	return &Client{
		baseURL: baseURL,
		model:   model,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type generateRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type generateResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

const triagePromptTemplate = `You are a terse security-triage assistant. An instrumentation pipeline flagged the following event as anomalous, using compression-based novelty detection (NCD score %.3f, flag threshold 0.5, 1.0 = maximally novel) and/or a known-bad-pattern rule match (matched rules: %s), relative to a device/app's recent baseline traffic.

Device: %s
App: %s
Event kind: %s
Raw detail (JSON): %s

In 2-3 sentences: explain plausible reasons this event differs from baseline. If this event appears highly malicious or is a critical zero-day threat (e.g., unexpected code execution, massive exfiltration, stealing credentials), you MUST end your response with the exact word: "VERDICT: BLOCK". Otherwise, end with "VERDICT: ALLOW". Be direct, no hedging filler.`

// Explain asks the local model for a short triage note on a flagged event.
func (c *Client) Explain(ctx context.Context, device, app, kind string, detail json.RawMessage, ncdScore float64, ruleMatches []string) (string, error) {
	ruleStr := "none"
	if len(ruleMatches) > 0 {
		ruleStr = strings.Join(ruleMatches, ", ")
	}
	prompt := fmt.Sprintf(triagePromptTemplate, ncdScore, ruleStr, device, app, kind, string(detail))

	reqBody, err := json.Marshal(generateRequest{
		Model: c.model,
		Messages: []message{
			{Role: "user", Content: prompt},
		},
		Stream: false,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm request failed (is it running at %s?): %w", c.baseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("llm returned %d: %s", resp.StatusCode, string(body))
	}

	var gr generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return "", err
	}
	
	if len(gr.Choices) > 0 {
		return gr.Choices[0].Message.Content, nil
	}
	return "", nil
}
