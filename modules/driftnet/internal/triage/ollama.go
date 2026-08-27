package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	model   string
	http    *http.Client
}

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

func (c *Client) Explain(ctx context.Context, device, app, kind string, detail json.RawMessage, ncdScore float64, ruleMatches []string) (string, error) {
	// [LAZY AI ORCHESTRATION]
	// Signal the Android host watchdog to start the LLM
	log.Println("[Lazy AI] Waking up LLM Engine natively on GPU via state file...")
	os.WriteFile("/root/llm_state", []byte("1"), 0644)
	
	defer func() {
		log.Println("[Lazy AI] Triage complete. Shutting down LLM Engine to save battery.")
		os.WriteFile("/root/llm_state", []byte("0"), 0644)
	}()

	// Wait for LLM to come online
	ready := false
	for i := 0; i < 30; i++ {
		time.Sleep(1 * time.Second)
		resp, err := c.http.Get(c.baseURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			ready = true
			break
		}
	}
	if !ready {
		return "", fmt.Errorf("timeout waiting for Lazy AI engine to wake up")
	}

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
		return "", fmt.Errorf("llm request failed: %w", err)
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
