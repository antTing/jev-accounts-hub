package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestParseDecideArgs(t *testing.T) {
	args, err := parseDecideArgs(map[string]json.RawMessage{
		"state":     json.RawMessage(`"ticket: refund"`),
		"questions": json.RawMessage(`{"urgent":{"type":"noul","instructions":"The ticket signals urgency"}}`),
	})
	if err != nil {
		t.Fatalf("parseDecideArgs returned error: %v", err)
	}
	if args.Model != defaultModel {
		t.Fatalf("default model = %q, want %q", args.Model, defaultModel)
	}
	if string(args.State) != `"ticket: refund"` {
		t.Fatalf("state changed: %s", args.State)
	}
	if string(args.Questions) != `{"urgent":{"type":"noul","instructions":"The ticket signals urgency"}}` {
		t.Fatalf("questions changed: %s", args.Questions)
	}
}

func TestParseDecideArgsPreservesStructuredState(t *testing.T) {
	args, err := parseDecideArgs(map[string]json.RawMessage{
		"state":     json.RawMessage(`{"ticket":{"subject":"refund"},"attempts":[1,2]}`),
		"questions": json.RawMessage(`{"urgent":{"type":"noul","instructions":"The ticket signals urgency"}}`),
	})
	if err != nil {
		t.Fatalf("parseDecideArgs returned error: %v", err)
	}
	if string(args.State) != `{"ticket":{"subject":"refund"},"attempts":[1,2]}` {
		t.Fatalf("structured state changed: %s", args.State)
	}
}

func TestParseDecideArgsRejectsInvalidQuestions(t *testing.T) {
	_, err := parseDecideArgs(map[string]json.RawMessage{
		"state":     json.RawMessage(`"hello"`),
		"questions": json.RawMessage(`[]`),
	})
	if err == nil || !strings.Contains(err.Error(), "questions") {
		t.Fatalf("error = %v, want questions validation error", err)
	}
}

func TestDecidePostsNativeSystemOneRequest(t *testing.T) {
	var got *http.Request
	server := &mcpServer{
		baseURL: "http://jev.test",
		apiKey:  "sk-jev-test",
		timeout: defaultTimeout,
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			got = request
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"answers":{"urgent":{"noul":true,"probability":0.9}}}`)),
				Header:     make(http.Header),
			}, nil
		})},
	}

	result, err := server.decide(decideArgs{
		State:     json.RawMessage(`{"ticket":"The ticket says production is blocked."}`),
		Model:     defaultModel,
		Questions: json.RawMessage(`{"urgent":{"type":"noul","instructions":"The state signals urgency"}}`),
		RequestID: "test-request",
	})
	if err != nil {
		t.Fatalf("decide returned error: %v", err)
	}
	if got == nil || got.URL.Path != "/v1/systemone" {
		t.Fatalf("request path = %v, want /v1/systemone", got.URL)
	}
	if got.Header.Get("Authorization") != "Bearer sk-jev-test" {
		t.Fatalf("authorization header = %q", got.Header.Get("Authorization"))
	}
	if got.Header.Get("X-Request-Id") != "test-request" {
		t.Fatalf("request id = %q", got.Header.Get("X-Request-Id"))
	}
	body, err := io.ReadAll(got.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if !strings.Contains(string(body), `"model":"jev-latest"`) || !strings.Contains(string(body), `"state":{"ticket":`) || !strings.Contains(string(body), `"questions"`) {
		t.Fatalf("request body = %s", body)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
