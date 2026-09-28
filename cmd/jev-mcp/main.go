// Command jev-mcp exposes the local jev-hub gateway as a small stdio MCP
// server. It deliberately keeps the gateway's native System One payload
// intact instead of pretending to be an OpenAI-compatible model provider.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL    = "http://127.0.0.1:8080"
	defaultModel      = "jev-latest"
	defaultTimeout    = 30 * time.Second
	maxInputBytes     = 8 << 20
	maxResponseBytes  = 8 << 20
	serverName        = "jev-hub"
	serverVersion     = "0.1.0"
	defaultMCPVersion = "2024-11-05"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type mcpServer struct {
	client    *http.Client
	baseURL   string
	apiKey    string
	timeout   time.Duration
	configErr error
}

type decideArgs struct {
	State     json.RawMessage
	Model     string
	Questions json.RawMessage
	RequestID string
}

func main() {
	server, err := newServer()
	if err != nil {
		// stdout is reserved for JSON-RPC messages. Diagnostics belong on stderr.
		fmt.Fprintln(os.Stderr, "jev-mcp:", err)
		server = &mcpServer{
			client:    &http.Client{Timeout: defaultTimeout},
			timeout:   defaultTimeout,
			configErr: err,
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var request rpcRequest
		if err := json.Unmarshal(line, &request); err != nil {
			_ = encoder.Encode(rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: -32700, Message: "parse error"},
			})
			continue
		}

		response, send := server.handle(request)
		if send {
			if err := encoder.Encode(response); err != nil {
				fmt.Fprintln(os.Stderr, "jev-mcp: write response:", err)
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "jev-mcp: read stdin:", err)
	}
}

func newServer() (*mcpServer, error) {
	loadCodexDotenv()

	base := strings.TrimRight(strings.TrimSpace(os.Getenv("TYPESAFE_BASE_URL")), "/")
	if base == "" {
		base = defaultBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("invalid TYPESAFE_BASE_URL")
	}

	key := strings.TrimSpace(os.Getenv("TYPESAFE_API_KEY"))
	if key == "" {
		return nil, fmt.Errorf("TYPESAFE_API_KEY is not set")
	}

	timeout := defaultTimeout
	if raw := strings.TrimSpace(os.Getenv("JEV_MCP_TIMEOUT")); raw != "" {
		parsedTimeout, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsedTimeout < time.Second {
			return nil, fmt.Errorf("invalid JEV_MCP_TIMEOUT")
		}
		timeout = parsedTimeout
	}

	return &mcpServer{
		client:  &http.Client{Timeout: timeout},
		baseURL: base,
		apiKey:  key,
		timeout: timeout,
	}, nil
}

func (s *mcpServer) handle(request rpcRequest) (rpcResponse, bool) {
	if request.Method == "notifications/initialized" || strings.HasPrefix(request.Method, "notifications/") {
		return rpcResponse{}, false
	}

	response := rpcResponse{JSONRPC: "2.0", ID: request.ID}
	switch request.Method {
	case "initialize":
		version := defaultMCPVersion
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(request.Params) > 0 {
			_ = json.Unmarshal(request.Params, &params)
			if strings.TrimSpace(params.ProtocolVersion) != "" {
				version = params.ProtocolVersion
			}
		}
		response.Result = map[string]any{
			"protocolVersion": version,
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    serverName,
				"version": serverVersion,
			},
			"instructions": "Use jev_decide for narrow semantic decisions. Keep exact rules and execution in code; treat Jev probabilities as advisory evidence.",
		}
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		response.Result = map[string]any{"tools": []any{jevDecideTool()}}
	case "tools/call":
		result, err := s.callTool(request.Params)
		if err != nil {
			response.Result = toolError(err)
		} else {
			response.Result = result
		}
	default:
		if len(request.ID) == 0 {
			return rpcResponse{}, false
		}
		response.Error = &rpcError{Code: -32601, Message: "method not found"}
	}
	return response, true
}

func jevDecideTool() map[string]any {
	return map[string]any{
		"name":        "jev_decide",
		"description": "Ask Jev for one or more narrow, typed judgments over the supplied state. Use Choice, Noul, or Score question objects in the native TypeSafe System One format. Do not use this for exact lookups, code generation, or tool execution.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"state": map[string]any{
					"type":        []string{"string", "object", "array"},
					"description": "The complete factual/contextual state needed to answer the questions.",
				},
				"questions": map[string]any{
					"type":        "object",
					"description": "A map of question IDs to TypeSafe question definitions, for example {\"urgent\": {\"type\": \"noul\", \"instructions\": \"The state signals time pressure\"}}.",
				},
				"model": map[string]any{
					"type":        "string",
					"description": "Optional Jev model name. Defaults to jev-latest.",
					"default":     defaultModel,
				},
				"request_id": map[string]any{
					"type":        "string",
					"description": "Optional request ID to correlate the decision with jev-hub logs.",
				},
			},
			"required":             []string{"state", "questions"},
			"additionalProperties": false,
		},
	}
}

func (s *mcpServer) callTool(raw json.RawMessage) (map[string]any, error) {
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, fmt.Errorf("invalid tools/call parameters")
	}
	if params.Name != "jev_decide" {
		return nil, fmt.Errorf("unknown tool %q", params.Name)
	}
	if s.configErr != nil {
		return toolError(s.configErr), nil
	}

	args, err := parseDecideArgs(params.Arguments)
	if err != nil {
		return toolError(err), nil
	}
	result, err := s.decide(args)
	if err != nil {
		return toolError(err), nil
	}
	return toolSuccess(result), nil
}

func parseDecideArgs(raw map[string]json.RawMessage) (decideArgs, error) {
	var args decideArgs
	stateRaw, ok := raw["state"]
	if !ok {
		return args, fmt.Errorf("state must be a non-empty string, object, or array")
	}
	var state any
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		return args, fmt.Errorf("state must be a non-empty string, object, or array")
	}
	switch value := state.(type) {
	case string:
		if strings.TrimSpace(value) == "" {
			return args, fmt.Errorf("state must be a non-empty string, object, or array")
		}
	case map[string]any, []any:
		// Native System One accepts structured state without flattening it.
	default:
		return args, fmt.Errorf("state must be a non-empty string, object, or array")
	}
	args.State = append(json.RawMessage(nil), stateRaw...)
	questions, ok := raw["questions"]
	if !ok || len(questions) == 0 || string(questions) == "null" {
		return args, fmt.Errorf("questions must be an object")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(questions, &object); err != nil || object == nil {
		return args, fmt.Errorf("questions must be an object")
	}
	args.Questions = append(json.RawMessage(nil), questions...)
	if modelRaw, ok := raw["model"]; ok {
		if err := json.Unmarshal(modelRaw, &args.Model); err != nil {
			return args, fmt.Errorf("model must be a string")
		}
	}
	args.Model = strings.TrimSpace(args.Model)
	if args.Model == "" {
		args.Model = defaultModel
	}
	if requestIDRaw, ok := raw["request_id"]; ok {
		if err := json.Unmarshal(requestIDRaw, &args.RequestID); err != nil {
			return args, fmt.Errorf("request_id must be a string")
		}
		args.RequestID = strings.TrimSpace(args.RequestID)
	}
	return args, nil
}

func (s *mcpServer) decide(args decideArgs) (any, error) {
	payload := struct {
		State     json.RawMessage `json:"state"`
		Model     string          `json:"model"`
		Questions json.RawMessage `json:"questions"`
	}{State: args.State, Model: args.Model, Questions: args.Questions}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}
	if len(body) > maxInputBytes {
		return nil, fmt.Errorf("request is too large")
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+s.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if args.RequestID != "" {
		request.Header.Set("X-Request-Id", args.RequestID)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("Jev gateway request failed: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Jev response: %w", err)
	}
	if len(responseBody) > maxResponseBytes {
		return nil, errors.New("Jev response is too large")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		// Do not echo gateway response bodies: they can contain request details or
		// account-specific diagnostics. The status is enough for the agent to retry
		// or ask the user to inspect the gateway.
		return nil, fmt.Errorf("Jev gateway returned HTTP %d", response.StatusCode)
	}

	var result any
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return map[string]any{"raw": string(responseBody)}, nil
	}
	return result, nil
}

func toolSuccess(value any) map[string]any {
	textValue, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		textValue = []byte(fmt.Sprint(value))
	}
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(textValue)}},
		"structuredContent": value,
		"isError":           false,
	}
}

func toolError(err error) map[string]any {
	message := "Jev decision unavailable"
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		message += ": " + err.Error()
	}
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": message}},
		"isError": true,
	}
}

func loadCodexDotenv() {
	paths := make([]string, 0, 3)
	if explicit := strings.TrimSpace(os.Getenv("TYPESAFE_DOTENV")); explicit != "" {
		paths = append(paths, explicit)
	}
	if codexHome := strings.TrimSpace(os.Getenv("CODEX_HOME")); codexHome != "" {
		paths = append(paths, filepath.Join(codexHome, ".env"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".codex", ".env"))
	} else if current, err := user.Current(); err == nil {
		paths = append(paths, filepath.Join(current.HomeDir, ".codex", ".env"))
	}

	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		loadDotenvFile(path)
	}
}

func loadDotenvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name != "TYPESAFE_API_KEY" && name != "TYPESAFE_BASE_URL" && name != "JEV_MCP_TIMEOUT" {
			continue
		}
		if strings.TrimSpace(os.Getenv(name)) != "" {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			if unquoted, err := strconv.Unquote(value); err == nil {
				value = unquoted
			} else {
				value = value[1 : len(value)-1]
			}
		}
		_ = os.Setenv(name, value)
	}
}
