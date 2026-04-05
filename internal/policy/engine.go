// Package policy evaluates access decisions against an Open Policy Agent endpoint.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// PolicyInput describes the access request sent to OPA for evaluation.
type PolicyInput struct {
	UserID      string   `json:"user_id"`
	UserGroups  []string `json:"user_groups"`
	DeviceID    string   `json:"device_id"`
	DeviceTags  []string `json:"device_tags"`
	DeviceState string   `json:"device_state"`
	ServiceID   string   `json:"service_id"`
	ServiceTags []string `json:"service_tags"`
	Action      string   `json:"action"`
	PathType    string   `json:"path_type"`    // "direct" or "relay"
	RequestTime time.Time `json:"request_time"`
}

// PolicyResult holds the decision returned by the policy engine.
type PolicyResult struct {
	Allow          bool              `json:"allow"`
	Reason         string            `json:"reason"`
	AllowedActions []string          `json:"allowed_actions"`
	AllowedServices []string         `json:"allowed_services"`
	TTL            int               `json:"ttl"`
	AuditLabels    map[string]string `json:"audit_labels"`
}

// Engine is a thin HTTP client for Open Policy Agent.
// When opaURL is empty the engine operates in allow-all mode (useful for MVP/dev).
type Engine struct {
	opaURL string
	client *http.Client
	logger *zap.Logger
}

// New creates a policy Engine. If opaURL is empty, every Evaluate call
// returns Allow: true without contacting an external service.
func New(opaURL string, logger *zap.Logger) *Engine {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Engine{
		opaURL: opaURL,
		client: &http.Client{Timeout: 5 * time.Second},
		logger: logger,
	}
}

// opaRequest wraps the input in the envelope OPA expects.
type opaRequest struct {
	Input PolicyInput `json:"input"`
}

// opaResponse is the top-level envelope OPA returns.
type opaResponse struct {
	Result PolicyResult `json:"result"`
}

// Evaluate checks whether the given input is permitted.
// In allow-all mode (empty OPA URL) it returns a permissive result immediately.
func (e *Engine) Evaluate(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
	if e.opaURL == "" {
		e.logger.Debug("policy engine disabled, allowing request",
			zap.String("user_id", input.UserID),
			zap.String("device_id", input.DeviceID),
		)

		return &PolicyResult{
			Allow:  true,
			Reason: "policy-engine-disabled",
		}, nil
	}

	body, err := json.Marshal(opaRequest{Input: input})
	if err != nil {
		return nil, fmt.Errorf("marshal policy input: %w", err)
	}

	endpoint := e.opaURL + "/v1/data/silkie/access"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OPA request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close on HTTP response body

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read OPA response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OPA returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var opaResp opaResponse
	if err := json.Unmarshal(respBody, &opaResp); err != nil {
		return nil, fmt.Errorf("decode OPA response: %w", err)
	}

	e.logger.Debug("policy evaluated",
		zap.String("user_id", input.UserID),
		zap.String("device_id", input.DeviceID),
		zap.Bool("allow", opaResp.Result.Allow),
		zap.String("reason", opaResp.Result.Reason),
	)

	return &opaResp.Result, nil
}
