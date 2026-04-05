package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestEvaluate_AllowAllMode(t *testing.T) {
	engine := New("", zap.NewNop())

	result, err := engine.Evaluate(context.Background(), PolicyInput{
		UserID:      "user-1",
		DeviceID:    "device-1",
		ServiceID:   "svc-1",
		Action:      "connect",
		RequestTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allow {
		t.Error("expected Allow to be true in allow-all mode")
	}

	if result.Reason != "policy-engine-disabled" {
		t.Errorf("expected reason %q, got %q", "policy-engine-disabled", result.Reason)
	}
}

func TestEvaluate_OPAAllow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/silkie/access" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("unexpected content-type: %s", ct)
		}

		var req opaRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if req.Input.UserID != "user-42" {
			t.Errorf("expected user_id %q, got %q", "user-42", req.Input.UserID)
		}

		resp := opaResponse{
			Result: PolicyResult{
				Allow:           true,
				Reason:          "admin-override",
				AllowedActions:  []string{"connect", "tunnel"},
				AllowedServices: []string{"ssh", "rdp"},
				TTL:             300,
				AuditLabels:     map[string]string{"policy": "admin"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp) //nolint:errcheck // test helper
	}))
	defer srv.Close()

	engine := New(srv.URL, zap.NewNop())

	result, err := engine.Evaluate(context.Background(), PolicyInput{
		UserID:      "user-42",
		UserGroups:  []string{"admins"},
		DeviceID:    "device-7",
		ServiceID:   "svc-ssh",
		Action:      "connect",
		PathType:    "direct",
		RequestTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allow {
		t.Error("expected Allow to be true")
	}

	if result.Reason != "admin-override" {
		t.Errorf("expected reason %q, got %q", "admin-override", result.Reason)
	}

	if result.TTL != 300 {
		t.Errorf("expected TTL 300, got %d", result.TTL)
	}

	if len(result.AllowedActions) != 2 {
		t.Errorf("expected 2 allowed actions, got %d", len(result.AllowedActions))
	}
}

func TestEvaluate_OPADeny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := opaResponse{
			Result: PolicyResult{
				Allow:  false,
				Reason: "group-not-permitted",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp) //nolint:errcheck // test helper
	}))
	defer srv.Close()

	engine := New(srv.URL, zap.NewNop())

	result, err := engine.Evaluate(context.Background(), PolicyInput{
		UserID:      "user-99",
		DeviceID:    "device-5",
		ServiceID:   "svc-db",
		Action:      "connect",
		RequestTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allow {
		t.Error("expected Allow to be false")
	}

	if result.Reason != "group-not-permitted" {
		t.Errorf("expected reason %q, got %q", "group-not-permitted", result.Reason)
	}
}

func TestEvaluate_OPAServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	engine := New(srv.URL, zap.NewNop())

	_, err := engine.Evaluate(context.Background(), PolicyInput{
		UserID:      "user-1",
		DeviceID:    "device-1",
		ServiceID:   "svc-1",
		Action:      "connect",
		RequestTime: time.Now(),
	})

	if err == nil {
		t.Fatal("expected error for OPA 500 response")
	}
}

func TestEvaluate_OPAUnreachable(t *testing.T) {
	engine := New("http://127.0.0.1:1", zap.NewNop())

	_, err := engine.Evaluate(context.Background(), PolicyInput{
		UserID:      "user-1",
		DeviceID:    "device-1",
		ServiceID:   "svc-1",
		Action:      "connect",
		RequestTime: time.Now(),
	})

	if err == nil {
		t.Fatal("expected error for unreachable OPA")
	}
}
