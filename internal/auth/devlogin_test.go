package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
)

func TestDevStatus_Enabled(t *testing.T) {
	r := chi.NewRouter()
	cfg := config.Config{DevMode: true, InternalSessionSecret: "test-secret"}
	h := auth.NewCallbackHandler(nil, cfg, nil, nil)
	h.Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/auth/dev-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var body map[string]bool
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body["enabled"] {
		t.Error("expected enabled=true")
	}
}

func TestDevStatus_Disabled(t *testing.T) {
	r := chi.NewRouter()
	cfg := config.Config{DevMode: false, InternalSessionSecret: "test-secret"}
	h := auth.NewCallbackHandler(nil, cfg, nil, nil)
	h.Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/auth/dev-status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	var body map[string]bool
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["enabled"] {
		t.Error("expected enabled=false")
	}
}

func TestDevLogin_Disabled(t *testing.T) {
	r := chi.NewRouter()
	cfg := config.Config{DevMode: false, InternalSessionSecret: "test-secret"}
	h := auth.NewCallbackHandler(nil, cfg, nil, nil)
	h.Mount(r)

	req := httptest.NewRequest(http.MethodGet, "/auth/dev-login", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}
