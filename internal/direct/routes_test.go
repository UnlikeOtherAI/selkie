package direct_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/direct"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
)

func TestDirectHomeRegistrationRouteRequiresCredential(t *testing.T) {
	t.Parallel()
	router := chi.NewRouter()
	direct.New(nil, config.Config{}, nil, ratelimit.NewMemoryLimiter()).Mount(router)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/direct/home/00000000-0000-4000-8000-000000000001/register", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("route did not reach credential gate: %d %s", response.Code, response.Body.String())
	}
}
