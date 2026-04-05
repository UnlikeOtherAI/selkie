// Package admin serves the web-based admin UI and login pages.
package admin

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

// Handler serves the admin dashboard and login HTML pages.
type Handler struct{}

// New creates a new admin Handler.
func New() *Handler {
	return &Handler{}
}

// Mount registers admin routes on the given router.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/admin", h.serveAdmin)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	r.Get("/login", h.serveLogin)
}

func (*Handler) serveAdmin(w http.ResponseWriter, _ *http.Request) {
	serveHTMLFile(w, "docs/template/admin.html")
}

func (*Handler) serveLogin(w http.ResponseWriter, _ *http.Request) {
	serveHTMLFile(w, "docs/template/login.html")
}

func serveHTMLFile(w http.ResponseWriter, path string) {
	body, err := os.ReadFile(path) //nolint:gosec // G304: paths are controlled server-side, not user input
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body)
}
