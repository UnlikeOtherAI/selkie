// Package services implements the device service catalog — devices report
// exported services and users discover what is available across their fleet.
package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/config"
	"github.com/unlikeotherai/silkie/internal/store"
	"go.uber.org/zap"
)

// Handler serves service-catalog HTTP endpoints.
type Handler struct {
	db     *store.DB
	logger *zap.Logger
	cfg    config.Config
}

// New creates a services Handler with the given dependencies.
func New(db *store.DB, logger *zap.Logger, cfg config.Config) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Handler{db: db, logger: logger, cfg: cfg}
}

// Mount registers service-catalog routes on the given router behind auth middleware.
func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg))
		r.Post("/v1/devices/{id}/services", h.handleUpsertServices)
		r.Get("/v1/devices/{id}/services", h.handleListDeviceServices)
		r.Get("/v1/services", h.handleListAllServices)
	})
}

// serviceEntry represents a single service in the upsert manifest.
type serviceEntry struct {
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	LocalBind    string   `json:"local_bind"`
	ExposureType string   `json:"exposure_type"`
	Tags         []string `json:"tags"`
	AuthMode     string   `json:"auth_mode"`
	HealthStatus string   `json:"health_status"`
}

// handleUpsertServices replaces all services for a device with the provided manifest.
func (h *Handler) handleUpsertServices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(chi.URLParam(r, "id"))
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "device id is required")
		return
	}

	var entries []serviceEntry
	if err := decodeJSON(r, &entries); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.verifyDeviceOwnership(r.Context(), deviceID, claims.Sub); err != nil {
		writeDeviceOwnershipError(w, h.logger, err, deviceID)
		return
	}

	if err := h.replaceDeviceServices(r.Context(), deviceID, entries); err != nil {
		h.logger.Error("replace device services", zap.Error(err), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.writeDeviceServices(w, r, deviceID)
}

// handleListDeviceServices returns all services for a specific device.
func (h *Handler) handleListDeviceServices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	deviceID := strings.TrimSpace(chi.URLParam(r, "id"))
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "device id is required")
		return
	}

	if err := h.verifyDeviceOwnership(r.Context(), deviceID, claims.Sub); err != nil {
		writeDeviceOwnershipError(w, h.logger, err, deviceID)
		return
	}

	h.writeDeviceServices(w, r, deviceID)
}

// handleListAllServices returns all services across all devices owned by the authenticated user.
func (h *Handler) handleListAllServices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select coalesce(json_agg(row_to_json(s)), '[]'::json)
		from (
			select ds.*
			from device_services ds
			join devices d on d.id = ds.device_id
			where d.owner_user_id = $1
			order by d.hostname, ds.name
		) s`,
		claims.Sub,
	).Scan(&payload)
	if err != nil {
		h.logger.Error("list all services", zap.Error(err), zap.String("owner_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to list services")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

// verifyDeviceOwnership checks that the device exists and belongs to the given user.
// Returns a sentinel error for not-found vs internal failures.
func (h *Handler) verifyDeviceOwnership(ctx context.Context, deviceID, userID string) error {
	var exists int
	err := h.db.Pool.QueryRow(
		ctx,
		`select 1 from devices where id = $1 and owner_user_id = $2`,
		deviceID,
		userID,
	).Scan(&exists)
	if err != nil {
		return err
	}

	return nil
}

// writeDeviceOwnershipError translates a verifyDeviceOwnership error into an HTTP response.
func writeDeviceOwnershipError(w http.ResponseWriter, logger *zap.Logger, err error, deviceID string) {
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	logger.Error("check device ownership", zap.Error(err), zap.String("device_id", deviceID))
	writeError(w, http.StatusInternalServerError, "failed to verify device")
}

// replaceDeviceServices deletes all existing services for the device and inserts the new manifest.
func (h *Handler) replaceDeviceServices(ctx context.Context, deviceID string, entries []serviceEntry) error {
	tx, err := h.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is best-effort after commit

	if _, execErr := tx.Exec(ctx, `delete from device_services where device_id = $1`, deviceID); execErr != nil {
		return fmt.Errorf("failed to replace services: %w", execErr)
	}

	for _, entry := range entries {
		if err := insertServiceEntry(ctx, tx, deviceID, entry); err != nil {
			return err
		}
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		return fmt.Errorf("failed to commit services: %w", commitErr)
	}

	return nil
}

// insertServiceEntry inserts a single service entry within a transaction.
func insertServiceEntry(ctx context.Context, tx pgx.Tx, deviceID string, entry serviceEntry) error {
	if entry.Name == "" || entry.Protocol == "" || entry.LocalBind == "" || entry.ExposureType == "" {
		return errors.New("each service must have name, protocol, local_bind, and exposure_type")
	}

	authMode := entry.AuthMode
	if authMode == "" {
		authMode = "inherit"
	}

	healthStatus := entry.HealthStatus
	if healthStatus == "" {
		healthStatus = "unknown"
	}

	tags := entry.Tags
	if tags == nil {
		tags = []string{}
	}

	_, err := tx.Exec(
		ctx,
		`insert into device_services (device_id, name, protocol, local_bind, exposure_type, auth_mode, health_status, tags)
		values ($1, $2, $3, $4, $5, $6, $7, $8)`,
		deviceID,
		entry.Name,
		entry.Protocol,
		entry.LocalBind,
		entry.ExposureType,
		authMode,
		healthStatus,
		tags,
	)
	if err != nil {
		return fmt.Errorf("failed to insert service %q: %w", entry.Name, err)
	}

	return nil
}

// writeDeviceServices loads and writes all services for a device as JSON.
func (h *Handler) writeDeviceServices(w http.ResponseWriter, r *http.Request, deviceID string) {
	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select coalesce(json_agg(row_to_json(s)), '[]'::json)
		from (
			select *
			from device_services
			where device_id = $1
			order by name
		) s`,
		deviceID,
	).Scan(&payload)
	if err != nil {
		h.logger.Error("list device services", zap.Error(err), zap.String("device_id", deviceID))
		writeError(w, http.StatusInternalServerError, "failed to list services")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()

	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain a single JSON object")
	}

	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value) //nolint:errcheck // best-effort write to HTTP response
}

func writeRawJSON(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
