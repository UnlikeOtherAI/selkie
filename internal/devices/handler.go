package devices

import (
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/unlikeotherai/silkie/internal/auth"
	"github.com/unlikeotherai/silkie/internal/config"
	"github.com/unlikeotherai/silkie/internal/store"
	"go.uber.org/zap"
)

type Handler struct {
	db     *store.DB
	logger *zap.Logger
	cfg    config.Config
}

func New(db *store.DB, logger *zap.Logger, cfg config.Config) *Handler {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &Handler{db: db, logger: logger, cfg: cfg}
}

func (h *Handler) Mount(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(auth.Middleware(h.cfg))
		r.Post("/v1/auth/pair/start", h.handlePairStart)
		r.Get("/v1/auth/pair/status", h.handlePairStatus)
		r.Get("/v1/devices", h.handleListDevices)
		r.Get("/v1/devices/{id}", h.handleGetDevice)
		r.Post("/v1/devices/{id}/heartbeat", h.handleHeartbeat)
		r.Delete("/v1/devices/{id}", h.handleDeleteDevice)
	})
}

type pairStartRequest struct {
	WGPublicKey  string `json:"wg_public_key"`
	Hostname     string `json:"hostname"`
	OSPlatform   string `json:"os_platform"`
	OSArch       string `json:"os_arch"`
	AgentVersion string `json:"agent_version"`
}

type heartbeatRequest struct {
	ExternalEndpointHost string `json:"external_endpoint_host"`
	ExternalEndpointPort int    `json:"external_endpoint_port"`
	AgentVersion         string `json:"agent_version"`
	DiskFreeBytes        int64  `json:"disk_free_bytes"`
}

func (h *Handler) handlePairStart(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req pairStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.WGPublicKey == "" || req.Hostname == "" || req.OSPlatform == "" || req.OSArch == "" || req.AgentVersion == "" {
		writeError(w, http.StatusBadRequest, "missing required fields")
		return
	}

	for range 5 {
		code, err := randomCode(6)
		if err != nil {
			h.logger.Error("generate pair code", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to create pair code")
			return
		}

		var createdCode string
		err = h.db.Pool.QueryRow(
			r.Context(),
			`insert into pair_codes (
				code,
				wg_public_key,
				hostname,
				os_platform,
				os_arch,
				agent_version,
				owner_user_id,
				status,
				expires_at
			) values ($1, $2, $3, $4, $5, $6, $7, 'pending', $8) returning code`,
			code,
			req.WGPublicKey,
			req.Hostname,
			req.OSPlatform,
			req.OSArch,
			req.AgentVersion,
			claims.Sub,
			time.Now().UTC().Add(10*time.Minute),
		).Scan(&createdCode)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]string{"code": createdCode})
			return
		}

		h.logger.Error("insert pair code", zap.Error(err))
	}

	writeError(w, http.StatusInternalServerError, "failed to create pair code")
}

func (h *Handler) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("code")))
	if len(code) != 6 {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}

	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select json_build_object(
			'status', case when status = 'claimed' or credential is not null or wg_config is not null then 'claimed' else 'pending' end,
			'credential', credential,
			'wg_config', wg_config
		) from pair_codes where code = $1 and expires_at > now()`,
		code,
	).Scan(&payload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "pair code not found")
			return
		}

		h.logger.Error("load pair status", zap.Error(err), zap.String("code", code))
		writeError(w, http.StatusInternalServerError, "failed to load pair status")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleListDevices(w http.ResponseWriter, r *http.Request) {
	claims, ok := auth.ClaimsFromContext(r.Context())
	if !ok || claims.Sub == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select coalesce(json_agg(row_to_json(d)), '[]'::json)
		from (
			select *
			from devices
			where owner_user_id = $1
			order by created_at desc
		) d`,
		claims.Sub,
	).Scan(&payload)
	if err != nil {
		h.logger.Error("list devices", zap.Error(err), zap.String("owner_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to list devices")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleGetDevice(w http.ResponseWriter, r *http.Request) {
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

	var payload []byte
	err := h.db.Pool.QueryRow(
		r.Context(),
		`select row_to_json(d)
		from (
			select *
			from devices
			where id = $1 and owner_user_id = $2
			limit 1
		) d`,
		deviceID,
		claims.Sub,
	).Scan(&payload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}

		h.logger.Error("get device", zap.Error(err), zap.String("device_id", deviceID), zap.String("owner_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to load device")
		return
	}

	writeRawJSON(w, http.StatusOK, payload)
}

func (h *Handler) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
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

	var req heartbeatRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	commandTag, err := h.db.Pool.Exec(
		r.Context(),
		`update devices
		set external_endpoint_host = $1,
			external_endpoint_port = $2,
			agent_version = $3,
			disk_free_bytes = $4,
			last_heartbeat_at = now(),
			updated_at = now()
		where id = $5 and owner_user_id = $6`,
		req.ExternalEndpointHost,
		req.ExternalEndpointPort,
		req.AgentVersion,
		req.DiskFreeBytes,
		deviceID,
		claims.Sub,
	)
	if err != nil {
		h.logger.Error("update heartbeat", zap.Error(err), zap.String("device_id", deviceID), zap.String("owner_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to update heartbeat")
		return
	}

	if commandTag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
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

	commandTag, err := h.db.Pool.Exec(
		r.Context(),
		`update devices
		set status = 'revoked',
			overlay_ip_reclaim_after = now() + interval '24 hours',
			updated_at = now()
		where id = $1 and owner_user_id = $2`,
		deviceID,
		claims.Sub,
	)
	if err != nil {
		h.logger.Error("revoke device", zap.Error(err), zap.String("device_id", deviceID), zap.String("owner_user_id", claims.Sub))
		writeError(w, http.StatusInternalServerError, "failed to revoke device")
		return
	}

	if commandTag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
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
	_ = json.NewEncoder(w).Encode(value)
}

func writeRawJSON(w http.ResponseWriter, status int, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func randomCode(length int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	chars := make([]byte, length)
	max := big.NewInt(int64(len(alphabet)))
	for i := range chars {
		n, err := crand.Int(crand.Reader, max)
		if err != nil {
			return "", err
		}

		chars[i] = alphabet[n.Int64()]
	}

	return string(chars), nil
}
