package direct_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/unlikeotherai/selkie/internal/auth"
	"github.com/unlikeotherai/selkie/internal/config"
	"github.com/unlikeotherai/selkie/internal/direct"
	mobileapi "github.com/unlikeotherai/selkie/internal/mobile"
	"github.com/unlikeotherai/selkie/internal/overlay"
	"github.com/unlikeotherai/selkie/internal/ratelimit"
	"github.com/unlikeotherai/selkie/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func TestPostgresDirectOwnerGrantExpiryRenewalAndRevocation(t *testing.T) {
	databaseURL := os.Getenv("SELKIE_DIRECT_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set SELKIE_DIRECT_TEST_DATABASE_URL to an isolated PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	adminDB, err := store.OpenDB(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminDB.Close()
	schema := fmt.Sprintf("direct_test_%d", time.Now().UnixNano())
	safeSchema := pgx.Identifier{schema}.Sanitize()
	if _, createErr := adminDB.Pool.Exec(ctx, "CREATE SCHEMA "+safeSchema); createErr != nil {
		t.Fatal(createErr)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_, _ = adminDB.Pool.Exec(cleanup, "DROP SCHEMA "+safeSchema+" CASCADE")
	}()
	poolConfig, parseErr := pgxpool.ParseConfig(databaseURL)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, poolErr := pgxpool.NewWithConfig(ctx, poolConfig)
	if poolErr != nil {
		t.Fatal(poolErr)
	}
	db := &store.DB{Pool: pool}
	defer db.Close()
	if _, createErr := db.Pool.Exec(ctx, `CREATE TABLE schema_migrations(filename text PRIMARY KEY,applied_at timestamptz NOT NULL DEFAULT now())`); createErr != nil {
		t.Fatal(createErr)
	}
	if checkedErr0 := db.RunMigrations(ctx, "../../migrations"); checkedErr0 != nil {
		t.Fatal(checkedErr0)
	}
	suffix := time.Now().Format("150405.000000000")
	var owner, guest string
	if checkedErr1 := db.Pool.QueryRow(ctx, `INSERT INTO users(external_id) VALUES($1) RETURNING id`, "direct-owner-"+suffix).Scan(&owner); checkedErr1 != nil {
		t.Fatal(checkedErr1)
	}
	if checkedErr2 := db.Pool.QueryRow(ctx, `INSERT INTO users(external_id) VALUES($1) RETURNING id`, "direct-guest-"+suffix).Scan(&guest); checkedErr2 != nil {
		t.Fatal(checkedErr2)
	}
	defer func() {
		cleanup, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancelCleanup()
		_, _ = db.Pool.Exec(cleanup, `DELETE FROM devices WHERE owner_user_id IN ($1,$2)`, owner, guest)
		_, _ = db.Pool.Exec(cleanup, `DELETE FROM users WHERE id IN ($1,$2)`, owner, guest)
	}()
	credential := "only-this-home-device-credential"
	hash, err := bcrypt.GenerateFromPassword([]byte(credential), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	network := fmt.Sprintf("10.101.%d.", time.Now().UnixNano()%250)
	home := insertDevice(ctx, t, db, owner, "home", "windows", network+"2", string(hash), 7)
	otherHome := insertDevice(ctx, t, db, owner, "other-home", "windows", network+"4", string(hash), 8)
	mobile := insertDevice(ctx, t, db, guest, "mobile", "ios", network+"3", "unused", 9)
	if _, checkedErr3 := db.Pool.Exec(ctx, `UPDATE devices SET direct_home_port=8790,external_endpoint_host='31.49.158.120',external_endpoint_port=51821 WHERE id IN ($1,$2)`, home, otherHome); checkedErr3 != nil {
		t.Fatal(checkedErr3)
	}
	if _, checkedErr4 := db.Pool.Exec(ctx, `UPDATE devices SET direct_scoped=true WHERE id=$1`, mobile); checkedErr4 != nil {
		t.Fatal(checkedErr4)
	}
	secret := strings.Repeat("signed-session-secret-", 3)
	cfg := config.Config{InternalSessionSecret: secret, WGServerPublicKey: base64.StdEncoding.EncodeToString(bytesOf(11)), WGServerEndpoint: "relay.selkie.live", WGServerPort: 51820, WGOverlayCIDR: "10.101.0.0/16", RafikiHomeDeviceID: home}
	router := chi.NewRouter()
	direct.New(db, cfg, nil, ratelimit.NewMemoryLimiter()).Mount(router)
	allocator, allocErr := overlay.New(db.Pool, cfg.WGOverlayCIDR)
	if allocErr != nil {
		t.Fatal(allocErr)
	}
	hub := &hubSpy{}
	mobileapi.New(db, nil, cfg, allocator, nil, hub, ratelimit.NewMemoryLimiter()).Mount(router)
	server := httptest.NewServer(router)
	defer server.Close()
	ordinary := insertDevice(ctx, t, db, guest, "ordinary-phone", "ios", network+"5", "unused", 13)
	ordinaryOwner := insertDevice(ctx, t, db, owner, "ordinary-owner-phone", "ios", network+"6", "unused", 15)
	// Owning the configured Rafiki data machine does not bypass team grants.
	ownerToken := mintDirectToken(t, owner, "", secret, time.Now().Add(time.Minute))
	for attempt := range 2 {
		ordinarySocket, ordinaryResponse, ordinaryErr := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/"+ordinaryOwner+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + ownerToken}}})
		if ordinaryResponse != nil && ordinaryResponse.Body != nil {
			_ = ordinaryResponse.Body.Close()
		}
		if ordinaryErr != nil {
			t.Fatal(ordinaryErr)
		}
		var ownerView direct.Snapshot
		if readErr := wsjson.Read(ctx, ordinarySocket, &ownerView); readErr != nil {
			t.Fatal(readErr)
		}
		_ = ordinarySocket.CloseNow()
		if len(ownerView.Peers) != 1 || ownerView.Peers[0].DeviceID != otherHome {
			t.Fatal("ordinary owner bypassed configured-home grant or lost generic Selkie home")
		}
		if attempt == 0 {
			// Even a legacy ordinary-row grant must not defeat the scoped flag.
			if _, grantErr := db.Pool.Exec(ctx, `INSERT INTO direct_home_grants(mobile_device_id,home_device_id,expires_at) VALUES($1,$2,now()+interval '1 minute')`, ordinaryOwner, home); grantErr != nil {
				t.Fatal(grantErr)
			}
		}
	}
	scopeToken := mintDirectToken(t, guest, home, secret, time.Now().Add(time.Minute))
	for _, path := range []string{"/api/v1/mobile/servers", "/api/v1/mobile/disconnect"} {
		method := http.MethodGet
		if strings.HasSuffix(path, "disconnect") {
			method = http.MethodPost
		}
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer "+scopeToken)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("scoped ordinary API allowed: %s => %d", path, recorder.Code)
		}
	}
	enrollBody := map[string]string{"hostname": "ordinary-phone", "os_platform": "ios", "os_arch": "arm64", "app_version": "test", "wg_public_key": base64.StdEncoding.EncodeToString(bytesOf(14))}
	body, marshalErr := json.Marshal(enrollBody)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	attempt := httptest.NewRequest(http.MethodPost, "/api/v1/mobile/enroll", bytes.NewReader(body))
	attempt.Header.Set("Authorization", "Bearer "+scopeToken)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, attempt)
	if recorder.Code == http.StatusOK {
		t.Fatal("scoped enrollment took over ordinary mobile hostname")
	}
	var ordinaryScoped bool
	var ordinaryKey string
	if scanErr := db.Pool.QueryRow(ctx, `SELECT d.direct_scoped,k.wg_public_key FROM devices d JOIN device_keys k ON k.device_id=d.id AND k.state='active' WHERE d.id=$1`, ordinary).Scan(&ordinaryScoped, &ordinaryKey); scanErr != nil {
		t.Fatal(scanErr)
	}
	if ordinaryScoped || ordinaryKey != base64.StdEncoding.EncodeToString(bytesOf(13)) {
		t.Fatal("ordinary device changed under scoped enrollment")
	}
	enrollBody["hostname"] = "scoped-new"
	body, marshalErr = json.Marshal(enrollBody)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	attempt = httptest.NewRequest(http.MethodPost, "/api/v1/mobile/enroll", bytes.NewReader(body))
	attempt.Header.Set("Authorization", "Bearer "+scopeToken)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, attempt)
	if recorder.Code != http.StatusOK {
		t.Fatalf("scoped enrollment failed: %d %s", recorder.Code, recorder.Body.String())
	}
	var enrolled struct {
		DeviceID string `json:"device_id"`
		WGConfig string `json:"wg_config"`
	}
	if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &enrolled); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if strings.Contains(enrolled.WGConfig, "[Peer]") || strings.Contains(enrolled.WGConfig, "relay.selkie.live") || hub.deviceSyncs != 0 {
		t.Fatal("scoped enrollment exposed hub peer")
	}
	var scoped bool
	if scanErr := db.Pool.QueryRow(ctx, `SELECT direct_scoped FROM devices WHERE id=$1`, enrolled.DeviceID).Scan(&scoped); scanErr != nil || !scoped {
		t.Fatal("scope was not stored atomically")
	}
	if _, cleanupErr := db.Pool.Exec(ctx, `DELETE FROM devices WHERE id=$1`, enrolled.DeviceID); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	// Scoped credentials cannot renew a grant onto an ordinary mobile row.
	forged, forgedResponse, forgedErr := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/"+ordinary+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + scopeToken}}})
	if forged != nil {
		_ = forged.CloseNow()
	}
	if forgedResponse != nil && forgedResponse.Body != nil {
		_ = forgedResponse.Body.Close()
	}
	if forgedErr == nil {
		t.Fatal("scoped token granted an ordinary device")
	}
	homeSocket, homeSocketResponse, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/home/"+home+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + credential}}})
	if homeSocketResponse != nil && homeSocketResponse.Body != nil {
		_ = homeSocketResponse.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer homeSocket.CloseNow()
	var initial direct.Snapshot
	if checkedErr5 := wsjson.Read(ctx, homeSocket, &initial); checkedErr5 != nil {
		t.Fatal(checkedErr5)
	}
	if len(initial.Peers) != 0 {
		t.Fatal("home exposed a guest before grant")
	}
	// A scoped token for this guest cannot read the home owner's device socket.
	token := mintDirectToken(t, guest, home, secret, time.Now().Add(3*time.Second))
	forbidden, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/"+home+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if forbidden != nil {
		_ = forbidden.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatal("guest read another owner's source device")
	}
	mobileSocket, mobileSocketResponse, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/"+mobile+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if mobileSocketResponse != nil && mobileSocketResponse.Body != nil {
		_ = mobileSocketResponse.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer mobileSocket.CloseNow()
	var snapshot direct.Snapshot
	if checkedErr6 := wsjson.Read(ctx, mobileSocket, &snapshot); checkedErr6 != nil {
		t.Fatal(checkedErr6)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].DeviceID != home {
		t.Fatalf("grant leaked other home: %+v", snapshot.Peers)
	}
	if checkedErr7 := wsjson.Read(ctx, homeSocket, &snapshot); checkedErr7 != nil {
		t.Fatal(checkedErr7)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].DeviceID != mobile {
		t.Fatal("grant was not delivered to home")
	}
	var count int
	if checkedErr8 := db.Pool.QueryRow(ctx, `SELECT count(*) FROM direct_home_grants WHERE mobile_device_id=$1 AND home_device_id=$2`, mobile, home).Scan(&count); checkedErr8 != nil || count != 1 {
		t.Fatal("grant did not persist")
	}
	// Exact lease expiry wakes the home socket even without a database mutation.
	if checkedErr9 := wsjson.Read(ctx, homeSocket, &snapshot); checkedErr9 != nil {
		t.Fatal(checkedErr9)
	}
	if len(snapshot.Peers) != 0 {
		t.Fatal("expired grant kept the mobile key")
	}
	// Reconnection renews the grant using fresh trusted authorization.
	renewed := mintDirectToken(t, guest, home, secret, time.Now().Add(time.Minute))
	renewedSocket, renewedSocketResponse, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/"+mobile+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + renewed}}})
	if renewedSocketResponse != nil && renewedSocketResponse.Body != nil {
		_ = renewedSocketResponse.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer renewedSocket.CloseNow()
	if checkedErr10 := wsjson.Read(ctx, renewedSocket, &snapshot); checkedErr10 != nil {
		t.Fatal(checkedErr10)
	}
	if len(snapshot.Peers) != 1 {
		t.Fatal("renewed grant missing")
	}
	if checkedErr11 := wsjson.Read(ctx, homeSocket, &snapshot); checkedErr11 != nil {
		t.Fatal(checkedErr11)
	}
	if len(snapshot.Peers) != 1 {
		t.Fatal("home did not restore renewed peer")
	}
	if _, checkedErr12 := db.Pool.Exec(ctx, `UPDATE device_keys SET state='retired',retired_at=now() WHERE device_id=$1`, mobile); checkedErr12 != nil {
		t.Fatal(checkedErr12)
	}
	if checkedErr13 := wsjson.Read(ctx, homeSocket, &snapshot); checkedErr13 != nil {
		t.Fatal(checkedErr13)
	}
	if len(snapshot.Peers) != 0 {
		t.Fatal("retired mobile key retained access")
	}
	// A same-owner scoped device still needs, and receives, a bounded lease.
	ownerScoped := insertDevice(ctx, t, db, owner, "scoped-owner-phone", "tvos", network+"7", "unused", 16)
	if _, scopeErr := db.Pool.Exec(ctx, `UPDATE devices SET direct_scoped=true WHERE id=$1`, ownerScoped); scopeErr != nil {
		t.Fatal(scopeErr)
	}
	ownerGrant := mintDirectToken(t, owner, home, secret, time.Now().Add(3*time.Second))
	ownerSocket, ownerResponse, ownerErr := websocket.Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/api/v1/direct/"+ownerScoped+"/peers", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + ownerGrant}}})
	if ownerResponse != nil && ownerResponse.Body != nil {
		_ = ownerResponse.Body.Close()
	}
	if ownerErr != nil {
		t.Fatal(ownerErr)
	}
	defer ownerSocket.CloseNow()
	if readErr := wsjson.Read(ctx, ownerSocket, &snapshot); readErr != nil {
		t.Fatal(readErr)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].DeviceID != home || snapshot.Peers[0].ValidUntil == nil {
		t.Fatal("same-owner scoped home route was unbounded")
	}
	if readErr := wsjson.Read(ctx, homeSocket, &snapshot); readErr != nil {
		t.Fatal(readErr)
	}
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].DeviceID != ownerScoped || snapshot.Peers[0].ValidUntil == nil {
		t.Fatal("configured home exposed an ordinary or unbounded owner peer")
	}
	if readErr := wsjson.Read(ctx, homeSocket, &snapshot); readErr != nil {
		t.Fatal(readErr)
	}
	if len(snapshot.Peers) != 0 {
		t.Fatal("same-owner scoped lease did not expire")
	}
	if _, checkedErr14 := db.Pool.Exec(ctx, `UPDATE devices SET status='revoked',revoked_at=now() WHERE id=$1`, home); checkedErr14 != nil {
		t.Fatal(checkedErr14)
	}
	if checkedErr15 := wsjson.Read(ctx, homeSocket, &snapshot); checkedErr15 == nil {
		t.Fatal("revoked home socket stayed authorized")
	}
}

func insertDevice(ctx context.Context, t *testing.T, db *store.DB, owner, name, platform, ip, hash string, keyByte byte) string {
	t.Helper()
	var id string
	err := db.Pool.QueryRow(ctx, `INSERT INTO devices(owner_user_id,hostname,status,overlay_ip,credential_hash,agent_version,os_platform,os_arch,os_version,kernel_version,cpu_model,cpu_cores,total_memory_bytes,disk_total_bytes,disk_free_bytes)
 VALUES($1,$2,'active',$3,$4,'test',$5,'arm64','','','',1,0,0,0) RETURNING id`, owner, name, ip, hash, platform).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	if _, checkedErr16 := db.Pool.Exec(ctx, `INSERT INTO device_keys(device_id,key_version,wg_public_key,state) VALUES($1,1,$2,'active')`, id, base64.StdEncoding.EncodeToString(bytesOf(keyByte))); checkedErr16 != nil {
		t.Fatal(checkedErr16)
	}
	return id
}

func mintDirectToken(t *testing.T, owner, home, secret string, expiry time.Time) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"iss": auth.Issuer, "sub": owner, "aud": []string{auth.AudienceMobile}, "exp": expiry.Unix(), "iat": time.Now().Unix(), "direct_home_id": home}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type hubSpy struct{ deviceSyncs int }

func (*hubSpy) SyncAll(context.Context) error              { return nil }
func (h *hubSpy) SyncDevice(context.Context, string) error { h.deviceSyncs++; return nil }
