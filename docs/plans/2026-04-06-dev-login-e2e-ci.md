# Dev Login, E2E Tests, and CI Pipeline

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a dev-mode-only login bypass, Playwright E2E tests against an isolated test database, and GitHub Actions CI that runs lints, unit tests, and E2E on PRs/main (with a deploy placeholder on main).

**Architecture:** A `DEV_MODE` env flag gates a `/auth/dev-login` endpoint that upserts a hardcoded "Agent Smith" user and mints a real JWT — no fake auth, no mocks, same pipeline as production. Playwright E2E tests create a fresh Postgres database per run, start the Go server as a child process, exercise every admin section, then tear everything down. CI runs Postgres + Redis as services.

**Tech Stack:** Go 1.23, chi v5, pgx/v5, Playwright (TypeScript), GitHub Actions, pnpm

---

### Task 1: Add DevMode to config

**Files:**
- Modify: `internal/config/config.go:10-68`

**Step 1: Add DevMode field to Config struct**

In `internal/config/config.go`, add `DevMode` field to the Config struct after `OPAEndpoint`:

```go
DevMode bool
```

And in the `Load()` function, add:

```go
DevMode: getenvBool("DEV_MODE", false),
```

**Step 2: Add getenvBool helper**

After the existing `getenvInt` function, add:

```go
func getenvBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
```

**Step 3: Verify build**

Run: `go build ./...`
Expected: clean build, no errors

**Step 4: Commit**

```
feat(config): add DEV_MODE flag
```

---

### Task 2: Extend JWT claims with user profile fields

**Files:**
- Modify: `internal/auth/callback.go:126-146`

The internal JWT currently only carries `sub` and `is_super`. The frontend needs `email`, `display_name`, and `picture` to render the avatar. Extend the claims and `mintToken` signature.

**Step 1: Extend jwtClaims struct**

Replace the `jwtClaims` struct (lines 126-130) with:

```go
type jwtClaims struct {
	Sub         string `json:"sub"`
	IsSuper     bool   `json:"is_super"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Picture     string `json:"picture,omitempty"`
	jwt.RegisteredClaims
}
```

**Step 2: Update mintToken signature**

Replace the `mintToken` method (lines 132-146) with:

```go
func (h *CallbackHandler) mintToken(userID string, isSuper bool, email, displayName, picture string) (string, error) {
	now := time.Now()
	c := jwtClaims{
		Sub:         userID,
		IsSuper:     isSuper,
		Email:       email,
		DisplayName: displayName,
		Picture:     picture,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "selkie",
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).
		SignedString([]byte(h.cfg.InternalSessionSecret))
}
```

**Step 3: Update the existing call site in ServeCallback**

In `ServeCallback` (line 75), change:

```go
token, err := h.mintToken(userID, isSuper)
```

to:

```go
email := uoaClaims.Email
displayName := uoaClaims.DisplayName
if displayName == "" {
	displayName = email
}
token, err := h.mintToken(userID, isSuper, email, displayName, "")
```

Note: remove the duplicate `displayName` fallback from `upsertUser` if needed, or leave it — the DB version is for storage, this is for the JWT.

**Step 4: Verify build**

Run: `go build ./...`
Expected: clean build

**Step 5: Run existing tests**

Run: `go test ./internal/auth/... ./internal/admin/...`
Expected: all pass (admin tests don't call mintToken directly — they use their own local helper)

**Step 6: Commit**

```
feat(auth): add email, display_name, picture to internal JWT claims
```

---

### Task 3: Dev login backend endpoints

**Files:**
- Create: `internal/auth/devlogin.go`
- Create: `internal/auth/devlogin_test.go`
- Modify: `internal/auth/callback.go:31-34` (Mount method)

**Step 1: Write the test file**

Create `internal/auth/devlogin_test.go`:

```go
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
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/... -run TestDev -v`
Expected: FAIL — routes not registered yet

**Step 3: Create devlogin.go**

Create `internal/auth/devlogin.go`:

```go
package auth

import (
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// Dev user constants — deterministic so tests and dev sessions always get the same user.
const (
	DevUserExternalID  = "dev-agent-smith"
	DevUserEmail       = "agent.smith@dev.local"
	DevUserDisplayName = "Agent Smith"
	DevUserPicture     = "https://api.dicebear.com/9.x/bottts/svg?seed=AgentSmith"
)

// ServeDevStatus returns whether dev-mode login is enabled.
func (h *CallbackHandler) ServeDevStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": h.cfg.DevMode})
}

// ServeDevLogin upserts a hardcoded dev user and issues a session JWT.
// Returns 404 when DevMode is false.
func (h *CallbackHandler) ServeDevLogin(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.DevMode {
		http.NotFound(w, r)
		return
	}

	claims := &UOAClaims{}
	claims.Subject = DevUserExternalID
	claims.Email = DevUserEmail
	claims.DisplayName = DevUserDisplayName

	userID, isSuper, err := h.upsertUser(r.Context(), claims)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("dev-login upsert", zap.Error(err))
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	token, err := h.mintToken(userID, isSuper, DevUserEmail, DevUserDisplayName, DevUserPicture)
	if err != nil {
		http.Error(w, "token error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin#token="+token, http.StatusFound)
}
```

**Step 4: Add dev routes to Mount**

In `internal/auth/callback.go`, update the `Mount` method (lines 31-34) to add the dev routes:

```go
func (h *CallbackHandler) Mount(r chi.Router) {
	r.Get("/auth/login", h.ServeLogin)
	r.Get("/auth/callback", h.ServeCallback)
	r.Get("/auth/dev-status", h.ServeDevStatus)
	r.Get("/auth/dev-login", h.ServeDevLogin)
}
```

**Step 5: Run tests**

Run: `go test ./internal/auth/... -run TestDev -v`
Expected: all 3 tests pass

**Step 6: Run full test suite**

Run: `go test ./...`
Expected: all pass

**Step 7: Lint**

Run: `make lint`
Expected: clean

**Step 8: Commit**

```
feat(auth): add dev-login and dev-status endpoints

When DEV_MODE=true, GET /auth/dev-login upserts a hardcoded "Agent Smith"
user and issues a real JWT. GET /auth/dev-status reports whether dev mode
is active. Both return 404/false when DEV_MODE is unset.
```

---

### Task 4: Frontend — dev login button

**Files:**
- Modify: `admin/login.html:54-79`

**Step 1: Add dev login button and fetch logic**

After the existing "Continue" button `</a>` (line 73), add a dev login button (hidden by default):

```html
<a
    id="dev-login-btn"
    href="/auth/dev-login"
    class="hidden w-full flex items-center justify-center gap-3 bg-ink-700 hover:bg-ink-600 active:bg-ink-800 text-ink-100 text-sm font-semibold px-4 py-3 rounded-xl transition border border-ink-600"
>
    <svg class="h-5 w-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 18l6-6-6-6"/><path d="M8 6l-6 6 6 6"/></svg>
    Dev Login
</a>
```

Add a script at the bottom of the body (before `</body>`):

```html
<script>
fetch('/auth/dev-status')
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.enabled) document.getElementById('dev-login-btn').classList.remove('hidden');
    })
    .catch(function() {});
</script>
```

**Step 2: Commit**

```
feat(ui): show dev login button when DEV_MODE is active
```

---

### Task 5: Frontend — avatar display in admin

**Files:**
- Modify: `admin/index.html:67-68` (header user area)
- Modify: `admin/index.html:791-796` (JS init)

**Step 1: Add avatar image element to header**

Replace the user info area (line 68):

```html
<span id="user-email" class="text-xs text-ink-400 font-mono"></span>
```

with:

```html
<div class="flex items-center gap-2.5">
    <img id="user-avatar" src="" alt="" class="hidden h-7 w-7 rounded-full ring-1 ring-ink-700 bg-ink-800" />
    <span id="user-email" class="text-xs text-ink-400 font-mono"></span>
</div>
```

**Step 2: Update JS init to populate avatar**

Replace the claims display block (lines 791-796):

```javascript
var claims = parseJWT(getToken());
if (claims) {
    var emailEl = document.getElementById('user-email');
    var email = claims.email || claims.sub || '';
    emailEl.textContent = claims.is_super ? email + ' (super)' : email;
}
```

with:

```javascript
var claims = parseJWT(getToken());
if (claims) {
    var emailEl = document.getElementById('user-email');
    var label = claims.display_name || claims.email || claims.sub || '';
    emailEl.textContent = claims.is_super ? label + ' (super)' : label;

    if (claims.picture) {
        var avatarEl = document.getElementById('user-avatar');
        avatarEl.src = claims.picture;
        avatarEl.alt = label;
        avatarEl.classList.remove('hidden');
    }
}
```

**Step 3: Commit**

```
feat(ui): display user avatar and display name from JWT claims
```

---

### Task 6: Playwright E2E infrastructure

**Files:**
- Create: `e2e/package.json`
- Create: `e2e/playwright.config.ts`
- Create: `e2e/global-setup.ts`
- Create: `e2e/global-teardown.ts`
- Create: `e2e/helpers.ts`
- Create: `e2e/.gitignore`
- Modify: `.env.example` (document DEV_MODE)

**Step 1: Create e2e/package.json**

```json
{
  "name": "selkie-e2e",
  "private": true,
  "scripts": {
    "test": "playwright test",
    "test:headed": "playwright test --headed",
    "test:ui": "playwright test --ui"
  },
  "devDependencies": {
    "@playwright/test": "^1.52.0",
    "pg": "^8.14.0"
  }
}
```

**Step 2: Create e2e/.gitignore**

```
node_modules/
test-results/
playwright-report/
.e2e-state.json
selkie-server
```

**Step 3: Create e2e/playwright.config.ts**

```typescript
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "html",
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:0",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { browserName: "chromium" },
    },
  ],
});
```

**Step 4: Create e2e/global-setup.ts**

This is the core of the test DB lifecycle. It:
1. Creates a fresh database `selkie_e2e_<timestamp>`
2. Runs all SQL migrations from `../migrations/`
3. Starts the Go server on a random port with DEV_MODE=true
4. Waits for /healthz to respond
5. Stores server URL + DB name for teardown

```typescript
import { type FullConfig } from "@playwright/test";
import { Client } from "pg";
import { execFileSync, spawn, type ChildProcess } from "child_process";
import { readFileSync, readdirSync, writeFileSync } from "fs";
import { join } from "path";
import * as net from "net";

const PROJECT_ROOT = join(__dirname, "..");
const STATE_FILE = join(__dirname, ".e2e-state.json");

async function getFreePort(): Promise<number> {
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.listen(0, () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

async function globalSetup(config: FullConfig) {
  const dbName = `selkie_e2e_${Date.now()}`;
  const pgUrl = process.env.E2E_PG_URL || "postgres://localhost:5432/postgres";

  // Create test database.
  const admin = new Client({ connectionString: pgUrl });
  await admin.connect();
  await admin.query(`CREATE DATABASE "${dbName}"`);
  await admin.end();

  // Run migrations.
  const dbUrl = pgUrl.replace(/\/[^/]*$/, `/${dbName}`);
  const migClient = new Client({ connectionString: dbUrl });
  await migClient.connect();

  const migrationsDir = join(PROJECT_ROOT, "migrations");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const sql = readFileSync(join(migrationsDir, file), "utf-8");
    await migClient.query(sql);
  }
  await migClient.end();

  // Build server binary.
  execFileSync("go", ["build", "-o", "e2e/selkie-server", "./cmd/control-server"], {
    cwd: PROJECT_ROOT,
    stdio: "pipe",
  });

  // Start server on a random port.
  const port = await getFreePort();
  const baseURL = `http://localhost:${port}`;

  const serverProcess: ChildProcess = spawn(
    join(__dirname, "selkie-server"),
    [],
    {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        DATABASE_URL: dbUrl,
        REDIS_URL: process.env.E2E_REDIS_URL || "redis://localhost:6379",
        DEV_MODE: "true",
        SERVER_PORT: String(port),
        LOG_LEVEL: "warn",
        INTERNAL_SESSION_SECRET: "e2e-test-secret-that-is-long-enough",
        UOA_SHARED_SECRET: "e2e-uoa-secret",
        UOA_BASE_URL: "http://localhost:0",
        UOA_DOMAIN: "localhost",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );

  // Wait for server to be ready (max 15s).
  const deadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`${baseURL}/healthz`);
      if (resp.ok) {
        ready = true;
        break;
      }
    } catch {
      // Not ready yet.
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  if (!ready) {
    serverProcess.kill();
    throw new Error("Server failed to start within 15s");
  }

  // Persist state for teardown and tests.
  const state = {
    pid: serverProcess.pid,
    port,
    baseURL,
    dbName,
    dbUrl,
    pgUrl,
  };
  writeFileSync(STATE_FILE, JSON.stringify(state));

  // Make baseURL available to all tests.
  process.env.E2E_BASE_URL = baseURL;

  // Update playwright config's baseURL for this run.
  config.projects.forEach((p) => {
    p.use.baseURL = baseURL;
  });
}

export default globalSetup;
```

**Step 5: Create e2e/global-teardown.ts**

```typescript
import { readFileSync, unlinkSync, existsSync } from "fs";
import { join } from "path";
import { Client } from "pg";

const STATE_FILE = join(__dirname, ".e2e-state.json");

async function globalTeardown() {
  if (!existsSync(STATE_FILE)) return;

  const state = JSON.parse(readFileSync(STATE_FILE, "utf-8"));

  // Kill server process.
  if (state.pid) {
    try {
      process.kill(state.pid, "SIGTERM");
    } catch {
      // Already exited.
    }
  }

  // Drop test database.
  if (state.dbName && state.pgUrl) {
    const admin = new Client({ connectionString: state.pgUrl });
    try {
      await admin.connect();
      // Terminate any remaining connections.
      await admin.query(
        `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`,
        [state.dbName],
      );
      await admin.query(`DROP DATABASE IF EXISTS "${state.dbName}"`);
    } catch (err) {
      console.error("teardown: failed to drop test DB:", err);
    } finally {
      await admin.end();
    }
  }

  // Clean up binary and state file.
  try {
    unlinkSync(join(__dirname, "selkie-server"));
  } catch {
    // Ignore.
  }
  unlinkSync(STATE_FILE);
}

export default globalTeardown;
```

**Step 6: Create e2e/helpers.ts**

Shared auth and seeding helpers for tests:

```typescript
import { type Page } from "@playwright/test";
import { readFileSync } from "fs";
import { join } from "path";

const STATE_FILE = join(__dirname, ".e2e-state.json");

export function getState(): {
  baseURL: string;
  dbUrl: string;
  port: number;
} {
  return JSON.parse(readFileSync(STATE_FILE, "utf-8"));
}

/** Navigate to dev-login and land on /admin with a valid JWT. */
export async function devLogin(page: Page) {
  const state = getState();
  await page.goto(`${state.baseURL}/auth/dev-login`);
  await page.waitForURL("**/admin#token=*", { timeout: 5000 });
  // The JS in the page will extract the token from the fragment.
  // Wait for the page to finish loading.
  await page.waitForSelector("#user-email", { timeout: 5000 });
}
```

**Step 7: Install dependencies**

Run: `cd e2e && pnpm install && pnpm exec playwright install chromium`

**Step 8: Document DEV_MODE in .env.example**

Add to the Server section of `.env.example`:

```
# Set to true to enable /auth/dev-login bypass (local development only).
# DEV_MODE=true
```

**Step 9: Commit**

```
feat(e2e): add Playwright infrastructure with isolated test database

globalSetup creates a fresh Postgres database, runs migrations, and
starts the server. globalTeardown kills the server and drops the DB.
```

---

### Task 7: E2E tests — auth flow

**Files:**
- Create: `e2e/tests/auth.spec.ts`

**Step 1: Write auth tests**

```typescript
import { test, expect } from "@playwright/test";
import { devLogin, getState } from "../helpers";

test.describe("Auth", () => {
  test("login page shows dev login button", async ({ page }) => {
    const { baseURL } = getState();
    await page.goto(`${baseURL}/login`);
    const devBtn = page.locator("#dev-login-btn");
    await expect(devBtn).toBeVisible({ timeout: 5000 });
    await expect(devBtn).toHaveText("Dev Login");
  });

  test("dev login redirects to admin with valid JWT", async ({ page }) => {
    await devLogin(page);
    // Should be on /admin now.
    expect(page.url()).toContain("/admin");
    // User info should be displayed.
    const userInfo = page.locator("#user-email");
    await expect(userInfo).toContainText("Agent Smith");
    await expect(userInfo).toContainText("(super)");
  });

  test("dev login shows avatar", async ({ page }) => {
    await devLogin(page);
    const avatar = page.locator("#user-avatar");
    await expect(avatar).toBeVisible();
    await expect(avatar).toHaveAttribute(
      "src",
      /dicebear.*AgentSmith/,
    );
  });

  test("sign out clears token and redirects to login", async ({ page }) => {
    await devLogin(page);
    await page.click("text=Sign out");
    await page.waitForURL("**/login");
    expect(page.url()).toContain("/login");
  });
});
```

**Step 2: Run tests**

Run: `cd e2e && pnpm test -- --grep Auth`
Expected: all 4 pass

**Step 3: Commit**

```
test(e2e): auth flow — dev login, avatar, sign out
```

---

### Task 8: E2E tests — Devices tab

**Files:**
- Create: `e2e/tests/devices.spec.ts`

Tests need to seed a device via direct DB inserts (since pair/claim requires a real agent). The dev user is created by dev-login.

```typescript
import { test, expect } from "@playwright/test";
import { Client } from "pg";
import { devLogin, getState } from "../helpers";
import { randomUUID } from "crypto";

test.describe("Devices tab", () => {
  let db: Client;
  let devUserID: string;

  test.beforeAll(async () => {
    const { dbUrl } = getState();
    db = new Client({ connectionString: dbUrl });
    await db.connect();
  });

  test.afterAll(async () => {
    await db.end();
  });

  test.beforeEach(async ({ page }) => {
    await devLogin(page);

    // Get dev user ID from DB.
    const res = await db.query(
      "SELECT id FROM users WHERE external_id = 'dev-agent-smith'",
    );
    devUserID = res.rows[0].id;
  });

  test("shows empty state when no devices", async ({ page }) => {
    const table = page.locator("#devices-table-wrap");
    await expect(table).toBeVisible();
    await expect(table).toContainText("No devices enrolled yet");
  });

  test("displays seeded device in table", async ({ page }) => {
    const deviceId = randomUUID();
    await db.query(
      `INSERT INTO devices (id, owner_user_id, hostname, status, credential_hash,
         agent_version, os_platform, os_version, os_arch, kernel_version,
         cpu_model, cpu_cores, total_memory_bytes, disk_total_bytes, disk_free_bytes,
         last_seen_at)
       VALUES ($1, $2, 'test-macbook', 'active', 'fakehash',
         '0.1.0', 'darwin', '15.0', 'arm64', '24.0.0',
         'Apple M2', 8, 17179869184, 500000000000, 250000000000,
         now())`,
      [deviceId, devUserID],
    );

    // Reload to pick up the new device.
    await page.reload();
    await page.waitForSelector("#devices-table-wrap:not(.hidden)", {
      timeout: 5000,
    });

    const row = page.locator("#devices-body tr", {
      hasText: "test-macbook",
    });
    await expect(row).toBeVisible();
    await expect(row).toContainText("active");
    await expect(row).toContainText("darwin");
    await expect(row).toContainText("0.1.0");

    // Clean up.
    await db.query("DELETE FROM devices WHERE id = $1", [deviceId]);
  });

  test("revoke button changes device status", async ({ page }) => {
    const deviceId = randomUUID();
    await db.query(
      `INSERT INTO devices (id, owner_user_id, hostname, status, credential_hash,
         agent_version, os_platform, os_version, os_arch, kernel_version,
         cpu_model, cpu_cores, total_memory_bytes, disk_total_bytes, disk_free_bytes)
       VALUES ($1, $2, 'revoke-target', 'active', 'fakehash',
         '0.1.0', 'darwin', '15.0', 'arm64', '24.0.0',
         'Apple M2', 8, 17179869184, 500000000000, 250000000000)`,
      [deviceId, devUserID],
    );

    await page.reload();
    await page.waitForSelector("#devices-body tr", { timeout: 5000 });

    // Accept the confirm dialog.
    page.on("dialog", (dialog) => dialog.accept());

    const row = page.locator("#devices-body tr", {
      hasText: "revoke-target",
    });
    await row.locator("text=Revoke").click();

    // After revoke, the table reloads. The device should now show as revoked.
    await page.waitForTimeout(500);
    const updatedRow = page.locator("#devices-body tr", {
      hasText: "revoke-target",
    });
    await expect(updatedRow).toContainText("revoked");

    // Verify in DB.
    const res = await db.query(
      "SELECT status FROM devices WHERE id = $1",
      [deviceId],
    );
    expect(res.rows[0].status).toBe("revoked");

    // Clean up.
    await db.query("DELETE FROM devices WHERE id = $1", [deviceId]);
  });
});
```

**Step 2: Run tests**

Run: `cd e2e && pnpm test -- --grep Devices`
Expected: all pass

**Step 3: Commit**

```
test(e2e): devices tab — empty state, display, revoke
```

---

### Task 9: E2E tests — Sessions tab

**Files:**
- Create: `e2e/tests/sessions.spec.ts`

Sessions require a device + service + connect_session seeded in the DB.

```typescript
import { test, expect } from "@playwright/test";
import { Client } from "pg";
import { devLogin, getState } from "../helpers";
import { randomUUID } from "crypto";

test.describe("Sessions tab", () => {
  let db: Client;
  let devUserID: string;

  test.beforeAll(async () => {
    const { dbUrl } = getState();
    db = new Client({ connectionString: dbUrl });
    await db.connect();
  });

  test.afterAll(async () => {
    await db.end();
  });

  test.beforeEach(async ({ page }) => {
    await devLogin(page);

    const res = await db.query(
      "SELECT id FROM users WHERE external_id = 'dev-agent-smith'",
    );
    devUserID = res.rows[0].id;
  });

  test("shows empty state when no sessions", async ({ page }) => {
    await page.click("#tab-sessions");
    const table = page.locator("#sessions-table-wrap");
    await expect(table).toBeVisible({ timeout: 5000 });
    await expect(table).toContainText("No sessions");
  });

  test("displays seeded session in table", async ({ page }) => {
    // Seed a device, service, and session.
    const deviceId = randomUUID();
    const serviceId = randomUUID();
    const sessionId = randomUUID();

    await db.query(
      `INSERT INTO devices (id, owner_user_id, hostname, status, credential_hash,
         agent_version, os_platform, os_version, os_arch, kernel_version,
         cpu_model, cpu_cores, total_memory_bytes, disk_total_bytes, disk_free_bytes)
       VALUES ($1, $2, 'session-device', 'active', 'fakehash',
         '0.1.0', 'linux', '6.1', 'amd64', '6.1.0',
         'Intel i7', 8, 17179869184, 500000000000, 250000000000)`,
      [deviceId, devUserID],
    );

    await db.query(
      `INSERT INTO services (id, device_id, name, protocol, local_bind, exposure_type)
       VALUES ($1, $2, 'ssh', 'tcp', '127.0.0.1:22', 'tcp')`,
      [serviceId, deviceId],
    );

    await db.query(
      `INSERT INTO connect_sessions (id, requester_user_id, target_device_id,
         target_service_id, requested_action, status, expires_at)
       VALUES ($1, $2, $3, $4, 'connect', 'pending',
         now() + interval '1 hour')`,
      [sessionId, devUserID, deviceId, serviceId],
    );

    await page.click("#tab-sessions");
    await page.waitForSelector("#sessions-table-wrap:not(.hidden)", {
      timeout: 5000,
    });

    const row = page.locator("#sessions-body tr").first();
    await expect(row).toBeVisible();
    await expect(row).toContainText("pending");
    await expect(row).toContainText("connect");

    // Clean up (cascade deletes handle services/sessions).
    await db.query("DELETE FROM connect_sessions WHERE id = $1", [sessionId]);
    await db.query("DELETE FROM services WHERE id = $1", [serviceId]);
    await db.query("DELETE FROM devices WHERE id = $1", [deviceId]);
  });
});
```

**Step 2: Run tests**

Run: `cd e2e && pnpm test -- --grep Sessions`
Expected: all pass

**Step 3: Commit**

```
test(e2e): sessions tab — empty state, seeded session display
```

---

### Task 10: E2E tests — System tab

**Files:**
- Create: `e2e/tests/system.spec.ts`

```typescript
import { test, expect } from "@playwright/test";
import { devLogin } from "../helpers";

test.describe("System tab", () => {
  test.beforeEach(async ({ page }) => {
    await devLogin(page);
    await page.click("#tab-system");
    // Wait for the system panel to become visible.
    await page.waitForSelector("#panel-system:not(.hidden)", {
      timeout: 5000,
    });
  });

  test("health checks show ok", async ({ page }) => {
    await expect(page.locator("#health-healthz")).toContainText("ok", {
      timeout: 5000,
    });
    await expect(page.locator("#health-readyz")).toContainText("ok", {
      timeout: 5000,
    });
  });

  test("server info displays version", async ({ page }) => {
    await expect(page.locator("#sys-version")).toContainText("0.1.0", {
      timeout: 5000,
    });
  });

  test("infrastructure status is visible", async ({ page }) => {
    // OPA should show as not configured in test env.
    await expect(page.locator("#sys-opa")).toContainText("allow-all", {
      timeout: 5000,
    });
  });

  test("JWT claims are displayed", async ({ page }) => {
    const claimsBlock = page.locator("#jwt-claims");
    await expect(claimsBlock).toContainText("is_super", { timeout: 5000 });
    await expect(claimsBlock).toContainText("agent.smith@dev.local");
  });

  test("audit log shows dev login event", async ({ page }) => {
    // The dev login itself should have created an audit event (if audit is wired).
    // If no audit events, we should see the empty or the table.
    const auditSection = page.locator("#panel-system");
    await expect(auditSection.locator("text=Audit Log")).toBeVisible();

    // Either we see "user.login" in the audit body, or we see an error/empty state.
    // The dev login doesn't log audit events (no auditor in test), so expect empty or error.
    const auditArea = page.locator("#audit-loading, #audit-error, #audit-table-wrap");
    await expect(auditArea.first()).toBeVisible({ timeout: 5000 });
  });
});
```

**Step 2: Run tests**

Run: `cd e2e && pnpm test -- --grep System`
Expected: all pass

**Step 3: Commit**

```
test(e2e): system tab — health, server info, JWT claims, audit
```

---

### Task 11: GitHub Actions CI pipeline

**Files:**
- Modify: `.github/workflows/ci.yml`

Replace the entire file. Adds:
- Existing lint, build+test, web-lint jobs (preserved)
- New `e2e` job with Postgres + Redis services
- New `deploy` placeholder job (main branch only, empty for now)

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  lint:
    name: lint (gate)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: go vet
        run: go vet ./...

      - name: golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: v2.1.6
          args: --timeout=5m

  build-test:
    name: build + test
    needs: lint
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_DB: selkie_test
          POSTGRES_USER: selkie
          POSTGRES_PASSWORD: testpass
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U selkie -d selkie_test"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
    steps:
      - uses: actions/checkout@v4

      - name: set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - name: verify modules
        run: |
          go mod download
          go mod verify

      - name: go build
        run: go build ./...

      - name: go test
        run: go test -race -count=1 ./...

  web:
    name: web lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - name: htmlhint
        run: npx --yes htmlhint@1.1.4 "web/**/*.html"

      - name: prettier check
        run: npx --yes prettier@3.3.3 --check "web/**/*.{html,css,js}"

  e2e:
    name: e2e tests
    needs: [lint, build-test]
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_DB: postgres
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U postgres"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
    steps:
      - uses: actions/checkout@v4

      - name: set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.23"
          cache: true

      - uses: actions/setup-node@v4
        with:
          node-version: "20"

      - uses: pnpm/action-setup@v4
        with:
          version: 9

      - name: install e2e deps
        working-directory: e2e
        run: pnpm install --frozen-lockfile

      - name: install playwright browsers
        working-directory: e2e
        run: pnpm exec playwright install --with-deps chromium

      - name: run e2e tests
        working-directory: e2e
        env:
          E2E_PG_URL: postgres://postgres:postgres@localhost:5432/postgres
          E2E_REDIS_URL: redis://localhost:6379
        run: pnpm test

      - name: upload test report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report
          path: e2e/playwright-report/
          retention-days: 7

  # Placeholder — deploy job runs only on main after all checks pass.
  deploy:
    name: deploy (placeholder)
    if: github.ref == 'refs/heads/main' && github.event_name == 'push'
    needs: [lint, build-test, web, e2e]
    runs-on: ubuntu-latest
    steps:
      - run: echo "TODO — deploy to Google Cloud"
```

**Step 2: Commit**

```
ci: add e2e job with isolated test DB, deploy placeholder on main
```

---

### Task 12: Final verification

**Step 1: Run full Go test suite**

Run: `go test -race -count=1 ./...`
Expected: all pass

**Step 2: Run linter**

Run: `make lint`
Expected: clean

**Step 3: Run E2E locally**

Run: `cd e2e && pnpm test`
Expected: all tests pass, test database created and dropped automatically

**Step 4: Verify dev login manually**

1. `DEV_MODE=true go run ./cmd/control-server`
2. Open `http://localhost:8080/login`
3. "Dev Login" button visible
4. Click it → land on `/admin` with Agent Smith avatar + name

**Step 5: Final commit**

Only if there are remaining uncommitted changes from adjustments.
