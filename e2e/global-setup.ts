import { type FullConfig } from "@playwright/test";
import { Client } from "pg";
import { execFileSync, spawn, type ChildProcess } from "child_process";
import { writeFileSync } from "fs";
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

  // The server runs its own migrations on startup via schema_migrations
  // tracking, so we skip manual migration here to avoid conflicts.
  const dbUrl = pgUrl.replace(/\/[^/]*$/, `/${dbName}`);

  // Build React admin UI.
  execFileSync("pnpm", ["build"], {
    cwd: join(PROJECT_ROOT, "admin-ui"),
    stdio: "pipe",
  });

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
        CONFIRM_DEV_MODE: "true",
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

  // Collect server output for diagnostics.
  let serverStdout = "";
  let serverStderr = "";
  serverProcess.stdout?.on("data", (d: Buffer) => {
    serverStdout += d.toString();
  });
  serverProcess.stderr?.on("data", (d: Buffer) => {
    serverStderr += d.toString();
  });

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
    const msg = [
      "Server failed to start within 15s",
      `stdout: ${serverStdout}`,
      `stderr: ${serverStderr}`,
    ].join("\n");
    throw new Error(msg);
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
