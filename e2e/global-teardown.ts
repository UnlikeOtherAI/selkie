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

  if (state.uoaPid) {
    try { process.kill(state.uoaPid, "SIGTERM"); } catch { /* Already exited. */ }
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
