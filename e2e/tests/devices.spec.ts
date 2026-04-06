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

    await page.reload();
    await page.waitForSelector("#devices-table-wrap:not(.hidden)", {
      timeout: 5000,
    });

    const row = page.locator("#devices-body tr", { hasText: "test-macbook" });
    await expect(row).toBeVisible();
    await expect(row).toContainText("active");
    await expect(row).toContainText("darwin");
    await expect(row).toContainText("0.1.0");

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

    page.on("dialog", (dialog) => dialog.accept());

    const row = page.locator("#devices-body tr", { hasText: "revoke-target" });
    await row.getByRole("button", { name: "Revoke" }).click();

    // Wait for table reload after revoke.
    await page.waitForTimeout(1000);

    const updatedRow = page.locator("#devices-body tr", {
      hasText: "revoke-target",
    });
    await expect(updatedRow).toContainText("revoked");

    const res = await db.query("SELECT status FROM devices WHERE id = $1", [
      deviceId,
    ]);
    expect(res.rows[0].status).toBe("revoked");

    await db.query("DELETE FROM devices WHERE id = $1", [deviceId]);
  });
});
