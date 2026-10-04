import { test, expect } from "@playwright/test";
import { devLogin } from "../helpers";

test.describe("System page", () => {
  test.beforeEach(async ({ page }) => {
    await devLogin(page);
    await page.click("#nav-system");
    await page.waitForURL("**/admin/system", { timeout: 5000 });
    await page.waitForSelector("#page-system", { timeout: 5000 });
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
    await expect(page.locator("#sys-opa")).toContainText("allow-all", {
      timeout: 5000,
    });
  });

  test("JWT claims are displayed", async ({ page }) => {
    const claimsBlock = page.locator("#jwt-claims");
    await expect(claimsBlock).toContainText("is_super", { timeout: 5000 });
    await expect(claimsBlock).not.toContainText("agent.smith@dev.local");
    await expect(claimsBlock).not.toContainText("display_name");
  });

  test("audit log section is visible", async ({ page }) => {
    const systemPage = page.locator("#page-system");
    await expect(systemPage.locator("text=Audit Log")).toBeVisible();
    await expect(page.locator("#audit-count")).toBeVisible({ timeout: 5000 });
  });
});
