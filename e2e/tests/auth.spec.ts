import { test, expect } from "@playwright/test";
import { createHmac } from "node:crypto";
import { devLogin, getState } from "../helpers";

test.describe("Auth", () => {
  test("login page shows dev login button", async ({ page }) => {
    const { baseURL } = getState();
    await page.goto(`${baseURL}/login`);
    const devBtn = page.locator("#dev-login-btn");
    await expect(devBtn).toBeVisible({ timeout: 10000 });
    await expect(devBtn).toHaveText("Dev Login");
  });

  test("dev login redirects to admin with valid JWT", async ({ page }) => {
    await devLogin(page);
    expect(page.url()).toContain("/admin");
    const userInfo = page.locator("#user-email");
    await expect(userInfo).toContainText("Agent Smith");
  });

  test("profile display uses the API while persisted JWT contains only references", async ({ page }) => {
    await devLogin(page);
    await expect(page.locator("#user-email")).toContainText("Agent Smith");
    const claims = await page.evaluate(() => {
      const token = localStorage.getItem("selkie_jwt")!;
      return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    });
    expect(claims.sub).toBeTruthy();
    expect(claims).not.toHaveProperty("email");
    expect(claims).not.toHaveProperty("display_name");
    expect(claims).not.toHaveProperty("picture");
  });

  test("legacy copied profiles are removed from persisted session on reload", async ({ page }) => {
    await devLogin(page);
    const oldClaims = await page.evaluate(() => {
      const token = localStorage.getItem("selkie_jwt")!;
      return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    });
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ ...oldClaims, email: "old@example.com", display_name: "Old Copy" })).toString("base64url");
    const signature = createHmac("sha256", "e2e-test-secret-that-is-long-enough").update(`${header}.${body}`).digest("base64url");
    await page.evaluate((token) => localStorage.setItem("selkie_jwt", token), `${header}.${body}.${signature}`);
    await page.reload();
    await expect(page.locator("#user-email")).toContainText("Agent Smith");
    const migrated = await page.evaluate(() => {
      const token = localStorage.getItem("selkie_jwt")!;
      return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    });
    expect(migrated.exp).toBe(oldClaims.exp);
    expect(migrated).not.toHaveProperty("email");
    expect(migrated).not.toHaveProperty("display_name");
  });

  test("dev login shows avatar", async ({ page }) => {
    await devLogin(page);
    const avatar = page.locator("#user-avatar");
    await expect(avatar).toBeVisible();
    await expect(avatar).toHaveAttribute("src", /dicebear.*AgentSmith/);
  });

  test("sign out clears token and redirects to login", async ({ page }) => {
    await devLogin(page);
    await page.click("button[title='Sign out']");
    await page.waitForURL("**/login", { timeout: 5000 });
    expect(page.url()).toContain("/login");
  });
});

test.describe("Debug session popup", () => {
  test("exports an existing session and imports it from the login popup", async ({ page, context }) => {
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    await devLogin(page);
    await page.getByRole("button", { name: "Debug session snapshot" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    const snapshot = await dialog.getByLabel("Session snapshot", { exact: true }).inputValue();
    await dialog.getByRole("button", { name: "Copy JSON", exact: true }).click();
    await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(snapshot);
    const data = JSON.parse(snapshot);
    expect(data.product).toBe("selkie");
    expect(data.version).toBe(1);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await page.click("button[title='Sign out']");
    await page.waitForURL("**/login");
    await page.getByRole("button", { name: "Debug session snapshot" }).click();
    await dialog.getByLabel("Session snapshot", { exact: true }).fill(snapshot);
    await dialog.getByRole("button", { name: "Log in with session", exact: true }).click();
    await page.waitForURL("**/admin");
    await expect(page.locator("#user-email")).toContainText("Agent Smith");
  });

  test("rejects forged sessions and clears sensitive popup input", async ({ page }) => {
    const { baseURL } = getState();
    await page.goto(`${baseURL}/login`);
    await page.getByRole("button", { name: "Debug session snapshot" }).click();
    const dialog = page.getByRole("dialog");
    const input = dialog.getByLabel("Session snapshot", { exact: true });
    const forged = `${Buffer.from(JSON.stringify({ alg: "HS256" })).toString("base64url")}.${Buffer.from(JSON.stringify({ sub: "forged", exp: Math.floor(Date.now() / 1000) + 3600 })).toString("base64url")}.invalid`;
    await input.fill(JSON.stringify({ product: "selkie", version: 1, token: forged }));
    await dialog.getByRole("button", { name: "Log in with session", exact: true }).click();
    await expect(dialog.getByRole("alert")).toContainText("cannot access");
    await expect(input).toHaveValue("");
    expect(new URL(page.url()).pathname).toBe("/login");
    expect(await page.evaluate(() => localStorage.getItem("selkie_jwt"))).toBeNull();
    await input.fill("sensitive snapshot");
    await page.keyboard.press("Escape");
    await page.getByRole("button", { name: "Debug session snapshot" }).click();
    await expect(input).toHaveValue("");
  });
});

function signedTestToken(audience: string, expiry: number): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify({ sub: "test-user", iss: "selkie", aud: [audience],
    is_super: true, iat: Math.floor(Date.now() / 1000), exp: expiry })).toString("base64url");
  const signingInput = `${header}.${body}`;
  // This is the disposable server's public test fixture, never a production key.
  const signature = createHmac("sha256", "e2e-test-secret-that-is-long-enough").update(signingInput).digest("base64url");
  return `${signingInput}.${signature}`;
}

for (const scenario of ["malformed", "expired", "mobile"] as const) {
  test(`debug session rejects ${scenario} input`, async ({ page, request }) => {
    const { baseURL } = getState();
    await page.goto(`${baseURL}/login`);
    await page.getByRole("button", { name: "Debug session snapshot" }).click();
    const dialog = page.getByRole("dialog");
    const input = dialog.getByLabel("Session snapshot", { exact: true });
    let snapshot = "{invalid JSON";
    if (scenario !== "malformed") {
      const token = signedTestToken(scenario === "mobile" ? "mobile" : "admin",
        Math.floor(Date.now() / 1000) + (scenario === "expired" ? -120 : 3600));
      if (scenario === "mobile") {
        const validAdmin = signedTestToken("admin", Math.floor(Date.now() / 1000) + 3600);
        const accepted = await request.get(`${baseURL}/api/v1/system/info`, {
          headers: { Authorization: `Bearer ${validAdmin}` },
        });
        expect(accepted.status()).toBe(200);
      }
      // Independently prove the real backend rejects both validly signed fixtures.
      const response = await request.get(`${baseURL}/api/v1/system/info`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(response.status()).toBe(401);
      snapshot = JSON.stringify({ product: "selkie", version: 1, token });
    }
    await input.fill(snapshot);
    await dialog.getByRole("button", { name: "Log in with session", exact: true }).click();
    await expect(dialog.getByRole("alert")).toBeVisible();
    await expect(input).toHaveValue("");
    expect(new URL(page.url()).pathname).toBe("/login");
    expect(await page.evaluate(() => localStorage.getItem("selkie_jwt"))).toBeNull();
  });
}

test("closing debug popup cancels a pending validated import", async ({ page }) => {
  await devLogin(page);
  const token = await page.evaluate(() => localStorage.getItem("selkie_jwt"));
  await page.click("button[title='Sign out']");
  await page.waitForURL("**/login");
  let release!: () => void;
  let started!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const requested = new Promise<void>((resolve) => { started = resolve; });
  await page.route("**/api/v1/system/info", async (route) => {
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    started();
    await pending;
    await route.fulfill({ response });
  });
  await page.getByRole("button", { name: "Debug session snapshot" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Session snapshot", { exact: true }).fill(JSON.stringify({ product: "selkie", version: 1, token }));
  await dialog.getByRole("button", { name: "Log in with session", exact: true }).click();
  await requested;
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  const delivered = page.waitForResponse("**/api/v1/system/info");
  release();
  await delivered;
  await page.getByRole("button", { name: "Debug session snapshot" }).click();
  await expect(dialog.getByLabel("Session snapshot", { exact: true })).toHaveValue("");
  expect(new URL(page.url()).pathname).toBe("/login");
  expect(await page.evaluate(() => localStorage.getItem("selkie_jwt"))).toBeNull();
});
