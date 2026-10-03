import { test, expect } from "@playwright/test";
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
  test("exports an existing session and imports it from the login popup", async ({ page }) => {
    await devLogin(page);
    await page.getByRole("button", { name: "Debug session snapshot" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    const snapshot = await dialog.getByLabel("Session snapshot", { exact: true }).inputValue();
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
