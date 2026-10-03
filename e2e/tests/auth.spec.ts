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

// Browser fixtures cover the rendered control; Go database tests prove UOA family semantics.
const codeA="A".repeat(43);
const codeB="B".repeat(43);

async function debugRoutes(page: import("@playwright/test").Page) {
 let displayed=codeA;
 await page.route("**/auth/debug-login/issue",async route=>{
  const body=route.request().postDataJSON();
  if(body.previous_token){expect(body.previous_token).toBe(displayed);displayed=codeB;}
  await route.fulfill({json:{url:new URL(route.request().url()).origin+"/",token:displayed}});
 });
 return () => displayed;
}

for(const width of [390,1440]) {
 test(`debug create renew and copy at ${width}px`,async({page,context})=>{
  await page.setViewportSize({width,height:900});
  await context.grantPermissions(["clipboard-read","clipboard-write"]);
  const displayed=await debugRoutes(page);
  await devLogin(page);
  await page.getByRole("button",{name:"Debug login",exact:true}).click();
  const dialog=page.getByRole("dialog");
  await dialog.getByRole("button",{name:"Create code",exact:true}).click();
  const input=dialog.getByLabel("Login code or JSON",{exact:true});
  await expect.poll(async()=>JSON.parse((await input.inputValue()) || "{}").token).toBe(codeA);
  await dialog.getByRole("button",{name:"Renew",exact:true}).click();
  await expect.poll(async()=>JSON.parse((await input.inputValue()) || "{}").token).toBe(codeB);
  expect(displayed()).toBe(codeB);
  const value=JSON.parse(await input.inputValue());expect(Object.keys(value).sort()).toEqual(["token","url"]);
  await dialog.getByRole("button",{name:"Copy JSON",exact:true}).click();
  expect(JSON.parse(await page.evaluate(()=>navigator.clipboard.readText()))).toEqual(value);
  await page.screenshot({path:`/tmp/selkie-debug-${width}-signed.png`});
 });
}

for(const shape of ["bare","json"]) {
 test(`login accepts ${shape} one-time code`,async({page})=>{
  const {baseURL}=getState();
  await page.setViewportSize({width:shape==="bare"?390:1440,height:900});
  await page.route("**/auth/debug-login/redeem",async route=>{
   expect(route.request().postDataJSON()).toEqual({token:codeA});
   await route.fulfill({json:{token:recipientFixture()}});
  });
  await page.route("**/auth/session",route=>route.fulfill({json:{sub:"recipient",display_name:"Recipient",is_super:true}}));
  await page.goto(`${baseURL}/login`);
  await page.getByRole("button",{name:"Debug login",exact:true}).click();
  const dialog=page.getByRole("dialog");
  await dialog.getByLabel("Login code or JSON",{exact:true}).fill(shape==="bare"?codeA:JSON.stringify({url:baseURL+"/",token:codeA}));
  await page.screenshot({path:`/tmp/selkie-debug-${shape}-login.png`});
  await dialog.getByRole("button",{name:"Log in with code",exact:true}).click();
  await page.waitForURL("**/admin");
  expect(await page.evaluate(()=>localStorage.getItem("selkie_jwt"))).toBe(recipientFixture());
 });
}

function recipientFixture() {
 const header=Buffer.from(JSON.stringify({alg:"HS256"})).toString("base64url");
 const body=Buffer.from(JSON.stringify({sub:"recipient",jti:"independent",exp:4102444800})).toString("base64url");
 return `${header}.${body}.browser-fixture`;
}

for(const input of ["{invalid JSON",JSON.stringify({url:"https://another.invalid/",token:codeA}),JSON.stringify({product:"selkie",version:1,token:"retired-session"})]) {
 test(`login rejects invalid payload ${input.slice(0,24)}`,async({page})=>{
  const {baseURL}=getState();await page.goto(`${baseURL}/login`);
  await page.getByRole("button",{name:"Debug login",exact:true}).click();
  const dialog=page.getByRole("dialog");const field=dialog.getByLabel("Login code or JSON",{exact:true});
  await field.fill(input);await dialog.getByRole("button",{name:"Log in with code",exact:true}).click();
  await expect(dialog.getByRole("alert")).toBeVisible();await expect(field).toHaveValue("");
  expect(await page.evaluate(()=>localStorage.getItem("selkie_jwt"))).toBeNull();
 });
}

test("used code and failed logout remain retryable",async({page})=>{
 const {baseURL}=getState();await page.route("**/auth/debug-login/redeem",route=>route.fulfill({status:401,json:{error:"used"}}));
 await page.goto(`${baseURL}/login`);await page.getByRole("button",{name:"Debug login",exact:true}).click();
 const dialog=page.getByRole("dialog");await dialog.getByLabel("Login code or JSON",{exact:true}).fill(codeA);
 await dialog.getByRole("button",{name:"Log in with code",exact:true}).click();
 await expect(dialog.getByRole("alert")).toContainText("already been used");
 await dialog.getByRole("button",{name:"Cancel",exact:true}).click();await devLogin(page);
 const token=await page.evaluate(()=>localStorage.getItem("selkie_jwt"));
 await page.route("**/auth/logout",route=>route.fulfill({status:503,json:{error:"retry"}}));
 await page.click("button[title='Sign out']");await expect(page.getByRole("alert")).toContainText("Try again");
 expect(await page.evaluate(()=>localStorage.getItem("selkie_jwt"))).toBe(token);
});

test("pending code cannot expose a previous account",async({page})=>{
 await devLogin(page);
 let release!:()=>void;let started!:()=>void;
 const pending=new Promise<void>(resolve=>{release=resolve});const requested=new Promise<void>(resolve=>{started=resolve});
 await page.route("**/auth/debug-login/issue",async route=>{started();await pending;await route.fulfill({json:{url:new URL(route.request().url()).origin+"/",token:codeA}})});
 await page.getByRole("button",{name:"Debug login",exact:true}).click();const dialog=page.getByRole("dialog");
 await dialog.getByRole("button",{name:"Create code",exact:true}).click();await requested;
 await page.evaluate(token=>localStorage.setItem("selkie_jwt",token),recipientFixture());release();
 await expect(dialog.getByRole("button",{name:"Create code",exact:true})).toBeEnabled();
 await expect(dialog.getByLabel("Login code or JSON",{exact:true})).toHaveValue("");
});

test("reload after unconfirmed logout keeps a working retry",async({page})=>{
 await devLogin(page);const token=await page.evaluate(()=>localStorage.getItem("selkie_jwt"));
 let attempts=0;
 await page.route("**/auth/logout",route=>{attempts++;return route.fulfill({status:attempts===1?503:204,...(attempts===1?{json:{error:"retry"}}:{})})});
 await page.click("button[title='Sign out']");await expect(page.getByRole("alert")).toContainText("Try again");
 await page.route("**/auth/session",route=>route.fulfill({status:503,json:{error:"pending",logout_pending:true}}));
 await page.reload();await expect(page.getByRole("button",{name:"Retry",exact:true})).toBeVisible();
 expect(await page.evaluate(()=>localStorage.getItem("selkie_jwt"))).toBe(token);
 await page.getByRole("button",{name:"Retry",exact:true}).click();await page.waitForURL("**/login");
 expect(attempts).toBe(2);expect(await page.evaluate(()=>localStorage.getItem("selkie_jwt"))).toBeNull();
});
