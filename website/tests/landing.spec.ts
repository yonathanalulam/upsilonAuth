import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
});

test("renders the complete product narrative", async ({ page }) => {
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Temporary, delegated authority for machine workloads.",
  );
  await expect(page.getByRole("heading", { name: "Use temporary permissions instead of shared credentials." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "See delegation in action." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "How authority moves through UpsilonAuth." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Run a complete local example." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Current status: beta" })).toBeVisible();
});

test("explains allowed and denied delegated requests", async ({ page }) => {
  const demo = page.getByRole("region", { name: "See delegation in action." });
  const decision = demo.locator(".demo-decision-result");

  await expect(demo.getByRole("heading", { name: "Orchestrator" })).toBeVisible();
  await expect(demo.getByRole("heading", { name: "Research Agent" })).toBeVisible();
  await expect(demo.getByRole("heading", { name: "Browser Worker" })).toBeVisible();
  await expect(demo.getByText("Browser Worker authority ⊆ Research Agent authority ⊆ Orchestrator authority")).toBeVisible();
  await expect(decision.getByText("ALLOW", { exact: true })).toBeVisible();
  await expect(decision).toContainText("Capability was delegated to this workload.");

  const restricted = demo.getByRole("button", { name: /Attempt restricted action/ });
  await restricted.focus();
  await page.keyboard.press("Enter");
  await expect(restricted).toHaveAttribute("aria-pressed", "true");
  await expect(decision.getByText("DENY", { exact: true })).toBeVisible();
  await expect(decision).toContainText("database:delete");
  await expect(decision).toContainText("Permission was never delegated.");
  await expect(decision).toContainText("web:read");

  await demo.getByRole("button", { name: /Run allowed request/ }).click();
  await expect(decision.getByText("ALLOW", { exact: true })).toBeVisible();
  await expect(decision).toContainText("example.com");
});

test("switches quickstart code without shifting the workbench", async ({ page }) => {
  const workbench = page.locator(".quickstart-workbench");
  const before = await workbench.boundingBox();
  await page.getByRole("tab", { name: /Verify/ }).click();
  await expect(page.locator(".code-body pre")).toContainText("verifier.Require");
  const after = await workbench.boundingBox();
  expect(after?.width).toBe(before?.width);
});

test("copies the local setup command", async ({ page }) => {
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText(value: string) {
          (window as typeof window & { copiedText?: string }).copiedText = value;
          return Promise.resolve();
        },
      },
    });
  });
  await page.getByRole("button", { name: "Copy Clone and start the local stack" }).click();
  await expect.poll(() => page.evaluate(() => (window as typeof window & { copiedText?: string }).copiedText)).toBe(
    "git clone https://github.com/yonathanalulam/upsilonAuth.git\ncd upsilonAuth\ngo run ./cmd/keygen > .env\n\nset -a\n. ./.env\nset +a\n\ndocker compose up --build -d\ncurl --fail http://127.0.0.1:8080/readyz",
  );
});

test("documents the authority model and security behavior", async ({ page }) => {
  await page.goto("/docs");
  await expect(page).toHaveTitle("UpsilonAuth");
  await expect(page.getByRole("heading", { name: "Run UpsilonAuth and protect a service." })).toBeVisible();
  await expect(page.getByText("POST", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("/v1/leases/:id/consume", { exact: true })).toBeVisible();

  await page.goto("/security");
  await expect(page).toHaveTitle("UpsilonAuth");
  await expect(page.getByRole("heading", { name: "How UpsilonAuth checks authority." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "UpsilonAuth is currently in beta." })).toBeVisible();
});

test("uses the UpsilonAuth name and logo consistently", async ({ page }) => {
  await expect(page).toHaveTitle("UpsilonAuth");
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", /upsilonauth-logo\.svg/);
  await expect(page.locator('img[src="/upsilonauth-logo.svg"]').first()).toBeVisible();
});

test("keeps every public page within the viewport", async ({ page }) => {
  for (const path of ["/", "/docs", "/security"]) {
    await page.goto(path);
    const dimensions = await page.evaluate(() => ({
      viewport: window.innerWidth,
      content: document.documentElement.scrollWidth,
    }));
    expect(dimensions.content, `${path} should not overflow`).toBeLessThanOrEqual(dimensions.viewport);
  }
});
