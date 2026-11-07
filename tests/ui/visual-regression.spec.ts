import type { Page } from "@playwright/test";
import { expect, test } from "./diagnostics";
import { fixturePrimary, fixtureSecondary, fixtureTsigPath, mockBindSetup, mockDashboard, mockPlatformFirstInstall } from "./fixtures";

async function expectNoHorizontalOverflow(page: Page): Promise<void> {
  const fits = await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
  expect(fits, "页面不应产生横向溢出").toBeTruthy();
}

test.describe("关键部署页面视觉回归", () => {
  test("平台优先首次安装页面在各视口可用", async ({ page }) => {
    await mockPlatformFirstInstall(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "先启动 DNSGuard 平台" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expect(page).toHaveScreenshot("platform-first-install.png", { fullPage: true });
  });

  test("BIND 诊断错误页面保持可读且操作区可见", async ({ page }) => {
    await mockBindSetup(page, "refused");
    await page.goto("/");
    await page.getByLabel("Primary 地址（host:port）").fill(fixturePrimary);
    await page.getByLabel("Secondary 地址（每行一台，至少一台）").fill(fixtureSecondary);
    await page.getByLabel("受保护 TSIG Key 文件路径").fill(fixtureTsigPath);
    await page.getByRole("button", { name: "验证节点和 TSIG" }).click();
    await expect(page.getByText("RCODE=REFUSED")).toBeVisible();
    await expect(page.getByRole("button", { name: "验证节点和 TSIG" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expect(page).toHaveScreenshot("bind-diagnostic-refused.png", { fullPage: true });
  });

  test("RPZ 管理页面在各视口保持可用", async ({ page }) => {
    await mockDashboard(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "域盾 DNSGuard" })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expect(page).toHaveScreenshot("rpz-dashboard.png", { fullPage: true });
  });
});
