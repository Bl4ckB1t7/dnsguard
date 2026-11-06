import { expect, test } from "./diagnostics";
import { fixturePrimary, fixtureSecondary, fixtureToken, fixtureTsigPath, mockBindSetup, mockDashboard, mockPlatformFirstInstall } from "./fixtures";

test.describe("平台优先的首次部署向导", () => {
  test("Bootstrap 登录后进入 BIND 接入阶段", async ({ page }) => {
    await mockPlatformFirstInstall(page);
    await page.goto("/");

    await expect(page.getByRole("heading", { name: "先启动 DNSGuard 平台" })).toBeVisible();
    await page.getByLabel("Bootstrap Token").fill(fixtureToken);
    await page.getByLabel("管理员密码", { exact: true }).fill("fixture-password-123");
    await page.getByLabel("确认密码").fill("fixture-password-123");
    await page.getByRole("button", { name: "检查平台并继续" }).click();
    await expect(page.getByText("Bootstrap Token", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "创建管理员并启动平台" }).click();
    await expect(page.getByRole("heading", { name: "接入已有 BIND" })).toBeVisible();
  });

  test("BIND 接入失败时展示 REFUSED、SERVFAIL 和超时证据", async ({ page }) => {
    for (const outcome of ["refused", "servfail", "timeout", "tsig"] as const) {
      await mockBindSetup(page, outcome);
      await page.goto("/");
      await page.getByLabel("Primary 地址（host:port）").fill(fixturePrimary);
      await page.getByLabel("Secondary 地址（每行一台，至少一台）").fill(fixtureSecondary);
      await page.getByLabel("受保护 TSIG Key 文件路径").fill(fixtureTsigPath);
      await page.getByRole("button", { name: "验证节点和 TSIG" }).click();
      await expect(page.getByText("初始化检查未通过")).toBeVisible();
      await expect(page.getByText(outcome === "refused" ? "RCODE=REFUSED" : outcome === "servfail" ? "RCODE=SERVFAIL" : outcome === "timeout" ? "请求超时" : "TSIG Key 文件不可读或格式无效")).toBeVisible();
      await page.unrouteAll();
    }
  });

  test("成功接入可预览并下载 RPZ 配置包，完成后进入管理页面", async ({ page }) => {
    await mockDashboard(page);
    await mockBindSetup(page);
    await page.goto("/");
    await page.getByLabel("Primary 地址（host:port）").fill(fixturePrimary);
    await page.getByLabel("Secondary 地址（每行一台，至少一台）").fill(fixtureSecondary);
    await page.getByLabel("受保护 TSIG Key 文件路径").fill(fixtureTsigPath);
    await page.getByRole("button", { name: "预览配置包" }).click();
    await expect(page.getByText("已生成 2 个文件")).toBeVisible();
    await page.getByText("README.md", { exact: true }).click();
    await expect(page.locator("pre").filter({ hasText: "fixture package; no secrets" })).toBeVisible();
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "下载 ZIP" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("dnsguard-rpz-package.zip");

    await page.getByRole("button", { name: "验证节点和 TSIG" }).click();
    await expect(page.getByText("BIND 连接成功，可以进入白名单配置。")).toBeVisible();
    await page.getByRole("button", { name: "验证通过并接入 BIND" }).click();
    await expect(page.getByRole("heading", { name: "域盾 DNSGuard" })).toBeVisible();
  });

  test("配置包下载失败时显示明确错误", async ({ page }) => {
    await mockBindSetup(page);
    await page.route("**/api/setup/rpz-package/download", async (route) => {
      await route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: "BIND 配置包服务暂不可用" }) });
    });
    await page.goto("/");
    await page.getByLabel("Primary 地址（host:port）").fill(fixturePrimary);
    await page.getByLabel("Secondary 地址（每行一台，至少一台）").fill(fixtureSecondary);
    await page.getByLabel("受保护 TSIG Key 文件路径").fill(fixtureTsigPath);
    await page.getByRole("button", { name: "下载 ZIP" }).click();
    await expect(page.getByText("配置包下载失败：BIND 配置包服务暂不可用")).toBeVisible();
  });
});
