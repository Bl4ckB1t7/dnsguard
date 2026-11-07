import { expect, test } from "./diagnostics";

const token = process.env.E2E_BOOTSTRAP_TOKEN;
const tsigPath = process.env.E2E_TSIG_PATH ?? "/run/dnsguard-secrets/rpz-manager.key";
const primary = process.env.E2E_PRIMARY ?? "172.34.0.10:53";
const secondary = process.env.E2E_SECONDARY ?? "172.34.0.11:53";
const phase = process.env.E2E_REAL_PHASE ?? "initial";

test.describe("真实隔离 BIND 首次部署", () => {
  test.skip(!process.env.E2E_REAL_BASE_URL, "只由 tests/e2e/run-all.sh 提供真实隔离环境参数");

  test("平台启动、BIND 接入、配置包、白名单草稿与真实发布", async ({ page }) => {
    test.skip(phase === "final", "最终阶段只执行只读核验");
    page.on("dialog", (dialog) => void dialog.accept());
    await page.goto("/");

    if (phase === "platform" || phase === "full" || phase === "package") {
      test.skip(!token, "平台阶段需要测试 Bootstrap Token");
      await expect(page.getByRole("heading", { name: "先启动 DNSGuard 平台" })).toBeVisible();
      await page.getByLabel("Bootstrap Token").fill(token!);
      await page.getByLabel("管理员密码", { exact: true }).fill("e2e-admin-password-123");
      await page.getByLabel("确认密码").fill("e2e-admin-password-123");
      await page.getByRole("button", { name: "检查平台并继续" }).click();
      await page.getByRole("button", { name: "创建管理员并启动平台" }).click();
      if (process.env.E2E_PLATFORM_STORAGE_STATE) {
        await page.context().storageState({ path: process.env.E2E_PLATFORM_STORAGE_STATE });
      }
      if (phase === "platform") return;
    }

    await expect(page.getByRole("heading", { name: "接入已有 BIND" })).toBeVisible();
    await page.getByLabel("Primary 地址（host:port）").fill(primary);
    await page.getByLabel("Secondary 地址（每行一台，至少一台）").fill(secondary);
    await page.getByLabel("受保护 TSIG Key 文件路径").fill(tsigPath);
    await page.getByRole("button", { name: "预览配置包" }).click();
    await expect(page.getByText(/已生成/)).toBeVisible();
    if (phase !== "bind") {
      const download = page.waitForEvent("download");
      await page.getByRole("button", { name: "下载 ZIP" }).click();
      const packageDownload = await download;
      expect(packageDownload.suggestedFilename()).toBe("dnsguard-rpz-package.zip");
      if (process.env.E2E_PACKAGE_PATH) await packageDownload.saveAs(process.env.E2E_PACKAGE_PATH);
    }
    if (phase === "package") return;

    const validationSuccess = page.getByText("BIND 连接成功，可以进入白名单配置。");
    for (let attempt = 0; attempt < 30 && await validationSuccess.count() === 0; attempt += 1) {
      await page.getByRole("button", { name: "验证节点和 TSIG" }).click();
      if (await validationSuccess.count() > 0) break;
      await page.waitForTimeout(1000);
    }
    await expect(validationSuccess).toBeVisible({ timeout: 30_000 });
    let completeStatus = 422;
    let completeBody = "";
    for (let attempt = 0; attempt < 30 && completeStatus !== 200; attempt += 1) {
      const completeResponse = page.waitForResponse((response) => response.url().includes("/api/setup/complete") && response.request().method() === "POST");
      await page.getByRole("button", { name: "验证通过并接入 BIND" }).click();
      const complete = await completeResponse;
      completeStatus = complete.status();
      completeBody = await complete.text();
      if (completeStatus !== 200) await page.waitForTimeout(1000);
    }
    if (completeStatus !== 200) throw new Error(`BIND 完成初始化返回 HTTP ${completeStatus}: ${completeBody}`);
    await expect(page.getByRole("heading", { name: "域盾 DNSGuard" })).toBeVisible({ timeout: 30_000 });

    await page.locator('input[type="file"]').setInputFiles({ name: "allowlist.txt", mimeType: "text/plain", buffer: Buffer.from("allowed.app.test\n") });
    await expect(page.getByText(/allowlist\.txt：1 个有效域名/)).toBeVisible();
    await page.getByRole("button", { name: "导入为 draft" }).click();
    await expect(page.getByText("已导入 1 个白名单 draft；请审核后手动发布")).toBeVisible();
    await page.getByRole("button", { name: "生成 / 发布 RPZ" }).click();
    await expect(page.getByText(/已发布成功|已通过 nsupdate 发布/)).toBeVisible({ timeout: 60_000 });
    await expect(page.getByRole("heading", { name: "版本记录" })).toBeVisible();

    await page.getByLabel("域名").fill("redirect.app.test");
    await page.getByLabel("记录类型").selectOption("A");
    await page.getByLabel("目标 IPv4").fill("192.0.2.99");
    await page.getByLabel("原因（可选）").fill("isolated e2e redirect");
    await page.getByRole("button", { name: "保存 RPZ 规则" }).click();
    await expect(page.getByText("RPZ 白名单规则已保存")).toBeVisible();
    await page.getByRole("button", { name: "生成 / 发布 RPZ" }).click();
    await expect(page.getByText(/已发布成功|已通过 nsupdate 发布/)).toBeVisible({ timeout: 60_000 });
  });

  test("真实 API 重启后的最终只读核验会结束首次引导", async ({ page }) => {
    test.skip(process.env.E2E_REAL_PHASE !== "final", "由 finalize-global-deny.sh 完成后执行");
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "域盾 DNSGuard" })).toBeVisible({ timeout: 30_000 });
    const check = page.getByRole("button", { name: /验证全局 DENY/ });
    const denyResponse = page.waitForResponse((response) => response.url().includes("/api/dns/global-deny/check") && response.request().method() === "GET");
    await check.click();
    const deny = await denyResponse;
    const denyBody = await deny.text();
    if (!deny.ok()) throw new Error(`全局 DENY 检查 HTTP ${deny.status()}: ${denyBody}`);
    if (!denyBody.includes('"ready":true')) throw new Error(`全局 DENY 检查未通过: ${denyBody}`);
    // The persisted completion fact is the authoritative result.  Once the
    // API has returned ready=true, the guide must disappear rather than leave
    // a stale success card on the page.
    await expect(page.locator("#deployment-guide-title")).toHaveCount(0, { timeout: 30_000 });
  });
});
