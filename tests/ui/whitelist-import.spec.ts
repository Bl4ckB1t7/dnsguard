import { expect, test } from "./diagnostics";
import { mockDashboard } from "./fixtures";

test.describe("隔离的白名单导入 UI", () => {
  test("TXT 导入先预览，重复项去重，错误项阻止 draft 导入", async ({ page }) => {
    await mockDashboard(page);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "RPZ 规则", exact: true })).toBeVisible();
    const fileInput = page.locator('input[type="file"]');
    await fileInput.setInputFiles({ name: "allowlist.txt", mimeType: "text/plain", buffer: Buffer.from("example.test\nexample.test\ninvalid_domain\n") });
    await expect(page.getByText(/allowlist\.txt：1 个有效域名，1 个重复项/)).toBeVisible();
    await expect(page.getByText(/有 1 项格式错误/)).toBeVisible();
    await expect(page.getByRole("button", { name: "导入为 draft" })).toBeDisabled();
  });

  test("JSON 导入允许预览且只显示为 draft，不触发发布请求", async ({ page }) => {
    await mockDashboard(page);
    page.on("dialog", (dialog) => void dialog.accept());
    let publishCalled = false;
    await page.route("**/api/dns/rpz/publish", async (route) => {
      publishCalled = true;
      await route.fulfill({ status: 500, body: "unexpected publish" });
    });
    await page.goto("/");
    await page.locator('input[type="file"]').setInputFiles({ name: "allowlist.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(["one.example", "two.example"])) });
    await expect(page.getByText(/allowlist\.json：2 个有效域名，0 个重复项/)).toBeVisible();
    await expect(page.getByRole("button", { name: "导入为 draft" })).toBeEnabled();
    await page.getByRole("button", { name: "导入为 draft" }).click();
    await expect(page.getByText(/已导入 2 个白名单 draft/)).toBeVisible();
    expect(publishCalled).toBe(false);
  });
});
