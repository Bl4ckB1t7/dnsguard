import { test as base, expect } from "@playwright/test";

export const test = base.extend({
  page: async ({ page }, use, testInfo) => {
    const consoleMessages: string[] = [];
    const failedRequests: string[] = [];
    page.on("console", (message) => consoleMessages.push(`[${message.type()}] ${message.text()}`));
    page.on("requestfailed", (request) => failedRequests.push(`${request.method()} ${request.url()} :: ${request.failure()?.errorText ?? "unknown"}`));
    await use(page);
    await testInfo.attach("browser-console.log", { body: consoleMessages.join("\n") || "(none)\n", contentType: "text/plain" });
    await testInfo.attach("failed-requests.log", { body: failedRequests.join("\n") || "(none)\n", contentType: "text/plain" });
  },
});

export { expect };
