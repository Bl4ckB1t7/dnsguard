import { defineConfig, devices } from "@playwright/test";

const realBaseURL = process.env.E2E_REAL_BASE_URL;

export default defineConfig({
  testDir: "./tests/ui",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  use: {
    baseURL: realBaseURL ?? "http://127.0.0.1:4173",
    ignoreHTTPSErrors: Boolean(realBaseURL),
    browserName: "chromium",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    ...devices["Desktop Chrome"],
    ...(process.env.E2E_STORAGE_STATE ? { storageState: process.env.E2E_STORAGE_STATE } : {}),
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "tablet", use: { ...devices["iPad Mini"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: realBaseURL ? undefined : {
    // Preview avoids Vite's inline React-refresh preamble, which is blocked by
    // the application's production CSP. API calls are intercepted by the tests.
    command: "npm run build && python3 -m http.server 4173 --bind 127.0.0.1 --directory dist",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
