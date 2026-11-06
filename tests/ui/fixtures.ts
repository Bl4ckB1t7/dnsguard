import type { Page, Route } from "@playwright/test";

export const fixtureToken = "fixture-bootstrap-token";
export const fixtureTsigPath = "/run/dnsguard-secrets/fixture-rpz-manager.key";
export const fixturePrimary = "192.0.2.10:53";
export const fixtureSecondary = "192.0.2.11:53";

export async function json(route: Route, value: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(value) });
}

export async function mockPlatformFirstInstall(page: Page): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/me") {
      await json(route, { authenticated: false, authEnabled: true, initialized: false, bindReady: false });
      return;
    }
    if (url.pathname === "/api/setup/status") {
      await json(route, { platformReady: true, bindReady: false, policyMode: "global", globalDenySetupDeferred: true, whitelistSeed: { available: false } });
      return;
    }
    if (url.pathname === "/api/setup/validate" && request.method() === "POST") {
      await json(route, {
        ready: true,
        checks: [
          { name: "平台运行环境", status: "pass", detail: "Docker API 可用" },
          { name: "Bootstrap Token", status: "pass", detail: "Token 已验证" },
        ],
      });
      return;
    }
    if (url.pathname === "/api/setup/complete" && request.method() === "POST") {
      await json(route, { initialized: true });
      return;
    }
    await json(route, {});
  });
}

export async function mockBindSetup(page: Page, outcome: "success" | "refused" | "servfail" | "timeout" | "tsig" = "success"): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/me") {
      await json(route, { authenticated: true, authEnabled: true, initialized: true, bindReady: false });
      return;
    }
    if (url.pathname === "/api/setup/status") {
      await json(route, { platformReady: true, bindReady: false, policyMode: "global", globalDenySetupDeferred: true, whitelistSeed: { available: false } });
      return;
    }
    if (url.pathname === "/api/setup/rpz-package/preview" && request.method() === "POST") {
      await json(route, {
        zone: "rpz.local",
        globalDenyZone: "global-deny.rpz.local",
        tsigKeyMode: "existing",
        tsigKeyName: "rpz-manager",
        files: [{ path: "README.md", content: "fixture package; no secrets" }, { path: "primary/named.conf", content: "zone fixture;" }],
        warnings: ["仅供隔离测试审核，Web 不会修改 BIND"],
      });
      return;
    }
    if (url.pathname === "/api/setup/rpz-package/download" && request.method() === "POST") {
      await route.fulfill({ status: 200, contentType: "application/zip", body: Buffer.from("fixture-zip") });
      return;
    }
    if ((url.pathname === "/api/setup/validate" || url.pathname === "/api/setup/complete") && request.method() === "POST") {
      if (outcome === "success") {
        await json(route, {
          ready: true,
          checks: [
            { name: "Primary SOA / Zone", status: "pass", detail: "Serial=42" },
            { name: "Secondary SOA / Zone", status: "pass", detail: "Serial=42" },
            { name: "TSIG 动态更新权限", status: "pass", detail: "受控测试已清理" },
          ],
        });
      } else {
        const detail = outcome === "refused" ? "RCODE=REFUSED" : outcome === "servfail" ? "RCODE=SERVFAIL" : outcome === "timeout" ? "请求超时" : "TSIG Key 文件不可读或格式无效";
        await json(route, { ready: false, error: "初始化检查未通过", checks: [{ name: "Primary SOA / Zone", status: "fail", detail }] }, 400);
      }
      return;
    }
    await route.fallback();
  });
}

export async function mockDashboard(page: Page): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/auth/me") {
      await json(route, { authenticated: true, authEnabled: true, initialized: true, bindReady: true });
      return;
    }
    if (url.pathname === "/api/setup/status") {
      await json(route, { policyMode: "global", globalDenySetupDeferred: true, deploymentCompleted: false, globalDenyVerification: { status: "not_verified" } });
      return;
    }
    if (url.pathname === "/api/dns/overview") {
      await json(route, { nodes: 2, healthyNodes: 2, rules: 1, publishedRules: 1, pendingPublish: false, publishEvidenceReady: true, publishEvidence: { id: "job-1", status: "succeeded", syncStatus: "published", nodeChecks: [{ id: "p", name: "Primary", role: "primary", address: fixturePrimary, status: "verified" }, { id: "s", name: "Secondary", role: "secondary", address: fixtureSecondary, status: "verified" }] }, rpzHits: null, rpzHitStatus: "not_run", lastSync: "2026-01-01T00:00:00Z", publisherMode: "nsupdate", policyMode: "global", globalDenyZone: "global-deny.rpz.local", lastPublish: "2026-01-01T00:00:00Z", publishMessage: "", publishJobId: "job-1", publishJobStatus: "succeeded" });
      return;
    }
    if (url.pathname === "/api/dns/nodes") {
      await json(route, [{ id: "p", name: "Primary", role: "primary", address: fixturePrimary, status: "healthy" }, { id: "s", name: "Secondary", role: "secondary", address: fixtureSecondary, status: "healthy" }]);
      return;
    }
    if (url.pathname === "/api/dns/rpz") {
      await json(route, [{ id: "r1", domain: "example.test", action: "passthru", type: "CNAME", reason: "fixture", status: "published", updatedAt: "2026-01-01T00:00:00Z" }]);
      return;
    }
    if (url.pathname === "/api/dns/rpz/preview") {
      await json(route, { pending: false, currentCount: 1, publishedCount: 1, changes: [] });
      return;
    }
    if (url.pathname === "/api/dns/rpz/versions") {
      await json(route, [{ id: "v1", createdAt: "2026-01-01T00:00:00Z", mode: "nsupdate", ruleCount: 1 }]);
      return;
    }
    if (url.pathname === "/api/settings") {
      await json(route, { title: "DNSGuard", subtitle: "fixture" });
      return;
    }
    if (url.pathname.startsWith("/api/audit")) {
      await json(route, { items: [], total: 0, page: 1, pageSize: 20 });
      return;
    }
    await json(route, {});
  });
}
