# DNSGuard Playwright UI tests

These tests drive the real React UI in Chromium. They intercept only the
browser's `/api` requests with isolated fixture responses; they never read
deployment secrets and never connect to Kali BIND, production DNS, or a real
DNSGuard API.

```bash
npm ci
npx playwright install chromium
npm run test:ui
```

Failure screenshots, videos, and traces are retained by Playwright. The suite
does not replace the real BIND/API acceptance tests; it verifies browser
navigation, form validation, error rendering, package download, and draft-only
import behavior.
