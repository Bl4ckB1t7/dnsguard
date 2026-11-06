import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/components/SetupWizard.tsx", import.meta.url), "utf8");

if (!source.includes("onComplete();")) {
  throw new Error("BIND setup completion must notify the parent application");
}

if (!source.includes('onClick={onComplete}')) {
  throw new Error("setup completion fallback must provide an RPZ management action");
}

if (!source.includes("进入 RPZ 管理页面")) {
  throw new Error("setup completion fallback action text is missing");
}

console.log("SetupWizard completion navigation contract: PASS");
