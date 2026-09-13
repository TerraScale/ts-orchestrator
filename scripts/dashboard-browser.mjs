#!/usr/bin/env node

// Read-only browser smoke test for the operator dashboard.
// Usage: node scripts/dashboard-browser.mjs [base-url]
// Set DASHBOARD_SCREENSHOTS_DIR to retain route screenshots.

import { chromium } from "/home/mariogk/Projects/TerraScale/ts-dashboard/node_modules/playwright/index.mjs";
import { mkdir } from "node:fs/promises";

const baseURL = process.argv[2] || process.env.DASHBOARD_BASE_URL || "http://127.0.0.1:18447";
const screenshots = process.env.DASHBOARD_SCREENSHOTS_DIR;
const routes = [
  ["/", "overview", "Global control plane"],
  ["/regions", "regions", "Regional estate"],
  ["/nodes", "nodes", "Host fleet"],
  ["/events", "events", "Control-plane activity"],
  ["/terrabase", "terrabase", "TerraBase fabric"],
  ["/delivery", "delivery", "Release delivery"],
];

const failures = [];
const record = (condition, message) => {
  if (!condition) failures.push(message);
};
const routeName = (route) => route === "/" ? "overview" : route.slice(1);

if (screenshots) await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await context.newPage();
const runtimeErrors = [];
page.on("console", (message) => {
  if (message.type() === "error") runtimeErrors.push(`console: ${message.text()}`);
});
page.on("pageerror", (error) => runtimeErrors.push(`page: ${error.message}`));
page.on("requestfailed", (request) => runtimeErrors.push(`request: ${request.url()} — ${request.failure()?.errorText}`));

const mainFingerprints = new Map();
for (const [route, expectedPage, expectedHeading] of routes) {
  await page.goto(new URL(route, baseURL).href, { waitUntil: "networkidle" });
  const name = routeName(route);
  const title = await page.title();
  const bodyPage = await page.locator("body").getAttribute("data-page");
  const heading = await page.locator("h1").innerText();
  const mainText = await page.locator("main").innerText();
  const visibleSections = await page.locator("main > section:not([hidden])").count();
  const ids = await page.locator("[id]").evaluateAll((elements) => elements.map((element) => element.id));
  const duplicateIDs = ids.filter((id, index) => ids.indexOf(id) !== index);
  const dimensions = await page.locator("body").evaluate((body) => ({
    scrollWidth: body.scrollWidth,
    clientWidth: body.clientWidth,
    scrollHeight: body.scrollHeight,
    clientHeight: body.clientHeight,
  }));

  record(title.length > 0, `${route}: missing document title`);
  record(bodyPage === expectedPage, `${route}: data-page=${bodyPage}, expected ${expectedPage}`);
  record(heading === expectedHeading, `${route}: h1=${JSON.stringify(heading)}, expected ${JSON.stringify(expectedHeading)}`);
  record(visibleSections > 0, `${route}: no visible page sections`);
  record(duplicateIDs.length === 0, `${route}: duplicate IDs: ${[...new Set(duplicateIDs)].join(", ")}`);
  record(dimensions.scrollWidth <= dimensions.clientWidth, `${route}: horizontal overflow ${dimensions.scrollWidth}/${dimensions.clientWidth}`);
  record(await page.locator(`nav a[href="${route}"]`).getAttribute("aria-current") === "page", `${route}: active nav link lacks aria-current=page`);
  mainFingerprints.set(name, mainText.replace(/\s+/g, " ").trim());

  if (screenshots) await page.screenshot({ path: `${screenshots}/${name}-1440.png`, fullPage: true });

  // The browser must be able to render both a connected projection and the
  // intentionally empty projection without throwing. Charts may be empty.
  const state = await page.evaluate(async () => (await fetch("/api/state")).json());
  record(state && Array.isArray(state.regions) && Array.isArray(state.nodes) && Array.isArray(state.events), `${route}: invalid /api/state shape`);
  const hasData = state.regions.length > 0 || state.nodes.length > 0 || state.events.length > 0;
  const chartPage = ["/", "/regions", "/nodes", "/delivery"].includes(route);
  if (hasData && chartPage) record(await page.locator(".apexcharts-canvas").count() > 0, `${route}: supplied state has chartable data but no ApexCharts canvas`);
  else record(await page.locator(".empty").count() > 0 || await page.locator("main").innerText().then((text) => /unavailable|no .* observations/i.test(text)), `${route}: empty projection has no no-data indication`);
}

record(new Set(mainFingerprints.values()).size === routes.length, "routes render identical main content; MPA pages are not distinct");

// Verify that server rendered navigation and page identity survive with JS off.
const noJS = await context.newPage();
for (const [route, expectedPage, expectedHeading] of routes) {
  await noJS.goto(new URL(route, baseURL).href, { waitUntil: "domcontentloaded" });
  record(await noJS.locator("body").getAttribute("data-page") === expectedPage, `${route} (JS off): missing page identity`);
  record(await noJS.locator("h1").innerText() === expectedHeading, `${route} (JS off): missing server heading`);
  record(await noJS.locator("nav a").count() === routes.length, `${route} (JS off): navigation incomplete`);
}
await noJS.close();
await browser.close();

for (const error of runtimeErrors) console.error(error);
record(runtimeErrors.length === 0, `runtime/CSP/request errors: ${runtimeErrors.length}`);
console.log(`Checked ${routes.length} routes at ${baseURL}`);
if (failures.length) {
  console.error(failures.map((failure) => `FAIL ${failure}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log("PASS: MPA identity, assets, no-data/data rendering, accessibility, and layout checks");
}
