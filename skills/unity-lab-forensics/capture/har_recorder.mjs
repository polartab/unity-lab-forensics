#!/usr/bin/env node
// Record a user-driven browser session and gracefully flush its HAR.
// Invoked by scripts/har_capture.py; do not use for replay or dynamic judging.
//
// Two modes:
//  * default: launch a dedicated Chromium (own profile) and use Playwright's
//    built-in recordHar; the browser is closed on stop.
//  * --cdp <endpoint>: attach to an ALREADY RUNNING Chrome over CDP and record
//    passively by assembling the HAR from network events. The user's browser
//    is never closed by this recorder; only the CDP connection ends.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright-core";

function option(name, required = true) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) {
    if (required) throw new Error(`missing required option: ${name}`);
    return undefined;
  }
  return process.argv[index + 1];
}

const url = option("--url", false);
const cdpUrl = option("--cdp", false);
const executablePath = option("--browser", false);
const harPath = path.resolve(option("--har"));
const statePath = path.resolve(option("--state"));
const stopPath = path.resolve(option("--stop"));
const headless = process.argv.includes("--headless");
const cdpMode = Boolean(cdpUrl);
const MAX_BODY = 16 * 1024 * 1024; // larger responses are recorded size-only
const startedAt = new Date().toISOString();
let state = {
  phase: "starting",
  pid: process.pid,
  har: harPath,
  startedAt,
  headless,
  mode: cdpMode ? "cdp-attach" : "dedicated",
};

function writeState(patch) {
  state = { ...state, ...patch };
  const temporary = `${statePath}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`);
  fs.renameSync(temporary, statePath);
}

writeState();

let browser;
let context;
let timer;
let finishing = false;
// CDP mode: request object -> HAR entry (shared across pages/contexts).
const entries = new Map();

function isTextual(mimeType) {
  return (
    /^(text\/|application\/(json|javascript|xml|xhtml))/i.test(mimeType || "") ||
    /urlencoded/i.test(mimeType || "") ||
    /\+(json|xml)/i.test(mimeType || "")
  );
}

function headerList(headers) {
  return Object.entries(headers || {}).map(([name, value]) => ({ name, value }));
}

function attachPage(page) {
  page.on("request", (request) => {
    const entry = {
      startedDateTime: new Date().toISOString(),
      _startMs: Date.now(),
      time: 0,
      request: {
        method: request.method(),
        url: request.url(),
        headers: headerList(request.headers()),
        queryString: [...new URL(request.url()).searchParams].map(([name, value]) => ({ name, value })),
        headersSize: -1,
        bodySize: -1,
        cookies: [],
      },
      response: null,
      cache: {},
      timings: { send: 0, wait: 0, receive: 0 },
    };
    try {
      const body = request.postDataBuffer();
      if (body && body.length) {
        const mimeType = request.headers()["content-type"] || "application/octet-stream";
        entry.request.bodySize = body.length;
        entry.request.postData = isTextual(mimeType)
          ? { mimeType, params: [], text: body.toString("utf8") }
          : { mimeType, params: [], text: body.toString("base64"), encoding: "base64" };
      }
    } catch {
      // postData unavailable (e.g. streamed); record the request without a body.
    }
    entries.set(request, entry);
  });
  page.on("response", (response) => {
    const entry = entries.get(response.request());
    if (!entry) return;
    const headers = response.headers();
    const mimeType = headers["content-type"] || "";
    entry.response = {
      status: response.status(),
      statusText: response.statusText(),
      headers: headerList(headers),
      headersSize: -1,
      bodySize: -1,
      redirectURL: headers["location"] || "",
      content: { mimeType, size: Number(headers["content-length"] || -1) },
    };
    entry.time = Date.now() - entry._startMs;
    const declared = Number(headers["content-length"] || 0);
    if (declared > MAX_BODY) return; // size-only entry; avoid buffering huge bodies
    response
      .body()
      .then((body) => {
        if (!entry.response) return;
        entry.response.content.size = body.length;
        if (isTextual(mimeType)) {
          entry.response.content.text = body.toString("utf8");
        } else {
          entry.response.content.text = body.toString("base64");
          entry.response.content.encoding = "base64";
        }
      })
      .catch(() => {
        // body already gone (stream consumed, cache evicted); keep size-only
      });
  });
  page.on("requestfailed", (request) => {
    const entry = entries.get(request);
    if (!entry) return;
    if (!entry.response) {
      entry.response = {
        status: 0,
        statusText: "",
        headers: [],
        headersSize: -1,
        bodySize: -1,
        redirectURL: "",
        content: { mimeType: "", size: -1 },
      };
    }
    entry._error = String(request.failure()?.errorText || "request failed");
    entry.time = Date.now() - entry._startMs;
  });
}

function attachContext(context) {
  for (const page of context.pages()) attachPage(page);
  context.on("page", attachPage);
}

async function finalize(reason) {
  if (finishing) return;
  finishing = true;
  clearInterval(timer);
  writeState({ phase: "stopping", stopRequestedAt: new Date().toISOString() });
  let closeError;
  try {
    // Dedicated mode: Playwright writes the HAR during context.close().
    // CDP mode: never touch the user's browser; the HAR is assembled below.
    if (!cdpMode) {
      if (context) await context.close();
      if (browser && browser.isConnected()) await browser.close();
    }
  } catch (error) {
    closeError = error instanceof Error ? error.message : String(error);
  }
  let harExists = fs.existsSync(harPath);
  let harBytes = harExists ? fs.statSync(harPath).size : 0;
  if (cdpMode) {
    try {
      const list = [...entries.values()]
        .sort((a, b) => a.startedDateTime.localeCompare(b.startedDateTime));
      for (const entry of list) {
        delete entry._startMs;
        if (entry._error) entry._error = undefined;
      }
      const document = {
        log: {
          version: "1.2",
          creator: { name: "unity-lab-forensics-har-recorder", version: "1.1-cdp" },
          pages: [],
          entries: list,
        },
      };
      fs.mkdirSync(path.dirname(harPath), { recursive: true });
      fs.writeFileSync(harPath, JSON.stringify(document));
      harExists = true;
      harBytes = fs.statSync(harPath).size;
      state.entryCount = list.length;
    } catch (error) {
      harExists = false;
      closeError = error instanceof Error ? error.message : String(error);
    }
  }
  writeState({
    phase: harExists ? "stopped" : "failed",
    reason,
    stoppedAt: new Date().toISOString(),
    harExists,
    harBytes,
    ...(closeError ? { closeError } : {}),
  });
  process.exitCode = harExists ? 0 : 1;
}

try {
  if (cdpMode) {
    browser = await chromium.connectOverCDP(cdpUrl);
    for (const existing of browser.contexts()) attachContext(existing);
    browser.on("context", attachContext);
    // When this recorder launched the browser, python deferred navigation so
    // the initial page load is recorded: drive the existing tab to --url now.
    if (url) {
      const pages = browser.contexts().flatMap((c) => c.pages());
      const target = pages.find((p) => /^(about:blank|chrome:\/\/(newtab)?\/?)$/.test(p.url())) || pages[0];
      if (!target) throw new Error("CDP browser has no page to navigate");
      await target.goto(url, { waitUntil: "domcontentloaded", timeout: 120000 });
    }
    let pageCount = 0;
    for (const existing of browser.contexts()) pageCount += existing.pages().length;
    writeState({ phase: "ready", readyAt: new Date().toISOString(), pages: pageCount });
  } else {
    if (!executablePath) throw new Error("missing required option: --browser");
    browser = await chromium.launch({ executablePath, headless });
    context = await browser.newContext({
      recordHar: { path: harPath, mode: "full", content: "embed" },
      viewport: null,
      ignoreHTTPSErrors: false,
    });
    const page = await context.newPage();
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 120000 });
    writeState({ phase: "ready", readyAt: new Date().toISOString() });
  }
  timer = setInterval(() => {
    if (fs.existsSync(stopPath)) void finalize("stop-file");
  }, 250);
  process.once("SIGTERM", () => void finalize("SIGTERM"));
  process.once("SIGINT", () => void finalize("SIGINT"));
} catch (error) {
  writeState({
    phase: "failed",
    failedAt: new Date().toISOString(),
    error: error instanceof Error ? error.message : String(error),
  });
  if (timer) clearInterval(timer);
  try {
    if (context) await context.close();
    if (browser && browser.isConnected()) await browser.close();
  } catch {
    // Preserve the original launch/navigation error in state.json.
  }
  process.exitCode = 1;
}
