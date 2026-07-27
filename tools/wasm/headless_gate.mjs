import { mkdtemp, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const targetUrl = process.argv[2];
if (!targetUrl) throw new Error("usage: node headless_gate.mjs <url>");

const chromeCandidates = [
  process.env.CHROME_BIN,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);
const chrome = chromeCandidates.find(path => {
  return existsSync(path);
});
if (!chrome) throw new Error("Chrome/Chromium is required for the WASM gate");

const profile = await mkdtemp(join(tmpdir(), "reticulum-wasm-chrome-"));
const debugPort = 9229;
const child = spawn(chrome, [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  `--remote-debugging-port=${debugPort}`,
  `--user-data-dir=${profile}`,
  "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
async function fetchJson(url, options) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(url, options);
      if (response.ok) return response.json();
    } catch {}
    await delay(100);
  }
  throw new Error(`Chrome debugging endpoint unavailable: ${url}`);
}

let socket;
try {
  const page = await fetchJson(
    `http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(targetUrl)}`,
    { method: "PUT" },
  );
  socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });

  let nextId = 1;
  const pending = new Map();
  socket.addEventListener("message", event => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const { resolve, reject } = pending.get(message.id);
      pending.delete(message.id);
      message.error ? reject(new Error(message.error.message)) : resolve(message.result);
    }
  });
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await command("Runtime.enable");

  let destinationPrinted = false;
  let sentPrinted = false;
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const result = await command("Runtime.evaluate", {
      expression: "JSON.stringify(window.__reticulumEvidence || null)",
      returnByValue: true,
    });
    const encoded = result.result?.value;
    const evidence = encoded ? JSON.parse(encoded) : null;
    if (evidence?.browserDest && !destinationPrinted) {
      console.log(`BROWSER_DESTINATION ${evidence.browserDest}`);
      destinationPrinted = true;
    }
    if (evidence?.errors?.length) {
      throw new Error(`browser errors: ${evidence.errors.join("; ")}`);
    }
    if (evidence?.sent && !sentPrinted) {
      console.log("WASM_SENT");
      sentPrinted = true;
    }
    if (evidence?.sent && evidence?.received) {
      console.log("WASM_RECEIVED");
      process.exitCode = 0;
      break;
    }
    await delay(200);
  }
  if (!process.exitCode && process.exitCode !== 0) {
    throw new Error("timed out waiting for WASM bidirectional exchange");
  }
} finally {
  if (socket) socket.close();
  child.kill("SIGTERM");
  if (child.exitCode === null) {
    await new Promise(resolve => child.once("exit", resolve));
  }
  await rm(profile, { recursive: true, force: true });
}
