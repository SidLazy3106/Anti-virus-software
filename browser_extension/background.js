importScripts("url_rules.js", "analyzer.js");

let blocklist = null;
async function getBlocklist() {
  if (!blocklist) {
    try { blocklist = (await (await fetch(chrome.runtime.getURL("blocklist.json"))).json()).domains || []; }
    catch { blocklist = []; }
  }
  return blocklist;
}

async function isAllowed(host) {
  const { allowed = {} } = await chrome.storage.session.get("allowed");
  return !!allowed[host];
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  let host;
  try { host = new URL(d.url).hostname; } catch { return; }
  const v = analyzeUrl(d.url, await getBlocklist());
  if (v.verdict === "malicious" && !(await isAllowed(host))) {
    const page = chrome.runtime.getURL("warning.html") +
      "?u=" + encodeURIComponent(d.url) + "&r=" + encodeURIComponent(v.reasons.join("|"));
    chrome.tabs.update(d.tabId, { url: page });
  } else {
    // clear a stale "!" when the tab moves on to a clean site
    chrome.action?.setBadgeText?.({ tabId: d.tabId, text: v.verdict === "suspicious" ? "!" : "" });
  }
}, { url: [{ schemes: ["http", "https"] }] });

chrome.downloads.onCreated.addListener((item) => {
  const { name, reasons } = analyzeDownload(item.filename || item.finalUrl || item.url || "");
  if (reasons.length) {
    chrome.notifications.create({
      type: "basic", iconUrl: "icons/icon128.png",
      title: "X-Secure: risky download", message: `${name}\n${reasons.join("; ")}\nX-Secure will scan it when the download finishes.`
    });
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type === "analyze") {
    getBlocklist().then(b => reply(analyzeUrl(msg.url, b)));
    return true;
  }
  if (msg.type === "allow") {
    chrome.storage.session.get("allowed").then(({ allowed = {} }) => {
      allowed[msg.host] = true;
      return chrome.storage.session.set({ allowed });
    }).then(() => reply({ ok: true }));
    return true;
  }
});

// ── desktop scanner bridge (Native Messaging) ─────────────────────────────
// When the X-Secure desktop app is installed as a native host ("python main.py nativehost install"),
// every finished download is scanned by the real desktop engine. If it isn't installed, this stays silent.
const HOST = "com.xsecure.scanner";

function scanWithDesktop(path) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(HOST, { type: "scan", path }, (resp) => {
        if (chrome.runtime.lastError || !resp) resolve(null);   // host not installed or failed
        else resolve(resp);
      });
    } catch { resolve(null); }
  });
}

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== "complete") return;
  const [item] = await chrome.downloads.search({ id: delta.id });
  if (!item || !item.filename) return;
  const r = await scanWithDesktop(item.filename);
  if (!r || !r.ok || r.verdict === "clean") return;
  const label = r.verdict === "malicious" ? "Dangerous" : "Suspicious";
  chrome.notifications.create("xsecure-dl-" + delta.id, {
    type: "basic", iconUrl: "icons/icon128.png", priority: 2,
    title: `X-Secure: ${label} download (risk ${r.score}/100)`,
    message: `${r.name}\n${(r.reasons || []).slice(0, 3).join("; ")}\nDon't open it. Quarantine it from the X-Secure app.`
  });
});

