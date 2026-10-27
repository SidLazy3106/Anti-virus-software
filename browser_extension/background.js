importScripts("analyzer.js");

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
  } else if (v.verdict === "suspicious") {
    chrome.action?.setBadgeText?.({ tabId: d.tabId, text: "!" });
  }
}, { url: [{ schemes: ["http", "https"] }] });

chrome.downloads.onCreated.addListener((item) => {
  const { name, reasons } = analyzeDownload(item.filename || item.finalUrl || item.url || "");
  if (reasons.length) {
    chrome.notifications.create({
      type: "basic", iconUrl: "icons/icon128.png",
      title: "Sentinel: risky download", message: `${name}\n${reasons.join("; ")}\nScan it with Sentinel before opening.`
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
