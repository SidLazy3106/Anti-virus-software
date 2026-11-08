// Flags suspicious pages that ask for a password. Text is inserted with textContent only (no innerHTML).
(async () => {
  const pw = document.querySelector('input[type="password"]');
  if (!pw) return;
  const v = await chrome.runtime.sendMessage({ type: "analyze", url: location.href });
  if (!v) return;
  const reasons = [...v.reasons];
  let crossPost = false;
  for (const f of document.forms) {
    if (!f.querySelector('input[type="password"]')) continue;
    try {
      if (new URL(f.action, location.href).hostname !== location.hostname) {
        crossPost = true;
        reasons.push("Password form submits to a different website");
      }
    } catch { /* ignore */ }
  }
  if (!(v.score >= 35 || (crossPost && v.score >= 15))) return;

  const bar = document.createElement("div");
  bar.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#b00020;color:#fff;" +
    "font:14px/1.4 system-ui,sans-serif;padding:10px 14px;box-shadow:0 2px 6px rgba(0,0,0,.4)";
  bar.textContent = "X-Secure warning: this page asks for a password and looks risky. " + reasons.slice(0, 3).join(" | ");
  const close = document.createElement("button");
  close.textContent = "Dismiss";
  close.style.cssText = "margin-left:12px;cursor:pointer";
  close.onclick = () => bar.remove();
  bar.appendChild(close);
  document.documentElement.appendChild(bar);
})();
