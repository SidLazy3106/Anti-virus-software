const p = new URLSearchParams(location.search);
const target = p.get("u") || "";
document.getElementById("url").textContent = target;
for (const r of (p.get("r") || "").split("|").filter(Boolean)) {
  const li = document.createElement("li");
  li.textContent = r;
  document.getElementById("reasons").appendChild(li);
}
document.getElementById("back").onclick = () => (history.length > 1 ? history.back() : window.close());
document.getElementById("go").onclick = async () => {
  try {
    const u = new URL(target);
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    await chrome.runtime.sendMessage({ type: "allow", host: u.hostname });
    location.href = u.href;
  } catch { /* invalid target */ }
};
