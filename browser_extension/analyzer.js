// URL risk analysis. Mirrors sentinel/webguard.py so desktop and browser give the same verdicts.
const BRANDS = ["google","microsoft","paypal","amazon","facebook","instagram","netflix","github","apple",
  "icloud","outlook","whatsapp","linkedin","dropbox","binance","coinbase","paytm","phonepe","flipkart",
  "hdfcbank","icicibank","sbi"];
const OFFICIAL = new Set(["google.com","gstatic.com","googlevideo.com",
  "microsoft.com","microsoftonline.com","live.com","office.com","paypal.com","amazon.com","amazon.in",
  "facebook.com","fbcdn.net","instagram.com","netflix.com","github.com",
  "apple.com","icloud.com","whatsapp.com","linkedin.com","dropbox.com","binance.com","coinbase.com","paytm.com",
  "phonepe.com","flipkart.com","hdfcbank.com","icicibank.com","sbi.co.in"]);
const RISKY_TLDS = new Set(["zip","mov","top","xyz","click","tk","ml","ga","cf","gq","work","country","kim",
  "loan","men","icu","cyou"]);
const KEYWORDS = ["login","signin","verify","secure","account","update","wallet","password","billing","confirm","suspend"];
const MULTI = new Set(["co.uk","com.au","co.in","org.in","net.in","ac.in","gov.in","co.jp","com.br","co.za"]);
// Shared hosting / user-content platforms: anyone can publish here, so brand + keyword checks still apply.
const USER_CONTENT = new Set(["amazonaws.com","googleapis.com","googleusercontent.com","githubusercontent.com",
  "windows.net","appspot.com","firebaseapp.com","web.app","github.io","pages.dev","workers.dev","r2.dev",
  "netlify.app","vercel.app","herokuapp.com","azurewebsites.net","blogspot.com","000webhostapp.com","glitch.me",
  "wixsite.com","weebly.com","ngrok.io","ngrok-free.app","trycloudflare.com","ipfs.io","dweb.link"]);
const SUSPICIOUS_AT = 35, MALICIOUS_AT = 70;

// Host exactly as typed (the URL parser rewrites 3232235777 / 0xC0A80001 to dotted form).
function rawHostOf(raw) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^\/?#\\]*@)?(\[[^\]]*\]|[^\/?#:\\]*)/i.exec(raw.trim());
  return m ? m[1].toLowerCase().replace(/\.$/, "") : "";
}

function lev(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
    }
    prev = cur;
  }
  return prev[b.length];
}
const leet = s => s.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/@/g, "a");

function registeredDomain(host) {
  const l = host.split(".");
  if (l.length >= 3 && MULTI.has(l.slice(-2).join("."))) return l.slice(-3).join(".");
  return l.length >= 2 ? l.slice(-2).join(".") : host;
}

function analyzeUrl(raw, badDomains = []) {
  const out = { score: 0, verdict: "clean", reasons: [] };
  const add = (p, why) => { out.score += p; out.reasons.push(why); };
  let u;
  try { u = new URL(raw); } catch { return { score: 50, verdict: "suspicious", reasons: ["Malformed URL"] }; }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (badDomains.some(d => host === d || host.endsWith("." + d))) add(100, "Domain is on the known-malicious list");

  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
  if (isIp) {
    add(30, "Uses a raw IP address instead of a domain name");
    if (!host.startsWith("[") && rawHostOf(raw) !== host) add(25, "IP address written in a disguised form (decimal/hex/octal)");
  }
  if (u.username || u.password) add(40, "Contains '@' in the address (hides the real destination)");
  if (host.includes("xn--")) add(25, "Punycode domain (possible look-alike characters)");

  const path = (u.pathname || "").toLowerCase();
  let reg = host;
  if (!isIp) {
    const labels = host.split(".");
    reg = registeredDomain(host);
    const regLabel = reg.split(".")[0], tld = labels[labels.length - 1];
    if (RISKY_TLDS.has(tld)) add(15, `Uncommon TLD .${tld} often used in abuse`);
    if (labels.length - reg.split(".").length >= 3) add(15, "Excessive number of subdomains");
    if ((host.match(/-/g) || []).length >= 3) add(10, "Many hyphens in the domain");
    if (USER_CONTENT.has(reg)) {
      const tail = (host.endsWith(reg) ? host.slice(0, host.length - reg.length) : "") + path;
      for (const b of BRANDS) {
        if (!reg.includes(b) && new RegExp(`(^|[^a-z])${b}([^a-z]|$)`).test(tail)) {
          add(35, `Brand name '${b}' on a shared hosting site (${reg})`); break;
        }
      }
    } else if (!OFFICIAL.has(reg)) {
      const norm = leet(regLabel);
      const sub = host.endsWith(reg) ? host.slice(0, host.length - reg.length) : "";
      for (const b of BRANDS) {
        if (regLabel === b) { if (RISKY_TLDS.has(tld)) { add(30, `Brand name '${b}' on an unofficial domain`); break; } continue; }
        if (norm === b) { add(50, `Look-alike of '${b}' using swapped characters`); break; }
        if (norm.includes(b)) { add(30, `Contains the brand name '${b}' but is not the official domain`); break; }
        if (b.length >= 6 && lev(regLabel, b) > 0 && lev(regLabel, b) <= 2 && Math.abs(regLabel.length - b.length) <= 2) {
          add(45, `Domain is one or two letters away from '${b}'`); break;
        }
        if (sub.includes(b)) { add(40, `Brand name '${b}' used as a subdomain of another site`); break; }
      }
    }
  }
  const hits = KEYWORDS.filter(k => host.includes(k) || path.includes(k));
  if (hits.length && !OFFICIAL.has(reg)) {
    add(hits.length === 1 ? 10 : 15, `Sensitive keywords: ${hits.slice(0, 4).join(", ")}`);
    if (u.protocol === "http:") add(10, "Sensitive page served over unencrypted HTTP");
  }
  if (raw.length > 120) add(10, "Very long URL");
  out.score = Math.min(out.score, 100);
  out.verdict = out.score >= MALICIOUS_AT ? "malicious" : out.score >= SUSPICIOUS_AT ? "suspicious" : "clean";
  return out;
}

const RISKY_DL_EXT = new Set(["exe","scr","msi","bat","cmd","ps1","vbs","js","jse","hta","lnk","iso","jar","com","pif"]);
const DECOY_DL = /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip)\s*\.(exe|scr|com|pif|bat|cmd|js|vbs|lnk|hta)$/i;
function analyzeDownload(nameOrUrl) {
  const rawName = (nameOrUrl.split(/[\\/]/).pop() || "").split("?")[0];
  let name = rawName;
  try { name = decodeURIComponent(rawName); } catch { /* malformed %-escape: keep raw name */ }
  const ext = (name.split(".").pop() || "").toLowerCase();
  const reasons = [];
  if (DECOY_DL.test(name)) reasons.push("Double extension: a document name hiding a program");
  else if (RISKY_DL_EXT.has(ext)) reasons.push(`Executable file type (.${ext})`);
  return { name, reasons };
}
