export const LOGIN_HTML: string = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="robots" content="noindex, nofollow">
<title>Sign in · TerraScale Orchestrator</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2338bdf8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolygon points='12 2 2 7 12 12 22 7 12 2'/%3E%3Cpolyline points='2 12 12 17 22 12'/%3E%3Cpolyline points='2 17 12 22 22 17'/%3E%3C/svg%3E">
<script>
(function () {
  var saved = null;
  try { saved = localStorage.getItem("ts-orch-theme"); } catch (e) {}
  var theme = saved === "light" || saved === "dark" ? saved : (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", theme);
})();
</script>
<style>
:root {
  --font-sans: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --radius: 14px;
}
[data-theme="dark"] {
  --bg: #07090d;
  --bg-glow-1: rgba(56, 189, 248, 0.10);
  --bg-glow-2: rgba(139, 92, 246, 0.10);
  --card: rgba(17, 20, 27, 0.82);
  --card-border: rgba(255, 255, 255, 0.08);
  --fg: #ecedee;
  --muted: #8b919c;
  --subtle: #5c626d;
  --line: rgba(255, 255, 255, 0.07);
  --btn-bg: #f5f5f6;
  --btn-fg: #0a0b0d;
  --btn-hover: #ffffff;
  --btn2-bg: rgba(255, 255, 255, 0.04);
  --btn2-border: rgba(255, 255, 255, 0.12);
  --btn2-hover: rgba(255, 255, 255, 0.08);
  --ok: #3ddc97;
  --warn: #f5b84b;
  --err: #ff6b6b;
  --err-bg: rgba(255, 107, 107, 0.08);
  --err-border: rgba(255, 107, 107, 0.28);
  --accent: #7dd3fc;
  --shadow: 0 1px 0 rgba(255, 255, 255, 0.04) inset, 0 30px 80px -20px rgba(0, 0, 0, 0.7);
  --grid: rgba(255, 255, 255, 0.035);
}
[data-theme="light"] {
  --bg: #f6f7f9;
  --bg-glow-1: rgba(14, 165, 233, 0.10);
  --bg-glow-2: rgba(124, 58, 237, 0.08);
  --card: rgba(255, 255, 255, 0.9);
  --card-border: rgba(15, 23, 42, 0.09);
  --fg: #0b0d12;
  --muted: #5b6270;
  --subtle: #8a909b;
  --line: rgba(15, 23, 42, 0.08);
  --btn-bg: #0b0d12;
  --btn-fg: #ffffff;
  --btn-hover: #1c1f27;
  --btn2-bg: rgba(15, 23, 42, 0.02);
  --btn2-border: rgba(15, 23, 42, 0.14);
  --btn2-hover: rgba(15, 23, 42, 0.05);
  --ok: #0f9d63;
  --warn: #b7791f;
  --err: #d93636;
  --err-bg: rgba(217, 54, 54, 0.06);
  --err-border: rgba(217, 54, 54, 0.25);
  --accent: #0284c7;
  --shadow: 0 1px 2px rgba(15, 23, 42, 0.04), 0 24px 60px -24px rgba(15, 23, 42, 0.25);
  --grid: rgba(15, 23, 42, 0.04);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  min-height: 100vh;
  font-family: var(--font-sans);
  background: var(--bg);
  color: var(--fg);
  -webkit-font-smoothing: antialiased;
  display: flex;
  flex-direction: column;
  transition: background-color 0.2s ease, color 0.2s ease;
}
.backdrop {
  position: fixed;
  inset: 0;
  pointer-events: none;
  background:
    radial-gradient(700px 400px at 15% -10%, var(--bg-glow-1), transparent 70%),
    radial-gradient(600px 380px at 95% 110%, var(--bg-glow-2), transparent 70%),
    linear-gradient(var(--grid) 1px, transparent 1px) 0 0 / 44px 44px,
    linear-gradient(90deg, var(--grid) 1px, transparent 1px) 0 0 / 44px 44px;
  mask-image: radial-gradient(ellipse at center, #000 40%, transparent 85%);
  -webkit-mask-image: radial-gradient(ellipse at center, #000 40%, transparent 85%);
}
.topbar {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 18px 24px;
  z-index: 1;
}
.status-pill {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--muted);
  padding: 6px 10px;
  border: 1px solid var(--card-border);
  border-radius: 999px;
  background: var(--card);
  backdrop-filter: blur(10px);
}
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--subtle);
  position: relative;
}
.dot.ok { background: var(--ok); }
.dot.warn { background: var(--warn); }
.dot.err { background: var(--err); }
.dot.ok::after {
  content: "";
  position: absolute;
  inset: -3px;
  border-radius: 50%;
  border: 1px solid var(--ok);
  opacity: 0;
  animation: ping 2.2s ease-out infinite;
}
@keyframes ping {
  0% { transform: scale(0.6); opacity: 0.8; }
  100% { transform: scale(2); opacity: 0; }
}
.theme-toggle {
  display: inline-flex;
  padding: 3px;
  border: 1px solid var(--card-border);
  border-radius: 999px;
  background: var(--card);
  backdrop-filter: blur(10px);
}
.theme-toggle button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 0;
  background: transparent;
  color: var(--muted);
  font: inherit;
  font-size: 12px;
  padding: 5px 10px;
  border-radius: 999px;
  cursor: pointer;
}
.theme-toggle button[aria-pressed="true"] {
  background: var(--btn2-hover);
  color: var(--fg);
}
.theme-toggle svg { width: 13px; height: 13px; }
main {
  position: relative;
  z-index: 1;
  flex: 1;
  display: grid;
  place-items: center;
  padding: 24px;
}
.card {
  width: 100%;
  max-width: 400px;
  background: var(--card);
  border: 1px solid var(--card-border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  padding: 36px 32px 28px;
  animation: rise 0.45s cubic-bezier(0.2, 0.8, 0.2, 1);
}
@keyframes rise {
  from { opacity: 0; transform: translateY(8px) scale(0.99); }
  to { opacity: 1; transform: none; }
}
.brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 14px;
  margin-bottom: 26px;
}
.logo {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: grid;
  place-items: center;
  background: linear-gradient(145deg, rgba(125, 211, 252, 0.18), rgba(167, 139, 250, 0.18));
  border: 1px solid var(--card-border);
}
.logo svg { width: 26px; height: 26px; color: var(--fg); }
h1 {
  margin: 0;
  font-size: 19px;
  font-weight: 600;
  letter-spacing: -0.015em;
}
.host {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted);
  margin-top: 4px;
}
.lede {
  margin: 0;
  color: var(--muted);
  font-size: 13.5px;
  line-height: 1.55;
}
.banner {
  display: none;
  gap: 10px;
  align-items: flex-start;
  padding: 11px 12px;
  margin-bottom: 18px;
  border-radius: 10px;
  border: 1px solid var(--err-border);
  background: var(--err-bg);
  color: var(--err);
  font-size: 13px;
  line-height: 1.45;
}
.banner.show { display: flex; }
.banner svg { width: 16px; height: 16px; flex: none; margin-top: 1px; }
.banner strong { display: block; font-weight: 600; margin-bottom: 2px; }
.banner span { color: var(--fg); opacity: 0.85; }
.btn {
  width: 100%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  height: 44px;
  border-radius: 10px;
  font: inherit;
  font-size: 14px;
  font-weight: 550;
  text-decoration: none;
  cursor: pointer;
  transition: background-color 0.15s ease, transform 0.08s ease, border-color 0.15s ease, opacity 0.15s ease;
  user-select: none;
}
.btn:active { transform: translateY(1px); }
.btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.btn-primary {
  border: 1px solid transparent;
  background: var(--btn-bg);
  color: var(--btn-fg);
}
.btn-primary:hover { background: var(--btn-hover); }
.btn-primary svg { width: 18px; height: 18px; }
.btn-secondary {
  margin-top: 10px;
  border: 1px dashed var(--btn2-border);
  background: var(--btn2-bg);
  color: var(--fg);
}
.btn-secondary:hover { background: var(--btn2-hover); }
.btn-secondary svg { width: 16px; height: 16px; color: var(--warn); }
.btn[aria-busy="true"] { opacity: 0.6; pointer-events: none; }
.divider {
  display: none;
  align-items: center;
  gap: 10px;
  margin: 18px 0 8px;
  color: var(--subtle);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.divider::before, .divider::after {
  content: "";
  flex: 1;
  height: 1px;
  background: var(--line);
}
.dev { display: none; }
.dev.show { display: block; }
.divider.show { display: flex; }
.dev-note {
  margin: 8px 0 0;
  font-size: 11.5px;
  color: var(--subtle);
  text-align: center;
}
.meta {
  margin-top: 24px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 11.5px;
  color: var(--subtle);
}
.meta .lock { display: inline-flex; align-items: center; gap: 6px; }
.meta svg { width: 12px; height: 12px; }
footer {
  position: relative;
  z-index: 1;
  text-align: center;
  font-size: 11.5px;
  color: var(--subtle);
  padding: 18px;
}
@media (max-width: 480px) {
  .card { padding: 28px 22px 22px; }
  .topbar { padding: 14px 16px; }
}
</style>
</head>
<body>
<div class="backdrop"></div>
<header class="topbar">
  <div class="status-pill" id="status" title="Backplane status">
    <span class="dot" id="status-dot"></span>
    <span id="status-text">Checking backplane…</span>
  </div>
  <div class="theme-toggle" role="group" aria-label="Theme">
    <button type="button" data-theme-set="dark" aria-pressed="false">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
      Dark
    </button>
    <button type="button" data-theme-set="light" aria-pressed="false">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
      Light
    </button>
  </div>
</header>
<main>
  <section class="card" aria-labelledby="title">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3 3 7.5 12 12l9-4.5L12 3z"/><path d="m3 12 9 4.5 9-4.5" opacity="0.7"/><path d="m3 16.5 9 4.5 9-4.5" opacity="0.4"/></svg>
      </div>
      <div>
        <h1 id="title">TerraScale Orchestrator</h1>
        <div class="host">orch.terrascale.tech</div>
      </div>
      <p class="lede">Private control plane for the TerraScale fleet. Sign in with an allowlisted GitHub account to continue.</p>
    </div>
    <div class="banner" id="error" role="alert">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
      <div><strong id="error-title">Sign-in failed</strong><span id="error-text"></span></div>
    </div>
    <a class="btn btn-primary" id="github" href="/auth/github/start">
      <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.387-1.333-1.757-1.333-1.757-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
      Sign in with GitHub
    </a>
    <div class="divider" id="dev-divider">Local development</div>
    <div class="dev" id="dev">
      <button type="button" class="btn btn-secondary" id="dev-login">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m16 18 6-6-6-6M8 6l-6 6 6 6"/></svg>
        Local Dev Sign-In (Aspire)
      </button>
      <p class="dev-note">Visible only when the Worker runs with LOCAL_DEV on loopback.</p>
    </div>
    <div class="meta">
      <span class="lock">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>
        OAuth PKCE · HttpOnly session
      </span>
      <span>Operators only</span>
    </div>
  </section>
</main>
<footer>TerraScale · Fleet backplane</footer>
<script type="module">
const root = document.documentElement;
const themeButtons = document.querySelectorAll("[data-theme-set]");
const syncTheme = () => {
  const current = root.getAttribute("data-theme");
  themeButtons.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeSet === current)));
};
themeButtons.forEach((b) => b.addEventListener("click", () => {
  root.setAttribute("data-theme", b.dataset.themeSet);
  try { localStorage.setItem("ts-orch-theme", b.dataset.themeSet); } catch {}
  syncTheme();
}));
syncTheme();
const media = window.matchMedia("(prefers-color-scheme: light)");
media.addEventListener("change", (e) => {
  let saved = null;
  try { saved = localStorage.getItem("ts-orch-theme"); } catch {}
  if (saved !== "light" && saved !== "dark") {
    root.setAttribute("data-theme", e.matches ? "light" : "dark");
    syncTheme();
  }
});

const messages = {
  unauthorized: ["Access denied", "This GitHub account is not on the operator allowlist."],
  forbidden: ["Access denied", "This GitHub account is not allowed to operate the fleet."],
  oauth_failed: ["GitHub sign-in failed", "The OAuth exchange with GitHub did not complete. Please try again."],
  state_mismatch: ["Sign-in expired", "The sign-in request expired or was tampered with. Please start again."],
  access_denied: ["Authorization cancelled", "GitHub authorization was cancelled."],
  session_expired: ["Session expired", "Your session has expired. Sign in again to continue."],
  dev_login_failed: ["Local sign-in failed", "The local dev sign-in endpoint rejected the request."]
};
const params = new URLSearchParams(location.search);
const showError = (code) => {
  const entry = messages[code] ?? ["Sign-in failed", "Unexpected error: " + code];
  document.getElementById("error-title").textContent = entry[0];
  document.getElementById("error-text").textContent = entry[1];
  document.getElementById("error").classList.add("show");
};
const errorCode = params.get("error");
if (errorCode) showError(errorCode);

const dot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const setStatus = (cls, text) => {
  dot.className = "dot " + cls;
  statusText.textContent = text;
};

const dev = document.getElementById("dev");
const devDivider = document.getElementById("dev-divider");
const devButton = document.getElementById("dev-login");
devButton.addEventListener("click", async () => {
  devButton.setAttribute("aria-busy", "true");
  try {
    const res = await fetch("/auth/dev-login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json", "x-requested-with": "ts-orch-ui" },
      body: "{}"
    });
    if (res.ok || res.type === "opaqueredirect" || res.redirected) {
      location.replace("/");
      return;
    }
    showError("dev_login_failed");
  } catch {
    showError("dev_login_failed");
  } finally {
    devButton.removeAttribute("aria-busy");
  }
});

const probe = async () => {
  try {
    const res = await fetch("/api/me", { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
    let data = {};
    try { data = await res.json(); } catch {}
    const user = data.user ?? data;
    const authenticated = res.ok && data.authenticated !== false && Boolean(user.login ?? user.id ?? data.owner);
    if (authenticated && !errorCode) {
      location.replace("/");
      return;
    }
    if (data.localDev === true) {
      dev.classList.add("show");
      devDivider.classList.add("show");
      setStatus("warn", "Local dev backplane");
    } else {
      setStatus("ok", "Backplane online");
    }
  } catch {
    setStatus("err", "Backplane unreachable");
  }
};
probe();
</script>
</body>
</html>
`;

export const INDEX_HTML: string = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="robots" content="noindex, nofollow">
<title>Status · TerraScale Orchestrator</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2338bdf8' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolygon points='12 2 2 7 12 12 22 7 12 2'/%3E%3Cpolyline points='2 12 12 17 22 12'/%3E%3Cpolyline points='2 17 12 22 22 17'/%3E%3C/svg%3E">
<script>
(function () {
  var saved = null;
  try { saved = localStorage.getItem("ts-orch-theme"); } catch (e) {}
  var theme = saved === "light" || saved === "dark" ? saved : (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", theme);
})();
</script>
<style>
:root {
  --font-sans: "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --radius: 12px;
}
[data-theme="dark"] {
  color-scheme: dark;
  --bg: #07090d;
  --panel: #0d1016;
  --panel-2: #11151c;
  --border: rgba(255, 255, 255, 0.075);
  --border-strong: rgba(255, 255, 255, 0.14);
  --fg: #ecedee;
  --muted: #8b919c;
  --subtle: #5c626d;
  --grid: rgba(255, 255, 255, 0.06);
  --hover: rgba(255, 255, 255, 0.045);
  --chip: rgba(255, 255, 255, 0.05);
  --btn-bg: #f5f5f6;
  --btn-fg: #0a0b0d;
  --ok: #3ddc97;
  --ok-bg: rgba(61, 220, 151, 0.1);
  --warn: #f5b84b;
  --warn-bg: rgba(245, 184, 75, 0.1);
  --err: #ff6b6b;
  --err-bg: rgba(255, 107, 107, 0.1);
  --info-bg: rgba(125, 211, 252, 0.08);
  --accent: #7dd3fc;
  --s1: #3987e5;
  --s2: #d95926;
  --s3: #199e70;
  --reserve: rgba(255, 255, 255, 0.16);
  --track: rgba(255, 255, 255, 0.06);
  --usage: #f0efec;
  --tip-bg: rgba(16, 19, 26, 0.96);
  --shadow: 0 20px 50px -20px rgba(0, 0, 0, 0.8);
}
[data-theme="light"] {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --panel-2: #fafbfc;
  --border: rgba(15, 23, 42, 0.08);
  --border-strong: rgba(15, 23, 42, 0.16);
  --fg: #0b0d12;
  --muted: #5b6270;
  --subtle: #8a909b;
  --grid: rgba(15, 23, 42, 0.07);
  --hover: rgba(15, 23, 42, 0.035);
  --chip: rgba(15, 23, 42, 0.045);
  --btn-bg: #0b0d12;
  --btn-fg: #ffffff;
  --ok: #0f9d63;
  --ok-bg: rgba(15, 157, 99, 0.09);
  --warn: #b7791f;
  --warn-bg: rgba(183, 121, 31, 0.1);
  --err: #d93636;
  --err-bg: rgba(217, 54, 54, 0.08);
  --info-bg: rgba(2, 132, 199, 0.07);
  --accent: #0284c7;
  --s1: #2a78d6;
  --s2: #eb6834;
  --s3: #1baf7a;
  --reserve: rgba(15, 23, 42, 0.16);
  --track: rgba(15, 23, 42, 0.06);
  --usage: #0b0b0b;
  --tip-bg: rgba(255, 255, 255, 0.98);
  --shadow: 0 16px 40px -18px rgba(15, 23, 42, 0.35);
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: var(--font-sans);
  font-size: 13px;
  background: var(--bg);
  color: var(--fg);
  -webkit-font-smoothing: antialiased;
  transition: background-color 0.2s ease, color 0.2s ease;
}
button, input, select { font: inherit; color: inherit; }
.mono { font-family: var(--font-mono); font-size: 12px; }
.muted { color: var(--muted); }
.subtle { color: var(--subtle); }
.num { font-variant-numeric: tabular-nums; }
header.top {
  position: sticky;
  top: 0;
  z-index: 20;
  background: color-mix(in srgb, var(--bg) 82%, transparent);
  backdrop-filter: saturate(1.4) blur(14px);
  -webkit-backdrop-filter: saturate(1.4) blur(14px);
  border-bottom: 1px solid var(--border);
}
.bar {
  max-width: 1480px;
  margin: 0 auto;
  padding: 10px 20px;
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}
.brand { display: flex; align-items: center; gap: 10px; margin-right: 4px; }
.logo {
  width: 30px;
  height: 30px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  background: linear-gradient(145deg, rgba(125, 211, 252, 0.2), rgba(167, 139, 250, 0.2));
  border: 1px solid var(--border);
}
.logo svg { width: 17px; height: 17px; }
.brand h1 { margin: 0; font-size: 14px; font-weight: 600; letter-spacing: -0.01em; }
.brand .host { font-family: var(--font-mono); font-size: 11px; color: var(--muted); }
.live {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 5px 10px;
  border: 1px solid var(--border);
  border-radius: 999px;
  color: var(--muted);
  font-size: 12px;
  background: var(--panel);
}
.dot { width: 7px; height: 7px; border-radius: 50%; background: var(--subtle); position: relative; flex: none; }
.dot.ok { background: var(--ok); }
.dot.warn { background: var(--warn); }
.dot.err { background: var(--err); }
.dot.ok.pulse::after {
  content: "";
  position: absolute;
  inset: -3px;
  border-radius: 50%;
  border: 1px solid var(--ok);
  animation: ping 2s ease-out infinite;
}
@keyframes ping { 0% { transform: scale(0.6); opacity: 0.8; } 100% { transform: scale(2.1); opacity: 0; } }
.spacer { flex: 1; }
.seg {
  display: inline-flex;
  padding: 2px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--panel);
}
.seg button {
  border: 0;
  background: transparent;
  color: var(--muted);
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 6px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.seg button:hover { color: var(--fg); }
.seg button[aria-pressed="true"] { background: var(--chip); color: var(--fg); box-shadow: inset 0 0 0 1px var(--border); }
.seg svg { width: 13px; height: 13px; }
.btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 28px;
  padding: 0 11px;
  border-radius: 7px;
  border: 1px solid var(--border-strong);
  background: var(--panel);
  color: var(--fg);
  font-size: 12px;
  cursor: pointer;
  transition: background-color 0.15s ease, border-color 0.15s ease;
  white-space: nowrap;
}
.btn:hover { background: var(--hover); }
.btn:focus-visible, .seg button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.btn svg { width: 13px; height: 13px; }
.btn.sm { height: 24px; padding: 0 8px; font-size: 11.5px; }
.btn.danger { color: var(--err); border-color: color-mix(in srgb, var(--err) 40%, transparent); }
.btn.danger:hover { background: var(--err-bg); }
.btn.primary { background: var(--btn-bg); color: var(--btn-fg); border-color: transparent; }
.btn[disabled] { opacity: 0.45; pointer-events: none; }
.btn[aria-busy="true"] { opacity: 0.6; pointer-events: none; }
.user {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 3px 10px 3px 3px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--panel);
  font-size: 12px;
}
.avatar {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: var(--chip);
  display: grid;
  place-items: center;
  font-size: 10px;
  font-weight: 600;
  overflow: hidden;
}
.avatar img { width: 100%; height: 100%; object-fit: cover; }
.devtag {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--warn);
  background: var(--warn-bg);
  padding: 1px 6px;
  border-radius: 4px;
}
main { max-width: 1480px; margin: 0 auto; padding: 18px 20px 60px; display: grid; gap: 18px; }
.chaos {
  border: 1px dashed color-mix(in srgb, var(--warn) 45%, transparent);
  background: var(--warn-bg);
  border-radius: var(--radius);
}
.chaos summary {
  list-style: none;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  font-size: 12px;
  color: var(--warn);
  font-weight: 550;
}
.chaos summary::-webkit-details-marker { display: none; }
.chaos summary svg { width: 14px; height: 14px; transition: transform 0.15s ease; }
.chaos[open] summary .chev { transform: rotate(90deg); }
.chaos-body { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 0 14px 12px; }
.chaos-body label { display: inline-flex; align-items: center; gap: 6px; color: var(--muted); font-size: 12px; }
.field {
  height: 26px;
  border-radius: 6px;
  border: 1px solid var(--border-strong);
  background: var(--panel);
  padding: 0 8px;
  font-size: 12px;
  min-width: 120px;
}
.vr { width: 1px; height: 20px; background: var(--border-strong); margin: 0 4px; }
section.block { display: grid; gap: 10px; }
.block-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.block-head h2 { margin: 0; font-size: 13px; font-weight: 600; letter-spacing: -0.005em; }
.block-head .hint { color: var(--subtle); font-size: 12px; }
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}
.kpis {
  display: grid;
  grid-template-columns: repeat(7, minmax(0, 1fr));
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--panel);
  overflow: hidden;
}
.kpi { padding: 12px 16px; border-right: 1px solid var(--border); min-width: 0; }
.kpi:last-child { border-right: 0; }
.kpi .k { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; }
.kpi .v { font-size: 20px; font-weight: 600; margin-top: 4px; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.kpi .v small { font-size: 12px; color: var(--muted); font-weight: 500; margin-left: 2px; }
.regions { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 12px; }
.region { padding: 14px 16px 16px; display: grid; gap: 12px; }
.region-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
.region-name { display: flex; align-items: baseline; gap: 8px; }
.region-name strong { font-family: var(--font-mono); font-size: 15px; font-weight: 600; }
.region-name span { color: var(--muted); font-size: 12px; }
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 20px;
  padding: 0 7px;
  border-radius: 5px;
  font-size: 11px;
  font-weight: 550;
  background: var(--chip);
  color: var(--muted);
  white-space: nowrap;
}
.badge svg { width: 11px; height: 11px; }
.badge.ok { background: var(--ok-bg); color: var(--ok); }
.badge.warn { background: var(--warn-bg); color: var(--warn); }
.badge.err { background: var(--err-bg); color: var(--err); }
.badge.info { background: var(--info-bg); color: var(--accent); }
.stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px 12px; }
.stat .k { font-size: 11px; color: var(--muted); }
.stat .v { font-size: 15px; font-weight: 600; margin-top: 2px; font-variant-numeric: tabular-nums; }
.stat .v small { font-size: 11px; color: var(--muted); font-weight: 500; }
.meter { display: grid; gap: 5px; }
.meter-top { display: flex; justify-content: space-between; font-size: 11.5px; color: var(--muted); }
.meter-top b { color: var(--fg); font-weight: 600; font-variant-numeric: tabular-nums; }
.track { position: relative; height: 6px; border-radius: 3px; background: var(--track); overflow: hidden; }
.fill { position: absolute; top: 0; bottom: 0; left: 0; border-radius: 3px; background: var(--s1); }
.charts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.chart-card { padding: 14px 16px 10px; min-width: 0; }
.chart-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; margin-bottom: 6px; }
.chart-head h3 { margin: 0; font-size: 12.5px; font-weight: 600; }
.chart-head p { margin: 2px 0 0; color: var(--subtle); font-size: 11.5px; }
.legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 11.5px; color: var(--muted); }
.legend span { display: inline-flex; align-items: center; gap: 6px; }
.legend b { color: var(--fg); font-weight: 600; font-variant-numeric: tabular-nums; }
.sw { width: 10px; height: 3px; border-radius: 2px; display: inline-block; }
.sw.s1 { background: var(--s1); }
.sw.s2 { background: var(--s2); }
.sw.s3 { background: var(--s3); }
.plot-host { position: relative; min-height: 120px; touch-action: pan-y; }
svg.plot { display: block; overflow: visible; }
svg.plot .grid { stroke: var(--grid); stroke-width: 1; }
svg.plot .base { stroke: var(--border-strong); stroke-width: 1; }
svg.plot text { fill: var(--subtle); font-size: 10.5px; font-family: var(--font-sans); font-variant-numeric: tabular-nums; }
svg.plot text.ptitle { fill: var(--muted); font-size: 11px; font-weight: 550; }
svg.plot .ln { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
svg.plot .ln.s1 { stroke: var(--s1); }
svg.plot .ln.s2 { stroke: var(--s2); }
svg.plot .ln.s3 { stroke: var(--s3); }
svg.plot .ar { stroke: none; opacity: 0.1; }
svg.plot .ar.s1 { fill: var(--s1); }
svg.plot .ar.s2 { fill: var(--s2); }
svg.plot .ar.s3 { fill: var(--s3); }
svg.plot .xh { stroke: var(--muted); stroke-width: 1; stroke-dasharray: 3 3; }
svg.plot .xd { stroke: var(--panel); stroke-width: 2; }
svg.plot .xd.s1 { fill: var(--s1); }
svg.plot .xd.s2 { fill: var(--s2); }
svg.plot .xd.s3 { fill: var(--s3); }
svg.plot .thr { stroke: var(--warn); stroke-width: 1; stroke-dasharray: 4 3; }
.empty {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  color: var(--subtle);
  font-size: 12px;
  pointer-events: none;
}
.tip {
  position: absolute;
  z-index: 30;
  pointer-events: none;
  min-width: 150px;
  padding: 8px 10px;
  border-radius: 8px;
  background: var(--tip-bg);
  border: 1px solid var(--border-strong);
  box-shadow: var(--shadow);
  font-size: 11.5px;
  display: grid;
  gap: 4px;
}
.tip[hidden] { display: none; }
.tip .t { color: var(--muted); font-variant-numeric: tabular-nums; margin-bottom: 2px; }
.tip .r { display: flex; align-items: center; gap: 8px; justify-content: space-between; }
.tip .r span { display: inline-flex; align-items: center; gap: 6px; color: var(--muted); }
.tip .r b { font-weight: 600; font-variant-numeric: tabular-nums; }
#gtip { position: fixed; }
.storage { display: grid; gap: 10px; padding: 6px 0 8px; }
.srow { display: grid; grid-template-columns: 150px minmax(0, 1fr) 110px; gap: 12px; align-items: center; }
.srow .who { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.srow .who small { color: var(--subtle); margin-left: 6px; }
.sbar { position: relative; height: 14px; border-radius: 4px; background: var(--track); }
.sbar .fill { border-radius: 4px; }
.sbar .fill.hot { background: var(--warn); }
.sbar .mark { position: absolute; top: -3px; bottom: -3px; width: 0; border-left: 1px dashed var(--warn); }
.srow .val { text-align: right; font-variant-numeric: tabular-nums; }
.srow .val small { color: var(--subtle); display: block; font-size: 10.5px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th {
  text-align: left;
  font-weight: 500;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--subtle);
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  background: var(--panel-2);
}
th:first-child { border-top-left-radius: var(--radius); }
th:last-child { border-top-right-radius: var(--radius); }
td { padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: middle; white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: var(--hover); }
td.r, th.r { text-align: right; }
.idcell b { font-family: var(--font-mono); font-size: 12px; font-weight: 600; }
.idcell div { color: var(--subtle); font-size: 11px; margin-top: 2px; }
.pack { width: 170px; display: grid; gap: 4px; }
.pack-track { position: relative; height: 8px; border-radius: 4px; background: var(--track); overflow: hidden; }
.pack-track .res {
  position: absolute; top: 0; bottom: 0; left: 0;
  background: repeating-linear-gradient(135deg, var(--reserve) 0 2px, transparent 2px 4px);
  border-right: 2px solid var(--panel);
}
.pack-track .req { position: absolute; top: 0; bottom: 0; background: var(--s1); border-radius: 0 3px 3px 0; }
.pack-track .use { position: absolute; top: -1px; bottom: -1px; width: 2px; margin-left: -1px; background: var(--usage); border-radius: 1px; }
.pack-meta { font-size: 11px; color: var(--muted); font-variant-numeric: tabular-nums; }
.pack-legend { display: flex; gap: 14px; font-size: 11.5px; color: var(--muted); flex-wrap: wrap; }
.pack-legend span { display: inline-flex; align-items: center; gap: 6px; }
.pk { width: 12px; height: 8px; border-radius: 2px; display: inline-block; }
.pk.res { background: repeating-linear-gradient(135deg, var(--reserve) 0 2px, transparent 2px 4px); box-shadow: inset 0 0 0 1px var(--border-strong); }
.pk.req { background: var(--s1); }
.pk.use { width: 2px; height: 10px; background: var(--usage); }
.actions { display: inline-flex; gap: 6px; }
.split { display: grid; grid-template-columns: minmax(0, 1.95fr) minmax(320px, 420px); gap: 12px; align-items: start; }
.split table th, .split table td { padding: 9px 10px; }
.dist { display: inline-flex; gap: 4px; }
.dist span { font-family: var(--font-mono); font-size: 11px; padding: 1px 5px; border-radius: 4px; background: var(--chip); color: var(--muted); }
.dist span.ok { color: var(--ok); background: var(--ok-bg); }
.dist span.warn { color: var(--warn); background: var(--warn-bg); }
.digest { font-family: var(--font-mono); font-size: 11.5px; }
.digest i { font-style: normal; color: var(--muted); }
.rollouts { display: grid; gap: 12px; }
.rollout { padding: 16px; display: grid; gap: 14px; }
.rollout.active { border-color: color-mix(in srgb, var(--accent) 35%, var(--border)); box-shadow: 0 0 0 3px var(--info-bg); }
.rollout-head { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; }
.rollout-head h3 { margin: 0; font-size: 14px; font-weight: 600; }
.rollout-head p { margin: 3px 0 0; color: var(--muted); font-size: 11.5px; }
.waves { display: grid; grid-auto-flow: column; grid-auto-columns: 1fr; gap: 6px; }
.wave { display: grid; gap: 6px; }
.wave .wbar { height: 5px; border-radius: 3px; background: var(--track); overflow: hidden; position: relative; }
.wave.done .wbar { background: var(--ok); }
.wave.active .wbar { background: color-mix(in srgb, var(--accent) 30%, var(--track)); }
.wave.active .wbar::after {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
  animation: sweep 1.4s linear infinite;
}
@keyframes sweep { from { transform: translateX(-100%); } to { transform: translateX(100%); } }
.wave .wl { display: flex; justify-content: space-between; font-size: 11px; color: var(--subtle); }
.wave .wl b { font-family: var(--font-mono); color: var(--muted); font-weight: 600; }
.wave.active .wl b, .wave.done .wl b { color: var(--fg); }
.bake { display: grid; gap: 6px; padding: 10px 12px; border-radius: 9px; background: var(--panel-2); border: 1px solid var(--border); }
.bake-top { display: flex; justify-content: space-between; font-size: 12px; }
.bake-top b { font-variant-numeric: tabular-nums; }
.bake .track { height: 5px; }
.bake .fill { background: var(--accent); transition: width 0.9s linear; }
.cmp { display: grid; grid-template-columns: auto 1fr 1fr; gap: 6px 14px; font-size: 12px; align-items: center; }
.cmp .h { font-size: 11px; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.05em; }
.cmp b { font-variant-numeric: tabular-nums; font-weight: 600; }
.cmp b.bad { color: var(--err); }
.none { padding: 26px 16px; text-align: center; color: var(--subtle); font-size: 12px; }
.events-tools { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.events { max-height: 460px; overflow-y: auto; }
.ev { display: grid; grid-template-columns: 74px 16px 150px 52px minmax(0, 1fr); gap: 10px; align-items: center; padding: 8px 14px; border-bottom: 1px solid var(--border); }
.ev:last-child { border-bottom: 0; }
.ev:hover { background: var(--hover); }
.ev .when { color: var(--subtle); font-size: 11.5px; font-variant-numeric: tabular-nums; }
.ev .ic { width: 16px; height: 16px; display: grid; place-items: center; }
.ev .ic svg { width: 14px; height: 14px; }
.ev .ic.ok { color: var(--ok); }
.ev .ic.warn { color: var(--warn); }
.ev .ic.err { color: var(--err); }
.ev .ic.info { color: var(--accent); }
.ev .kind { font-size: 12px; font-weight: 550; }
.ev .rg { font-family: var(--font-mono); font-size: 11px; color: var(--muted); }
.ev .what { min-width: 0; display: flex; gap: 8px; align-items: center; overflow: hidden; }
.ev .what b { font-weight: 550; font-family: var(--font-mono); font-size: 12px; white-space: nowrap; }
.ev .what .kv { font-family: var(--font-mono); font-size: 11px; color: var(--muted); background: var(--chip); padding: 1px 6px; border-radius: 4px; white-space: nowrap; }
.toasts { position: fixed; right: 18px; bottom: 18px; z-index: 50; display: grid; gap: 8px; }
.toast {
  min-width: 260px;
  max-width: 380px;
  padding: 10px 12px;
  border-radius: 9px;
  background: var(--tip-bg);
  border: 1px solid var(--border-strong);
  box-shadow: var(--shadow);
  font-size: 12.5px;
  display: flex;
  gap: 10px;
  align-items: flex-start;
  animation: rise 0.25s ease;
}
.toast .dot { margin-top: 5px; }
@keyframes rise { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
dialog {
  border: 1px solid var(--border-strong);
  border-radius: 14px;
  padding: 0;
  background: var(--panel);
  color: var(--fg);
  box-shadow: var(--shadow);
  width: min(420px, calc(100vw - 32px));
}
dialog::backdrop { background: rgba(0, 0, 0, 0.45); backdrop-filter: blur(2px); }
.dlg { padding: 20px; display: grid; gap: 10px; }
.dlg h3 { margin: 0; font-size: 15px; }
.dlg p { margin: 0; color: var(--muted); line-height: 1.5; }
.dlg .row { display: flex; justify-content: flex-end; gap: 8px; margin-top: 8px; }
.banner {
  display: none;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: 9px;
  border: 1px solid color-mix(in srgb, var(--err) 35%, transparent);
  background: var(--err-bg);
  color: var(--err);
  font-size: 12.5px;
}
.banner.show { display: flex; }
@media (max-width: 1180px) {
  .kpis { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .kpi:nth-child(4) { border-right: 0; }
  .kpi:nth-child(-n+4) { border-bottom: 1px solid var(--border); }
  .split { grid-template-columns: 1fr; }
}
@media (max-width: 900px) {
  .charts { grid-template-columns: 1fr; }
  .ev { grid-template-columns: 64px 16px 1fr; }
  .ev .rg, .ev .what { grid-column: 3; }
}
@media (max-width: 640px) {
  .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .kpi { border-right: 0; border-bottom: 1px solid var(--border); }
  .srow { grid-template-columns: 100px minmax(0, 1fr) 80px; }
  .bar { padding: 10px 12px; }
  main { padding: 14px 12px 40px; }
}
</style>
</head>
<body>
<header class="top">
  <div class="bar">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3 3 7.5 12 12l9-4.5L12 3z"/><path d="m3 12 9 4.5 9-4.5" opacity="0.7"/><path d="m3 16.5 9 4.5 9-4.5" opacity="0.4"/></svg>
      </div>
      <div>
        <h1>TerraScale Orchestrator</h1>
        <div class="host">orch.terrascale.tech</div>
      </div>
    </div>
    <div class="live" title="Backplane connection">
      <span class="dot" id="conn-dot"></span>
      <span id="conn-text">Connecting…</span>
      <span class="subtle num" id="updated"></span>
    </div>
    <button type="button" class="btn sm" id="pause" aria-pressed="false" title="Pause auto-refresh">
      <svg viewBox="0 0 24 24" fill="currentColor" id="pause-icon"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg>
      <span id="pause-text">Pause</span>
    </button>
    <div class="spacer"></div>
    <div class="seg" role="group" aria-label="Region" id="region-pills"></div>
    <div class="seg" role="group" aria-label="Time window">
      <button type="button" data-window="1h" aria-pressed="true">1h</button>
      <button type="button" data-window="48h" aria-pressed="false">48h</button>
    </div>
    <div class="seg" role="group" aria-label="Theme">
      <button type="button" data-theme-set="dark" aria-pressed="false" title="Dark theme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
        Dark
      </button>
      <button type="button" data-theme-set="light" aria-pressed="false" title="Light theme">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
        Light
      </button>
    </div>
    <div class="user" id="user" hidden>
      <span class="avatar" id="avatar"></span>
      <span id="user-login" class="mono"></span>
      <span class="devtag" id="user-dev" hidden>local</span>
    </div>
    <button type="button" class="btn" id="logout">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></svg>
      Sign Out
    </button>
  </div>
</header>
<main>
  <div class="banner" id="banner" role="alert">
    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>
    <span id="banner-text"></span>
  </div>

  <details class="chaos" id="chaos" hidden>
    <summary>
      <svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 18 6-6-6-6"/></svg>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/></svg>
      Local Aspire Dev Chaos
      <span class="subtle" style="font-weight:400">POST /api/dev/chaos · LOCAL_DEV only</span>
    </summary>
    <div class="chaos-body">
      <label>Node <select class="field" id="chaos-node"></select></label>
      <label>Service <select class="field" id="chaos-service"></select></label>
      <label>Secret <input class="field" id="chaos-secret" placeholder="secret name" spellcheck="false"></label>
      <span class="vr"></span>
      <button type="button" class="btn sm danger" data-chaos="kill_node">Kill Node</button>
      <button type="button" class="btn sm" data-chaos="inject_5xx">Inject Canary 5xx</button>
      <button type="button" class="btn sm" data-chaos="cpu_load">CPU Load Spike</button>
      <button type="button" class="btn sm" data-chaos="clear_load">Clear Load</button>
      <button type="button" class="btn sm" data-chaos="bump_secret">Bump Vault Secret</button>
      <button type="button" class="btn sm" data-chaos="fill_disk">Simulate &gt;75% Disk</button>
      <button type="button" class="btn sm" data-chaos="atlas_roundtrip">Test Atlas Publish/Resolve</button>
    </div>
  </details>

  <section class="block" aria-labelledby="h-regions">
    <div class="block-head"><h2 id="h-regions">Fleet overview</h2><span class="hint" id="regions-hint"></span></div>
    <div class="kpis" id="kpis"></div>
    <div class="regions" id="regions"></div>
  </section>

  <section class="block" aria-labelledby="h-charts">
    <div class="block-head"><h2 id="h-charts">Live metrics</h2><span class="hint" id="charts-hint"></span></div>
    <div class="charts">
      <div class="card chart-card">
        <div class="chart-head">
          <div><h3>Fleet CPU</h3><p>Capacity-weighted utilization and CPU pressure (PSI some avg10)</p></div>
          <div class="legend" id="lg-cpu"></div>
        </div>
        <div class="plot-host" id="ch-cpu"></div>
      </div>
      <div class="card chart-card">
        <div class="chart-head">
          <div><h3>Fleet memory</h3><p>Used of total RAM and memory pressure (PSI some avg10)</p></div>
          <div class="legend" id="lg-mem"></div>
        </div>
        <div class="plot-host" id="ch-mem"></div>
      </div>
      <div class="card chart-card">
        <div class="chart-head">
          <div><h3>Edge traffic</h3><p>Kestrel + YARP requests/s, p95 latency and 5xx rate</p></div>
          <div class="legend" id="lg-edge"></div>
        </div>
        <div class="plot-host" id="ch-edge"></div>
      </div>
      <div class="card chart-card">
        <div class="chart-head">
          <div><h3>Stateful storage</h3><p><span class="mono">/var/lib/ts-data</span> utilization · auto-grow at 75%</p></div>
          <div class="legend" id="lg-disk"></div>
        </div>
        <div class="storage" id="ch-disk"></div>
      </div>
    </div>
  </section>

  <section class="block" aria-labelledby="h-nodes">
    <div class="block-head">
      <h2 id="h-nodes">Nodes &amp; slice packing</h2>
      <span class="hint" id="nodes-hint"></span>
      <div class="spacer"></div>
      <div class="pack-legend">
        <span><i class="pk res"></i>ts-orch.slice reserve</span>
        <span><i class="pk req"></i>Scheduled requests</span>
        <span><i class="pk use"></i>Actual usage</span>
      </div>
    </div>
    <div class="card table-wrap">
      <table>
        <thead>
          <tr>
            <th>Node</th><th>Region</th><th>Pool</th><th>Shape</th><th>Status</th>
            <th>CPU packing</th><th>RAM packing</th><th class="r">PSI cpu / mem</th><th class="r">Disk</th><th class="r">Actions</th>
          </tr>
        </thead>
        <tbody id="nodes"></tbody>
      </table>
    </div>
  </section>

  <section class="split">
    <div class="block" aria-labelledby="h-services">
      <div class="block-head"><h2 id="h-services">Services</h2><span class="hint" id="services-hint"></span></div>
      <div class="card table-wrap">
        <table>
          <thead>
            <tr>
              <th>Service</th><th>Mode</th><th>Priority</th><th>Image</th><th>Replicas</th><th class="r">p95</th><th class="r">5xx</th>
            </tr>
          </thead>
          <tbody id="services"></tbody>
        </table>
      </div>
    </div>
    <div class="block" aria-labelledby="h-rollouts">
      <div class="block-head"><h2 id="h-rollouts">Rollouts</h2><span class="hint" id="rollouts-hint"></span></div>
      <div class="rollouts" id="rollouts"></div>
    </div>
  </section>

  <section class="block" aria-labelledby="h-events">
    <div class="block-head">
      <h2 id="h-events">Recent events</h2>
      <span class="hint" id="events-hint"></span>
      <div class="spacer"></div>
      <div class="events-tools">
        <div class="seg" role="group" aria-label="Event type" id="event-filters"></div>
        <input class="field" id="event-search" type="search" placeholder="Filter subject or detail" spellcheck="false">
      </div>
    </div>
    <div class="card events" id="events"></div>
  </section>
</main>
<div class="tip" id="gtip" hidden></div>
<div class="toasts" id="toasts" aria-live="polite"></div>
<dialog id="confirm">
  <form method="dialog" class="dlg">
    <h3 id="confirm-title"></h3>
    <p id="confirm-text"></p>
    <div class="row">
      <button type="submit" class="btn" value="cancel">Cancel</button>
      <button type="submit" class="btn primary" value="ok" id="confirm-ok">Confirm</button>
    </div>
  </form>
</dialog>
<script type="module">
const REGION_ORDER = ["gru", "fra", "sjc"];
const REGION_NAMES = { gru: "São Paulo", fra: "Frankfurt", sjc: "San Jose" };
const WINDOWS = { "1h": 3600000, "48h": 172800000 };
const BUCKETS = { "1h": 20000, "48h": 900000 };
const REFRESH_MS = 5000;
const BAKE_MS = 45000;
const DATA_MOUNT = "/var/lib/ts-data";
const ACTIVE_PHASES = new Set(["pending", "canary", "baking", "waves"]);
const EVENT_GROUPS = [
  ["all", "All", null],
  ["deploy", "Deploys", ["deploy_started", "canary_started", "canary_passed", "rollout_succeeded", "rollout_failed"]],
  ["rollback", "Rollbacks", ["rollback"]],
  ["autoscale", "Autoscale", ["replica_scale_up", "replica_scale_down", "pool_scale_up", "pool_scale_down", "pool_scale_blocked"]],
  ["nodes", "Nodes", ["node_enrolled", "node_connected", "node_lost", "node_drained", "failover", "oom_kill"]],
  ["tls", "TLS & secrets", ["tls_renewed", "secret_rotated"]],
  ["volume", "Volumes", ["volume_grown"]],
  ["chaos", "Chaos", ["chaos"]]
];
const EVENT_META = {
  deploy_started: ["Deploy started", "info", "deploy"],
  canary_started: ["Canary started", "info", "canary"],
  canary_passed: ["Canary passed", "ok", "check"],
  rollback: ["Canary auto-rollback", "err", "undo"],
  rollout_succeeded: ["Rollout succeeded", "ok", "check"],
  rollout_failed: ["Rollout failed", "err", "x"],
  replica_scale_up: ["Replicas scaled up", "info", "up"],
  replica_scale_down: ["Replicas scaled down", "info", "down"],
  pool_scale_up: ["Pool scaled up", "info", "up"],
  pool_scale_down: ["Pool scaled down", "info", "down"],
  pool_scale_blocked: ["Pool scale blocked", "warn", "warn"],
  node_enrolled: ["Node enrolled", "ok", "plus"],
  node_connected: ["Node connected", "ok", "plug"],
  node_lost: ["Node lost", "err", "x"],
  node_drained: ["Node drained", "warn", "down"],
  failover: ["Failover", "warn", "swap"],
  oom_kill: ["OOM kill", "err", "x"],
  volume_grown: ["Volume grown", "info", "disk"],
  secret_rotated: ["Secret rotated", "info", "key"],
  tls_renewed: ["TLS renewed", "ok", "lock"],
  chaos: ["Chaos injected", "warn", "bolt"]
};
const ICONS = {
  deploy: '<path d="M12 19V5M5 12l7-7 7 7"/>',
  canary: '<circle cx="12" cy="12" r="3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  undo: '<path d="M3 7v6h6"/><path d="M21 17a9 9 0 0 0-15-6.7L3 13"/>',
  x: '<path d="M18 6 6 18M6 6l12 12"/>',
  up: '<path d="m18 15-6-6-6 6"/>',
  down: '<path d="m6 9 6 6 6-6"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  plug: '<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0V8zM12 18v4"/>',
  swap: '<path d="M7 16V4M3 8l4-4 4 4M17 8v12M21 16l-4 4-4-4"/>',
  disk: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 14h18M7 17h.01"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  bolt: '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
  ok: '<path d="M20 6 9 17l-5-5"/>',
  warn: '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
  err: '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6M9 9l6 6"/>'
};
const icon = (name) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + (ICONS[name] ?? "") + "</svg>";

const state = {
  me: null,
  status: null,
  top: null,
  metrics: null,
  events: [],
  region: "all",
  window: "1h",
  paused: false,
  eventGroup: "all",
  eventQuery: "",
  tick: 0,
  lastUpdated: 0,
  inflight: false
};

const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const num = (v) => typeof v === "number" && Number.isFinite(v);
const ms = (t) => (num(t) ? (t < 1e12 ? t * 1000 : t) : 0);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const sum = (arr, f) => arr.reduce((a, x) => a + (f(x) || 0), 0);
const fmtPct = (v) => (num(v) ? (Math.abs(v) < 10 && v !== 0 ? v.toFixed(1) : Math.round(v).toString()) + "%" : "—");
const fmtMs = (v) => (num(v) ? (v >= 1000 ? (v / 1000).toFixed(2) + " s" : Math.round(v) + " ms") : "—");
const fmtRps = (v) => (num(v) ? (v >= 10000 ? (v / 1000).toFixed(0) + "k" : v >= 1000 ? (v / 1000).toFixed(1) + "k" : v >= 10 ? Math.round(v).toString() : v.toFixed(1)) : "—");
const fmtGiB = (mib) => (num(mib) ? (mib / 1024 >= 100 ? Math.round(mib / 1024) : (mib / 1024).toFixed(1)) + " GiB" : "—");
const fmtCores = (m) => (num(m) ? (m / 1000).toFixed(m % 1000 === 0 ? 0 : 1) : "—");
const clock = (t) => new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const ago = (t) => {
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
};
const inRegion = (r) => state.region === "all" || r === state.region;
const regionRank = (r) => {
  const i = REGION_ORDER.indexOf(r);
  return i < 0 ? 99 : i;
};

const root = document.documentElement;
const themeButtons = document.querySelectorAll("[data-theme-set]");
const syncTheme = () => {
  const current = root.getAttribute("data-theme");
  themeButtons.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.themeSet === current)));
};
themeButtons.forEach((b) => b.addEventListener("click", () => {
  root.setAttribute("data-theme", b.dataset.themeSet);
  try { localStorage.setItem("ts-orch-theme", b.dataset.themeSet); } catch {}
  syncTheme();
}));
syncTheme();
window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
  let saved = null;
  try { saved = localStorage.getItem("ts-orch-theme"); } catch {}
  if (saved !== "light" && saved !== "dark") {
    root.setAttribute("data-theme", e.matches ? "light" : "dark");
    syncTheme();
  }
});

const toast = (text, kind) => {
  const el = document.createElement("div");
  el.className = "toast";
  el.innerHTML = '<span class="dot ' + esc(kind ?? "ok") + '"></span><span>' + esc(text) + "</span>";
  $("toasts").appendChild(el);
  setTimeout(() => el.remove(), 4500);
};

const confirmAction = (title, text, okLabel, danger) => new Promise((resolve) => {
  const dlg = $("confirm");
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = text;
  const ok = $("confirm-ok");
  ok.textContent = okLabel;
  ok.className = danger ? "btn danger" : "btn primary";
  dlg.returnValue = "";
  dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
  dlg.showModal();
});

const sessionLost = () => location.replace("/?error=session_expired");

const getJson = async (path) => {
  const res = await fetch(path, { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
  if (res.status === 401) {
    sessionLost();
    throw new Error("unauthorized");
  }
  if (!res.ok) throw new Error(path + " -> HTTP " + res.status);
  return res.json();
};

const post = async (path, body) => {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", accept: "application/json", "x-requested-with": "ts-orch-ui" },
    body: JSON.stringify(body ?? {})
  });
  if (res.status === 401) {
    sessionLost();
    throw new Error("Session expired");
  }
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) throw new Error(data?.error?.message ?? "HTTP " + res.status);
  return data;
};

const nodesById = () => {
  const m = new Map();
  for (const n of state.status?.nodes ?? []) m.set(n.id, n);
  return m;
};

const topByNode = () => {
  const m = new Map();
  for (const p of state.top?.nodes ?? []) {
    const prev = m.get(p.nodeId);
    if (!prev || ms(p.ts) > ms(prev.ts)) m.set(p.nodeId, p);
  }
  return m;
};

const edgeAgg = (snapshots, serviceName) => {
  let rps = 0, errW = 0, p95W = 0, p95Max = null, req = 0, r5 = 0;
  for (const snap of snapshots) {
    for (const s of snap?.services ?? []) {
      if (serviceName && s.serviceName !== serviceName) continue;
      const r = num(s.rps) ? s.rps : 0;
      rps += r;
      if (num(s.errorRate5xxPct)) errW += r * s.errorRate5xxPct;
      if (num(s.p95Ms)) {
        p95W += r * s.p95Ms;
        p95Max = p95Max === null ? s.p95Ms : Math.max(p95Max, s.p95Ms);
      }
      if (num(s.requests)) req += s.requests;
      if (num(s.responses5xx)) r5 += s.responses5xx;
    }
  }
  const has = snapshots.some((s) => (s?.services ?? []).some((x) => !serviceName || x.serviceName === serviceName));
  if (!has) return { rps: null, err: null, p95: null };
  const err = req > 0 ? (r5 / req) * 100 : rps > 0 ? errW / rps : 0;
  const p95 = rps > 0 ? p95W / rps : p95Max;
  return { rps, err, p95 };
};

const normPoint = (p) => {
  const edge = p.edge ? edgeAgg([p.edge]) : null;
  return {
    nodeId: p.nodeId ?? "fleet",
    region: p.region,
    ts: ms(p.ts),
    cpu: p.cpuPct ?? p.cpuAvg ?? null,
    cpuPsi: p.cpuPsi10 ?? p.cpuPsiAvg ?? null,
    memMiB: p.memUsedMiB ?? p.memAvgMiB ?? null,
    memPsi: p.memPsi10 ?? p.memPsiAvg ?? null,
    disk: p.diskUsedPct ?? p.diskPct ?? null,
    rps: edge ? edge.rps : p.edgeRps ?? null,
    err: edge ? edge.err : p.edge5xx ?? null,
    p95: edge ? edge.p95 : p.edgeP95Ms ?? null
  };
};

const metricPoints = (data) => {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  return data.points ?? data.nodes ?? data.series ?? data.metrics ?? [];
};

const buildSeries = () => {
  const nodes = nodesById();
  const span = WINDOWS[state.window];
  const bucket = BUCKETS[state.window];
  const t1 = Date.now();
  const t0 = t1 - span;
  const buckets = new Map();
  for (const raw of metricPoints(state.metrics)) {
    const p = normPoint(raw);
    if (!p.ts || p.ts < t0 - bucket) continue;
    const region = p.region ?? nodes.get(p.nodeId)?.region;
    if (state.region !== "all" && region !== state.region) continue;
    const b = Math.floor(p.ts / bucket) * bucket + bucket / 2;
    let per = buckets.get(b);
    if (!per) buckets.set(b, (per = new Map()));
    let acc = per.get(p.nodeId);
    if (!acc) per.set(p.nodeId, (acc = { n: {}, s: {} }));
    for (const k of ["cpu", "cpuPsi", "memMiB", "memPsi", "disk", "rps", "err", "p95"]) {
      if (num(p[k])) {
        acc.s[k] = (acc.s[k] ?? 0) + p[k];
        acc.n[k] = (acc.n[k] ?? 0) + 1;
      }
    }
  }
  const rows = [];
  for (const [ts, per] of [...buckets.entries()].sort((a, b) => a[0] - b[0])) {
    let cpuW = 0, cpuT = 0, psiS = 0, psiN = 0, memU = 0, memT = 0, mpsiS = 0, mpsiN = 0, rps = 0, errW = 0, p95W = 0, p95Max = null, hasEdge = false;
    for (const [nodeId, acc] of per) {
      const avg = (k) => (acc.n[k] ? acc.s[k] / acc.n[k] : null);
      const node = nodes.get(nodeId);
      const cap = node?.cpuTotalMilli || 1;
      const cpu = avg("cpu");
      if (cpu !== null) { cpuW += cpu * cap; cpuT += cap; }
      const cpsi = avg("cpuPsi");
      if (cpsi !== null) { psiS += cpsi; psiN++; }
      const mem = avg("memMiB");
      if (mem !== null && node?.memTotalMiB) { memU += mem; memT += node.memTotalMiB; }
      const mpsi = avg("memPsi");
      if (mpsi !== null) { mpsiS += mpsi; mpsiN++; }
      const r = avg("rps");
      if (r !== null) {
        hasEdge = true;
        rps += r;
        const e = avg("err");
        if (e !== null) errW += r * e;
        const p = avg("p95");
        if (p !== null) { p95W += r * p; p95Max = p95Max === null ? p : Math.max(p95Max, p); }
      }
    }
    rows.push({
      ts,
      cpu: cpuT ? cpuW / cpuT : null,
      cpuPsi: psiN ? psiS / psiN : null,
      mem: memT ? (memU / memT) * 100 : null,
      memPsi: mpsiN ? mpsiS / mpsiN : null,
      rps: hasEdge ? rps : null,
      err: hasEdge ? (rps > 0 ? errW / rps : 0) : null,
      p95: hasEdge ? (rps > 0 ? p95W / rps : p95Max) : null
    });
  }
  return { rows, t0, t1 };
};

const niceMax = (v, floor) => {
  const m = Math.max(v || 0, floor);
  const p = Math.pow(10, Math.floor(Math.log10(m)));
  const n = m / p;
  const s = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
  return s * p;
};

const timeLabel = (t) => {
  const d = new Date(t);
  if (state.window === "1h") return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  return d.toLocaleDateString([], { weekday: "short" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
};

const plot = (host, series, panels) => {
  const { rows, t0, t1 } = series;
  const width = Math.max(280, Math.floor(host.clientWidth || 600));
  const L = 46, R = 12;
  const iw = width - L - R;
  const xOf = (t) => L + ((t - t0) / (t1 - t0)) * iw;
  const meta = [];
  let html = "";
  panels.forEach((p, pi) => {
    const last = pi === panels.length - 1;
    const top = p.title ? 20 : 8;
    const bottom = last ? 22 : 6;
    const h = p.height;
    const ih = h - top - bottom;
    let maxV = 0;
    for (const r of rows) for (const s of p.series) if (num(r[s.key])) maxV = Math.max(maxV, r[s.key]);
    let ymax = niceMax(maxV * 1.08, p.floor ?? 1);
    if (p.cap) ymax = Math.min(ymax, p.cap);
    const yOf = (v) => top + ih - (clamp(v, 0, ymax) / ymax) * ih;
    let g = "";
    if (p.title) g += '<text class="ptitle" x="' + L + '" y="12">' + esc(p.title) + "</text>";
    for (let k = 0; k <= 3; k++) {
      const v = (ymax * k) / 3;
      const y = yOf(v).toFixed(1);
      g += '<line class="' + (k === 0 ? "base" : "grid") + '" x1="' + L + '" x2="' + (width - R) + '" y1="' + y + '" y2="' + y + '"/>';
      g += '<text x="' + (L - 8) + '" y="' + (Number(y) + 3.5) + '" text-anchor="end">' + esc(p.fmt(v)) + "</text>";
    }
    if (num(p.threshold) && p.threshold < ymax) {
      const y = yOf(p.threshold).toFixed(1);
      g += '<line class="thr" x1="' + L + '" x2="' + (width - R) + '" y1="' + y + '" y2="' + y + '"/>';
    }
    p.series.forEach((s, si) => {
      const segs = [];
      let cur = [];
      for (const r of rows) {
        if (!num(r[s.key]) || r.ts < t0) {
          if (cur.length) segs.push(cur);
          cur = [];
          continue;
        }
        cur.push([xOf(r.ts), yOf(r[s.key])]);
      }
      if (cur.length) segs.push(cur);
      for (const seg of segs) {
        const d = seg.map((pt, i) => (i ? "L" : "M") + pt[0].toFixed(1) + " " + pt[1].toFixed(1)).join("");
        if (si === 0 && p.area !== false) {
          const base = (top + ih).toFixed(1);
          g += '<path class="ar ' + s.cls + '" d="' + d + "L" + seg[seg.length - 1][0].toFixed(1) + " " + base + "L" + seg[0][0].toFixed(1) + " " + base + 'Z"/>';
        }
        if (seg.length === 1) g += '<circle class="xd ' + s.cls + '" r="2.5" cx="' + seg[0][0].toFixed(1) + '" cy="' + seg[0][1].toFixed(1) + '"/>';
        else g += '<path class="ln ' + s.cls + '" d="' + d + '"/>';
      }
    });
    if (last) {
      for (let k = 0; k <= 4; k++) {
        const t = t0 + ((t1 - t0) * k) / 4;
        const anchor = k === 0 ? "start" : k === 4 ? "end" : "middle";
        g += '<text x="' + xOf(t).toFixed(1) + '" y="' + (h - 5) + '" text-anchor="' + anchor + '">' + esc(timeLabel(t)) + "</text>";
      }
    }
    g += '<line class="xh" x1="-20" x2="-20" y1="' + top + '" y2="' + (top + ih) + '" visibility="hidden"/>';
    p.series.forEach((s) => { g += '<circle class="xd ' + s.cls + '" data-hover="1" r="4" cx="-20" cy="-20" visibility="hidden"/>'; });
    html += '<svg class="plot" width="' + width + '" height="' + h + '" viewBox="0 0 ' + width + " " + h + '" role="img" aria-label="' + esc(p.title ?? p.series.map((s) => s.label).join(", ")) + '">' + g + "</svg>";
    meta.push({ yOf, series: p.series, fmt: p.fmt });
  });
  const hasData = rows.some((r) => panels.some((p) => p.series.some((s) => num(r[s.key]))));
  if (!hasData) html += '<div class="empty">No samples in this window</div>';
  host.innerHTML = html + '<div class="tip" hidden></div>';
  host._plot = { rows: rows.filter((r) => r.ts >= t0), meta, xOf, L, iw, t0, t1, width };
  if (host._hoverX !== undefined && host._hoverX !== null) hover(host, host._hoverX);
};

const hover = (host, x) => {
  const p = host._plot;
  const tip = host.querySelector(".tip");
  if (!p || !p.rows.length || !tip) return;
  const t = p.t0 + ((x - p.L) / p.iw) * (p.t1 - p.t0);
  let lo = 0, hi = p.rows.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (p.rows[mid].ts < t) lo = mid + 1; else hi = mid;
  }
  if (lo > 0 && Math.abs(p.rows[lo - 1].ts - t) < Math.abs(p.rows[lo].ts - t)) lo--;
  const row = p.rows[lo];
  const cx = p.xOf(row.ts).toFixed(1);
  let lines = '<div class="t">' + esc(new Date(row.ts).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit", second: state.window === "1h" ? "2-digit" : undefined, hour12: false })) + "</div>";
  host.querySelectorAll("svg.plot").forEach((svg, i) => {
    const m = p.meta[i];
    if (!m) return;
    const xh = svg.querySelector(".xh");
    xh.setAttribute("x1", cx);
    xh.setAttribute("x2", cx);
    xh.setAttribute("visibility", "visible");
    const dots = svg.querySelectorAll('[data-hover="1"]');
    m.series.forEach((s, si) => {
      const v = row[s.key];
      const dot = dots[si];
      if (num(v)) {
        dot.setAttribute("cx", cx);
        dot.setAttribute("cy", m.yOf(v).toFixed(1));
        dot.setAttribute("visibility", "visible");
      } else {
        dot.setAttribute("visibility", "hidden");
      }
      lines += '<div class="r"><span><i class="sw ' + s.cls + '"></i>' + esc(s.label) + "</span><b>" + esc(num(v) ? m.fmt(v) : "—") + "</b></div>";
    });
  });
  tip.innerHTML = lines;
  tip.hidden = false;
  const tw = tip.offsetWidth;
  const left = Number(cx) + 14 + tw > p.width ? Number(cx) - 14 - tw : Number(cx) + 14;
  tip.style.left = Math.max(0, left) + "px";
  tip.style.top = "6px";
};

const clearHover = (host) => {
  host.querySelectorAll(".xh, [data-hover='1']").forEach((el) => el.setAttribute("visibility", "hidden"));
  const tip = host.querySelector(".tip");
  if (tip) tip.hidden = true;
};

for (const id of ["ch-cpu", "ch-mem", "ch-edge"]) {
  const host = $(id);
  host.addEventListener("pointermove", (e) => {
    host._hoverX = e.clientX - host.getBoundingClientRect().left;
    hover(host, host._hoverX);
  });
  host.addEventListener("pointerleave", () => {
    host._hoverX = null;
    clearHover(host);
  });
}

const legend = (items) => items.map((i) => '<span><i class="sw ' + i.cls + '"></i>' + esc(i.label) + " <b>" + esc(i.value) + "</b></span>").join("");

const lastValue = (rows, key) => {
  for (let i = rows.length - 1; i >= 0; i--) if (num(rows[i][key])) return rows[i][key];
  return null;
};

const pctFmt = (v) => (v >= 10 || v === 0 ? Math.round(v) : v.toFixed(1)) + "%";
const msAxis = (v) => (v >= 1000 ? (v / 1000).toFixed(1) + "s" : Math.round(v) + "ms");
const rpsAxis = (v) => (v >= 1000 ? (v / 1000).toFixed(1) + "k" : v >= 10 ? Math.round(v).toString() : v.toFixed(1));

const renderCharts = () => {
  const series = buildSeries();
  const rows = series.rows;
  plot($("ch-cpu"), series, [{
    height: 190,
    floor: 10,
    cap: 100,
    fmt: pctFmt,
    series: [
      { key: "cpu", label: "CPU used", cls: "s1" },
      { key: "cpuPsi", label: "CPU PSI", cls: "s2" }
    ]
  }]);
  $("lg-cpu").innerHTML = legend([
    { cls: "s1", label: "CPU", value: fmtPct(lastValue(rows, "cpu")) },
    { cls: "s2", label: "PSI", value: fmtPct(lastValue(rows, "cpuPsi")) }
  ]);
  plot($("ch-mem"), series, [{
    height: 190,
    floor: 10,
    cap: 100,
    fmt: pctFmt,
    series: [
      { key: "mem", label: "Memory used", cls: "s1" },
      { key: "memPsi", label: "Memory PSI", cls: "s2" }
    ]
  }]);
  $("lg-mem").innerHTML = legend([
    { cls: "s1", label: "RAM", value: fmtPct(lastValue(rows, "mem")) },
    { cls: "s2", label: "PSI", value: fmtPct(lastValue(rows, "memPsi")) }
  ]);
  plot($("ch-edge"), series, [
    { title: "Requests / s", height: 78, floor: 1, fmt: rpsAxis, series: [{ key: "rps", label: "Requests/s", cls: "s1" }] },
    { title: "p95 latency", height: 70, floor: 10, fmt: msAxis, series: [{ key: "p95", label: "p95 latency", cls: "s1" }] },
    { title: "5xx rate", height: 82, floor: 1, cap: 100, fmt: pctFmt, area: true, series: [{ key: "err", label: "5xx rate", cls: "s1" }] }
  ]);
  $("lg-edge").innerHTML = legend([
    { cls: "s1", label: "RPS", value: fmtRps(lastValue(rows, "rps")) },
    { cls: "s1", label: "p95", value: fmtMs(lastValue(rows, "p95")) },
    { cls: "s1", label: "5xx", value: fmtPct(lastValue(rows, "err")) }
  ]).replaceAll('<i class="sw s1"></i>', "");
  const pts = metricPoints(state.metrics).length;
  $("charts-hint").textContent = (state.window === "1h" ? "Last hour · 10 s samples" : "Last 48 hours · 1 m rollups") + (pts ? " · " + pts.toLocaleString() + " points" : "");
  renderStorage();
};

const dataVolume = (node) => {
  const vols = node.volumes ?? [];
  return vols.find((v) => v.mountPath === DATA_MOUNT) ?? vols.find((v) => (v.mountPath ?? "").startsWith(DATA_MOUNT)) ?? null;
};

const renderStorage = () => {
  const tops = topByNode();
  const rows = (state.status?.nodes ?? [])
    .filter((n) => n.poolKind === "stateful" && inRegion(n.region))
    .sort((a, b) => regionRank(a.region) - regionRank(b.region) || a.id.localeCompare(b.id))
    .map((n) => {
      const vol = dataVolume(n);
      const used = num(vol?.usedPct) ? vol.usedPct : tops.get(n.id)?.diskUsedPct ?? null;
      return { n, vol, used };
    });
  if (!rows.length) {
    $("ch-disk").innerHTML = '<div class="none">No stateful nodes in this view</div>';
    $("lg-disk").innerHTML = "";
    return;
  }
  const hot = rows.filter((r) => num(r.used) && r.used >= 75).length;
  $("lg-disk").innerHTML = hot ? '<span class="badge warn">' + icon("warn") + hot + " above 75%</span>" : '<span class="badge ok">' + icon("ok") + "All below 75%</span>";
  $("ch-disk").innerHTML = rows.map(({ n, vol, used }) => {
    const pct = num(used) ? clamp(used, 0, 100) : 0;
    const size = num(vol?.sizeGiB) ? vol.sizeGiB : null;
    const usedGiB = size !== null && num(used) ? (size * used) / 100 : null;
    const tip = n.id + " · " + n.region + "|" + (vol?.mountPath ?? DATA_MOUNT) + "|Used: " + fmtPct(used) + (size !== null ? "|Size: " + size + " GiB" : "") + (usedGiB !== null ? "|Used: " + usedGiB.toFixed(1) + " GiB" : "") + (vol?.device ? "|Device: " + vol.device : "");
    return '<div class="srow" data-tip="' + esc(tip) + '">' +
      '<div class="who mono">' + esc(n.id) + "<small>" + esc(n.region) + "</small></div>" +
      '<div class="sbar"><div class="fill' + (pct >= 75 ? " hot" : "") + '" style="width:' + pct.toFixed(1) + '%"></div><div class="mark" style="left:75%"></div></div>' +
      '<div class="val"><b>' + esc(fmtPct(used)) + "</b><small>" + esc(size !== null ? (usedGiB !== null ? usedGiB.toFixed(0) + " / " : "") + size + " GiB" : "size unknown") + "</small></div>" +
      "</div>";
  }).join("");
};

const regionHealth = (r) => {
  if (r.health === "down" || (r.nodes > 0 && r.nodesReady === 0)) return "down";
  if (r.health === "unknown" || r.nodesReady < r.nodes || r.nodes === 0) return "degraded";
  return "ok";
};
const HEALTH_BADGE = { ok: ["ok", "ok", "Healthy"], degraded: ["warn", "warn", "Degraded"], down: ["err", "err", "Down"] };
const healthBadge = (h) => {
  const b = HEALTH_BADGE[h];
  return '<span class="badge ' + b[0] + '">' + icon(b[1]) + esc(b[2]) + "</span>";
};

const regionEdge = (label) => {
  const tops = topByNode();
  const snaps = [];
  for (const n of state.status?.nodes ?? []) {
    if (label && n.region !== label) continue;
    const t = tops.get(n.id);
    if (t?.edge) snaps.push(t.edge);
  }
  if (snaps.length) return edgeAgg(snaps);
  const series = buildSeriesFor(label);
  return { rps: lastValue(series, "rps"), err: lastValue(series, "err"), p95: lastValue(series, "p95") };
};

const buildSeriesFor = (label) => {
  const saved = state.region;
  state.region = label ?? "all";
  const s = buildSeries().rows;
  state.region = saved;
  return s;
};

const meter = (label, used, total, fmtTotal) => {
  const pct = total > 0 ? (used / total) * 100 : null;
  return '<div class="meter" data-tip="' + esc(label + "|Requested: " + fmtTotal(used) + "|Total: " + fmtTotal(total) + "|Packing: " + fmtPct(pct)) + '">' +
    '<div class="meter-top"><span>' + esc(label) + "</span><span><b>" + esc(fmtPct(pct)) + '</b> <span class="subtle">' + esc(fmtTotal(used) + " / " + fmtTotal(total)) + "</span></span></div>" +
    '<div class="track"><div class="fill" style="width:' + (pct === null ? 0 : clamp(pct, 0, 100)).toFixed(1) + '%"></div></div></div>';
};

const renderRegions = () => {
  const st = state.status;
  const regions = [...(st?.regions ?? [])].sort((a, b) => regionRank(a.label) - regionRank(b.label));
  const visible = regions.filter((r) => inRegion(r.label));
  const nodes = (st?.nodes ?? []).filter((n) => inRegion(n.region));
  const services = (st?.services ?? []).filter((s) => state.region === "all" || (s.regions ?? []).includes(state.region));
  const active = (st?.rollouts ?? []).filter((r) => ACTIVE_PHASES.has(r.phase) && inRegion(r.currentRegion ?? r.region ?? state.region));
  const edge = regionEdge(state.region === "all" ? null : state.region);
  const ready = sum(visible, (r) => r.nodesReady);
  const total = sum(visible, (r) => r.nodes);
  const dbs = sum(visible, (r) => r.databases);
  const kpi = (k, v, small) => '<div class="kpi"><div class="k">' + esc(k) + '</div><div class="v">' + v + (small ? "<small>" + esc(small) + "</small>" : "") + "</div></div>";
  $("kpis").innerHTML =
    kpi("Nodes ready", esc(ready), "/ " + total) +
    kpi("Regions", esc(visible.filter((r) => regionHealth(r) === "ok").length), "/ " + visible.length + " healthy") +
    kpi("Services", esc(services.length)) +
    kpi("Atlas DBs", esc(dbs.toLocaleString())) +
    kpi("Edge RPS", esc(fmtRps(edge.rps))) +
    kpi("p95 latency", esc(fmtMs(edge.p95))) +
    kpi("Active rollouts", esc(active.length));
  $("regions-hint").textContent = st ? nodes.length + " nodes · " + regions.length + " regions" : "";
  if (!visible.length) {
    $("regions").innerHTML = '<div class="card none">' + (st ? "No regions match this filter" : "Waiting for backplane…") + "</div>";
    return;
  }
  $("regions").innerHTML = visible.map((r) => {
    const h = regionHealth(r);
    const e = regionEdge(r.label);
    return '<article class="card region">' +
      '<div class="region-head"><div class="region-name"><strong>' + esc(r.label) + "</strong><span>" + esc(REGION_NAMES[r.label] ?? "") + "</span></div>" + healthBadge(h) + "</div>" +
      '<div class="stats">' +
        '<div class="stat"><div class="k">Nodes</div><div class="v">' + esc(r.nodesReady) + "<small> / " + esc(r.nodes) + "</small></div></div>" +
        '<div class="stat"><div class="k">Stateful · Worker</div><div class="v">' + esc(r.statefulNodes) + "<small> · </small>" + esc(r.workerNodes) + "</div></div>" +
        '<div class="stat"><div class="k">Atlas DBs</div><div class="v">' + esc((r.databases ?? 0).toLocaleString()) + "</div></div>" +
        '<div class="stat"><div class="k">RPS</div><div class="v">' + esc(fmtRps(e.rps)) + "</div></div>" +
        '<div class="stat"><div class="k">p95</div><div class="v">' + esc(fmtMs(e.p95)) + "</div></div>" +
        '<div class="stat"><div class="k">5xx rate</div><div class="v">' + esc(fmtPct(e.err)) + "</div></div>" +
      "</div>" +
      meter("CPU requested", r.cpuRequestedMilli ?? 0, r.cpuTotalMilli ?? 0, (m) => fmtCores(m) + " cores") +
      meter("RAM requested", r.memRequestedMiB ?? 0, r.memTotalMiB ?? 0, fmtGiB) +
      '<div class="meter-top"><span>Packing efficiency</span><span><b>' + esc(fmtPct(r.packingPct)) + "</b></span></div>" +
      "</article>";
  }).join("");
};

const nodeRequests = (node) => {
  if (num(node.cpuRequestedMilli) || num(node.memRequestedMiB)) return { cpu: node.cpuRequestedMilli ?? null, mem: node.memRequestedMiB ?? null };
  const specs = new Map((state.status?.services ?? []).map((s) => [s.name, s]));
  let cpu = 0, mem = 0, known = false;
  for (const p of state.status?.placements ?? []) {
    if (p.nodeId !== node.id || p.state === "stopped" || p.state === "failed") continue;
    const s = specs.get(p.serviceName);
    if (num(s?.cpuRequestMilli)) { cpu += s.cpuRequestMilli; known = true; }
    if (num(s?.memRequestMiB)) { mem += s.memRequestMiB; known = true; }
  }
  return known ? { cpu, mem } : { cpu: null, mem: null };
};

const packBar = (kind, total, reservePct, requested, usedPct, fmt) => {
  const reqPct = num(requested) && total > 0 ? (requested / total) * 100 : null;
  const res = clamp(reservePct, 0, 100);
  const req = reqPct === null ? 0 : clamp(reqPct, 0, 100 - res);
  const tip = kind + " packing|Reserve (ts-orch.slice): " + fmtPct(reservePct) + "|Requested: " + (reqPct === null ? "—" : fmtPct(reqPct) + " · " + fmt(requested)) + "|Usage: " + fmtPct(usedPct) + "|Total: " + fmt(total);
  return '<div class="pack" data-tip="' + esc(tip) + '">' +
    '<div class="pack-track"><span class="res" style="width:' + res.toFixed(1) + '%"></span>' +
    (reqPct === null ? "" : '<span class="req" style="left:' + res.toFixed(1) + "%;width:" + req.toFixed(1) + '%"></span>') +
    (num(usedPct) ? '<span class="use" style="left:' + clamp(usedPct, 0, 100).toFixed(1) + '%"></span>' : "") +
    "</div>" +
    '<div class="pack-meta">req ' + esc(reqPct === null ? "—" : fmtPct(reqPct)) + " · use " + esc(fmtPct(usedPct)) + "</div></div>";
};

const NODE_BADGE = { active: "ok", pending: "", draining: "warn", drained: "", down: "err" };

const renderNodes = () => {
  const tops = topByNode();
  const placements = state.status?.placements ?? [];
  const nodes = (state.status?.nodes ?? [])
    .filter((n) => inRegion(n.region))
    .sort((a, b) => regionRank(a.region) - regionRank(b.region) || (a.poolKind === b.poolKind ? 0 : a.poolKind === "stateful" ? -1 : 1) || a.id.localeCompare(b.id));
  $("nodes-hint").textContent = nodes.length ? nodes.filter((n) => n.status === "active").length + " active of " + nodes.length : "";
  if (!nodes.length) {
    $("nodes").innerHTML = '<tr><td colspan="10" class="none">' + (state.status ? "No nodes in this view" : "Waiting for backplane…") + "</td></tr>";
    return;
  }
  $("nodes").innerHTML = nodes.map((n) => {
    const t = tops.get(n.id);
    const req = nodeRequests(n);
    const cpuTotal = n.cpuTotalMilli ?? 0;
    const memTotal = n.memTotalMiB ?? 0;
    const memReservePct = memTotal > 0 ? (Math.max(memTotal * 0.1, 1024) / memTotal) * 100 : 10;
    const memUsedPct = num(t?.memUsedMiB) && memTotal > 0 ? (t.memUsedMiB / memTotal) * 100 : null;
    const vol = dataVolume(n);
    const disk = num(t?.diskUsedPct) ? t.diskUsedPct : vol?.usedPct ?? null;
    const count = placements.filter((p) => p.nodeId === n.id && p.state !== "stopped").length;
    const seen = ms(n.lastSeenAt);
    const stale = seen && Date.now() - seen > 30000 && n.status !== "down";
    const canDrain = n.status === "active" || n.status === "pending";
    const canActivate = n.status === "draining" || n.status === "drained";
    return "<tr>" +
      '<td class="idcell"><b>' + esc(n.id) + "</b><div>" + esc(n.vcnIp ?? "") + " · " + count + " replica" + (count === 1 ? "" : "s") + (n.faultDomain ? " · " + esc(n.faultDomain) : "") + "</div></td>" +
      '<td class="mono">' + esc(n.region) + "</td>" +
      '<td><span class="badge ' + (n.poolKind === "stateful" ? "info" : "") + '">' + esc(n.poolKind) + "</span></td>" +
      '<td class="idcell"><span class="mono">' + esc(n.shape) + "</span><div>" + esc(n.arch) + " · " + esc(fmtCores(cpuTotal)) + " vCPU · " + esc(fmtGiB(memTotal)) + "</div></td>" +
      '<td><span class="badge ' + (NODE_BADGE[n.status] ?? "") + '">' + esc(n.status) + "</span>" + (stale ? ' <span class="badge warn" title="Last heartbeat ' + esc(ago(seen)) + '">stale</span>' : "") + (n.drainRequested && n.status === "active" ? ' <span class="badge warn">drain req</span>' : "") + "</td>" +
      "<td>" + packBar("CPU", cpuTotal, 15, req.cpu, t?.cpuPct ?? null, (m) => fmtCores(m) + " cores") + "</td>" +
      "<td>" + packBar("RAM", memTotal, memReservePct, req.mem, memUsedPct, fmtGiB) + "</td>" +
      '<td class="r num">' + esc(fmtPct(t?.cpuPsi10)) + ' <span class="subtle">/</span> ' + esc(fmtPct(t?.memPsi10)) + "</td>" +
      '<td class="r num">' + (num(disk) && disk >= 75 ? '<span class="badge warn">' + esc(fmtPct(disk)) + "</span>" : esc(fmtPct(disk))) + "</td>" +
      '<td class="r"><div class="actions">' +
        '<button type="button" class="btn sm" data-node-action="drain" data-node="' + esc(n.id) + '"' + (canDrain ? "" : " disabled") + ">Drain</button>" +
        '<button type="button" class="btn sm" data-node-action="activate" data-node="' + esc(n.id) + '"' + (canActivate ? "" : " disabled") + ">Activate</button>" +
        '<button type="button" class="btn sm danger" data-node-action="reboot" data-node="' + esc(n.id) + '">Reboot</button>' +
      "</div></td></tr>";
  }).join("");
};

const NODE_ACTIONS = {
  drain: ["Drain node", "Stop scheduling onto {id} and migrate its replicas to other nodes. Stateful replicas will stop until the node is activated again.", "Drain", false],
  activate: ["Activate node", "Return {id} to the schedulable pool.", "Activate", false],
  reboot: ["Reboot node", "Reboot the VM behind {id} through the OCI API. Replicas on it are unavailable until it reconnects.", "Reboot", true]
};

$("nodes").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-node-action]");
  if (!btn) return;
  const action = btn.dataset.nodeAction;
  const id = btn.dataset.node;
  const meta = NODE_ACTIONS[action];
  if (!meta) return;
  if (!(await confirmAction(meta[0], meta[1].replace("{id}", id), meta[2], meta[3]))) return;
  btn.setAttribute("aria-busy", "true");
  try {
    await post("/api/nodes/" + encodeURIComponent(id) + "/" + action);
    toast(meta[2] + " requested for " + id, "ok");
    refresh(true);
  } catch (err) {
    toast(meta[2] + " failed: " + err.message, "err");
  } finally {
    btn.removeAttribute("aria-busy");
  }
});

const shortImage = (img) => {
  if (!img) return '<span class="subtle">—</span>';
  const at = img.indexOf("@");
  const name = at >= 0 ? img.slice(0, at) : img;
  const repo = name.split("/").pop();
  const digest = at >= 0 ? img.slice(at + 1).replace("sha256:", "").slice(0, 8) : "";
  return '<span class="digest" title="' + esc(img) + '">' + esc(repo) + (digest ? "<i>@</i>" + esc(digest) : "") + "</span>";
};

const PRIORITY_BADGE = { high: "info", normal: "", low: "" };

const renderServices = () => {
  const st = state.status;
  const tops = topByNode();
  const nodes = st?.nodes ?? [];
  const snaps = nodes.filter((n) => inRegion(n.region)).map((n) => tops.get(n.id)?.edge).filter(Boolean);
  const services = (st?.services ?? [])
    .filter((s) => state.region === "all" || (s.regions ?? []).includes(state.region))
    .sort((a, b) => a.name.localeCompare(b.name));
  $("services-hint").textContent = services.length ? services.length + " services" : "";
  if (!services.length) {
    $("services").innerHTML = '<tr><td colspan="7" class="none">' + (st ? "No services in this view" : "Waiting for backplane…") + "</td></tr>";
    return;
  }
  const placements = st?.placements ?? [];
  $("services").innerHTML = services.map((s) => {
    const regions = [...(s.regions ?? [])].filter(inRegion).sort((a, b) => regionRank(a) - regionRank(b));
    const dist = regions.map((r) => {
      const ps = placements.filter((p) => p.serviceName === s.name && p.region === r && p.state !== "stopped");
      const ready = ps.filter((p) => p.state === "ready").length;
      return '<span class="' + (ps.length && ready === ps.length ? "ok" : "warn") + '" title="' + esc(r + ": " + ready + " ready of " + ps.length) + '">' + esc(r) + " " + ready + "/" + ps.length + "</span>";
    }).join("");
    const ready = state.region === "all" ? s.ready : placements.filter((p) => p.serviceName === s.name && p.region === state.region && p.state === "ready").length;
    const desired = state.region === "all" ? s.desired : placements.filter((p) => p.serviceName === s.name && p.region === state.region && p.state !== "stopped").length;
    const e = edgeAgg(snaps, s.name);
    return "<tr>" +
      '<td class="idcell"><b>' + esc(s.name) + "</b></td>" +
      '<td><span class="badge">' + esc(s.mode) + "</span></td>" +
      '<td><span class="badge ' + (PRIORITY_BADGE[s.priority] ?? "") + '">' + esc(s.priority) + "</span></td>" +
      "<td>" + shortImage(s.image) + "</td>" +
      '<td><div style="display:flex;gap:8px;align-items:center"><b class="num" style="color:' + (ready >= desired ? "var(--ok)" : "var(--warn)") + '">' + esc(ready) + '</b><span class="subtle num">/ ' + esc(desired) + '</span><span class="dist">' + dist + "</span></div></td>" +
      '<td class="r num">' + esc(fmtMs(e.p95)) + "</td>" +
      '<td class="r num">' + (num(e.err) && e.err >= 1 ? '<span class="badge err">' + esc(fmtPct(e.err)) + "</span>" : esc(fmtPct(e.err))) + "</td>" +
      "</tr>";
  }).join("");
};

const PHASE_BADGE = { pending: ["", "Pending"], canary: ["info", "Canary"], baking: ["info", "Canary bake"], waves: ["info", "Waves"], succeeded: ["ok", "Succeeded"], rolled_back: ["err", "Rolled back"], failed: ["err", "Failed"] };

const rolloutCard = (r, active) => {
  const pb = PHASE_BADGE[r.phase] ?? ["", r.phase];
  const svc = (state.status?.services ?? []).find((s) => s.name === r.serviceName);
  const order = REGION_ORDER.filter((x) => !svc || (svc.regions ?? []).includes(x) || x === r.currentRegion);
  const extra = (svc?.regions ?? []).filter((x) => !order.includes(x));
  const waves = [...order, ...extra].filter((x) => !r.region || x === r.region);
  const curIdx = r.currentRegion ? waves.indexOf(r.currentRegion) : -1;
  const finished = r.phase === "succeeded";
  const waveHtml = waves.map((w, i) => {
    const cls = finished || (curIdx >= 0 && i < curIdx) ? "done" : i === curIdx && active ? "active" : "";
    const label = cls === "done" ? "done" : cls === "active" ? (r.phase === "canary" || r.phase === "baking" ? "canary" : "rolling") : "queued";
    return '<div class="wave ' + cls + '"><div class="wbar"></div><div class="wl"><b>' + esc(w) + "</b><span>" + esc(label) + "</span></div></div>";
  }).join("");
  let bake = "";
  const canaryAt = ms(r.canaryStartedAt);
  if (active && canaryAt && (r.phase === "canary" || r.phase === "baking")) {
    const left = Math.max(0, BAKE_MS - (Date.now() - canaryAt));
    const pct = clamp(((BAKE_MS - left) / BAKE_MS) * 100, 0, 100);
    bake = '<div class="bake"><div class="bake-top"><span class="muted">Canary bake' + (r.currentRegion ? " · " + esc(r.currentRegion) : "") + '</span><b data-bake="' + canaryAt + '">' + (left > 0 ? Math.ceil(left / 1000) + "s left" : "evaluating…") + "</b></div>" +
      '<div class="track"><div class="fill" data-bake-bar="' + canaryAt + '" style="width:' + pct.toFixed(1) + '%"></div></div></div>';
  }
  let cmp = "";
  if (num(r.baselineP95Ms) || num(r.baseline5xxPct)) {
    const tops = topByNode();
    const snaps = (state.status?.nodes ?? []).filter((n) => !r.currentRegion || n.region === r.currentRegion).map((n) => tops.get(n.id)?.edge).filter(Boolean);
    const live = edgeAgg(snaps, r.serviceName);
    const badP95 = num(live.p95) && num(r.baselineP95Ms) && live.p95 > r.baselineP95Ms * 1.5;
    const bad5xx = num(live.err) && num(r.baseline5xxPct) && live.err > Math.max(r.baseline5xxPct * 2, r.baseline5xxPct + 1);
    cmp = '<div class="cmp"><span></span><span class="h">Baseline</span><span class="h">Canary</span>' +
      '<span class="muted">p95</span><b>' + esc(fmtMs(r.baselineP95Ms)) + "</b><b" + (badP95 ? ' class="bad"' : "") + ">" + esc(fmtMs(live.p95)) + "</b>" +
      '<span class="muted">5xx</span><b>' + esc(fmtPct(r.baseline5xxPct)) + "</b><b" + (bad5xx ? ' class="bad"' : "") + ">" + esc(fmtPct(live.err)) + "</b></div>";
  }
  const when = active ? "started " + ago(ms(r.startedAt)) : r.finishedAt ? "finished " + ago(ms(r.finishedAt)) : "started " + ago(ms(r.startedAt));
  return '<article class="card rollout' + (active ? " active" : "") + '">' +
    '<div class="rollout-head"><div><h3>' + esc(r.serviceName) + '</h3><p>' + shortImage(r.targetImage) + (r.previousImage ? ' <span class="subtle">from</span> ' + shortImage(r.previousImage) : "") + "</p>" +
    '<p>wave ' + esc(r.currentWave ?? 0) + " / " + esc(r.totalWaves ?? waves.length) + " · " + esc(when) + "</p></div>" +
    '<span class="badge ' + pb[0] + '">' + esc(pb[1]) + "</span></div>" +
    '<div class="waves">' + waveHtml + "</div>" + bake + cmp +
    (r.error ? '<div class="banner show">' + esc(r.error) + "</div>" : "") +
    (active ? '<div style="display:flex;justify-content:flex-end"><button type="button" class="btn danger" data-rollback="' + esc(r.serviceName) + '" data-region="' + esc(r.region ?? "") + '">' + icon("undo") + "Rollback</button></div>" : "") +
    "</article>";
};

const renderRollouts = () => {
  const all = [...(state.status?.rollouts ?? [])].filter((r) => state.region === "all" || !r.region || r.region === state.region);
  const active = all.filter((r) => ACTIVE_PHASES.has(r.phase)).sort((a, b) => ms(b.startedAt) - ms(a.startedAt));
  const recent = all.filter((r) => !ACTIVE_PHASES.has(r.phase)).sort((a, b) => ms(b.finishedAt ?? b.startedAt) - ms(a.finishedAt ?? a.startedAt)).slice(0, 2);
  $("rollouts-hint").textContent = active.length ? active.length + " active" : "";
  let html = active.map((r) => rolloutCard(r, true)).join("");
  if (!active.length) html += '<div class="card none">No active rollout · deploy with <span class="mono">ts-orch deploy</span></div>';
  html += recent.map((r) => rolloutCard(r, false)).join("");
  $("rollouts").innerHTML = html;
};

$("rollouts").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-rollback]");
  if (!btn) return;
  const service = btn.dataset.rollback;
  const region = btn.dataset.region;
  if (!(await confirmAction("Roll back " + service, "Immediately restore the previous image digest" + (region ? " in " + region : " in every region") + " and abort the current rollout.", "Rollback", true))) return;
  btn.setAttribute("aria-busy", "true");
  try {
    await post("/api/rollback", region ? { service, region } : { service });
    toast("Rollback started for " + service, "ok");
    refresh(true);
  } catch (err) {
    toast("Rollback failed: " + err.message, "err");
  } finally {
    btn.removeAttribute("aria-busy");
  }
});

const tickBake = () => {
  document.querySelectorAll("[data-bake]").forEach((el) => {
    const left = Math.max(0, BAKE_MS - (Date.now() - Number(el.dataset.bake)));
    el.textContent = left > 0 ? Math.ceil(left / 1000) + "s left" : "evaluating…";
  });
  document.querySelectorAll("[data-bake-bar]").forEach((el) => {
    const left = Math.max(0, BAKE_MS - (Date.now() - Number(el.dataset.bakeBar)));
    el.style.width = clamp(((BAKE_MS - left) / BAKE_MS) * 100, 0, 100).toFixed(1) + "%";
  });
  if (state.lastUpdated) $("updated").textContent = "· " + clock(state.lastUpdated);
};
setInterval(tickBake, 1000);

$("event-filters").innerHTML = EVENT_GROUPS.map(([key, label]) => '<button type="button" data-egroup="' + key + '" aria-pressed="' + (key === "all") + '">' + esc(label) + "</button>").join("");
$("event-filters").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-egroup]");
  if (!btn) return;
  state.eventGroup = btn.dataset.egroup;
  $("event-filters").querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b === btn)));
  renderEvents();
});
$("event-search").addEventListener("input", (e) => {
  state.eventQuery = e.target.value.trim().toLowerCase();
  renderEvents();
});

const renderEvents = () => {
  const group = EVENT_GROUPS.find((g) => g[0] === state.eventGroup);
  const kinds = group?.[2] ? new Set(group[2]) : null;
  const q = state.eventQuery;
  const list = [...state.events]
    .filter((ev) => !kinds || kinds.has(ev.kind))
    .filter((ev) => state.region === "all" || !ev.region || ev.region === state.region)
    .filter((ev) => !q || (ev.subject + " " + ev.kind + " " + Object.entries(ev.detail ?? {}).map(([k, v]) => k + "=" + v).join(" ")).toLowerCase().includes(q))
    .sort((a, b) => ms(b.ts) - ms(a.ts) || (b.id ?? 0) - (a.id ?? 0))
    .slice(0, 150);
  $("events-hint").textContent = state.events.length ? list.length + " of " + state.events.length : "";
  if (!list.length) {
    $("events").innerHTML = '<div class="none">' + (state.events.length ? "No events match this filter" : "No events yet") + "</div>";
    return;
  }
  $("events").innerHTML = list.map((ev) => {
    const meta = EVENT_META[ev.kind] ?? [ev.kind, "info", "bolt"];
    const t = ms(ev.ts);
    const kv = Object.entries(ev.detail ?? {}).slice(0, 4).map(([k, v]) => '<span class="kv">' + esc(k) + "=" + esc(String(v).length > 40 ? String(v).slice(0, 40) + "…" : v) + "</span>").join("");
    return '<div class="ev">' +
      '<span class="when" title="' + esc(new Date(t).toLocaleString()) + '">' + esc(ago(t)) + "</span>" +
      '<span class="ic ' + meta[1] + '">' + icon(meta[2]) + "</span>" +
      '<span class="kind">' + esc(meta[0]) + "</span>" +
      '<span class="rg">' + esc(ev.region ?? "global") + "</span>" +
      '<span class="what"><b>' + esc(ev.subject) + "</b>" + kv + "</span>" +
      "</div>";
  }).join("");
};

const renderRegionPills = () => {
  const extra = (state.status?.regions ?? []).map((r) => r.label).filter((r) => !REGION_ORDER.includes(r));
  const list = ["all", ...REGION_ORDER, ...extra];
  const host = $("region-pills");
  const key = list.join(",");
  if (host.dataset.key !== key) {
    host.dataset.key = key;
    host.innerHTML = list.map((r) => '<button type="button" data-region="' + esc(r) + '" aria-pressed="false"' + (r === "all" ? "" : ' class="mono"') + ">" + esc(r === "all" ? "All" : r) + "</button>").join("");
  }
  host.querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.region === state.region)));
};
$("region-pills").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-region]");
  if (!btn) return;
  state.region = btn.dataset.region;
  try { localStorage.setItem("ts-orch-region", state.region); } catch {}
  renderAll();
});

document.querySelectorAll("[data-window]").forEach((b) => b.addEventListener("click", () => {
  state.window = b.dataset.window;
  document.querySelectorAll("[data-window]").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
  try { localStorage.setItem("ts-orch-window", state.window); } catch {}
  state.metrics = null;
  renderCharts();
  loadMetrics().then(renderCharts);
}));

const PLAY_ICON = '<path d="M7 5v14l12-7z"/>';
const PAUSE_ICON = '<rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/>';
$("pause").addEventListener("click", () => {
  state.paused = !state.paused;
  $("pause").setAttribute("aria-pressed", String(state.paused));
  $("pause-text").textContent = state.paused ? "Resume" : "Pause";
  $("pause-icon").innerHTML = state.paused ? PLAY_ICON : PAUSE_ICON;
  setConn();
  if (!state.paused) refresh(true);
});

let connState = "warn";
let connText = "Connecting…";
const setConn = (cls, text) => {
  if (cls) connState = cls;
  if (text) connText = text;
  $("conn-dot").className = "dot " + (state.paused ? "warn" : connState) + (state.paused ? "" : " pulse");
  $("conn-text").textContent = state.paused ? "Paused" : connText;
};

const showBanner = (text) => {
  $("banner-text").textContent = text ?? "";
  $("banner").classList.toggle("show", Boolean(text));
};

const loadMetrics = async () => {
  try {
    state.metrics = await getJson("/api/metrics?window=" + state.window);
    return true;
  } catch {
    return false;
  }
};

const renderAll = () => {
  renderRegionPills();
  renderRegions();
  renderCharts();
  renderNodes();
  renderServices();
  renderRollouts();
  renderEvents();
  renderChaosTargets();
};

const refresh = async (force) => {
  if (state.inflight) return;
  if (!force && (state.paused || document.hidden)) return;
  state.inflight = true;
  state.tick++;
  const wantMetrics = force || state.window === "1h" || state.tick % 6 === 1 || !state.metrics;
  const [status, top, events, metrics] = await Promise.allSettled([
    getJson("/api/status"),
    getJson("/api/top"),
    getJson("/api/events?limit=200"),
    wantMetrics ? loadMetrics() : Promise.resolve(true)
  ]);
  state.inflight = false;
  if (status.status === "fulfilled") state.status = status.value;
  if (top.status === "fulfilled") state.top = top.value;
  if (events.status === "fulfilled") state.events = Array.isArray(events.value) ? events.value : events.value?.events ?? [];
  const failed = [status, top, events].filter((r) => r.status === "rejected").length + (metrics.status === "fulfilled" && metrics.value === false ? 1 : 0);
  if (status.status === "rejected") {
    setConn("err", "Backplane unreachable");
    showBanner("Could not load /api/status: " + (status.reason?.message ?? "network error") + ". Retrying every 5 s.");
  } else {
    state.lastUpdated = Date.now();
    setConn(failed ? "warn" : "ok", failed ? "Partial data" : "Live");
    showBanner(null);
  }
  tickBake();
  renderAll();
};

const chaosNode = () => $("chaos-node").value;
const chaosService = () => $("chaos-service").value;
const CHAOS = {
  kill_node: () => ({ body: { kind: "kill_node", nodeId: chaosNode() }, label: "Killed " + chaosNode(), need: chaosNode() }),
  inject_5xx: () => ({ body: { kind: "inject_5xx", service: chaosService(), ratePct: 50, durationSeconds: 120 }, label: "Injecting 50% 5xx into " + chaosService() + " for 120 s", need: chaosService() }),
  cpu_load: () => ({ body: { kind: "cpu_load", nodeId: chaosNode(), cpuPct: 95, durationSeconds: 300 }, label: "CPU spike 95% on " + chaosNode() + " for 5 min", need: chaosNode() }),
  clear_load: () => ({ body: { kind: "cpu_load", nodeId: chaosNode(), cpuPct: 0, durationSeconds: 0 }, label: "Cleared synthetic load on " + chaosNode(), need: chaosNode() }),
  bump_secret: () => {
    const name = $("chaos-secret").value.trim();
    return { body: { kind: "bump_secret", secretName: name }, label: "Bumped Vault secret " + name, need: name };
  },
  fill_disk: () => ({ body: { kind: "fill_disk", nodeId: chaosNode(), usedPct: 80 }, label: "Simulating 80% disk on " + chaosNode(), need: chaosNode() }),
  atlas_roundtrip: () => ({ body: { kind: "atlas_roundtrip" }, label: "Atlas publish → resolve round-trip", need: "ok" })
};

const renderChaosTargets = () => {
  if (!state.me?.localDev) return;
  const fill = (sel, values) => {
    const key = values.join(",");
    if (sel.dataset.key === key) return;
    const prev = sel.value;
    sel.dataset.key = key;
    sel.innerHTML = values.map((v) => '<option value="' + esc(v) + '">' + esc(v) + "</option>").join("");
    if (values.includes(prev)) sel.value = prev;
  };
  fill($("chaos-node"), (state.status?.nodes ?? []).map((n) => n.id).sort());
  fill($("chaos-service"), (state.status?.services ?? []).map((s) => s.name).sort());
};

$("chaos").addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-chaos]");
  if (!btn) return;
  const make = CHAOS[btn.dataset.chaos];
  if (!make) return;
  const c = make();
  if (!c.need) {
    toast("Select a target first", "warn");
    return;
  }
  btn.setAttribute("aria-busy", "true");
  try {
    const res = await post("/api/dev/chaos", c.body);
    toast(c.label + (res?.message ? " · " + res.message : ""), "ok");
    refresh(true);
  } catch (err) {
    toast("Chaos failed: " + err.message, "err");
  } finally {
    btn.removeAttribute("aria-busy");
  }
});

$("logout").addEventListener("click", async () => {
  $("logout").setAttribute("aria-busy", "true");
  try {
    await fetch("/auth/logout", { method: "POST", credentials: "same-origin", redirect: "manual", headers: { "x-requested-with": "ts-orch-ui" } });
  } catch {}
  location.replace("/");
});

const gtip = $("gtip");
document.addEventListener("pointerover", (e) => {
  const el = e.target.closest?.("[data-tip]");
  if (!el) {
    gtip.hidden = true;
    return;
  }
  const parts = el.dataset.tip.split("|");
  gtip.innerHTML = '<div class="t">' + esc(parts[0]) + "</div>" + parts.slice(1).map((p) => {
    const i = p.indexOf(": ");
    return i < 0 ? '<div class="r"><span>' + esc(p) + "</span></div>" : '<div class="r"><span>' + esc(p.slice(0, i)) + "</span><b>" + esc(p.slice(i + 2)) + "</b></div>";
  }).join("");
  gtip.hidden = false;
});
document.addEventListener("pointermove", (e) => {
  if (gtip.hidden) return;
  const w = gtip.offsetWidth;
  const h = gtip.offsetHeight;
  const x = e.clientX + 14 + w > window.innerWidth ? e.clientX - 14 - w : e.clientX + 14;
  const y = e.clientY + 14 + h > window.innerHeight ? e.clientY - 14 - h : e.clientY + 14;
  gtip.style.left = Math.max(4, x) + "px";
  gtip.style.top = Math.max(4, y) + "px";
});

let resizeTimer = 0;
new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(renderCharts, 80);
}).observe($("ch-cpu"));

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh(false);
});

const boot = async () => {
  try { const r = localStorage.getItem("ts-orch-region"); if (r) state.region = r; } catch {}
  try {
    const w = localStorage.getItem("ts-orch-window");
    if (w === "1h" || w === "48h") state.window = w;
  } catch {}
  document.querySelectorAll("[data-window]").forEach((x) => x.setAttribute("aria-pressed", String(x.dataset.window === state.window)));
  renderAll();
  try {
    const me = await getJson("/api/me");
    const user = me.user ?? me;
    const login = user.login ?? user.name ?? me.owner;
    if (!login && me.authenticated === false) {
      sessionLost();
      return;
    }
    state.me = { ...me, login };
    $("user").hidden = false;
    $("user-login").textContent = login ?? "operator";
    const avatar = user.avatarUrl ?? user.avatar_url;
    if (avatar) {
      const img = document.createElement("img");
      img.alt = "";
      img.src = avatar;
      $("avatar").replaceChildren(img);
    } else {
      $("avatar").textContent = String(login ?? "?").slice(0, 2).toUpperCase();
    }
    if (me.localDev === true) {
      $("user-dev").hidden = false;
      $("chaos").hidden = false;
    }
  } catch (err) {
    if (err.message !== "unauthorized") setConn("err", "Backplane unreachable");
  }
  await refresh(true);
  setInterval(() => refresh(false), REFRESH_MS);
};
boot();
</script>
</body>
</html>
`;
