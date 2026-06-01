"use strict";
// JASniffer SPA — live capture grid + Fiddler-style request/response inspectors.
// Vanilla JS, no build step. Talks to the REST API and a SignalR hub.
(() => {
  const ROW_H = 26;

  const state = {
    sessions: new Map(),   // id -> summary
    ids: [],               // capture order
    filtered: [],          // ids passing the current filter
    selectedId: null,
    detail: null,
    reqTab: "headers",
    resTab: "headers",
    filter: { text: "", method: "", status: "", type: "" },
    methods: new Set(),
    types: new Set(),
    follow: true,
  };

  const $ = (s) => document.querySelector(s);
  const el = {
    gridScroll: $("#gridScroll"), gridRows: $("#gridRows"),
    reqBadges: $("#reqBadges"), resBadges: $("#resBadges"),
    reqBody: $("#reqBody"), resBody: $("#resBody"),
    reqTabs: $("#reqTabs"), resTabs: $("#resTabs"),
    counts: $("#counts"), connDot: $("#connDot"),
    filterText: $("#filterText"), filterMethod: $("#filterMethod"),
    filterStatus: $("#filterStatus"), filterType: $("#filterType"),
  };

  // ---- helpers -------------------------------------------------------------
  const escapeHtml = (s) => s == null ? "" : String(s).replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function formatBytes(n) {
    if (n == null) return "";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(2) + " KB";
    if (n < 1073741824) return (n / 1048576).toFixed(2) + " MB";
    return (n / 1073741824).toFixed(2) + " GB";
  }

  function statusClass(s) {
    if (s.error) return "serr";
    const g = Math.floor(s.status / 100);
    return g === 2 ? "s2" : g === 3 ? "s3" : g === 4 ? "s4" : g === 5 ? "s5" : "";
  }

  const shortType = (ct) => !ct ? "" : ct.split(";")[0].trim();
  const httpLabel = (v) => v && v.startsWith("2") ? "HTTP/2" : "HTTP/1.1";

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error(r.status + " " + r.statusText);
    const ct = r.headers.get("content-type") || "";
    return ct.includes("json") ? r.json() : r.text();
  }

  // ---- ingest / filter -----------------------------------------------------
  function upsert(s) {
    if (!state.sessions.has(s.id)) state.ids.push(s.id);
    state.sessions.set(s.id, s);
    if (s.method && !state.methods.has(s.method)) { state.methods.add(s.method); addOption(el.filterMethod, s.method); }
    const t = shortType(s.responseContentType);
    if (t && !state.types.has(t)) { state.types.add(t); addOption(el.filterType, t); }
  }

  function addOption(select, value) {
    const o = document.createElement("option");
    o.value = value; o.textContent = value;
    select.appendChild(o);
  }

  function matches(s) {
    const f = state.filter;
    if (f.method && s.method !== f.method) return false;
    if (f.status && Math.floor(s.status / 100) !== +f.status) return false;
    if (f.type && shortType(s.responseContentType) !== f.type) return false;
    if (f.text) {
      const hay = (s.url + " " + s.method + " " + s.status + " " + (s.host || "") + " " + (s.responseContentType || "")).toLowerCase();
      if (!hay.includes(f.text)) return false;
    }
    return true;
  }

  function applyFilter() {
    state.filtered = state.ids.filter((id) => matches(state.sessions.get(id)));
  }

  // ---- virtualized grid ----------------------------------------------------
  let renderQueued = false;
  function scheduleRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      const follow = isAtBottom();
      applyFilter();
      el.gridRows.style.height = (state.filtered.length * ROW_H) + "px";
      if (follow) el.gridScroll.scrollTop = el.gridScroll.scrollHeight;
      renderVisible();
      updateCounts();
    });
  }

  const isAtBottom = () =>
    el.gridScroll.scrollTop + el.gridScroll.clientHeight >= el.gridRows.offsetHeight - ROW_H * 3;

  function renderVisible() {
    const total = state.filtered.length;
    const top = el.gridScroll.scrollTop;
    const h = el.gridScroll.clientHeight;
    const start = Math.max(0, Math.floor(top / ROW_H) - 8);
    const end = Math.min(total, Math.ceil((top + h) / ROW_H) + 8);
    let html = "";
    for (let i = start; i < end; i++) html += rowHtml(state.sessions.get(state.filtered[i]), i);
    el.gridRows.innerHTML = html;
  }

  function rowHtml(s, i) {
    const special = s.wasTunneled || s.isUdp;
    const cls = (s.id === state.selectedId ? " sel" : "") + (s.completed || special ? "" : " pending") + (s.wasTunneled ? " tunneled" : "") + (s.isUdp ? " udp" : "");
    const res = s.isUdp ? "UDP" : s.wasTunneled ? "TUN" : s.error ? "ERR" : (s.status || "…");
    const resCls = s.isUdp ? "s-udp" : s.wasTunneled ? "" : statusClass(s);
    const proto = s.isUdp ? s.scheme : s.wasTunneled ? "tunnel" : (s.scheme + (s.responseHttpVersion ? " " + (s.responseHttpVersion.startsWith("2") ? "h2" : "h1") : ""));
    const size = special ? formatBytes(s.tunnelBytesUp + s.tunnelBytesDown) : formatBytes(s.bodyLength);
    return `<div class="grid-row${cls}" data-id="${s.id}" style="top:${i * ROW_H}px">
      <div class="col col-id">${s.id}</div>
      <div class="col col-res ${resCls}">${res}</div>
      <div class="col col-proto">${escapeHtml(proto)}</div>
      <div class="col col-method"><span class="method-badge">${escapeHtml(s.method)}</span></div>
      <div class="col col-host" title="${escapeHtml(s.host)}">${escapeHtml(s.host)}</div>
      <div class="col col-url" title="${escapeHtml(s.url)}">${escapeHtml(s.path + s.query)}</div>
      <div class="col col-type">${escapeHtml(shortType(s.responseContentType))}</div>
      <div class="col col-size">${size}</div>
      <div class="col col-time">${s.completed ? Math.round(s.durationMs) + "ms" : ""}</div>
    </div>`;
  }

  function updateCounts() {
    el.counts.textContent = `${state.filtered.length} of ${state.ids.length} sessions`;
  }

  // ---- selection + inspectors ---------------------------------------------
  async function selectSession(id) {
    state.selectedId = id;
    renderVisible();
    try {
      state.detail = await api(`/api/sessions/${id}`);
      renderInspectors();
    } catch {
      el.reqBody.innerHTML = el.resBody.innerHTML = `<div class="empty">Session no longer available.</div>`;
    }
  }

  function renderInspectors() {
    const d = state.detail;
    if (!d) return;
    const s = d.summary;

    el.reqBadges.innerHTML =
      `<span class="badge b-blue">${escapeHtml(s.method)}</span>` +
      `<span class="badge b-muted">HTTP/${escapeHtml(s.requestHttpVersion)}</span>`;

    const statusBadge = s.wasTunneled
      ? `<span class="badge b-muted">TUNNELED</span>`
      : s.error
        ? `<span class="badge b-red">ERROR</span>`
        : `<span class="badge ${badgeColor(s.status)}">${s.status} ${escapeHtml(s.reason || "")}</span>`;
    el.resBadges.innerHTML = statusBadge +
      (s.wasTunneled ? "" : `<span class="badge b-muted">${httpLabel(s.responseHttpVersion)}</span>`) +
      (s.wasTunneled ? "" : `<span class="badge b-muted">BODY: ${formatBytes(s.bodyLength)}</span>`) +
      (d.tlsSummary ? `<span class="badge b-green" title="Derived from the active preset; the upstream TLS version is not surfaced">${escapeHtml(d.tlsSummary)}</span>` : "") +
      (s.followedRedirects && s.finalUrl && s.finalUrl !== s.url ? `<span class="badge b-blue" title="${escapeHtml(s.finalUrl)}">→ redirected</span>` : "");

    setCount(el.reqTabs, "headers", d.requestHeaders.length);
    setCount(el.reqTabs, "params", d.queryParams.length);
    setCount(el.reqTabs, "cookies", d.requestCookies.length);
    setCount(el.resTabs, "headers", d.responseHeaders.length);
    setCount(el.resTabs, "cookies", d.responseCookies.length);

    renderReqTab(state.reqTab);
    renderResTab(state.resTab);
  }

  const badgeColor = (st) => {
    const g = Math.floor(st / 100);
    return g === 2 ? "b-green" : g === 3 ? "b-blue" : g === 4 ? "b-orange" : g === 5 ? "b-red" : "b-muted";
  };

  function setCount(tabs, name, n) {
    const btn = tabs.querySelector(`[data-tab="${name}"]`);
    if (btn) btn.textContent = btn.dataset.label + (n ? ` (${n})` : "");
  }

  function renderReqTab(tab) {
    state.reqTab = tab;
    const d = state.detail; if (!d) return;
    let html;
    switch (tab) {
      case "headers": html = kvTable(d.requestHeaders.map((h) => [h.name, h.value]), true); break;
      case "params": html = d.queryParams.length ? kvTable(d.queryParams.map((p) => [p.name, p.value])) : note("No query parameters."); break;
      case "cookies": html = d.requestCookies.length ? kvTable(d.requestCookies.map((c) => [c.name, c.value])) : note("No request cookies."); break;
      case "auth": html = renderAuth(d); break;
      case "raw": html = `<pre class="raw">${escapeHtml(buildRaw(d, false))}</pre>`; break;
      case "body": html = renderBody(d.requestBody, d.summary.id, "request"); break;
    }
    el.reqBody.innerHTML = html;
    afterRender(el.reqBody, d.summary.id, "request");
    activate(el.reqTabs, tab);
  }

  function renderResTab(tab) {
    state.resTab = tab;
    const d = state.detail; if (!d) return;
    let html;
    switch (tab) {
      case "headers": html = kvTable(d.responseHeaders.map((h) => [h.name, h.value]), true); break;
      case "cookies": html = renderResCookies(d); break;
      case "raw": html = `<pre class="raw">${escapeHtml(buildRaw(d, true))}</pre>`; break;
      case "preview": html = renderPreview(d); break;
      case "body": html = renderBody(d.responseBody, d.summary.id, "response"); break;
    }
    el.resBody.innerHTML = html;
    afterRender(el.resBody, d.summary.id, "response");
    activate(el.resTabs, tab);
  }

  const activate = (tabs, tab) =>
    tabs.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));

  const note = (t) => `<div class="note">${escapeHtml(t)}</div>`;

  function kvTable(pairs, withFilter) {
    if (!pairs.length) return note("Nothing here.");
    const rows = pairs.map(([k, v]) =>
      `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(v)}</td></tr>`).join("");
    const filter = withFilter ? `<input class="kv-filter" id="kvFilter" placeholder="Filter headers…" />` : "";
    return filter + `<table class="kv">${rows}</table>`;
  }

  function renderAuth(d) {
    const a = d.auth;
    if (!a) return note("No Authorization header.");
    let rows = `<tr><td class="k">Scheme</td><td class="v">${escapeHtml(a.scheme)}</td></tr>`;
    if (a.username != null) rows += `<tr><td class="k">Username</td><td class="v">${escapeHtml(a.username)}</td></tr>`;
    if (a.password != null) rows += `<tr><td class="k">Password</td><td class="v">${escapeHtml(a.password)}</td></tr>`;
    if (a.token != null) rows += `<tr><td class="k">Token</td><td class="v">${escapeHtml(a.token)}</td></tr>`;
    return `<table class="kv">${rows}</table>`;
  }

  function renderResCookies(d) {
    if (!d.responseCookies.length) return note("No Set-Cookie headers.");
    const rows = d.responseCookies.map((c) => {
      const attrs = [c.domain && "domain=" + c.domain, c.path && "path=" + c.path, c.expires && "expires=" + c.expires,
        c.maxAge && "max-age=" + c.maxAge, c.secure && "Secure", c.httpOnly && "HttpOnly", c.sameSite && "SameSite=" + c.sameSite]
        .filter(Boolean).join(" · ");
      return `<tr><td class="k">${escapeHtml(c.name)}</td><td class="v">${escapeHtml(c.value)}<div class="muted">${escapeHtml(attrs)}</div></td></tr>`;
    }).join("");
    return `<table class="kv">${rows}</table>`;
  }

  function buildRaw(d, isResponse) {
    const s = d.summary;
    let raw;
    if (isResponse) {
      raw = `${httpLabel(s.responseHttpVersion)} ${s.status} ${s.reason || ""}\n`;
      for (const h of d.responseHeaders) raw += `${h.name}: ${h.value}\n`;
      raw += "\n";
      const b = d.responseBody;
      raw += bodyForRaw(b);
    } else {
      raw = `${s.method} ${s.path}${s.query} HTTP/${s.requestHttpVersion}\n`;
      if (!d.requestHeaders.some((h) => h.name.toLowerCase() === "host")) raw += `Host: ${s.host}\n`;
      for (const h of d.requestHeaders) raw += `${h.name}: ${h.value}\n`;
      raw += "\n";
      raw += bodyForRaw(d.requestBody);
    }
    return raw;
  }

  const bodyForRaw = (b) =>
    !b || b.size === 0 ? "" : (b.isText && b.text != null ? b.text : `[${b.kind} body · ${formatBytes(b.size)}]`);

  function renderPreview(d) {
    const b = d.responseBody, id = d.summary.id;
    if (d.summary.wasTunneled) return note("Tunneled session — not inspected.");
    if (!b || b.size === 0) return note("No response body.");
    if (b.kind === "image") return `<img class="preview-img" src="/api/sessions/${id}/response-body" alt="response image" />`;
    if (b.kind === "html") return `<iframe class="preview-frame" sandbox="" src="/api/sessions/${id}/response-body"></iframe>`;
    if (b.kind === "json" && b.text != null) return `<pre class="raw">${jsonHighlight(b.text)}</pre>`;
    if (b.isText && b.text != null) return `<pre class="raw">${escapeHtml(b.text)}</pre>`;
    return `<div class="note">Binary ${escapeHtml(b.kind)} · ${formatBytes(b.size)} · <span class="dl" data-dl="response" data-id="${id}">download</span></div><div class="hexdump" data-hex="response" data-id="${id}">loading…</div>`;
  }

  function renderBody(b, id, dir) {
    if (!b || b.size === 0) return note("No body.");
    const head = `<div class="section-label">${escapeHtml(b.kind)} · ${formatBytes(b.size)}${b.truncated ? " · truncated" : ""} · <span class="dl" data-dl="${dir}" data-id="${id}">download</span></div>`;
    if (b.isText && b.text != null) return head + `<pre class="raw">${escapeHtml(b.text)}</pre>`;
    return head + `<div class="hexdump" data-hex="${dir}" data-id="${id}">loading…</div>`;
  }

  function afterRender(container, id, dir) {
    const filter = container.querySelector("#kvFilter");
    if (filter) {
      filter.addEventListener("input", () => {
        const q = filter.value.toLowerCase();
        container.querySelectorAll(".kv tr").forEach((tr) =>
          tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none");
      });
    }
    container.querySelectorAll("[data-dl]").forEach((n) =>
      n.addEventListener("click", () => window.open(`/api/sessions/${n.dataset.id}/${n.dataset.dl}-body?download=1`, "_blank")));
    container.querySelectorAll("[data-hex]").forEach((n) => loadHex(n));
  }

  async function loadHex(node) {
    try {
      const r = await fetch(`/api/sessions/${node.dataset.id}/${node.dataset.hex}-body`);
      const buf = new Uint8Array(await r.arrayBuffer());
      node.textContent = hexDump(buf, 4096);
    } catch { node.textContent = "(unable to load body)"; }
  }

  function hexDump(bytes, max) {
    const n = Math.min(bytes.length, max);
    let out = "";
    for (let i = 0; i < n; i += 16) {
      let hex = "", ascii = "";
      for (let j = 0; j < 16; j++) {
        if (i + j < n) {
          const b = bytes[i + j];
          hex += b.toString(16).padStart(2, "0") + " ";
          ascii += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
        } else hex += "   ";
      }
      out += i.toString(16).padStart(8, "0") + "  " + hex + " " + ascii + "\n";
    }
    if (bytes.length > max) out += `… ${formatBytes(bytes.length - max)} more\n`;
    return out;
  }

  function jsonHighlight(text) {
    let pretty = text;
    try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch { return escapeHtml(text); }
    return escapeHtml(pretty).replace(
      /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
      (m) => {
        let cls = "json-num";
        if (/^"/.test(m)) cls = /:$/.test(m) ? "json-key" : "json-str";
        else if (/true|false/.test(m)) cls = "json-bool";
        else if (/null/.test(m)) cls = "json-null";
        return `<span class="${cls}">${m}</span>`;
      });
  }

  // ---- toolbar / settings --------------------------------------------------
  function wireUi() {
    el.gridRows.addEventListener("click", (e) => {
      const row = e.target.closest(".grid-row");
      if (row) selectSession(+row.dataset.id);
    });
    el.gridScroll.addEventListener("scroll", () => renderVisible());

    el.reqTabs.addEventListener("click", (e) => { if (e.target.dataset.tab) renderReqTab(e.target.dataset.tab); });
    el.resTabs.addEventListener("click", (e) => { if (e.target.dataset.tab) renderResTab(e.target.dataset.tab); });
    el.reqTabs.querySelectorAll(".tab").forEach((b) => b.dataset.label = b.textContent);
    el.resTabs.querySelectorAll(".tab").forEach((b) => b.dataset.label = b.textContent);

    $("#btnClear").addEventListener("click", () => api("/api/clear", { method: "POST" }));
    $("#btnExport").addEventListener("click", () => {
      const filtered = state.filtered.length !== state.ids.length;
      window.open("/api/export.saz" + (filtered ? "?ids=" + state.filtered.join(",") : ""), "_blank");
    });
    $("#btnCa").addEventListener("click", () => window.open("/api/ca.cer", "_blank"));
    $("#hintDownloadCa").addEventListener("click", () => window.open("/api/ca.cer", "_blank"));
    const installCa = async () => {
      try {
        const r = await api("/api/install-ca", { method: "POST" });
        alert(r.message || (r.ok ? "CA установлен." : "Не удалось установить CA."));
      } catch { alert("Не удалось обратиться к эндпоинту установки CA."); }
    };
    $("#btnInstallCa").addEventListener("click", installCa);
    $("#hintInstallCa").addEventListener("click", installCa);
    $("#hintClose").addEventListener("click", () => { $("#caHint").classList.add("hidden"); localStorage.setItem("ca-dismissed", "1"); });

    $("#tglRedirects").addEventListener("change", saveSettings);
    $("#tglCapture").addEventListener("change", saveSettings);
    $("#modeManual").addEventListener("click", () => applyMode("manual"));
    $("#modeSystem").addEventListener("click", () => applyMode("system"));
    $("#tglUdp").addEventListener("change", async (e) => {
      try {
        const r = await api("/api/udp-capture", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: e.target.checked }) });
        if (e.target.checked && !r.running) {
          e.target.checked = false;
          alert(r.error || (r.supported ? "Could not start UDP capture." : "UDP capture needs Windows + admin + WinDivert.dll next to the app."));
        }
      } catch { e.target.checked = false; }
    });

    el.filterText.addEventListener("input", () => { state.filter.text = el.filterText.value.toLowerCase(); scheduleRender(); });
    el.filterMethod.addEventListener("change", () => { state.filter.method = el.filterMethod.value; scheduleRender(); });
    el.filterStatus.addEventListener("change", () => { state.filter.status = el.filterStatus.value; scheduleRender(); });
    el.filterType.addEventListener("change", () => { state.filter.type = el.filterType.value; scheduleRender(); });

    initDividers();
  }

  async function saveSettings() {
    const dto = {
      smartRedirects: $("#tglRedirects").checked,
      maxRedirects: 10,
      capture: $("#tglCapture").checked,
      upstreamProxy: null,
    };
    await api("/api/settings", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(dto) });
  }

  function initDividers() {
    drag($("#divider"), (dx, startW) => {
      const w = Math.min(window.innerWidth - 380, Math.max(320, startW + dx));
      $("#gridPane").style.width = w + "px";
      renderVisible();
    }, () => $("#gridPane").offsetWidth, "x");
    drag($("#inspectDivider"), (dy, startH) => {
      const h = Math.max(120, startH + dy);
      document.querySelector(".inspect.req").style.flex = `0 0 ${h}px`;
    }, () => document.querySelector(".inspect.req").offsetHeight, "y");
  }

  function drag(handle, onMove, getStart, axis) {
    handle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const start = axis === "x" ? e.clientX : e.clientY;
      const startVal = getStart();
      const move = (ev) => onMove((axis === "x" ? ev.clientX : ev.clientY) - start, startVal);
      const up = () => { document.removeEventListener("mousemove", move); document.removeEventListener("mouseup", up); };
      document.addEventListener("mousemove", move);
      document.addEventListener("mouseup", up);
    });
  }

  // ---- bootstrap -----------------------------------------------------------
  function setDot(on) { el.connDot.className = "dot " + (on ? "dot-on" : "dot-off"); }

  function connectHub() {
    const conn = new signalR.HubConnectionBuilder().withUrl("/hub/sessions").withAutomaticReconnect().build();
    conn.on("sessions", (batch) => { for (const s of batch) upsert(s); if (state.detail && batch.some((b) => b.id === state.detail.summary.id)) { /* keep open */ } scheduleRender(); });
    conn.on("cleared", () => {
      state.sessions.clear(); state.ids = []; state.filtered = []; state.selectedId = null; state.detail = null;
      el.reqBody.innerHTML = el.resBody.innerHTML = `<div class="empty">Select a session to inspect.</div>`;
      el.reqBadges.innerHTML = el.resBadges.innerHTML = "";
      scheduleRender();
    });
    conn.onreconnected(() => setDot(true));
    conn.onclose(() => setDot(false));
    conn.start().then(() => setDot(true)).catch(() => { setDot(false); setTimeout(connectHub, 2000); });
  }

  function setActiveMode(mode) {
    $("#modeSystem").classList.toggle("active", mode === "system");
    $("#modeManual").classList.toggle("active", mode !== "system");
  }

  async function applyMode(mode) {
    if (mode === "system" && !state.systemProxySupported) {
      alert("Режим System (системный прокси) доступен только на Windows. Здесь используйте Manual и направьте приложение/браузер на 127.0.0.1:" + (state.proxyPort || 8866) + ".");
      return;
    }
    try {
      const r = await api("/api/system-proxy", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ enabled: mode === "system" }) });
      setActiveMode(r.enabled ? "system" : "manual");
      if (mode === "system" && !r.enabled) alert("Не удалось включить системный прокси.");
    } catch { /* ignore */ }
  }

  async function loadStatus() {
    try {
      const st = await api("/api/status");
      state.proxyPort = st.proxyPort;
      state.systemProxySupported = st.systemProxySupported;
      $("#hintPort").textContent = st.proxyPort;
      $("#caStore").textContent = "CA: " + st.caSubject + "  ·  stored in " + st.caStoreDirectory;
      $("#modeHint").textContent = "→ 127.0.0.1:" + st.proxyPort;
      setActiveMode(st.systemProxyEnabled ? "system" : "manual");
      if (!st.systemProxySupported) $("#modeSystem").classList.add("disabled");
      const udp = $("#tglUdp");
      udp.checked = !!st.udpRunning;
      if (!st.udpSupported) { udp.disabled = true; udp.parentElement.title = "UDP-захват (WinDivert) доступен только на Windows."; }
      if (!localStorage.getItem("ca-dismissed")) $("#caHint").classList.remove("hidden");
    } catch { /* status is best-effort */ }
  }

  async function loadSettings() {
    try {
      const s = await api("/api/settings");
      $("#tglRedirects").checked = s.smartRedirects;
      $("#tglCapture").checked = s.capture;
    } catch { /* ignore */ }
  }

  async function loadSessions() {
    try {
      const list = await api("/api/sessions");
      for (const s of list) upsert(s);
      scheduleRender();
    } catch { /* ignore */ }
  }

  wireUi();
  loadStatus();
  loadSettings();
  loadSessions();
  connectHub();
})();
