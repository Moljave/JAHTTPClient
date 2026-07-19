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
    filter: { text: "", method: "", status: "", type: "", host: "" },
    hiddenHosts: new Set(),
    methods: new Set(),
    types: new Set(),
    follow: true,
    maxRedirects: 10,      // restored from /settings; preserved across saves
    fingerprints: [],      // captured fingerprints saved to the selection list
    lastCapture: null,     // { ja3, ja3Md5 } from the most recent self-test
    fpScan: null,          // { preset -> Ja3Report } from the last full device scan (for the Info tab)
    // Applied (committed) proxy + fingerprint — edited in the fields, committed via Apply.
    // Auto-saved toggles use these so a half-typed proxy/preset is never applied by accident.
    appliedProxy: "",
    appliedRotating: false,
    appliedPreset: "Chrome",
    // Resender
    rsDetail: null,        // last response detail shown in the Resender
    rsResTab: "headers",
    rsHistory: [],         // [{ id, method, status }]
    rsRawHeaders: false,
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
    jumpLatest: $("#jumpLatest"), capturePill: $("#capturePill"),
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

  const pad2 = (n) => String(n).padStart(2, "0");
  // Wall-clock start time HH:MM:SS for the grid; full local date/time for tooltips.
  function clockTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime()) ? "" : `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }
  function fullTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return isNaN(d.getTime()) ? "" : d.toLocaleString();
  }

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (!r.ok) throw new Error(r.status + " " + r.statusText);
    const ct = r.headers.get("content-type") || "";
    return ct.includes("json") ? r.json() : r.text();
  }

  const getJson = (path) => api(path);
  const postJson = (path, body) =>
    api(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch {
      try {
        const ta = document.createElement("textarea");
        ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select(); document.execCommand("copy"); ta.remove();
        return true;
      } catch { return false; }
    }
  }

  let toastTimer;
  function flash(msg) {
    const t = $("#toast");
    t.textContent = msg; t.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.add("hidden"), 1600);
  }

  // Reproduces the request as a direct curl command (single-quote escaped).
  function buildCurl(d) {
    const s = d.summary;
    const q = (v) => "'" + String(v).replace(/'/g, "'\\''") + "'";
    let c = "curl " + q(s.url);
    if (s.method && s.method !== "GET") c += " -X " + s.method;
    for (const h of d.requestHeaders) {
      if (h.name.toLowerCase() === "content-length") continue; // curl recomputes
      c += " \\\n  -H " + q(h.name + ": " + h.value);
    }
    if (d.requestBody && d.requestBody.isText && d.requestBody.text) c += " \\\n  --data-raw " + q(d.requestBody.text);
    return c;
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
    if (f.host && s.host !== f.host) return false;
    if (state.hiddenHosts.has(s.host)) return false;
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
      trimClientCap();
      const follow = isAtBottom();
      applyFilter();
      el.gridRows.style.height = (state.filtered.length * ROW_H) + "px";
      if (follow) el.gridScroll.scrollTop = el.gridScroll.scrollHeight;
      renderVisible();
      updateCounts();
      updateEmptyState();
      updateFollowUi(follow);
    });
  }

  const isAtBottom = () =>
    el.gridScroll.scrollTop + el.gridScroll.clientHeight >= el.gridRows.offsetHeight - ROW_H * 3;

  // Reflect follow-tail state: when the user has scrolled up and new rows are arriving,
  // surface a "jump to latest" affordance; hide it while pinned to the bottom.
  function updateFollowUi(atBottom) {
    state.follow = atBottom;
    el.jumpLatest.classList.toggle("show", !atBottom && state.filtered.length > 0);
  }

  function jumpToLatest() {
    el.gridScroll.scrollTop = el.gridScroll.scrollHeight;
    state.follow = true;
    el.jumpLatest.classList.remove("show");
    renderVisible();
  }

  // Defense-in-depth cap on client memory: the server evicts + broadcasts removals, but
  // trim here too so a very long capture can never grow the tab's state without bound.
  const CLIENT_MAX = 25000;
  function trimClientCap() {
    if (state.ids.length <= CLIENT_MAX) return;
    const drop = state.ids.splice(0, state.ids.length - CLIENT_MAX);
    for (const id of drop) {
      state.sessions.delete(id);
      if (state.selectedId === id) { state.selectedId = null; state.detail = null; clearInspectors(); }
    }
  }

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
    const size = special ? formatBytes((s.tunnelBytesUp || 0) + (s.tunnelBytesDown || 0)) : formatBytes(s.bodyLength);
    return `<div class="grid-row${cls}" data-id="${s.id}" style="top:${i * ROW_H}px">
      <div class="col col-id">${s.id}</div>
      <div class="col col-res ${resCls}">${res}</div>
      <div class="col col-proto">${escapeHtml(proto)}</div>
      <div class="col col-method"><span class="method-badge">${escapeHtml(s.method)}</span></div>
      <div class="col col-host" title="${escapeHtml(s.host)}">${escapeHtml(s.host)}</div>
      <div class="col col-url" title="${escapeHtml(s.url)}">${escapeHtml(s.path + s.query)}</div>
      <div class="col col-type">${escapeHtml(shortType(s.responseContentType))}</div>
      <div class="col col-size">${size}</div>
      <div class="col col-started" title="${escapeHtml(fullTime(s.startedUtc))}">${escapeHtml(clockTime(s.startedUtc))}</div>
      <div class="col col-time">${s.completed ? Math.round(s.durationMs) + "ms" : ""}</div>
    </div>`;
  }

  function updateCounts() {
    el.counts.textContent = `${state.filtered.length} из ${state.ids.length} сессий`;
    const chip = $("#filterChip");
    const parts = [];
    if (state.filter.host) parts.push("host = " + state.filter.host);
    if (state.hiddenHosts.size) parts.push("скрыто хостов: " + state.hiddenHosts.size);
    if (parts.length) { chip.textContent = parts.join(" · ") + "  ✕"; chip.classList.remove("hidden"); }
    else chip.classList.add("hidden");
  }

  function clearHostFilters() {
    state.filter.host = "";
    state.hiddenHosts.clear();
    scheduleRender();
  }

  // Adds a host to the "don't decrypt" (bypass) list and persists it — the standard
  // workaround for Cloudflare/JS-challenge sites that break under MITM.
  async function addBypassHost(host) {
    const list = $("#txtBypass").value.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
    if (!list.includes(host)) list.push(host);
    $("#txtBypass").value = list.join("\n");
    await saveSettings();
    flash("Без расшифровки: " + host + " — перезагрузите страницу");
  }

  // ---- selection + inspectors ---------------------------------------------
  async function selectSession(id) {
    state.selectedId = id;
    renderVisible();
    try {
      const d = await api(`/api/sessions/${id}`);
      if (state.selectedId !== id) return; // a newer selection won the race — ignore this one
      state.detail = d;
      renderInspectors();
    } catch {
      if (state.selectedId !== id) return;
      el.reqBody.innerHTML = el.resBody.innerHTML = `<div class="empty">Сессия больше недоступна.</div>`;
    }
  }

  function renderInspectors() {
    const d = state.detail;
    if (!d) return;
    const s = d.summary;

    el.reqBadges.innerHTML =
      `<span class="badge b-blue">${escapeHtml(s.method)}</span>` +
      `<span class="badge b-muted">HTTP/${escapeHtml(s.requestHttpVersion)}</span>` +
      (s.startedUtc ? `<span class="badge b-muted" title="Начало запроса: ${escapeHtml(fullTime(s.startedUtc))}">🕓 ${escapeHtml(clockTime(s.startedUtc))}</span>` : "");
    el.resBadges.innerHTML = responseBadgesHtml(s, d);

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

  // Response badges shared by the main inspector and the Resender.
  function responseBadgesHtml(s, d) {
    const statusBadge = s.wasTunneled
      ? `<span class="badge b-muted">TUNNELED</span>`
      : s.error
        ? `<span class="badge b-red">ERROR</span>`
        : `<span class="badge ${badgeColor(s.status)}">${s.status} ${escapeHtml(s.reason || "")}</span>`;
    const cf = d && d.responseHeaders && d.responseHeaders.some((h) => h.name.toLowerCase() === "cf-mitigated");
    return statusBadge +
      (s.wasTunneled ? "" : `<span class="badge b-muted">${httpLabel(s.responseHttpVersion)}</span>`) +
      (s.wasTunneled ? "" : `<span class="badge b-muted">BODY: ${formatBytes(s.bodyLength)}</span>`) +
      (s.completed && !s.wasTunneled ? `<span class="badge b-muted">${Math.round(s.durationMs)} ms</span>` : "") +
      (cf ? `<span class="badge b-orange" title="Cloudflare-челлендж. MITM-сниф такие сайты обычно не проходит (страница отдаётся браузеру по HTTP/1.1 + ре-фингерпринт). Добавьте хост в «Пропускать без расшифровки»: ПКМ по сессии → «Не расшифровывать этот хост».">CF challenge</span>` : "") +
      (d && d.tlsSummary ? `<span class="badge b-green" title="Производное от активного пресета; реальная версия TLS апстрима не раскрывается">${escapeHtml(d.tlsSummary)}</span>` : "") +
      (s.followedRedirects && s.finalUrl && s.finalUrl !== s.url ? `<span class="badge b-blue" title="${escapeHtml(s.finalUrl)}">→ редирект</span>` : "");
  }

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
      case "params": html = d.queryParams.length ? kvTable(d.queryParams.map((p) => [p.name, p.value])) : note("Нет query-параметров."); break;
      case "cookies": html = d.requestCookies.length ? kvTable(d.requestCookies.map((c) => [c.name, c.value])) : note("Нет cookie запроса."); break;
      case "auth": html = renderAuth(d); break;
      case "info": html = renderInfo(d); break;
      case "raw": html = `<pre class="raw">${escapeHtml(buildRaw(d, false))}</pre>`; break;
      case "body": html = renderBody(d.requestBody, d.summary.id, "request"); break;
    }
    el.reqBody.innerHTML = html;
    afterRender(el.reqBody, d.summary.id, "request");
    activate(el.reqTabs, tab);
  }

  function renderResTab(tab) {
    state.resTab = tab;
    if (state.detail) renderResTabInto(state.detail, el.resBody, el.resTabs, tab);
  }

  // Renders a response tab for any detail into any container/tabs — reused by the
  // main inspector and the Resender's response pane.
  function renderResTabInto(d, bodyEl, tabsEl, tab) {
    let html;
    switch (tab) {
      case "headers": html = kvTable(d.responseHeaders.map((h) => [h.name, h.value]), true); break;
      case "cookies": html = renderResCookies(d); break;
      case "raw": html = `<pre class="raw">${escapeHtml(buildRaw(d, true))}</pre>`; break;
      case "preview": html = renderPreview(d); break;
      case "body": html = renderBody(d.responseBody, d.summary.id, "response"); break;
    }
    bodyEl.innerHTML = html;
    afterRender(bodyEl, d.summary.id, "response");
    activate(tabsEl, tab);
  }

  const activate = (tabs, tab) =>
    tabs.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));

  const note = (t) => `<div class="note">${escapeHtml(t)}</div>`;

  function kvTable(pairs, withFilter) {
    if (!pairs.length) return note("Пусто.");
    const rows = pairs.map(([k, v]) =>
      `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(v)}</td></tr>`).join("");
    const filter = withFilter ? `<input class="kv-filter" id="kvFilter" placeholder="Фильтр заголовков…" />` : "";
    return filter + `<table class="kv">${rows}</table>`;
  }

  function renderAuth(d) {
    const a = d.auth;
    if (!a) return note("Нет заголовка Authorization.");
    let rows = `<tr><td class="k">Scheme</td><td class="v">${escapeHtml(a.scheme)}</td></tr>`;
    if (a.username != null) rows += `<tr><td class="k">Username</td><td class="v">${escapeHtml(a.username)}</td></tr>`;
    if (a.password != null) rows += `<tr><td class="k">Password</td><td class="v">${escapeHtml(a.password)}</td></tr>`;
    if (a.token != null) rows += `<tr><td class="k">Token</td><td class="v">${escapeHtml(a.token)}</td></tr>`;
    return `<table class="kv">${rows}</table>`;
  }

  // ---- deep per-request Info tab ------------------------------------------
  const hex4 = (n) => "0x" + Number(n).toString(16).padStart(4, "0");
  const yesno = (b) => b ? "да" : "нет";

  function kvRows(pairs) {
    return pairs
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(v)}</td></tr>`)
      .join("");
  }
  function kvSection(title, pairs) {
    const rows = kvRows(pairs);
    return rows ? `<div class="info-grp"><div class="section-label">${escapeHtml(title)}</div><table class="kv">${rows}</table></div>` : "";
  }

  // A maximally-detailed breakdown of one request: client, versions, the engine's real
  // TLS fingerprint (JA3 + JA4 + parsed detail, cross-referenced from the full scan),
  // upstream result, timings and sizes.
  function renderInfo(d) {
    const s = d.summary;
    const fp = state.fpScan ? state.fpScan[s.fingerprintPreset] : null;

    const client = kvSection("Клиент", [
      ["Клиент (endpoint)", d.clientEndpoint],
      ["Метод", s.method],
      ["URL", s.url],
      ["Схема", s.scheme],
      ["Хост", s.host],
      ["Порт", s.port],
      ["Путь", s.path],
      ["Query-параметров", d.queryParams.length],
    ]);

    const timing = kvSection("Время", [
      ["Начало", fullTime(s.startedUtc)],
      ["Длительность", s.completed ? Math.round(s.durationMs) + " ms" : "…"],
    ]);

    const proto = kvSection("Протокол и версии", [
      ["Браузер ↔ прокси", "HTTP/" + s.requestHttpVersion + " (ALPN всегда http/1.1)"],
      ["Прокси ↔ сайт", s.wasTunneled ? "туннель (без инспекции)" : httpLabel(s.responseHttpVersion)],
      ["TLS (апстрим)", d.tlsSummary || "—"],
    ]);

    let fpRows;
    if (s.wasTunneled || s.isUdp) {
      fpRows = `<tr><td class="k">—</td><td class="v muted">Сессия не проходила через движок (туннель / UDP).</td></tr>`;
    } else if (fp && fp.ok) {
      fpRows = kvRows([
        ["Пресет", fp.preset],
        ["JA3", fp.ja3Md5],
        ["JA3 (строка)", fp.ja3],
        ["JA4", fp.ja4],
        ["TLS", fp.tlsVersion],
        ["Шифры / расширения", fp.cipherCount + " / " + fp.extensionCount],
        ["ALPN", (fp.alpn || []).join(", ")],
        ["TLS 1.3 / key_share / GREASE", `${yesno(fp.tls13)} / ${yesno(fp.keyShare)} / ${yesno(fp.grease)}`],
        ["Кривые (groups)", (fp.curves || []).map(hex4).join(" ")],
        ["Алгоритмы подписи", (fp.signatureAlgorithms || []).map(hex4).join(" ")],
        ["Версии (supported_versions)", (fp.supportedVersions || []).map(hex4).join(" ")],
      ]);
    } else {
      fpRows = `<tr><td class="k">Пресет</td><td class="v">${escapeHtml(s.fingerprintPreset)}` +
        `<div class="muted">Реальный JA3/JA4 движка — <span class="dl" data-scan>снять для всех пресетов</span> (по loopback, мимо TLS‑инспекторов).</div></td></tr>`;
    }
    const fpSection = `<div class="info-grp"><div class="section-label">Отпечаток движка (апстрим‑лег)</div><table class="kv">${fpRows}</table></div>`;

    const upstream = kvSection("Апстрим", [
      ["IP хоста", d.hostIp],
      ["Апстрим OK", s.wasTunneled ? null : yesno(s.upstreamOk)],
      ["Ошибка", s.error],
      ["Следовал редиректам", yesno(s.followedRedirects)],
      ["Финальный URL", s.finalUrl && s.finalUrl !== s.url ? s.finalUrl : null],
    ]);

    const sizes = kvSection("Размеры", [
      ["Тело запроса", d.requestBody && d.requestBody.size ? formatBytes(d.requestBody.size) + (d.requestBody.truncated ? " (обрезано)" : "") : "0 B"],
      ["Тело ответа", s.wasTunneled
        ? formatBytes((s.tunnelBytesUp || 0) + (s.tunnelBytesDown || 0)) + " (туннель)"
        : (s.bodyLength ? formatBytes(s.bodyLength) : "0 B")],
      ["Content-Type ответа", s.responseContentType],
    ]);

    const counts = kvSection("Заголовки и cookie", [
      ["Заголовков запроса", d.requestHeaders.length],
      ["Заголовков ответа", d.responseHeaders.length],
      ["Cookie запроса", d.requestCookies.length],
      ["Set-Cookie ответа", d.responseCookies.length],
    ]);

    return client + timing + proto + fpSection + upstream + sizes + counts;
  }

  function renderResCookies(d) {
    if (!d.responseCookies.length) return note("Нет заголовков Set-Cookie.");
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
    if (d.summary.wasTunneled) return note("Туннелированная сессия — не инспектируется.");
    if (!b || b.size === 0) return note("Нет тела ответа.");
    if (b.kind === "image") return `<img class="preview-img" src="/api/sessions/${id}/response-body" alt="response image" />`;
    if (b.kind === "html") return `<iframe class="preview-frame" sandbox="" src="/api/sessions/${id}/response-body"></iframe>`;
    if (b.kind === "json" && b.text != null) return `<pre class="raw">${jsonHighlight(b.text)}</pre>`;
    if (b.isText && b.text != null) return `<pre class="raw">${escapeHtml(b.text)}</pre>`;
    return `<div class="note">Бинарные данные ${escapeHtml(b.kind)} · ${formatBytes(b.size)} · <span class="dl" data-dl="response" data-id="${id}">скачать</span></div><div class="hexdump" data-hex="response" data-id="${id}">загрузка…</div>`;
  }

  function renderBody(b, id, dir) {
    if (!b || b.size === 0) return note("Нет тела.");
    const head = `<div class="section-label">${escapeHtml(b.kind)} · ${formatBytes(b.size)}${b.truncated ? " · обрезано" : ""} · <span class="dl" data-dl="${dir}" data-id="${id}">скачать</span></div>`;
    if (b.isText && b.text != null) return head + `<pre class="raw">${escapeHtml(b.text)}</pre>`;
    return head + `<div class="hexdump" data-hex="${dir}" data-id="${id}">загрузка…</div>`;
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
      n.addEventListener("click", () => window.open(`/api/sessions/${n.dataset.id}/${n.dataset.dl}-body?download=true`, "_blank")));
    container.querySelectorAll("[data-hex]").forEach((n) => loadHex(n));
    // "снять для всех пресетов" link in the Info tab → run the full scan, then re-render.
    container.querySelectorAll("[data-scan]").forEach((n) =>
      n.addEventListener("click", async () => { n.textContent = "снимаю…"; await runFullScan(); if (state.reqTab === "info") renderReqTab("info"); }));
  }

  async function loadHex(node) {
    try {
      const r = await fetch(`/api/sessions/${node.dataset.id}/${node.dataset.hex}-body`);
      const buf = new Uint8Array(await r.arrayBuffer());
      node.textContent = hexDump(buf, 4096);
    } catch { node.textContent = "(не удалось загрузить тело)"; }
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
    el.gridScroll.addEventListener("scroll", () => { renderVisible(); updateFollowUi(isAtBottom()); });

    el.reqTabs.addEventListener("click", (e) => { if (e.target.dataset.tab) renderReqTab(e.target.dataset.tab); });
    el.resTabs.addEventListener("click", (e) => { if (e.target.dataset.tab) renderResTab(e.target.dataset.tab); });
    el.reqTabs.querySelectorAll(".tab").forEach((b) => b.dataset.label = b.textContent);
    el.resTabs.querySelectorAll(".tab").forEach((b) => b.dataset.label = b.textContent);

    $("#btnClear").addEventListener("click", () => {
      if (state.ids.length === 0 || confirm(`Удалить все ${state.ids.length} сессий? Это действие необратимо.`)) {
        api("/api/clear", { method: "POST" });
      }
    });
    $("#btnExport").addEventListener("click", () => {
      const filtered = state.filtered.length !== state.ids.length;
      window.open("/api/export.saz" + (filtered ? "?ids=" + state.filtered.join(",") : ""), "_blank");
    });
    $("#btnCa").addEventListener("click", () => window.open("/api/ca.cer", "_blank"));
    $("#btnCaPem").addEventListener("click", () => window.open("/api/ca.pem", "_blank"));
    $("#btnCaAndroid").addEventListener("click", () => window.open("/api/ca-android", "_blank"));
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
    $("#numMaxRedirects").addEventListener("change", saveSettings);
    $("#tglCapture").addEventListener("change", async () => { await saveSettings(); syncCaptureUi(); });
    $("#btnPause").addEventListener("click", toggleCapture);
    el.capturePill.addEventListener("click", toggleCapture);
    el.capturePill.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleCapture(); } });
    $("#btnTheme").addEventListener("click", toggleTheme);
    el.jumpLatest.addEventListener("click", jumpToLatest);
    $("#modeManual").addEventListener("click", () => applyMode("manual"));
    $("#modeSystem").addEventListener("click", () => applyMode("system"));
    $("#tglUdp").addEventListener("change", onUdpToggle);
    // Preset + proxy are applied explicitly (Apply/Reset); reflect the label live on change.
    $("#selPreset").addEventListener("change", () => { $("#presetLabel").textContent = presetLabelFor($("#selPreset").value); });
    $("#btnApplyPreset").addEventListener("click", applyPreset);
    $("#btnResetPreset").addEventListener("click", resetPreset);
    $("#btnApplyProxy").addEventListener("click", applyProxy);
    $("#btnResetProxy").addEventListener("click", resetProxy);
    $("#tglForceHttp1").addEventListener("change", saveSettings);
    $("#tglInterceptAll").addEventListener("change", saveSettings);
    $("#tglInsecure").addEventListener("change", saveSettings);
    $("#txtBypass").addEventListener("change", saveSettings);
    $("#btnTestProxy").addEventListener("click", testProxy);
    $("#btnSelftest").addEventListener("click", runSelfTest);
    $("#btnFullScan").addEventListener("click", runFullScan);
    $("#btnFpAdd").addEventListener("click", addFingerprint);
    $("#fpList").addEventListener("click", (e) => {
      const b = e.target.closest(".fp-x");
      if (b) removeFingerprint(b.dataset.fp);
    });

    $("#btnSettings").addEventListener("click", () => openModal("settingsModal"));
    $("#settingsClose").addEventListener("click", () => closeModal("settingsModal"));

    // Resender
    $("#btnResender").addEventListener("click", () => openResender(state.detail || null));
    $("#rsClose").addEventListener("click", () => closeModal("resenderModal"));
    $("#rsSend").addEventListener("click", sendResender);
    $("#rsAddHeader").addEventListener("click", addHeaderRow);
    $("#btnRsRaw").addEventListener("click", toggleRawHeaders);
    $("#rsHeaders").addEventListener("click", (e) => { if (e.target.classList.contains("hrow-del")) e.target.closest(".hrow").remove(); });
    $("#rsHistory").addEventListener("change", (e) => loadRsHistory(e.target.value));
    $("#rsReqTabs").addEventListener("click", (e) => { if (e.target.dataset.tab) switchRsReqTab(e.target.dataset.tab); });
    $("#rsResTabs").addEventListener("click", (e) => { if (e.target.dataset.tab) renderRsResTab(e.target.dataset.tab); });
    $("#rsResTabs").querySelectorAll(".tab").forEach((b) => b.dataset.label = b.textContent);
    rs("rsUrl").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); sendResender(); } });
    ["settingsModal", "resenderModal"].forEach((id) =>
      $("#" + id).addEventListener("click", (e) => { if (e.target.id === id) closeModal(id); }));

    el.filterText.addEventListener("input", () => { state.filter.text = el.filterText.value.toLowerCase(); scheduleRender(); });
    el.filterMethod.addEventListener("change", () => { state.filter.method = el.filterMethod.value; scheduleRender(); });
    el.filterStatus.addEventListener("change", () => { state.filter.status = el.filterStatus.value; scheduleRender(); });
    el.filterType.addEventListener("change", () => { state.filter.type = el.filterType.value; scheduleRender(); });
    $("#filterChip").addEventListener("click", clearHostFilters);

    // context menu + copy-as-cURL + keyboard
    el.gridRows.addEventListener("contextmenu", (e) => {
      const row = e.target.closest(".grid-row");
      if (!row) return;
      e.preventDefault();
      showContextMenu(e.clientX, e.clientY, +row.dataset.id);
    });
    $("#ctxMenu").addEventListener("click", (e) => {
      const act = e.target.dataset.act;
      if (!act) return;
      const id = +$("#ctxMenu").dataset.id;
      hideContextMenu();
      ctxAction(act, id);
    });
    document.addEventListener("click", (e) => { if (!e.target.closest("#ctxMenu")) hideContextMenu(); });
    el.gridScroll.addEventListener("scroll", hideContextMenu);
    document.addEventListener("keydown", onKeyDown);
    $("#btnReqCurl").addEventListener("click", async () => {
      if (state.detail && await copyText(buildCurl(state.detail))) flash("cURL скопирован");
    });

    initDividers();
  }

  // Sends the full settings object. The proxy + fingerprint come from the APPLIED state
  // (committed via their Apply buttons), NOT the live fields — so auto-saving an unrelated
  // toggle can never apply a half-typed proxy or an un-applied preset.
  async function saveSettings() {
    const mr = parseInt($("#numMaxRedirects").value, 10);
    if (Number.isFinite(mr) && mr >= 1 && mr <= 50) state.maxRedirects = mr;
    const dto = {
      smartRedirects: $("#tglRedirects").checked,
      maxRedirects: state.maxRedirects || 10,
      capture: $("#tglCapture").checked,
      upstreamProxy: state.appliedProxy,
      rotatingProxy: state.appliedRotating,
      fingerprintPreset: state.appliedPreset,
      forceHttp1: $("#tglForceHttp1").checked,
      interceptAllPorts: $("#tglInterceptAll").checked,
      ignoreUpstreamCertErrors: $("#tglInsecure").checked,
      bypassHosts: $("#txtBypass").value,
    };
    const res = await postJson("/api/settings", dto);
    if (res) state.appliedProxy = res.upstreamProxy || ""; // server-decoded friendly form
    $("#presetLabel").textContent = presetLabelFor(state.appliedPreset);
    return res;
  }

  // Human label for a preset value (built-in option text or a captured "custom:<name>").
  function presetLabelFor(value) {
    const opt = [...$("#selPreset").options].find((o) => o.value === value);
    return opt ? opt.textContent : (value || "Chrome");
  }

  // ---- Apply / Reset: proxy ------------------------------------------------
  async function applyProxy() {
    state.appliedProxy = $("#txtProxy").value.trim();
    state.appliedRotating = $("#tglRotating").checked;
    await saveSettings();
    $("#txtProxy").value = state.appliedProxy; // reflect the server-canonicalized (decoded) form
    flash(state.appliedProxy ? "Прокси применён" : "Прокси очищен (прямое соединение)");
  }
  function resetProxy() {
    $("#txtProxy").value = state.appliedProxy;
    $("#tglRotating").checked = state.appliedRotating;
    flash("Поле прокси сброшено");
  }

  // ---- Apply / Reset: fingerprint preset -----------------------------------
  async function applyPreset() {
    state.appliedPreset = $("#selPreset").value;
    await saveSettings();
    flash("Отпечаток применён: " + presetLabelFor(state.appliedPreset));
  }
  function resetPreset() {
    $("#selPreset").value = state.appliedPreset;
    $("#presetLabel").textContent = presetLabelFor(state.appliedPreset);
    flash("Выбор отпечатка сброшен");
  }

  async function testProxy() {
    const out = $("#proxyTestOut");
    out.textContent = "Проверка прокси…";
    try {
      const r = await postJson("/api/test-proxy", { proxy: $("#txtProxy").value });
      out.innerHTML = r.ok
        ? `✅ Прокси работает · внешний IP: <b>${escapeHtml(r.ip || "?")}</b>` + (r.proxy ? `<br><span class="muted">${escapeHtml(r.proxy)}</span>` : "")
        : `⚠ ${escapeHtml(r.error || "не удалось")}`;
    } catch { out.textContent = "Не удалось выполнить тест."; }
  }

  async function runSelfTest() {
    const out = $("#selftestOut");
    out.textContent = "Снимаю реальный ClientHello локально…";
    $("#fpSave").classList.add("hidden");
    state.lastCapture = null;
    try {
      const r = await api("/api/fingerprint-selftest");
      if (!r.ok) { out.textContent = "⚠ " + (r.error || "не удалось"); return; }
      const real = r.tls13 && r.keyShare; // real browsers offer TLS 1.3 + key_share; TLS-inspectors typically don't
      out.innerHTML =
        `${real ? "✅" : "⚠"} <b>${escapeHtml(r.preset)}</b> · TLS1.3=${r.tls13} · key_share=${r.keyShare} · GREASE=${r.grease} · ` +
        `шифров ${r.cipherCount} · расширений ${r.extensionCount}<br>` +
        `JA3 = <b>${r.ja3Md5}</b><br><span class="muted" style="word-break:break-all">${escapeHtml(r.ja3)}</span>` +
        (real ? "" : "<br><span class=\"muted\">Похоже, исходящий TLS перехватывается прокси/инспектором — наружу уходит его отпечаток, не движка.</span>");
      // Offer to save this capture into the selection list.
      state.lastCapture = { ja3: r.ja3, ja3Md5: r.ja3Md5 };
      $("#fpName").value = (r.preset || "").split(" · ")[0];
      $("#fpSave").classList.remove("hidden");
    } catch { out.textContent = "Не удалось снять отпечаток."; }
  }

  // Full device scan (#3): every preset's real JA3 + JA4 + engine identity, captured locally.
  async function runFullScan() {
    const out = $("#scanOut");
    out.innerHTML = `<div class="note">Снимаю отпечатки всех пресетов локально…</div>`;
    try {
      const r = await api("/api/fingerprint-scan");
      state.fpScan = {};
      (r.fingerprints || []).forEach((f) => { state.fpScan[f.preset] = f; });
      out.innerHTML = renderScan(r);
    } catch { out.innerHTML = `<div class="note">Не удалось выполнить скан.</div>`; }
  }

  function renderScan(r) {
    const e = r.engine || {};
    const eng = `<div class="scan-engine"><b>Устройство / движок:</b> ${escapeHtml(e.os || "")} · ${escapeHtml(e.framework || "")} · ` +
      `ОС ${escapeHtml(e.osArchitecture || "")}, процесс ${escapeHtml(e.processArchitecture || "")}<br>` +
      `Активный пресет: <b>${escapeHtml(e.activePreset || "")}</b>${e.forceHttp1 ? " · форс HTTP/1.1" : ""} · ` +
      `${e.egressProxy ? "прокси " + escapeHtml(e.egressProxy) : "прямое соединение"}</div>`;
    const rows = (r.fingerprints || []).map((f) => f.ok
      ? `<tr><td>${escapeHtml(f.preset)}</td><td>${escapeHtml(f.tlsVersion || "")}</td>` +
        `<td>${f.cipherCount}/${f.extensionCount}</td><td>${escapeHtml((f.alpn || []).join(","))}</td>` +
        `<td class="mono" title="${escapeHtml(f.ja3)}">${escapeHtml(f.ja3Md5)}</td><td class="mono">${escapeHtml(f.ja4)}</td></tr>`
      : `<tr><td>${escapeHtml(f.preset)}</td><td colspan="5" class="muted">${escapeHtml(f.error || "ошибка")}</td></tr>`).join("");
    return eng +
      `<div class="scan-wrap"><table class="scan-table">` +
      `<tr><th>Пресет</th><th>TLS</th><th>Ciph/Ext</th><th>ALPN</th><th>JA3 (md5)</th><th>JA4</th></tr>${rows}</table></div>` +
      `<div class="setting-note">Снято по loopback — мимо любых TLS‑инспекторов. JA4 нормализует порядок, поэтому у Chrome/Edge/Safari он может совпасть, а JA3 (учитывает порядок) — различаться.</div>`;
  }

  async function loadFingerprints() {
    try { state.fingerprints = (await api("/api/fingerprints")) || []; }
    catch { state.fingerprints = []; }
    renderFingerprints();
  }

  function renderFingerprints() {
    const grp = $("#fpGroup");
    grp.innerHTML = state.fingerprints.map((f) =>
      `<option value="custom:${escapeHtml(f.name)}">${escapeHtml(f.name)} · ${escapeHtml((f.ja3Md5 || "").slice(0, 8))}</option>`).join("");
    grp.hidden = state.fingerprints.length === 0;
    $("#fpList").innerHTML = state.fingerprints.map((f) =>
      `<div class="fp-item"><button class="fp-x" data-fp="${escapeHtml(f.name)}" title="Удалить из списка">✕</button>` +
      `<code>${escapeHtml(f.name)}</code> · ${escapeHtml(f.preset || "Chrome")} · ` +
      `<span class="muted">${escapeHtml((f.ja3Md5 || "").slice(0, 12))}</span></div>`).join("");
  }

  async function addFingerprint() {
    if (!state.lastCapture) { flash("Сначала снимите отпечаток"); return; }
    const name = $("#fpName").value.trim().replace(/[\/\\:]/g, "-");
    if (!name) { flash("Введите имя отпечатка"); return; }
    let base = $("#selPreset").value; // record which built-in preset reproduces this JA3
    if (base.startsWith("custom:")) {
      const m = state.fingerprints.find((f) => f.name === base.slice(7));
      base = m ? m.preset : "Chrome";
    }
    const res = await postJson("/api/fingerprints",
      { name, ja3: state.lastCapture.ja3, ja3Md5: state.lastCapture.ja3Md5, preset: base });
    if (res) {
      state.fingerprints = res;
      renderFingerprints();
      $("#fpName").value = "";
      $("#fpSave").classList.add("hidden");
      flash("Отпечаток добавлен: " + name);
    }
  }

  async function removeFingerprint(name) {
    try {
      const r = await fetch(`/api/fingerprints/${encodeURIComponent(name)}`, { method: "DELETE" });
      if (!r.ok) { flash("Не удалось удалить"); return; }
      state.fingerprints = await r.json();
      // The server resets the active selection to Chrome if it was this capture — mirror it.
      if (state.appliedPreset === "custom:" + name) state.appliedPreset = "Chrome";
      if ($("#selPreset").value === "custom:" + name) $("#selPreset").value = "Chrome";
      renderFingerprints();
      $("#presetLabel").textContent = presetLabelFor(state.appliedPreset);
      flash("Удалён: " + name);
    } catch { flash("Не удалось удалить"); }
  }

  // ---- modals + UDP install + composer ------------------------------------
  function openModal(id) { $("#" + id).classList.remove("hidden"); }
  function closeModal(id) { $("#" + id).classList.add("hidden"); }

  async function udpCall(enabled) {
    try { return await postJson("/api/udp-capture", { enabled }); }
    catch { return { running: false, supported: false, error: "request failed" }; }
  }

  async function onUdpToggle(e) {
    if (!e.target.checked) { await udpCall(false); return; }
    let r = await udpCall(true);
    if (!r.running && r.supported && /not found|windivert\.dll/i.test(r.error || "")) {
      if (confirm("WinDivert не найден. Скачать и установить автоматически с reqrypt.org (≈400 КБ, официальный релиз)?")) {
        const ins = await api("/api/install-windivert", { method: "POST" });
        alert(ins.message || (ins.ok ? "Установлено." : "Не удалось установить."));
        if (ins.installed) r = await udpCall(true);
      }
    }
    if (!r.running) {
      e.target.checked = false;
      if (r.error) alert(r.error);
    }
  }

  // ---- Resender: edit a request, resend, see the response inline ----------
  const rs = (id) => $("#" + id);

  function openResender(detail) {
    fillResender(detail);
    renderRsResponse(detail || null);
    openModal("resenderModal");
    rs("rsUrl").focus();
  }

  function fillResender(d) {
    rs("rsMethod").value = d ? (d.summary.method || "GET").toUpperCase() : "GET";
    rs("rsUrl").value = d ? (d.summary.url || "") : "";
    setHeaderRows(d ? d.requestHeaders.map((h) => ({ name: h.name, value: h.value, on: true })) : []);
    rs("rsBody").value = d && d.requestBody && d.requestBody.isText && d.requestBody.text ? d.requestBody.text : "";
    rs("rsStatus").textContent = "Правьте запрос и нажмите Send — ответ появится справа.";
    switchRsReqTab("headers");
  }

  function headerRowHtml(h) {
    return `<div class="hrow">
      <input type="checkbox" class="hrow-on" ${h.on === false ? "" : "checked"} title="включить/выключить заголовок"/>
      <input class="hrow-name" placeholder="Header" value="${escapeHtml(h.name)}"/>
      <input class="hrow-val" placeholder="value" value="${escapeHtml(h.value)}"/>
      <button class="hrow-del" type="button" title="удалить">✕</button>
    </div>`;
  }

  function setHeaderRows(headers) {
    if (state.rsRawHeaders) { rs("rsHeadersRaw").value = headers.filter((h) => h.on !== false).map((h) => h.name + ": " + h.value).join("\n"); return; }
    rs("rsHeaders").innerHTML = headers.map(headerRowHtml).join("");
  }

  function currentHeaderRows() {
    const out = [];
    rs("rsHeaders").querySelectorAll(".hrow").forEach((row) => out.push({
      name: row.querySelector(".hrow-name").value,
      value: row.querySelector(".hrow-val").value,
      on: row.querySelector(".hrow-on").checked,
    }));
    return out;
  }

  function addHeaderRow() {
    const div = document.createElement("div");
    div.innerHTML = headerRowHtml({ name: "", value: "", on: true });
    rs("rsHeaders").appendChild(div.firstElementChild);
    rs("rsHeaders").lastElementChild.querySelector(".hrow-name").focus();
  }

  function collectHeaderBlock() {
    if (state.rsRawHeaders) return rs("rsHeadersRaw").value;
    const lines = [];
    rs("rsHeaders").querySelectorAll(".hrow").forEach((row) => {
      if (!row.querySelector(".hrow-on").checked) return;
      const name = row.querySelector(".hrow-name").value.trim();
      if (name) lines.push(name + ": " + row.querySelector(".hrow-val").value);
    });
    return lines.join("\n");
  }

  function parseHeaderText(text) {
    return text.split("\n").map((l) => l.trim()).filter(Boolean).map((l) => {
      const i = l.indexOf(":");
      return i > 0 ? { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim(), on: true } : null;
    }).filter(Boolean);
  }

  function toggleRawHeaders() {
    const headers = state.rsRawHeaders ? parseHeaderText(rs("rsHeadersRaw").value) : currentHeaderRows();
    state.rsRawHeaders = !state.rsRawHeaders;
    rs("rsHeaders").classList.toggle("hidden", state.rsRawHeaders);
    rs("rsHeadersRaw").classList.toggle("hidden", !state.rsRawHeaders);
    rs("btnRsRaw").classList.toggle("active", state.rsRawHeaders);
    setHeaderRows(headers);
  }

  function switchRsReqTab(tab) {
    rs("rsHeadersPane").classList.toggle("hidden", tab !== "headers");
    rs("rsBodyPane").classList.toggle("hidden", tab !== "body");
    activate(rs("rsReqTabs"), tab);
  }

  async function sendResender() {
    const url = rs("rsUrl").value.trim();
    const status = rs("rsStatus");
    if (!url) { status.textContent = "Укажите URL."; return; }
    status.textContent = "Отправка…";
    rs("rsSend").disabled = true;
    try {
      const resp = await fetch("/api/compose", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ method: rs("rsMethod").value, url, headers: collectHeaderBlock(), body: rs("rsBody").value }),
      });
      const data = await resp.json().catch(() => ({}));
      if (resp.ok && data.summary) {
        const s = data.summary;
        status.textContent = `Отправлено — #${s.id} · ${s.error ? "ERR" : s.status} · ${Math.round(s.durationMs)} ms`;
        pushRsHistory(s);
        renderRsResponse(data);
      } else {
        status.textContent = data.error || ("Ошибка HTTP " + resp.status);
      }
    } catch {
      status.textContent = "Запрос не удался.";
    } finally {
      rs("rsSend").disabled = false;
    }
  }

  function pushRsHistory(s) {
    state.rsHistory = state.rsHistory.filter((h) => h.id !== s.id);
    state.rsHistory.unshift({ id: s.id, method: s.method, status: s.status });
    if (state.rsHistory.length > 30) state.rsHistory.pop();
    rs("rsHistory").innerHTML = `<option value="">История (${state.rsHistory.length})</option>` +
      state.rsHistory.map((h) => `<option value="${h.id}">#${h.id} ${escapeHtml(h.method)} ${h.status || ""}</option>`).join("");
  }

  function renderRsResponse(detail) {
    state.rsDetail = detail;
    const badges = rs("rsResBadges");
    if (!detail) { badges.innerHTML = `<span class="muted">Ответ появится здесь после Send.</span>`; rs("rsResBody").innerHTML = ""; return; }
    badges.innerHTML = responseBadgesHtml(detail.summary, detail);
    setCount(rs("rsResTabs"), "headers", detail.responseHeaders.length);
    setCount(rs("rsResTabs"), "cookies", detail.responseCookies.length);
    renderResTabInto(detail, rs("rsResBody"), rs("rsResTabs"), state.rsResTab);
  }

  function renderRsResTab(tab) {
    state.rsResTab = tab;
    if (state.rsDetail) renderResTabInto(state.rsDetail, rs("rsResBody"), rs("rsResTabs"), tab);
  }

  async function loadRsHistory(id) {
    if (!id) return;
    try {
      const d = await getJson("/api/sessions/" + id);
      if (rs("rsHistory").value !== id) return; // a newer history pick superseded this one
      fillResender(d);
      renderRsResponse(d);
    } catch { flash("Сессия больше недоступна"); }
  }

  // Resend a captured request unchanged (new session), without opening the editor.
  async function resendAsIs(d) {
    try {
      const headers = d.requestHeaders.map((h) => h.name + ": " + h.value).join("\n");
      const body = d.requestBody && d.requestBody.isText && d.requestBody.text ? d.requestBody.text : "";
      const resp = await fetch("/api/compose", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ method: d.summary.method, url: d.summary.url, headers, body }),
      });
      const data = await resp.json().catch(() => ({}));
      flash(resp.ok && data.summary ? `Отправлено #${data.summary.id} · ${data.summary.status}` : (data.error || "Ошибка"));
    } catch { flash("Запрос не удался"); }
  }

  const store = {
    get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };

  function initDividers() {
    drag($("#divider"), (dx, startW) => {
      const w = Math.min(window.innerWidth - 380, Math.max(320, startW + dx));
      $("#gridPane").style.width = w + "px";
      store.set("split-grid-w", String(w));
      renderVisible();
    }, () => $("#gridPane").offsetWidth, "x");
    drag($("#inspectDivider"), (dy, startH) => {
      const h = Math.max(120, startH + dy);
      document.querySelector(".inspect.req").style.flex = `0 0 ${h}px`;
      store.set("split-req-h", String(h));
    }, () => document.querySelector(".inspect.req").offsetHeight, "y");

    // Resender's edit/response split (its DOM is static, so bind once here).
    const rsDiv = $("#rsDivider");
    if (rsDiv) {
      drag(rsDiv, (dx, startW) => {
        const total = rsDiv.parentElement.offsetWidth;
        const w = Math.min(total - 260, Math.max(260, startW + dx));
        document.querySelector(".resender-req").style.flex = `0 0 ${w}px`;
      }, () => document.querySelector(".resender-req").offsetWidth, "x");
    }

    // Restore persisted sizes, re-clamped to the current viewport.
    const savedW = parseFloat(store.get("split-grid-w"));
    if (Number.isFinite(savedW)) {
      $("#gridPane").style.width = Math.min(window.innerWidth - 380, Math.max(320, savedW)) + "px";
    }
    const savedH = parseFloat(store.get("split-req-h"));
    if (Number.isFinite(savedH)) {
      document.querySelector(".inspect.req").style.flex = `0 0 ${Math.max(120, savedH)}px`;
    }
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

  // ---- session ops: context menu, copy, replay, remove, keyboard ----------
  function clearInspectors() {
    el.reqBody.innerHTML = el.resBody.innerHTML = `<div class="empty">Выберите сессию для просмотра.</div>`;
    el.reqBadges.innerHTML = el.resBadges.innerHTML = "";
  }

  function removeLocal(id) {
    if (!state.sessions.has(id)) return;
    state.sessions.delete(id);
    const i = state.ids.indexOf(id);
    if (i >= 0) state.ids.splice(i, 1);
    if (state.selectedId === id) { state.selectedId = null; state.detail = null; clearInspectors(); }
    scheduleRender();
  }

  async function removeSession(id) {
    try { await fetch(`/api/sessions/${id}`, { method: "DELETE" }); } catch { /* removed locally regardless */ }
    removeLocal(id);
  }

  function hideContextMenu() { $("#ctxMenu").classList.add("hidden"); }

  const ctxItem = (act, label) => `<div class="ctx-item" data-act="${act}">${label}</div>`;
  const ctxSep = `<div class="ctx-sep"></div>`;

  function showContextMenu(x, y, id) {
    const m = $("#ctxMenu");
    m.innerHTML =
      ctxItem("resender", "Открыть в Resender") +
      ctxItem("resend", "Повторить как есть") +
      ctxSep +
      ctxItem("copyurl", "Копировать URL") +
      ctxItem("copycurl", "Копировать как cURL") +
      ctxItem("copyresp", "Копировать тело ответа") +
      ctxItem("copyreq", "Копировать тело запроса") +
      ctxItem("copyrhdr", "Копировать заголовки ответа") +
      ctxSep +
      ctxItem("open", "Открыть URL в браузере") +
      ctxItem("save", "Сохранить тело ответа") +
      ctxSep +
      ctxItem("hostonly", "Только этот хост") +
      ctxItem("hosthide", "Скрыть этот хост") +
      ctxItem("bypasshost", "Не расшифровывать этот хост (bypass)") +
      ctxSep +
      `<div class="ctx-item danger" data-act="remove">Удалить сессию</div>`;
    m.dataset.id = id;
    m.classList.remove("hidden");
    m.style.left = Math.min(x, window.innerWidth - m.offsetWidth - 6) + "px";
    m.style.top = Math.min(y, window.innerHeight - m.offsetHeight - 6) + "px";
  }

  async function ctxAction(act, id) {
    const s = state.sessions.get(id);
    // actions that work from the summary alone (no detail fetch)
    switch (act) {
      case "remove": removeSession(id); return;
      case "copyurl": if (s && await copyText(s.url)) flash("URL скопирован"); return;
      case "open": if (s) window.open(s.url, "_blank"); return;
      case "save": window.open(`/api/sessions/${id}/response-body?download=true`, "_blank"); return;
      case "hostonly": if (s) { state.filter.host = s.host; scheduleRender(); } return;
      case "hosthide": if (s) { state.hiddenHosts.add(s.host); scheduleRender(); } return;
      case "bypasshost": if (s) await addBypassHost(s.host); return;
    }
    // actions needing the full detail
    let d;
    try { d = await getJson(`/api/sessions/${id}`); } catch { return; }
    switch (act) {
      case "resender": openResender(d); break;
      case "resend": resendAsIs(d); break;
      case "copycurl": if (await copyText(buildCurl(d))) flash("cURL скопирован"); break;
      case "copyresp":
        if (d.responseBody && d.responseBody.isText && d.responseBody.text != null) {
          if (await copyText(d.responseBody.text)) flash("Тело ответа скопировано");
        } else flash("Тело не текстовое — используйте «Сохранить»");
        break;
      case "copyreq":
        if (d.requestBody && d.requestBody.isText && d.requestBody.text != null) {
          if (await copyText(d.requestBody.text)) flash("Тело запроса скопировано");
        } else flash("Нет текстового тела запроса");
        break;
      case "copyrhdr":
        if (await copyText(d.responseHeaders.map((h) => h.name + ": " + h.value).join("\n"))) flash("Заголовки ответа скопированы");
        break;
    }
  }

  function moveSelection(delta) {
    const list = state.filtered;
    if (!list.length) return;
    let idx = list.indexOf(state.selectedId);
    idx = idx < 0 ? (delta > 0 ? 0 : list.length - 1) : Math.max(0, Math.min(list.length - 1, idx + delta));
    selectSession(list[idx]);
    ensureRowVisible(idx);
  }

  function ensureRowVisible(idx) {
    const top = idx * ROW_H, bottom = top + ROW_H;
    const vt = el.gridScroll.scrollTop, vb = vt + el.gridScroll.clientHeight;
    if (top < vt) el.gridScroll.scrollTop = top;
    else if (bottom > vb) el.gridScroll.scrollTop = bottom - el.gridScroll.clientHeight;
    renderVisible();
  }

  function onboardingHtml() {
    const p = state.proxyPort || 8866;
    return `<div class="onboard">
      <div class="onboard-title">Сессий пока нет</div>
      <ol>
        <li>В <b>⚙ Settings</b> нажмите <b>Install CA</b> (Windows) или <b>Download CA</b> и установите как доверенный корневой сертификат.</li>
        <li>Выберите режим <b>System</b> (Windows) или направьте браузер/приложение на прокси <code>127.0.0.1:${p}</code>.</li>
        <li>Откройте любой сайт — сессии появятся здесь вживую.</li>
      </ol>
      <div class="muted">Горячие клавиши: <b>↑/↓</b> — навигация, <b>Del</b> — удалить, <b>/</b> — фильтр, ПКМ по строке — меню.</div>
    </div>`;
  }

  function updateEmptyState() {
    const empty = $("#gridEmpty");
    if (state.ids.length === 0) { empty.innerHTML = onboardingHtml(); empty.classList.remove("hidden"); }
    else if (state.filtered.length === 0) { empty.innerHTML = `<div class="empty">Нет совпадений по фильтру.</div>`; empty.classList.remove("hidden"); }
    else empty.classList.add("hidden");
  }

  const anyModalOpen = () =>
    !$("#settingsModal").classList.contains("hidden") || !$("#resenderModal").classList.contains("hidden");

  function onKeyDown(e) {
    if (e.key === "Escape") { closeModal("settingsModal"); closeModal("resenderModal"); hideContextMenu(); return; }
    const tag = document.activeElement && document.activeElement.tagName;
    const inField = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
    if (!inField && !anyModalOpen() && (e.key === "/" || (e.ctrlKey && (e.key === "f" || e.key === "F")))) {
      e.preventDefault(); el.filterText.focus(); el.filterText.select(); return;
    }
    if (inField || anyModalOpen() || !$("#ctxMenu").classList.contains("hidden")) return;
    if (e.key === "ArrowDown") { e.preventDefault(); moveSelection(1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); moveSelection(-1); }
    else if (e.key === "Delete" && state.selectedId != null) { e.preventDefault(); removeSession(state.selectedId); }
  }

  // ---- bootstrap -----------------------------------------------------------
  const CONN = {
    on: ["dot-on", "SignalR: подключено — идёт живой захват"],
    reconnecting: ["dot-reconnecting", "SignalR: переподключение… захват приостановлен"],
    off: ["dot-off", "SignalR: отключено"],
  };
  function setConn(status) {
    const [cls, title] = CONN[status] || CONN.off;
    el.connDot.className = "dot " + cls;
    el.connDot.title = title;
  }

  function connectHub() {
    const conn = new signalR.HubConnectionBuilder().withUrl("/hub/sessions").withAutomaticReconnect().build();
    conn.on("sessions", (batch) => { for (const s of batch) upsert(s); scheduleRender(); });
    conn.on("removed", (ids) => { for (const id of ids) removeLocal(id); });
    conn.on("cleared", () => {
      state.sessions.clear(); state.ids = []; state.filtered = []; state.selectedId = null; state.detail = null;
      // Also drop the accumulated method/content-type filter options so the dropdowns
      // don't offer values for a capture that no longer exists.
      state.methods.clear(); state.types.clear();
      el.filterMethod.length = 1; el.filterType.length = 1;
      state.filter.method = ""; state.filter.type = "";
      clearInspectors();
      scheduleRender();
    });
    conn.onreconnecting(() => setConn("reconnecting"));
    conn.onreconnected(() => setConn("on"));
    conn.onclose(() => setConn("off"));
    conn.start().then(() => setConn("on")).catch(() => { setConn("off"); setTimeout(connectHub, 2000); });
  }

  // ---- theme (light/dark) --------------------------------------------------
  function currentTheme() {
    return document.documentElement.getAttribute("data-theme")
      || (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  }
  function updateThemeButton(theme) {
    const b = $("#btnTheme");
    if (!b) return;
    b.textContent = theme === "light" ? "☀️" : "🌙";
    b.title = theme === "light" ? "Переключить на тёмную тему" : "Переключить на светлую тему";
  }
  function toggleTheme() {
    const next = currentTheme() === "light" ? "dark" : "light";
    try { localStorage.setItem("theme", next); } catch { /* private mode */ }
    document.documentElement.setAttribute("data-theme", next);
    updateThemeButton(next);
  }

  // ---- capture pause state (mirrored into always-visible chrome) ------------
  function syncCaptureUi() {
    const on = $("#tglCapture").checked;
    el.capturePill.classList.toggle("on", !on);
    const btn = $("#btnPause");
    btn.textContent = on ? "⏸ Пауза" : "▶ Запись";
    btn.classList.toggle("primary", !on);
    btn.title = on ? "Приостановить запись сессий (Capture)" : "Возобновить запись сессий (Capture)";
  }
  async function toggleCapture() {
    const cb = $("#tglCapture");
    cb.checked = !cb.checked;
    await saveSettings();
    syncCaptureUi();
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
      const r = await postJson("/api/system-proxy", { enabled: mode === "system" });
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
      const caText = "CA: " + st.caSubject + "  ·  " + st.caStoreDirectory;
      $("#caStore").textContent = caText;
      $("#caStoreInfo").textContent = caText;
      if (st.androidCaFile) {
        $("#caAndroidInfo").innerHTML =
          "Android (системно, root/эмулятор): <code>" + escapeHtml(st.androidCaFile) +
          "</code> → <code>/system/etc/security/cacerts/</code> (chmod 644, ремоунт /system rw, перезагрузка). " +
          "Без root — кнопка <b>PEM</b>, затем Настройки → Безопасность → установить сертификат CA.";
      }
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
      $("#tglForceHttp1").checked = s.forceHttp1;
      $("#tglInterceptAll").checked = s.interceptAllPorts;
      $("#tglInsecure").checked = s.ignoreUpstreamCertErrors;
      $("#txtBypass").value = s.bypassHosts || "";
      $("#txtProxy").value = s.upstreamProxy || "";
      $("#tglRotating").checked = s.rotatingProxy;
      state.appliedProxy = s.upstreamProxy || "";
      state.appliedRotating = !!s.rotatingProxy;
      state.maxRedirects = s.maxRedirects > 0 ? s.maxRedirects : 10;
      $("#numMaxRedirects").value = state.maxRedirects;
      if (s.fingerprintPreset) $("#selPreset").value = s.fingerprintPreset;
      state.appliedPreset = s.fingerprintPreset || "Chrome";
      const label = $("#selPreset").selectedOptions[0]?.textContent || s.fingerprintPreset;
      if (label) $("#presetLabel").textContent = label;
      syncCaptureUi(); // reflect persisted capture state in the toolbar (pill + Pause button)
    } catch { /* ignore */ }
  }

  async function loadSessions() {
    try {
      const list = await api("/api/sessions");
      for (const s of list) upsert(s);
      scheduleRender();
    } catch { /* ignore */ }
  }

  updateThemeButton(currentTheme());
  wireUi();
  loadStatus();
  loadFingerprints().then(loadSettings); // options must exist before settings selects one
  loadSessions();
  connectHub();
})();
