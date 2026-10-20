"use strict";

const $ = (id) => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has("token")) {
  sessionStorage.setItem("traceglass-token", fragment.get("token"));
  history.replaceState(null, "", location.pathname);
}
const token = sessionStorage.getItem("traceglass-token") || "";
let paused = false;
let loading = false;
let nextBefore = 0;
let currentBefore = 0;
let filterHost = "";
let filterFlagged = false;

function bytes(value) {
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let unit = -1;
  do { value /= 1024; unit++; } while (value >= 1024 && unit < units.length - 1);
  return `${value.toFixed(1)} ${units[unit]}`;
}

async function api(path) {
  const response = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error("Open the dashboard link printed by Traceglass to authenticate this tab.");
    throw new Error(`Local API returned ${response.status}. Check the Traceglass terminal.`);
  }
  return response.json();
}

function cell(row, text, detail) {
  const td = document.createElement("td");
  td.textContent = text;
  if (detail) {
    const small = document.createElement("small");
    small.textContent = detail;
    td.append(small);
  }
  row.append(td);
  return td;
}

function render(records) {
  const body = $("flows");
  body.replaceChildren();
  if (!records.length) {
    const row = document.createElement("tr");
    const td = cell(row, filterHost || filterFlagged ? "No completed flows match your filters." : "Your network story starts here. Point an app at the proxy, then make a request.");
    td.colSpan = 6;
    td.className = "empty";
    body.append(row);
  }
  for (const record of records) {
    const row = document.createElement("tr");
    cell(row, new Date(record.timestamp).toLocaleTimeString(), record.method);
    const host = cell(row, record.host, `PORT ${record.port}`);
    host.title = record.host;
    const mode = cell(row, record.mode === "inspected" ? "HTTPS inspected" : record.mode === "tunnel" ? "Encrypted tunnel" : "HTTP metadata");
    mode.className = `mode ${record.mode}`;
    cell(row, bytes(record.request_bytes + record.response_bytes), `${record.duration_ms.toLocaleString()} ms`);
    const status = cell(row, record.status || "--", record.error_code);
    if (record.error_code) status.className = "amber";
    const flags = cell(row, "");
    if (!record.flags.length) {
      flags.textContent = "No rule matches";
      flags.className = "neutral";
    }
    for (const flag of record.flags) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = flag;
      flags.append(badge);
    }
    body.append(row);
  }
  $("table-note").textContent = `${records.length} completed flows shown / newest first${currentBefore ? " / historical page" : ""}`;
}

async function refresh() {
  if (loading) return;
  loading = true;
  $("older").disabled = true;
  try {
    const query = new URLSearchParams({ limit: "100", host: filterHost, flagged: String(filterFlagged) });
    if (currentBefore) query.set("before", currentBefore);
    const [status, page] = await Promise.all([api("/api/status"), api(`/api/records?${query}`)]);
    $("records").textContent = status.stats.records.toLocaleString();
    $("flagged").textContent = status.stats.flagged.toLocaleString();
    $("volume").textContent = bytes(status.stats.request_bytes + status.stats.response_bytes);
    $("active").textContent = status.active;
    $("queue").textContent = `${status.stats.queued} queued / ${status.stats.dropped.toLocaleString()} dropped`;
    $("proxy").textContent = status.proxy;
    $("inspection").textContent = status.inspect?.length ? `${status.inspect.length} domain rules` : "Tunnel only";
    $("inspection").title = (status.inspect || []).join(", ");
    $("retention").textContent = `RETENTION / ${status.max_records.toLocaleString()} FLOWS / ${status.max_age}`;
    $("connection").textContent = paused ? "Updates paused" : "Local connection healthy";
    $("live-label").textContent = paused ? "PAUSED" : "LIVE";
    $("error").hidden = status.stats.dropped === 0;
    if (status.stats.dropped > 0) $("error").textContent = `Storage backpressure: ${status.stats.dropped} metadata records were dropped this session. Forwarding continued; the activity history is incomplete.`;
    render(page.records);
    nextBefore = page.next_before;
    $("older").disabled = !nextBefore;
    $("latest").hidden = !currentBefore;
  } catch (error) {
    $("connection").textContent = "Connection needs attention";
    $("error").textContent = error.message;
    $("error").hidden = false;
  } finally {
    loading = false;
  }
}

$("pause").addEventListener("click", () => {
  paused = !paused;
  $("pause").textContent = paused ? "Resume updates" : "Pause updates";
  $("live-label").textContent = paused ? "PAUSED" : "LIVE";
  $("connection").textContent = paused ? "Updates paused" : "Reconnecting";
  if (!paused) { currentBefore = 0; refresh(); }
});
$("filters").addEventListener("submit", (event) => {
  event.preventDefault();
  if (loading) return;
  filterHost = $("host").value.trim().toLowerCase();
  filterFlagged = $("flagged-only").checked;
  currentBefore = 0;
  refresh();
});
$("older").addEventListener("click", () => {
  if (loading || !nextBefore) return;
  paused = true;
  $("pause").textContent = "Resume updates";
  currentBefore = nextBefore;
  refresh();
});
$("latest").addEventListener("click", () => {
  if (loading) return;
  currentBefore = 0;
  paused = false;
  $("pause").textContent = "Pause updates";
  refresh();
});
refresh();
setInterval(() => { if (!paused && !document.hidden) refresh(); }, 3000);
