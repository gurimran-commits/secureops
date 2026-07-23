const statusEl = document.querySelector("#status");
const totalPacketsEl = document.querySelector("#totalPackets");
const ppsEl = document.querySelector("#pps");
const uniqueSourcesEl = document.querySelector("#uniqueSources");
const alertCountEl = document.querySelector("#alertCount");
const protocolsEl = document.querySelector("#protocols");
const sourcesEl = document.querySelector("#sources");
const alertsEl = document.querySelector("#alerts");
const packetsEl = document.querySelector("#packets");
const packetMeterEl = document.querySelector("#packetMeter");
const ppsMeterEl = document.querySelector("#ppsMeter");
const sourceDotsEl = document.querySelector("#sourceDots");
const severityPillEl = document.querySelector("#severityPill");
const trafficBarsEl = document.querySelector("#trafficBars");
const windowLabelEl = document.querySelector("#windowLabel");

const trafficHistory = Array.from({ length: 18 }, () => 0);

async function getJson(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function renderRows(container, rows, emptyText) {
  container.innerHTML = "";
  if (!rows.length) {
    container.innerHTML = `<p class="empty">${emptyText}</p>`;
    return;
  }
  rows.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `<span>${escapeHtml(label)}</span><strong>${value}</strong>`;
    container.appendChild(row);
  });
}

function renderProtocolRings(protocols) {
  protocolsEl.innerHTML = "";
  const entries = Object.entries(protocols);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  if (!entries.length) {
    protocolsEl.innerHTML = '<p class="empty">No protocol data yet.</p>';
    return;
  }

  entries.slice(0, 4).forEach(([protocol, count], index) => {
    const percent = Math.round((count / total) * 100);
    const ring = document.createElement("div");
    ring.className = "ring";
    ring.style.setProperty("--value", `${percent}%`);
    ring.style.setProperty("--ring-color", index % 2 ? "#25d7f2" : "#ff4fc3");
    ring.innerHTML = `<strong>${percent}</strong><span>${escapeHtml(protocol)}</span>`;
    protocolsEl.appendChild(ring);
  });
}

function renderAlerts(alerts) {
  alertsEl.innerHTML = "";
  alertCountEl.textContent = alerts.length;
  severityPillEl.textContent = alerts.length ? alerts[0].severity : "quiet";
  severityPillEl.dataset.level = alerts.length ? alerts[0].severity : "quiet";
  if (!alerts.length) {
    alertsEl.innerHTML = '<p class="empty">No alerts in SQLite yet.</p>';
    return;
  }
  alerts.forEach((alert) => {
    const row = document.createElement("div");
    row.className = "alert";
    row.innerHTML = `<span>${escapeHtml(alert.detector)}: ${escapeHtml(alert.reason)}</span><strong>${escapeHtml(alert.severity)}</strong><span>${escapeHtml(alert.observed_value)} / ${escapeHtml(alert.threshold)}</span>`;
    alertsEl.appendChild(row);
  });
}

function renderPackets(packets) {
  packetsEl.innerHTML = "";
  packets.forEach((packet) => {
    const row = document.createElement("tr");
    row.innerHTML = `<td>${formatTime(packet.timestamp)}</td><td>${escapeHtml(packet.src_ip)}</td><td>${escapeHtml(packet.dst_ip)}</td><td>${escapeHtml(packet.protocol)}</td><td>${packet.size_bytes}</td>`;
    packetsEl.appendChild(row);
  });
}

function renderVisuals(metrics) {
  const pps = Number(metrics.packets_per_second || 0);
  const packetPercent = Math.min(100, Number(metrics.total_packets || 0));
  const ppsPercent = Math.min(100, pps * 10);
  packetMeterEl.style.width = `${packetPercent}%`;
  ppsMeterEl.style.width = `${ppsPercent}%`;
  windowLabelEl.textContent = `${metrics.window_seconds}s window`;

  sourceDotsEl.innerHTML = "";
  const sourceCount = Math.min(10, Number(metrics.unique_sources || 0));
  for (let index = 0; index < 10; index += 1) {
    const dot = document.createElement("i");
    dot.className = index < sourceCount ? "on" : "";
    sourceDotsEl.appendChild(dot);
  }

  trafficHistory.push(Math.max(1, Number(metrics.total_packets || 0)));
  trafficHistory.shift();
  const maxValue = Math.max(...trafficHistory, 1);
  trafficBarsEl.innerHTML = "";
  trafficHistory.forEach((value, index) => {
    const bar = document.createElement("i");
    bar.style.height = `${Math.max(8, (value / maxValue) * 100)}%`;
    bar.style.opacity = String(0.35 + index / 24);
    trafficBarsEl.appendChild(bar);
  });
}

async function refresh() {
  try {
    const [health, metrics, alerts, packets] = await Promise.all([
      getJson("/api/health"),
      getJson("/api/metrics"),
      getJson("/api/alerts"),
      getJson("/api/packets"),
    ]);

    const capture = health.capture;
    statusEl.textContent = capture.running
      ? `Capture running on ${capture.interface || "default interface"}`
      : capture.last_error || capture.message || `Capture ${capture.readiness}`;

    totalPacketsEl.textContent = metrics.total_packets;
    ppsEl.textContent = metrics.packets_per_second;
    uniqueSourcesEl.textContent = metrics.unique_sources;
    renderVisuals(metrics);
    renderProtocolRings(metrics.protocol_counts);
    renderRows(sourcesEl, metrics.top_sources, "No source data yet.");
    renderAlerts(alerts);
    renderPackets(packets);
  } catch (error) {
    statusEl.textContent = `Dashboard refresh failed: ${error.message}`;
  }
}

document.querySelector("#startCapture").addEventListener("click", async () => {
  await getJson("/api/capture/start", { method: "POST" });
  await refresh();
});

document.querySelector("#stopCapture").addEventListener("click", async () => {
  await getJson("/api/capture/stop", { method: "POST" });
  await refresh();
});

document.querySelector("#demoTraffic").addEventListener("click", async () => {
  await getJson("/api/demo/traffic", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ packets: 220, source_count: 1, protocol: "TCP" }),
  });
  await refresh();
});

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return escapeHtml(value);
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

refresh();
setInterval(refresh, 3000);
