const rootEl = document.getElementById("scan-root");
const closeBtn = document.getElementById("scan-close");

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function shortHash(hash) {
  const value = String(hash || "");
  if (!value) {
    return "";
  }
  if (value.length <= 24) {
    return value;
  }
  return `${value.slice(0, 12)}…${value.slice(-10)}`;
}

function latestScanFrom(scans, history) {
  if (Array.isArray(history) && history[0]) {
    return history[0];
  }
  return (
    Object.values(scans || {}).sort((a, b) => (b.ts || 0) - (a.ts || 0))[0] || null
  );
}

function enginePills(report) {
  const clam = report?.static_analysis?.clamav || {};
  const yara = report?.static_analysis?.yara || {};
  const engines = report?.engines || {};
  const clamOn =
    engines.clamav === true ||
    (clam.status && clam.status !== "unavailable" && clam.status !== "error");
  const yaraOn =
    engines.yara === true ||
    yara.status === "completed";
  const heuristicsOn = Array.isArray(report?.static_analysis?.heuristics);
  return `
    <div class="scan-engines">
      <span class="engine-pill ${clamOn ? "is-on" : "is-off"}">ClamAV ${clamOn ? "on" : "unavailable"}</span>
      <span class="engine-pill ${yaraOn ? "is-on" : "is-off"}">YARA ${yaraOn ? "on" : "unavailable"}</span>
      <span class="engine-pill ${heuristicsOn ? "is-on" : "is-off"}">Heuristics on</span>
    </div>
  `;
}

function reasoningHtml(scan) {
  const report = scan.report || {};
  const assessment = report.assessment || {};
  const evidence = assessment.evidence || [];
  const yaraMatches = report.static_analysis?.yara?.matches || [];
  const clamRaw = report.static_analysis?.clamav?.raw || "";
  const file = report.file || {};
  const rows = [];
  for (const item of evidence) {
    rows.push(`
      <div class="reason-item">
        <span class="reason-source">${escapeHtml(item.source || "EVIDENCE")}</span>
        <p>${escapeHtml(item.message || "")}</p>
      </div>
    `);
  }
  if (yaraMatches.length) {
    rows.push(`
      <div class="reason-item">
        <span class="reason-source">YARA</span>
        <p>${escapeHtml(yaraMatches.join(", "))}</p>
      </div>
    `);
  }
  if (clamRaw) {
    rows.push(`
      <div class="reason-item">
        <span class="reason-source">SCANNER OUTPUT</span>
        <p>${escapeHtml(clamRaw)}</p>
      </div>
    `);
  }
  if (file.sha256 || file.mime_type || file.size) {
    const bits = [
      file.mime_type,
      file.size != null ? `${Number(file.size).toLocaleString()} bytes` : "",
      shortHash(file.sha256)
    ].filter(Boolean);
    rows.push(`
      <div class="reason-item">
        <span class="reason-source">FILE</span>
        <p class="scan-hash">${escapeHtml(bits.join(" · "))}</p>
      </div>
    `);
  }
  if (!rows.length) {
    rows.push(`<div class="reason-item"><p>No extra evidence was recorded for this scan.</p></div>`);
  }
  return rows.join("");
}

function renderScan(scan) {
  if (!scan) {
    rootEl.innerHTML = `<p class="empty">No downloads scanned yet.</p>`;
    return;
  }
  if (scan.status === "scanning") {
    rootEl.innerHTML = `<p class="scan-pulse">Scanning ${escapeHtml(scan.filename || "download")}…</p>`;
    return;
  }
  if (scan.status === "error") {
    rootEl.innerHTML = `<div class="glass-panel"><p class="scan-reason">${escapeHtml(scan.error || "Scan failed.")}</p></div>`;
    return;
  }
  const risk = scan.risk || scan.report?.assessment?.risk || "UNKNOWN";
  const reason = scan.report?.assessment?.reason || "";
  const actions =
    scan.action === "deleted"
      ? `<p class="scan-removed">File removed from Downloads.</p>`
      : scan.action === "kept"
      ? `<p class="scan-kept">Kept in Downloads.</p>
         <div class="scan-actions">
           <button type="button" class="scan-delete" data-scan-action="delete" data-download-id="${Number(scan.downloadId)}">Delete file</button>
         </div>`
      : `<div class="scan-actions">
           <button type="button" class="scan-delete" data-scan-action="delete" data-download-id="${Number(scan.downloadId)}">Delete file</button>
           <button type="button" data-scan-action="show" data-download-id="${Number(scan.downloadId)}">Keep file</button>
         </div>`;
  rootEl.innerHTML = `
    <section class="glass-panel">
      <p class="scan-risk" data-risk="${escapeHtml(risk)}">${escapeHtml(risk)}</p>
      <p class="scan-name">${escapeHtml(scan.filename || "download")}</p>
      <p class="scan-reason">${escapeHtml(reason)}</p>
      ${enginePills(scan.report)}
      ${actions}
      <div class="reason-block">
        <button type="button" class="reason-toggle" id="reason-toggle" aria-expanded="false">
          <span>Reasoning</span>
          <svg class="chevron" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
            <path d="M4 6.5 8 10.5 12 6.5" />
          </svg>
        </button>
        <div class="reason-body" id="reason-body" hidden>
          ${reasoningHtml(scan)}
        </div>
      </div>
    </section>
  `;
}

async function loadScan() {
  const data = await chrome.runtime.sendMessage({ type: "GET_DOWNLOAD_SCANS" });
  renderScan(data?.latest || latestScanFrom(data?.scans, data?.history));
}

closeBtn?.addEventListener("click", () => window.close());

rootEl.addEventListener("click", async (event) => {
  const toggle = event.target.closest("#reason-toggle");
  if (toggle) {
    const body = document.getElementById("reason-body");
    const open = !toggle.classList.contains("is-open");
    toggle.classList.toggle("is-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    body?.classList.toggle("is-open", open);
    if (body) {
      body.hidden = !open;
    }
    return;
  }
  const button = event.target.closest("[data-scan-action]");
  if (!button) {
    return;
  }
  const downloadId = Number(button.dataset.downloadId);
  const type = button.dataset.scanAction === "delete" ? "DELETE_SCANNED_FILE" : "SHOW_SCANNED_FILE";
  button.disabled = true;
  const result = await chrome.runtime.sendMessage({ type, downloadId });
  if (!result?.ok) {
    button.disabled = false;
    return;
  }
  await loadScan();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") {
    return;
  }
  if (changes.downloadScans || changes.downloadScanHistory) {
    loadScan().catch((error) => console.error(error));
  }
});

loadScan().catch((error) => {
  rootEl.innerHTML = `<p class="empty">Could not load scan results.</p>`;
  console.error(error);
});
