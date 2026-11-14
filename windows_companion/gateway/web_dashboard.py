"""Self-contained local web workbench served by PsycheGatewayService on localhost."""

from __future__ import annotations

WEB_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>PSYCHE AI — Sovereign Local Workbench</title>
<style>
  :root {
    --bg: #0f131b;
    --panel: #151b26;
    --panel-alt: #1b2231;
    --border: #2a3449;
    --text: #e6ecf5;
    --muted: #93a1b8;
    --accent: #3d7cf5;
    --accent-hover: #2d66d6;
    --success: #2ea043;
    --warn: #d29922;
    --danger: #a82838;
    --mono: "Cascadia Code", "Consolas", "Courier New", monospace;
    --sans: "Segoe UI", system-ui, -apple-system, sans-serif;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 13px;
    line-height: 1.45;
  }
  header.topbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 18px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 20;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 15px;
    letter-spacing: 0.4px;
  }
  .badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
  .badge {
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 600;
    background: var(--panel-alt);
    border: 1px solid var(--border);
    color: var(--text);
  }
  .badge.ok { border-color: #2ea04366; color: #7ee787; }
  .badge.warn { border-color: #d2992266; color: #f2cc60; }
  .badge.danger { border-color: #f8514966; color: #ff7b72; }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  button {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    padding: 7px 12px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s ease;
  }
  button:hover { background: var(--accent-hover); }
  button.secondary {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    color: var(--text);
  }
  button.secondary:hover { background: #232c3f; }
  button.secondary.active {
    background: #22355c;
    border-color: var(--accent);
  }
  button.danger { background: var(--danger); }
  button.danger:hover { background: #8c1f2e; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }

  input, textarea, select {
    width: 100%;
    background: #0c1017;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    font-family: var(--sans);
    font-size: 12.5px;
  }
  textarea { resize: vertical; }
  pre, code {
    font-family: var(--mono);
    font-size: 11.5px;
  }

  .grid {
    display: grid;
    grid-template-columns: 380px 1fr;
    gap: 14px;
    padding: 14px 18px;
    min-height: calc(100vh - 58px);
  }
  @media (max-width: 1020px) {
    .grid { grid-template-columns: 1fr; }
  }
  .col {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
  }
  .card h2 {
    margin: 0 0 8px 0;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
  }
  .list-scroll {
    max-height: 210px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .item-row {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    cursor: pointer;
  }
  .item-row:hover { border-color: var(--accent); }
  .item-row.selected {
    border-color: var(--accent);
    background: #1e2a42;
  }
  .item-meta {
    font-size: 11px;
    color: var(--muted);
    margin-bottom: 3px;
  }
  .tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 10px;
  }
  .pillar-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 10px;
  }
  .pillar-card {
    background: var(--panel-alt);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px;
  }
  .pillar-card h3 {
    margin: 0 0 6px 0;
    font-size: 12px;
    color: #8ab4ff;
    text-transform: uppercase;
  }
  .pillar-json {
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
    color: #cdd6e5;
  }
  .locked-banner {
    display: none;
    max-width: 560px;
    margin: 80px auto;
    background: var(--panel);
    border: 1px solid var(--danger);
    border-radius: 12px;
    padding: 28px;
    text-align: center;
  }
  .locked-banner h1 {
    font-size: 18px;
    color: #ff7b72;
    margin-top: 0;
  }
  .kv-row {
    display: flex;
    justify-content: space-between;
    gap: 8px;
    align-items: center;
    padding: 5px 0;
    border-bottom: 1px dashed #252f42;
  }
  .kv-row:last-child { border-bottom: none; }
  .row-actions {
    display: flex;
    gap: 8px;
    margin-top: 8px;
    flex-wrap: wrap;
  }
  .muted { color: var(--muted); font-size: 12px; }
  a.apk-link { color: #79b8ff; text-decoration: none; font-weight: 600; }
  a.apk-link:hover { text-decoration: underline; }
</style>
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span>PSYCHE AI</span>
      <span class="badge">Local Sovereign Workbench</span>
    </div>
    <div class="badges">
      <span id="vaultBadge" class="badge">VAULT: ...</span>
      <span id="aiBadge" class="badge">NEURAL AI: ...</span>
      <span id="hwBadge" class="badge">GPU Telemetry: ...</span>
      <span class="badge ok">CLOUD: DISABLED ($0.00)</span>
    </div>
    <div class="actions">
      <button id="blurBtn" class="secondary" type="button">Privacy Blur: OFF</button>
      <button id="refreshBtn" class="secondary" type="button">Refresh</button>
      <button id="panicBtn" class="danger" type="button">Emergency Panic Lock</button>
    </div>
  </header>

  <div id="lockedOverlay" class="locked-banner">
    <h1>VAULT LOCKED (PANIC LOCK ENGAGED)</h1>
    <p class="muted">
      All decrypted SQLite access, vector caches, and plaintext UI views are zeroized.
      External AI calls remain disabled ($0.00).
    </p>
    <div style="margin-top: 18px;">
      <button id="unlockBtn" type="button">Unlock Local Vault (Windows DPAPI)</button>
    </div>
  </div>

  <main id="workbench" class="grid">
    <!-- Left Column -->
    <section class="col">
      <div class="card">
        <h2>Contacts &amp; Relationship Tiers</h2>
        <div id="contactsList" class="list-scroll"></div>
      </div>

      <div class="card">
        <h2>Manual Message Analyzer (7 Modes)</h2>
        <div style="display:flex; flex-direction:column; gap:8px;">
          <div style="display:grid; grid-template-columns:1fr 140px; gap:8px;">
            <input id="manualSender" type="text" placeholder="Sender name (e.g. Aarav)" />
            <select id="manualTier">
              <option value="CLOSE_FRIEND">CLOSE_FRIEND</option>
              <option value="INNER_CIRCLE">INNER_CIRCLE</option>
              <option value="FAMILY">FAMILY</option>
              <option value="COLLEAGUE">COLLEAGUE</option>
              <option value="ACQUAINTANCE">ACQUAINTANCE</option>
            </select>
          </div>
          <textarea id="manualText" rows="3" placeholder="Paste message (EN / Hindi / Hinglish / Malayalam / Manglish / Telugu / Tenglish)..."></textarea>
          <button id="analyzeBtn" type="button">Analyze Message (Local Neural Core)</button>
        </div>
      </div>

      <div class="card">
        <h2 id="timelineHeader">Chronological Conversation Timeline</h2>
        <div id="timelineList" class="list-scroll"></div>
      </div>

      <div class="card">
        <h2>Open Loops (Commitments &amp; Questions)</h2>
        <div id="loopsList" class="list-scroll" style="max-height:140px;"></div>
      </div>
    </section>

    <!-- Right Column -->
    <section class="col">
      <div class="card" style="flex:1; display:flex; flex-direction:column;">
        <div class="tabs">
          <button class="secondary active" data-tab="pillars" type="button">6 Intelligence Pillars</button>
          <button class="secondary" data-tab="safeguards" type="button">Uncertainty &amp; Reality Check</button>
          <button class="secondary" data-tab="memories" type="button">Memory Integrity Ledger</button>
          <button class="secondary" data-tab="pairing" type="button">Phone Pairing &amp; Neural AI</button>
        </div>

        <div id="tab-pillars" class="tab-pane"></div>
        <div id="tab-safeguards" class="tab-pane" style="display:none;"></div>
        <div id="tab-memories" class="tab-pane" style="display:none;"></div>
        <div id="tab-pairing" class="tab-pane" style="display:none;"></div>
      </div>

      <div class="card">
        <h2>Human-Reviewed Reply Studio (Zero Send Guard: Copy Only)</h2>
        <div style="display:flex; flex-direction:column; gap:8px;">
          <select id="candidateSelect"></select>
          <textarea id="replyEditor" rows="4" placeholder="Select or edit candidate draft here..."></textarea>
          <div class="row-actions">
            <button id="approveCopyBtn" type="button">Approve &amp; Copy to Clipboard (Manual Send)</button>
            <button id="rejectBtn" class="secondary" type="button">Reject Draft</button>
          </div>
          <div id="reviewStatus" class="muted">Awaiting user review decision (requires_user_review=true).</div>
        </div>
      </div>
    </section>
  </main>

<script>
(() => {
  let state = null;
  let selectedPersonId = null;
  let selectedMemoryId = null;
  let activeTab = "pillars";
  let privacyBlur = false;
  let activePairingQr = null;

  const $ = (id) => document.getElementById(id);

  function maskText(txt) {
    if (!privacyBlur || !txt) return txt || "";
    if (txt.length <= 4) return "****";
    return txt.slice(0, 2) + "*".repeat(Math.min(18, txt.length - 3)) + txt.slice(-1);
  }

  function esc(str) {
    return String(str ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  async function api(url, opts = {}) {
    const res = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      ...opts,
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.message || `HTTP ${res.status}`);
    }
    return data;
  }

  async function loadState(personId = selectedPersonId) {
    const q = personId ? `?person_id=${encodeURIComponent(personId)}` : "";
    state = await api(`/v1/web/state${q}`);
    render();
  }

  function render() {
    if (!state) return;
    const locked = Boolean(state.vault_locked);
    $("lockedOverlay").style.display = locked ? "block" : "none";
    $("workbench").style.display = locked ? "none" : "grid";

    const vBadge = $("vaultBadge");
    vBadge.textContent = locked ? "LOCAL VAULT: LOCKED (RAM ZEROIZED)" : "LOCAL VAULT: UNLOCKED";
    vBadge.className = "badge " + (locked ? "danger" : "ok");

    const aiBadge = $("aiBadge");
    aiBadge.textContent = state.neural_ai_online
      ? "NEURAL AI: ONLINE (Qwen2.5-3B Vulkan)"
      : "AI: TIER-0 FALLBACK";
    aiBadge.className = "badge " + (state.neural_ai_online ? "ok" : "warn");

    $("hwBadge").textContent =
      `${state.gpu_name || "Local GPU"} | Free VRAM: ${Math.round(state.free_vram_mib || 0)} / ${Math.round(state.total_vram_mib || 0)} MiB | RAM: ${(state.process_ram_mib || 0).toFixed(1)} MiB`;

    if (locked) return;

    // Contacts
    const contacts = state.people || [];
    if (!selectedPersonId && contacts.length > 0) {
      selectedPersonId = contacts[0].person_id;
    }
    $("contactsList").innerHTML = contacts.length
      ? contacts.map((p) => `
          <div class="item-row ${p.person_id === state.selected_person_id ? "selected" : ""}" data-pid="${esc(p.person_id)}">
            <div><strong>${esc(maskText(p.canonical_display_name))}</strong></div>
            <div class="item-meta">${esc(p.relationship_tier)} | trust=${Number(p.trust_level || 0).toFixed(2)}</div>
          </div>
        `).join("")
      : `<div class="muted">No contacts yet. Analyze a message below or pair your Android phone.</div>`;

    document.querySelectorAll("#contactsList .item-row").forEach((el) => {
      el.addEventListener("click", () => {
        selectedPersonId = el.getAttribute("data-pid");
        loadState(selectedPersonId);
      });
    });

    // Timeline
    const events = state.timeline_events || [];
    $("timelineList").innerHTML = events.length
      ? events.map((ev) => `
          <div class="item-row" style="cursor:default;">
            <div class="item-meta">${esc(ev.direction)} | ${esc((ev.detected_language_modes || []).join(", "))} | ${esc(ev.posted_at_utc)}</div>
            <div>${esc(privacyBlur ? "[HIDDEN BY PRIVACY BLUR]" : ev.raw_text_immutable)}</div>
            <div class="item-meta">sha256=${esc(String(ev.raw_text_sha256 || "").slice(0, 14))}...</div>
          </div>
        `).join("")
      : `<div class="muted">No captured events for this contact yet.</div>`;

    // Open Loops
    const loops = state.open_loops || [];
    $("loopsList").innerHTML = loops.length
      ? loops.map((lp) => `
          <div class="item-row" style="cursor:default; display:flex; justify-content:space-between; gap:8px; align-items:center;">
            <div>
              <div class="item-meta">[${esc(lp.status)} | ${esc(lp.loop_kind)}]</div>
              <div>${esc(privacyBlur ? "[HIDDEN BY PRIVACY BLUR]" : lp.description)}</div>
            </div>
            <button class="secondary dismiss-loop-btn" data-lid="${esc(lp.loop_id)}" type="button">Dismiss</button>
          </div>
        `).join("")
      : `<div class="muted">No unresolved open loops.</div>`;

    document.querySelectorAll(".dismiss-loop-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        await api("/v1/web/memory", {
          method: "POST",
          body: JSON.stringify({ action: "DISMISS_LOOP", loop_id: btn.getAttribute("data-lid") }),
        });
        await loadState();
      });
    });

    renderRightTabs();
    renderReplyStudio();
  }

  function renderRightTabs() {
    const pkt = state.synthesis_packet;
    if (privacyBlur) {
      const hidden = `<div class="muted">[HIDDEN BY PRIVACY BLUR — SHA-256 VERIFIED]</div>`;
      $("tab-pillars").innerHTML = hidden;
      $("tab-safeguards").innerHTML = hidden;
      $("tab-memories").innerHTML = hidden;
    } else if (!pkt) {
      $("tab-pillars").innerHTML = `<div class="muted">No synthesis packet yet. Select a contact or analyze a message.</div>`;
      $("tab-safeguards").innerHTML = `<div class="muted">No uncertainty audit yet.</div>`;
    } else {
      const pillars = pkt.pillar_assessments || {};
      $("tab-pillars").innerHTML = `
        <div class="pillar-grid">
          ${Object.entries(pillars).map(([name, val]) => `
            <div class="pillar-card">
              <h3>${esc(name)}</h3>
              <pre class="pillar-json">${esc(JSON.stringify(val, null, 2))}</pre>
            </div>
          `).join("")}
        </div>
      `;

      const unc = pkt.uncertainty_audit || {};
      const rc = pkt.reality_check_audit || {};
      $("tab-safeguards").innerHTML = `
        <div style="display:flex; flex-direction:column; gap:10px;">
          <div class="pillar-card">
            <h3>Contextual Uncertainty Audit</h3>
            <p><strong>Verdict:</strong> ${esc(unc.verdict_status)} (Confidence: ${Number(unc.calibrated_confidence || 0).toFixed(2)})</p>
            <p><strong>Primary Interpretation:</strong> ${esc(unc.primary_interpretation)}</p>
            <p><strong>Alternative Hypotheses:</strong></p>
            <ul>
              ${(unc.alternative_explanations || []).map((a) => `
                <li><code>${esc(a.hypothesis_id)}</code> (${Number(a.plausibility_score || a.confidence || 0).toFixed(2)}): ${esc(a.explanation || a.hypothesis_text)}</li>
              `).join("")}
            </ul>
          </div>
          <div class="pillar-card">
            <h3>Reality-Checking &amp; Anti-Sycophancy Audit</h3>
            <p><strong>Sycophancy Guard Passed:</strong> ${esc(rc.sycophancy_guard_passed)}</p>
            <p><strong>Independent Thinking Prompt:</strong> ${esc(rc.independent_thinking_prompt)}</p>
            <pre class="pillar-json">${esc(JSON.stringify({
              challenged_user_assumptions: rc.challenged_user_assumptions,
              challenged_ai_assumptions: rc.challenged_ai_assumptions,
              feelings_vs_facts_distinction: rc.feelings_vs_facts_distinction || rc.distinction_feelings_vs_facts
            }, null, 2))}</pre>
          </div>
        </div>
      `;
    }

    if (!privacyBlur) {
      const mems = state.memories || [];
      $("tab-memories").innerHTML = `
        <div style="display:flex; flex-direction:column; gap:8px;">
          <div class="list-scroll" style="max-height:240px;">
            ${mems.length ? mems.map((m) => `
              <div class="item-row ${m.memory_id === selectedMemoryId ? "selected" : ""}" data-mid="${esc(m.memory_id)}">
                <div class="item-meta">[${esc(m.epistemic_class)} | ${esc(m.memory_domain)} | v${esc(m.revision_number)} | Q=${esc(m.quarantine_status)}]</div>
                <div>${esc(m.statement_text)}</div>
              </div>
            `).join("") : `<div class="muted">No active memory rows for this contact.</div>`}
          </div>
          <div class="row-actions">
            <input id="correctMemInput" type="text" placeholder="Enter non-destructive memory correction statement..." style="flex:1;" />
            <button id="correctMemBtn" type="button">Correct Memory</button>
            <button id="releaseQuarBtn" class="secondary" type="button">Release Quarantine</button>
            <button id="deleteMemBtn" class="danger" type="button">Delete Memory</button>
          </div>
        </div>
      `;
      document.querySelectorAll("#tab-memories .item-row").forEach((el) => {
        el.addEventListener("click", () => {
          selectedMemoryId = el.getAttribute("data-mid");
          renderRightTabs();
        });
      });
      const cmBtn = $("correctMemBtn");
      if (cmBtn) {
        cmBtn.addEventListener("click", async () => {
          if (!selectedMemoryId) return;
          const stmt = $("correctMemInput").value.trim();
          if (!stmt) return;
          await api("/v1/web/memory", {
            method: "POST",
            body: JSON.stringify({ action: "CORRECT_MEMORY", memory_id: selectedMemoryId, statement: stmt }),
          });
          await loadState();
        });
      }
      const rqBtn = $("releaseQuarBtn");
      if (rqBtn) {
        rqBtn.addEventListener("click", async () => {
          if (!selectedMemoryId) return;
          await api("/v1/web/memory", {
            method: "POST",
            body: JSON.stringify({ action: "RELEASE_QUARANTINE", memory_id: selectedMemoryId }),
          });
          await loadState();
        });
      }
      const dmBtn = $("deleteMemBtn");
      if (dmBtn) {
        dmBtn.addEventListener("click", async () => {
          if (!selectedMemoryId) return;
          await api("/v1/web/memory", {
            method: "POST",
            body: JSON.stringify({ action: "DELETE_MEMORY", memory_id: selectedMemoryId }),
          });
          selectedMemoryId = null;
          await loadState();
        });
      }
    }

    // Pairing & Neural AI tab
    const devs = state.paired_devices || [];
    const gwUrl = state.windows_host_endpoint || "https://10.7.155.45:8443";
    $("tab-pairing").innerHTML = `
      <div style="display:flex; flex-direction:column; gap:10px;">
        <div class="pillar-card">
          <h3>Legion 5 Pro Endpoints &amp; Android Companion</h3>
          <div class="kv-row"><span>LAN HTTPS/TLS 1.3 Gateway</span><code>${esc(gwUrl)}</code></div>
          <div class="kv-row"><span>Android APK Download</span><a class="apk-link" href="/download/apk">${esc(gwUrl)}/download/apk</a></div>
          <div class="kv-row"><span>TLS SHA-256 Fingerprint</span><code>${esc(state.windows_tls_cert_sha256)}</code></div>
          <div class="kv-row"><span>Local Neural Engine</span><code>${state.neural_ai_online ? "http://127.0.0.1:8089 (Qwen2.5-3B Vulkan ONLINE)" : "Tier-0 Fallback"}</code></div>
        </div>
        <div class="pillar-card">
          <h3>Paired Devices (${devs.length})</h3>
          ${devs.length ? devs.map((d) => `
            <div class="kv-row">
              <span>${esc(d.device_name)} [${esc(d.trust_status)}]</span>
              <code>${esc(String(d.device_id).slice(0, 12))}... | ${esc(d.paired_at_utc)}</code>
            </div>
          `).join("") : `<div class="muted">No devices paired yet. Install PSYCHE-AI-Companion.apk on your phone and tap Start Pairing.</div>`}
          <div class="row-actions">
            <button id="genPairingBtn" type="button">Generate Pairing Session</button>
          </div>
          ${activePairingQr ? `
            <pre class="pillar-json" style="margin-top:8px;">Session: ${esc(activePairingQr.pairing_session_id)}
Expires: ${esc(activePairingQr.expires_at_utc)}</pre>
          ` : ""}
        </div>
      </div>
    `;
    const gpBtn = $("genPairingBtn");
    if (gpBtn) {
      gpBtn.addEventListener("click", async () => {
        activePairingQr = await api("/v1/pair/init", { method: "POST", body: "{}" });
        renderRightTabs();
      });
    }
  }

  function renderReplyStudio() {
    const sel = $("candidateSelect");
    const ed = $("replyEditor");
    const pkt = state.synthesis_packet;
    if (privacyBlur) {
      sel.innerHTML = `<option>[HIDDEN BY PRIVACY BLUR]</option>`;
      ed.value = "[HIDDEN BY PRIVACY BLUR — SHA-256 VERIFIED]";
      return;
    }
    const cands = pkt?.goal_aware_recommendations?.reply_candidates || [];
    if (!cands.length) {
      sel.innerHTML = `<option>No reply candidates generated yet</option>`;
      ed.value = "";
      return;
    }
    sel.innerHTML = cands.map((c, idx) => {
      const label = c.strategy_label || c.tone_label || `Draft ${idx + 1}`;
      const dna = Number(c.comm_dna_match_score ?? c.dna_authenticity_score ?? 0).toFixed(2);
      return `<option value="${idx}">${esc(label)} (DNA=${dna})</option>`;
    }).join("");
    ed.value = cands[0].draft_text || "";
    sel.onchange = () => {
      const c = cands[Number(sel.value)];
      if (c) ed.value = c.draft_text || "";
    };
  }

  // Event Bindings
  document.querySelectorAll(".tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeTab = btn.getAttribute("data-tab");
      document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("active", b === btn));
      document.querySelectorAll(".tab-pane").forEach((p) => {
        p.style.display = p.id === `tab-${activeTab}` ? "block" : "none";
      });
    });
  });

  $("blurBtn").addEventListener("click", () => {
    privacyBlur = !privacyBlur;
    $("blurBtn").textContent = privacyBlur ? "Privacy Blur: ON" : "Privacy Blur: OFF";
    render();
  });

  $("refreshBtn").addEventListener("click", () => loadState());

  $("panicBtn").addEventListener("click", async () => {
    await api("/v1/web/vault", { method: "POST", body: JSON.stringify({ action: "PANIC_LOCK" }) });
    await loadState();
  });

  $("unlockBtn").addEventListener("click", async () => {
    await api("/v1/web/vault", { method: "POST", body: JSON.stringify({ action: "UNLOCK" }) });
    await loadState();
  });

  $("analyzeBtn").addEventListener("click", async () => {
    const sender = $("manualSender").value.trim() || "Manual Contact";
    const rawText = $("manualText").value.trim();
    const tier = $("manualTier").value;
    if (!rawText) return;
    $("analyzeBtn").disabled = true;
    $("analyzeBtn").textContent = "Synthesizing...";
    try {
      const pkt = await api("/v1/web/analyze", {
        method: "POST",
        body: JSON.stringify({ sender_name: sender, raw_text: rawText, relationship_tier: tier }),
      });
      selectedPersonId = pkt.person_id;
      $("manualText").value = "";
      await loadState(selectedPersonId);
    } finally {
      $("analyzeBtn").disabled = false;
      $("analyzeBtn").textContent = "Analyze Message (Local Neural Core)";
    }
  });

  $("approveCopyBtn").addEventListener("click", async () => {
    const pkt = state?.synthesis_packet;
    const text = $("replyEditor").value.trim();
    if (!pkt || !text) return;
    const cands = pkt.goal_aware_recommendations?.reply_candidates || [];
    const chosen = cands[Number($("candidateSelect").value)] || {};
    const decision = text === (chosen.draft_text || "").trim() ? "ACCEPTED_AS_IS" : "EDITED_BY_USER";
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text).catch(() => {});
    }
    await api(`/v1/syntheses/${encodeURIComponent(pkt.synthesis_id)}/review`, {
      method: "POST",
      body: JSON.stringify({ decision, user_final_edited_text: text }),
    });
    $("reviewStatus").textContent = `Decision recorded (${decision}) & copied to clipboard for manual send.`;
  });

  $("rejectBtn").addEventListener("click", async () => {
    const pkt = state?.synthesis_packet;
    if (!pkt) return;
    await api(`/v1/syntheses/${encodeURIComponent(pkt.synthesis_id)}/review`, {
      method: "POST",
      body: JSON.stringify({ decision: "REJECTED" }),
    });
    $("reviewStatus").textContent = "Draft rejected by user; nothing copied or sent.";
  });

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${location.host}/v1/ws/events`);
    ws.onmessage = () => loadState().catch(() => {});
    ws.onclose = () => setTimeout(connectWs, 3000);
  }

  loadState();
  connectWs();
})();
</script>
</body>
</html>
"""
