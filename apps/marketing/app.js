import { BENCHMARK_SERVERS, BENCHMARK_SUMMARY, PRESET_SCHEMAS } from './benchmark-data.js';

// State
let currentTools = PRESET_SCHEMAS.stripe_payment.tools;
let activeWreckIndex = 0;
let wreckInterval = null;

// Disaster Wreck Scenarios
const WRECKS = [
  {
    id: "double-charge",
    tag: "WRECK 01",
    title: "The $340 Double-Charge",
    subtitle: "Transient network timeout triggers un-idempotent retry storm",
    vetoClass: "VETO_STATE_CORRUPTION",
    checkId: "TC-IDEMP-001 / TC-IDEMP-002",
    financialLoss: "$340.00",
    lossLabel: "Direct Customer Overcharge",
    affectedRate: "100% of tested servers",
    steps: [
      { sender: "Agent", text: "Calling create_payment_intent({ amount: 3400, customer: 'cus_9a2b' })...", status: "pending" },
      { sender: "Network", text: "Gateway timeout (504) after 4000ms. Socket drop.", status: "warn" },
      { sender: "Agent", text: "Timeout encountered. Retrying transaction attempt #2...", status: "pending" },
      { sender: "Server", text: "Charge 1 succeeded: ch_101 ($34.00). Charge 2 created: ch_102 ($34.00)!", status: "error" },
      { sender: "ToolVeto", text: "CRITICAL VETO: Sequential replay detected without idempotencyKey. Merge Blocked.", status: "veto" }
    ],
    codeDiff: `// ToolVeto Fix (FastMCP / Zod):
+ idempotencyKey: z.string().uuid().describe("Unique token preventing duplicate charges on retry"),
+ if (await cache.has(idempotencyKey)) return cache.get(idempotencyKey);`
  },
  {
    id: "runaway-loop",
    tag: "WRECK 02",
    title: "The 47× Runaway Retry Loop",
    subtitle: "Raw 500 error string leaves LLM blind; repeating identical call 47 times",
    vetoClass: "VETO_PANIC",
    checkId: "TC-FUZZ-001 / TC-ERR-001",
    financialLoss: "$28.40",
    lossLabel: "Wasted LLM Token Budget",
    affectedRate: "140,000 Tokens Burned",
    steps: [
      { sender: "Agent", text: "Calling schedule_meeting({ date: 'tomorrow morning', user: 'u_89' })...", status: "pending" },
      { sender: "Server", text: "500 Internal Server Error: TypeError: Cannot read property 'split' of undefined at parseDate()", status: "error" },
      { sender: "Agent", text: "Error gave no parameter context. Retrying: schedule_meeting({ date: 'tomorrow morning' })... (Attempt 2/47)", status: "warn" },
      { sender: "Server", text: "500 Internal Server Error (Identical stack trace repeated 47 times until token window exhausted)", status: "error" },
      { sender: "ToolVeto", text: "CRITICAL VETO: Error response lacks parameter citation and self-correction format. Merge Blocked.", status: "veto" }
    ],
    codeDiff: `// ToolVeto Fix: Structured Self-Correction Error
- return { error: err.stack };
+ return {
+   isError: true,
+   content: [{ type: "text", text: "Invalid parameter 'date': Value 'tomorrow morning' is not ISO-8601. Example: '2026-10-15T09:00:00Z'." }]
+ };`
  },
  {
    id: "context-bomb",
    tag: "WRECK 03",
    title: "The 57,000-Token Context Bomb",
    subtitle: "Unbounded query dumps 2,400 rows into prompt context, wiping agent memory",
    vetoClass: "VETO_DATALOSS",
    checkId: "TC-CTX-001 / TC-SCHEMA-003",
    financialLoss: "100%",
    lossLabel: "Context Window Memory Eviction",
    affectedRate: "90% of tested servers",
    steps: [
      { sender: "Agent", text: "Calling list_customers({ status: 'active' }) to find single customer email...", status: "pending" },
      { sender: "Server", text: "Streaming 2,480 customer JSON objects (412 KB payload, ~57,200 tokens)...", status: "warn" },
      { sender: "LLM", text: "Context limit exceeded! Older system instructions and tool schemas truncated.", status: "error" },
      { sender: "Agent", text: "Reasoning corrupted. Hallucinating tool names and arguments.", status: "error" },
      { sender: "ToolVeto", text: "CRITICAL VETO: Collection tool 'list_customers' lacks pagination bounds (limit/max_results). Merge Blocked.", status: "veto" }
    ],
    codeDiff: `// ToolVeto Fix: Strict Pagination Window
  inputSchema: {
    type: "object",
    properties: {
+     limit: z.number().int().min(1).max(100).default(25).describe("Max items to protect LLM context"),
+     cursor: z.string().optional().describe("Pagination cursor token")
    }
  }`
  }
];

// In-Browser Evaluation Engine (Pure Client-Side Implementation of ToolVeto Checks)
export function evaluateToolsLocally(tools) {
  if (!tools || !Array.isArray(tools) || tools.length === 0) {
    return {
      score: 0,
      tier: "REJECTED",
      vetoTriggered: true,
      vetoReason: "No tools found in schema manifest",
      dimensions: { d1: 0, d2: 0, d3: 0, d4: 0, d5: 0 },
      findings: [{ level: "CRITICAL", id: "TC-SCHEMA-002", tool: "all", message: "Empty tool collection" }],
      fixes: []
    };
  }

  const findings = [];
  const fixes = [];
  let hasCriticalVeto = false;
  let vetoReason = "";

  const mutationKeywords = ["create", "update", "delete", "post", "send", "charge", "refund", "execute", "run", "deploy", "purge", "write", "insert", "drop"];
  const collectionKeywords = ["list", "search", "find", "get_all", "query", "scan", "fetch_all"];

  const toolNames = tools.map(t => t.name || "");

  let d1Score = 100;
  let d2Score = 80;
  let d3Score = 100;
  let d4Score = 90;
  let d5Score = 100;

  for (const tool of tools) {
    const name = tool.name || "unnamed_tool";
    const lowerName = name.toLowerCase();
    const isMutation = mutationKeywords.some(kw => lowerName.includes(kw));
    const isCollection = collectionKeywords.some(kw => lowerName.includes(kw));
    const schema = tool.inputSchema || {};
    const props = schema.properties || {};
    const propKeys = Object.keys(props);

    // D1 Checks: Idempotency
    if (isMutation) {
      const hasIdempotencyKey = propKeys.some(k => {
        const lk = k.toLowerCase();
        return lk.includes("idemp") || lk === "client_request_token" || lk === "client_msg_id" || lk === "request_id";
      });

      if (!hasIdempotencyKey) {
        hasCriticalVeto = true;
        vetoReason = `Mutation tool '${name}' lacks idempotency key parameter (TC-IDEMP-003)`;
        d1Score = Math.min(d1Score, 20);
        findings.push({
          level: "CRITICAL",
          id: "TC-IDEMP-003",
          tool: name,
          message: `Missing explicit idempotency key in schema definition for mutation tool '${name}'. Susceptible to duplicate charges/operations on agent timeout.`
        });
        fixes.push({
          tool: name,
          issue: "Missing idempotency key parameter",
          diff: `+ idempotency_key: z.string().uuid().describe("Unique token preventing duplicate mutations on retry")`
        });
      }

      // D5 Check: State Auditability & Pairing
      const companionRead = toolNames.some(other => {
        const lOther = other.toLowerCase();
        return (lOther.startsWith("get_") || lOther.startsWith("read_") || lOther.startsWith("inspect_")) &&
          (lOther.includes(lowerName.replace(/^(create_|update_|delete_)/, "")) || lowerName.includes(lOther.replace(/^(get_|read_)/, "")));
      });

      if (!companionRead) {
        d5Score = Math.min(d5Score, 30);
        findings.push({
          level: "HIGH",
          id: "TC-PAIR-001",
          tool: name,
          message: `Mutation tool '${name}' lacks companion inspection query tool. Agents cannot verify pre/post state changes.`
        });
        fixes.push({
          tool: name,
          issue: "Missing companion inspection read tool",
          diff: `+ // Register companion read tool for verification\n+ server.tool("get_${name.replace(/^(create_|update_)/, "")}", { id: z.string() }, async ({ id }) => ...);`
        });
      }
    }

    // D3 Checks: Context Hygiene & Pagination
    if (isCollection) {
      const hasPagination = propKeys.some(k => {
        const lk = k.toLowerCase();
        return lk.includes("limit") || lk.includes("pagesize") || lk.includes("max_results") || lk.includes("per_page") || lk === "count";
      });

      if (!hasPagination) {
        hasCriticalVeto = true;
        vetoReason = `Collection tool '${name}' lacks pagination bounds (TC-CTX-001 / Context Bomb)`;
        d3Score = Math.min(d3Score, 50);
        findings.push({
          level: "CRITICAL",
          id: "TC-CTX-001",
          tool: name,
          message: `Collection query tool '${name}' exposes no pagination parameters. May return thousands of rows, evicting LLM context.`
        });
        fixes.push({
          tool: name,
          issue: "Unbounded collection query (Context Bomb)",
          diff: `+ limit: z.number().int().min(1).max(100).default(25).describe("Max rows returned to protect LLM context"),\n+ cursor: z.string().optional().describe("Cursor token for forward pagination")`
        });
      }
    }

    // Schema Ergonomics (TC-SCHEMA-001)
    for (const [propName, propDef] of Object.entries(props)) {
      if (!propDef.description || propDef.description.trim().length === 0) {
        d3Score = Math.min(d3Score, 75);
        findings.push({
          level: "MEDIUM",
          id: "TC-SCHEMA-001",
          tool: `${name}.${propName}`,
          message: `Field '${propName}' in tool '${name}' has no description. Degrades agent tool-selection precision.`
        });
      }
    }
  }

  // Calculate composite score
  const baseScore = Math.round(
    d1Score * 0.30 +
    d2Score * 0.25 +
    d3Score * 0.25 +
    d4Score * 0.10 +
    d5Score * 0.10
  );

  const phi = hasCriticalVeto ? 0.4 : 1.0;
  const finalScore = Math.round(baseScore * phi);

  let tier = "REJECTED";
  if (!hasCriticalVeto) {
    if (finalScore >= 90) tier = "PLATINUM";
    else if (finalScore >= 80) tier = "GOLD";
    else if (finalScore >= 70) tier = "SILVER";
    else if (finalScore >= 60) tier = "BRONZE";
  }

  return {
    score: finalScore,
    tier,
    vetoTriggered: hasCriticalVeto,
    vetoReason,
    dimensions: {
      d1: d1Score,
      d2: d2Score,
      d3: d3Score,
      d4: d4Score,
      d5: d5Score
    },
    findings,
    fixes
  };
}

// UI Initialization
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    initHeroCopyTabs();
    initDisasterPlayer();
    initPlayground();
    initBenchmarkGrid();
    initDiffModal();
    initStatsCounters();
    initHeroChaosCanvas();
    initHeroFlightDeck();
    initWaveformOscilloscope();
    initAudioSynthesizer();
    initBentoSpotlight();
    initRoiSlider();
  });
}

// 1. Hero Terminal Copy Tabs
function initHeroCopyTabs() {
  const tabs = document.querySelectorAll(".cmd-tab");
  const cmdText = document.getElementById("hero-cmd-text");
  const copyBtn = document.getElementById("hero-copy-btn");

  const commands = {
    npx: "npx toolveto@latest check stdio://path/to/server",
    pnpm: "pnpm dlx toolveto check stdio://path/to/server",
    docker: "docker run --rm -v $(pwd):/app ghcr.io/toolveto/toolveto check /app",
    action: `name: ToolVeto Crash Test
on: [pull_request]
jobs:
  crash-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: toolveto/action@v1
        with:
          server: "stdio://./dist/index.js"`
  };

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const key = tab.dataset.cmd;
      if (cmdText && commands[key]) {
        cmdText.textContent = commands[key];
      }
    });
  });

  if (copyBtn && cmdText) {
    copyBtn.addEventListener("click", () => {
      navigator.clipboard.writeText(cmdText.textContent).then(() => {
        const originalHTML = copyBtn.innerHTML;
        copyBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
          <span>COPIED!</span>
        `;
        copyBtn.classList.add("copied");
        setTimeout(() => {
          copyBtn.innerHTML = originalHTML;
          copyBtn.classList.remove("copied");
        }, 2000);
      });
    });
  }
}

// 2. Interactive Disaster Replay Player (Beat 2)
function initDisasterPlayer() {
  const tabs = document.querySelectorAll(".disaster-nav-btn");
  const displayTitle = document.getElementById("wreck-title");
  const displaySubtitle = document.getElementById("wreck-subtitle");
  const displayTag = document.getElementById("wreck-tag");
  const displayLoss = document.getElementById("wreck-loss");
  const displayLossLabel = document.getElementById("wreck-loss-label");
  const displayVeto = document.getElementById("wreck-veto-badge");
  const displayCheck = document.getElementById("wreck-check-id");
  const chatLogs = document.getElementById("wreck-chat-logs");
  const codeDiff = document.getElementById("wreck-code-diff");

  function renderWreck(index) {
    activeWreckIndex = index;
    const w = WRECKS[index];
    if (!w) return;

    tabs.forEach((tab, i) => {
      tab.classList.toggle("active", i === index);
    });

    if (displayTitle) displayTitle.textContent = w.title;
    if (displaySubtitle) displaySubtitle.textContent = w.subtitle;
    if (displayTag) displayTag.textContent = w.tag;
    if (displayLoss) displayLoss.textContent = w.financialLoss;
    if (displayLossLabel) displayLossLabel.textContent = w.lossLabel;
    if (displayVeto) displayVeto.textContent = w.vetoClass;
    if (displayCheck) displayCheck.textContent = w.checkId;
    if (codeDiff) codeDiff.textContent = w.codeDiff;

    if (chatLogs) {
      chatLogs.innerHTML = "";
      w.steps.forEach((step, idx) => {
        const div = document.createElement("div");
        div.className = `wreck-step status-${step.status}`;
        div.style.animationDelay = `${idx * 120}ms`;
        div.innerHTML = `
          <div class="step-sender">${step.sender}</div>
          <div class="step-bubble">${step.text}</div>
        `;
        chatLogs.appendChild(div);
      });
    }
  }

  tabs.forEach((tab, idx) => {
    tab.addEventListener("click", () => {
      renderWreck(idx);
    });
  });

  renderWreck(0);
}

// 3. Interactive Playground (Beat 3)
function initPlayground() {
  const presetBtns = document.querySelectorAll(".preset-btn");
  const schemaEditor = document.getElementById("schema-editor-textarea");
  const runBtn = document.getElementById("run-lint-btn");

  const scoreNum = document.getElementById("pg-score-number");
  const tierBadge = document.getElementById("pg-tier-badge");
  const vetoAlert = document.getElementById("pg-veto-alert");
  const vetoReason = document.getElementById("pg-veto-reason");

  const barD1 = document.getElementById("pg-bar-d1");
  const barD2 = document.getElementById("pg-bar-d2");
  const barD3 = document.getElementById("pg-bar-d3");
  const barD4 = document.getElementById("pg-bar-d4");
  const barD5 = document.getElementById("pg-bar-d5");

  const valD1 = document.getElementById("pg-val-d1");
  const valD2 = document.getElementById("pg-val-d2");
  const valD3 = document.getElementById("pg-val-d3");
  const valD4 = document.getElementById("pg-val-d4");
  const valD5 = document.getElementById("pg-val-d5");

  const findingsContainer = document.getElementById("pg-findings-list");
  const fixDiffContainer = document.getElementById("pg-fix-diff");

  function runAudit() {
    let parsed = null;
    try {
      parsed = JSON.parse(schemaEditor.value);
    } catch (e) {
      alert("Invalid JSON format in schema editor: " + e.message);
      return;
    }

    const tools = Array.isArray(parsed) ? parsed : (parsed.tools || [parsed]);
    const res = evaluateToolsLocally(tools);

    // Update Score & Tier
    if (scoreNum) scoreNum.textContent = res.score;
    if (tierBadge) {
      tierBadge.textContent = res.tier;
      tierBadge.className = `tier-badge tier-${res.tier.toLowerCase()}`;
    }

    // Update VETO Alert Banner
    if (vetoAlert && vetoReason) {
      if (res.vetoTriggered) {
        vetoAlert.classList.remove("hidden");
        vetoReason.textContent = res.vetoReason;
      } else {
        vetoAlert.classList.add("hidden");
      }
    }

    // Update Dimensional Bars
    if (barD1 && valD1) { barD1.style.width = `${res.dimensions.d1}%`; valD1.textContent = `${res.dimensions.d1}/100`; }
    if (barD2 && valD2) { barD2.style.width = `${res.dimensions.d2}%`; valD2.textContent = `${res.dimensions.d2}/100`; }
    if (barD3 && valD3) { barD3.style.width = `${res.dimensions.d3}%`; valD3.textContent = `${res.dimensions.d3}/100`; }
    if (barD4 && valD4) { barD4.style.width = `${res.dimensions.d4}%`; valD4.textContent = `${res.dimensions.d4}/100`; }
    if (barD5 && valD5) { barD5.style.width = `${res.dimensions.d5}%`; valD5.textContent = `${res.dimensions.d5}/100`; }

    // Update Findings List
    if (findingsContainer) {
      findingsContainer.innerHTML = "";
      if (res.findings.length === 0) {
        findingsContainer.innerHTML = `<div class="pass-note">All 12 stateful chaos invariants passed! Zero vetoes triggered.</div>`;
      } else {
        res.findings.forEach(f => {
          const item = document.createElement("div");
          item.className = `finding-item level-${f.level.toLowerCase()}`;
          item.innerHTML = `
            <span class="finding-badge">${f.level}</span>
            <span class="finding-id">${f.id}</span>
            <span class="finding-tool">${f.tool}</span>
            <div class="finding-msg">${f.message}</div>
          `;
          findingsContainer.appendChild(item);
        });
      }
    }

    // Update Actionable Fix Diff
    if (fixDiffContainer) {
      if (res.fixes.length > 0) {
        fixDiffContainer.textContent = res.fixes.map(f => `// Fix for ${f.tool} (${f.issue}):\n${f.diff}`).join("\n\n");
      } else {
        fixDiffContainer.textContent = "// No schema fixes needed! Your tool contracts meet 100/100 Platinum Tier standards.";
      }
    }
  }

  presetBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      presetBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      const key = btn.dataset.preset;
      if (PRESET_SCHEMAS[key]) {
        schemaEditor.value = JSON.stringify(PRESET_SCHEMAS[key].tools, null, 2);
        runAudit();
      }
    });
  });

  if (runBtn) {
    runBtn.addEventListener("click", runAudit);
  }

  // Initial load
  if (schemaEditor) {
    schemaEditor.value = JSON.stringify(PRESET_SCHEMAS.stripe_payment.tools, null, 2);
    runAudit();
  }
}

// 4. Benchmark Grid (Beat 4: The 10-Server Wall)
function initBenchmarkGrid() {
  const grid = document.getElementById("benchmark-cards-grid");
  const filterInput = document.getElementById("benchmark-search-input");
  if (!grid) return;

  function renderCards(filterText = "") {
    grid.innerHTML = "";
    const filtered = BENCHMARK_SERVERS.filter(s =>
      s.name.toLowerCase().includes(filterText.toLowerCase()) ||
      s.repo.toLowerCase().includes(filterText.toLowerCase()) ||
      s.category.toLowerCase().includes(filterText.toLowerCase())
    );

    filtered.forEach(s => {
      const card = document.createElement("div");
      card.className = "benchmark-card";
      card.innerHTML = `
        <div class="card-header">
          <div class="repo-meta">
            <span class="repo-category">${s.category}</span>
            <h4 class="repo-name">${s.name}</h4>
            <a href="https://github.com/${s.repo}" target="_blank" rel="noreferrer" class="repo-link">${s.repo}</a>
          </div>
          <div class="stars-badge">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg>
            ${s.stars}
          </div>
        </div>
        
        <div class="score-row">
          <div class="score-pill">
            <span class="score-val">${s.score}</span>
            <span class="score-denom">/100</span>
          </div>
          <span class="tier-pill tier-${s.tier.toLowerCase()}">${s.tier}</span>
          <span class="gate-pill">CI: ${s.ciGate} (${s.criticalFailures} Crit)</span>
        </div>

        <div class="dim-micro-bars">
          <div class="micro-bar-col" title="D1 Idempotency: ${s.dimensions.d1}%">
            <span class="dim-label">D1</span>
            <div class="micro-track"><div class="micro-fill" style="height: ${s.dimensions.d1}%"></div></div>
          </div>
          <div class="micro-bar-col" title="D2 Errors: ${s.dimensions.d2}%">
            <span class="dim-label">D2</span>
            <div class="micro-track"><div class="micro-fill" style="height: ${s.dimensions.d2}%"></div></div>
          </div>
          <div class="micro-bar-col" title="D3 Context: ${s.dimensions.d3}%">
            <span class="dim-label">D3</span>
            <div class="micro-track"><div class="micro-fill" style="height: ${s.dimensions.d3}%"></div></div>
          </div>
          <div class="micro-bar-col" title="D4 Bounds: ${s.dimensions.d4}%">
            <span class="dim-label">D4</span>
            <div class="micro-track"><div class="micro-fill" style="height: ${s.dimensions.d4}%"></div></div>
          </div>
          <div class="micro-bar-col" title="D5 Audit: ${s.dimensions.d5}%">
            <span class="dim-label">D5</span>
            <div class="micro-track"><div class="micro-fill" style="height: ${s.dimensions.d5}%"></div></div>
          </div>
        </div>

        <div class="issue-box">
          <strong>Primary Vulnerability:</strong>
          <p>${s.keyIssue}</p>
        </div>

        <div class="card-footer">
          <button class="open-pr-btn" data-server-id="${s.id}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"></circle><circle cx="6" cy="6" r="3"></circle><path d="M13 6h3a2 2 0 0 1 2 2v7"></path><line x1="6" y1="9" x2="6" y2="21"></line></svg>
            Inspect PR Diff
          </button>
        </div>
      `;
      grid.appendChild(card);
    });

    // Attach click listeners to "Inspect PR Diff"
    document.querySelectorAll(".open-pr-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const serverId = btn.dataset.serverId;
        const target = BENCHMARK_SERVERS.find(s => s.id === serverId);
        if (target) openDiffModal(target);
      });
    });
  }

  if (filterInput) {
    filterInput.addEventListener("input", (e) => {
      renderCards(e.target.value);
    });
  }

  renderCards();
}

// 5. PR Diff Modal Viewer
let activeModalServer = null;

function openDiffModal(server) {
  activeModalServer = server;
  const modal = document.getElementById("diff-modal");
  const modalTitle = document.getElementById("modal-repo-name");
  const modalPrTitle = document.getElementById("modal-pr-title");
  const modalDiffText = document.getElementById("modal-diff-content");
  const modalSummary = document.getElementById("modal-summary-text");

  if (!modal) return;

  if (modalTitle) modalTitle.textContent = `${server.name} (${server.repo})`;
  if (modalPrTitle) modalPrTitle.textContent = server.prTitle;
  if (modalDiffText) modalDiffText.textContent = server.diffSnippet;
  if (modalSummary) {
    modalSummary.innerHTML = `
      <p><strong>Evaluated Score:</strong> <span class="score-highlight">${server.score}/100</span> [Tier: ${server.tier}]</p>
      <p><strong>CI Merge Gate:</strong> <strong style="color: #ff4757;">🔴 ${server.ciGate} (${server.criticalFailures} Critical Failures)</strong></p>
      <p><strong>Fatal Veto Code:</strong> <code>${server.criticalVeto}</code></p>
      <p><strong>Root Cause:</strong> ${server.keyIssue}</p>
      <p><strong>Prepared Patch Manifest:</strong> <code>${server.prArtifact}</code></p>
    `;
  }

  modal.classList.add("open");
  document.body.style.overflow = "hidden";
}

function initDiffModal() {
  const modal = document.getElementById("diff-modal");
  const closeBtn = document.getElementById("modal-close-btn");
  const copyDiffBtn = document.getElementById("modal-copy-diff-btn");
  const backdrop = document.getElementById("modal-backdrop");

  function closeModal() {
    if (modal) modal.classList.remove("open");
    document.body.style.overflow = "";
  }

  if (closeBtn) closeBtn.addEventListener("click", closeModal);
  if (backdrop) backdrop.addEventListener("click", closeModal);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && modal && modal.classList.contains("open")) {
      closeModal();
    }
  });

  if (copyDiffBtn) {
    copyDiffBtn.addEventListener("click", () => {
      if (activeModalServer) {
        navigator.clipboard.writeText(activeModalServer.diffSnippet).then(() => {
          const originalText = copyDiffBtn.textContent;
          copyDiffBtn.textContent = "COPIED TO CLIPBOARD!";
          setTimeout(() => { copyDiffBtn.textContent = originalText; }, 2000);
        });
      }
    });
  }
}

// 6. Animated Metric Counters
function initStatsCounters() {
  const statNumbers = document.querySelectorAll(".stat-counter");
  statNumbers.forEach(stat => {
    const target = parseFloat(stat.dataset.target || 0);
    const isCurrency = stat.dataset.prefix === "$";
    const isPercent = stat.dataset.suffix === "%";
    let current = 0;
    const increment = target / 30;

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        current = target;
        clearInterval(timer);
      }
      let formatted = Math.round(current);
      if (isCurrency) formatted = `$${formatted}`;
      if (isPercent) formatted = `${formatted}%`;
      stat.textContent = formatted;
    }, 40);
  });
}

// 7. Hero Interactive Chaos Particle Canvas
let chaosCanvasBurst = null;

function initHeroChaosCanvas() {
  const canvas = document.getElementById("chaos-particle-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const parent = canvas.parentElement;
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = (parent && parent.offsetHeight) ? parent.offsetHeight : 750);

  function onResize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = (parent && parent.offsetHeight) ? parent.offsetHeight : 750;
  }
  window.addEventListener("resize", onResize);

  let mouse = { x: -9999, y: -9999, radius: 130 };
  window.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    mouse.x = e.clientX - rect.left;
    mouse.y = e.clientY - rect.top;
  });
  window.addEventListener("mouseleave", () => {
    mouse.x = -9999;
    mouse.y = -9999;
  });

  // Particle pool
  const particles = [];
  const PARTICLE_COUNT = 45;

  class Packet {
    constructor() {
      this.reset();
    }
    reset() {
      this.x = Math.random() * (width * 0.45);
      this.y = Math.random() * height;
      this.vx = 1.2 + Math.random() * 2.2;
      this.vy = (Math.random() - 0.5) * 0.8;
      this.radius = 2.5 + Math.random() * 2.5;
      this.isChaos = Math.random() > 0.45;
      this.color = this.isChaos ? "#ff3355" : "#00f5a0";
      this.glowColor = this.isChaos ? "rgba(255, 51, 85, 0.4)" : "rgba(0, 245, 160, 0.4)";
      this.alpha = 0.4 + Math.random() * 0.6;
      this.history = [];
    }
    update() {
      // Mouse magnetic repel
      const dx = mouse.x - this.x;
      const dy = mouse.y - this.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < mouse.radius && dist > 0) {
        const force = (mouse.radius - dist) / mouse.radius;
        this.x -= (dx / dist) * force * 5;
        this.y -= (dy / dist) * force * 5;
      }

      this.x += this.vx;
      this.y += this.vy;

      // History trail
      this.history.push({ x: this.x, y: this.y });
      if (this.history.length > 5) this.history.shift();

      // Shield barrier collision at width * 0.58
      const barrierX = width * 0.58;
      if (this.isChaos && this.x >= barrierX - 25 && this.x <= barrierX + 15) {
        // Veto deflection!
        this.vx = -Math.abs(this.vx) * 0.8;
        this.alpha *= 0.6;
        triggerSpark(this.x, this.y, this.color);
      }

      // Reset when off bounds
      if (this.x > width + 40 || this.x < -40 || this.y < -40 || this.y > height + 40 || this.alpha < 0.1) {
        this.reset();
      }
    }
    draw() {
      // Trail
      if (this.history.length > 1) {
        ctx.beginPath();
        ctx.moveTo(this.history[0].x, this.history[0].y);
        for (let i = 1; i < this.history.length; i++) {
          ctx.lineTo(this.history[i].x, this.history[i].y);
        }
        ctx.strokeStyle = this.glowColor;
        ctx.lineWidth = this.radius * 0.7;
        ctx.stroke();
      }

      // Packet head
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = this.color;
      ctx.shadowBlur = 10;
      ctx.shadowColor = this.color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }
  }

  for (let i = 0; i < PARTICLE_COUNT; i++) {
    particles.push(new Packet());
  }

  // Sparks array for VETO impacts
  const sparks = [];
  function triggerSpark(x, y, color) {
    for (let i = 0; i < 6; i++) {
      const angle = Math.random() * Math.PI * 2;
      const speed = 1.2 + Math.random() * 3.2;
      sparks.push({
        x,
        y,
        vx: Math.cos(angle) * speed,
        vy: Math.sin(angle) * speed,
        radius: 1.5,
        color,
        life: 1.0
      });
    }
  }

  chaosCanvasBurst = function() {
    const burstX = width * 0.58;
    const burstY = height * 0.45;
    for (let i = 0; i < 35; i++) {
      triggerSpark(burstX + (Math.random() - 0.5) * 50, burstY + (Math.random() - 0.5) * 100, "#ff3355");
    }
  };

  let isVisible = true;
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(([entry]) => {
      isVisible = entry.isIntersecting;
    }, { threshold: 0.1 });
    observer.observe(canvas);
  }

  function animate() {
    if (isVisible) {
      ctx.clearRect(0, 0, width, height);

      // Draw subtle defensive shield barrier
      const barrierX = width * 0.58;
      const grad = ctx.createLinearGradient(0, 0, 0, height);
      grad.addColorStop(0, "rgba(255, 122, 0, 0)");
      grad.addColorStop(0.3, "rgba(255, 122, 0, 0.2)");
      grad.addColorStop(0.5, "rgba(255, 51, 85, 0.35)");
      grad.addColorStop(0.7, "rgba(255, 122, 0, 0.2)");
      grad.addColorStop(1, "rgba(255, 122, 0, 0)");

      ctx.beginPath();
      ctx.moveTo(barrierX, 60);
      ctx.quadraticCurveTo(barrierX + 35, height * 0.5, barrierX, height - 60);
      ctx.strokeStyle = grad;
      ctx.lineWidth = 2.5;
      ctx.setLineDash([6, 6]);
      ctx.stroke();
      ctx.setLineDash([]);

      // Update & draw packets
      for (const p of particles) {
        p.update();
        p.draw();
      }

      // Update & draw sparks
      for (let i = sparks.length - 1; i >= 0; i--) {
        const s = sparks[i];
        s.x += s.vx;
        s.y += s.vy;
        s.life -= 0.04;
        if (s.life <= 0) {
          sparks.splice(i, 1);
          continue;
        }
        ctx.beginPath();
        ctx.arc(s.x, s.y, s.radius * s.life, 0, Math.PI * 2);
        ctx.fillStyle = s.color;
        ctx.globalAlpha = s.life;
        ctx.fill();
        ctx.globalAlpha = 1.0;
      }
    }
    requestAnimationFrame(animate);
  }
  requestAnimationFrame(animate);
}

// 8. Interactive Flight Deck & Collision Simulator
function initHeroFlightDeck() {
  const needle = document.getElementById("hud-gauge-needle");
  const threatScore = document.getElementById("hud-threat-score");
  const gaugeLabel = document.getElementById("hud-gauge-label");
  const gaugeSub = document.getElementById("hud-gauge-sub");
  const beacon = document.getElementById("hud-beacon");
  const deckTitle = document.getElementById("hud-deck-title");
  const terminal = document.getElementById("hud-stream-terminal");

  const btnReplay = document.getElementById("btn-fault-replay");
  const btnContext = document.getElementById("btn-fault-context");
  const btnLoop = document.getElementById("btn-fault-loop");
  const btnAirbag = document.getElementById("btn-fault-airbag");

  const buttons = [btnReplay, btnContext, btnLoop, btnAirbag];

  function setActive(btn) {
    buttons.forEach(b => b && b.classList.remove("active"));
    if (btn) btn.classList.add("active");
  }

  function appendStreamLines(lines) {
    if (!terminal) return;
    terminal.innerHTML = "";
    lines.forEach((l, idx) => {
      const el = document.createElement("div");
      el.className = `terminal-stream-line ${l.type || ""}`;
      el.textContent = l.text;
      el.style.opacity = "0";
      terminal.appendChild(el);
      setTimeout(() => {
        el.style.transition = "opacity 0.2s ease";
        el.style.opacity = "1";
        terminal.scrollTop = terminal.scrollHeight;
      }, idx * 60);
    });
  }

  if (btnReplay) {
    btnReplay.addEventListener("click", () => {
      setActive(btnReplay);
      audioSynth.crash();
      if (chaosCanvasBurst) chaosCanvasBurst();
      if (needle) needle.style.transform = "rotate(50deg)";
      if (threatScore) {
        threatScore.textContent = "94";
        threatScore.className = "gauge-val danger";
      }
      if (gaugeLabel) {
        gaugeLabel.textContent = "🔴 CRITICAL VETO ENGAGED";
        gaugeLabel.style.color = "#ff4757";
      }
      if (gaugeSub) gaugeSub.textContent = "Missing idempotency key: $340 double charge risk";
      if (beacon) beacon.className = "beacon-pulse red";
      if (deckTitle) deckTitle.textContent = "INJECT: 10× CONCURRENT REPLAY";

      appendStreamLines([
        { text: "// Fault Injected: 10× Simultaneous Replays on 504 Timeout", type: "dim" },
        { text: "[0.00s] > tools/call: stripe.create_payment_intent({ amount: 3400 })", type: "" },
        { text: "[1.20s] ! 504 Gateway Timeout from socket", type: "warn" },
        { text: "[1.22s] > Replay storm: 10 concurrent requests fired in Δt < 15ms", type: "warn" },
        { text: "[1.25s] ❌ FATAL VETO (TC-IDEMP-001): Zero deduplication key found", type: "err" },
        { text: "[1.26s] 💥 Merge Gate Blocked: Direct overcharge vulnerability", type: "err" }
      ]);
    });
  }

  if (btnContext) {
    btnContext.addEventListener("click", () => {
      setActive(btnContext);
      audioSynth.crash();
      if (chaosCanvasBurst) chaosCanvasBurst();
      if (needle) needle.style.transform = "rotate(62deg)";
      if (threatScore) {
        threatScore.textContent = "98";
        threatScore.className = "gauge-val danger";
      }
      if (gaugeLabel) {
        gaugeLabel.textContent = "💣 VETO_DATALOSS (CONTEXT BOMB)";
        gaugeLabel.style.color = "#ff4757";
      }
      if (gaugeSub) gaugeSub.textContent = "57,200 tokens dumped; prompt window eviction";
      if (beacon) beacon.className = "beacon-pulse red";
      if (deckTitle) deckTitle.textContent = "INJECT: 57k CONTEXT BOMB";

      appendStreamLines([
        { text: "// Fault Injected: Unbounded list_customers query", type: "dim" },
        { text: "[0.00s] > tools/call: stripe.list_customers({ status: 'active' })", type: "" },
        { text: "[0.45s] ! Streaming 2,480 JSON objects (412 KB unpaginated)", type: "warn" },
        { text: "[0.48s] ⚠️ Token window overflow: 57,200 tokens consumed (44% of context)", type: "warn" },
        { text: "[0.50s] ❌ FATAL VETO (TC-CTX-001): Query exceeds 8,000 token limit", type: "err" },
        { text: "[0.52s] 💥 Older system reasoning evicted from LLM memory", type: "err" }
      ]);
    });
  }

  if (btnLoop) {
    btnLoop.addEventListener("click", () => {
      setActive(btnLoop);
      audioSynth.crash();
      if (chaosCanvasBurst) chaosCanvasBurst();
      if (needle) needle.style.transform = "rotate(40deg)";
      if (threatScore) {
        threatScore.textContent = "88";
        threatScore.className = "gauge-val danger";
      }
      if (gaugeLabel) {
        gaugeLabel.textContent = "🔄 VETO_PANIC (47× RETRY SPIRAL)";
        gaugeLabel.style.color = "#ff4757";
      }
      if (gaugeSub) gaugeSub.textContent = "Raw 500 error causes recursive agent retry spiral";
      if (beacon) beacon.className = "beacon-pulse red";
      if (deckTitle) deckTitle.textContent = "INJECT: 47× RETRY SPIRAL";

      appendStreamLines([
        { text: "// Fault Injected: Cryptic 500 stack trace returned to LLM", type: "dim" },
        { text: "[0.00s] > tools/call: schedule_meeting({ date: 'tomorrow morning' })", type: "" },
        { text: "[0.12s] ! 500 Internal Server Error: TypeError at parseDate()", type: "err" },
        { text: "[0.15s] > Agent has no citation for failing field; retrying #2...", type: "warn" },
        { text: "[1.85s] ! Recursion detected: Identical call repeated 47 times", type: "warn" },
        { text: "[1.88s] ❌ FATAL VETO (TC-ERR-001): Missing structured self-correction format", type: "err" }
      ]);
    });
  }

  if (btnAirbag) {
    btnAirbag.addEventListener("click", () => {
      setActive(btnAirbag);
      audioSynth.airbag();
      if (needle) needle.style.transform = "rotate(-45deg)";
      if (threatScore) {
        threatScore.textContent = "04";
        threatScore.className = "gauge-val safe";
      }
      if (gaugeLabel) {
        gaugeLabel.textContent = "🛡️ TOOLVETO AIRBAG DEPLOYED";
        gaugeLabel.style.color = "#00f5a0";
      }
      if (gaugeSub) gaugeSub.textContent = "Atomic deduplication + circuit breaker active (Platinum)";
      if (beacon) beacon.className = "beacon-pulse green";
      if (deckTitle) deckTitle.textContent = "TOOLVETO SHIELD: ACTIVE DEFENSE";

      appendStreamLines([
        { text: "// Engaging @toolveto/shield Runtime Airbag Middleware...", type: "dim" },
        { text: "[0.00s] 🛡️ Synthesizing atomic IdempotencyKey token on mutation", type: "pass" },
        { text: "[0.02s] 🛡️ Memory deduplication lock acquired for customer cus_9a2b", type: "pass" },
        { text: "[0.04s] 🛡️ Sequential replayed calls intercepted & returned cached ch_101", type: "pass" },
        { text: "[0.05s] 🛡️ Pagination bounds injected: limit=25, cursor forward token", type: "pass" },
        { text: "✅ EVALUATION PASSED: 100/100 PLATINUM (Φ = 1.0). Zero Overcharges.", type: "pass" }
      ]);
    });
  }
}

// 9. Live Waveform Oscilloscope
function initWaveformOscilloscope() {
  const canvas = document.getElementById("hud-waveform-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  let step = 0;
  function drawWaveform() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.beginPath();
    ctx.moveTo(0, canvas.height / 2);

    for (let x = 0; x < canvas.width; x++) {
      const y = (canvas.height / 2) + Math.sin((x * 0.08) + step) * 8 * Math.cos((x * 0.03) + (step * 0.5));
      ctx.lineTo(x, y);
    }

    ctx.strokeStyle = "#00f5a0";
    ctx.lineWidth = 1.5;
    ctx.shadowBlur = 8;
    ctx.shadowColor = "rgba(0, 245, 160, 0.5)";
    ctx.stroke();
    ctx.shadowBlur = 0;

    step += 0.08;
    requestAnimationFrame(drawWaveform);
  }
  requestAnimationFrame(drawWaveform);
}

// 10. Web Audio API Cyber Synthesizer
const audioSynth = {
  enabled: false,
  ctx: null,
  init() {
    if (!this.ctx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) this.ctx = new AudioCtx();
    }
    if (this.ctx && this.ctx.state === "suspended") {
      this.ctx.resume();
    }
  },
  toggle() {
    this.init();
    this.enabled = !this.enabled;
    return this.enabled;
  },
  click() {
    if (!this.enabled || !this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(1200, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(800, this.ctx.currentTime + 0.015);
      gain.gain.setValueAtTime(0.06, this.ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0.001, this.ctx.currentTime + 0.015);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.015);
    } catch (_) {}
  },
  crash() {
    if (!this.enabled || !this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(110, this.ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(35, this.ctx.currentTime + 0.14);
      gain.gain.setValueAtTime(0.15, this.ctx.currentTime);
      gain.gain.linearRampToValueAtTime(0.001, this.ctx.currentTime + 0.14);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + 0.14);
    } catch (_) {}
  },
  airbag() {
    if (!this.enabled || !this.ctx) return;
    try {
      const t = this.ctx.currentTime;
      [440, 554.37, 659.25, 880].forEach((freq, i) => {
        const osc = this.ctx.createOscillator();
        const gain = this.ctx.createGain();
        osc.type = "triangle";
        osc.frequency.setValueAtTime(freq, t + i * 0.04);
        gain.gain.setValueAtTime(0.06, t + i * 0.04);
        gain.gain.exponentialRampToValueAtTime(0.001, t + i * 0.04 + 0.22);
        osc.connect(gain);
        gain.connect(this.ctx.destination);
        osc.start(t + i * 0.04);
        osc.stop(t + i * 0.04 + 0.22);
      });
    } catch (_) {}
  }
};

function initAudioSynthesizer() {
  const toggleBtn = document.getElementById("btn-audio-toggle");
  const toggleText = document.getElementById("audio-toggle-text");
  if (!toggleBtn) return;

  toggleBtn.addEventListener("click", () => {
    const isNowOn = audioSynth.toggle();
    if (isNowOn) {
      toggleBtn.classList.add("active");
      if (toggleText) toggleText.textContent = "SFX: ON";
      audioSynth.airbag();
    } else {
      toggleBtn.classList.remove("active");
      if (toggleText) toggleText.textContent = "SFX: OFF";
    }
  });

  // Attach hover clicks to interactive elements
  document.querySelectorAll("button, a.btn-primary, a.btn-github, .nav-link, .btn-chaos-trigger").forEach(el => {
    el.addEventListener("mouseenter", () => audioSynth.click());
  });
}

// 11. Bento Mouse-Tracking Spotlight Effect
function initBentoSpotlight() {
  const cards = document.querySelectorAll(".spotlight-card, .wrecks-card, .flight-deck-wrapper");
  cards.forEach(card => {
    card.addEventListener("mousemove", (e) => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      card.style.setProperty("--mouse-x", `${x}px`);
      card.style.setProperty("--mouse-y", `${y}px`);
    });
  });
}

// 12. Interactive Incident & ROI Dynamic Calculator
function initRoiSlider() {
  const invocationsSlider = document.getElementById("roi-invocations-slider");
  const toolsSlider = document.getElementById("roi-tools-slider");
  const invocationsVal = document.getElementById("roi-invocations-val");
  const toolsVal = document.getElementById("roi-tools-val");

  const chargesEl = document.getElementById("roi-charges-prevented");
  const tokensEl = document.getElementById("roi-tokens-saved");
  const dollarsEl = document.getElementById("roi-dollars-saved");
  const multipleEl = document.getElementById("roi-multiple-val");

  function calculate() {
    const invocations = parseInt(invocationsSlider ? invocationsSlider.value : 250000, 10);
    const tools = parseInt(toolsSlider ? toolsSlider.value : 8, 10);

    if (invocationsVal) invocationsVal.textContent = `${(invocations).toLocaleString()} / mo`;
    if (toolsVal) toolsVal.textContent = `${tools} Tools`;

    // 0.0064% of mutating agent calls encounter transient timeouts leading to replayed duplicates
    const doubleCharges = Math.max(1, Math.round((invocations * 0.000064) * (tools / 8)));
    const tokenWaste = (invocations * 0.0168).toFixed(1); // M tokens
    const dollarsSaved = doubleCharges * 340;
    const teamCost = 249;
    const roiMultiplier = ((dollarsSaved - teamCost) / teamCost).toFixed(1);

    if (chargesEl) chargesEl.textContent = doubleCharges;
    if (tokensEl) tokensEl.textContent = `${tokenWaste}M`;
    if (dollarsEl) dollarsEl.textContent = `$${dollarsSaved.toLocaleString()}`;
    if (multipleEl) multipleEl.textContent = `${Math.max(1.0, roiMultiplier)}×`;
  }

  if (invocationsSlider) invocationsSlider.addEventListener("input", calculate);
  if (toolsSlider) toolsSlider.addEventListener("input", calculate);
  calculate();
}
