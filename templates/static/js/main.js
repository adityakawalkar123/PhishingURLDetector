/**
 * ============================================================
 *  PhishGuard — Frontend JavaScript
 *  Handles: URL submission, API calls, UI state management,
 *           result rendering, animations
 * ============================================================
 */

"use strict";

// ─────────────────────────────────────────────
//  DOM ELEMENT REFERENCES
// ─────────────────────────────────────────────
const urlInput       = document.getElementById("url-input");
const analyzeBtn     = document.getElementById("analyze-btn");
const clearBtn       = document.getElementById("clear-btn");
const rescanBtn      = document.getElementById("rescan-btn");
const statusText     = document.getElementById("status-text");
const statusDot      = document.querySelector(".status-dot");
const resultsSection = document.getElementById("results-section");
const checksGrid     = document.getElementById("checks-grid");
const loadingOverlay = document.getElementById("loading-overlay");
const loaderText     = document.getElementById("loader-text");
const loaderBar      = document.getElementById("loader-bar");

// Result panel elements
const verdictBanner  = document.getElementById("verdict-banner");
const verdictEmoji   = document.getElementById("verdict-emoji");
const verdictLabel   = document.getElementById("verdict-label");
const verdictDesc    = document.getElementById("verdict-desc");
const scoreNumber    = document.getElementById("score-number");
const ringFill       = document.getElementById("ring-fill");
const statUrlVal     = document.getElementById("stat-url-val");
const statPassed     = document.getElementById("stat-passed");
const statFailed     = document.getElementById("stat-failed");
const statTotal      = document.getElementById("stat-total");


// ─────────────────────────────────────────────
//  PARALLAX MOUSE EFFECT
//  Creates a subtle depth effect on mouse move
// ─────────────────────────────────────────────
document.addEventListener("mousemove", (e) => {
  const xPct = (e.clientX / window.innerWidth  - 0.5) * 2; // -1 to 1
  const yPct = (e.clientY / window.innerHeight - 0.5) * 2;

  // Move grid layer slightly with mouse
  const grid = document.querySelector(".bg-grid");
  if (grid) {
    grid.style.transform = `translate(${xPct * 6}px, ${yPct * 6}px)`;
  }

  // Move orbs
  const orb1 = document.querySelector(".orb-1");
  const orb2 = document.querySelector(".orb-2");
  if (orb1) orb1.style.transform = `translate(${xPct * 12}px, ${yPct * 12}px)`;
  if (orb2) orb2.style.transform = `translate(${-xPct * 10}px, ${-yPct * 10}px)`;
});


// ─────────────────────────────────────────────
//  SAMPLE URL CHIPS
// ─────────────────────────────────────────────
document.querySelectorAll(".sample-chip").forEach(chip => {
  chip.addEventListener("click", () => {
    urlInput.value = chip.dataset.url;
    urlInput.focus();
    // Animate the input
    urlInput.closest(".input-wrapper").style.borderColor = "var(--cyan-dim)";
    setTimeout(() => {
      urlInput.closest(".input-wrapper").style.borderColor = "";
    }, 1000);
  });
});


// ─────────────────────────────────────────────
//  CLEAR BUTTON
// ─────────────────────────────────────────────
clearBtn.addEventListener("click", () => {
  urlInput.value = "";
  urlInput.focus();
  setStatus("idle", "AWAITING INPUT");
});


// ─────────────────────────────────────────────
//  ENTER KEY SUPPORT
// ─────────────────────────────────────────────
urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") triggerAnalysis();
});


// ─────────────────────────────────────────────
//  ANALYZE BUTTON
// ─────────────────────────────────────────────
analyzeBtn.addEventListener("click", triggerAnalysis);


// ─────────────────────────────────────────────
//  RE-SCAN BUTTON — scroll back up
// ─────────────────────────────────────────────
rescanBtn.addEventListener("click", () => {
  resultsSection.style.display = "none";
  urlInput.value = "";
  setStatus("idle", "AWAITING INPUT");
  document.getElementById("scanner").scrollIntoView({ behavior: "smooth" });
  urlInput.focus();
});


// ─────────────────────────────────────────────
//  MAIN TRIGGER FUNCTION
// ─────────────────────────────────────────────
function triggerAnalysis() {
  const url = urlInput.value.trim();

  if (!url) {
    shakeInput();
    setStatus("idle", "NO URL ENTERED");
    return;
  }

  runAnalysis(url);
}


// ─────────────────────────────────────────────
//  SHAKE ANIMATION ON EMPTY INPUT
// ─────────────────────────────────────────────
function shakeInput() {
  const wrapper = urlInput.closest(".input-wrapper");
  wrapper.style.borderColor = "var(--red)";
  wrapper.style.animation = "none";

  let shakes = 0;
  const shakeInterval = setInterval(() => {
    wrapper.style.transform = shakes % 2 === 0 ? "translateX(-5px)" : "translateX(5px)";
    shakes++;
    if (shakes > 6) {
      clearInterval(shakeInterval);
      wrapper.style.transform = "";
      wrapper.style.borderColor = "";
    }
  }, 60);
}


// ─────────────────────────────────────────────
//  STATUS BAR HELPER
// ─────────────────────────────────────────────
function setStatus(type, text) {
  statusDot.className = "status-dot " + type;
  statusText.textContent = text;
}


// ─────────────────────────────────────────────
//  LOADER SEQUENCE
// ─────────────────────────────────────────────
const scanSteps = [
  "INITIALIZING SCAN...",
  "PARSING URL STRUCTURE...",
  "CHECKING HTTPS PROTOCOL...",
  "ANALYZING DOMAIN LENGTH...",
  "SCANNING FOR KEYWORDS...",
  "DETECTING IP ADDRESS...",
  "INSPECTING SPECIAL CHARS...",
  "COUNTING SUBDOMAINS...",
  "CALCULATING RISK SCORE...",
  "GENERATING REPORT..."
];

function showLoader() {
  loadingOverlay.style.display = "flex";
  loaderBar.style.width = "0%";

  let step = 0;
  const interval = setInterval(() => {
    if (step < scanSteps.length) {
      loaderText.textContent = scanSteps[step];
      loaderBar.style.width = ((step + 1) / scanSteps.length * 100) + "%";
      step++;
    } else {
      clearInterval(interval);
    }
  }, 120);

  return interval;
}

function hideLoader() {
  loaderBar.style.width = "100%";
  setTimeout(() => {
    loadingOverlay.style.display = "none";
  }, 300);
}


// ─────────────────────────────────────────────
//  CORE ANALYSIS — Fetch from Backend
// ─────────────────────────────────────────────
async function runAnalysis(url) {
  setStatus("active", "SCANNING...");
  analyzeBtn.disabled = true;
  analyzeBtn.querySelector(".btn-text").textContent = "ANALYZING...";

  const loaderInterval = showLoader();

  try {
    const response = await fetch("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    clearInterval(loaderInterval);
    hideLoader();

    if (data.error) {
      showError(data.error);
      setStatus("idle", "ERROR");
      return;
    }

    renderResults(data);

  } catch (err) {
    clearInterval(loaderInterval);
    hideLoader();
    showError("Connection failed. Make sure the Flask server is running.");
    setStatus("idle", "CONNECTION ERROR");
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.querySelector(".btn-text").textContent = "ANALYZE URL";
  }
}


// ─────────────────────────────────────────────
//  RENDER RESULTS
// ─────────────────────────────────────────────
function renderResults(data) {
  const risk = data.risk;

  // ── 1. Show results section ──────────────────
  resultsSection.style.display = "block";

  // ── 2. Verdict banner ───────────────────────
  const colorMap = {
    "SAFE":      { color: "var(--green)", border: "#00ff8833", bg: "#00ff8808" },
    "SUSPICIOUS":{ color: "var(--amber)", border: "#ffaa0033", bg: "#ffaa0008" },
    "HIGH_RISK": { color: "var(--red)",   border: "#ff336633", bg: "#ff336608" }
  };

  const theme = colorMap[risk.level] || colorMap["SUSPICIOUS"];

  verdictBanner.style.borderColor = theme.border;
  verdictBanner.style.background  = theme.bg;
  verdictBanner.style.color       = theme.color;
  verdictEmoji.textContent        = risk.emoji;
  verdictLabel.textContent        = risk.label.toUpperCase();
  verdictLabel.style.color        = theme.color;
  verdictDesc.textContent         = risk.description;

  // ── 3. Score ring animation ──────────────────
  const score = data.total_score;
  const circumference = 314; // 2 * π * 50
  const dashOffset = circumference - (score / 100) * circumference;

  scoreNumber.textContent = score;
  scoreNumber.style.color = theme.color;

  // Animate ring
  ringFill.style.stroke = theme.color;
  setTimeout(() => {
    ringFill.style.strokeDashoffset = dashOffset;
  }, 100);

  // Animate score counter
  animateCounter(scoreNumber, 0, score, 1200);

  // ── 4. Stats row ─────────────────────────────
  statUrlVal.textContent  = data.url;
  statPassed.textContent  = data.checks_passed;
  statFailed.textContent  = data.checks_failed;
  statTotal.textContent   = data.total_checks;

  // ── 5. Check cards ───────────────────────────
  checksGrid.innerHTML = "";

  data.checks.forEach((check, index) => {
    const card = buildCheckCard(check, index);
    checksGrid.appendChild(card);
  });

  // ── 6. Status bar ────────────────────────────
  const statusMap = { "SAFE": "safe", "SUSPICIOUS": "warn", "HIGH_RISK": "danger" };
  setStatus(statusMap[risk.level] || "warn", risk.label.toUpperCase());

  // ── 7. Scroll to results ─────────────────────
  setTimeout(() => {
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 200);
}


// ─────────────────────────────────────────────
//  BUILD CHECK CARD ELEMENT
// ─────────────────────────────────────────────
function buildCheckCard(check, index) {
  const card = document.createElement("div");

  // Determine card color class
  let cardClass, badgeClass;
  if (check.score === 0) {
    cardClass  = "passed";
    badgeClass = "badge-zero";
  } else if (check.score <= 15) {
    cardClass  = "warn";
    badgeClass = "badge-low";
  } else {
    cardClass  = "failed";
    badgeClass = "badge-high";
  }

  card.className = `check-card ${cardClass}`;
  card.style.animationDelay = `${index * 0.06}s`;

  card.innerHTML = `
    <div class="check-icon">${check.icon}</div>
    <div class="check-body">
      <div class="check-name">${check.name.toUpperCase()}</div>
      <div class="check-detail">${escapeHtml(check.detail)}</div>
    </div>
    <div class="check-score-badge ${badgeClass}">
      ${check.score > 0 ? "+" + check.score : "✓"}
    </div>
  `;

  return card;
}


// ─────────────────────────────────────────────
//  ANIMATED COUNTER
// ─────────────────────────────────────────────
function animateCounter(element, from, to, duration) {
  const start = performance.now();
  function update(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}


// ─────────────────────────────────────────────
//  ERROR DISPLAY
// ─────────────────────────────────────────────
function showError(message) {
  // Flash red border on input
  const wrapper = urlInput.closest(".input-wrapper");
  wrapper.style.borderColor = "var(--red)";
  wrapper.style.boxShadow   = "0 0 0 1px var(--red), 0 0 20px var(--red-dim)";

  setTimeout(() => {
    wrapper.style.borderColor = "";
    wrapper.style.boxShadow   = "";
  }, 3000);

  // Show a temporary alert below input
  const hint = document.querySelector(".input-hint");
  const original = hint.textContent;
  hint.style.color = "var(--red)";
  hint.textContent = "⚠ " + message;

  setTimeout(() => {
    hint.style.color = "";
    hint.textContent = original;
  }, 4000);
}


// ─────────────────────────────────────────────
//  HTML ESCAPE (Security: sanitize output)
// ─────────────────────────────────────────────
function escapeHtml(str) {
  const div = document.createElement("div");
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}


// ─────────────────────────────────────────────
//  INPUT LIVE FEEDBACK — change ring color as
//  user types suspicious-looking content
// ─────────────────────────────────────────────
urlInput.addEventListener("input", () => {
  const val = urlInput.value.toLowerCase();
  const wrapper = urlInput.closest(".input-wrapper");

  if (val.startsWith("http://")) {
    wrapper.style.borderColor = "var(--amber-dim)";
  } else if (val.includes("@") || val.includes("192.") || val.includes("login")) {
    wrapper.style.borderColor = "var(--red-dim)";
  } else if (val.startsWith("https://")) {
    wrapper.style.borderColor = "var(--green-dim)";
  } else {
    wrapper.style.borderColor = "";
  }
});


// ─────────────────────────────────────────────
//  INIT — focus input on load
// ─────────────────────────────────────────────
window.addEventListener("load", () => {
  urlInput.focus();
  console.log(
    "%c🛡️  PhishGuard Loaded",
    "color: #00ffcc; font-size: 16px; font-weight: bold; font-family: monospace;"
  );
});
