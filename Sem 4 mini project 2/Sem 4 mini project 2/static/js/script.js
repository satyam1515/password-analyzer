/**
 * script.js
 * Password Strength Research Application
 * Frontend JavaScript Controller
 *
 * Handles: API calls, DOM updates, chart rendering, animations,
 *          password visibility toggle, and form validation.
 *
 * Author: Password Strength Research Project
 */

"use strict";

/* ══════════════════════════════════════════════════════════════
   CONSTANTS & STATE
════════════════════════════════════════════════════════════════ */

const API_URL        = "/analyze";
const DEBOUNCE_DELAY = 1500; // ms to wait after keystroke before auto-analyzing

let debounceTimer    = null;
let isPasswordShown  = false;
let lastAnalysisData = null;

/* ══════════════════════════════════════════════════════════════
   DOM REFERENCES
════════════════════════════════════════════════════════════════ */

const passwordInput    = document.getElementById("passwordInput");
const analyzeBtn       = document.getElementById("analyzeBtn");
const clearBtn         = document.getElementById("clearBtn");
const togglePwBtn      = document.getElementById("togglePwBtn");
const loadingOverlay   = document.getElementById("loadingOverlay");
const strengthMeterBar = document.getElementById("strengthMeterBar");

/* Panel elements — Rules */
const rulesScore        = document.getElementById("rulesScore");
const rulesRing         = document.getElementById("rulesRingFill");
const rulesProgress     = document.getElementById("rulesProgress");
const rulesBadge        = document.getElementById("rulesBadge");
const rulesList         = document.getElementById("rulesList");
const rulesPassed       = document.getElementById("rulesPassed");

/* Panel elements — Entropy */
const entropyBits       = document.getElementById("entropyBits");
const entropyScore      = document.getElementById("entropyScore");
const entropyRing       = document.getElementById("entropyRingFill");
const entropyProgress   = document.getElementById("entropyProgress");
const entropyBadge      = document.getElementById("entropyBadge");
const charsetInfo       = document.getElementById("charsetInfo");
const charsetPills      = document.getElementById("charsetPills");

/* Panel elements — Pattern */
const patternWarning    = document.getElementById("patternWarning");
const patternList       = document.getElementById("patternList");
const patternStatus     = document.getElementById("patternStatus");

/* Panel elements — zxcvbn */
const zxcvbnDots        = document.getElementById("zxcvbnDots");
const zxcvbnLabel       = document.getElementById("zxcvbnLabel");
const zxcvbnCrack       = document.getElementById("zxcvbnCrack");
const zxcvbnOnline      = document.getElementById("zxcvbnOnline");
const zxcvbnGuesses     = document.getElementById("zxcvbnGuesses");
const zxcvbnFeedback    = document.getElementById("zxcvbnFeedback");

/* Panel elements — Hybrid */
const hybridBigScore    = document.getElementById("hybridBigScore");
const hybridBadge       = document.getElementById("hybridBadge");
const hybridProgress    = document.getElementById("hybridProgress");
const hybridBreakdown   = document.getElementById("hybridBreakdown");

/* Dashboard */
const dashRulesScore    = document.getElementById("dashRulesScore");
const dashEntropyScore  = document.getElementById("dashEntropyScore");
const dashZxcvbnScore   = document.getElementById("dashZxcvbnScore");
const dashHybridScore   = document.getElementById("dashHybridScore");
const dashRulesClass    = document.getElementById("dashRulesClass");
const dashEntropyClass  = document.getElementById("dashEntropyClass");
const dashZxcvbnClass   = document.getElementById("dashZxcvbnClass");
const dashHybridClass   = document.getElementById("dashHybridClass");
const chartImg          = document.getElementById("comparisonChart");
const chartPlaceholder  = document.getElementById("chartPlaceholder");

/* Suggestions */
const suggestionsList   = document.getElementById("suggestionsList");
const suggestionsSection = document.getElementById("suggestionsSection");


/* ══════════════════════════════════════════════════════════════
   EVENT LISTENERS
════════════════════════════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
  // Live debounced analysis on keystroke
  passwordInput.addEventListener("input", () => {
    updateStrengthMeter();
    clearTimeout(debounceTimer);
    if (passwordInput.value.length > 0) {
      // Auto-analysis disabled per user request
      // debounceTimer = setTimeout(analyzePassword, DEBOUNCE_DELAY);
    } else {
      resetAllPanels();
    }
  });

  // Explicit analyze button
  analyzeBtn.addEventListener("click", () => {
    clearTimeout(debounceTimer);
    analyzePassword();
  });

  // Clear button
  clearBtn.addEventListener("click", clearAll);

  // Toggle password visibility
  togglePwBtn.addEventListener("click", togglePasswordVisibility);

  // Enter key on input
  passwordInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      clearTimeout(debounceTimer);
      analyzePassword();
    }
  });
});


/* ══════════════════════════════════════════════════════════════
   PASSWORD VISIBILITY TOGGLE
════════════════════════════════════════════════════════════════ */

function togglePasswordVisibility() {
  isPasswordShown = !isPasswordShown;
  passwordInput.type = isPasswordShown ? "text" : "password";

  const icon = togglePwBtn.querySelector("i");
  if (isPasswordShown) {
    icon.className = "fas fa-eye-slash";
    togglePwBtn.title = "Hide Password";
  } else {
    icon.className = "fas fa-eye";
    togglePwBtn.title = "Show Password";
  }
}


/* ══════════════════════════════════════════════════════════════
   LIVE STRENGTH METER (visual feedback before full analysis)
════════════════════════════════════════════════════════════════ */

function updateStrengthMeter() {
  const pw = passwordInput.value;
  if (!pw) {
    strengthMeterBar.style.width = "0%";
    strengthMeterBar.className = "strength-meter-bar";
    return;
  }

  // Quick heuristic score for instant feedback
  let quickScore = 0;
  if (pw.length >= 8)  quickScore += 20;
  if (pw.length >= 12) quickScore += 10;
  if (/[A-Z]/.test(pw)) quickScore += 20;
  if (/[a-z]/.test(pw)) quickScore += 15;
  if (/[0-9]/.test(pw)) quickScore += 20;
  if (/[^a-zA-Z0-9]/.test(pw)) quickScore += 15;

  strengthMeterBar.style.width = quickScore + "%";
  strengthMeterBar.className = "strength-meter-bar " + getScoreFillClass(quickScore);
}


/* ══════════════════════════════════════════════════════════════
   MAIN API CALL
════════════════════════════════════════════════════════════════ */

async function analyzePassword() {
  const password = passwordInput.value;

  if (!password.trim()) {
    showToast("Please enter a password to analyse.", "warning");
    return;
  }

  // --- BATCH ANALYSIS LOGIC (EASY TO REMOVE LATER) ---
  const passwords = password.trim().split(/\s+/);
  if (passwords.length > 1) {
    showLoading(true);
    try {
      const response = await fetch('/analyze_batch', {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ passwords })
      });
      if (!response.ok) throw new Error(`HTTP error ${response.status}`);
      const data = await response.json();
      
      // Show batch analysis
      document.getElementById("batchAnalysisSection").style.display = "block";
      // Hide single analysis sections
      if (document.getElementById("singleAnalysisSection")) document.getElementById("singleAnalysisSection").style.display = "none";
      if (document.getElementById("bottomRowSection")) document.getElementById("bottomRowSection").style.display = "none";
      if (document.getElementById("dashboardSection")) document.getElementById("dashboardSection").style.display = "none";
      if (document.getElementById("suggestionsSection")) document.getElementById("suggestionsSection").style.display = "none";
      
      renderBatchPanel(data.results);
    } catch (err) {
      showToast(`Batch error: ${err.message}`, "error");
    } finally {
      showLoading(false);
    }
    return; // Exit early so single-password logic doesn't run
  }
  
  // --- SINGLE PASSWORD LOGIC ---
  // If only 1 password, ensure batch UI is hidden and single UI is visible
  if (document.getElementById("batchAnalysisSection")) document.getElementById("batchAnalysisSection").style.display = "none";
  if (document.getElementById("singleAnalysisSection")) document.getElementById("singleAnalysisSection").style.display = "block";
  if (document.getElementById("bottomRowSection")) document.getElementById("bottomRowSection").style.display = "block";
  if (document.getElementById("dashboardSection")) document.getElementById("dashboardSection").style.display = "block";

  showLoading(true);

  try {
    const response = await fetch(API_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ password })
    });

    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.error || `HTTP error ${response.status}`);
    }

    const data = await response.json();
    lastAnalysisData = data;
    renderAllPanels(data);

  } catch (err) {
    showToast(`Analysis error: ${err.message}`, "error");
    console.error("Analysis error:", err);
  } finally {
    showLoading(false);
  }
}


/* ══════════════════════════════════════════════════════════════
   RENDER ALL PANELS
════════════════════════════════════════════════════════════════ */

function renderAllPanels(data) {
  renderRulesPanel(data.rules);
  renderEntropyPanel(data.entropy);
  renderPatternPanel(data.pattern);
  renderZxcvbnPanel(data.zxcvbn);
  renderHybridPanel(data.hybrid);
  renderDashboard(data);
  renderSuggestions(data.hybrid.suggestions);
  renderPwnedBanner(data.pwned_count);
}

function renderPwnedBanner(count) {
  const banner = document.getElementById("pwnedAlertBanner");
  const countText = document.getElementById("pwnedCountText");
  if (!banner || !countText) return;
  
  if (count && count > 0) {
    countText.textContent = count.toLocaleString();
    banner.style.display = "block";
  } else {
    banner.style.display = "none";
  }
}


/* ── Rules Panel ─────────────────────────────────────────────── */

function renderRulesPanel(rules) {
  const score = rules.score;
  const cls   = rules.classification;

  // Score ring
  animateRing(rulesRing, score, getScoreStrokeClass(score));

  // Number
  animateNumber(rulesScore, score);

  // Progress bar
  animateProgress(rulesProgress, score, getScoreFillClass(score));

  // Badge
  setBadge(rulesBadge, cls, score);

  // Rules count
  if (rulesPassed) {
    rulesPassed.textContent = `${rules.passed_count} / ${rules.total_rules} rules passed`;
  }

  // Rules list
  if (rulesList) {
    rulesList.innerHTML = "";
    rules.rules.forEach((rule, i) => {
      const li = document.createElement("li");
      li.className = "rule-item";
      li.style.animationDelay = `${i * 60}ms`;
      li.innerHTML = `
        <span class="rule-icon ${rule.passed ? "rule-pass" : "rule-fail"}">
          <i class="fas fa-${rule.passed ? "check" : "times"}"></i>
        </span>
        <span class="rule-name">${escHtml(rule.name)}</span>
        <span class="rule-pts">+${rule.points}pts</span>
      `;
      rulesList.appendChild(li);
    });
  }
}


/* ── Entropy Panel ───────────────────────────────────────────── */

function renderEntropyPanel(entropy) {
  const score = entropy.score;
  const cls   = entropy.classification;

  // Big entropy number
  if (entropyBits) animateNumber(entropyBits, entropy.entropy, 1);

  // Score ring & progress
  animateRing(entropyRing, score, getScoreStrokeClass(score));
  if (entropyScore) animateNumber(entropyScore, score);
  animateProgress(entropyProgress, score, getScoreFillClass(score));

  // Badge
  setBadge(entropyBadge, cls, score);

  // Charset pills
  if (charsetPills) {
    charsetPills.innerHTML = entropy.charsets_used.map(cs =>
      `<span class="charset-pill"><i class="fas fa-check-circle"></i> ${escHtml(cs)}</span>`
    ).join("");
  }

  // Charset info rows
  if (charsetInfo) {
    charsetInfo.innerHTML = `
      <div class="info-row">
        <span class="info-key">Password Length</span>
        <span class="info-value mono">${entropy.length} chars</span>
      </div>
      <div class="info-row">
        <span class="info-key">Character Set Size</span>
        <span class="info-value mono">${entropy.charset_size}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Bits per Character</span>
        <span class="info-value mono">${entropy.bits_per_char}</span>
      </div>
      <div class="info-row">
        <span class="info-key">Total Entropy</span>
        <span class="info-value mono">${entropy.entropy} bits</span>
      </div>
    `;
  }
}


/* ── Pattern Panel ───────────────────────────────────────────── */

function renderPatternPanel(pattern) {
  if (!patternWarning) return;

  if (pattern.has_pattern) {
    patternWarning.classList.add("show");
    if (patternList) {
      patternList.innerHTML = pattern.patterns_found.map(p =>
        `<li>${escHtml(p)}</li>`
      ).join("");
    }
    if (patternStatus) {
      patternStatus.innerHTML = `<span class="text-danger"><i class="fas fa-exclamation-triangle me-1"></i>Patterns Detected</span>`;
    }
  } else {
    patternWarning.classList.remove("show");
    if (patternStatus) {
      patternStatus.innerHTML = `<span style="color:var(--accent-green)"><i class="fas fa-check-circle me-1"></i>No patterns detected</span>`;
    }
  }
}


/* ── zxcvbn Panel ────────────────────────────────────────────── */

function renderZxcvbnPanel(zxcvbn) {
  const score = zxcvbn.score; // 0–4

  // Score dots
  if (zxcvbnDots) {
    const dots = zxcvbnDots.querySelectorAll(".score-dot");
    const dotColors = ["#ff7b72", "#ff7b72", "#f0a500", "#3fb950", "#3fb950"];
    dots.forEach((dot, i) => {
      dot.style.background = i <= score ? dotColors[score] : "var(--bg-card)";
    });
  }

  // Label
  if (zxcvbnLabel) zxcvbnLabel.textContent = zxcvbn.score_label;

  // Crack times
  if (zxcvbnCrack)  zxcvbnCrack.textContent  = zxcvbn.crack_time_display || "N/A";
  if (zxcvbnOnline) zxcvbnOnline.textContent  = zxcvbn.crack_time_online  || "N/A";
  if (zxcvbnGuesses) {
    const g = zxcvbn.guesses_log10;
    zxcvbnGuesses.textContent = `10^${g} guesses`;
  }

  // Feedback
  if (zxcvbnFeedback) {
    zxcvbnFeedback.innerHTML = "";

    if (zxcvbn.feedback_warning) {
      const div = document.createElement("div");
      div.className = "feedback-item";
      div.innerHTML = `<i class="fas fa-exclamation-circle"></i> <span>${escHtml(zxcvbn.feedback_warning)}</span>`;
      zxcvbnFeedback.appendChild(div);
    }

    zxcvbn.feedback_suggestions.forEach(s => {
      const div = document.createElement("div");
      div.className = "feedback-item";
      div.innerHTML = `<i class="fas fa-lightbulb"></i> <span>${escHtml(s)}</span>`;
      zxcvbnFeedback.appendChild(div);
    });

    if (!zxcvbn.feedback_warning && zxcvbn.feedback_suggestions.length === 0) {
      zxcvbnFeedback.innerHTML = `
        <div class="feedback-item">
          <i class="fas fa-check-circle" style="color:var(--accent-green)"></i>
          <span style="color:var(--accent-green)">No specific feedback — password looks solid.</span>
        </div>`;
    }
  }
}


/* ── Hybrid Panel ────────────────────────────────────────────── */

function renderHybridPanel(hybrid) {
  const score = hybrid.hybrid_score;
  const cls   = hybrid.classification;

  if (hybridBigScore) {
    animateNumber(hybridBigScore, score);
    hybridBigScore.className = "hybrid-big-score " + getScoreColorClass(score);
  }

  if (hybridProgress) animateProgress(hybridProgress, score, getScoreFillClass(score));

  // Badge
  if (hybridBadge) setBadge(hybridBadge, cls, score);

  // Weight breakdown bars
  if (hybridBreakdown) {
    const b = hybrid.breakdown;
    const w = hybrid.weights;
    const items = [
      { label: "Rules (30%)",   value: b.rules_contribution,   pct: (b.rules_contribution / 100)*100,   fill: "fill-medium" },
      { label: "Entropy (30%)", value: b.entropy_contribution, pct: (b.entropy_contribution / 100)*100, fill: "fill-strong" },
      { label: "Dict-Aware (20%)", value: b.dict_contribution,  pct: (b.dict_contribution / 100)*100,  fill: "fill-vstrong" },
      { label: "Pattern (10%)", value: b.pattern_contribution, pct: (b.pattern_contribution / 100)*100, fill: "fill-medium" },
      { label: "Crack-Resist (10%)", value: b.crack_contribution, pct: (b.crack_contribution / 100)*100, fill: "fill-strong" },
    ];

    hybridBreakdown.innerHTML = items.map(item => `
      <div class="weight-bar-row">
        <span class="weight-label">${item.label}</span>
        <div class="weight-bar-track">
          <div class="weight-bar-fill ${item.fill}" style="width: ${Math.min(item.value, 30)}px; transition: width .8s ease;"></div>
        </div>
        <span class="weight-pct">${item.value.toFixed(1)}</span>
      </div>
    `).join("");

    // Animate the bars after insertion
    requestAnimationFrame(() => {
      hybridBreakdown.querySelectorAll(".weight-bar-fill").forEach((bar, i) => {
        setTimeout(() => {
          const raw = items[i].value;
          const maxPx = 200;
          bar.style.width = Math.min((raw / 30) * maxPx, maxPx) + "px";
        }, i * 100);
      });
    });
  }
}


/* ── Dashboard ───────────────────────────────────────────────── */

function renderDashboard(data) {
  const r = data.rules;
  const e = data.entropy;
  const z = data.zxcvbn;
  const h = data.hybrid;

  // Score cells
  setCellScore(dashRulesScore,   dashRulesClass,   r.score, r.classification);
  setCellScore(dashEntropyScore, dashEntropyClass, e.score, e.classification);
  setCellScore(dashZxcvbnScore,  dashZxcvbnClass,  z.normalized_score, z.score_label);
  setCellScore(dashHybridScore,  dashHybridClass,  h.hybrid_score, h.classification);

  // Chart
  if (data.chart) {
    if (chartPlaceholder) chartPlaceholder.style.display = "none";
    if (chartImg) {
      chartImg.src = "data:image/png;base64," + data.chart;
      chartImg.style.display = "block";
    }
  }
}


/* ── Suggestions ─────────────────────────────────────────────── */

function renderSuggestions(suggestions) {
  if (!suggestionsList || !suggestionsSection) return;

  suggestionsList.innerHTML = suggestions.map((s, i) => `
    <div class="suggestion-item" style="animation-delay: ${i * 60}ms">
      <i class="fas fa-arrow-right"></i>
      <span>${escHtml(s)}</span>
    </div>
  `).join("");

  suggestionsSection.style.display = suggestions.length > 0 ? "block" : "none";
}


/* ══════════════════════════════════════════════════════════════
   HELPER FUNCTIONS
════════════════════════════════════════════════════════════════ */

/** Animate a score ring by setting stroke-dashoffset.
 *  Uses setAttribute('class') because SVG elements expose className
 *  as a read-only SVGAnimatedString — direct assignment throws a TypeError.
 */
function animateRing(ringEl, score, strokeClass) {
  if (!ringEl) return;
  const circumference = 201; // 2π × 32
  const offset = circumference - (score / 100) * circumference;
  ringEl.style.strokeDashoffset = offset;
  ringEl.setAttribute('class', 'score-ring-fill ' + strokeClass);
}

/** Animate a numeric value from 0 to target. */
function animateNumber(el, target, decimals = 0) {
  if (!el) return;
  const duration = 700;
  const start    = performance.now();
  const startVal = parseFloat(el.textContent) || 0;

  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3); // ease-out-cubic
    const current  = startVal + (target - startVal) * eased;
    el.textContent = decimals > 0 ? current.toFixed(decimals) : Math.round(current);
    if (progress < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/** Animate a progress bar to a given percentage. */
function animateProgress(el, pct, fillClass) {
  if (!el) return;
  el.className = "progress-bar-animated " + fillClass;
  requestAnimationFrame(() => {
    el.style.width = Math.min(pct, 100) + "%";
  });
}

/** Set badge text, class, and colour based on classification. */
function setBadge(el, classification, score) {
  if (!el) return;
  const map = {
    "Weak":       "badge-weak",
    "Medium":     "badge-medium",
    "Strong":     "badge-strong",
    "Very Strong":"badge-vstrong",
    "Fair":       "badge-medium",
    "Very Weak":  "badge-weak",
  };
  el.className = "score-strength-badge " + (map[classification] || "badge-weak");
  el.textContent = classification;
}

/** Set dashboard score cell values with animation. */
function setCellScore(scoreEl, classEl, score, classification) {
  if (scoreEl) animateNumber(scoreEl, score);
  if (classEl) {
    classEl.textContent  = classification;
    classEl.className    = "cell-classification " + getScoreColorClass(score);
  }
}

/** Map score to CSS colour class. */
function getScoreColorClass(score) {
  if (score <= 40) return "score-weak";
  if (score <= 70) return "score-medium";
  if (score <= 90) return "score-strong";
  return "score-vstrong";
}

/** Map score to fill CSS class. */
function getScoreFillClass(score) {
  if (score <= 40) return "fill-weak";
  if (score <= 70) return "fill-medium";
  if (score <= 90) return "fill-strong";
  return "fill-vstrong";
}

/** Map score to stroke CSS class for SVG rings. */
function getScoreStrokeClass(score) {
  if (score <= 40) return "stroke-weak";
  if (score <= 70) return "stroke-medium";
  if (score <= 90) return "stroke-strong";
  return "stroke-vstrong";
}

/** Escape HTML to prevent XSS. */
function escHtml(str) {
  const d = document.createElement("div");
  d.appendChild(document.createTextNode(String(str)));
  return d.innerHTML;
}

/** Show or hide the loading overlay. */
function showLoading(show) {
  if (loadingOverlay) {
    loadingOverlay.classList.toggle("show", show);
  }
}

/** Show a toast notification. */
function showToast(message, type = "info") {
  const container = document.querySelector(".toast-container") || document.body;
  const toast = document.createElement("div");
  const colorMap = {
    info:    "var(--accent-blue)",
    warning: "var(--accent-orange)",
    error:   "var(--accent-red)",
    success: "var(--accent-green)",
  };

  toast.style.cssText = `
    background: var(--bg-card);
    border: 1px solid var(--border-primary);
    border-left: 4px solid ${colorMap[type] || colorMap.info};
    border-radius: 8px;
    padding: .85rem 1.25rem;
    color: var(--text-primary);
    font-size: .85rem;
    box-shadow: var(--shadow-lg);
    margin-bottom: .5rem;
    max-width: 320px;
    animation: slideIn .3s ease;
  `;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

/** Clear all inputs and reset panels. */
function clearAll() {
  passwordInput.value = "";
  isPasswordShown     = false;
  passwordInput.type  = "password";
  strengthMeterBar.style.width = "0%";
  strengthMeterBar.className   = "strength-meter-bar";
  resetAllPanels();
  passwordInput.focus();
}

/** Reset all panels to placeholder state. */
function resetAllPanels() {
  // Rules
  if (rulesScore)   rulesScore.textContent   = "0";
  if (rulesProgress) { rulesProgress.style.width = "0%"; rulesProgress.className = "progress-bar-animated"; }
  if (rulesBadge)   { rulesBadge.textContent = "—"; rulesBadge.className = "score-strength-badge"; }
  if (rulesList)    rulesList.innerHTML = `<div class="placeholder-state"><i class="fas fa-lock"></i><p>Enter a password to see rules evaluation</p></div>`;
  if (rulesPassed)  rulesPassed.textContent = "";

  // Entropy
  if (entropyBits)    entropyBits.textContent    = "0";
  if (entropyScore)   entropyScore.textContent   = "0";
  if (entropyProgress){ entropyProgress.style.width = "0%"; }
  if (entropyBadge)   { entropyBadge.textContent = "—"; entropyBadge.className = "score-strength-badge"; }
  if (charsetPills)   charsetPills.innerHTML     = "";
  if (charsetInfo)    charsetInfo.innerHTML      = "";

  // Pattern
  if (patternWarning) patternWarning.classList.remove("show");
  if (patternStatus)  patternStatus.innerHTML = "";

  // zxcvbn
  if (zxcvbnDots) zxcvbnDots.querySelectorAll(".score-dot").forEach(d => { d.style.background = "var(--bg-card)"; });
  if (zxcvbnLabel)  zxcvbnLabel.textContent  = "—";
  if (zxcvbnCrack)  zxcvbnCrack.textContent  = "—";
  if (zxcvbnOnline) zxcvbnOnline.textContent = "—";
  if (zxcvbnGuesses) zxcvbnGuesses.textContent = "—";
  if (zxcvbnFeedback) zxcvbnFeedback.innerHTML = "";

  // Hybrid
  if (hybridBigScore)  { hybridBigScore.textContent = "0"; hybridBigScore.className = "hybrid-big-score"; }
  if (hybridProgress)  { hybridProgress.style.width = "0%"; }
  if (hybridBadge)     { hybridBadge.textContent = "—"; hybridBadge.className = "score-strength-badge"; }
  if (hybridBreakdown) hybridBreakdown.innerHTML = "";

  // Dashboard
  [dashRulesScore, dashEntropyScore, dashZxcvbnScore, dashHybridScore].forEach(el => { if (el) el.textContent = "—"; });
  [dashRulesClass, dashEntropyClass, dashZxcvbnClass, dashHybridClass].forEach(el => { if (el) { el.textContent = ""; el.className = "cell-classification"; } });

  // Chart
  if (chartImg) { chartImg.src = ""; chartImg.style.display = "none"; }
  if (chartPlaceholder) chartPlaceholder.style.display = "flex";

  // Suggestions
  if (suggestionsSection) suggestionsSection.style.display = "none";

  // Pwned banner
  const pwnedBanner = document.getElementById("pwnedAlertBanner");
  if (pwnedBanner) pwnedBanner.style.display = "none";

  // Rings — use setAttribute because SVG className is a read-only getter
  [rulesRing, entropyRing].forEach(ring => {
    if (ring) {
      ring.style.strokeDashoffset = '201';
      ring.setAttribute('class', 'score-ring-fill');
    }
  });

  // Also clear batch UI if applicable
  const batchSection = document.getElementById("batchAnalysisSection");
  if (batchSection && batchSection.style.display !== "none") {
    document.getElementById("batchTableBody").innerHTML = "";
  }
}

/* ══════════════════════════════════════════════════════════════
   BATCH ANALYSIS RENDERER
════════════════════════════════════════════════════════════════ */

function renderBatchPanel(results) {
  const tbody = document.getElementById("batchTableBody");
  if (!tbody) return;
  
  tbody.innerHTML = "";
  
  results.forEach(res => {
    const tr = document.createElement("tr");
    
    // Determine row color based on Hybrid score class
    let badgeClass = "badge bg-secondary";
    if (res.classification === "Weak") badgeClass = "badge bg-danger";
    else if (res.classification === "Medium") badgeClass = "badge bg-warning text-dark";
    else if (res.classification === "Strong") badgeClass = "badge bg-info text-dark";
    else if (res.classification === "Very Strong") badgeClass = "badge bg-success";

    tr.innerHTML = `
      <td class="text-start font-monospace">${escHtml(res.password)}</td>
      <td>${res.length}</td>
      <td>${res.rules_score}</td>
      <td>${res.entropy_score}</td>
      <td>${res.dict_aware_score}</td>
      <td>${res.pattern_score}</td>
      <td class="fw-bold">${res.hybrid_score}</td>
      <td>${res.pwned_count > 0 ? `<i class="fas fa-triangle-exclamation text-danger" title="Pwned ${res.pwned_count} times"></i>` : `<i class="fas fa-check text-success"></i>`}</td>
      <td><span class="${badgeClass}">${res.classification}</span></td>
    `;
    tbody.appendChild(tr);
  });
}
