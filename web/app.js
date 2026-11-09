const directoryPath = document.querySelector("#directory-path");
const baselineState = document.querySelector("#baseline-state");
const initButton = document.querySelector("#init-button");
const checkButton = document.querySelector("#check-button");
const notice = document.querySelector("#notice");
const emptyState = document.querySelector("#empty-state");
const resultsContent = document.querySelector("#results-content");
const resultSummary = document.querySelector("#result-summary");
const summaryCards = document.querySelector("#summary-cards");
const resultRows = document.querySelector("#result-rows");
const cleanMessage = document.querySelector("#clean-message");
const confirmDialog = document.querySelector("#confirm-dialog");
const confirmInit = document.querySelector("#confirm-init");

const labels = {
  added: { label: "NEW", className: "new" },
  changed: { label: "CHANGED", className: "changed" },
  missing: { label: "MISSING", className: "missing" },
};

function showNotice(message, kind = "info") {
  notice.textContent = message;
  notice.className = `notice ${kind}`;
  notice.hidden = false;
}

function clearNotice() {
  notice.hidden = true;
  notice.textContent = "";
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    body: options.method === "POST" ? "{}" : undefined,
    credentials: "same-origin",
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const details = Array.isArray(payload.details) ? ` ${payload.details.join("; ")}` : "";
    throw new Error(`${payload.error || `Request failed (${response.status})`}${details}`);
  }
  return payload;
}

function setBusy(busy, activeButton) {
  initButton.disabled = busy;
  checkButton.disabled = busy;
  if (busy && activeButton) {
    activeButton.dataset.originalLabel = activeButton.querySelector("span").textContent;
    activeButton.querySelector("span").textContent = activeButton === initButton ? "Creating…" : "Checking…";
    activeButton.classList.add("is-loading");
  } else {
    for (const button of [initButton, checkButton]) {
      if (button.dataset.originalLabel) {
        button.querySelector("span").textContent = button.dataset.originalLabel;
        delete button.dataset.originalLabel;
      }
      button.classList.remove("is-loading");
    }
  }
}

function setBaselineState(exists, count, error) {
  baselineState.className = `baseline-state ${exists && !error ? "is-ready" : "is-empty"}`;
  const text = baselineState.querySelector("span:last-child");
  if (error) {
    text.textContent = "Baseline needs attention";
    baselineState.title = error;
  } else if (exists) {
    text.textContent = `Baseline ready · ${count} file${count === 1 ? "" : "s"}`;
    baselineState.title = "A baseline is saved for this directory";
  } else {
    text.textContent = "No baseline yet";
    baselineState.title = "Create a baseline before checking files";
  }
}

async function loadStatus() {
  try {
    const status = await requestJson("/api/status");
    directoryPath.textContent = status.directory;
    directoryPath.title = status.directory;
    setBaselineState(status.baseline_exists, status.baseline_file_count, status.baseline_error);
  } catch (error) {
    directoryPath.textContent = "Dashboard unavailable";
    setBaselineState(false, 0, error.message);
    showNotice(error.message, "error");
  }
}

function resetResults() {
  emptyState.hidden = true;
  resultsContent.hidden = false;
  cleanMessage.hidden = true;
  resultRows.replaceChildren();
  summaryCards.replaceChildren();
}

function addSummaryCard(label, count, kind) {
  const card = document.createElement("div");
  card.className = `summary-card ${kind}`;
  const value = document.createElement("strong");
  value.textContent = String(count);
  const caption = document.createElement("span");
  caption.textContent = label;
  card.append(value, caption);
  summaryCards.append(card);
}

function addResultRow(kind, filePath) {
  const row = document.createElement("tr");
  const statusCell = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = `result-badge ${labels[kind].className}`;
  badge.textContent = labels[kind].label;
  statusCell.append(badge);
  const pathCell = document.createElement("td");
  const code = document.createElement("code");
  code.textContent = filePath;
  pathCell.append(code);
  row.append(statusCell, pathCell);
  resultRows.append(row);
}

function renderResults(data) {
  resetResults();
  const groups = ["added", "changed", "missing"];
  const totalDifferences = groups.reduce((sum, kind) => sum + data[kind].length, 0);
  resultSummary.textContent = data.has_differences
    ? `${totalDifferences} difference${totalDifferences === 1 ? "" : "s"} found`
    : "No differences found";
  addSummaryCard("NEW", data.added.length, "new");
  addSummaryCard("CHANGED", data.changed.length, "changed");
  addSummaryCard("MISSING", data.missing.length, "missing");
  addSummaryCard("UNCHANGED", data.unchanged_count, "unchanged");

  for (const kind of groups) {
    for (const path of data[kind]) addResultRow(kind, path);
  }
  if (!data.has_differences) cleanMessage.hidden = false;
}

async function initializeBaseline() {
  clearNotice();
  setBusy(true, initButton);
  try {
    const result = await requestJson("/api/init", { method: "POST" });
    showNotice(`Baseline created successfully. ${result.file_count} file${result.file_count === 1 ? "" : "s"} recorded.`, "success");
    resultSummary.textContent = "Baseline created";
    emptyState.hidden = false;
    resultsContent.hidden = true;
    await loadStatus();
  } catch (error) {
    showNotice(error.message, "error");
  } finally {
    setBusy(false);
  }
}

async function checkFiles() {
  clearNotice();
  setBusy(true, checkButton);
  try {
    const result = await requestJson("/api/check", { method: "POST" });
    renderResults(result);
    if (result.has_differences) {
      showNotice("Differences found. Review the file list below; do not reset the baseline unless you trust the current files.", "warning");
    } else {
      showNotice("Integrity check complete. Files match the saved baseline.", "success");
    }
  } catch (error) {
    showNotice(error.message, "error");
  } finally {
    setBusy(false);
  }
}

initButton.addEventListener("click", () => confirmDialog.showModal());
confirmInit.addEventListener("click", (event) => {
  event.preventDefault();
  confirmDialog.close("confirm");
  initializeBaseline();
});
checkButton.addEventListener("click", checkFiles);
loadStatus();
