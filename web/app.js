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
const chooseFolderButton = document.querySelector("#choose-folder-button");
const folderDialog = document.querySelector("#folder-dialog");
const folderRootSelect = document.querySelector("#allowed-root-select");
const folderCurrentPath = document.querySelector("#folder-current-path");
const folderUpButton = document.querySelector("#folder-up-button");
const folderList = document.querySelector("#folder-list");
const folderListEmpty = document.querySelector("#folder-list-empty");
const folderDialogError = document.querySelector("#folder-dialog-error");
const folderUseButton = document.querySelector("#folder-use-button");
const folderCancelButton = document.querySelector("#folder-cancel-button");
let folderPickerPath = null;
let folderPickerParent = null;

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
  const { payload: requestPayload, ...fetchOptions } = options;
  const response = await fetch(url, {
    ...fetchOptions,
    headers: { "Content-Type": "application/json", ...(fetchOptions.headers || {}) },
    body: fetchOptions.method === "POST" ? JSON.stringify(requestPayload || {}) : undefined,
    credentials: "same-origin",
  });
  const responseData = await response.json().catch(() => ({}));
  if (!response.ok) {
    const details = Array.isArray(responseData.details) ? ` ${responseData.details.join("; ")}` : "";
    throw new Error(`${responseData.error || `Request failed (${response.status})`}${details}`);
  }
  return responseData;
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

function setBaselineState(exists, count, snapshotCount, error) {
  baselineState.className = `baseline-state ${exists && !error ? "is-ready" : "is-empty"}`;
  const text = baselineState.querySelector("span:last-child");
  if (error) {
    text.textContent = "Baseline needs attention";
    baselineState.title = error;
  } else if (exists) {
    text.textContent = `Baseline ready · ${count} file${count === 1 ? "" : "s"} · ${snapshotCount || 0} text snapshot${snapshotCount === 1 ? "" : "s"}`;
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
    setBaselineState(status.baseline_exists, status.baseline_file_count, status.text_snapshot_count, status.baseline_error);
    return status;
  } catch (error) {
    directoryPath.textContent = "Dashboard unavailable";
    setBaselineState(false, 0, 0, error.message);
    showNotice(error.message, "error");
    return null;
  }
}

async function loadFolders(path = null) {
  folderDialogError.hidden = true;
  folderDialogError.textContent = "";
  folderList.replaceChildren();
  folderListEmpty.hidden = true;
  folderCurrentPath.textContent = "Loading allowed folders…";
  folderUpButton.disabled = true;

  const url = path
    ? `/api/directories?${new URLSearchParams({ path })}`
    : "/api/directories";
  const data = await requestJson(url);
  folderPickerPath = data.current;
  folderPickerParent = data.parent;
  folderCurrentPath.textContent = data.current;
  folderCurrentPath.title = data.current;
  folderUpButton.disabled = !data.parent;

  const existingRoots = new Set(Array.from(folderRootSelect.options, (option) => option.value));
  for (const root of data.allowed_roots) {
    if (!existingRoots.has(root)) {
      const option = document.createElement("option");
      option.value = root;
      option.textContent = root;
      folderRootSelect.append(option);
    }
  }
  folderRootSelect.value = data.allowed_root;

  for (const folder of data.folders) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "folder-entry";
    button.textContent = folder.name;
    button.title = folder.path;
    button.addEventListener("click", () => loadFolders(folder.path).catch(showFolderError));
    folderList.append(button);
  }
  folderListEmpty.hidden = data.folders.length > 0;
}

function showFolderError(error) {
  folderDialogError.textContent = error.message || String(error);
  folderDialogError.hidden = false;
  folderCurrentPath.textContent = folderPickerPath || "Choose an allowed location";
}

function resetForNewDirectory() {
  emptyState.hidden = false;
  resultsContent.hidden = true;
  cleanMessage.hidden = true;
  resultRows.replaceChildren();
  summaryCards.replaceChildren();
  resultSummary.textContent = "Run a check to see results";
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

function addDiffRow(filePath, diff) {
  const row = document.createElement("tr");
  row.className = "diff-row";
  const cell = document.createElement("td");
  cell.colSpan = 2;
  if (typeof diff === "string") {
    const details = document.createElement("details");
    details.className = "diff-details";
    const summary = document.createElement("summary");
    summary.textContent = "View exact text changes";
    const pre = document.createElement("pre");
    pre.className = "diff-content";
    pre.textContent = diff || `No line-level text differences for ${filePath}.`;
    details.append(summary, pre);
    cell.append(details);
  } else {
    const note = document.createElement("span");
    note.className = "diff-unavailable";
    note.textContent = "Text diff unavailable — create the baseline with text snapshots enabled; binary, non-UTF-8, or oversized files are not previewed.";
    cell.append(note);
  }
  row.append(cell);
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

  const diffs = data.diffs || {};
  for (const kind of groups) {
    for (const path of data[kind]) {
      addResultRow(kind, path);
      const diff = Object.hasOwn(diffs, path) ? diffs[path] : undefined;
      addDiffRow(path, diff);
    }
  }
  if (!data.has_differences) cleanMessage.hidden = false;
}

async function initializeBaseline() {
  clearNotice();
  setBusy(true, initButton);
  try {
    const includeTextSnapshots = document.querySelector("#snapshot-toggle").checked;
    const result = await requestJson("/api/init", {
      method: "POST",
      payload: { include_text_snapshots: includeTextSnapshots },
    });
    const snapshotNote = includeTextSnapshots
      ? ` Text snapshots saved for ${result.text_snapshot_count} eligible file(s) in the baseline.`
      : " Text snapshots were not saved; future checks will show changed file names only.";
    showNotice(`Baseline created successfully. ${result.file_count} file${result.file_count === 1 ? "" : "s"} recorded.${snapshotNote}`, "success");
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

chooseFolderButton.addEventListener("click", () => {
  folderDialog.showModal();
  loadFolders().catch(showFolderError);
});
folderRootSelect.addEventListener("change", () => {
  if (folderRootSelect.value) loadFolders(folderRootSelect.value).catch(showFolderError);
});
folderUpButton.addEventListener("click", () => {
  if (folderPickerParent) loadFolders(folderPickerParent).catch(showFolderError);
});
folderCancelButton.addEventListener("click", () => folderDialog.close());
folderUseButton.addEventListener("click", async () => {
  if (!folderPickerPath) return;
  folderUseButton.disabled = true;
  clearNotice();
  try {
    await requestJson("/api/select-directory", {
      method: "POST",
      payload: { directory: folderPickerPath },
    });
    folderDialog.close();
    resetForNewDirectory();
    const status = await loadStatus();
    if (status) {
      showNotice(
        status.baseline_exists
          ? "Folder changed. This folder has an existing baseline."
          : "Folder changed. Create a baseline for this folder before checking it.",
        "success",
      );
    }
  } catch (error) {
    showFolderError(error);
  } finally {
    folderUseButton.disabled = false;
  }
});

initButton.addEventListener("click", () => confirmDialog.showModal());
confirmInit.addEventListener("click", (event) => {
  event.preventDefault();
  confirmDialog.close("confirm");
  initializeBaseline();
});
checkButton.addEventListener("click", checkFiles);
loadStatus();
