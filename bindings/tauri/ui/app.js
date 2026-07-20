// The window's whole script. It calls five commands and renders their answers.
//
// NOTHING IS BUILT WITH innerHTML. Every value below either came from a
// document or is derived from one, and `textContent` is the only assignment
// that cannot turn a note's contents into markup. The CSP would stop a script
// from running, but it would not stop a bare `<b>` in a note from silently
// changing what a reviewer reads.
//
// There is no fetch, no XMLHttpRequest, no WebSocket and no EventSource in this
// file, and the CSP forbids all four. The only channel out of this window is
// Tauri's IPC to the process that owns it.

const invoke = window.__TAURI__.core.invoke;

const el = (id) => document.getElementById(id);

/** Replace an element's children. */
function replace(target, ...nodes) {
  target.replaceChildren(...nodes);
}

function node(tag, text, className) {
  const created = document.createElement(tag);
  if (text !== undefined && text !== null) created.textContent = text;
  if (className) created.className = className;
  return created;
}

/** A span map table: labels, lengths and synthetic replacements only. */
function spanTable(spans) {
  if (spans.length === 0) {
    return node(
      "p",
      "Nothing was detected. That is not the same as nothing being there - see the banner above.",
      "empty",
    );
  }
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const heading of [
    "Label",
    "Layer",
    "Bytes",
    "Confidence",
    "Checksum",
    "Replaced with",
  ]) {
    head.append(node("th", heading));
  }
  table.append(head);
  for (const span of spans) {
    const row = document.createElement("tr");
    row.append(node("td", span.label));
    row.append(node("td", span.layer));
    row.append(node("td", String(span.byte_len)));
    row.append(node("td", span.confidence.toFixed(2)));
    row.append(node("td", span.checksum_validated ? "validated" : "-"));
    row.append(node("td", span.replacement));
    table.append(row);
  }
  return table;
}

function setStatus(target, message, kind) {
  target.textContent = message;
  target.className = kind ? `status ${kind}` : "status";
}

/** The tier the user has selected. */
function tier() {
  return el("tier").value;
}

async function refreshAbout() {
  const about = await invoke("about");
  el("version").textContent = `v${about.version}`;
  el("disclosure").textContent = about.disclosure;
}

async function refreshLayers() {
  const report = await invoke("layer_report");
  const rows = report.layers.map((layer) => {
    const wrapper = node("div", null, "layer");
    wrapper.append(
      node("span", layer.live ? "live" : "absent", `flag ${layer.live ? "live" : "dead"}`),
    );
    const body = node("div");
    body.append(node("div", `${layer.id} - ${layer.name}`, "layer-name"));
    body.append(node("p", layer.detail, "layer-detail"));
    wrapper.append(body);
    return wrapper;
  });
  replace(el("layers"), ...rows);
}

// The tier control reflects whether the tier can actually run, BEFORE it is
// chosen. A refusal that only arrives after a document has been picked is a
// refusal that teaches people to avoid the feature rather than configure it.
async function refreshTierGate() {
  const option = el("tier").querySelector('option[value="expert-determination"]');
  try {
    await invoke("expert_tier_gate");
    option.disabled = false;
    option.textContent = "Expert Determination - adds L3 (local model configured)";
    el("tier-note").textContent =
      "Expert Determination runs a full-document sweep with the LOCAL model named by DEID_L3_MODEL. Nothing is uploaded.";
  } catch (refusal) {
    option.disabled = true;
    option.textContent = "Expert Determination - not available on this machine";
    if (el("tier").value === "expert-determination") el("tier").value = "safe-harbor";
    el("tier-note").textContent = String(refusal);
  }
}

async function runText() {
  const button = el("run-text");
  const status = el("text-status");
  const text = el("note").value;
  if (text.length === 0) {
    setStatus(status, "Nothing to de-identify.", "error");
    return;
  }
  button.disabled = true;
  setStatus(status, "Running...");
  try {
    const outcome = await invoke("deidentify_text", { tier: tier(), text });
    el("output").value = outcome.text;
    replace(el("text-spans"), spanTable(outcome.spans));
    // Deliberately not "clean", "safe" or "de-identified": it says what was
    // removed and nothing about what remains.
    setStatus(
      status,
      `${outcome.spans.length} rule-detectable identifier(s) removed. Names were not.`,
      "ok",
    );
  } catch (error) {
    el("output").value = "";
    replace(el("text-spans"));
    setStatus(status, String(error), "error");
  } finally {
    button.disabled = false;
  }
}

/** The report for one redacted file: counts and structural names only. */
function fileReport(outcome) {
  const parts = [];
  parts.push(
    node(
      "p",
      `Format ${outcome.format}. ${outcome.masked} identifier(s) removed across ${outcome.locations} location(s).`,
    ),
  );

  if (outcome.images_not_read) {
    const warn = node("div", null, "warn");
    warn.append(node("strong", "This file is NOT fully de-identified."));
    warn.append(node("p", outcome.images_not_read.warning));
    const list = document.createElement("ul");
    for (const page of outcome.images_not_read.pages) {
      list.append(
        node(
          "li",
          `page ${page.page}: ${page.images} image(s), ${page.plausible_content} too large to be decoration`,
        ),
      );
    }
    warn.append(list);
    parts.push(warn);
  }

  if (outcome.parts.length > 0) {
    const table = document.createElement("table");
    const head = document.createElement("tr");
    head.append(node("th", "Page or part"));
    head.append(node("th", "Removed"));
    table.append(head);
    for (const part of outcome.parts) {
      const row = document.createElement("tr");
      row.append(node("td", part.name));
      row.append(node("td", String(part.masked)));
      table.append(row);
    }
    parts.push(table);
  }

  if (outcome.stripped.length > 0) {
    parts.push(node("p", `Removed wholesale: ${outcome.stripped.join(", ")}`, "empty"));
  }

  parts.push(spanTable(outcome.spans));

  const verification = node("p", null, "empty");
  verification.textContent =
    outcome.identifiers_checked === 0
      ? `Verifier ${outcome.verification_method} ran and had nothing to look for: nothing was removed.`
      : `Verifier ${outcome.verification_method} confirmed all ${outcome.identifiers_checked} removed identifier(s) are absent from the saved bytes.`;
  parts.push(verification);

  const checks = document.createElement("ul");
  checks.className = "empty";
  for (const check of outcome.verification_checks) checks.append(node("li", check));
  parts.push(checks);

  parts.push(node("p", outcome.disclosure, "disclosure mono"));
  return parts;
}

async function runFile() {
  const button = el("run-file");
  const status = el("file-status");
  button.disabled = true;
  setStatus(status, "Waiting for the file dialog...");
  try {
    const outcome = await invoke("redact_document", { tier: tier() });
    if (outcome === null) {
      replace(el("file-report"));
      setStatus(status, "Cancelled. Nothing was written.");
      return;
    }
    replace(el("file-report"), ...fileReport(outcome));
    setStatus(status, `Saved. ${outcome.masked} identifier(s) removed. Names were not.`, "ok");
  } catch (error) {
    replace(el("file-report"));
    setStatus(status, String(error), "error");
  } finally {
    button.disabled = false;
  }
}

el("run-text").addEventListener("click", runText);
el("run-file").addEventListener("click", runFile);
el("tier").addEventListener("change", () => {
  el("output").value = "";
  replace(el("text-spans"));
  replace(el("file-report"));
});

await refreshAbout();
await refreshTierGate();
await refreshLayers();
