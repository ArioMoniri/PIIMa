// DOM rendering and exports.
//
// EVERYTHING IS BUILT WITH createElement AND textContent. There is not one
// `innerHTML` assignment in this file, and that is a security property rather
// than a style rule: the strings being rendered are a clinical note the user
// pasted, and a note containing `<img onerror=...>` would otherwise execute in
// the one page whose entire claim is that nothing leaves the tab. The page CSP
// would block the load, but relying on a second line of defence for a bug that
// is trivially avoidable in the first is not a trade worth making.

import { PASSTHROUGH } from "./compose.js";
import { family } from "./policy.js";

/// One `<mark>` for a detected span, carrying its provenance.
function markFor(segment) {
  const mark = document.createElement("mark");
  const label = segment.span.label;
  mark.className = `ent fam-${family(label)}`;
  if (segment.passthrough !== null) mark.classList.add("passthrough");
  mark.textContent = segment.original;
  mark.tabIndex = 0;
  const detail = describe(segment);
  mark.title = detail;
  // The tooltip is a `title`, which no browser reliably shows on KEYBOARD
  // focus. The same string therefore also goes to a live region on focus and on
  // hover, so the provenance is reachable without a mouse.
  mark.dataset.detail = detail;
  return mark;
}

/// The human sentence about one span. Used for the tooltip, the live region and
/// the HTML export, so all three can never drift apart.
export function describe(segment) {
  const span = segment.span;
  const parts = [
    span.label,
    `layer ${span.layer}`,
    `confidence ${span.confidence.toFixed(2)}`,
    span.checksumValidated
      ? "checksum-validated (arithmetic, not a model guess)"
      : "not checksum-validated",
    `bytes ${span.start}..${span.end}`,
  ];
  parts.push(
    segment.passthrough === null
      ? `masked by ${segment.method}`
      : `LEFT IN THE OUTPUT: ${segment.passthrough}`,
  );
  if (segment.note) parts.push(segment.note);
  return parts.join(" - ");
}

/// The source text with every detected span marked in place.
export function renderHighlight(target, segments, onDetail) {
  target.replaceChildren();
  for (const segment of segments) {
    if (segment.kind === "keep") {
      target.append(document.createTextNode(segment.text));
      continue;
    }
    const mark = markFor(segment);
    const show = () => onDetail(mark.dataset.detail);
    mark.addEventListener("focus", show);
    mark.addEventListener("mouseenter", show);
    target.append(mark);
  }
}

/// Plain text into a `<pre>`.
export function renderText(target, text) {
  target.textContent = text;
}

/// Original and replacement side by side in the reading order of the note.
export function renderInline(target, segments) {
  target.replaceChildren();
  for (const segment of segments) {
    if (segment.kind === "keep" || segment.passthrough !== null) {
      target.append(
        document.createTextNode(
          segment.kind === "keep" ? segment.text : segment.original,
        ),
      );
      continue;
    }
    const removed = document.createElement("del");
    removed.className = "diff";
    removed.textContent = segment.original;
    target.append(removed);
    if (segment.replacement.length > 0) {
      const added = document.createElement("ins");
      added.className = "diff";
      added.textContent = segment.replacement;
      target.append(added);
    }
  }
}

function cell(row, text, mono) {
  const td = document.createElement("td");
  td.textContent = text;
  if (mono) td.className = "mono";
  row.append(td);
  return td;
}

function pill(row, text, kind) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = `pill ${kind}`;
  span.textContent = text;
  td.append(span);
  row.append(td);
}

/// The span map as a real table: both offset systems, provenance, outcome.
export function renderTable(tbody, segments) {
  tbody.replaceChildren();
  let rows = 0;
  for (const segment of segments) {
    if (segment.kind !== "span") continue;
    rows += 1;
    const span = segment.span;
    const row = document.createElement("tr");
    cell(row, `${span.start}..${span.end}`, true);
    cell(row, `${segment.outputStart}..${segment.outputEnd}`, true);
    cell(row, span.label, true);
    cell(row, span.layer, true);
    if (segment.passthrough === null) {
      pill(row, "mask", "mask");
    } else if (segment.passthrough === PASSTHROUGH.KEPT) {
      pill(row, "keep", "keep");
    } else {
      pill(row, "NOT MASKED", "suppressed");
    }
    cell(row, span.confidence.toFixed(2), true);
    cell(row, span.checksumValidated ? "yes" : "-", true);
    cell(
      row,
      segment.passthrough === null
        ? segment.method + (segment.note ? ` (${segment.note})` : "")
        : segment.passthrough,
      true,
    );
    cell(row, segment.passthrough === null ? segment.replacement : "-", true);
    tbody.append(row);
  }
  return rows;
}

/// Save a string as a file, without a network round trip.
///
/// A blob URL and a synthetic click: the bytes never leave the tab, and the
/// object URL is revoked immediately so the blob is not retained -- it holds
/// the clinical note.
export function download(filename, mime, contents) {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

/// The span map as JSON.
///
/// CARRIES `original`, which is the identifier itself. That is what makes the
/// export a round-trip table and what makes it as sensitive as the note. The
/// field is named plainly rather than hidden behind a hash, so nobody handles
/// this file believing it is de-identified.
export function spanMapJson(segments, meta) {
  const spans = segments
    .filter((segment) => segment.kind === "span")
    .map((segment) => ({
      start: segment.span.start,
      end: segment.span.end,
      outputStart: segment.outputStart,
      outputEnd: segment.outputEnd,
      label: segment.span.label,
      layer: segment.span.layer,
      confidence: Number(segment.span.confidence.toFixed(4)),
      checksumValidated: segment.span.checksumValidated,
      masked: segment.passthrough === null,
      method: segment.method,
      passthroughReason: segment.passthrough,
      replacement: segment.passthrough === null ? segment.replacement : null,
      original: segment.original,
    }));
  return JSON.stringify(
    {
      note: "Offsets are UTF-8 BYTE offsets. `original` is the identifier: this file is as sensitive as the source note.",
      producedBy: meta.build,
      tier: meta.tier,
      confidenceThreshold: meta.threshold,
      namesMasked: false,
      namesNote:
        "No L2 model is loaded in this build, so no name was detected or masked.",
      spans,
    },
    null,
    2,
  );
}

function csvField(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

/// The span map as CSV, same columns as the table plus the original.
export function spanMapCsv(segments) {
  const header = [
    "start",
    "end",
    "output_start",
    "output_end",
    "label",
    "layer",
    "masked",
    "confidence",
    "checksum_validated",
    "method",
    "passthrough_reason",
    "replacement",
    "original",
  ];
  const rows = segments
    .filter((segment) => segment.kind === "span")
    .map((segment) =>
      [
        segment.span.start,
        segment.span.end,
        segment.outputStart,
        segment.outputEnd,
        segment.span.label,
        segment.span.layer,
        segment.passthrough === null ? "yes" : "no",
        segment.span.confidence.toFixed(4),
        segment.span.checksumValidated ? "yes" : "no",
        segment.method ?? "",
        segment.passthrough ?? "",
        segment.passthrough === null ? segment.replacement : "",
        segment.original,
      ]
        .map(csvField)
        .join(","),
    );
  return [header.join(","), ...rows].join("\n") + "\n";
}

const EXPORT_STYLE = `
body{font:15px/1.6 system-ui,sans-serif;margin:0 auto;max-width:50rem;padding:2rem 1rem;color:#16181c;background:#fff}
pre{background:#f4f4f2;border:1px solid #ddd;border-radius:6px;padding:1rem;white-space:pre-wrap;word-break:break-word;font:13px/1.7 ui-monospace,monospace}
mark{border-radius:2px;padding:0 1px;border-bottom:2px solid currentColor}
mark.passthrough{background:transparent;border:1px dashed currentColor}
.fam-id{background:#e4e4fb;color:#3b3ba8}.fam-contact{background:#dcf1f4;color:#0f5f6b}
.fam-date{background:#fbeedb;color:#6b3f08}.fam-place{background:#e0f2e4;color:#1f5a2c}
.fam-name{background:#fbe3e1;color:#8c1d18}.fam-other{background:#e9e9e9;color:#4a4a4a}
.warning{background:#fdf3e0;border:1px solid #7a4b00;border-left-width:4px;border-radius:6px;padding:1rem;color:#7a4b00}
.warning strong{color:#8c1d18}
`;

/// The highlight view as a standalone HTML file.
///
/// The banner travels with it. An exported highlight page that showed masked
/// identifiers without saying that names were never looked for would be a
/// document that misleads whoever it is forwarded to, which is worse than the
/// panel misleading the person who generated it.
export function highlightHtml(segments, meta) {
  const doc = document.implementation.createHTMLDocument("deid-tr highlight");
  const style = doc.createElement("style");
  style.textContent = EXPORT_STYLE;
  doc.head.append(style);

  const title = doc.createElement("h1");
  title.textContent = "deid-tr - detected spans";
  doc.body.append(title);

  const warning = doc.createElement("div");
  warning.className = "warning";
  const strong = doc.createElement("strong");
  strong.textContent = "Names are not masked in this output. ";
  warning.append(strong);
  warning.append(
    doc.createTextNode(
      "No L2 model was loaded, so no patient, clinician or relative name was detected. " +
        "Marked spans are the fixed-format direct identifiers the L1 rule layer can prove. " +
        `Produced by ${meta.build}, tier ${meta.tier}, confidence threshold ${meta.threshold.toFixed(2)}. ` +
        "This file contains the ORIGINAL text and is as sensitive as the source note.",
    ),
  );
  doc.body.append(warning);

  const pre = doc.createElement("pre");
  for (const segment of segments) {
    if (segment.kind === "keep") {
      pre.append(doc.createTextNode(segment.text));
      continue;
    }
    const mark = doc.createElement("mark");
    mark.className = `fam-${family(segment.span.label)}`;
    if (segment.passthrough !== null) mark.classList.add("passthrough");
    mark.title = describe(segment);
    mark.textContent = segment.original;
    pre.append(mark);
  }
  doc.body.append(pre);
  return `<!doctype html>\n${doc.documentElement.outerHTML}\n`;
}
