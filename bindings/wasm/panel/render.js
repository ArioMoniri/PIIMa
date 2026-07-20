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
import { family, sigil } from "./policy.js";

/// The shell of a `<mark>`: family coding, provenance, and the span ordinal
/// that links it to its span map row.
///
/// `data-span` is the join key. It is stamped by `compose()` in document order
/// and is the only thing the marked-source view, the masked view, the inline
/// diff and the table agree on, so hover linkage and the masking sweep both
/// hang off it rather than off any view's own DOM order.
function markShell(segment, { withSigil }) {
  const mark = document.createElement("mark");
  const familyName = family(segment.span.label);
  mark.className = `ent fam-${familyName}`;
  if (segment.passthrough !== null) mark.classList.add("passthrough");
  mark.dataset.span = String(segment.index);
  mark.tabIndex = 0;
  const detail = describe(segment);
  mark.title = detail;
  // The tooltip is a `title`, which no browser reliably shows on KEYBOARD
  // focus. The same string therefore also goes to a live region on focus and on
  // hover, so the provenance is reachable without a mouse.
  mark.dataset.detail = detail;
  if (withSigil) {
    // A real element rather than a `::before` with generated content, so its
    // `user-select: none` is honoured on copy. Generated content leaks into the
    // clipboard in some engines, and a two-letter sigil pasted into the middle
    // of a de-identified note would be a corruption of the output.
    const tag = document.createElement("span");
    tag.className = "sigil";
    tag.setAttribute("aria-hidden", "true");
    tag.textContent = sigil(familyName);
    mark.append(tag);
  }
  return mark;
}

/// One `<mark>` for a detected span in the SOURCE view: original text, sigil.
function markFor(segment) {
  const mark = markShell(segment, { withSigil: true });
  mark.append(document.createTextNode(segment.original));
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

/// The de-identified output, with every span marked in place.
///
/// THIS VIEW'S RESTING STATE IS THE ANSWER. A masked span renders as its
/// REPLACEMENT; a span that was detected and then left in the output renders as
/// the ORIGINAL inside a dashed outline. So the two outcomes cannot look alike,
/// and reading this pane straight through gives exactly the bytes the text
/// export writes -- which is why the masking sweep can borrow these nodes for
/// 900ms without the result ever depending on the sweep having run.
///
/// Returns the sweep units, one per masked span, in document order. The caller
/// decides whether to animate them; this function's output is complete and
/// correct either way.
export function renderMasked(target, segments, onDetail) {
  target.replaceChildren();
  const units = [];
  for (const segment of segments) {
    if (segment.kind === "keep") {
      target.append(document.createTextNode(segment.text));
      continue;
    }
    // No sigil here: this pane's text is the de-identified note and people copy
    // it out of the page. Family stays legible through hue plus the underline
    // treatment, and the span map carries the exact label.
    const mark = markShell(segment, { withSigil: false });
    // Same wiring as the marked-source view: `title` is not shown on KEYBOARD
    // focus by any browser, so the provenance also goes to the live region.
    const show = () => onDetail(mark.dataset.detail);
    mark.addEventListener("focus", show);
    mark.addEventListener("mouseenter", show);
    const text = document.createElement("span");
    text.className = "sur";
    if (segment.passthrough !== null) {
      // NEVER ANIMATED, and structurally so: an un-masked span produces no
      // sweep unit at all. A span shown "transforming" that is in fact sitting
      // unchanged in the output is the one lie this panel must never tell.
      text.textContent = segment.original;
      mark.append(text);
      target.append(mark);
      continue;
    }
    text.textContent = segment.replacement;
    mark.append(text);
    target.append(mark);
    units.push({
      mark,
      text,
      row: null,
      index: segment.index,
      from: segment.original,
      final: segment.replacement,
    });
  }
  return units;
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
    removed.dataset.span = String(segment.index);
    removed.textContent = segment.original;
    target.append(removed);
    if (segment.replacement.length > 0) {
      const added = document.createElement("ins");
      added.className = "diff";
      added.dataset.span = String(segment.index);
      added.textContent = segment.replacement;
      target.append(added);
    }
  }
}

/// One data cell.
///
/// `classes` carries the column's TYPE, not its decoration: `num` is what makes
/// a column of byte offsets right-aligned and tabular, so the digits of
/// `55..66` and `222..232` land in the same vertical tracks and a reviewer can
/// see the magnitudes without reading them. A quantity that is not marked `num`
/// is a quantity the eye has to parse one row at a time.
function cell(row, text, classes) {
  const td = document.createElement("td");
  td.textContent = text;
  if (classes) td.className = classes;
  row.append(td);
  return td;
}

/// The label, with its family sigil, so the table repeats the third
/// non-hue channel the marks use and the two are readable against each other.
function labelCell(row, label) {
  const td = document.createElement("td");
  td.className = "mono";
  const familyName = family(label);
  const tag = document.createElement("span");
  tag.className = `sigil fam-${familyName}`;
  tag.setAttribute("aria-hidden", "true");
  tag.textContent = sigil(familyName);
  td.append(tag, document.createTextNode(label));
  row.append(td);
}

function pill(row, text, kind) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = `pill ${kind}`;
  span.textContent = text;
  td.append(span);
  row.append(td);
}

/// How each sortable column extracts its key.
///
/// Offset is the DEFAULT and the only one that is also document order, which is
/// why it is what the panel starts on: a span map read top to bottom should
/// walk the note the way the note is written. Label and confidence are the two
/// questions a reviewer actually asks of the table ("show me every date",
/// "show me what the pipeline was least sure of"), and confidence descending is
/// the wrong default precisely because the low end is the interesting end.
const SORT_KEYS = {
  offset: (segment) => segment.span.start,
  label: (segment) => segment.span.label,
  confidence: (segment) => segment.span.confidence,
};

/// Sort a copy, never the caller's array.
///
/// The panel's segment list is the composition order and the byte-offset
/// bookkeeping depends on it; a table header that reordered it in place would
/// silently corrupt the next render's offsets.
function sorted(spans, sort) {
  const key = SORT_KEYS[sort?.column] ?? SORT_KEYS.offset;
  const direction = sort?.direction === "descending" ? -1 : 1;
  return [...spans].sort((left, right) => {
    const a = key(left);
    const b = key(right);
    if (a === b) return left.index - right.index;
    return (a < b ? -1 : 1) * direction;
  });
}

/// The span map as a real table: both offset systems, provenance, outcome.
///
/// Returns the row element for each span, keyed by span ordinal, so the caller
/// can link a hovered mark to its row and sweep the two in step.
export function renderTable(tbody, segments, sort) {
  tbody.replaceChildren();
  const rowsByIndex = new Map();
  let rows = 0;
  for (const segment of sorted(
    segments.filter((candidate) => candidate.kind === "span"),
    sort,
  )) {
    rows += 1;
    const span = segment.span;
    const row = document.createElement("tr");
    row.dataset.span = String(segment.index);
    rowsByIndex.set(segment.index, row);
    cell(row, `${span.start}..${span.end}`, "mono num");
    cell(row, `${segment.outputStart}..${segment.outputEnd}`, "mono num");
    labelCell(row, span.label);
    cell(row, span.layer, "mono");
    if (segment.passthrough === null) {
      pill(row, "mask", "mask");
    } else if (segment.passthrough === PASSTHROUGH.KEPT) {
      pill(row, "keep", "keep");
    } else {
      pill(row, "NOT MASKED", "suppressed");
    }
    cell(row, span.confidence.toFixed(2), "mono num");
    cell(row, span.checksumValidated ? "yes" : "-", "mono");
    cell(
      row,
      segment.passthrough === null
        ? segment.method + (segment.note ? ` (${segment.note})` : "")
        : segment.passthrough,
      "mono",
    );
    cell(row, segment.passthrough === null ? segment.replacement : "-", "mono");
    tbody.append(row);
  }
  return { rows, rowsByIndex };
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

/// Save raw bytes -- a redacted PDF or `.docx` -- as a local download.
///
/// Separate from [`download`] rather than a widened parameter, because the two
/// differ in a way worth keeping visible: `download` is handed a JS string and
/// the Blob encodes it as UTF-8, which is right for text and CORRUPTING for a
/// binary container. These bytes came out of the wasm module already final and
/// must reach the disk untouched, so they are wrapped in a fresh `Uint8Array`
/// over a copy and never round-tripped through a string.
///
/// A Blob and an object URL, exactly like the text exports: the browser writes
/// the file locally. No request is made and none could be -- every networking
/// global has been a throwing stub since before any file handler was wired up.
export function downloadBytes(filename, mime, bytes) {
  const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: mime }));
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
