// The panel's redaction policy, and the honest account of what it is.
//
// WHAT IS REAL HERE AND WHAT IS A STUB, stated at the top because the
// difference is the difference between a demo and a claim:
//
//   * `surrogate` is REAL. It returns the replacement the wasm module's L5
//     engine produced -- format-preserving, salted, consistent within the
//     document -- computed in Rust, in the same code the CLI runs.
//   * `mask`, `redact`, `hash`, `date-shift` and `remove` are PANEL-SIDE. They
//     are applied here in JavaScript over the span map. `core::redact::
//     RedactionPolicy` exists and implements all six for real, but the wasm
//     binding does not export it, so this page cannot reach it. When the
//     binding does, this module becomes a thin adapter and these five stop
//     being local re-implementations.
//
// The six values below are deliberately 1:1 with `core`'s `RedactionMethod`
// variants -- Mask, Redact, Hash, DateShift, Surrogate, Remove -- and the two
// fallbacks below (date-shift on a non-date, an absent replacement) mirror what
// `core` does in the same situations, so the swap changes the implementation
// and not the behaviour.
//
// The stub is marked in the UI as well as here. A method selector that silently
// did its own thing while looking like the pipeline's would be the exact
// category of lie this project exists to not tell.

/// Which colour family a label belongs to, for the highlight view.
///
/// Grouped rather than one colour per label because there are 34 direct labels
/// and no palette distinguishes 34 hues legibly. The exact label is always in
/// the tooltip and in the span table, so the colour is a hint and never the
/// only carrier of the information.
export function family(label) {
  if (label.endsWith("_NAME")) return "name";
  if (label.startsWith("DATE") || label === "AGE_OVER_89") return "date";
  if (label === "PHONE" || label === "EMAIL" || label === "URL") {
    return "contact";
  }
  if (label === "IP_ADDRESS") return "contact";
  if (label.startsWith("ADDRESS") || label === "POSTAL_CODE") return "place";
  if (label === "FACILITY_NAME") return "place";
  if (
    label === "TCKN" ||
    label === "VKN" ||
    label === "SGK_NO" ||
    label === "MRN" ||
    label === "IBAN" ||
    label === "PASSPORT_NO" ||
    label.endsWith("_ID") ||
    label.endsWith("_NO")
  ) {
    return "id";
  }
  return "other";
}

/// The six methods, in the order the selector offers them.
export const METHODS = [
  ["surrogate", "surrogate (L5, real)"],
  ["mask", "mask - [LABEL]"],
  ["redact", "redact - block"],
  ["hash", "hash - digest"],
  ["date-shift", "date-shift - offset days"],
  ["remove", "remove - delete"],
];

/// The method a label starts on.
///
/// Surrogate for everything, because it is the only one that is the pipeline's
/// own answer and the only one that keeps the note readable as clinical prose.
export function defaultMethod() {
  return "surrogate";
}

/// FNV-1a, 32 bits, hex.
///
/// DISPLAY ONLY, and labelled as such in the UI. An unkeyed 32-bit digest of a
/// short Turkish name is trivially enumerable by anyone holding the output, so
/// this is what a hash method looks like, not a hash method that is safe to
/// ship. A real one is a keyed HMAC with a per-run secret -- the same fix the
/// project's own `text_hash: u64` is waiting on.
function fnv1a32(text) {
  const bytes = new TextEncoder().encode(text);
  let hash = 0x811c9dc5;
  for (const byte of bytes) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/// Recognised date shapes, and the pieces needed to rebuild one.
///
/// Turkish clinical text writes `12.03.2024` far more often than anything else,
/// so `DD.MM.YYYY` leads. A span that matches none of these is NOT silently
/// left alone: `apply` falls back to a mask and the span table says
/// `date-shift (unparsed)`, because a date-shift that quietly did nothing would
/// leave a real date in the output while the UI claimed a method had run.
const DATE_SHAPES = [
  { re: /^(\d{1,2})([./-])(\d{1,2})\2(\d{4})$/, order: "dmy" },
  { re: /^(\d{4})([./-])(\d{1,2})\2(\d{1,2})$/, order: "ymd" },
];

function pad(value, width) {
  return String(value).padStart(width, "0");
}

/// Shift a date by `days`, preserving its separator and field order.
///
/// Returns `null` when the span is not a date this panel can parse.
function shiftDate(original, days) {
  const text = original.trim();
  for (const shape of DATE_SHAPES) {
    const match = shape.re.exec(text);
    if (!match) continue;
    const separator = match[2];
    const [year, month, day] =
      shape.order === "dmy"
        ? [Number(match[4]), Number(match[3]), Number(match[1])]
        : [Number(match[1]), Number(match[3]), Number(match[4])];
    // UTC throughout: a local-time Date shifted by whole days lands an hour
    // out across a DST boundary and silently changes the day.
    const shifted = new Date(Date.UTC(year, month - 1, day));
    if (Number.isNaN(shifted.getTime())) return null;
    shifted.setUTCDate(shifted.getUTCDate() + days);
    const y = pad(shifted.getUTCFullYear(), 4);
    const m = pad(shifted.getUTCMonth() + 1, 2);
    const d = pad(shifted.getUTCDate(), 2);
    return shape.order === "dmy"
      ? `${d}${separator}${m}${separator}${y}`
      : `${y}${separator}${m}${separator}${d}`;
  }
  return null;
}

/// Apply one method to one span.
///
/// `span.replacement` is what the wasm run produced. It is used unchanged by
/// `surrogate` and ignored by every other method, which is what makes the
/// stub/real boundary visible in the output rather than only in a comment.
///
/// Returns `{ text, note }`; `note` is non-null when the method could not do
/// what its name says and something else happened instead.
export function apply(method, span, original, shiftDays) {
  switch (method) {
    case "surrogate":
      return span.replacement === null || span.replacement === undefined
        ? { text: `[${span.label}]`, note: "no L5 replacement, masked instead" }
        : { text: span.replacement, note: null };
    case "mask":
      return { text: `[${span.label}]`, note: null };
    case "redact":
      // A FIXED width, deliberately not the original's. Drawing one block per
      // removed character republishes the length of the identifier, and length
      // is a re-identification signal: an eight-character surname is a much
      // smaller candidate set than "a surname".
      return { text: "█".repeat(8), note: null };
    case "hash":
      return {
        // `[LABEL:digest]`, the shape `core::redact` uses, so the output does
        // not change when the real keyed implementation replaces this one.
        text: `[${span.label}:${fnv1a32(original)}]`,
        note: null,
      };
    case "date-shift": {
      const shifted = shiftDate(original, shiftDays);
      return shifted === null
        ? { text: `[${span.label}]`, note: "not a parseable date, masked" }
        : { text: shifted, note: null };
    }
    case "remove":
      return { text: "", note: null };
    default:
      return { text: `[${span.label}]`, note: "unknown method, masked" };
  }
}
