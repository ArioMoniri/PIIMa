// The panel's redaction policy. A TypeScript port of
// bindings/wasm/panel/policy.js, deliberately behaviour-for-behaviour identical.
//
// WHAT IS REAL HERE AND WHAT IS A STUB, stated at the top because the
// difference is the difference between a demo and a claim:
//
//   * `surrogate` is REAL. It returns the replacement the wasm module's L5
//     engine produced -- format-preserving, salted, consistent within the
//     document -- computed in Rust, in the same code the CLI runs.
//   * `mask`, `redact`, `hash`, `date-shift` and `remove` are PANEL-SIDE. They
//     are applied here over the span map. `core::redact::RedactionPolicy`
//     implements all six for real, but the wasm binding does not export it, so
//     neither panel can reach it.
//
// WHY THIS IS A PORT AND NOT AN IMPORT: the vanilla panel's modules are plain
// browser ES modules that the Vite build would happily consume -- and then the
// vanilla panel would no longer be six files you can read on their own, it
// would be six files plus whatever this app did to them. The auditable page
// stops being auditable the moment a bundler is a prerequisite for
// understanding it. The duplication is the price of that, and it is paid
// deliberately: `policy.test.ts` pins the two implementations to the same
// answers so the copy cannot drift silently.

import type { DetectedSpan } from "./types";

/**
 * Which colour family a label belongs to, for the highlight view.
 *
 * Grouped rather than one colour per label because there are 34 direct labels
 * and no palette distinguishes 34 hues legibly. The exact label is always in
 * the span map, so the colour is a hint and never the only carrier.
 */
export type Family = "id" | "contact" | "date" | "place" | "name" | "other";

export function family(label: string): Family {
  // FAITHFUL TO THE VANILLA PANEL, INCLUDING ITS DEAD BRANCH. `_NAME` is tested
  // first, so `FACILITY_NAME` resolves to "name" and the `place` test for it
  // below is unreachable. That is arguably wrong -- a hospital is a place --
  // but it is what the audited page does, and `policy.test.ts` asserts the two
  // agree. Quietly "fixing" it here would give two surfaces that colour the
  // same label differently while both claim to be the same policy, which is a
  // worse defect than the one being fixed. Changing it means changing the
  // vanilla panel first, in its own commit.
  if (label.endsWith("_NAME")) return "name";
  if (label.startsWith("DATE") || label === "AGE_OVER_89") return "date";
  if (label === "PHONE" || label === "EMAIL" || label === "URL") return "contact";
  if (label === "IP_ADDRESS") return "contact";
  if (label.startsWith("ADDRESS") || label === "POSTAL_CODE") return "place";
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

/**
 * The two-letter sigil printed on a mark and beside a span map label.
 *
 * COLOUR IS NOT ALLOWED TO BE THE ONLY CHANNEL. About one man in twelve has
 * some colour vision deficiency, and a masking tool whose family coding is
 * hue-only fails them silently -- they see marks, cannot tell an identifier
 * number from a date, and have no way to know they are missing anything. So
 * each family is carried three times over: this sigil, a distinct underline
 * treatment in the stylesheet, and the hue. Any one of the three alone
 * separates the families, and the exact label is in the span map besides.
 */
const SIGILS: Record<Family, string> = {
  id: "ID",
  contact: "CT",
  date: "DT",
  place: "PL",
  name: "NM",
  other: "OT",
};

export function sigil(familyName: Family): string {
  return SIGILS[familyName];
}

/** The six methods, in the order the selector offers them. */
export const METHODS: ReadonlyArray<readonly [string, string]> = [
  ["surrogate", "surrogate (L5, real)"],
  ["mask", "mask - [LABEL]"],
  ["redact", "redact - block"],
  ["hash", "hash - digest"],
  ["date-shift", "date-shift - offset days"],
  ["remove", "remove - delete"],
];

export function defaultMethod(): string {
  return "surrogate";
}

/**
 * FNV-1a, 32 bits, hex.
 *
 * DISPLAY ONLY, and labelled as such in the UI. An unkeyed 32-bit digest of a
 * short Turkish name is trivially enumerable by anyone holding the output, so
 * this is what a hash method looks like, not a hash method that is safe to
 * ship. A real one is a keyed HMAC with a per-run secret.
 */
function fnv1a32(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let hash = 0x811c9dc5;
  for (const byte of bytes) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

/**
 * Recognised date shapes.
 *
 * Turkish clinical text writes `12.03.2024` far more often than anything else,
 * so `DD.MM.YYYY` leads. A span matching none of these is NOT silently left
 * alone: `apply` falls back to a mask and the span table says
 * `date-shift (unparsed)`, because a date-shift that quietly did nothing would
 * leave a real date in the output while the UI claimed a method had run.
 */
const DATE_SHAPES = [
  { re: /^(\d{1,2})([./-])(\d{1,2})\2(\d{4})$/, order: "dmy" },
  { re: /^(\d{4})([./-])(\d{1,2})\2(\d{1,2})$/, order: "ymd" },
] as const;

function pad(value: number, width: number): string {
  return String(value).padStart(width, "0");
}

function shiftDate(original: string, days: number): string | null {
  const text = original.trim();
  for (const shape of DATE_SHAPES) {
    const match = shape.re.exec(text);
    if (!match) continue;
    const separator = match[2]!;
    const [year, month, day] =
      shape.order === "dmy"
        ? [Number(match[4]), Number(match[3]), Number(match[1])]
        : [Number(match[1]), Number(match[3]), Number(match[4])];
    // UTC throughout: a local-time Date shifted by whole days lands an hour out
    // across a DST boundary and silently changes the day.
    const shifted = new Date(Date.UTC(year!, month! - 1, day!));
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

export interface Applied {
  readonly text: string;
  readonly note: string | null;
}

/**
 * Apply one method to one span.
 *
 * `span.replacement` is what the wasm run produced. It is used unchanged by
 * `surrogate` and ignored by every other method, which is what makes the
 * stub/real boundary visible in the output rather than only in a comment.
 */
export function apply(
  method: string,
  span: DetectedSpan,
  original: string,
  shiftDays: number,
): Applied {
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
      return { text: `[${span.label}:${fnv1a32(original)}]`, note: null };
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
