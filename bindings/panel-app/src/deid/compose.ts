// Turning a wasm span map plus the user's policy into the rendered output.
//
// BYTE OFFSETS, NOT STRING INDICES, and this is the single most likely place
// for a panel to be quietly wrong. `MaskedSpan.start` is a UTF-8 BYTE offset
// into the original document; JavaScript string indices are UTF-16 code units.
// `"ş".length` is 1 in JS and 2 in the span map, so `doc.slice(span.start,
// span.end)` is wrong for every Turkish note -- it drifts one position per
// non-ASCII character and eventually splits a letter in half. So the document
// is encoded to bytes ONCE and every slice is taken from that array and decoded
// back.

import { apply } from "./policy";
import { PASSTHROUGH } from "./types";
import type {
  Composition,
  DetectedSpan,
  Passthrough,
  Policy,
  Segment,
} from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * Byte length of a string, for tracking offsets into the OUTPUT text.
 *
 * The output offsets cannot be derived from the input ones: a replacement
 * deliberately does not preserve the original's length, so every span after the
 * first is displaced by the sum of the differences before it.
 */
function byteLength(text: string): number {
  return encoder.encode(text).length;
}

/**
 * The order of these tests is the order of authority.
 *
 * L4's own `keep` is checked FIRST: it is a decision the pipeline made about
 * the span, and no panel control should be able to overrule it into a mask. The
 * user's controls are checked after, and a span that survives all three is
 * masked.
 */
function classify(span: DetectedSpan, policy: Policy): Passthrough | null {
  if (span.decision !== "mask") return PASSTHROUGH.KEPT;
  if (policy.disabled.has(span.label)) return PASSTHROUGH.DISABLED;
  if (span.confidence < policy.threshold) return PASSTHROUGH.BELOW_THRESHOLD;
  return null;
}

/** Compose the de-identified document from the original plus the span map. */
export function compose(
  doc: string,
  spans: readonly DetectedSpan[],
  policy: Policy,
): Composition {
  const bytes = encoder.encode(doc);
  const slice = (start: number, end: number) =>
    decoder.decode(bytes.subarray(start, end));

  const segments: Segment[] = [];
  let output = "";
  let outputBytes = 0;
  let cursor = 0;
  // The span's ordinal in DOCUMENT ORDER, stamped here rather than recomputed
  // per view. The document page, the span map and the output view all render
  // the same span and have to agree on which one it is: this is the key that
  // links a highlighted row to its bar, and the order the blackout staggers
  // along. Deriving it separately in each renderer is how those drift apart.
  let index = 0;

  for (const span of spans) {
    const gap = slice(cursor, span.start);
    if (gap.length > 0) {
      segments.push({ kind: "keep", text: gap });
      output += gap;
      outputBytes += byteLength(gap);
    }

    const original = slice(span.start, span.end);
    const passthrough = classify(span, policy);
    const method = policy.methods.get(span.label) ?? "surrogate";
    const applied =
      passthrough === null
        ? apply(method, span, original, policy.shiftDays)
        : { text: original, note: null };

    segments.push({
      kind: "span",
      index: index++,
      span,
      original,
      replacement: applied.text,
      note: applied.note,
      method: passthrough === null ? method : null,
      passthrough,
      outputStart: outputBytes,
      outputEnd: outputBytes + byteLength(applied.text),
    });
    output += applied.text;
    outputBytes += byteLength(applied.text);
    cursor = span.end;
  }

  const tail = slice(cursor, bytes.length);
  if (tail.length > 0) {
    segments.push({ kind: "keep", text: tail });
    output += tail;
  }

  return { segments, output };
}

/** Count of spans per label, for the entity-type controls. */
export function tally(spans: readonly DetectedSpan[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const span of spans) {
    counts.set(span.label, (counts.get(span.label) ?? 0) + 1);
  }
  return counts;
}

/** How many spans were genuinely removed and replaced. */
export function maskedCount(segments: readonly Segment[]): number {
  return segments.filter((s) => s.kind === "span" && s.passthrough === null)
    .length;
}

/** How many spans were detected, masked or not. */
export function spanCount(segments: readonly Segment[]): number {
  return segments.filter((s) => s.kind === "span").length;
}
