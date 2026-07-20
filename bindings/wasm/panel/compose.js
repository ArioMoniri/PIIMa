// Turning a wasm span map plus the user's policy into the rendered output.
//
// BYTE OFFSETS, NOT STRING INDICES, and this is the single most likely place
// for the panel to be quietly wrong. `MaskedSpan.start` is a UTF-8 BYTE offset
// into the original document; JavaScript string indices are UTF-16 code units.
// `"ş".length` is 1 in JS and 2 in the span map, so `doc.slice(span.start,
// span.end)` is wrong for every Turkish note -- it drifts one position per
// non-ASCII character and eventually splits a letter in half. So the document
// is encoded to bytes ONCE and every slice is taken from that array and decoded
// back. The cost is one copy per keystroke; the alternative is a panel that
// highlights the wrong characters in exactly the language it is built for.

// `policy.js` owns the method table, this module owns the offsets. Split that
// way because the two are the two things that go wrong, and they go wrong for
// unrelated reasons.
import { apply } from "./policy.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/// Byte length of a string, for tracking offsets into the OUTPUT text.
///
/// The output offsets cannot be derived from the input ones: a replacement
/// deliberately does not preserve the original's length, so every span after
/// the first is displaced by the sum of the differences before it.
function byteLength(text) {
  return encoder.encode(text).length;
}

/// Why a detected span was left in the output.
///
/// Named cases rather than a boolean, because "not masked" has four causes and
/// three of them are the user's own doing. A UI that showed only the outcome
/// would leave someone believing the pipeline had decided something the slider
/// decided.
export const PASSTHROUGH = {
  KEPT: "L4 kept it",
  DISABLED: "type switched off",
  BELOW_THRESHOLD: "below the confidence threshold",
};

/**
 * Compose the de-identified document from the original plus the span map.
 *
 * @param {string} doc the original text
 * @param {Array} spans the wasm span map, ordered and non-overlapping
 * @param {{disabled: Set<string>, methods: Map<string,string>, threshold: number, shiftDays: number}} policy
 */
export function compose(doc, spans, policy) {
  const bytes = encoder.encode(doc);
  const slice = (start, end) => decoder.decode(bytes.subarray(start, end));

  const segments = [];
  let output = "";
  let outputBytes = 0;
  let cursor = 0;

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

/// The order of these tests is the order of authority.
///
/// L4's own `keep` is checked FIRST: it is a decision the pipeline made about
/// the span, and no panel control should be able to overrule it into a mask.
/// The user's controls are checked after, and a span that survives all three
/// is masked.
function classify(span, policy) {
  if (span.decision !== "mask") return PASSTHROUGH.KEPT;
  if (policy.disabled.has(span.label)) return PASSTHROUGH.DISABLED;
  if (span.confidence < policy.threshold) return PASSTHROUGH.BELOW_THRESHOLD;
  return null;
}

/// Count of spans per label, for the entity-type controls.
export function tally(spans) {
  const counts = new Map();
  for (const span of spans) {
    counts.set(span.label, (counts.get(span.label) ?? 0) + 1);
  }
  return counts;
}
