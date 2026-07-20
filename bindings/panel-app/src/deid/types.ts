// The shapes that cross the wasm boundary, and the shapes the views consume.
//
// These mirror `core::Span` / `core::MappedSpan`. They are re-declared here
// rather than generated because the wasm-bindgen .d.ts describes handles into
// linear memory, and every one of those has to be `free()`d; what the React
// tree holds is the flattened, owned copy taken before the handles are
// released. Keeping the two types distinct is what stops a component from
// accidentally retaining a pointer to the clinical note.

/** Why a detected span was left in the output. */
export const PASSTHROUGH = {
  KEPT: "L4 kept it",
  DISABLED: "type switched off",
  BELOW_THRESHOLD: "below the confidence threshold",
} as const;

export type Passthrough = (typeof PASSTHROUGH)[keyof typeof PASSTHROUGH];

/** One span of the wasm span map, flattened out of its handle. */
export interface DetectedSpan {
  /** UTF-8 BYTE offset into the original document. Not a string index. */
  readonly start: number;
  /** Exclusive UTF-8 byte offset. */
  readonly end: number;
  readonly label: string;
  readonly layer: string;
  readonly decision: string;
  readonly confidence: number;
  readonly checksumValidated: boolean;
  readonly replacement: string | null;
}

/** A run of text the pipeline did not touch. */
export interface KeepSegment {
  readonly kind: "keep";
  readonly text: string;
}

/**
 * A detected span, positioned in the composed output.
 *
 * `passthrough === null` is the ONLY thing in this application that means
 * "this text was genuinely removed and replaced". Every downstream decision --
 * whether a bar is drawn, what the counts say, what the span map row reads --
 * resolves back to this one field, so that there is exactly one definition of
 * "masked" and not four that can drift apart.
 */
export interface SpanSegment {
  readonly kind: "span";
  /** Ordinal in DOCUMENT ORDER. The join key between every view. */
  readonly index: number;
  readonly span: DetectedSpan;
  readonly original: string;
  readonly replacement: string;
  readonly note: string | null;
  readonly method: string | null;
  readonly passthrough: Passthrough | null;
  readonly outputStart: number;
  readonly outputEnd: number;
}

export type Segment = KeepSegment | SpanSegment;

export interface Composition {
  readonly segments: readonly Segment[];
  readonly output: string;
}

export interface Policy {
  readonly disabled: ReadonlySet<string>;
  readonly methods: ReadonlyMap<string, string>;
  readonly threshold: number;
  readonly shiftDays: number;
}
