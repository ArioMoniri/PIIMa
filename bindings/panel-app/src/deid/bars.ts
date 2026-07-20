// THE BLACKOUT BARS, AND THE RULE THAT GOVERNS THEM.
//
// ============================================================================
// RULE 1: ONLY GENUINELY MASKED SPANS GET A BAR.
// ============================================================================
//
// This animation is far more convincing than a text scramble. A black bar
// sweeping down a page is the single most recognisable visual shorthand for
// "this was redacted" that exists, and a reader who sees one over a patient
// name will believe the name is gone. In this build it is NOT gone: L2 has no
// trained model, no weights ship, and PATIENT_NAME, CLINICIAN_NAME and
// RELATIVE_NAME pass through untouched. A bar over one of them would be the UI
// asserting a safety property that is false -- and a convincing lie is worse
// than an ugly truth, because an ugly truth gets checked.
//
// So the rule is not "remember not to do that". It is enforced three ways, and
// each one alone would have to be deliberately dismantled to break it:
//
//   1. TYPE. `RedactionBar` carries a brand keyed to a module-private symbol.
//      `BRAND` is not exported, so no code outside this file can write an
//      object literal that type-checks as a `RedactionBar`. `barsFor` is the
//      only exported producer, and it derives every bar from a `SpanSegment`
//      whose `passthrough` is null.
//      THE HONEST LIMIT OF THIS: `x as unknown as RedactionBar` still compiles,
//      because TypeScript has no sealed type. The brand stops the accident, not
//      the determined edit -- which is exactly why it is not the only mechanism
//      and why (2) exists.
//
//   2. RUNTIME. `barsFor` re-checks the invariant on the way out and throws if
//      it is ever violated. Types are erased at runtime, and this app is
//      shipped as a bundle; a future edit that widens the filter would
//      otherwise produce a lie that only a reader of this file would catch.
//      The thrown message carries the span INDEX and LABEL and never the
//      covered text (I4: document text never enters an error, a log or a
//      panic).
//
//   3. STRUCTURE, in the view layer. `MaskedSpanView` renders the bar element
//      as a child; `KeptSpanView` is a separate component whose JSX contains no
//      bar element at all. The bar is not a class toggled on a shared node --
//      there is no node under a kept span for a bar to appear on. Breaking this
//      requires adding markup to a component whose entire docblock says not to.
//
// `bars.test.ts` covers all three, with an unmasked PATIENT_NAME as the fixture
// because that is the exact span this build gets wrong if anything here rots.
//
// ============================================================================
// RULE 2: THE ANIMATION IS NEVER THE ONLY SIGNAL.
// ============================================================================
//
// Nothing in this module computes anything. Bars are derived from a composition
// that is already complete: the output text, the counts, the span map and the
// live region are all correct and on screen before a bar is built, and the
// components render their FINAL state by default with the animation added on
// top. A reader who looks away, whose tab is backgrounded, or whose browser
// never runs a CSS animation sees the same result.
//
// ============================================================================
// RULE 3: prefers-reduced-motion: reduce DISABLES ALL OF IT.
// ============================================================================
//
// Checked live (see `useReducedMotion`), not cached at module load, so a viewer
// who changes the system setting mid-session gets the new behaviour on the next
// run. Under reduce, the final state is what renders and no bar is ever drawn.
// The exported output is byte-identical either way, because export reads
// `composition.output`, which this module cannot reach.

import type { Segment, SpanSegment } from "./types";

/** Module-private. Not exported, which is what makes the brand a brand. */
declare const BRAND: unique symbol;

/**
 * One black bar: the visual record of one span that was removed and replaced.
 *
 * There is no way to obtain one of these except from `barsFor`.
 */
export interface RedactionBar {
  readonly [BRAND]: true;
  /** Ordinal in document order. The join key to the span map row. */
  readonly index: number;
  /** The text that WAS there and is not any more. */
  readonly original: string;
  /** The surrogate that replaced it. What the bar resolves to reveal. */
  readonly surrogate: string;
  readonly label: string;
  /** Milliseconds after the sweep starts that this bar begins covering. */
  readonly delay: number;
}

/**
 * Milliseconds. The whole sweep is budgeted to finish well inside 1.5s on a
 * note with any plausible number of spans, because this is a tool and not a
 * title sequence. STAGGER_MAX is the per-span delay on a short note; on a long
 * one the stagger compresses so the TOTAL never exceeds SWEEP_BUDGET.
 */
export const COVER_MS = 200;
/** The bar sits opaque while the text underneath is swapped. */
export const HOLD_MS = 120;
/**
 * The bar wipes away to reveal the surrogate.
 *
 * THIS PHASE IS NOT DECORATION. A bar that stayed opaque forever would say
 * "this was painted over", and painting over is what a flattened PDF does --
 * the text is still in the file underneath. What actually happened here is that
 * the text was REMOVED from the string and a surrogate was put in its place.
 * The resolve is the part of the animation that tells the truth about which of
 * those two operations ran.
 */
export const REVEAL_MS = 240;
export const BAR_TOTAL_MS = COVER_MS + HOLD_MS + REVEAL_MS;

const STAGGER_MAX = 90;
const SWEEP_BUDGET = 700;

/**
 * Thrown when the masked-only invariant is violated at runtime.
 *
 * Carries the offending span's index and label. NEVER its text: an error string
 * is the most likely thing in a program to end up in a console, a bug report or
 * a log file, and the text under a bar is by construction the text this project
 * exists to keep off all three (I4).
 */
export class UnmaskedSpanError extends Error {
  constructor(index: number, label: string, reason: string) {
    super(
      `refusing to draw a blackout bar over span #${index} (${label}): ` +
        `it was not masked (${reason}). A bar over an unmasked span asserts a ` +
        `safety property this build does not have.`,
    );
    this.name = "UnmaskedSpanError";
  }
}

/**
 * Is this segment one the pipeline genuinely removed and replaced?
 *
 * The single predicate. Everything that draws a bar, counts a mask or claims a
 * removal resolves back through here, so there is one definition and not five.
 */
export function isMasked(segment: Segment): segment is SpanSegment {
  return segment.kind === "span" && segment.passthrough === null;
}

/**
 * Build the bar list for a composition, in document order.
 *
 * THE ONLY PRODUCER OF `RedactionBar`. See the header of this file.
 *
 * Zero-length replacements (the `remove` method) are excluded: there is nothing
 * for a bar to resolve INTO, and collapsing the box at the end of the reveal
 * would reflow the page under the reader. Those spans render in their final
 * state -- absent -- immediately, which is the truth about them.
 */
export function barsFor(segments: readonly Segment[]): RedactionBar[] {
  const masked = segments.filter(isMasked).filter((s) => s.replacement.length > 0);

  const stagger =
    masked.length === 0
      ? 0
      : Math.min(STAGGER_MAX, SWEEP_BUDGET / masked.length);

  return masked.map((segment, position) => {
    // Belt and braces, and the braces are load-bearing. `isMasked` above is the
    // filter; this is the assertion that the filter is still the filter. If a
    // later edit reorders or widens the pipeline, this throws in the developer's
    // face rather than shipping a bar over a live patient name.
    if (segment.passthrough !== null) {
      throw new UnmaskedSpanError(
        segment.index,
        segment.span.label,
        segment.passthrough,
      );
    }
    return {
      index: segment.index,
      original: segment.original,
      surrogate: segment.replacement,
      label: segment.span.label,
      delay: Math.round(position * stagger),
    } as RedactionBar;
  });
}

/** Total duration of a sweep over these bars, in milliseconds. */
export function sweepDuration(bars: readonly RedactionBar[]): number {
  if (bars.length === 0) return 0;
  return bars[bars.length - 1]!.delay + BAR_TOTAL_MS;
}

/**
 * Index the bars by span ordinal, so a span map row can find its own bar's
 * delay and light up in step with it rather than merely at the same time.
 */
export function barsByIndex(
  bars: readonly RedactionBar[],
): ReadonlyMap<number, RedactionBar> {
  return new Map(bars.map((bar) => [bar.index, bar]));
}
