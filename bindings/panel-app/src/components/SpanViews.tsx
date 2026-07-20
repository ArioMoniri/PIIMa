// THE THIRD ENFORCEMENT OF RULE 1, and the one that is genuinely structural.
//
// There are two components here and they are not variants of one component.
// `MaskedSpanView` renders a `<span class="bar">`; `KeptSpanView` does not
// contain that element, or any element it could be applied to. The blackout bar
// is NOT a class toggled on a shared node -- if it were, one wrong boolean
// would put a bar over an unmasked patient name, and the bug would look like a
// styling bug rather than like a false safety claim.
//
// The dispatch below is total and reads off the single predicate `isMasked`, so
// there is no third case and no default branch where a span could fall through
// into the wrong renderer.
//
// To break this you would have to add bar markup to a component whose docblock
// says not to, which is a different kind of act from getting a condition
// backwards.

import { isMasked } from "@/deid/bars";
import type { RedactionBar } from "@/deid/bars";
import { family, sigil } from "@/deid/policy";
import type { Segment, SpanSegment } from "@/deid/types";

const FAMILY_CLASS: Record<string, string> = {
  id: "fam-id",
  contact: "fam-contact",
  date: "fam-date",
  place: "fam-place",
  name: "fam-name",
  other: "fam-other",
};

function familyClass(label: string): string {
  return FAMILY_CLASS[family(label)] ?? "fam-other";
}

/**
 * A span that was genuinely removed and replaced.
 *
 * Takes a `RedactionBar`, not a boolean and not a segment. The bar type can
 * only be produced by `barsFor`, so a caller cannot render this component for a
 * span that was not masked without first obtaining a value it has no way to
 * construct.
 */
export function MaskedSpanView({
  segment,
  bar,
}: {
  segment: SpanSegment;
  bar: RedactionBar;
}) {
  const label = segment.span.label;
  return (
    <span
      className={`mark ${familyClass(label)}`}
      // CSSOM, not a parsed style attribute: React writes custom properties
      // through `node.style.setProperty`, which `style-src 'self'` does not
      // govern. This is the one place the app relies on that distinction.
      style={{ "--bar-delay": `${bar.delay}ms` } as React.CSSProperties}
      data-span-index={segment.index}
      data-masked="true"
      title={`${label} - ${sigil(family(label))} - removed and replaced by ${segment.method}`}
    >
      <span className="mark-stack">
        {/* The text that WAS here. Present in the DOM in both phases so the box
            never resizes; hidden by default and revealed only for the first
            frames of the sweep. */}
        <span className="mark-before" aria-hidden="true">
          {segment.original}
        </span>
        {/* THE FINAL STATE, AND THE DEFAULT ONE. This is what a reader sees if
            no animation ever runs: the surrogate, already in place. */}
        <span className="mark-after">{segment.replacement}</span>
      </span>
      <span className="bar" aria-hidden="true" />
    </span>
  );
}

/**
 * A span the pipeline detected and did NOT mask.
 *
 * DO NOT ADD A BAR ELEMENT TO THIS COMPONENT. In this build every `*_NAME` span
 * that ever appears would land here, because L2 has no trained model and names
 * are not masked. A bar drawn here is the UI telling a clinician a patient name
 * was removed from a document that still contains it. The dashed outline says
 * "found, left in", which is what happened.
 */
export function KeptSpanView({ segment }: { segment: SpanSegment }) {
  const label = segment.span.label;
  return (
    <span
      className={`mark mark-kept ${familyClass(label)}`}
      data-span-index={segment.index}
      data-masked="false"
      title={`${label} - ${sigil(family(label))} - DETECTED BUT NOT REMOVED (${segment.passthrough}). This text is still in the output.`}
    >
      {segment.original}
    </span>
  );
}

/** Plain text the pipeline did not touch. */
export function KeepView({ text }: { text: string }) {
  return <>{text}</>;
}

/** Total dispatch over the three segment shapes. */
export function SegmentView({
  segment,
  bars,
}: {
  segment: Segment;
  bars: ReadonlyMap<number, RedactionBar>;
}) {
  if (segment.kind === "keep") return <KeepView text={segment.text} />;
  if (!isMasked(segment)) return <KeptSpanView segment={segment} />;
  const bar = bars.get(segment.index);
  // A masked span with no bar is the `remove` method: nothing to reveal, so
  // `barsFor` excluded it. It still renders in its final state -- absent --
  // rather than being dropped from the tree, so the span map row still has
  // something to point at.
  if (!bar) return <MaskedNoBarView segment={segment} />;
  return <MaskedSpanView segment={segment} bar={bar} />;
}

/** A masked span with an empty replacement. Genuinely gone; nothing to draw. */
function MaskedNoBarView({ segment }: { segment: SpanSegment }) {
  return (
    <span
      className="mark fam-other"
      data-span-index={segment.index}
      data-masked="true"
      title={`${segment.span.label} - removed, no replacement text`}
    />
  );
}
