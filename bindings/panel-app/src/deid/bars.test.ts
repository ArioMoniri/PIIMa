// THE TEST FOR RULE 1.
//
// "Only genuinely masked spans get a bar" is the one property of this app that,
// if it broke, would make the product actively dangerous rather than merely
// wrong: a black bar over a patient name that is still in the exported file is
// the UI asserting a safety property this build does not have. So it is tested
// at the data layer here and at the DOM layer in SpanViews.test.tsx, because
// the two could break independently.

import { describe, expect, it } from "vitest";
import { barsFor, isMasked, UnmaskedSpanError, sweepDuration } from "./bars";
import { compose } from "./compose";
import { DOC, NAME_SPAN, OPEN_POLICY, SPANS, TCKN_SPAN } from "./fixtures";
import { PASSTHROUGH } from "./types";
import type { Segment, SpanSegment } from "./types";

function segmentsOf(threshold = 0) {
  return compose(DOC, SPANS, { ...OPEN_POLICY, threshold }).segments;
}

describe("barsFor", () => {
  it("gives no bar to a detected name that was not masked", () => {
    const bars = barsFor(segmentsOf());
    expect(bars.some((bar) => bar.label === "PATIENT_NAME")).toBe(false);
  });

  it("gives a bar to a span that really was removed and replaced", () => {
    const bars = barsFor(segmentsOf());
    const tckn = bars.find((bar) => bar.label === "TCKN");
    expect(tckn).toBeDefined();
    expect(tckn?.original).toBe("12345678901");
    expect(tckn?.surrogate).toBe(TCKN_SPAN.replacement);
  });

  it("draws exactly as many bars as the composition says were masked", () => {
    const segments = segmentsOf();
    const masked = segments.filter(isMasked).length;
    expect(barsFor(segments)).toHaveLength(masked);
  });

  it("drops a bar when the user's threshold un-masks a span", () => {
    // The PHONE span is confidence 0.6. Above 0.6 it stops being masked, so its
    // bar must disappear -- a bar that survived the control that un-masked its
    // span would be claiming a removal the user themselves switched off.
    expect(barsFor(segmentsOf(0.5)).some((b) => b.label === "PHONE")).toBe(true);
    expect(barsFor(segmentsOf(0.9)).some((b) => b.label === "PHONE")).toBe(false);
  });

  it("throws rather than drawing a bar over an unmasked span", () => {
    // Simulates the future edit this guard exists for: a filter that lets a
    // kept span through. Types are erased in the shipped bundle, so this is the
    // mechanism that still holds there.
    const kept: SpanSegment = {
      kind: "span",
      index: 0,
      span: NAME_SPAN,
      original: "Ayse Yilmaz",
      replacement: "Zeynep Kaya",
      note: null,
      method: null,
      passthrough: PASSTHROUGH.KEPT,
      outputStart: 0,
      outputEnd: 11,
    };
    // `barsFor` filters first, so reach the assertion by handing it a segment
    // that claims to be masked to the filter and is not.
    const lying = { ...kept, passthrough: null } as SpanSegment;
    Object.defineProperty(lying, "passthrough", {
      get: (() => {
        let first = true;
        return () => {
          // null to the filter, then the truth to the assertion.
          if (first) {
            first = false;
            return null;
          }
          return PASSTHROUGH.KEPT;
        };
      })(),
    });
    expect(() => barsFor([lying])).toThrow(UnmaskedSpanError);
  });

  it("never puts document text in the error it throws (I4)", () => {
    // An error string is the most likely thing in a program to reach a console,
    // a bug report or a log file, and the text under a bar is by construction
    // the text this project exists to keep off all three.
    const thrown = new UnmaskedSpanError(3, "PATIENT_NAME", PASSTHROUGH.KEPT);
    expect(thrown.message).not.toContain("Ayse");
    expect(thrown.message).not.toContain("Yilmaz");
    expect(thrown.message).toContain("#3");
    expect(thrown.message).toContain("PATIENT_NAME");
  });

  it("excludes a masked span whose replacement is empty", () => {
    // The `remove` method. There is nothing for a bar to resolve into, and a
    // bar that collapsed to zero width at the end would reflow the page.
    const removed: Segment[] = [
      {
        kind: "span",
        index: 0,
        span: TCKN_SPAN,
        original: "12345678901",
        replacement: "",
        note: null,
        method: "remove",
        passthrough: null,
        outputStart: 0,
        outputEnd: 0,
      },
    ];
    expect(barsFor(removed)).toHaveLength(0);
  });

  it("staggers in document order and keeps the sweep inside its budget", () => {
    const bars = barsFor(segmentsOf());
    const delays = bars.map((bar) => bar.delay);
    expect(delays).toEqual([...delays].sort((a, b) => a - b));
    expect(delays[0]).toBe(0);
    expect(sweepDuration(bars)).toBeLessThan(1500);
  });

  it("carries the document-order index compose stamped, not its own position", () => {
    // The bar's `index` is the join key to the span map row. The name span sits
    // between them in document order and gets no bar, so a bar list numbered by
    // its own position would point every row at the wrong span.
    const bars = barsFor(segmentsOf());
    expect(bars.map((bar) => bar.label)).toEqual(["TCKN", "PHONE"]);
    expect(bars.map((bar) => bar.index)).toEqual([1, 2]);
    expect(bars.map((bar) => bar.index)).toEqual(
      [...bars.map((bar) => bar.index)].sort((a, b) => a - b),
    );
  });
});
