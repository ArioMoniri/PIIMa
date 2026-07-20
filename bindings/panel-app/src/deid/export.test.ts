// RULE 3, AND THE HALF OF IT THAT MATTERS MOST.
//
// "prefers-reduced-motion disables the animation" is easy and would be true of
// almost any implementation. "the exported output is byte-identical either way"
// is the property with teeth: it says the animation is presentation and cannot
// reach the artifact. A tool whose accessibility setting changed the contents
// of the de-identified file would be unusable by anyone who needed the setting,
// and the difference would be invisible until someone diffed two downloads.
//
// The test is structural rather than behavioural: `compose()` is a pure
// function of (text, spans, policy), and nothing in the animation path is one
// of its inputs. That is the reason the property holds, and this pins it.

import { describe, expect, it } from "vitest";
import { exportBytes } from "@/App";
import { barsFor } from "./bars";
import { compose } from "./compose";
import { DOC, OPEN_POLICY, SPANS } from "./fixtures";

describe("exported output", () => {
  it("is identical whether or not a sweep ran", () => {
    const encoder = new TextEncoder();

    const withAnimation = compose(DOC, SPANS, OPEN_POLICY);
    // Building the bars is the entire animation-side effect on this data. Doing
    // it between the two compositions is the closest this can get to "a sweep
    // happened", and the point is that it changes nothing.
    barsFor(withAnimation.segments);
    const withoutAnimation = compose(DOC, SPANS, OPEN_POLICY);

    expect(encoder.encode(withAnimation.output)).toEqual(
      encoder.encode(withoutAnimation.output),
    );
  });

  it("matches what the output tab shows and what a download would contain", () => {
    // Two producers of the same bytes: `compose` accumulates the string as it
    // walks, `exportBytes` re-joins the segments afterwards. If they ever
    // disagree, the text on screen is not the text in the file -- which is the
    // one discrepancy a de-identification tool must not have.
    const { segments, output } = compose(DOC, SPANS, OPEN_POLICY);
    expect(exportBytes(segments)).toBe(output);
  });

  it("still contains the unmasked name, which is the point", () => {
    // If this test ever starts failing because the name is gone, that is not a
    // fix -- it means something started masking names, and the banner, the
    // README and the four places docs/DEPLOY.md names have all become false.
    const { output } = compose(DOC, SPANS, OPEN_POLICY);
    expect(output).toContain("Ayse Yilmaz");
    expect(output).not.toContain("12345678901");
  });
});
