// RULE 1 AT THE DOM LEVEL.
//
// bars.test.ts proves no bar OBJECT is built for an unmasked span. This proves
// no bar ELEMENT reaches the page. The two can break independently -- a bar
// object could exist and never render, and a bar element could be added to the
// wrong component without any bar object being involved -- so both are tested.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DocumentView } from "./DocumentView";
import { barsByIndex, barsFor } from "@/deid/bars";
import { compose } from "@/deid/compose";
import { DOC, OPEN_POLICY, SPANS } from "@/deid/fixtures";

function renderDoc(sweeping: boolean) {
  const { segments } = compose(DOC, SPANS, OPEN_POLICY);
  const bars = barsFor(segments);
  return render(
    <DocumentView
      segments={segments}
      bars={barsByIndex(bars)}
      sweeping={sweeping}
      runKey={1}
    />,
  );
}

describe("the document view", () => {
  it("puts no bar element inside an unmasked span", () => {
    const { container } = renderDoc(true);
    const kept = container.querySelectorAll('[data-masked="false"]');
    expect(kept.length).toBeGreaterThan(0);
    for (const node of kept) {
      expect(node.querySelector(".bar")).toBeNull();
    }
  });

  it("puts a bar element inside every masked span", () => {
    const { container } = renderDoc(true);
    const masked = container.querySelectorAll('[data-masked="true"]');
    expect(masked.length).toBe(2); // TCKN and PHONE, not the name
    for (const node of masked) {
      expect(node.querySelector(".bar")).not.toBeNull();
    }
  });

  it("draws no more bars than there were masked spans", () => {
    const { container } = renderDoc(true);
    expect(container.querySelectorAll(".bar")).toHaveLength(2);
  });

  it("leaves the unmasked name text in the page, visibly untreated", () => {
    const { container } = renderDoc(true);
    const kept = container.querySelector('[data-masked="false"]');
    expect(kept?.textContent).toBe("Ayse Yilmaz");
    // The dashed-outline class, which is what says "found, left in".
    expect(kept?.classList.contains("mark-kept")).toBe(true);
    // And it says so in words too, for anyone who cannot see an outline.
    expect(kept?.getAttribute("title")).toContain("NOT REMOVED");
  });

  it("renders the surrogate as the resting text of a masked span", () => {
    // RULE 2: the final state is what the markup says, animation or not. The
    // original is present only as an aria-hidden layer for the sweep to cover.
    const { container } = renderDoc(false);
    const masked = container.querySelector('[data-masked="true"]');
    expect(masked?.querySelector(".mark-after")?.textContent).toBe(
      "98765432109",
    );
    expect(masked?.querySelector(".mark-before")?.getAttribute("aria-hidden")).toBe(
      "true",
    );
  });

  it("renders identical span content whether or not a sweep is running", () => {
    // RULE 2, stated as an equality. The `sweeping` class is the ONLY
    // difference between an animating render and a settled one; no text, no
    // element and no attribute inside a span depends on it.
    const playing = renderDoc(true).container.querySelector(".doc-page")!
      .innerHTML;
    const settled = renderDoc(false).container.querySelector(".doc-page")!
      .innerHTML;
    expect(playing).toBe(settled);
  });

  it("labels every page as extracted text rather than a rendering", () => {
    renderDoc(false);
    for (const label of screen.getAllByText(/extracted text/i)) {
      expect(label.textContent).toContain("not a rendering of the source file");
    }
  });
});
