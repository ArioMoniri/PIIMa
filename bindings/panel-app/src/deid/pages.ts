// Splitting the composed segments into page-shaped blocks.
//
// WHAT THIS IS NOT: a rendering of the source PDF. There is no rasteriser here
// and the CSP forbids loading one (`script-src 'self'`, `img-src 'none'`), so
// this app cannot show you a picture of your document and does not pretend to.
// What it lays out is the EXTRACTED TEXT -- the same string the pipeline read,
// in the same order, with the spans in their real positions in it. The page
// shape is a reading aid, not a facsimile, and the view labels itself that way
// on every page.
//
// The distinction matters more than it looks. If the extractor mis-ordered a
// two-column layout, or dropped a header, a facsimile would show you the header
// you expect while the pipeline never saw it. Showing the text the pipeline
// actually processed means what you audit is what ran.
//
// Pagination is by LINE COUNT, not by measuring the rendered box: measurement
// would make the page breaks depend on the viewport, so two people looking at
// the same note would disagree about which page a span is on, and the span map
// could not name one.

import type { Segment, SpanSegment } from "./types";

/** Lines per page. Chosen to look like a page at the app's type size. */
export const LINES_PER_PAGE = 32;

export interface Page {
  readonly number: number;
  readonly segments: readonly Segment[];
}

/**
 * Split segments across pages at line boundaries.
 *
 * A `keep` run is split at the newline that crosses the boundary. A `span` is
 * NEVER split -- an identifier broken across two pages would render as two
 * partial marks, and a half-drawn blackout bar over half an identifier is
 * exactly the kind of thing that reads as "partially redacted".
 */
export function paginate(segments: readonly Segment[]): Page[] {
  const pages: Page[] = [];
  let current: Segment[] = [];
  let lines = 0;

  const flush = () => {
    pages.push({ number: pages.length + 1, segments: current });
    current = [];
    lines = 0;
  };

  for (const segment of segments) {
    if (segment.kind === "span") {
      current.push(segment);
      continue;
    }
    let rest = segment.text;
    while (rest.length > 0) {
      const room = LINES_PER_PAGE - lines;
      const parts = rest.split("\n");
      if (parts.length <= room) {
        current.push({ kind: "keep", text: rest });
        lines += parts.length - 1;
        break;
      }
      const head = parts.slice(0, room).join("\n");
      current.push({ kind: "keep", text: head + "\n" });
      rest = parts.slice(room).join("\n");
      flush();
    }
  }
  if (current.length > 0 || pages.length === 0) flush();
  return pages;
}

/** Which page a given span ordinal landed on, for the span map's column. */
export function pageOfSpan(pages: readonly Page[]): ReadonlyMap<number, number> {
  const map = new Map<number, number>();
  for (const page of pages) {
    for (const segment of page.segments) {
      if (segment.kind === "span") map.set(segment.index, page.number);
    }
  }
  return map;
}

/** Every span segment on a page, in document order. */
export function spansOf(page: Page): SpanSegment[] {
  return page.segments.filter((s): s is SpanSegment => s.kind === "span");
}
