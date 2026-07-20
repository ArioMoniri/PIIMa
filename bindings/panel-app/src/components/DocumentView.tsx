import { Card } from "@/components/ui/card";
import { SegmentView } from "./SpanViews";
import { paginate } from "@/deid/pages";
import type { RedactionBar } from "@/deid/bars";
import type { Segment } from "@/deid/types";

/**
 * The page-shaped view of the document.
 *
 * THE LABEL ON EVERY PAGE IS LOAD-BEARING. This is EXTRACTED TEXT laid out in a
 * page shape. It is not a rendering of the source PDF and it is not a picture
 * of the file: there is no rasteriser in this app, and the CSP forbids loading
 * one (`script-src 'self'`, `img-src 'none'`). Telling someone they are looking
 * at their document when they are looking at a text reconstruction of it is a
 * smaller lie than a bar over an unmasked name, but it is the same kind of lie
 * -- a claim about what the tool did, made by an illustration -- so it gets the
 * same treatment: say what it is, on the artifact, where it cannot be missed.
 */
export function DocumentView({
  segments,
  bars,
  sweeping,
  runKey,
}: {
  segments: readonly Segment[];
  bars: ReadonlyMap<number, RedactionBar>;
  sweeping: boolean;
  runKey: number;
}) {
  const pages = paginate(segments);

  return (
    // `key={runKey}` remounts the animated subtree per sweep. CSS animations do
    // not replay when a class is removed and re-added inside one commit, so a
    // second run would otherwise render nothing moving at all -- and "the
    // animation silently stopped working" is indistinguishable, to a reader,
    // from "there was nothing to animate".
    <div key={runKey} className={sweeping ? "sweeping space-y-4" : "space-y-4"}>
      {pages.map((page) => (
        <Card key={page.number} className="overflow-hidden">
          <div className="flex items-baseline justify-between border-b border-border bg-muted px-4 py-1.5">
            <span className="text-xs font-medium text-muted-foreground">
              Page {page.number} of {pages.length}
            </span>
            <span className="text-xs text-muted-foreground">
              extracted text, not a rendering of the source file
            </span>
          </div>
          <div className="doc-page px-6 py-5">
            {page.segments.map((segment, position) => (
              <SegmentView
                key={segment.kind === "span" ? `s${segment.index}` : `k${page.number}-${position}`}
                segment={segment}
                bars={bars}
              />
            ))}
          </div>
        </Card>
      ))}
    </div>
  );
}
