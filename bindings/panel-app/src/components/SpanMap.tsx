import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { family, sigil } from "@/deid/policy";
import { isMasked } from "@/deid/bars";
import type { RedactionBar } from "@/deid/bars";
import type { Segment, SpanSegment } from "@/deid/types";

/**
 * The span map: one row per detected span, masked or not.
 *
 * RULE 2 LIVES HERE. This table is complete and correct before a single frame
 * of the blackout has rendered, and it stays on screen after. A reader who
 * looked away, whose tab was backgrounded, or who has motion switched off gets
 * the same information from it. The row highlight is decoration on top of a
 * table that already said everything.
 *
 * THE `masked` COLUMN IS THE ONE THAT MATTERS. A span that was detected and
 * left in the output says so in words, in its own column, and the surrogate
 * column shows the original text unchanged -- so the row for an unmasked
 * patient name reads as a row about text that is still there. That is the
 * non-animated statement of the same fact the missing bar makes.
 */
export function SpanMap({
  segments,
  bars,
  pageOf,
}: {
  segments: readonly Segment[];
  bars: ReadonlyMap<number, RedactionBar>;
  pageOf: ReadonlyMap<number, number>;
}) {
  const spans = segments.filter((s): s is SpanSegment => s.kind === "span");

  if (spans.length === 0) {
    return (
      <p className="py-6 text-sm text-muted-foreground">
        No identifiers detected. Names are not among the things looked for: no
        L2 model is loaded in this build, so zero names were masked.
      </p>
    );
  }

  return (
    <Table>
      <caption className="mt-2 text-left text-xs text-muted-foreground">
        Offsets are UTF-8 <strong>byte</strong> offsets into the original text,
        not JavaScript string indices. A Turkish note is multi-byte: in{" "}
        <code>ş</code>, <code>ğ</code> and <code>İ</code> the two differ.
      </caption>
      <TableHeader>
        <TableRow>
          <TableHead scope="col">#</TableHead>
          <TableHead scope="col">Page</TableHead>
          <TableHead scope="col">Label</TableHead>
          <TableHead scope="col">Bytes</TableHead>
          <TableHead scope="col">Layer</TableHead>
          <TableHead scope="col">Conf.</TableHead>
          <TableHead scope="col">Outcome</TableHead>
          <TableHead scope="col">In the output</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {spans.map((segment) => {
          const masked = isMasked(segment);
          const bar = bars.get(segment.index);
          return (
            <TableRow
              key={segment.index}
              // Only a row whose span has a bar syncs to one, and it syncs to
              // ITS OWN delay -- which is what makes the row light up in step
              // with its bar rather than merely at the same time as the sweep.
              className={bar ? "row-sync" : undefined}
              style={
                bar
                  ? ({ "--bar-delay": `${bar.delay}ms` } as React.CSSProperties)
                  : undefined
              }
            >
              <TableCell className="tabular-nums text-muted-foreground">
                {segment.index + 1}
              </TableCell>
              <TableCell className="tabular-nums text-muted-foreground">
                {pageOf.get(segment.index) ?? "-"}
              </TableCell>
              <TableCell>
                <span className="font-mono text-xs">{segment.span.label}</span>{" "}
                <Badge variant="outline" className="font-mono">
                  {sigil(family(segment.span.label))}
                </Badge>
              </TableCell>
              <TableCell className="font-mono text-xs tabular-nums">
                {segment.span.start}-{segment.span.end}
              </TableCell>
              <TableCell className="text-xs">{segment.span.layer}</TableCell>
              <TableCell className="font-mono text-xs tabular-nums">
                {segment.span.checksumValidated
                  ? "1.000*"
                  : segment.span.confidence.toFixed(3)}
              </TableCell>
              <TableCell>
                {masked ? (
                  <Badge variant="secondary">removed &amp; replaced</Badge>
                ) : (
                  <Badge variant="danger">
                    still in output - {segment.passthrough}
                  </Badge>
                )}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {masked ? (
                  segment.replacement === "" ? (
                    <em className="text-muted-foreground">nothing</em>
                  ) : (
                    segment.replacement
                  )
                ) : (
                  <span className="text-danger">
                    the original text, unchanged
                  </span>
                )}
                {segment.note ? (
                  <span className="block text-muted-foreground">
                    {segment.note}
                  </span>
                ) : null}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
