import { useEffect, useMemo, useRef, useState } from "react";
import { Banner } from "@/components/Banner";
import { DocumentView } from "@/components/DocumentView";
import { NetworkCounter } from "@/components/NetworkCounter";
import { SpanMap } from "@/components/SpanMap";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { barsByIndex, barsFor } from "@/deid/bars";
import { compose, maskedCount, spanCount } from "@/deid/compose";
import { pageOfSpan, paginate } from "@/deid/pages";
import { defaultMethod } from "@/deid/policy";
import type { DetectedSpan, Segment } from "@/deid/types";
import type { Runtime } from "@/deid/wasm";
import { newSalt } from "@/deid/wasm";
import { useBlackout } from "@/lib/use-blackout";
import { useReducedMotion } from "@/lib/use-reduced-motion";

const SAMPLE = `Hasta Kabul Formu
Kurum: Cerrahpasa Tip Fakultesi Hastanesi

Ad Soyad: Ayse Yilmaz
TCKN: 10000000147
Dogum tarihi: 12.03.1979
Telefon: 0532 111 22 33
E-posta: ayse.yilmaz@ornek.com.tr
IBAN: TR330006100519786457841326

Anamnez
Hasta 12.03.2024 tarihinde poliklinige basvurdu. Ust batinda
carcinoma'li lezyon suphesi ile PET-CT'de degerlendirildi.
Metformin'e devam edilmesi, Adalat dozunun azaltilmasi onerildi.
Kontrol MRI'da bulgular stabil seyretti.

Takip eden hekim: Op. Dr. Mehmet Demir
`;

export function App({ runtime }: { runtime: Runtime }) {
  const [text, setText] = useState(SAMPLE);
  const [spans, setSpans] = useState<DetectedSpan[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [threshold, setThreshold] = useState(0.5);
  const [dark, setDark] = useState(false);
  const salt = useRef(newSalt());
  const reduced = useReducedMotion();

  // Debounced, because de-identification runs on every keystroke and a long
  // note re-encodes the whole document each time. 120ms is below the threshold
  // at which typing feels laggy and above the interval between keystrokes.
  useEffect(() => {
    const id = setTimeout(() => {
      if (text.length === 0) {
        setSpans([]);
        setError(null);
        return;
      }
      try {
        setSpans(runtime.detect(text, salt.current));
        setError(null);
      } catch (caught) {
        // The wasm error is a `core::Error` rendering: offsets, labels and
        // layers, structurally incapable of carrying document text (I4). Safe
        // to display.
        setError(caught instanceof Error ? caught.message : String(caught));
        setSpans([]);
      }
    }, 120);
    return () => clearTimeout(id);
  }, [text, runtime]);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  const composition = useMemo(
    () =>
      compose(text, spans, {
        disabled: new Set<string>(),
        methods: new Map<string, string>(),
        threshold,
        shiftDays: 0,
      }),
    [text, spans, threshold],
  );

  // THE ONLY CALL TO `barsFor` IN THE APPLICATION. Every bar on screen comes
  // from here, from a composition, filtered by the masked-only predicate.
  const bars = useMemo(() => barsFor(composition.segments), [composition]);
  const barIndex = useMemo(() => barsByIndex(bars), [bars]);
  const blackout = useBlackout(bars);

  const pages = useMemo(() => paginate(composition.segments), [composition]);
  const pageOf = useMemo(() => pageOfSpan(pages), [pages]);

  const detected = spanCount(composition.segments);
  const masked = maskedCount(composition.segments);

  return (
    <div className="min-h-dvh bg-background text-foreground">
      <a
        href="#note"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        Skip to the note editor
      </a>

      <header className="border-b border-border">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div>
            <h1 className="text-lg font-semibold">deid-tr</h1>
            <p className="text-sm text-muted-foreground">
              Turkish clinical de-identification, entirely in this tab.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <Label htmlFor="theme" className="text-sm">
              Dark theme
            </Label>
            <Switch id="theme" checked={dark} onCheckedChange={setDark} />
          </div>
        </div>
      </header>

      {/* The banner is the first thing in the main region and is never inside a
          scroll container, so it cannot be pushed off the first screen by
          output above it. */}
      <main className="mx-auto max-w-6xl space-y-5 px-4 py-5">
        <Banner />

        <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Note</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Label htmlFor="note" className="sr-only">
                Clinical note to de-identify
              </Label>
              <textarea
                id="note"
                value={text}
                onChange={(event) => setText(event.target.value)}
                spellCheck={false}
                rows={18}
                className="w-full rounded-md border border-input bg-background p-3 font-mono text-xs leading-relaxed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                aria-describedby="note-help"
              />
              <p id="note-help" className="text-xs text-muted-foreground">
                Nothing typed here leaves this tab. Method:{" "}
                <span className="font-mono">{defaultMethod()}</span> (L5, real).
              </p>

              <div className="space-y-2">
                <Label htmlFor="threshold" className="text-sm">
                  Confidence threshold:{" "}
                  <span className="font-mono tabular-nums">
                    {threshold.toFixed(2)}
                  </span>
                </Label>
                <Slider
                  id="threshold"
                  min={0}
                  max={1}
                  step={0.01}
                  value={[threshold]}
                  onValueChange={([next]) => setThreshold(next ?? 0)}
                  aria-describedby="threshold-help"
                />
                <p id="threshold-help" className="text-xs text-muted-foreground">
                  Spans below this confidence are left in the output. Raising it
                  masks less, not more.
                </p>
              </div>

              <NetworkCounter build={runtime.build} />
            </CardContent>
          </Card>

          <div className="space-y-4">
            {/*
              THE COUNTS, WHICH ARE RULE 2 IN ITS PLAINEST FORM. They are
              rendered from the composition, never from the animation, and they
              are correct before the first frame and after the last. `masked`
              and `detected` are two numbers rather than one on purpose: "5
              detected, 5 masked" and "5 detected, 3 masked" have to be
              distinguishable at a glance, and a single figure hides which one
              you are looking at.
            */}
            <div
              aria-live="polite"
              className="rounded-md border border-border bg-muted px-3 py-2 text-sm"
            >
              {error ? (
                <span className="text-danger">Pipeline error: {error}</span>
              ) : detected === 0 ? (
                <>
                  No identifiers detected in this note. Names are not among the
                  things looked for: no L2 model is loaded, so zero names were
                  masked.
                </>
              ) : (
                <>
                  <strong className="tabular-nums">{detected}</strong> identifier
                  {detected === 1 ? "" : "s"} detected,{" "}
                  <strong className="tabular-nums">{masked}</strong> removed and
                  replaced. <strong>Zero names masked:</strong> no L2 model is
                  loaded in this build, so names were never looked for.
                </>
              )}
            </div>

            <Tabs defaultValue="document">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <TabsList>
                  <TabsTrigger value="document">Document</TabsTrigger>
                  <TabsTrigger value="spans">
                    Span map ({detected})
                  </TabsTrigger>
                  <TabsTrigger value="output">Output text</TabsTrigger>
                </TabsList>
                {blackout.playing ? (
                  <Button variant="outline" size="sm" onClick={blackout.settle}>
                    Skip animation
                  </Button>
                ) : reduced ? (
                  <span className="text-xs text-muted-foreground">
                    reduced motion: showing the final state
                  </span>
                ) : null}
              </div>

              <TabsContent value="document">
                <DocumentView
                  segments={composition.segments}
                  bars={barIndex}
                  sweeping={blackout.playing}
                  runKey={blackout.runKey}
                />
              </TabsContent>

              <TabsContent value="spans">
                <div className={blackout.playing ? "sweeping" : undefined}>
                  <SpanMap
                    segments={composition.segments}
                    bars={barIndex}
                    pageOf={pageOf}
                  />
                </div>
              </TabsContent>

              <TabsContent value="output">
                {/*
                  THE EXPORTABLE TEXT, read straight off `composition.output`.
                  It is composed by `compose()` and is byte-identical whether a
                  bar ever rendered, whether the sweep was skipped, and whether
                  reduced motion is on -- nothing in the animation path can
                  reach this string. `export.test.ts` asserts it.
                */}
                <Card>
                  <CardContent className="pt-4">
                    <pre className="doc-page overflow-x-auto text-xs">
                      {composition.output}
                    </pre>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </div>

        <footer className="pb-8 text-xs text-muted-foreground">
          <p>
            This is the React surface. The vanilla panel at{" "}
            <code>bindings/wasm/panel/</code> is six readable files with no build
            step; it is the minimal auditable proof and neither replaces the
            other. Both load the same WebAssembly module.
          </p>
        </footer>
      </main>
    </div>
  );
}

/** Exported for the export test: the bytes a download would contain. */
export function exportBytes(segments: readonly Segment[]): string {
  return segments
    .map((segment) =>
      segment.kind === "keep" ? segment.text : segment.replacement,
    )
    .join("");
}
