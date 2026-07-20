import { useEffect, useRef, useState } from "react";
import { sweepDuration, type RedactionBar } from "@/deid/bars";
import { useReducedMotion } from "./use-reduced-motion";

export interface Blackout {
  /** True while a sweep is in flight. False means: render the final state. */
  readonly playing: boolean;
  /**
   * Bumped once per sweep. Used as a React `key` on the animated subtree so a
   * re-run restarts the CSS animations instead of continuing the old ones --
   * CSS animations do not replay when a class is removed and re-added within a
   * single commit, and a second sweep would otherwise show nothing at all.
   */
  readonly runKey: number;
  /** Skip to the end. Wired to the "skip animation" control. */
  readonly settle: () => void;
}

/**
 * Drive one blackout sweep per composition.
 *
 * THE DEFAULT IS THE FINAL STATE. `playing` starts false, and the components
 * render the settled document whenever it is false. This hook only ever turns
 * the animation ON for a bounded interval; nothing downstream needs it to have
 * run in order to be correct. That is what makes rule 2 hold structurally
 * rather than by discipline: there is no code path where "the animation did not
 * run" and "the output is wrong" are the same state.
 *
 * THE TIMER IS A `setTimeout`, NOT AN ANIMATION EVENT. `animationend` does not
 * fire for an element whose animation was never started -- a backgrounded tab,
 * a browser with animations disabled at the engine level, an element scrolled
 * out of a container that skipped compositing. Any of those would leave
 * `playing` true forever and the document stuck mid-cover. `setTimeout` still
 * fires in a backgrounded tab, throttled, so the settled state always arrives.
 */
export function useBlackout(bars: readonly RedactionBar[]): Blackout {
  const reduced = useReducedMotion();
  const [playing, setPlaying] = useState(false);
  const [runKey, setRunKey] = useState(0);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    clearTimeout(timer.current);

    // RULE 3. Under `reduce` no sweep is ever started, so no bar is drawn and
    // the document renders settled on the first paint.
    if (reduced || bars.length === 0) {
      setPlaying(false);
      return;
    }

    setRunKey((key) => key + 1);
    setPlaying(true);
    // The margin covers the gap between the CSS animation's own clock and this
    // one under throttling. Settling slightly late is invisible; settling early
    // would cut a bar off mid-reveal.
    timer.current = setTimeout(() => setPlaying(false), sweepDuration(bars) + 120);

    return () => clearTimeout(timer.current);
  }, [bars, reduced]);

  return {
    playing,
    runKey,
    settle: () => {
      clearTimeout(timer.current);
      setPlaying(false);
    },
  };
}
