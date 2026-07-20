// RULE 3: reduced motion jumps to the final state, and never starts a sweep.

import { renderHook, act } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useBlackout } from "./use-blackout";
import { barsFor } from "@/deid/bars";
import { compose } from "@/deid/compose";
import { DOC, OPEN_POLICY, SPANS } from "@/deid/fixtures";

function setReducedMotion(reduce: boolean) {
  Object.defineProperty(globalThis, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: reduce && query.includes("prefers-reduced-motion"),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}

const bars = barsFor(compose(DOC, SPANS, OPEN_POLICY).segments);

afterEach(() => {
  vi.useRealTimers();
  setReducedMotion(false);
});

describe("useBlackout", () => {
  it("never starts a sweep under prefers-reduced-motion: reduce", () => {
    setReducedMotion(true);
    const { result } = renderHook(() => useBlackout(bars));
    expect(result.current.playing).toBe(false);
  });

  it("plays, then settles on its own timer", () => {
    vi.useFakeTimers();
    setReducedMotion(false);
    const { result } = renderHook(() => useBlackout(bars));
    expect(result.current.playing).toBe(true);

    // The timer is a setTimeout rather than an `animationend` listener, because
    // `animationend` never fires for an animation the engine skipped -- which
    // would leave the document stuck mid-cover with a bar over it forever.
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(result.current.playing).toBe(false);
  });

  it("settles immediately when asked to skip", () => {
    setReducedMotion(false);
    const { result } = renderHook(() => useBlackout(bars));
    act(() => result.current.settle());
    expect(result.current.playing).toBe(false);
  });

  it("does not start a sweep when there is nothing masked", () => {
    setReducedMotion(false);
    const { result } = renderHook(() => useBlackout([]));
    expect(result.current.playing).toBe(false);
  });
});
