import { useEffect, useState } from "react";

/**
 * Whether the viewer has asked for reduced motion.
 *
 * SUBSCRIBED, NOT SAMPLED AT MODULE LOAD. Vestibular disorders are real and
 * this is a clinical tool; a viewer who turns the system setting on mid-session
 * should get the new behaviour immediately, not after a reload they have no
 * reason to know they need.
 *
 * The initial value is read synchronously in the state initialiser rather than
 * in an effect, so the FIRST render under `reduce` already has no animation.
 * Reading it in an effect would paint one animated frame first, which is the
 * exact frame the setting exists to prevent.
 */
export function useReducedMotion(): boolean {
  const query = "(prefers-reduced-motion: reduce)";
  const [reduced, setReduced] = useState(
    () => globalThis.matchMedia?.(query).matches === true,
  );

  useEffect(() => {
    const media = globalThis.matchMedia?.(query);
    if (!media) return;
    const onChange = () => setReduced(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return reduced;
}
