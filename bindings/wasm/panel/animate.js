// The masking sweep. PRESENTATION ONLY.
//
// FOUR RULES THIS MODULE EXISTS TO OBEY, and each one is a way a masking tool
// could lie with an animation:
//
//   1. IT IS NEVER THE ONLY SIGNAL. `render()` paints the FINAL state before
//      this module is called. The counts, the span map, the live region and the
//      exported text are all already correct and already on screen. A reader
//      who looks away, whose tab is backgrounded, or whose browser drops
//      `requestAnimationFrame` entirely sees exactly the same result. This
//      module only borrows the text of already-final nodes for a few hundred
//      milliseconds and hands them back.
//   2. IT ONLY ANIMATES SPANS THAT WERE ACTUALLY MASKED. The caller passes
//      units built from segments whose `passthrough` is null. Showing a name
//      "transforming" while it sits unchanged in the output would be an
//      actively dangerous lie in this product, so the un-masked spans are drawn
//      as static dashed outlines and never move.
//   3. IT NEVER GATES, DELAYS OR ALTERS THE PIPELINE. De-identification has
//      already run and `state.output` is already composed by the time this is
//      reachable. Exported bytes are identical whether or not a frame ever
//      rendered.
//   4. `prefers-reduced-motion: reduce` DISABLES IT ENTIRELY. Vestibular
//      disorders are real and this is a clinical tool. The check is made here,
//      at play time, rather than cached at module load, so a viewer who changes
//      the system setting mid-session gets the new behaviour on the next run.

/// Glyphs the scramble draws from. Deliberately geometric ASCII and box
/// characters: no emoji, and nothing that could be mistaken for a real
/// identifier mid-frame.
const GLYPHS = "#*+=-~^%$&/\\|<>";

/// Milliseconds. The whole sweep is budgeted to finish well inside 1.2s on a
/// note with any plausible number of spans, because this is a tool and not a
/// title sequence. STAGGER_MAX is the per-span delay on a short note; on a long
/// one the stagger compresses so the TOTAL sweep never exceeds SWEEP_BUDGET.
const STAGGER_MAX = 70;
const SWEEP_BUDGET = 520;
/// How long after a span's outline pulse begins its text starts transforming.
/// The gap is what makes the sweep read as "found, then replaced" rather than
/// as a single flash.
const HANDOFF_MS = 140;
const SCRAMBLE_MS = 270;

/// Superseding generation counter. A run started while another is in flight
/// abandons the old frame loop rather than letting two loops fight over the
/// same text nodes.
let generation = 0;

/// True when the viewer has asked for reduced motion, evaluated live.
export function reducedMotion() {
  return globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
}

/// Force every unit back to its final text and strip every transient class.
///
/// This is the safety net as well as the normal ending. It runs from the last
/// animation frame, from a timeout that fires even in a backgrounded tab where
/// `requestAnimationFrame` is paused, and from `cancel()`.
function settle(units) {
  for (const unit of units) {
    unit.text.textContent = unit.final;
    unit.mark.classList.remove("sweeping");
    unit.mark.style.removeProperty("--sweep-delay");
    if (unit.row) {
      unit.row.classList.remove("sweeping");
      unit.row.style.removeProperty("--sweep-delay");
    }
  }
}

/// Abandon any sweep in flight. Callers use this before re-rendering, so a
/// half-scrambled node is never left behind in a DOM that is about to be
/// replaced anyway.
export function cancel() {
  generation += 1;
}

/// One frame of the transform for a single span.
///
/// The returned string is ALWAYS `to.length` characters, so the mark's width
/// never changes mid-sweep and the note does not reflow under the reader. Early
/// frames show the original's own characters where it has them, so the eye
/// reads "this text became that text" rather than "noise appeared here".
function mix(from, to, progress) {
  const settled = Math.min(to.length, Math.floor(to.length * progress * 1.4));
  let out = "";
  for (let index = 0; index < to.length; index += 1) {
    if (index < settled) {
      out += to[index];
    } else if (progress < 0.35 && index < from.length) {
      out += from[index];
    } else {
      out += GLYPHS[(Math.random() * GLYPHS.length) | 0];
    }
  }
  return out;
}

/**
 * Play the sweep over already-rendered, already-final nodes.
 *
 * @param {Array<{mark: Element, text: Element, row: Element|null, from: string, final: string}>} units
 *   one per MASKED span, in document order.
 * @returns {boolean} whether anything was animated, for the caller's own tests.
 */
export function play(units) {
  generation += 1;
  const gen = generation;
  const animated = units.filter((unit) => unit.final.length > 0);
  if (animated.length === 0 || reducedMotion()) return false;

  const stagger = Math.min(STAGGER_MAX, SWEEP_BUDGET / animated.length);
  for (const [index, unit] of animated.entries()) {
    unit.start = index * stagger;
    // The outline pulse is a CSS animation driven off this custom property, so
    // the compositor owns the part that runs per frame and JavaScript only owns
    // the text. The span map row shares the delay, which is what makes the row
    // light up in step with its span rather than merely at the same time.
    unit.mark.style.setProperty("--sweep-delay", `${unit.start}ms`);
    unit.mark.classList.add("sweeping");
    if (unit.row) {
      unit.row.style.setProperty("--sweep-delay", `${unit.start}ms`);
      unit.row.classList.add("sweeping");
    }
    unit.text.textContent = unit.from;
  }

  const started = performance.now();
  const total = animated.at(-1).start + HANDOFF_MS + SCRAMBLE_MS;

  const frame = (now) => {
    if (gen !== generation) return;
    const elapsed = now - started;
    let running = false;
    for (const unit of animated) {
      const progress = (elapsed - unit.start - HANDOFF_MS) / SCRAMBLE_MS;
      if (progress >= 1) {
        unit.text.textContent = unit.final;
        continue;
      }
      running = true;
      unit.text.textContent =
        progress <= 0 ? unit.from : mix(unit.from, unit.final, progress);
    }
    if (running) requestAnimationFrame(frame);
    else settle(animated);
  };
  requestAnimationFrame(frame);

  // The net for rule 1. `requestAnimationFrame` does not fire in a backgrounded
  // tab, so a reader who switches away mid-sweep and returns would otherwise
  // find the note frozen mid-scramble -- a masked span rendered as noise that
  // is neither the original nor the replacement. `setTimeout` still fires
  // there, throttled, so the final state arrives regardless.
  setTimeout(() => {
    if (gen === generation) settle(animated);
  }, total + 250);

  return true;
}
