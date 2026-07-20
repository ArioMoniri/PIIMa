/**
 * THE MOST IMPORTANT ELEMENT ON THE PAGE.
 *
 * A clinician who pastes a note and watches black bars sweep down it will
 * assume the names went with everything else. They did not. This states that at
 * the top, in the reading order, before any output, and nothing below it is
 * allowed to push it off the first screen.
 *
 * The blackout animation makes this banner MORE necessary than it was on the
 * vanilla panel, not less. A text scramble reads as "something happened here".
 * A black bar reads as "this is redacted", with the full weight of every
 * redacted document anyone has ever seen behind it. The stronger the visual
 * claim, the louder the correction has to be.
 *
 * It is not `aria-live`. It is present from first paint and never changes, so a
 * live region would announce nothing; it is a landmark with a heading, which is
 * what gets it into the rotor and into the reading order at the top.
 */
export function Banner() {
  return (
    <aside
      role="note"
      aria-labelledby="banner-title"
      className="rounded-lg border-2 border-danger bg-card p-4"
    >
      <h2 id="banner-title" className="text-base font-semibold">
        What this panel does and does not remove
      </h2>
      <ul className="mt-2 space-y-2 text-sm">
        <li>
          <strong>Removed:</strong> identifiers the L1 rule layer can prove -
          TCKN, VKN, IBAN, phone numbers, e-mail addresses, dates and the other
          fixed-format direct identifiers, checksum-validated where the format
          carries a checksum. These are the spans that get a black bar.
        </li>
        <li className="font-medium text-danger">
          <strong>NOT removed: names.</strong> Patient, clinician and relative
          names are the job of the L2 model ensemble.{" "}
          <strong>No L2 model is loaded in this build</strong>, so deid-tr masks
          zero names. A name is shown with a dashed outline and no bar, and its
          span map row says <em>still in output</em>. If you see no bar over a
          name, that is not a rendering delay - it is the truth about the file
          you are about to export.
        </li>
        <li>
          <strong>Nothing is uploaded.</strong> The text you paste is
          de-identified by a WebAssembly module in this tab. The network counter
          below is live evidence, not a promise.
        </li>
      </ul>
    </aside>
  );
}
