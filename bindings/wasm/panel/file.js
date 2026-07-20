// Reading a dropped file, deciding what it actually is, and handing it to the
// wasm module.
//
// # Nothing here touches the network, and it could not if it wanted to
//
// `FileReader` reads from a `File` handle the user themselves gave the page
// through a drop or a picker. It is local by construction: there is no URL
// involved, no request is issued, and the resource timeline stays empty across
// the whole read. `panel.js` has already replaced `fetch`, `XMLHttpRequest`,
// `WebSocket`, `EventSource`, `WebTransport`, `RTCPeerConnection` and
// `navigator.sendBeacon` with throwing stubs before this module is ever
// imported, so even a mistake here cannot become an upload. The redacted file
// comes back the same way: a `Blob` and an object URL, which the browser saves
// locally and never transmits.
//
// # Why the size ceiling is checked before the read and not after
//
// A PDF is parsed into an object graph in the wasm module's linear memory, and
// a large one can take seconds during which the tab is unresponsive. Telling
// someone their file was too big AFTER they waited for it is the version of
// this feature that wastes their time and then refuses; the ceiling is
// therefore a property of the `File` handle, which is known the instant it is
// dropped.

// THE CEILING IS NOT DEFINED HERE. `wasm.maxFileBytes()` is the authority and
// the panel reads it at start-up. A second copy of the number in JavaScript
// would be a number that can disagree with the one actually enforced, and the
// direction it would disagree in is the bad one: a JS constant left too high
// lets someone wait through a read for a file the module then refuses, which is
// exactly the "surface the ceiling before the wait" requirement, inverted.

/// The formats the wasm module reports, mapped to what a reader calls them.
///
/// `detectFormat` answers with the CONTENT's format. This table exists so the
/// UI can name it in the same words the file picker and the drop hint use.
const FORMAT_NAMES = new Map([
  ["txt", "plain text"],
  ["csv", "CSV"],
  ["json", "JSON"],
  ["jsonl", "JSON Lines"],
  ["docx", "DOCX"],
  ["pdf", "PDF"],
]);

/// The two formats that cannot be edited in place.
///
/// A `.txt` round-trips through the editor unchanged, so the live-highlight
/// experience works on it. A PDF does not: its text is a decoded view of glyph
/// codes positioned by content-stream operators, and there is no edit a person
/// could make in a textarea that maps back onto those bytes. So these two get a
/// read-only presentation and a download, and the panel says which it is giving
/// you rather than letting someone type into a view that cannot save.
const BINARY_FORMATS = new Set(["pdf", "docx"]);

export function formatName(format) {
  return FORMAT_NAMES.get(format) ?? format;
}

export function isBinary(format) {
  return BINARY_FORMATS.has(format);
}

/// What a file's NAME claims it is, independently of its bytes.
///
/// Deliberately a separate answer from `detectFormat`'s, so the two can be
/// compared and a disagreement reported. A file whose name and bytes disagree
/// is either mislabelled or disguised, and both are worth saying out loud
/// before anything is redacted: the tool follows the BYTES, which means the
/// result may not be the kind of file the reader thinks they handed over.
export function formatFromName(name) {
  const dot = name.lastIndexOf(".");
  if (dot < 0) return null;
  switch (name.slice(dot + 1).toLowerCase()) {
    case "txt":
    case "text":
    case "md":
    case "log":
      return "txt";
    case "csv":
    case "tsv":
      return "csv";
    case "json":
      return "json";
    case "jsonl":
    case "ndjson":
      return "jsonl";
    case "docx":
      return "docx";
    case "pdf":
      return "pdf";
    default:
      return null;
  }
}

/// `.md` and `.txt` are both plain text to the pipeline.
///
/// So a `.md` file whose bytes are plain text is NOT a disagreement, even
/// though the extension and the detected format are spelled differently. This
/// is the one place the comparison needs to know that two names mean one
/// format, and getting it wrong would make every Markdown file trigger a
/// warning that means nothing.
export function formatsDisagree(detected, claimed) {
  if (claimed === null || detected === null) return false;
  return detected !== claimed;
}

/// Read a `File` into bytes, reporting progress.
///
/// `FileReader` rather than `File.arrayBuffer()` SPECIFICALLY for the progress
/// events. `arrayBuffer()` is a single promise that resolves when the whole
/// file is in memory, which for a large PDF is several seconds of a UI with
/// nothing moving on it. The reader emits `progress` as it goes, which is the
/// difference between "this page is working" and "this page is frozen".
export function readBytes(file, onProgress) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("progress", (event) => {
      if (event.lengthComputable && event.total > 0) {
        onProgress(event.loaded / event.total);
      }
    });
    reader.addEventListener("load", () => {
      onProgress(1);
      resolve(new Uint8Array(reader.result));
    });
    // The error carries a `DOMException` name such as `NotReadableError`, which
    // is about the FILE HANDLE and never about the file's contents (I4).
    reader.addEventListener("error", () =>
      reject(new Error(reader.error?.name ?? "the file could not be read")),
    );
    reader.readAsArrayBuffer(file);
  });
}

/// Yield to the browser so a status line painted just before a synchronous wasm
/// call is actually on screen when the freeze starts.
///
/// A `setTimeout(0)` is not enough on its own: it runs after the current task
/// but not necessarily after a paint. Waiting for two animation frames means
/// the style change has been committed and composited, so the message a reader
/// sees during the freeze is the one describing the work being done rather than
/// the previous one.
///
/// # The timeout is not belt-and-braces, it is the whole correctness argument
///
/// `requestAnimationFrame` DOES NOT FIRE IN A BACKGROUNDED TAB. A reader who
/// drops a PDF and switches away -- which is the natural thing to do while
/// something is processing -- would leave this promise pending forever, and the
/// redaction would never start. Not slow: never. The file would sit at 50% with
/// no error, which is indistinguishable from the tool having silently swallowed
/// their document. Measured here by driving the panel in a tab that was not
/// foregrounded; the raw two-frame version hung exactly as described.
///
/// So the frames are RACED against a timer. Whichever resolves first wins: in a
/// visible tab that is the frames, which is what makes the progress line
/// correct; in a hidden one it is the timer, which is what makes the feature
/// work at all. The cost of the timer winning early is a status line that was
/// not composited, in a tab nobody is looking at.
export function afterPaint() {
  const frames = new Promise((resolve) =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve())),
  );
  const fallback = new Promise((resolve) => setTimeout(resolve, 50));
  return Promise.race([frames, fallback]);
}

/// Human file size, for a ceiling message that has to be read at a glance.
export function humanSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
