import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { loadRuntime } from "./deid/wasm";
import "./index.css";

// THE MODULE IS LOADED BEFORE REACT MOUNTS, and the network trap is armed
// inside that load. By the time any component exists -- and therefore by the
// time any clinical text can have been typed -- every networking global is a
// throwing stub. Mounting first and loading in an effect would open a window,
// however short, in which the editor accepted a note while `fetch` still
// worked. Nothing would use it, but "nothing would use it" is the kind of claim
// this project does not accept from itself.

const root = createRoot(document.getElementById("root")!);

root.render(
  <p className="p-6 text-sm" role="status">
    Loading the de-identification module from this directory. Nothing is
    fetched from any other origin.
  </p>,
);

loadRuntime().then(
  (runtime) => {
    root.render(
      <StrictMode>
        <App runtime={runtime} />
      </StrictMode>,
    );
  },
  (error: unknown) => {
    // The failure is almost always the same one and the message says so
    // outright, because "Failed to fetch" on its own sends people looking for a
    // network problem on a page that has no network.
    root.render(
      <div className="p-6 text-sm" role="alert">
        <p className="font-medium">
          The WebAssembly module did not load, so nothing has been
          de-identified.
        </p>
        <p className="mt-2">
          This app loads <code>./pkg-web/deid_tr_wasm.js</code> from its own
          directory. If that directory is missing, build it with{" "}
          <code>just build-wasm</code> and serve the app with{" "}
          <code>just serve-panel-app</code>, which copies it into place.
        </p>
        <p className="mt-2 font-mono text-xs">
          {error instanceof Error ? error.message : String(error)}
        </p>
      </div>,
    );
  },
);
