import { useEffect, useState } from "react";
import { networkWitness, onNetworkChange } from "@/deid/wasm";

/**
 * Live evidence that this page makes no requests after it has loaded.
 *
 * THREE INSTRUMENTS, REPORTED SEPARATELY, because they fail differently and a
 * single green tick would hide which one was doing the work:
 *
 *   - trapped globals: `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`,
 *     `WebTransport`, `RTCPeerConnection`, `sendBeacon`, each replaced with a
 *     throwing stub. Catches anything that calls a name we knew to stub.
 *   - the resource timeline: what the browser ACTUALLY fetched, including
 *     anything a dependency reaches through a path nobody thought to stub.
 *   - CSP violations: a declarative load the policy refused never reaches the
 *     network and so appears in neither of the above. That is a control
 *     WORKING, but it is still the page trying something it should not, and a
 *     reader deserves to be told which of the two happened.
 *
 * The counter is not decoration and is not a badge. A number that only ever
 * says zero teaches nobody anything; this one moves the moment something
 * happens, and says what.
 */
export function NetworkCounter({ build }: { build: string }) {
  const [witness, setWitness] = useState(networkWitness);

  useEffect(() => onNetworkChange(() => setWitness(networkWitness())), []);

  const clean =
    witness.trapped.length === 0 &&
    witness.observed === 0 &&
    witness.blocked.length === 0;

  return (
    <div
      // Polite, not assertive: this is a standing fact, and a change to it is
      // important but never more important than whatever the user is doing.
      aria-live="polite"
      className="rounded-md border border-border bg-muted p-3 text-xs"
    >
      <p className="font-medium">
        {clean
          ? "No network call. 0 requests since the module finished loading."
          : "Something reached for the network. Details below."}
      </p>
      <ul className="mt-1 space-y-0.5 text-muted-foreground">
        <li>
          trapped networking globals called:{" "}
          <span className="font-mono">
            {witness.trapped.length === 0
              ? "none"
              : witness.trapped.join(", ")}
          </span>
        </li>
        <li>
          resources fetched since load:{" "}
          <span className="font-mono tabular-nums">{witness.observed}</span>
        </li>
        <li>
          CSP refusals:{" "}
          <span className="font-mono">
            {witness.blocked.length === 0 ? "none" : witness.blocked.join(", ")}
          </span>
        </li>
        <li className="pt-1">
          <span className="font-mono">{build}</span>
        </li>
      </ul>
    </div>
  );
}
