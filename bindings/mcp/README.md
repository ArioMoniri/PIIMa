# deid-tr MCP gateway

A stdio JSON-RPC MCP server that lets a clinician use a cloud model on Turkish clinical text
without the cloud provider ever seeing PHI.

It masks on the way out and re-identifies on the way back:

```text
  note ---> deidentify ---> masked note ---> MCP client ---> cloud model
                 |                                                |
            span map (in memory only, never written, never logged)|
                 |                                                v
  answer <-- reidentify <-- masked answer <-- MCP client <--------+
```

The masked note is what leaves the machine. The span map -- the table mapping each surrogate
back to the real identifier -- stays in this process, and this process has no way to send it
anywhere.

## Status

M2. The gateway builds a pipeline with **no detectors registered**, so L2 contributes nothing
and **names are not masked**. What runs is L1 (deterministic rules and checksums: TCKN, VKN,
SGK, phone, IBAN, MRN, date, email) and L4's demotion guardrail.

`health` derives its layer report from the pipeline it is actually holding rather than from a
hardcoded list, so `L2.live` and `L2.detectors` tell you the truth about the running process.
Check it before trusting the output. Do not treat the current output as Safe Harbor compliant.

## Install

```sh
just mcp-build          # release binary at target/release/deid-mcp
just mcp-run            # run it in the foreground, for a smoke test
just mcp-check          # fmt, clippy, tests, and the no-socket gate for this crate
```

## Registering it with an MCP client

The server speaks newline-delimited JSON-RPC on stdin/stdout and is launched by the client. It
is not a service you start yourself and connect to.

### Claude Code

```sh
claude mcp add deid-tr -- /absolute/path/to/target/release/deid-mcp
```

### Any client using the standard `mcpServers` config

```json
{
  "mcpServers": {
    "deid-tr": {
      "command": "/absolute/path/to/target/release/deid-mcp",
      "args": ["--tier", "safe-harbor", "--session-ttl", "900"]
    }
  }
}
```

Use an absolute path. A relative one resolves against whatever working directory the client
happens to have, and the failure looks like the server hanging rather than a missing file.

Verify the registration with the `health` tool before sending anything real through it.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `deidentify` | `text` | `session`, masked `text`, `spans`, `masked_spans`, `expires_in_seconds` |
| `reidentify` | `text`, `session` | restored `text`, `substitutions`, `entities_restored` |
| `forget` | `session` | `entities_destroyed` |
| `health` | none | version, tier, live layers, loaded models, transport, retention policy |

### Placeholders

`deidentify` replaces each identifier with a token shaped like:

```text
[PATIENT_NAME_4f1a2b7c_2]
 |            |        |
 |            |        +-- ordinal: distinct entities of this label, first-seen order
 |            +----------- nonce: 32 random bits, fresh for every document
 +------------------------ schema label
```

Keep the tokens verbatim in whatever you send to the model. The label lets the model reason
about the redaction ("the patient", "their clinician") and the ordinal keeps a recurring entity
recognisable as one entity. The nonce is what stops one session's tokens being restored by
another session's span map, so tokens are never stable across calls and must not be cached.

Two alternatives were available and both are wrong for a round trip specifically:

- **The pipeline's fallback placeholders** (`[TCKN]`, `[PATIENT_NAME]`) are not reversible --
  every TCKN in a note collapses onto one token, and restoring from that would put one
  patient's identifier onto another patient's finding.
- **Core's real L5 surrogates** (`Pipeline::with_surrogates`) are format-preserving: a Turkish
  name becomes a plausible Turkish name. That is right for producing a de-identified corpus and
  wrong here, because re-identification is a *search* for the surrogate in a model's free-text
  answer. A fake surname that collides with an ordinary word, or that the model echoes in an
  unrelated sentence, would be rewritten into a real patient's name. What this path needs is
  not plausibility but being unmistakable in arbitrary text.

L5 therefore stays deliberately uninstalled here, and `health` reports `L5.live: false` with
that reason.

## Session lifecycle and retention

A session exists only to hold one span map.

| Property | Value | Configure with |
|---|---|---|
| Default lifetime | 900 s (15 minutes) from creation | `--session-ttl SECONDS` |
| Concurrent sessions | 128 | `--max-sessions N` |
| Document ceiling | 1 MiB | `--max-document-bytes N` |
| Storage | memory only | not configurable |

- **The window runs from creation, not from last use.** A sliding window lets a chatty client
  hold a span map open indefinitely, which is the "lives forever in memory" failure the
  deadline exists to bound.
- **The clock is monotonic.** Moving the system clock backwards does not extend a session.
- **Expiry is enforced on access**, not by a timer, so an idle process holds no expired maps.
- **Destruction zeroes the buffer.** Each identifier lives in a `Vec<u8>` that is overwritten
  with zeroes in `Drop`, with no `unsafe` and no zeroing crate. This is defence in depth, not a
  guarantee: it cannot erase copies made by a reallocation, by the stack, or by swap. The
  deadline is the primary control.
- **Everything is destroyed when stdin closes**, so a clean shutdown leaves nothing resident.
- Call `forget` as soon as a round trip is finished. Do not wait for the TTL.

An expired handle and a handle that never existed produce the **identical** error --
`session_not_found`, same code, same message. Distinguishing them would turn the gateway into
an oracle telling an attacker whether a guessed handle was ever real.

Treat a session handle as a credential, not an identifier. It is a bearer capability over a
table of real patient identifiers. Never write one into a prompt, a file, a ticket, or a log.
The gateway does not log handles either; it logs a per-session sequence number instead.

## Network posture (I3)

**The transport is stdin/stdout. There is no socket in this build.**

The gateway never talks to the cloud model -- the MCP client does. That split is what makes it
safe for this process to hold the span map: it is structurally incapable of transmitting it.
Three things enforce that rather than merely describing it:

1. no socket-capable dependency in `Cargo.toml`, checked by `tests/no_listener.rs`;
2. no socket type and no `std::net` import in any source file, checked by the same test;
3. `just mcp-no-socket` inspects the **resolved** dependency graph, including transitive edges
   a source scan cannot see.

`--expose`, `--port`, `--listen`, `--host`, `--http` and `--bind` are recognised only in order
to be refused with an explanation. An operator who assumes the feature exists is told plainly
that it does not, rather than being handed a process they believe is reachable and
authenticated when it is neither.

If a socket transport is ever added, all four of these hold together:

- it binds loopback (`127.0.0.1`) and nothing else -- never the all-interfaces address, in any
  of its spellings;
- exposure beyond loopback requires an explicit `--expose` flag;
- **and** a bearer token;
- **and** a startup warning naming what is now reachable.

Any one of those alone is insufficient. The repository's pre-commit guard blocks the
all-interfaces address in every spelling, including the idiomatic Rust ones, so this is
enforced at edit time as well as at review time.

## Logging (I4)

Diagnostics go to **stderr** and never to stdout, because stdout is the protocol frame. A log
line carries an operation name, entity labels, byte offsets and counts:

```text
deid-mcp op=deidentify tier=safe_harbor session_seq=3 source_bytes=214 masked_bytes=228 masked_spans=4 labels=TCKN:1,PHONE:2,DATE:1
```

No document text, no model response, no surrogate value and no session handle appears in any
log line or any error message. The `Event` type takes only numbers and `&'static str`, so
there is no path from a document into a log; the error enum carries no `String` field, so there
is no path from a document into an error either. `--quiet` suppresses the stream entirely.

## What this does not do

- It does not send anything anywhere. Egress is the MCP client's job and its responsibility.
- It does not persist a span map. Restart the process and every session is gone.
- It does not mask names yet. No detector is registered, so L2 proposes nothing; see Status.
- It does not run the contextual sweep. `--tier expert` selects Expert Determination, and the
  pipeline will refuse the run until an L3 implementation is wired in, rather than silently
  degrading to Safe Harbor and returning an unswept document that looks swept.
