# Deploying deid-serve as a service

The companion to `docs/DEPLOY.md`, which covers building, packaging and installing artifacts. This
one covers the thing that changes the product's central claim: running `deid-serve` as a service
that accepts clinical text over a socket.

Read section 1 before you read the instructions. It is the reason the instructions are shaped the
way they are, and it is the part a copy-pasted command cannot tell you.

---

## 1. The tension, stated plainly

deid-tr's premise is that **PHI never leaves the device**. That is invariant I1, it is why `core/`
has no network dependency, why the contextual LLM is local, why the browser panel uploads nothing,
and why the whole product is defensible to a compliance officer at all.

**A server deployment breaks that sentence.** Not metaphorically — literally. If `deid-serve` runs
on host A and a clinical export job on host B posts notes to it, then clinical text containing
patient names, TCKNs, addresses and diagnoses crosses a network. The premise becomes "PHI never
leaves *this network*", which is a different and weaker claim, and whether it is an acceptable one
depends entirely on which network.

Two deployments, same binary, opposite verdicts:

**Legitimate.** `deid-serve` on a segmented hospital network, inside the institution's own
perimeter, reachable only by named internal systems, on infrastructure already covered by that
institution's KVKK obligations and its data processing inventory. Clinical data already crosses this
network — the LIS talks to the HIS, the PACS talks to the workstations. Adding one more internal
service that processes the same data under the same controls is a normal architectural decision, and
it is why a REST surface exists at all: the alternative is not "no network service", it is every
team building their own unaudited wrapper around the Python binding.

**Illegitimate.** `deid-serve` on a VPS, a cloud instance with a public address, or any host
reachable from the open internet — including "just for testing", including "only for a week",
including behind an obscure port. Clinical text crossing the public internet to reach a
de-identification service is the exact harm this product exists to prevent, performed by the
product. There is no configuration of this software that makes that acceptable, and this document
will not help you do it.

The line is not technical. Both look identical to the process. The difference is who can route to
the address, and only you know that.

### What changes in the threat model, in plain language

**Who can see the text in transit.** `deid-serve` terminates no TLS and never will. On the wire, a
request body is a clinical note in cleartext, and a response body is either the masked note or — on
`/reidentify` — the *restored original*. Anyone who can observe the path sees both: a switch with
port mirroring, a compromised host on the same segment, anything doing ARP spoofing on a flat
network, a passive tap. The bearer token crosses in a header, in cleartext, on every request, so
observing one request is enough to make all subsequent ones yourself. **Terminating TLS in a reverse
proxy is not optional for an exposed bind.** Section 6 has a worked configuration for nginx and
Caddy.

**What the span map holds in memory.** `/deidentify` returns a **session handle**, and the process
keeps the corresponding span map for the retention window (`--session-ttl`, default 900 seconds).
That span map is the table mapping each surrogate back to the real identifier it replaced. It is not
a derivative of the PHI; it *is* the PHI, with the narrative stripped away and an index attached. It
lives in process memory, is never written to disk, and is destroyed on expiry and at shutdown. While
it exists, anyone holding both a session handle and network reach to the process can call
`/reidentify` and get the original document back. That is the feature — round-trip
re-identification is what makes the gateway and the batch path useful — and it is also the sharpest
edge in the product.

**Why the session store is the most sensitive structure in the product.** A leaked masked document
is a document with the identifiers removed. A leaked *span map* is a de-identification failure for
every document that produced it, retroactively, in one object. It is the highest-value target in the
system and the reason the exposure gates are as annoying as they are. Three consequences follow, all
deliberate:

- Session handles come from the OS CSPRNG, never a counter or a clock, so they cannot be guessed or
  enumerated.
- Sessions expire, and a full store refuses new sessions rather than evicting live ones.
- The process has **no outbound network capability at all** — no HTTP client in its dependency list,
  no `TcpStream::connect` anywhere in the crate, both enforced by tests. It accepts connections; it
  never makes one. It holds the span map safely only because it has nowhere to send it.

### And before any of this: what is *not* masked

This build has **no trained L2 model**, so **deid-tr masks ZERO names.** `PATIENT_NAME`,
`CLINICIAN_NAME` and `RELATIVE_NAME` pass through untouched. What is masked is the rule-detectable
set: TCKN, VKN, SGK, IBAN, phone, MRN, email, dates.

If your reason for deploying this is "so that names are removed before the data goes somewhere
else", that requirement is not met, and no flag, tier or configuration meets it. `just deploy-check`
reports it on every run, `GET /health` and `GET /entities` report it per label, and the process
prints it at startup — because the one thing an operator must not discover by reading the output is
that names are still in it.

---

## 2. The default: run it locally

```
just deploy-local
```

Builds the release binary and runs it bound to `127.0.0.1:8787`, printing the exact command it runs
so you can copy the safe invocation rather than reconstructing one later. Nothing off the machine
can reach it. No token is needed, because the gate is the kernel rather than a credential.

Anything else is passed through:

```
just deploy-local --port 9000
just deploy-local --session-ttl 300 --max-sessions 16
```

This is the deployment that needs no justification, and many of the deployments people reach for a
container to build are this one with extra steps.

---

## 3. The preflight

```
just deploy-check                                                    # check the default
just deploy-check --host 10.1.2.3 --expose --token-file ./secrets/deid_bearer
```

Creates no socket, starts nothing, and exits non-zero if the deployment must not proceed.

| Check | What it does |
|---|---|
| `bind` | Runs the real `bind::plan`. Fails on anything the binary would refuse. |
| `token` | Length, whitespace and repetition. Stricter than the binary's start-time floor. |
| `tls` | Always warns. This service terminates none; see section 6. |
| `layer-l1` / `l2` / `l3` | Which layers are live in a pipeline built from these same flags. |

`WARN` does not fail. The TLS warning and the "masks zero names" warning are true of every correct
deployment as well as every broken one, and a check that fails on the correct default is a check
people learn to suppress with a flag.

`bind` can PASS while `token` FAILs. That is not a contradiction: `bind` reports what the running
binary would do (its floor is 32 characters), and `token` is the stricter judgement a human asked
for before exposing a PHI endpoint. The binary would start; you should not let it.

---

## 4. systemd

`deploy/systemd/deid-serve.service`. Loopback, a dedicated unprivileged `deid` user, and hardening
directives each carrying a comment saying what it prevents *in this product* rather than in general.

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin deid
sudo install -m 0755 target/release/deid-serve /usr/local/bin/deid-serve
sudo install -m 0644 deploy/systemd/deid-serve.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now deid-serve
```

`MemoryDenyWriteExecute=yes` is the one directive that may need removing later: it is free today
because `deid-serve` is ahead-of-time compiled Rust with no JIT, and a future build linking an ONNX
runtime for L2 or a local LLM runtime for L3 will generate code at run time and fail to start under
it. Removing it *then* is correct; keeping it now costs nothing.

### Supplying a bearer token

**There is no `EnvironmentFile=` in that unit and there must never be.** A token in the environment
is visible in `/proc/PID/environ` and in `systemctl show`, which any user may run. A token in
`--token` is visible in `ps` to every user on the box. Use one of these instead.

**systemd credentials (preferred, systemd v247+).** The file is placed in a private per-unit
directory no other unit can read, and never enters the environment or the argument vector.

```
sudo install -d -m 0700 /etc/deid-tr
openssl rand -hex 32 | sudo tee /etc/deid-tr/bearer >/dev/null
sudo chmod 0400 /etc/deid-tr/bearer && sudo chown root:root /etc/deid-tr/bearer
```

then in the unit:

```
LoadCredential=bearer:/etc/deid-tr/bearer
ExecStart=/usr/local/bin/deid-serve --port 8787 --token-file %d/bearer
```

**A root-owned file (fallback, older systemd).** The same `0400 root:root` file, plus a
`SupplementaryGroups=` that lets the service user read that one file, and the same `--token-file`.
Still a file, still not an environment variable.

Generate the token; do not choose one. `openssl rand -hex 32` clears every check. A department name
padded to thirty-two characters also clears the length floor while carrying perhaps twenty bits of
entropy, and the preflight **cannot** reliably tell you so — see the doc comment on
`preflight::token_weakness` for exactly what it can and cannot catch.

---

## 5. Container

`deploy/container/`. Multi-stage build, `debian:trixie-slim` runtime, non-root `deid` user, read-only
root filesystem, all capabilities dropped, `HEALTHCHECK` on `/health`, no model weights, and no
network access at build time beyond one `cargo fetch`.

```
docker build -f deploy/container/Dockerfile -t deid-tr/deid-serve:local .
docker compose -f deploy/container/compose.yaml up
```

### The container networking problem, honestly

The image's default command binds the **container's loopback**. Under bridge networking Docker
forwards a published port to the container's *bridge* address, not to its loopback — so the default
image **fails closed**: `docker run -p 8787:8787` gives a connection refused rather than a
de-identification endpoint nobody chose to publish.

This is exactly the situation in which every other project reaches for an all-interfaces bind inside
the container, on the entirely reasonable grounds that a container network namespace is already
isolated. **We refuse that unconditionally** (ADR D-040), so there are two supported shapes.

**Host networking — the default service in `compose.yaml`, Linux.** The container shares the host's
network namespace, so the loopback it binds *is* the host's loopback. Identical reachability to
`just deploy-local`, no token needed, nothing published. On Docker Desktop for macOS or Windows host
networking behaves differently and the right answer there is `just deploy-local` on the host.

**Bridge networking — the `bridge` profile.** The entrypoint resolves the container's *own* address
— a specific interface address, not an all-interfaces bind — and passes `--expose` with a token read
from a mounted Docker secret. The publish is `127.0.0.1:8787:8787`, on the host's loopback.

```
install -d -m 0700 ./secrets
openssl rand -hex 32 > ./secrets/deid_bearer && chmod 0400 ./secrets/deid_bearer
docker compose -f deploy/container/compose.yaml --profile bridge up
```

Two independent gates: every request is authenticated, and the host publishes only on its loopback,
so nothing off the machine reaches the port even if the token leaks. (`secrets/` is git-ignored.
Verify that before you create it.)

**Never `-p 8787:8787`.** A publish with no host address in front of it publishes on every interface
the host has. That is the incumbent's documented default — their prose is consistently loopback,
their shipped compose file is not, and the operator gets the compose file. It is the specific bug
this project does not ship, and `bindings/service/tests/no_deployment_path_binds_all_interfaces.rs`
fails if any publish in our compose file loses its host address.

---

## 6. TLS is your job, not this service's

`deid-serve` terminates no TLS. That is a deliberate scope decision — a TLS stack is a large
dependency, a large attack surface, and a certificate lifecycle this process has no business owning
— and it means an exposed bind is **cleartext unless you put a terminator in front of it**.

The shape in both examples is the same and it is the shape to copy: **the proxy is the only thing
exposed, and `deid-serve` stays on loopback.** Do not expose the service *and* proxy it; that leaves
the cleartext port reachable next to the encrypted one.

### Caddy

```
deid.hastane.internal {
    # An internal CA for an internal hostname. A public ACME challenge for a
    # hospital-internal name publishes that name in a certificate transparency
    # log, permanently and for anyone.
    tls internal

    reverse_proxy 127.0.0.1:8787

    # Request bodies are clinical notes. Nothing about them goes in a log.
    log {
        output file /var/log/caddy/deid.log
        format json
    }
}
```

### nginx

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name deid.hastane.internal;

    ssl_certificate     /etc/ssl/certs/deid.crt;
    ssl_certificate_key /etc/ssl/private/deid.key;
    ssl_protocols       TLSv1.3;

    # PHI IN THE ACCESS LOG IS THE FAILURE MODE. This API has no query string,
    # so URLs carry no PHI today, but the default combined format also logs the
    # referer and user agent and a future route might be less clean. Off is the
    # right setting for this vhost specifically.
    access_log off;
    error_log  /var/log/nginx/deid-error.log warn;

    # A clinical document is not a 1MB request and a batch of them is not a 10MB
    # one. Set this to what your largest real batch needs and no higher: an
    # unbounded body on a PHI endpoint is a memory-exhaustion lever.
    client_max_body_size 32m;

    location / {
        # LOOPBACK. deid-serve is not exposed; this proxy is the only thing that
        # is.
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;

        # deid-serve implements no keep-alive: it closes every connection and
        # announces that it does. Do not let the proxy assume otherwise.
        proxy_set_header Connection "";

        # Masking a large batch is not instant, and a proxy timeout mid-batch
        # leaves a session holding a span map with no client coming back for it.
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

With either in place `deid-serve` keeps its default loopback bind and needs no `--expose` at all —
the proxy reaches it over loopback. **That is the recommended exposed architecture**: the only
process listening on a routable address is the one whose job is TLS.

If you genuinely need `deid-serve` itself on a routable address — a second host must reach it
directly and no proxy is possible — then you need `--expose`, a specific address and a generated
token, you still need TLS from somewhere, and you should run `just deploy-check` and read every line
of it first.

---

## 7. What this service will not do, ever

- **Bind all interfaces.** No flag, environment variable, configuration file or container setting
  reaches it. Not with `--expose`, not with a token, not with both, in any spelling — including
  `::ffff:` in front of the IPv4 form, which is the one that gets past a naive check. ADR D-040
  records the decision and what it costs.
- **Read configuration from the environment.** `argv` is the only configuration channel, because
  `argv` is the one a human typed. A misconfigured deployment environment must not be able to move
  a PHI endpoint.
- **Make an outbound connection.** No HTTP client in the dependency list, ever. This is what makes
  holding the span map defensible.
- **Log document text.** No request or response body, surrogate, session handle or bearer token
  enters a log line, an error string or a metric label (I4).

---

## 8. Before you expose anything, in order

1. Read section 1 again and answer, out loud, which of the two deployments this is.
2. `just deploy-check` with the exact flags you intend to use. Exit code 0, no `FAIL` lines.
3. Read every `WARN` line. They are true of correct deployments too, which is why they do not fail.
4. Confirm that names being masked is not part of your acceptance criteria, because they are not.
5. Confirm TLS is terminated in front of the service and the service itself stays on loopback.
6. Confirm the session TTL matches your retention policy rather than the default.
7. Confirm the bearer token was generated and is stored as a root-owned file or a systemd
   credential — not in an environment variable, an `.env` file, or a shell history.
