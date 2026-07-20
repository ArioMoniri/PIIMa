# deid-tr @@VERSION@@ — @@TARGET@@

Turkish clinical text de-identification. Everything in this bundle runs on this machine.
Nothing here opens a socket to send your text anywhere.

Source revision: `@@COMMIT@@`
License: Apache-2.0 (see `LICENSE`)

---

## READ THIS FIRST: names are NOT masked

This build masks **no names**. Not patient names, not clinician names, not relative names.

L2 — the NER ensemble that detects names — has **no trained model in this build**, and no model
weights ship in this bundle. `--tier expert` does not change it: that tier adds the L3
quasi-identifier sweep, which also masks no names.

If you paste a note containing `Ayşe Yılmaz` into any surface in this bundle, `Ayşe Yılmaz`
comes back out. Treat the output as **not de-identified**. It is not Safe Harbor compliant and
it is not fit to send to a cloud model.

Run `bin/deid doctor` for this machine's answer about which layers can actually run here.

## What DOES work

Rule-detectable identifiers, from L1 (regex plus checksum) with L4's demotion guardrail:

| Masked | Not masked |
|---|---|
| TCKN (11-digit, checksum-validated) | PATIENT_NAME |
| VKN (10-digit) | CLINICIAN_NAME |
| SGK number | RELATIVE_NAME |
| Turkish phone formats (`+90 5XX`, `0(5XX)`, `05XX`) | anything else with no fixed format |
| IBAN (TR, mod-97) | |
| MRN | |
| Email | |
| Dates | |

Latin/English medical vocabulary (`carcinoma`, `costa`, `Adalat`, `metformin`) is on an
allowlist and is deliberately kept, because masking it destroys the note.

## No model weights are bundled

There is no model directory in this bundle and you are not missing one. **No weights exist to
ship**, for any layer. Do not go hunting for them.

`deid pull` — the explicit, checksummed weight fetch — is **not implemented**. Running it prints
its contract and exits. Weights are never downloaded at inference time, by design: a lazy fetch
is a network call on a machine holding PHI.

For `--tier expert` you supply your own **local** model: `--model FILE.gguf --runtime BIN`
(or `DEID_L3_MODEL` / `DEID_L3_RUNTIME`). If L3 cannot be wired, the run fails; it never
silently falls back to Safe Harbor. The L3 model is local, always. There is no cloud path.

## Contents

```
bin/deid          CLI: mask text and files (txt, csv, json, jsonl, docx, pdf)
bin/deid-mcp      stdio JSON-RPC MCP gateway: mask out, re-identify back
bin/deid-serve    local HTTP service, binds 127.0.0.1:8787 by default
panel/            the browser panel (static files)
pkg-web/          the WASM module the panel loads
SHA256SUMS        checksum of every file above
LICENSE           Apache-2.0
```

`bin/deid-serve` refuses an all-interfaces bind unconditionally — `--expose` and `--token` do
not unlock `0.0.0.0` or `::`. Bind the one address you mean, or bind loopback and tunnel.

## Verify before you run anything

```sh
shasum -a 256 -c SHA256SUMS      # macOS
sha256sum -c SHA256SUMS          # Linux
```

Compare the checksums against the ones published out of band with this bundle. A bundle whose
checksums you did not check is a binary of unknown origin about to read patient records.

## Use it

```sh
./bin/deid mask note.txt
./bin/deid doctor
./bin/deid-serve                 # http://127.0.0.1:8787
```

The panel is static and needs any local web server, rooted at **this directory** (the panel
loads the module from the sibling `../pkg-web/`):

```sh
python3 -m http.server --bind 127.0.0.1 8722
# then open http://127.0.0.1:8722/panel/index.html
```

Open the browser's Network tab while you use it. It stays empty. That is the point.

## Registering the MCP gateway

From a checkout, `just register-mcp` prints the exact block with absolute paths filled in.
From this bundle, the command is the absolute path to `bin/deid-mcp`:

```json
{
  "mcpServers": {
    "deid-tr": {
      "command": "/absolute/path/to/bin/deid-mcp",
      "args": ["--tier", "safe-harbor", "--session-ttl", "900"]
    }
  }
}
```

Call the gateway's `health` tool before sending anything real through it. It reports which
layers are actually live in the process you just started, rather than which ones are supposed
to be.
