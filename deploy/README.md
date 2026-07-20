# deploy/

Deployment artifacts for `deid-serve`, the local HTTP/JSON de-identification service.

**Read [`../docs/DEPLOY-SERVER.md`](../docs/DEPLOY-SERVER.md) before using any of them.** It states
what changes when clinical text starts crossing a network to reach this process, and that argument
is the reason these files are shaped the way they are. Nothing in this directory is safe to
copy-paste without it. [`../docs/DEPLOY.md`](../docs/DEPLOY.md) covers the separate question of
building, packaging and installing the artifacts.

| Path | What it is |
|---|---|
| `systemd/deid-serve.service` | Loopback bind, dedicated unprivileged user, hardening directives that each say what they prevent in this product. No environment file, ever. |
| `container/Dockerfile` | Multi-stage, minimal runtime base, non-root user, `HEALTHCHECK` on `/health`, no model weights. |
| `container/compose.yaml` | Host networking by default; a `bridge` profile that publishes `127.0.0.1:PORT:PORT` and never a bare `PORT:PORT`. |
| `container/entrypoint.sh` | The two things a Dockerfile line cannot express: resolving this container's own address, and the health probe. |

## The two commands

```
just deploy-local     # run it here, on 127.0.0.1, with the exact command printed
just deploy-check     # preflight: bind, token, TLS, and which layers are actually live
```

`deploy-local` is the default and the one the documentation leads with. `deploy-check` creates no
socket and exits non-zero if the deployment must not proceed. Run it with the exact flags you intend
to use, before you expose anything.

## Two things that are true of every file here

**An all-interfaces bind is refused unconditionally.** There is no flag, environment variable,
configuration file or container setting that reaches one — not with `--expose`, not with a bearer
token, not with both, in any spelling. `bindings/service/tests/no_deployment_path_binds_all_interfaces.rs`
is the proof, and `docs/DECISIONS.md` D-040 records the decision along with what it costs the
container-networking cases it refuses.

**This build masks ZERO names.** L2 has no trained model, so `PATIENT_NAME`, `CLINICIAN_NAME` and
`RELATIVE_NAME` pass through untouched; TCKN, VKN, SGK, IBAN, phone, MRN, email and dates are
masked. No deployment configuration changes that. `just deploy-check` says so on every run.
