#!/usr/bin/env bash
# PreToolUse guard for Write and Edit.
#
# WHY this exists at all: an instruction in a prompt is a suggestion an agent rationalises
# past at 2am. A hook returning exit 2 means the edit does not happen. The invariants I1-I8
# are load-bearing for a PHI pipeline, so they are enforced mechanically, not socially.
#
# WHY the patterns are deliberately over-broad: a guard that blocks only the shapes someone
# happened to think of is a guard with a blind spot, and the blind spot is where the leak
# goes. Where a check must choose, it prefers a false positive that a human overrides to a
# miss nobody notices - except in the narrow allow cases below, which exist because a guard
# that fires on ordinary work is a guard the next engineer disables.
#
# RESIDUAL CEILING - what this guard does NOT cover, stated plainly because a guard whose
# documentation overstates it is how the next engineer gets surprised:
#
#   The I4 checks are a regex over IDENTIFIER NAMES in the text being written. They cannot follow
#   a value. Three shapes are known to pass and are not fixable at this layer:
#     - a variable alias        `let s = doc_text; println!("{s}");`
#     - a slice or sub-expression `println!("{}", &doc[0..4]);`
#     - an assert               `assert_eq!(expected, doc_text);` and any macro not enumerated
#   Renaming the binding defeats the check, and renaming a binding is not an exotic manoeuvre.
#
#   The REAL mitigation for I4 is at the type level, not here: error types in core/ carry byte
#   offsets, entity labels and a text_hash and are forbidden a String field (enforced below), and
#   any type that can hold document text gets a hand-written Debug impl that prints offsets. If a
#   type cannot hold the text, no format string can print it, whatever the local variable is
#   called. This guard is defence in depth against the careless case - it is not the guarantee.
#
#   Likewise the I1 crate ban below is a NAME ENUMERATION and can only ever list the HTTP clients
#   someone thought of. The structural gate is `just core-no-socket`, which inspects the RESOLVED
#   dependency graph. Do not read a passing hook as proof that core/ cannot open a socket.
#
# Contract: tool-call JSON on stdin, exit 0 to allow, exit 2 to block with the reason on stderr.
set -euo pipefail

# WHY fail CLOSED rather than open: a guard that silently disables itself when a dependency is
# missing is worse than no guard, because the team believes they are still protected.
if ! command -v jq >/dev/null 2>&1; then
  cat >&2 <<'EOF'
BLOCKED by guard_invariants.sh [GUARD-UNAVAILABLE]
  jq is not installed, so the invariant guard cannot inspect this tool call.
  This guard fails CLOSED: a guard that disables itself is worse than no guard.
  do instead     : install jq, then retry.
                   macOS   : brew install jq
                   Debian  : sudo apt-get install -y jq
                   Fedora  : sudo dnf install -y jq
                   Alpine  : apk add jq
EOF
  exit 2
fi

# WHY read stdin once into a variable: stdin is a stream and cannot be rewound, but every
# check below needs a different field out of the same payload.
payload="$(cat)"

if ! printf '%s' "$payload" | jq -e . >/dev/null 2>&1; then
  cat >&2 <<'EOF'
BLOCKED by guard_invariants.sh [GUARD-UNAVAILABLE]
  stdin was not parseable JSON, so the invariant guard could not inspect this tool call.
  do instead     : ensure the hook is wired to PreToolUse with the standard payload shape.
EOF
  exit 2
fi

jqr() { printf '%s' "$payload" | jq -r "$1" 2>/dev/null || true; }

tool_name="$(jqr '.tool_name // ""')"
file_path="$(jqr '.tool_input.file_path // .tool_input.notebook_path // ""')"

# WHY canonicalise before ANY path match: every path rule below is a literal comparison, and
# `eval/./thresholds.yaml`, `eval//thresholds.yaml` and `eval/gold/../gold/g.jsonl` all open
# exactly the protected file while matching none of the patterns. Absolute paths were already
# handled; only normalisation leaked. One step here closes it for I2, I5 and I7 at once, rather
# than every pattern separately growing its own tolerance for `.`, `..` and doubled separators.
normalise_path() {
  printf '%s' "$1" | awk '
    {
      p = $0
      abs = (substr(p, 1, 1) == "/")
      n = split(p, seg, "/")
      top = 0
      for (i = 1; i <= n; i++) {
        s = seg[i]
        if (s == "" || s == ".") continue
        if (s == "..") {
          if (top > 0 && st[top] != "..") { delete st[top]; top-- } else { st[++top] = ".." }
          continue
        }
        st[++top] = s
      }
      out = ""
      for (i = 1; i <= top; i++) out = out (i > 1 ? "/" : "") st[i]
      printf "%s%s", (abs ? "/" : ""), out
    }'
}
file_path="$(normalise_path "$file_path")"

# WHY a second, repository-root-relative form: the allowlists below are fail-OPEN, and an
# unanchored one re-creates the very defect it was written to fix. `(^|/)scripts/` matches any
# path SEGMENT, so core/src/scripts/sweep.rs and bindings/python/scripts/sweep.py were exempt
# from the cloud-SDK ban - a directory name defeating the invariant, again. Allowlists are
# therefore anchored to the repository root; the BLOCK patterns keep their segment match,
# because over-matching a block is safe and over-matching an allow is a hole.
repo_root="${CLAUDE_PROJECT_DIR:-}"
[ -n "$repo_root" ] || repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[ -n "$repo_root" ] || repo_root="$PWD"
repo_root="$(normalise_path "$repo_root")"
rel_path="$file_path"
case "$file_path" in
  "$repo_root"/*) rel_path="${file_path#"$repo_root"/}" ;;
esac

# Every shape an editing tool can carry content in, concatenated into one blob.
#
# WHY all four and not the obvious two: reading only .content and .new_string meant MultiEdit
# (.tool_input.edits[].new_string) and NotebookEdit (.tool_input.new_source) both resolved to the
# empty string, and the empty-content early-exit below then waved them through with EVERY content
# check skipped - I1, I3, I4 and the L3-local corollary all off, for two tools that write source
# files exactly like Write does. The I7 branch already named MultiEdit, so the coverage was
# intended; the extractor never caught up. A guard reads the payload it is given, not the payload
# it expects.
#
# .new_source may be a string or an array of source lines, so array shapes are joined rather than
# stringified - `tostring` on an array yields JSON, which would hide `"use reqwest"` inside quotes
# and escapes and defeat the very patterns below.
content="$(jqr '
  [ (.tool_input.content    // empty),
    (.tool_input.new_string // empty),
    (.tool_input.edits // [] | .[]? | .new_string // empty),
    (.tool_input.new_source // empty)
  ]
  | map(if type == "array" then map(tostring) | join("") else tostring end)
  | join("\n")')"

# WHY the empty-content exit must FAIL CLOSED for editing tools: "no content found" and "content
# is legitimately empty" are different facts, and conflating them is exactly how the MultiEdit and
# NotebookEdit bypasses above stayed invisible. An unrecognised payload shape means the guard did
# not inspect the write, and a guard that silently no-ops on a shape it does not recognise is how
# this entire class of bypass recurs the next time a tool is added.
#
# The test is KEY PRESENCE, not emptiness: `Write` with content:"" and `Edit` with new_string:""
# (deleting a line) are ordinary work and stay allowed. A NotebookEdit deleting a cell carries no
# source at all, so its own edit_mode is accepted as the recognised shape.
editing_tool='^(Write|Edit|MultiEdit|NotebookEdit|Update)$'
if printf '%s' "$tool_name" | grep -qE "$editing_tool"; then
  shape_ok="$(jqr '[ (.tool_input | has("content")),
                     (.tool_input | has("new_string")),
                     (.tool_input | has("edits")),
                     (.tool_input | has("new_source")),
                     ((.tool_input.edit_mode // "") == "delete") ] | any')"
  if [ "$shape_ok" != "true" ]; then
    printf 'BLOCKED by guard_invariants.sh [GUARD-UNAVAILABLE]\n' >&2
    printf '  tool           : %s\n' "$tool_name" >&2
    printf '  target path    : %s\n' "${file_path:-<no path in payload>}" >&2
    printf '  the payload carried no recognised content field, so NO content invariant (I1, I3,\n' >&2
    printf '  I4, L3-is-local) could be checked against this write. This guard fails CLOSED on an\n' >&2
    printf '  unrecognised shape: a guard that no-ops on a payload it cannot read is a blind spot.\n' >&2
    printf '  do instead     : teach the extractor in guard_invariants.sh this shape (alongside\n' >&2
    printf '                   .content, .new_string, .edits[].new_string and .new_source), add a\n' >&2
    printf '                   BLOCK and an ALLOW case to scripts/hooks/test_hooks.sh, then retry.\n' >&2
    exit 2
  fi
fi

block() {
  # WHY the pattern and never the matched text: this guard runs over clinical source and
  # fixtures. Echoing the matched span into stderr would itself be the leak it is preventing.
  printf 'BLOCKED by guard_invariants.sh [%s]\n' "$1" >&2
  printf '  matched pattern: %s\n' "$2" >&2
  printf '  target path    : %s\n' "${file_path:-<no path in payload>}" >&2
  printf '  do instead     : %s\n' "$3" >&2
  printf '  (the matched text is deliberately not printed - it may be PHI)\n' >&2
  exit 2
}

# ---------------------------------------------------------------------------
# I2 - eval/thresholds.yaml is raise-only.
# ---------------------------------------------------------------------------
if printf '%s' "$file_path" | grep -qE '(^|/)eval/thresholds\.yaml$'; then
  block "I2 recall-is-the-product" \
        '(^|/)eval/thresholds\.yaml$' \
        'thresholds are raise-only and need a human decision plus a docs/DECISIONS.md ADR. Ask the human, record the ADR, and let them make the edit.'
fi

# ---------------------------------------------------------------------------
# I5 - model cards are build artifacts, never hand-written.
# Scoped narrowly on purpose: the repository README.md and docs/*.md are ordinary prose.
# ---------------------------------------------------------------------------
card_pattern='(^|/)(models?|checkpoints?|hf|release)/[^ ]*README\.md$|(^|/)model_card[^/]*\.md$|(^|/)cards/[^/]*\.md$'
if printf '%s' "$file_path" | grep -qE "$card_pattern"; then
  block "I5 cards-are-build-artifacts" \
        "$card_pattern" \
        'model cards are generated by scripts/publish.py from a committed eval run in eval/results/<run_id>.json. Change the generator or the eval run, never the card.'
fi

# ---------------------------------------------------------------------------
# I7 - the golden set is append-only.
#
# WHY this is a channel and not a wall: adding a fixture the pipeline gets wrong is the single
# most valuable commit in this repository, so creating a NEW fixture file and APPENDING to an
# existing one both stay frictionless. What is blocked is the shape that silently weakens the
# corpus: Write replaces a whole file, and an Edit that rewrites or deletes an existing line
# makes a red test go green by moving the goalposts.
# ---------------------------------------------------------------------------
gold_pattern='(^|/)eval/(gold|adversarial)/[^/]*\.jsonl$'
i7_advice='the golden set is append-only (I7). ADDING a new fixture file, or APPENDING a new line to an existing one, is always allowed and is the most valuable commit type here. Rewriting, reordering or deleting an existing fixture is not: if a fixture looks wrong, report it and let a human decide. To append with Edit, set old_string to the exact current tail of the file and new_string to that same tail followed by your new lines.'

if printf '%s' "$file_path" | grep -qE "$gold_pattern"; then
  # A file that does not exist yet cannot be weakened - creating fixtures stays frictionless.
  if [ -e "$file_path" ]; then
    if [ "$tool_name" = "Write" ]; then
      block "I7 golden-set-is-append-only" \
            "Write to existing ${gold_pattern}" \
            "$i7_advice"
    fi
    if [ "$tool_name" = "Edit" ] || [ "$tool_name" = "MultiEdit" ]; then
      old_string="$(jqr '.tool_input.old_string // ""')"
      new_string="$(jqr '.tool_input.new_string // ""')"
      existing="$(cat "$file_path" 2>/dev/null || true)"
      # Strict append has two halves: the replacement must extend the text it replaces, and the
      # text it replaces must be the tail of the file. Anything else edits history.
      appends=0
      case "$new_string" in
        "$old_string"*) appends=1 ;;
      esac
      tail_ok=0
      case "$existing" in
        *"$old_string") tail_ok=1 ;;
      esac
      [ -n "$old_string" ] || { appends=0; tail_ok=0; }
      if [ "$appends" -ne 1 ] || [ "$tail_ok" -ne 1 ]; then
        block "I7 golden-set-is-append-only" \
              "non-appending Edit to existing ${gold_pattern}" \
              "$i7_advice"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Content checks below.
#
# Comment lines are stripped first so that a comment explaining a ban is not itself a
# violation. `#` is treated as a comment introducer only when it is NOT followed by `[` or `!`,
# because `#[error("...")]` and `#![forbid(unsafe_code)]` are Rust attributes, not comments -
# and the thiserror attribute is exactly where a PHI leak hides.
# ---------------------------------------------------------------------------
code_lines="$(printf '%s\n' "$content" | grep -vE '^[[:space:]]*(#($|[^!\[])|//|/\*|\*|--|<!--)' || true)"

# ---------------------------------------------------------------------------
# I1 corollary - the L3 contextual sweep is LOCAL only, everywhere in the repository.
#
# WHY this is repo-wide with an allowlist rather than scoped to paths containing "context":
# the previous scoping meant core/src/l3/sweep.rs and bindings/python/llm.py could both reach a
# cloud API, which is the whole invariant, defeated by a directory name. The allowlist exists
# so this guard, its tests and the documentation can name the SDKs they ban - and it is anchored
# to the repository root, because an unanchored allowlist reintroduces that same defect.
#
# WHY a generic https heuristic sits alongside the named provider list: an enumeration of SDKs
# can only ever cover the providers someone thought of, and the two largest cloud LLM endpoints
# in production use - generativelanguage.googleapis.com and bedrock-runtime - match neither
# `https://api.` nor any named SDK. I2 says prefer a false positive to a miss, so ANY remote
# https host in a non-allowlisted source file is a finding, and the message routes a legitimate
# case through human review rather than inviting the next engineer to widen the allowlist.
# ---------------------------------------------------------------------------
cloud_allowlist='^(scripts|docs)/|^\.claude/agents/'
cloud_advice='the L3 contextual layer runs a LOCAL quantized model via candle or ort. Sending PHI to a cloud model in order to detect its PHI defeats the entire product and violates I1. Implement the Contextual trait against a local runtime. This applies to every path in the repository, not just core/src/context/. ESCAPE HATCH: if this URL or SDK is genuinely not an inference path (a docs link, a registry mirror, a checksum source), do NOT widen this guard yourself - ask the human, record the reasoning in docs/DECISIONS.md, and let them decide whether the call site moves under scripts/ or the URL becomes a documented exception.'
if ! printf '%s' "$rel_path" | grep -qE "$cloud_allowlist"; then
  cloud_sdk='(^|[^a-z-])(openai|anthropic|google-generativeai|google\.generativeai|google\.genai|cohere|mistralai|groq|litellm|openrouter|replicate|together|togetherai|perplexity|deepseek|fireworks|anyscale|vertexai|bedrock|bedrock-runtime|azure\.ai\.inference|azure-ai-inference|ChatCompletionsClient|InferenceClient)([^a-z-]|$)'
  cloud_host='generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com|openrouter\.ai|api\.anthropic\.com|api\.openai\.com|bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com|azure\.com/openai|openai\.azure\.com'
  cloud_import='(import|from|use|require|extern crate|dependencies)[^\n]{0,60}(replicate|together)([^a-z-]|$)'
  if printf '%s\n' "$code_lines" | grep -qiE "$cloud_sdk" \
     || printf '%s\n' "$code_lines" | grep -qiE "$cloud_host" \
     || printf '%s\n' "$code_lines" | grep -qiE "$cloud_import"; then
    block "I1-corollary L3-is-local-only" \
          "$cloud_sdk | $cloud_host" \
          "$cloud_advice"
  fi

  # Generic heuristic. Loopback is the only host a local runtime ever needs.
  #
  # WHY `https?` and not `https`: an https-only pattern reads a scheme as the risk, but the risk
  # is the HOST. `minreq::get("http://x/y")` is the same exfiltration as the TLS spelling with one
  # character removed, and plaintext http to a remote host is strictly worse, not exempt. Every
  # self-hosted inference gateway in production speaks plain http, so this was the likely
  # spelling, not an exotic one.
  remote_http="$(printf '%s\n' "$code_lines" | grep -oiE 'https?://[^[:space:]"'\''<>),;]+' \
    | grep -viE '^https?://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)([:/]|$)' \
    | grep -vE '^[[:space:]]*$' || true)"
  if [ -n "$remote_http" ]; then
    block "I1-corollary L3-is-local-only" \
          'http:// or https:// to any host that is not localhost/127.0.0.1' \
          "$cloud_advice"
  fi
fi

# ---------------------------------------------------------------------------
# WHY scripts/hooks/, docs/ and Markdown generally are exempt from the remaining content
# checks: this guard and the documentation that explains it must be able to spell out the very
# patterns they ban. A guard that cannot document itself gets deleted by the next engineer.
# Exempting Markdown is safe because the path-based rules above have already run.
#
# Anchored to the repository root for the same reason the cloud allowlist is: unanchored, a
# directory named docs/ anywhere - core/src/docs/ - turned off I3, I4 and I1 for that file.
# ---------------------------------------------------------------------------
if printf '%s' "$rel_path" | grep -qE '^(scripts/hooks|docs)/' \
   || printf '%s' "$file_path" | grep -qE '\.(md|markdown)$'; then
  exit 0
fi

if [ -z "$content" ]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# I3 - never bind 0.0.0.0, never bind "::".
# Matched in assignment / bind-like context only, so prose mentioning the address is fine.
#
# WHY the non-dotted-quad spellings are here: `SocketAddr::from(([0, 0, 0, 0], 8080))` and
# `Ipv4Addr::UNSPECIFIED` are THE idiomatic ways to write this in Rust. A guard that only knows
# the string "0.0.0.0" catches the spelling nobody uses and misses the two that everybody does.
# ---------------------------------------------------------------------------
Z='[[:space:]]*0[[:space:]]*'
bind_v4="(bind|listen|host|addr|address|interface)[^\n]{0,40}0\.0\.0\.0|0\.0\.0\.0:[0-9]|=[[:space:]]*\"?0\.0\.0\.0|Ipv4Addr::UNSPECIFIED|(SocketAddr|SocketAddrV4|IpAddr|Ipv4Addr)[^\n]{0,40}[\[(]${Z},${Z},${Z},${Z}[])]"
if printf '%s\n' "$code_lines" | grep -qiE "$bind_v4"; then
  block "I3 never-bind-all-interfaces" \
        "$bind_v4" \
        'default to 127.0.0.1. Exposure beyond loopback requires an explicit --expose flag, a bearer token and a startup warning. Ipv4Addr::UNSPECIFIED and SocketAddr::from(([0,0,0,0], port)) are 0.0.0.0 spelled in Rust; use Ipv4Addr::LOCALHOST.'
fi

bind_v6='(bind|listen|host|addr|address|interface)[^\n]{0,40}("::"|'\''::'\''|"::([0-9]+)?")|"::":?[0-9]*"?[[:space:]]*[,)]|Ipv6Addr::UNSPECIFIED|\[::\]'
if printf '%s\n' "$code_lines" | grep -qiE "$bind_v6"; then
  block "I3 never-bind-all-interfaces" \
        "$bind_v6" \
        'the IPv6 unspecified address "::" binds every interface exactly like 0.0.0.0, and Ipv6Addr::UNSPECIFIED and "[::]" are the same address in the two other spellings Rust and URL authorities accept. Default to 127.0.0.1 and gate exposure behind --expose plus a bearer token.'
fi

# ---------------------------------------------------------------------------
# I4 - input text must never be interpolated into a log, error or panic.
#
# The alternations below are wide on purpose. The previous version matched Python dot-notation
# logging and five Rust macros, which meant tracing::error!, log::warn!, write!/writeln!, dbg!
# and the thiserror #[error("...")] attribute all wrote document text to stderr unchallenged -
# and #[error] is the single most likely leak in this codebase, because it is the one that
# looks like an error definition rather than a log statement.
#
# WHY the content is JOINED across newlines before matching, instead of the obvious line-by-line
# grep: rustfmt MANUFACTURES the bypass. Take any single-line form this guard blocks and run
# `rustfmt --edition 2021` on it; the macro, the format string and the closing `);` land on three
# separate lines, and a single-line pattern can never see it again. `just check` runs fmt, so the
# guard would block the leak on write and the formatter would immediately reshape it into a form
# invisible to every later edit. Log lines here are descriptive and therefore long, so the
# wrapped form is the common case, not the corner case. Newlines inside balanced parentheses and
# brackets are collapsed to spaces so a logical macro invocation is one line again.
#
# WHY the format-string interior is a bounded `.` and not `[^)]` or `[^"]`: `println!(r"span) at
# {doc_text}")` puts a `)` inside a raw string and `[^)]*` stops dead at it. Raw strings in both
# the r"..." and r#"..."# forms therefore need no special case - there is nothing to escape past.
# ---------------------------------------------------------------------------
joined_lines="$(printf '%s\n' "$code_lines" | awk '
  {
    line = $0
    n = length(line)
    for (i = 1; i <= n; i++) {
      c = substr(line, i, 1)
      if (instr) {
        if (c == "\\") { i++; continue }
        if (c == "\"") instr = 0
        continue
      }
      if (c == "\"") { instr = 1; continue }
      if (c == "(" || c == "[") depth++
      else if (c == ")" || c == "]") { if (depth > 0) depth-- }
    }
    printf "%s", line
    if (depth > 0) printf " "; else printf "\n"
  }
  END { printf "\n" }' || true)"

SENS='(text|doc|note|snippet|input|phi|patient|narrative|raw)'
# WHY the benign suffix list: doc_id, span_len and text_hash are metadata, not the text itself,
# and I4 explicitly permits offsets and types in logs.
BENIGN='_(id|ids|len|count|hash|sha|idx|index|path|type|kind|url|name|dir|file|ext|size|offset|start|end|label|sha256)$'

# WHY macro names are spelled WITHOUT the `!` and joined by an optional-whitespace `BANG`:
# `println ! ("{doc_text}")` and `tracing :: error ! ("{doc_text}")` are both accepted by rustc,
# and a pattern that assumed the punctuation was glued together waved both straight through.
SP='[[:space:]]*'
BANG="${SP}!${SP}"
MACRO_NAME='format|eprintln|println|print|panic|write|writeln|dbg|todo|unimplemented'
CALL="((${MACRO_NAME})${BANG}|\.expect${SP}|unwrap_or_else${SP})\("
LOG_PATH="(tracing|log|slog|defmt)${SP}::${SP}(event${SP}::${SP})?(error|warn|warning|info|debug|trace)${BANG}\("
ARG='.{0,240}'
IDENT="&?[a-z_.]*${SENS}[a-z_]*"

leak_patterns=(
  # Rust macros with an inline `{ident}` capture.
  "${CALL}${ARG}\{[a-z_]*${SENS}[a-z_]*[}:]"
  # Positional arguments. WHY the run-up to the comma is unconstrained: the previous shape
  # anchored the identifier to the FIRST comma only, so `println!("{} {}", count, doc_text)` -
  # positional formatting, the default in any line with more than one value - was allowed.
  # Every argument after the format string is now checked, not just the first.
  "${CALL}${ARG},${SP}${IDENT}[[:space:],)]"
  # dbg!(&doc_text) has no format string at all, so it needs its own shape.
  "dbg${BANG}\(${SP}${IDENT}"
  # The Rust logging FAMILY, path form: tracing::error!, log::warn!, slog, defmt.
  "${LOG_PATH}${ARG}\{[a-z_.]*${SENS}[a-z_]*[}:]"
  "${LOG_PATH}${ARG},${SP}${IDENT}[[:space:],)]"
  # thiserror / anyhow attribute macros. An error Display string reaches stderr, a log
  # aggregator and a bug-report attachment, which is three copies of a patient name.
  "#\[(error|source|context)\(\"${ARG}\{[a-z_.]*${SENS}[a-z_]*"
  "(anyhow!|bail!|ensure!)\(${ARG}\{[a-z_.]*${SENS}[a-z_]*[}:]"
  # Python: dot-notation loggers, print(f""), raised exceptions.
  "(logging|log|logger|self\.log|_log)\.(error|warning|warn|info|debug|critical|exception)\(${SP}f?[\"'][^\"']*\{[a-z_.]*${SENS}[a-z_]*"
  "print\(${SP}f[\"'][^\"']*\{[a-z_.]*${SENS}[a-z_]*"
  "(raise|Exception|ValueError|RuntimeError)${ARG}f[\"'][^\"']*\{[a-z_.]*${SENS}[a-z_]*"
)

for p in "${leak_patterns[@]}"; do
  hits="$(printf '%s\n' "$joined_lines" | grep -oiE "$p" || true)"
  [ -n "$hits" ] || continue
  # Narrow the hit to the bare identifier so the benign-suffix filter judges the variable,
  # not the surrounding macro call.
  idents="$(printf '%s\n' "$hits" | grep -oiE "[a-z_.]*${SENS}[a-z_]*" || true)"
  real="$(printf '%s\n' "$idents" | grep -viE "$BENIGN" | grep -vE '^[[:space:]]*$' || true)"
  if [ -n "$real" ]; then
    block "I4 feedback-on-a-miss-is-PHI" \
          "$p" \
          'never interpolate document text into a log, error or panic. Error messages are the classic PHI leak: the message reaches stderr, then a log aggregator, then a bug report attachment, and the patient name is now in three systems. Log byte offsets, entity labels and counts instead, and carry the text only in memory.'
  fi
done

# ---------------------------------------------------------------------------
# I4, type level - an error type that can HOLD text will eventually PRINT text.
#
# Error types in this codebase carry byte offsets, lengths and entity labels. A String field is
# the structural precondition for a leak, so it is rejected at the type definition rather than
# at the hundred call sites that might later format it.
#
# Two triggers, both deliberately narrow to stay quiet on ordinary work:
#   1. any file under core/src/ named error.rs, and
#   2. any #[derive(..., Error, ...)] block, wherever it lives.
# ---------------------------------------------------------------------------
string_field=':[[:space:]]*String[[:space:],}]|:[[:space:]]*String$|\(String\)|\([[:space:]]*String[[:space:]]*[,)]'
err_advice='error types carry offsets, lengths and entity labels - never text. A String field on an error is the structural precondition for a PHI leak: whatever can be stored will eventually be Displayed into a log. Store `start: usize`, `end: usize`, `label: EntityLabel` and a `text_hash`, and let the caller re-slice the original document in memory if it needs the span.'

if printf '%s' "$file_path" | grep -qE '(^|/)core/src/([^ ]*/)?error\.rs$'; then
  if printf '%s\n' "$code_lines" | grep -qE "$string_field"; then
    block "I4 error-types-carry-offsets-not-text" \
          "String field in core/src/**/error.rs" \
          "$err_advice"
  fi
fi

derive_error_hit="$(printf '%s\n' "$code_lines" | awk -v pat="$string_field" '
  /#\[derive\(/ && /Error/ { pending = 1; next }
  pending && /^[[:space:]]*\}/ { pending = 0; next }
  pending {
    if ($0 ~ /:[[:space:]]*String[[:space:],}]/ || $0 ~ /:[[:space:]]*String$/ || $0 ~ /\(String\)/ || $0 ~ /\([[:space:]]*String[[:space:]]*[,)]/) {
      print "HIT"
    }
  }
' || true)"
if [ -n "$derive_error_hit" ]; then
  block "I4 error-types-carry-offsets-not-text" \
        "String field inside a #[derive(.., Error, ..)] type" \
        "$err_advice"
fi

# ---------------------------------------------------------------------------
# I1 - core/ has no network dependency, and neither does the workspace root manifest.
#
# WHY the scope is every file under core/ and not just core/Cargo.toml: a manifest-only check
# meant `use reqwest::Client;` in core/src/pipeline.rs and `use std::net::TcpStream;` anywhere
# in the crate both passed. The invariant is "core/ is structurally incapable of sending PHI
# anywhere", which is a property of the source, not of one file.
# ---------------------------------------------------------------------------
in_core=0
printf '%s' "$file_path" | grep -qE '(^|/)core/' && in_core=1
root_manifest=0
if printf '%s' "$file_path" | grep -qE '(^|/)Cargo\.toml$' && ! printf '%s' "$file_path" | grep -qE '(^|/)bindings/'; then
  root_manifest=1
fi

if [ "$in_core" -eq 1 ] || [ "$root_manifest" -eq 1 ]; then
  # WHY this list is explicitly NOT the guarantee: it is a name enumeration, and an enumeration
  # covers only the clients someone thought of. minreq, ehttp, async-std and smol are all real,
  # all open sockets, and all sailed into core/ past the previous list; `hyper-util` sailed past
  # it a second way, by being "hyper" plus a hyphen the word boundary treated as a terminator.
  # Both holes are patched below, and both will reopen the day a new client is published.
  #
  # The REAL gate is `just core-no-socket`, which reads the RESOLVED dependency graph out of
  # cargo rather than guessing from names, and is wired into `just check`. Treat this hook as a
  # speed bump that gives fast feedback at edit time, and the resolved-graph check as the wall.
  net_crate='reqwest|ureq|hyper|tonic|isahc|curl|surf|attohttpc|awc|minreq|ehttp|http[_-]req|async[_-]std|smol|tungstenite|quinn|socket2|mio|websocket|actix[_-]web|axum|warp|rocket|tiny[_-]http|trust[_-]dns|hickory[_-]dns'
  # WHY the trailing `[a-z0-9_-]*`: `hyper-util = "0.1"` is the hyper HTTP stack, and a pattern
  # that stopped at the word boundary read the `-` as "different crate" and allowed it. Cargo
  # ecosystems name companion crates by suffix, so the suffix is part of the name, not a break.
  crate_tail='[a-z0-9_-]*'
  http_dep="^[[:space:]]*(${net_crate})${crate_tail}[[:space:]]*=|\"(${net_crate})${crate_tail}\"[[:space:]]*[,:=]"
  http_use="(^|[^a-zA-Z0-9_])(${net_crate})${crate_tail}::|use[[:space:]]+(${net_crate})${crate_tail}([^a-zA-Z0-9_]|$)|extern[[:space:]]+crate[[:space:]]+(${net_crate})${crate_tail}"
  socket_use='std::net::(TcpStream|TcpListener|UdpSocket)|use[[:space:]]+std::net::|socket2::|(^|[^a-zA-Z0-9_])(TcpStream|TcpListener|UdpSocket)::'
  if printf '%s\n' "$code_lines" | grep -qE "$http_dep" \
     || printf '%s\n' "$code_lines" | grep -qE "$http_use" \
     || printf '%s\n' "$code_lines" | grep -qE "$socket_use"; then
    block "I1 PHI-never-leaves-the-device" \
          "${http_dep} | ${http_use} | ${socket_use}" \
          'core/ must not depend on, import, or open a network connection. core/ is pure: rules, checksums, span algebra, surrogates, audit. Put any I/O in bindings/, behind a trait that core/ defines. The workspace root manifest is covered too, because a root dependency is a dependency of core/.'
  fi
fi

exit 0
