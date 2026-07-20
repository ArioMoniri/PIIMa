#!/usr/bin/env bash
# git pre-commit hook body. Installed by scripts/hooks/install.sh, verified by `just verify-hooks`.
#
# WHY: git history is effectively permanent. A patient identifier committed once survives
# deletion, rebase-and-force-push and repository transfer, and it is world-readable the moment
# the repo goes public. This is the last mechanical checkpoint before that becomes irreversible.
#
# Exit non-zero to abort the commit. Reports file and LINE NUMBER only, never the digits.
#
# `--scan-stdin` runs the content scanners over stdin instead of the git index, so the scanning
# logic is testable by scripts/hooks/test_hooks.sh without constructing a throwaway repository.
set -euo pipefail

fail=0

note_failure() {
  fail=1
  printf 'COMMIT BLOCKED [%s]\n' "$1" >&2
  printf '  %s\n' "$2" >&2
}

secret_pattern='AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{30,}|(api[_-]?key|secret|password|passwd|token)[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{12,}["'"'"']'

# ---------------------------------------------------------------------------
# I8 - TCKN checksum scan.
#
# WHY checksum rather than "11 digits": clinical text and code are full of 11-digit numbers that
# are not national IDs (timestamps, accession numbers, phone strings). Only a checksum-VALID
# sequence could be a real person's TCKN, so only that blocks - which keeps the hook usable and
# keeps deliberately-invalid synthetic fixtures committable.
#
# WHY a SLIDING WINDOW and not maximal digit runs: the previous version pulled out the longest
# digit run on a line and skipped it unless its length was exactly 11. That meant every failure
# mode the spec names - an ID suffixed (`12345678901'in` is fine, but `1234567890123` is not),
# an ID glued inside a longer number, an ID glued inside a word - evaded the hook entirely. Now
# every 11-digit window of every digit run of length >= 11 is checksummed.
#
# WHY every exclusion below is TOKEN-scoped and none is LINE-scoped: a line-scoped exclusion is a
# kill switch on the whole record. eval/gold/*.jsonl carries ONE CLINICAL NOTE PER LINE, averaging
# ~3000 characters, so `if (line ~ /UUID/) next` meant a single UUID anywhere on a line - a doc_id,
# a run id, a span id - stopped the TCKN scan for that entire note, and a checksum-valid national
# ID sharing the line was accepted. The same held for `checksum = "<valid TCKN>"`. No fixture
# carries a UUID today, which is exactly what made it dangerous: migrating doc_id to UUIDs would
# have silently disabled TCKN scanning across the whole gold set with no test going red. The
# matched digest or UUID is now blanked out of the line and scanning continues over the rest.
#
# RESIDUAL RISK, documented rather than hidden: sliding over long digit runs raises the false
# positive rate, because ~1 in 100 random 11-digit windows is checksum-valid and a 64-character
# hash contains 54 windows. Three narrow token exclusions keep that usable:
#   1. the value of a lockfile / integrity key (`checksum = "..."`, sha256/sha512/integrity),
#   2. alnum tokens that are entirely hexadecimal and at least 16 characters long, and
#   3. the UUID itself, wherever it appears on the line.
# What this still costs: a >=16-character token of pure DECIMAL digits is treated as hex and
# skipped, so a TCKN embedded in a 16+ digit run is missed. That is the deliberate trade - it is
# the only shape where a hash and an identifier are indistinguishable, and I2 says prefer the
# false positive, but a hook noisy enough to be bypassed protects nothing. If this ever needs
# tightening, tighten (2) before (1).
# ---------------------------------------------------------------------------
tckn_awk='
function is_hex_token(t) {
  return (length(t) >= 16 && t ~ /^[0-9a-fA-F]+$/)
}
{
  rest = $0
  # Exclusion 3: UUIDs. Their 4-character groups are short enough to dodge the hex-token length
  # rule, so each UUID is blanked - and only the UUID, never the line around it.
  while (match(rest, /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/)) {
    rest = substr(rest, 1, RSTART - 1) " " substr(rest, RSTART + RLENGTH)
  }
  # Exclusion 1: the VALUE of a lockfile or integrity key. Content-addressed by construction and
  # never a person - but only the value is dropped, so anything else on the line still gets read.
  while (match(rest, /(checksum|integrity|hash|digest|sha256|sha512|sha1|blake3|md5)[[:space:]]*[-:=][[:space:]]*"?[0-9a-zA-Z]+"?/)) {
    rest = substr(rest, 1, RSTART - 1) " " substr(rest, RSTART + RLENGTH)
  }
  # Exclusion 4: the FRACTIONAL PART of a decimal number. The sliding window reads every 11-digit
  # substring of a longer run, so a float mantissa is a lottery ticket: 0.8859259259259259 contains
  # an 11-digit window that satisfies the TCKN checksum, and eval result artifacts are full of
  # them. Two such windows blocked a real commit of eval/results/*.json.
  #
  # Narrow on purpose - only digits following a '.' that itself follows a digit, i.e. the tail of
  # a number like 0.885..., never a bare or quoted 11-digit field. A TCKN written as JSON is
  # either a quoted string or a bare 11-digit number, and both still get read in full.
  while (match(rest, /[0-9]\.[0-9]+/)) {
    keep = substr(rest, RSTART, 1)
    rest = substr(rest, 1, RSTART - 1) keep " " substr(rest, RSTART + RLENGTH)
  }

  while (match(rest, /[0-9A-Za-z]+/)) {
    token = substr(rest, RSTART, RLENGTH)
    rest = substr(rest, RSTART + RLENGTH)
    # Exclusion 2a: long pure-hex tokens are digests, not identifiers.
    if (is_hex_token(token)) continue

    inner = token
    while (match(inner, /[0-9]+/)) {
      run = substr(inner, RSTART, RLENGTH)
      inner = substr(inner, RSTART + RLENGTH)
      n = length(run)
      if (n < 11) continue
      for (w = 1; w <= n - 10; w++) {
        cand = substr(run, w, 11)
        split("", d)
        for (i = 1; i <= 11; i++) d[i] = substr(cand, i, 1) + 0
        if (d[1] == 0) continue
        odd  = d[1] + d[3] + d[5] + d[7] + d[9]
        even = d[2] + d[4] + d[6] + d[8]
        c10 = ((odd * 7 - even) % 10 + 10) % 10
        if (d[10] != c10) continue
        sum = 0
        for (i = 1; i <= 10; i++) sum += d[i]
        if (d[11] != (sum % 10)) continue
        print FILENAME_LABEL ":" NR
        # One report per line is enough: the location is the actionable part, and a long run
        # would otherwise print the same line dozens of times.
        next
      }
    }
  }
}
'

# ---------------------------------------------------------------------------
# Testing entry point. Scans stdin and exits 1 on any finding, 0 otherwise.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--scan-stdin" ]; then
  buf="$(cat)"
  label="${2:-<stdin>}"
  hits="$(printf '%s\n' "$buf" | awk -v FILENAME_LABEL="$label" "$tckn_awk" || true)"
  sec="$(printf '%s\n' "$buf" | grep -nEi "$secret_pattern" | cut -d: -f1 || true)"
  if [ -n "${hits//[$'\n' ]/}" ]; then
    printf 'SCAN: checksum-valid TCKN at %s\n' "$(printf '%s' "$hits" | tr '\n' ' ')" >&2
    exit 1
  fi
  if [ -n "$sec" ]; then
    printf 'SCAN: credential-shaped content at line(s) %s\n' "$(printf '%s' "$sec" | tr '\n' ' ')" >&2
    exit 1
  fi
  exit 0
fi

# Only added/copied/modified paths matter; deletions cannot introduce content.
staged="$(git diff --cached --name-only --diff-filter=ACM)"

if [ -z "$staged" ]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# I8 - licensed corpora never enter the repository.
# ---------------------------------------------------------------------------
corpus_hits="$(printf '%s\n' "$staged" | grep -iE '(^|/)(n2c2|mimic|i2b2|tehr)(/|$)|\.dua$|(n2c2|mimic|i2b2|tehr)[^/]*\.(txt|jsonl|json|csv|xml|zip)$' || true)"
if [ -n "$corpus_hits" ]; then
  note_failure "I8 licensed-corpus" "the following staged paths look like licensed corpus data (n2c2 / MIMIC / i2b2 / TEHR / DUA):"
  printf '%s\n' "$corpus_hits" | sed 's/^/    /' >&2
  printf '  These are used under a Data Use Agreement and must never be committed.\n' >&2
  printf '  do instead: keep the corpus outside the repo; commit only synthetic derived fixtures.\n' >&2
fi

# ---------------------------------------------------------------------------
# Secrets.
# ---------------------------------------------------------------------------
env_hits="$(printf '%s\n' "$staged" | grep -E '(^|/)\.env($|\.)' || true)"
if [ -n "$env_hits" ]; then
  note_failure "SECRET dotenv" "a .env file is staged:"
  printf '%s\n' "$env_hits" | sed 's/^/    /' >&2
  printf '  do instead: keep secrets in your shell environment or a secret manager; commit a .env.example with empty values.\n' >&2
fi

# ---------------------------------------------------------------------------
# I1 - core/ manifests carry no network dependency.
#
# This is the check that core/Cargo.toml's header comment refers to. It greps the STAGED
# manifest, not the working tree, because the staged blob is what is about to become permanent.
# ---------------------------------------------------------------------------
net_crate='reqwest|ureq|hyper|tonic|isahc|surf|curl|attohttpc|awc'
for manifest in $(printf '%s\n' "$staged" | grep -E '(^|/)core/[^/]*Cargo\.toml$' || true); do
  dep_hits="$(git show ":$manifest" 2>/dev/null \
    | grep -nE "^[[:space:]]*(${net_crate})[[:space:]]*=|\"(${net_crate})\"[[:space:]]*[,:=]" \
    | cut -d: -f1 || true)"
  if [ -n "$dep_hits" ]; then
    note_failure "I1 core-has-no-network-dependency" \
      "$manifest declares an HTTP client dependency at line(s): $(printf '%s' "$dep_hits" | tr '\n' ' ')"
    printf '  core/ must be structurally incapable of sending PHI anywhere. Put I/O in bindings/,\n' >&2
    printf '  behind a trait that core/ defines.\n' >&2
  fi
done

tckn_report=""
for path in $staged; do
  # Skip binaries: a checksum hit inside compressed bytes is noise, not PHI.
  if ! git show ":$path" 2>/dev/null | head -c 8000 | LC_ALL=C grep -Iq . 2>/dev/null; then
    continue
  fi
  hits="$(git show ":$path" 2>/dev/null | awk -v FILENAME_LABEL="$path" "$tckn_awk" || true)"
  if [ -n "$hits" ]; then
    tckn_report="${tckn_report}${hits}"$'\n'
  fi

  # The guards' own test corpus is exempt from the CREDENTIAL scan only. That file's
  # job is to contain one specimen of every pattern these hooks detect, so scanning it
  # makes the hooks untestable -- the suite cannot assert "a credential is blocked"
  # without holding a credential-shaped string.
  #
  # Deliberately narrow, because a blanket exemption is a place to hide a real secret:
  #   - one exact path, not a directory or a glob
  #   - the TCKN scan above still runs on it, because that is the invariant (I8) with a
  #     real person on the other end, and its test vectors are generated at runtime and
  #     are never checksum-valid on disk
  # Anything added to that file is reviewed as hook logic, not as application code.
  case "$path" in
    scripts/hooks/test_hooks.sh) ;;
    *)
      secret_hits="$(git show ":$path" 2>/dev/null | grep -nEi "$secret_pattern" | cut -d: -f1 || true)"
      if [ -n "$secret_hits" ]; then
        note_failure "SECRET pattern" "credential-shaped content in $path at line(s): $(printf '%s' "$secret_hits" | tr '\n' ' ')"
        printf '  do instead: move the value to the environment or a secret manager and commit a placeholder.\n' >&2
      fi
      ;;
  esac
done

if [ -n "${tckn_report//[$'\n' ]/}" ]; then
  note_failure "I8 checksum-valid-TCKN" "a checksum-VALID Turkish national ID (TCKN) is staged. It could belong to a real person."
  printf '  locations (file:line - digits deliberately not shown):\n' >&2
  printf '%s' "$tckn_report" | grep -vE '^[[:space:]]*$' | sort -u | sed 's/^/    /' >&2
  printf '  do instead: use a checksum-INVALID synthetic TCKN in fixtures - flip the last digit so d11\n' >&2
  printf '              no longer equals (d1+..+d10) mod 10. Real IDs never belong in this repo (I8).\n' >&2
fi

if [ "$fail" -ne 0 ]; then
  printf '\npre-commit refused the commit. Fix the items above, or re-run with --no-verify only if a\nhuman has reviewed every finding and confirmed none of it is real PHI.\n' >&2
  exit 1
fi

exit 0
