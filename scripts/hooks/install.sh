#!/usr/bin/env bash
# Installs the PHI pre-commit hook into this clone.
#
# WHY this is a script and not a README step: .git/hooks is not versioned, so every clone starts
# unprotected. `just install-hooks` is the first thing a new contributor runs.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source_hook="${repo_root}/scripts/hooks/pre_commit_phi.sh"
hooks_dir="${repo_root}/.git/hooks"
target_hook="${hooks_dir}/pre-commit"

if [ ! -f "$source_hook" ]; then
  printf 'install.sh: cannot find %s\n' "$source_hook" >&2
  exit 1
fi

mkdir -p "$hooks_dir"
chmod +x "$source_hook"

if [ -e "$target_hook" ] || [ -L "$target_hook" ]; then
  backup="${target_hook}.backup.$(date +%Y%m%d%H%M%S)"
  mv "$target_hook" "$backup"
  printf 'install.sh: existing pre-commit hook moved to %s\n' "$backup"
fi

# Symlink so edits to the versioned script take effect immediately; copy where symlinks are
# unavailable, at the cost of needing a re-run after each edit.
if ln -s "../../scripts/hooks/pre_commit_phi.sh" "$target_hook" 2>/dev/null; then
  method="symlink"
else
  cp "$source_hook" "$target_hook"
  method="copy"
fi

chmod +x "$target_hook"

printf 'install.sh: pre-commit hook installed (%s)\n' "$method"
printf '  source : %s\n' "$source_hook"
printf '  target : %s\n' "$target_hook"
printf '  guards : checksum-valid TCKN (I8), licensed corpora (n2c2/MIMIC/i2b2/TEHR), .env and secrets\n'
if [ "$method" = "copy" ]; then
  printf '  note   : this clone got a COPY. Re-run install.sh after editing pre_commit_phi.sh.\n'
fi
