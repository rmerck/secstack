#!/usr/bin/env bash
# check-secrets.sh: blocks commits and pushes that would put secrets, engagement data (client names,
# past targets) or live scope addresses into this repo. The checks are in scripts/check_secrets.py.
#
# install.sh installs a small wrapper as the pre-commit, pre-merge-commit, pre-applypatch, commit-msg,
# applypatch-msg and pre-push hooks; each runs this script with --hook <name>. By hand:
#   scripts/check-secrets.sh          what is staged
#   scripts/check-secrets.sh --all    every tracked and untracked (not ignored) file as it is on disk
# Live scope and the deny-list come from the runtime root: $SECOPS, else `git config secstack.secops`,
# else ~/GitHub/.sec-ops. Findings show paths, line numbers and key names, never the values.
# It fails closed: without python3, a readable runtime root or readable content, it refuses.
set -u
src="${BASH_SOURCE[0]}"
while [ -L "$src" ]; do   # find check_secrets.py next to the real file, even through a link
  dir="$(cd -P "$(dirname "$src")" && pwd -P)"; src="$(readlink "$src")"
  case "$src" in /*) ;; *) src="$dir/$src" ;; esac
done
here="$(cd -P "$(dirname "$src")" && pwd -P)" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "check-secrets: python3 not found, so nothing can be checked; refusing. Install the Xcode command line tools (xcode-select --install), or use --no-verify after checking by hand." >&2
  exit 1
fi
case "$(basename "$0")" in   # run directly as a hook (a link named after it)
  pre-commit|pre-merge-commit|pre-applypatch|commit-msg|applypatch-msg|pre-push)
    exec python3 -I "$here/check_secrets.py" --hook "$(basename "$0")" "$@" ;;
esac
exec python3 -I "$here/check_secrets.py" "$@"
