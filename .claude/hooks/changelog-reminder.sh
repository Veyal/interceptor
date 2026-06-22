#!/usr/bin/env bash
# Stop hook — remind to update CHANGELOG.md when project files changed without a changelog entry.
#
# Design notes:
#   * ALWAYS exits 0. Blocking the stop happens ONLY via a JSON {"decision":"block"} payload,
#     so a bug or unexpected error can never trap the session (a non-zero exit could).
#   * Honors stop_hook_active to avoid infinite Stop loops.
#   * A touched CHANGELOG.md counts as "logged" — the hook then stays quiet.

input="$(cat 2>/dev/null || true)"

# Already continuing from a previous Stop-hook block this turn -> let it stop.
case "$input" in
  *'"stop_hook_active":true'* | *'"stop_hook_active": true'*) exit 0 ;;
esac

cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

status="$(git status --porcelain 2>/dev/null || true)"
[ -n "$status" ] || exit 0

# Strip the 3-char porcelain status prefix to get paths (handles spaces in names).
paths="$(printf '%s\n' "$status" | cut -c4-)"

# CHANGELOG.md already touched -> nothing to nag about.
printf '%s\n' "$paths" | grep -qxF 'CHANGELOG.md' && exit 0

# Any real project changes? Exclude tooling/meta files.
project="$(printf '%s\n' "$paths" | grep -vxE '(\.claude(/.*)?|\.gitignore|\.DS_Store|CHANGELOG\.md)' || true)"
[ -n "$project" ] || exit 0

reason="Project files changed but CHANGELOG.md was not updated. Per this project's changelog policy (see CLAUDE.md), add an entry under ## [Unreleased] in CHANGELOG.md summarizing what changed (group under Added / Changed / Fixed / Removed), then finish."
printf '{"decision":"block","reason":"%s"}\n' "$reason"
exit 0
