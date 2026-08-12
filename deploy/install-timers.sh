#!/usr/bin/env bash
# Install MCPWatch's systemd *user* timers on the collection host.
#
# User units, not system units: `sudo` on this box needs a password, and
# `Linger=yes` is already enabled for the account so user timers survive logout
# and reboot without it. Idempotent — safe to re-run after every deploy.
set -euo pipefail

UNIT_DIR="${HOME}/.config/systemd/user"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/systemd" && pwd)"

mkdir -p "${UNIT_DIR}"
install -m 0644 "${SRC_DIR}"/mcpwatch-*.service "${SRC_DIR}"/mcpwatch-*.timer "${UNIT_DIR}/"

systemctl --user daemon-reload
systemctl --user enable --now \
    mcpwatch-registry-incremental.timer \
    mcpwatch-registry-full.timer \
    mcpwatch-manifest.timer \
    mcpwatch-backup.timer \
    mcpwatch-health.timer

# mcpwatch-sandbox.timer is installed above but deliberately NOT enabled.
#
# It is the only unit that executes untrusted third-party code, and it should
# not start running unattended on the strength of a passing test suite. Enable
# it once a full cycle has been watched end to end:
#
#     systemctl --user enable --now mcpwatch-sandbox.timer
#
# The cycle re-verifies containment before every run and refuses to start if any
# property fails, so enabling it is not a standing grant — but the decision to
# let it run nightly is a deliberate one, and it belongs to a person.

echo
echo "Installed. Next runs:"
systemctl --user list-timers 'mcpwatch-*' --no-pager

cat <<'NOTE'

Linger must be on for these to fire without an active login:
    loginctl show-user "$USER" --property=Linger

Useful commands:
    systemctl --user list-timers 'mcpwatch-*'
    systemctl --user start mcpwatch-manifest.service      # run one now
    systemctl --user start mcpwatch-backfill.service      # WP5, one-shot, no timer
    uv run python -m mcpwatch.sandbox verify               # WP8 containment gate
    systemctl --user start mcpwatch-sandbox.service        # WP8, one cycle now
    journalctl --user -u mcpwatch-manifest.service -n 50  # last run's output
    systemctl --user list-units --failed                  # a failed health check shows here
    uv run python -m mcpwatch.health                      # check right now
    uv run python -m mcpwatch.backup --verify-only        # is the backup sound?
    uv run python -m mcpwatch.backup --restore-to /tmp/rehearsal   # restore drill
NOTE
