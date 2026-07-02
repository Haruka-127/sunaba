#!/usr/bin/env bash
set -euo pipefail

: "${SUNABA_UID:?SUNABA_UID is required}"
: "${SUNABA_GID:?SUNABA_GID is required}"
: "${SUNABA_WORKDIR:?SUNABA_WORKDIR is required}"
: "${OPENCODE_SERVER_PASSWORD:?OPENCODE_SERVER_PASSWORD is required}"

if ! getent group agent >/dev/null 2>&1; then
  groupadd -g "$SUNABA_GID" agent 2>/dev/null || groupadd agent
fi

if ! id agent >/dev/null 2>&1; then
  useradd -m -u "$SUNABA_UID" -g agent -s /bin/bash agent 2>/dev/null || useradd -m -g agent -s /bin/bash agent
fi

printf 'agent ALL=(ALL) NOPASSWD:ALL\n' >/etc/sudoers.d/sunaba
chmod 0440 /etc/sudoers.d/sunaba

mkdir -p /home/agent/.local/share /home/agent/.config /home/agent/.cache
chown agent:agent /home/agent /home/agent/.cache 2>/dev/null || true
chown -R agent:agent /home/agent/.local /home/agent/.config 2>/dev/null || true

cd "$SUNABA_WORKDIR"
exec sudo -E -H -u agent opencode serve --hostname 0.0.0.0 --port 4096
