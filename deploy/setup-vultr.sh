#!/usr/bin/env bash
# Provision a fresh Vultr Cloud Compute VM (Ubuntu 22.04/24.04) to run
# Detonation Chamber end to end: Docker + gVisor for the sandbox, Node/Python/Git
# for host-side artifact fetch, and the FastAPI app as a systemd service.
#
# Usage (as root, from the repo root on the VM):
#   sudo bash deploy/setup-vultr.sh
#
# Then open http://<your-vultr-ip>:8000
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_USER="${SUDO_USER:-root}"
PORT="${DC_PORT:-8000}"

echo "==> Detonation Chamber setup (repo: $REPO_DIR)"

echo "==> Installing base packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg git strace python3 python3-venv python3-pip

echo "==> Installing Docker"
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
fi
systemctl enable --now docker

echo "==> Installing Node.js 20 (host-side npm pack)"
if ! command -v npm >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

echo "==> Installing gVisor (runsc) for kernel-level sandbox isolation"
if ! command -v runsc >/dev/null 2>&1; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y
  apt-get install -y runsc || echo "!! gVisor install failed; app will fall back to runc (still contained by --network none)"
fi
if command -v runsc >/dev/null 2>&1; then
  runsc install || true          # registers the runsc runtime with Docker
  systemctl restart docker
fi

echo "==> Building the sandbox image"
docker build -t dc-sandbox:latest "$REPO_DIR/sandbox"

echo "==> Creating Python virtualenv and installing the app"
python3 -m venv "$REPO_DIR/.venv"
"$REPO_DIR/.venv/bin/pip" install -q --upgrade pip
"$REPO_DIR/.venv/bin/pip" install -q -r "$REPO_DIR/requirements.txt"

ENV_FILE="$REPO_DIR/.env"
[ -f "$ENV_FILE" ] || cp "$REPO_DIR/deploy/.env.example" "$ENV_FILE"

echo "==> Installing systemd service"
cat > /etc/systemd/system/detonation-chamber.service <<EOF
[Unit]
Description=Detonation Chamber
After=docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=$REPO_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$REPO_DIR/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PORT
Restart=on-failure
# The app shells out to docker, npm, pip and git on the host.

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now detonation-chamber

# The Vultr Ubuntu image ships with ufw active (SSH only); open the app port.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q active; then
  ufw allow "${PORT}/tcp" || true
  ufw reload || true
fi

IP=$(curl -fsS https://ipinfo.io/ip 2>/dev/null || echo "<your-vultr-ip>")
echo ""
echo "============================================================"
echo " Detonation Chamber is live:  http://$IP:$PORT"
echo " Runtime: $(command -v runsc >/dev/null 2>&1 && echo 'gVisor (runsc)' || echo 'runc')"
echo " Set VULTR_INFERENCE_API_KEY in $ENV_FILE then:"
echo "   systemctl restart detonation-chamber"
echo " Logs:   journalctl -u detonation-chamber -f"
echo "============================================================"
