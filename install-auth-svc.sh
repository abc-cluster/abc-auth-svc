#!/usr/bin/env bash
# install-auth-svc.sh — Install abc-auth-svc on aither
#
# Run ON aither as root or with sudo.
# Idempotent: safe to re-run on updates.
#
# What it does:
#   1. Installs Python build deps (for boto3 pycurl if needed)
#   2. Creates /opt/abc-auth-svc/ with a Python venv
#   3. Installs boto3 into the venv
#   4. Copies abc-auth-svc.py to /opt/abc-auth-svc/
#   5. Generates SESSION_SECRET in /etc/abc-auth-svc/session_secret (if absent)
#
# Usage:
#   scp auth/abc-auth-svc.py sun-aither:/tmp/abc-auth-svc.py
#   scp auth/scripts/install-auth-svc.sh sun-aither:/tmp/install-auth-svc.sh
#   ssh sun-aither "sudo bash /tmp/install-auth-svc.sh"

set -euo pipefail

SVC_DIR="/opt/abc-auth-svc"
VENV="${SVC_DIR}/venv"
SECRET_DIR="/etc/abc-auth-svc"
SECRET_FILE="${SECRET_DIR}/session_secret"
SRC="${1:-/tmp/abc-auth-svc.py}"

echo "[1/4] Installing Python deps..."
apt-get install -y --quiet python3-venv

echo "[2/4] Setting up venv at ${VENV}..."
mkdir -p "${SVC_DIR}"
if [ ! -d "${VENV}" ]; then
  python3 -m venv "${VENV}"
fi
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet boto3

echo "[3/4] Installing service script..."
if [ ! -f "${SRC}" ]; then
  echo "  ERROR: ${SRC} not found. Copy abc-auth-svc.py to aither first." >&2
  exit 1
fi
# Drift detection (added 2026-06-09; ref project_authsvc_deploy_drift memory).
# The recurring symptom of the drift was: someone edits /opt/abc-auth-svc/
# abc-auth-svc.py in place to land a hotfix, the repo lags, a later release of
# the install script silently overwrites the hotfix and reintroduces the bug.
# Surface drift loudly before overwriting + timestamp-backup so it's recoverable.
LIVE="${SVC_DIR}/abc-auth-svc.py"
if [ -f "${LIVE}" ]; then
  LIVE_MD5=$(md5sum "${LIVE}" | awk '{print $1}')
  SRC_MD5=$(md5sum "${SRC}"  | awk '{print $1}')
  if [ "${LIVE_MD5}" = "${SRC_MD5}" ]; then
    echo "  Live ≡ source (md5 ${SRC_MD5:0:8}…) — reinstalling for idempotency."
  else
    BAK="${SVC_DIR}/abc-auth-svc.py.bak.$(date +%s)"
    cp "${LIVE}" "${BAK}"
    echo "  DRIFT detected — live md5 ${LIVE_MD5:0:8}… ≠ source md5 ${SRC_MD5:0:8}…"
    echo "  Backed up live → ${BAK}"
    echo "  (See ~/.claude/.../project_authsvc_deploy_drift.md — drift is the recurring symptom.)"
  fi
fi
cp "${SRC}" "${LIVE}"
chmod 644 "${LIVE}"
# Verify the install round-tripped byte-identical — defends against partial
# writes / disk-full / suid-strip edge cases. Fail loud if not.
if ! diff -q "${SRC}" "${LIVE}" > /dev/null; then
  echo "  FAIL: ${LIVE} does not match ${SRC} after install" >&2
  exit 1
fi
echo "  Installed: ${LIVE}  (md5 $(md5sum "${LIVE}" | awk '{print $1}' | cut -c1-8)…)"

echo "[4/4] Generating session secret..."
mkdir -p "${SECRET_DIR}"
chmod 700 "${SECRET_DIR}"
if [ ! -f "${SECRET_FILE}" ]; then
  python3 -c "import secrets; print(secrets.token_hex(32))" > "${SECRET_FILE}"
  chmod 600 "${SECRET_FILE}"
  echo "  Generated: ${SECRET_FILE}"
else
  echo "  Exists:    ${SECRET_FILE} (not overwritten)"
fi

echo ""
echo "=== Install complete ==="
echo "  Service script: ${SVC_DIR}/abc-auth-svc.py"
echo "  Python venv:    ${VENV}"
echo "  Session secret: ${SECRET_FILE}"
echo ""
echo "Next steps:"
echo "  1. Add SESSION_SECRET to the Nomad job:"
echo "       sudo cat ${SECRET_FILE}"
echo "       # Copy the output into abc-auth-svc.nomad.hcl env.SESSION_SECRET"
echo "  2. Submit the Nomad job:"
echo "       nomad job run auth/abc-auth-svc.nomad.hcl"
echo "  3. Verify:"
echo "       curl -s http://127.0.0.1:8085/auth/health"
