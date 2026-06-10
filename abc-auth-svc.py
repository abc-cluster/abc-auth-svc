#!/usr/bin/env python3
"""
abc-auth-svc — Unified forward authentication service for ABC Cluster.

Replaces both the old abc-forward-auth-svc (Nomad token validation, port 4181)
and the standalone MinIO session service, and absorbs abc-signup-svc's /claim
endpoint. Single service, single port, covering all ABC Cluster auth paths:

  Path 1 — Browser / workbench (MinIO credentials → session cookie):
    Validates pool user credentials against MinIO (access key + secret key).
    Issues HMAC-signed session cookies. Acts as Caddy's forward_auth endpoint
    so JupyterHub, Grafana, and other browser services share one login session.
    Checks PocketBase slot state after credential validation — suspended/expired
    slots are denied even if their MinIO credentials are still valid.

  Path 2 — API / upload portal (Nomad ACL token):
    Validates Nomad ACL tokens via /v1/acl/token/self.
    Returns X-Auth-User, X-Auth-Group, X-Auth-Namespace, X-Auth-Policies headers.
    Backward-compatible with abc-forward-auth-svc callers (same /verify + /healthz
    endpoints, same port 4181).

  Path 3 — Slot claiming:
    POST /slots/claim  — claims an unclaimed pool slot by claim_code, returns
    a complete config.yaml ready to drop in at ~/.abc/config.yaml.

  Path 4 — Operator lifecycle management:
    GET  /manage/slots              — list all slots (operator token required)
    GET  /manage/slots/:slot        — single slot record
    POST /manage/slots/:slot/rotate     — rotate MinIO + Nomad credentials
    POST /manage/slots/:slot/suspend    — disable slot (MinIO, Nomad, files)
    POST /manage/slots/:slot/reactivate — re-enable suspended slot

Endpoints:
  GET  /healthz        — liveness check (200 OK) — backward compat alias
  GET  /auth/health    — liveness check (200 OK)
  GET  /verify         — Nomad ACL token validation (X-Nomad-Token or Authorization: Bearer)
  GET  /validate          — Caddy forward_auth: 200 + user headers or 302 to /auth/login
  GET  /validate-optional — Like /validate but always 200; sets X-Auth-User only when
                            session is valid. Used by Grafana's Caddy proxy so that
                            unauthenticated visitors fall through to Grafana's own
                            [auth.anonymous] Viewer role instead of hitting the login form.
  GET  /auth/login     — HTML login form (MinIO credentials)
  POST /auth/login     — validate MinIO credentials, set session cookie, redirect
  GET  /auth/logout    — clear session cookie, redirect to /auth/login
  POST /slots/claim    — claim a pool slot; body: {claim_code, name, email}
  GET  /manage/slots   — list slots (X-Operator-Token required)
  GET  /manage/slots/:slot    — single slot
  POST /manage/slots/:slot/rotate
  POST /manage/slots/:slot/suspend
  POST /manage/slots/:slot/reactivate

Session cookie (browser path):
  Name:    abc_session
  Format:  base64url( "<username>:<expiry_unix>:<hmac_sha256>" )
  TTL:     7 days (configurable via SESSION_TTL_SECONDS env var)
  Flags:   HttpOnly; SameSite=Lax; Path=/; Secure (unless COOKIE_SECURE=false)

Environment:
  MINIO_ENDPOINT      — MinIO S3 endpoint (default: http://localhost:9000)
  NOMAD_ADDR          — Nomad API address (default: http://localhost:4646)
  NOMAD_TOKEN         — Nomad management token (for /manage/ credential operations)
  SESSION_SECRET      — HMAC signing key (required in production; auto-generated otherwise)
  AUTH_SVC_PORT       — listen port (default: 4181)
  AUTH_SVC_BIND       — bind address (default: 0.0.0.0)
  SESSION_TTL_SECONDS — session lifetime in seconds (default: 604800 = 7 days)
  POCKETBASE_URL       — PocketBase base URL (default: http://127.0.0.1:8091)
  PB_ADMIN_EMAIL       — PocketBase superuser email (default: abc-auth@internal)
  PB_ADMIN_PASSWORD    — PocketBase superuser password (required in production)
  OPERATOR_TOKEN       — Secret token for /manage/* endpoints (required in production)
  JUPYTERHUB_API_URL   — JupyterHub admin API base URL (default: http://127.0.0.1:8000/hub/api)
  JUPYTERHUB_API_TOKEN — JupyterHub admin API token (set in jupyterhub_config api_tokens)

Deploy: Nomad raw_exec service on aither, see abc-auth-svc.nomad.hcl.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, unquote, urlparse

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MINIO_ENDPOINT      = os.getenv("MINIO_ENDPOINT", "http://localhost:9000")
NOMAD_ADDR          = os.getenv("NOMAD_ADDR", "http://localhost:4646").rstrip("/")
NOMAD_TOKEN         = os.getenv("NOMAD_TOKEN", "")
AUTH_SVC_PORT       = int(os.getenv("AUTH_SVC_PORT", "4181"))
AUTH_SVC_BIND       = os.getenv("AUTH_SVC_BIND", "0.0.0.0")
SESSION_TTL_SECONDS  = int(os.getenv("SESSION_TTL_SECONDS", str(86400 * 7)))
SESSION_COOKIE_NAME  = "abc_session"
# COOKIE_DOMAIN: when set (e.g. ".seedling.abc-cluster.cloud"), the session cookie
# is shared across all subdomains in the family. Required for the Grafana auth proxy
# (grafana.seedling.*) to read a session set on workbench.seedling.*.
# Leave empty to scope the cookie to the exact host (old behaviour).
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", "")

# CLI_TOKEN_TTL: one-time magic link code lifetime in seconds (used by abc portal open).
CLI_TOKEN_TTL = int(os.getenv("CLI_TOKEN_TTL", "60"))

# COOKIE_SECURE: whether session + MinIO cookies carry the Secure attribute.
# Default true (TLS-fronted deployments). Set false ONLY for air-gapped /
# plain-HTTP LAN deployments where there is no TLS — browsers reject Secure
# cookies over http://, so workbench/grafana/upload/minio SSO would silently
# fail to persist a session. The air-gapped LAN is its own security boundary;
# dropping Secure there does not weaken a meaningful threat model.
# Accepts: true/false/1/0/yes/no (case-insensitive).
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").strip().lower() in ("true", "1", "yes")

POCKETBASE_URL    = os.getenv("POCKETBASE_URL", "http://127.0.0.1:8091").rstrip("/")
PB_ADMIN_EMAIL    = os.getenv("PB_ADMIN_EMAIL", "abc-auth@internal")
PB_ADMIN_PASSWORD = os.getenv("PB_ADMIN_PASSWORD", "")
OPERATOR_TOKEN    = os.getenv("OPERATOR_TOKEN", "")

# JupyterHub admin API — used to stop a user's server on slot suspension
JUPYTERHUB_API_URL   = os.getenv("JUPYTERHUB_API_URL",   "http://127.0.0.1:8000/hub/api")
JUPYTERHUB_API_TOKEN = os.getenv("JUPYTERHUB_API_TOKEN", "")

# Cluster-static values for config.yaml generation (same as abc-signup-svc)
CLUSTER_NOMAD_ENDPOINT  = os.getenv("CLUSTER_NOMAD_ENDPOINT",  "https://api.seedling.abc-cluster.cloud")
CLUSTER_MINIO_ENDPOINT  = os.getenv("CLUSTER_MINIO_ENDPOINT",  "https://s3.seedling.abc-cluster.cloud")
CLUSTER_UPLOAD_ENDPOINT = os.getenv("CLUSTER_UPLOAD_ENDPOINT", "https://upload.seedling.abc-cluster.cloud/files/")
# Public broker URL — stamped into seedling/v1 configs as `auth_endpoint` so
# the CLI doesn't have to derive it from CLUSTER_NOMAD_ENDPOINT (which only
# works when the broker happens to live at `auth.<rest>`; on seedling it
# actually lives at `workbench.<rest>` behind Caddy's /auth/* route).
CLUSTER_AUTH_ENDPOINT   = os.getenv("CLUSTER_AUTH_ENDPOINT",   "https://workbench.seedling.abc-cluster.cloud")
CLUSTER_NAME            = os.getenv("CLUSTER_NAME",            "seedling")
CLUSTER_DATACENTER      = os.getenv("CLUSTER_DATACENTER",      "seedling-prod")
CLUSTER_HEAD_POOL       = os.getenv("CLUSTER_HEAD_POOL",       "platform")
CLUSTER_WORKER_POOL     = os.getenv("CLUSTER_WORKER_POOL",     "compute")

_secret_env = os.getenv("SESSION_SECRET", "")
if not _secret_env:
    _secret_env = secrets.token_hex(32)
    print(
        "[auth-svc] WARNING: SESSION_SECRET not set — sessions will not "
        "survive restarts. Set SESSION_SECRET in the Nomad job env.",
        file=sys.stderr,
    )
SESSION_SECRET = _secret_env.encode()

if not PB_ADMIN_PASSWORD:
    print("[auth-svc] WARNING: PB_ADMIN_PASSWORD not set — PocketBase calls will fail.", file=sys.stderr)
if not OPERATOR_TOKEN:
    print("[auth-svc] WARNING: OPERATOR_TOKEN not set — /manage/ endpoints are unprotected.", file=sys.stderr)

# ---------------------------------------------------------------------------
# PocketBase token management
# ---------------------------------------------------------------------------

_pb_token_cache: dict = {"token": "", "expires": 0.0}
_pb_token_lock  = threading.Lock()


def _pb_token() -> str:
    """Return a valid PocketBase admin JWT, refreshing if near expiry."""
    with _pb_token_lock:
        if time.time() < _pb_token_cache["expires"] - 60:
            return _pb_token_cache["token"]
        body = json.dumps({"identity": PB_ADMIN_EMAIL, "password": PB_ADMIN_PASSWORD}).encode()
        req = urllib.request.Request(
            f"{POCKETBASE_URL}/api/collections/_superusers/auth-with-password",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        _pb_token_cache["token"]   = data["token"]
        _pb_token_cache["expires"] = time.time() + 6 * 24 * 3600  # 6-day conservative TTL
        return _pb_token_cache["token"]


def _pb_request(method: str, path: str, data=None, retry: bool = True):
    """Make an authenticated PocketBase API request. Returns parsed JSON."""
    body = json.dumps(data).encode() if data is not None else None
    headers = {
        "Authorization": f"Bearer {_pb_token()}",
        "Content-Type":  "application/json",
    }
    req = urllib.request.Request(
        f"{POCKETBASE_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code == 401 and retry:
            with _pb_token_lock:
                _pb_token_cache["expires"] = 0.0
            return _pb_request(method, path, data, retry=False)
        raise


def _pb_get(path: str):
    return _pb_request("GET", path)


def _pb_post(path: str, data: dict):
    return _pb_request("POST", path, data)


def _pb_patch(path: str, data: dict):
    return _pb_request("PATCH", path, data)


# ---------------------------------------------------------------------------
# One-time CLI magic-link codes   (POST /auth/cli-token + GET /auth/redeem)
# ---------------------------------------------------------------------------
# In-memory store: {code_str: (username, expiry_ts, next_url)}
# Codes are 32-byte random hex strings (64 chars). TTL = CLI_TOKEN_TTL seconds.
# Expired codes are evicted lazily on each new code issuance.

_cli_codes: dict = {}  # {code: (username, expiry_ts, next_url, extra)}
# extra is {} for regular portals, or {"minio_token": "<jwt>"} for MinIO SSO

# Trusted cluster domain for safe absolute redirects in /auth/redeem.
# Only URLs whose hostname ends with this suffix are accepted.
_TRUSTED_DOMAIN = os.getenv("TRUSTED_DOMAIN", ".abc-cluster.cloud")

def _is_trusted_redirect(url: str) -> bool:
    """Return True if url is an absolute https:// URL within the trusted cluster domain."""
    try:
        from urllib.parse import urlparse as _urlparse
        p = _urlparse(url)
        return p.scheme == "https" and (
            p.netloc == _TRUSTED_DOMAIN.lstrip(".") or
            p.netloc.endswith(_TRUSTED_DOMAIN)
        )
    except Exception:
        return False


MINIO_CONSOLE_URL = os.getenv("MINIO_CONSOLE_URL", "http://localhost:9001")

def _minio_console_login(access_key: str, secret_key: str) -> str | None:
    """Call MinIO Console /api/v1/login and return the JWT token string, or None on failure."""
    try:
        payload = json.dumps({"accessKey": access_key, "secretKey": secret_key}).encode()
        req = urllib.request.Request(
            f"{MINIO_CONSOLE_URL}/api/v1/login",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            # MinIO returns 204 No Content with Set-Cookie: token=<jwt>
            for hdr, val in resp.headers.items():
                if hdr.lower() == "set-cookie" and val.startswith("token="):
                    # Parse just the token value before the first semicolon
                    return val.split(";")[0][len("token="):]
    except Exception as exc:
        print(f"[auth-svc] _minio_console_login error: {exc}", file=sys.stderr)
    return None


def _cli_codes_issue(username: str, next_url: str, extra: dict = None) -> str:
    """Issue a one-time code. extra carries portal-specific data (e.g. minio_token)."""
    now = time.time()
    expired = [k for k, v in _cli_codes.items() if v[1] <= now]
    for k in expired:
        _cli_codes.pop(k, None)
    code = secrets.token_hex(32)
    _cli_codes[code] = (username, now + CLI_TOKEN_TTL, next_url, extra or {})
    return code

def _cli_codes_redeem(code: str):
    """Redeem a one-time code. Returns (username, next_url, extra) or None."""
    entry = _cli_codes.pop(code, None)
    if entry is None:
        return None
    username, expiry, next_url, extra = entry
    if time.time() > expiry:
        return None
    return username, next_url, extra


def _pb_find_slot(filter_expr: str):
    """Fetch the first slot matching filter_expr. Returns record dict or None."""
    encoded = urllib.parse.quote(filter_expr)
    resp = _pb_get(f"/api/collections/slots/records?filter={encoded}&skipTotal=1&perPage=1")
    items = resp.get("items", [])
    return items[0] if items else None


# ---------------------------------------------------------------------------
# Slot state cache — used by /validate to avoid a PocketBase round-trip on
# every proxied request. TTL of 60 s means a suspended slot is denied within
# ~60 seconds of the suspension action.
# ---------------------------------------------------------------------------

_slot_state_cache: dict      = {}   # {minio_access_key: {"state": str, "ts": float}}
_slot_state_cache_lock       = threading.Lock()
_SLOT_STATE_TTL              = 60.0  # seconds

def _cached_slot_state(username: str) -> str:
    """Return slot state for username from cache, refreshing from PocketBase if stale.

    Returns "none" for admin/non-pool users, "error" if PocketBase unreachable.
    """
    now = time.time()
    with _slot_state_cache_lock:
        entry = _slot_state_cache.get(username)
        if entry and now - entry["ts"] < _SLOT_STATE_TTL:
            return entry["state"]
    try:
        slot  = _pb_find_slot(f"minio_access_key='{username}'")
        state = slot.get("state", "") if slot else "none"
    except Exception as e:
        print(f"[auth-svc] slot state cache refresh failed for {username!r}: {e}", file=sys.stderr)
        state = "error"  # PocketBase unavailable — allow through (fail open)
    with _slot_state_cache_lock:
        _slot_state_cache[username] = {"state": state, "ts": now}
    return state


def _invalidate_slot_cache(username: str):
    """Evict username from slot state cache (call after any state change)."""
    with _slot_state_cache_lock:
        _slot_state_cache.pop(username, None)


# ---------------------------------------------------------------------------
# JupyterHub admin API helpers
# ---------------------------------------------------------------------------

def _jh_stop_server(slot_name: str):
    """Tell JupyterHub to stop the jupyter-<slot_name> user server (best-effort)."""
    if not JUPYTERHUB_API_TOKEN:
        print(f"[auth-svc] JH stop skipped — JUPYTERHUB_API_TOKEN not set", file=sys.stderr)
        return
    jh_user = f"jupyter-{slot_name}"
    url = f"{JUPYTERHUB_API_URL}/users/{urllib.parse.quote(jh_user, safe='')}/server"
    req = urllib.request.Request(
        url,
        method="DELETE",
        headers={
            "Authorization": f"token {JUPYTERHUB_API_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(f"[auth-svc] JH stop server {jh_user!r}: HTTP {r.status}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        # 400 = server not running (OK), 404 = user not found (OK)
        if e.code not in (400, 404):
            print(f"[auth-svc] JH stop server {jh_user!r}: HTTP {e.code} (warn)", file=sys.stderr)
        else:
            print(f"[auth-svc] JH stop server {jh_user!r}: HTTP {e.code} (no active server)", file=sys.stderr)
    except Exception as e:
        print(f"[auth-svc] JH stop server {jh_user!r}: {e}", file=sys.stderr)


def _jh_mint_user_token(jh_user: str, note: str, expires_in: int) -> dict:
    """Mint a JupyterHub user token via the admin API.

    Powers POST /workbench/token (the laptop-side `abc workbench connect`
    flow). The JH admin token is loaded from JUPYTERHUB_API_TOKEN; auth-svc
    is the only place that holds it, so individual slots never need an
    admin-tier credential.

    Requires: the 'auth-svc' JH service (registered in tljh-custom.py) must
    have the 'tokens' scope in its load_roles entry. Without it JH returns
    403 "no permissions to generate tokens". The scope was added 2026-06-05;
    tljh-custom.py now includes: 'scopes': [..., 'tokens'].

    Returns the dict that JupyterHub returns on POST /users/<u>/tokens
    (keys: token, id, expires_at, scopes, note, ...) or raises.
    """
    if not JUPYTERHUB_API_TOKEN:
        raise RuntimeError("JUPYTERHUB_API_TOKEN not configured on abc-auth-svc")
    url = f"{JUPYTERHUB_API_URL}/users/{urllib.parse.quote(jh_user, safe='')}/tokens"
    payload = {}
    if note:
        payload["note"] = note
    if expires_in and expires_in > 0:
        payload["expires_in"] = int(expires_in)
    req = urllib.request.Request(
        url,
        method="POST",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"token {JUPYTERHUB_API_TOKEN}",
            "Content-Type":  "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def _jh_user_exists(jh_user: str):
    """Return True/False if the JH user exists; None on probe failure.

    Used by the mint-failure log + /manage/slots/<slot>/diag to classify a
    JH 403:
      - 403 + user absent  → mint name wrong (Caddy/JH bare-name vs the
        mint target) OR user never logged in via browser.
      - 403 + user present → role scope too narrow OR admin token stale.
    Cheap single GET; the admin token has read:users.
    """
    if not JUPYTERHUB_API_TOKEN:
        return None
    url = f"{JUPYTERHUB_API_URL}/users/{urllib.parse.quote(jh_user, safe='')}"
    req = urllib.request.Request(
        url, headers={"Authorization": f"token {JUPYTERHUB_API_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status == 200
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Session tokens
# ---------------------------------------------------------------------------

def _make_session_token(username: str) -> str:
    expiry  = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{username}:{expiry}"
    sig     = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()


def _verify_session_token(token: str):
    try:
        decoded = base64.urlsafe_b64decode(token.encode() + b"==").decode()
        parts   = decoded.rsplit(":", 2)
        if len(parts) != 3:
            return None, False
        username, expiry_str, sig = parts
        if time.time() > int(expiry_str):
            return None, False
        payload  = f"{username}:{expiry_str}"
        expected = hmac.new(SESSION_SECRET, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None, False
        return username, True
    except Exception:
        return None, False


# ---------------------------------------------------------------------------
# Cookie parsing
# ---------------------------------------------------------------------------

def _parse_cookies(header: str) -> dict:
    cookies = {}
    for part in (header or "").split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


def _cookie_header(name: str, value: str, max_age: int) -> str:
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={max_age}"]
    if COOKIE_SECURE:
        parts.append("Secure")
    if COOKIE_DOMAIN:
        parts.append(f"Domain={COOKIE_DOMAIN}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Nomad ACL token validation  (path 2 — API / upload portal)
# ---------------------------------------------------------------------------

def _lookup_nomad_token(token: str):
    if not token:
        return None
    req = urllib.request.Request(
        f"{NOMAD_ADDR}/v1/acl/token/self",
        headers={"X-Nomad-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError:
        return None
    except Exception as exc:
        print(f"[auth-svc] nomad lookup error: {exc}", file=sys.stderr)
        return None


def _nomad_identity_headers(info: dict) -> dict:
    name     = info.get("Name") or "anonymous"
    ttype    = info.get("Type", "client")
    policies = info.get("Policies") or []
    roles    = info.get("Roles") or []

    if ttype == "management":
        group, namespace, policy_str = "admin", "*", "management"
    else:
        if policies:
            group      = policies[0]
            policy_str = ",".join(policies)
        elif roles:
            role_name  = roles[0].get("Name", "unknown")
            group      = role_name[2:] if role_name.startswith("r-") else role_name
            policy_str = f"role:{role_name}"
        else:
            group, policy_str = "unknown", ""

        ns_guess = group
        if group.startswith("member-"):
            ns_guess = group[len("member-"):]
        elif group.endswith("-pool"):
            ns_guess = group[: -len("-pool")]
        elif group.endswith("-admin"):
            ns_guess = group[: -len("-admin")]
        elif group.endswith("-member"):
            ns_guess = group[: -len("-member")]
        namespace = info.get("Namespace") or ns_guess

    return {
        "X-Auth-User":      name,
        "X-Auth-Group":     group,
        "X-Auth-Namespace": namespace,
        "X-Auth-Policies":  policy_str,
    }


def _groups_from_policies(policy_str: str) -> list:
    """Derive sorted list of group names from a comma-separated policy string.

    Strips well-known suffixes (-pool, -admin, -member) and the su- prefix
    so callers get clean group names like ["mbhg-hostgen", "multi-group"].
    Management tokens return ["*"] (all-groups).
    Role-based tokens (policy_str starts with "role:") are not expanded here
    — call _minio_groups_for_user() to get actual bucket access for those.
    """
    if policy_str == "management":
        return ["*"]
    groups, seen = [], set()
    for p in policy_str.split(","):
        p = p.strip()
        if not p or p.startswith("role:"):
            continue   # skip role references — need separate expansion
        if p.startswith("su-"):
            inner = p[3:]
            for suffix in ("-pool", "-admin", "-member"):
                if inner.endswith(suffix):
                    g = inner[: -len(suffix)]
                    break
            else:
                g = inner
        else:
            g = p
        if g and g not in seen:
            seen.add(g)
            groups.append(g)
    return sorted(groups)


def _minio_groups_for_user(username: str) -> list:
    """Return the list of group names (su-{group}) the MinIO user belongs to.

    Calls `mcli admin user info sdroot <username>`, parses the MemberOf line,
    then for each group strips the g- prefix and -admin/-member suffix to get
    the bucket-level group name. Falls back to [] on any error.

    Example: g-multi-group-admin → multi-group
             g-mbhg-hostgen-pool  → mbhg-hostgen
    """
    import subprocess as _sp
    try:
        r = _sp.run(
            ["/usr/local/bin/mcli", "admin", "user", "info", "sdroot", username],
            capture_output=True, text=True, timeout=5,
        )
        groups, seen = [], set()
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("MemberOf:"):
                # Format: MemberOf: [g-multi-group-admin g-mbhg-hostgen-pool]
                inner = line[len("MemberOf:"):].strip().strip("[]")
                for gname in inner.split():
                    gname = gname.strip()
                    if gname.startswith("g-"):
                        gname = gname[2:]  # strip 'g-'
                    for suffix in ("-admin", "-pool", "-member"):
                        if gname.endswith(suffix):
                            gname = gname[: -len(suffix)]
                            break
                    if gname and gname not in seen:
                        seen.add(gname)
                        groups.append(gname)
        return sorted(groups)
    except Exception as exc:
        print(f"[auth-svc] _minio_groups_for_user({username!r}): {exc}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# MinIO credential validation  (path 1 — browser / workbench)
# ---------------------------------------------------------------------------

_boto_cfg = BotoConfig(
    connect_timeout=5,
    read_timeout=5,
    retries={"max_attempts": 1},
)


def _validate_minio(username: str, password: str) -> bool:
    """Return True iff (username, password) is a valid MinIO credential.

    Uses list_buckets() as the probe, but distinguishes AUTHENTICATION failure
    from AUTHORIZATION failure: a restricted member (policy `su-<group>-member`)
    is not granted `s3:ListAllMyBuckets`, so list_buckets() returns
    403 AccessDenied — yet the request was correctly signed, which proves the
    credential is real. Only signature/key errors (InvalidAccessKeyId,
    SignatureDoesNotMatch) mean the credential itself is bad.
    """
    try:
        s3 = boto3.client(
            "s3",
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=username,
            aws_secret_access_key=password,
            region_name="us-east-1",
            config=_boto_cfg,
        )
        s3.list_buckets()
        return True
    except ClientError as e:
        code = (e.response.get("Error", {}) or {}).get("Code", "")
        # AccessDenied = signature authenticated, policy just lacks this action.
        # The credential is valid; members legitimately land here.
        if code in ("AccessDenied", "AccessDeniedException"):
            return True
        # InvalidAccessKeyId / SignatureDoesNotMatch / etc. = bad credential.
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Nomad management helpers (used by /manage/ endpoints)
# ---------------------------------------------------------------------------

def _nomad_api(method: str, path: str, data=None):
    """Make a Nomad management API call using NOMAD_TOKEN."""
    body = json.dumps(data).encode() if data is not None else None
    req  = urllib.request.Request(
        f"{NOMAD_ADDR}{path}",
        data=body,
        headers={
            "X-Nomad-Token": NOMAD_TOKEN,
            "Content-Type":  "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def _nomad_create_token(slot_name: str, group_name: str, role_id: str):
    """Create a new Nomad ACL client token for a slot. Returns (accessor_id, secret_id)."""
    resp = _nomad_api("POST", "/v1/acl/token", {
        "Name":     f"pool-{slot_name}",
        "Type":     "client",
        "Policies": [],
        "Roles":    [{"ID": role_id}] if role_id else [],
    })
    return resp["AccessorID"], resp["SecretID"]


def _nomad_delete_token(accessor_id: str):
    """Delete a Nomad ACL token by accessor ID (best-effort)."""
    try:
        _nomad_api("DELETE", f"/v1/acl/token/{accessor_id}")
    except Exception as e:
        print(f"[auth-svc] warn: nomad token delete {accessor_id}: {e}", file=sys.stderr)


def _nomad_get_role_id(role_name: str):
    """Look up a Nomad ACL role ID by name. Returns ID string or None."""
    try:
        roles = _nomad_api("GET", "/v1/acl/roles")
        for r in roles:
            if r.get("Name") == role_name:
                return r["ID"]
    except Exception as e:
        print(f"[auth-svc] warn: nomad role lookup {role_name}: {e}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# MinIO management helpers (via mcli subprocess)
# ---------------------------------------------------------------------------

def _mcli(*args) -> str:
    """Run /usr/local/bin/mcli with the sdroot alias pre-configured."""
    cmd    = ["/usr/local/bin/mcli"] + list(args)
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


def _mcli_safe(*args) -> bool:
    """Run mcli, returning False instead of raising on failure."""
    try:
        _mcli(*args)
        return True
    except subprocess.CalledProcessError as e:
        print(f"[auth-svc] warn: mcli {' '.join(args)}: {e.stderr}", file=sys.stderr)
        return False


def _minio_rotate_secret(muser: str) -> str:
    """Generate a new MinIO secret key for muser. Returns new secret."""
    new_secret = secrets.token_urlsafe(32)
    # mcli admin user add is idempotent — it updates the password if user exists
    _mcli("admin", "user", "add", "sdroot", muser, new_secret)
    return new_secret


# ---------------------------------------------------------------------------
# config.yaml builder (ported from abc-signup-svc, double-prefix bug fixed)
# ---------------------------------------------------------------------------

def _build_config_yaml(slot_name: str, group_name: str, nomad_token: str,
                        minio_access_key: str, minio_secret_key: str,
                        cred_source: str = "", opaque_token: str = "") -> str:
    """Build a complete ~/.abc/config.yaml for a slot.

    Phase 1 introduces a `cred_source` switch that selects the rendered shape:

    - "" / "local"      → today's shape: real Nomad token + MinIO secret_key
                          baked into the YAML. The CLI uses them directly
                          (no broker call).
    - "seedling/v1"     → opaque shape: only the bare opaque + identity +
                          cluster endpoint. The CLI's SeedlingV1CredSource
                          POSTs to /auth/exchange on use to get the real
                          Nomad+MinIO creds (5-min in-memory cache). The
                          real creds NEVER appear in the on-disk YAML.
                          `opaque_token` must be non-empty.

    Other cred_source values raise — the caller is requesting a path we
    haven't taught the renderer yet, and silently falling back would land
    a confusing config on the user's laptop.
    """
    namespace = f"su-{group_name}"
    cs = (cred_source or "").strip().lower()

    if cs in ("", "local"):
        # Use minio_access_key directly — do NOT prepend "slot-" again.
        # (abc-signup-svc had a bug: bucket_user_id = f"slot-{slot_name}" which
        # produced "slot-slot-calm_dassie" when slot_name = "slot-calm_dassie")
        return (
            f"version: 1.0\n"
            f"active_context: {CLUSTER_NAME}\n"
            f"contexts:\n"
            f"    {CLUSTER_NAME}:\n"
            f"        access_token: {nomad_token}\n"
            f"        admin:\n"
            f"            id: pool-{slot_name}\n"
            f"            services:\n"
            f"                minio:\n"
            f"                    access_key: {minio_access_key}\n"
            f"                    endpoint: {CLUSTER_MINIO_ENDPOINT}\n"
            f"                    secret_key: {minio_secret_key}\n"
            f"                nomad:\n"
            f"                    addr: {CLUSTER_NOMAD_ENDPOINT}\n"
            f"                    datacenters:\n"
            f"                        - {CLUSTER_DATACENTER}\n"
            f"                    head_pool: {CLUSTER_HEAD_POOL}\n"
            f"                    namespace: {namespace}\n"
            f"                    token: {nomad_token}\n"
            f"                    worker_pool: {CLUSTER_WORKER_POOL}\n"
            f"                tools:\n"
            f"                    endpoint: {CLUSTER_MINIO_ENDPOINT}\n"
            f"        auth:\n"
            f"            whoami: {slot_name}\n"
            f"        cluster_type: abc-cluster\n"
            f"        endpoint: {CLUSTER_NOMAD_ENDPOINT}\n"
            f"        upload_endpoint: {CLUSTER_UPLOAD_ENDPOINT}\n"
        )

    if cs == "seedling/v1":
        if not opaque_token:
            raise ValueError("cred_source=seedling/v1 requires a non-empty opaque_token")
        # Minimal opaque shape. NO real Nomad token, NO MinIO secret here.
        # The CLI's SeedlingV1CredSource calls POST <auth_endpoint>/auth/exchange
        # with the opaque as Bearer to resolve real creds at use time (5-min cache).
        # We stamp auth_endpoint explicitly so the CLI doesn't have to guess
        # the broker URL — for this deployment it lives at
        # workbench.<rest>/auth/*, not auth.<rest>.
        return (
            f"version: 1.0\n"
            f"active_context: {CLUSTER_NAME}\n"
            f"contexts:\n"
            f"    {CLUSTER_NAME}:\n"
            f"        cred_source: seedling/v1\n"
            f"        access_token: {opaque_token}\n"
            f"        auth:\n"
            f"            whoami: {slot_name}\n"
            f"        auth_endpoint: {CLUSTER_AUTH_ENDPOINT}\n"
            f"        cluster_type: abc-cluster\n"
            f"        endpoint: {CLUSTER_NOMAD_ENDPOINT}\n"
            f"        upload_endpoint: {CLUSTER_UPLOAD_ENDPOINT}\n"
        )

    raise ValueError(f"_build_config_yaml: unsupported cred_source {cred_source!r}")


# ---------------------------------------------------------------------------
# config_yaml blob — derived cache in PocketBase
#
# The slots collection has a `config_yaml` text field (added 2026-06-01 via
# scripts/migrate-add-config-yaml.py). It holds the rendered ~/.abc/config.yaml
# blob — the same bytes the user gets on their laptop at claim time.
#
# Consumers READ the blob from PocketBase without re-rendering:
#   - the JupyterHub pre_spawn_hook materializes it to disk on session start
#   - `abc auth config refresh` pulls it via GET /slots/me/config
#
# `_persist_slot_config(slot_id)` is the SINGLE WRITER for the blob.
# Call it from any code path that mutates a field that is INPUT to
# _build_config_yaml — slot_name, group, nomad_token_secret,
# minio_access_key, minio_secret_key. State-only mutations don't need it.
#
# Design: brainstorms/abc-seedling-onboarding/2026-06-01-claim-time-config-dropthrough.md
# ---------------------------------------------------------------------------

RENDERER_VERSION = "abc-auth-svc/v3.0"


def _now_iso_pb() -> str:
    """PocketBase v0.23 date format — milliseconds + 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Opaque-token broker support (Phase 1: cred_source=seedling/v1)
#
# A slot opted into the broker pathway has:
#   - cred_source       = "seedling/v1"
#   - opaque_token_hash = sha256_hex(opaque_user_token)
#
# The bare opaque is given to the user once (at claim time / cred-source flip)
# and persisted only on the user's laptop. The server keeps the hash. On
# /auth/exchange, the user presents the bare opaque as a Bearer; we hash it,
# look up the slot, and (Pattern A) return the real Nomad+MinIO creds.
#
# Design: brainstorms/abc-seedling-onboarding/2026-06-01-opaque-tokens-credential-broker.md
# ---------------------------------------------------------------------------

OPAQUE_PREFIX = "abco_"  # "abc-opaque" — namespaces opaque tokens for grep/logs
OPAQUE_BYTES  = 32       # 32 bytes → 43 chars urlsafe base64 → easy to copy/paste

def _mint_opaque_token() -> str:
    """Generate a fresh opaque user token. Returns the bare token (give to user);
    callers must persist sha256_hex(token) on the slot, never the bare value."""
    return OPAQUE_PREFIX + secrets.token_urlsafe(OPAQUE_BYTES)

def _hash_opaque(token: str) -> str:
    """SHA-256 hex of an opaque token. Stable; safe to store in PocketBase."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _pb_find_slot_by_opaque(opaque: str):
    """Look up a claimed slot whose opaque_token_hash matches the given bare opaque.
    Returns the slot dict or None.

    Constant-time-ish: we hash the input first and compare via PB's `=` filter
    (server-side compare on bytes equal to a 64-char hex). The bare opaque
    never enters PocketBase logs or queries; only its hash does.
    """
    if not opaque:
        return None
    h = _hash_opaque(opaque)
    # extra constraint: only claimed slots can exchange — suspended/expired
    # tokens MUST not resolve to creds even if the hash matches.
    return _pb_find_slot(f"opaque_token_hash='{h}' && state='claimed'")


def _build_creds_bundle(slot: dict) -> dict:
    """Render the real-credentials bundle for a slot as a JSON-shaped dict.

    Mirrors `_build_config_yaml` content but in a structure the CLI's
    SeedlingV1CredSource (see internal/credsource/seedling_v1.go) will
    deserialize directly into its Creds value type. Snake_case keys to
    match the Go struct's yaml tags.
    """
    slot_name        = (slot.get("slot_name") or "").strip()
    group_name       = _resolve_group_name_from_slot(slot)
    nomad_token      = (slot.get("nomad_token_secret") or "").strip()
    minio_access_key = (slot.get("minio_access_key") or "").strip()
    minio_secret_key = (slot.get("minio_secret_key") or "").strip()
    namespace        = f"su-{group_name}" if group_name else ""

    return {
        "whoami": slot_name,
        "source": "seedling/v1",
        "nomad": {
            "addr":         CLUSTER_NOMAD_ENDPOINT,
            "token":        nomad_token,
            "namespace":    namespace,
            "datacenters":  [CLUSTER_DATACENTER],
            "head_pool":    CLUSTER_HEAD_POOL,
            "worker_pool":  CLUSTER_WORKER_POOL,
        },
        "minio": {
            "endpoint":   CLUSTER_MINIO_ENDPOINT,
            "access_key": minio_access_key,
            "secret_key": minio_secret_key,
        },
    }


def _resolve_group_name_from_slot(slot: dict) -> str:
    """Module-level group-name resolver. Mirror of the per-handler method
    in the HTTP handler class so module-level helpers can use it too."""
    name = slot.get("group_name") or ""
    if name:
        return name
    gid = slot.get("group")
    if not gid:
        return ""
    try:
        grp = _pb_get(f"/api/collections/groups/records/{gid}")
        return grp.get("name", "")
    except Exception:
        return ""


def _persist_slot_config(slot_id: str, opaque_token: str = "") -> str:
    """Re-render a slot's config_yaml blob from its current atomic fields and
    write it back to PocketBase. Returns the rendered YAML so the caller can
    also send it in an HTTP response without re-rendering.

    Behaviour depends on the slot's cred_source field:
    - "" / "local"    → re-render real-creds shape from current atomic fields.
                        Triggered by any rotation of nomad_token_secret /
                        minio_secret_key etc. `opaque_token` is ignored.
    - "seedling/v1"   → re-render opaque shape. Requires `opaque_token` (the
                        bare opaque) — the server only stores the hash, so
                        a caller minting/flipping opaques MUST pass the bare
                        value at the moment of the change. If called without
                        a bare opaque on a seedling/v1 slot, this is a NO-OP
                        and returns the existing blob unchanged — rotation
                        of real creds doesn't invalidate the user's opaque,
                        so the blob is stable across rotations.

    Caller responsibilities (single writer discipline — see brainstorm):
    - For `local` slots: call AFTER any PATCH that touches slot_name / group /
      nomad_token_secret / minio_access_key / minio_secret_key.
    - For `seedling/v1` slots: call WITH the bare opaque AFTER minting
      (claim, cred-source flip to seedling/v1, future opaque rotation). Other
      mutations do not require a call.
    - For cross-portal coherence (MinIO + Nomad + workbench), also call
      `_invalidate_slot_cache(muser)` and `_jh_stop_server(slot_name)` if
      credentials rotated — see _manage_rotate.
    """
    slot = _pb_get(f"/api/collections/slots/records/{slot_id}")
    group_name = _resolve_group_name_from_slot(slot)
    cs = (slot.get("cred_source") or "").strip().lower()

    if cs == "seedling/v1" and not opaque_token:
        # Stable-blob invariant: rotation of real creds on a seedling/v1 slot
        # does NOT change the user-visible YAML. Caller didn't pass an
        # opaque, so we leave the existing blob alone.
        return slot.get("config_yaml") or ""

    config_yaml = _build_config_yaml(
        slot_name        = slot["slot_name"],
        group_name       = group_name,
        nomad_token      = slot.get("nomad_token_secret", ""),
        minio_access_key = slot.get("minio_access_key", ""),
        minio_secret_key = slot.get("minio_secret_key", ""),
        cred_source      = cs,
        opaque_token     = opaque_token,
    )
    _pb_patch(f"/api/collections/slots/records/{slot_id}", {
        "config_yaml":          config_yaml,
        "config_yaml_at":       _now_iso_pb(),
        "config_yaml_renderer": RENDERER_VERSION,
    })
    return config_yaml


# ---------------------------------------------------------------------------
# Claim lock — prevents concurrent claim race on the same code
# ---------------------------------------------------------------------------

_claim_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Login page HTML
# ---------------------------------------------------------------------------

_LOGIN_HTML = """\
<!doctype html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>abc-cluster · sign in</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>
    (function(){{
      try{{
        var s=localStorage.getItem('abc-theme');
        if(s==='dark'||s==='light') document.documentElement.setAttribute('data-theme',s);
      }}catch(e){{}}
    }})();
    document.addEventListener('DOMContentLoaded',function(){{
      var btn=document.getElementById('theme-toggle');
      if(btn) btn.addEventListener('click',function(){{
        var root=document.documentElement;
        var cur=root.getAttribute('data-theme')||'light';
        var next=cur==='dark'?'light':'dark';
        root.setAttribute('data-theme',next);
        try{{localStorage.setItem('abc-theme',next);}}catch(e){{}}
      }});
    }});
  </script>
  <style>
    /* ── tokens ── */
    :root, :root[data-theme="dark"] {{
      --bg:#070f0c; --bg-1:#0b1a15; --bg-2:#0f2219;
      --text:#c5e5dc; --text-dim:#7db8a8; --text-mute:#4a7d6f;
      --ink:#e8f9f4; --ink-dim:#c8a84c;
      --accent:#c8a84c; --primary:#4ab89a;
      --rule:#163d32; --rule-soft:#0e2a22;
      --danger:#e07b7b;
    }}
    :root[data-theme="light"] {{
      --bg:#ffffff; --bg-1:#eef6f2; --bg-2:#e3eee8;
      --text:#1a4a3a; --text-dim:#2d7060; --text-mute:#6aaa96;
      --ink:#0a2820; --ink-dim:#907028;
      --accent:#907028; --primary:#2d7060;
      --rule:#a8d8cc; --rule-soft:#c8e8e0;
      --danger:#b04040;
    }}

    /* ── reset + base ── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; }}
    html {{ color-scheme: dark light; }}
    body {{
      background: var(--bg); color: var(--text);
      font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 15px; line-height: 1.55;
      min-height: 100dvh;
      display: flex; flex-direction: column;
    }}
    code, pre, .mono {{
      font-family: 'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace;
    }}

    /* ── topbar (site-kit chrome) ── */
    .topbar {{
      border-bottom: 1px solid var(--rule); background: var(--bg);
      padding: 14px 0; position: sticky; top: 0; z-index: 100;
      backdrop-filter: blur(8px);
    }}
    .topbar-inner {{
      max-width: 1180px; margin: 0 auto; padding: 0 32px;
      display: flex; align-items: center; gap: 18px;
    }}
    .top-spacer {{ flex: 1; }}
    .brand {{
      display: flex; align-items: center; gap: 10px;
      color: var(--ink); text-decoration: none;
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px; font-weight: 600;
    }}
    .brand-mark {{ width: 36px; height: 36px; color: var(--ink); flex: none; }}
    .brand-name {{ letter-spacing: -0.01em; }}
    .brand-name .dim {{ opacity: 0.45; }}
    .brand-name .tier {{ opacity: 0.55; font-weight: 400; }}
    .theme-toggle {{
      background: none; border: 1px solid var(--rule); border-radius: 6px;
      cursor: pointer; color: var(--text-dim); padding: 5px 7px;
      display: flex; align-items: center; transition: color .12s, border-color .12s;
    }}
    .theme-toggle:hover {{ color: var(--ink); border-color: var(--ink-dim); }}
    .theme-toggle svg {{ width: 15px; height: 15px; display: block; }}
    .ti-sun  {{ display: none; }}
    .ti-moon {{ display: block; }}
    [data-theme="dark"]  .ti-sun  {{ display: block; }}
    [data-theme="dark"]  .ti-moon {{ display: none; }}
    [data-theme="light"] .ti-sun  {{ display: block; }}
    [data-theme="light"] .ti-moon {{ display: none; }}

    /* ── page layout ── */
    .page {{
      flex: 1; display: flex; align-items: center; justify-content: center;
      padding: 48px 24px;
    }}

    /* ── login card ── */
    .login-card {{
      width: 100%; max-width: 400px;
    }}
    .login-eyebrow {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; font-weight: 600; letter-spacing: 0.14em;
      text-transform: uppercase; color: var(--accent);
      margin-bottom: 6px;
    }}
    .login-title {{
      font-size: 22px; font-weight: 600; letter-spacing: -0.02em;
      color: var(--ink); margin-bottom: 4px; line-height: 1.2;
    }}
    .login-sub {{
      font-size: 13.5px; color: var(--text-dim); margin-bottom: 28px;
    }}

    /* ── form shell (matches landing page .form-shell) ── */
    .form-shell {{
      border: 1px solid var(--rule); border-radius: 8px; overflow: hidden;
    }}
    .form-shell-head {{
      display: flex; align-items: center; justify-content: space-between;
      padding: 11px 18px; background: var(--bg-2);
      border-bottom: 1px solid var(--rule);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase;
      color: var(--text-dim);
    }}
    .form-shell-head .label {{ color: var(--ink); }}
    .form-shell-head .path {{ color: var(--text-mute); }}
    .form-shell-body {{ padding: 20px 18px 18px; display: flex; flex-direction: column; gap: 16px; }}

    /* ── field ── */
    .field {{ display: flex; flex-direction: column; gap: 6px; }}
    .field label {{
      font-size: 12.5px; font-weight: 500; color: var(--ink); letter-spacing: 0.01em;
    }}
    .field input {{
      width: 100%; padding: 9px 12px;
      background: var(--bg); color: var(--ink);
      border: 1px solid var(--rule); border-radius: 6px;
      font-family: 'IBM Plex Sans', sans-serif; font-size: 14px;
      transition: border-color .12s, background .12s;
      -webkit-appearance: none; appearance: none;
    }}
    .field input:focus {{
      outline: none; border-color: var(--accent);
      background: var(--bg-1);
    }}
    .field input::placeholder {{ color: var(--text-mute); opacity: 1; }}
    /* Override browser autofill yellow/grey tint */
    .field input:-webkit-autofill,
    .field input:-webkit-autofill:hover,
    .field input:-webkit-autofill:focus {{
      -webkit-box-shadow: 0 0 0 40px var(--bg-1) inset !important;
      -webkit-text-fill-color: var(--ink) !important;
      caret-color: var(--ink);
    }}
    .field .hint {{
      font-size: 12px; color: var(--text-mute); font-weight: 400;
    }}
    .field .hint code {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.92em; color: var(--ink);
    }}

    /* ── submit button (matches landing .btn.primary) ── */
    .btn {{
      display: inline-flex; align-items: center; gap: 6px;
      padding: 9px 20px; border-radius: 6px; cursor: pointer;
      font-family: 'IBM Plex Sans', sans-serif;
      font-size: 13px; font-weight: 600; text-decoration: none;
      border: 1px solid var(--rule); background: transparent; color: var(--ink);
      transition: all .12s; width: 100%; justify-content: center;
    }}
    .btn.primary {{
      background: var(--ink); color: var(--bg); border-color: var(--ink);
    }}
    .btn.primary:hover {{
      background: var(--accent); border-color: var(--accent); color: var(--bg);
    }}
    .btn .arrow {{ transition: transform .12s; }}
    .btn:hover .arrow {{ transform: translateX(3px); }}

    /* ── error block ── */
    .error-block {{
      background: var(--bg-1);
      border: 1px solid var(--danger);
      border-radius: 6px;
      color: var(--danger);
      font-size: 13px; padding: 10px 14px;
    }}

    /* ── footer note ── */
    .login-footer {{
      margin-top: 14px; text-align: center;
      font-size: 12px; color: var(--text-mute);
      font-family: 'JetBrains Mono', monospace;
      letter-spacing: 0.02em;
    }}
    .login-footer code {{
      font-family: inherit; color: var(--text-dim);
    }}
  </style>
</head>
<body>

<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="https://seedling.abc-cluster.cloud" aria-label="abc-cluster home">
      <svg class="brand-mark" viewBox="7 37 86 26" aria-hidden="true">
        <line x1="20" y1="50" x2="80" y2="50" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
        <circle cx="20" cy="50" r="9" fill="var(--bg)" stroke="currentColor" stroke-width="3"/>
        <circle cx="50" cy="50" r="9" fill="var(--bg)" stroke="currentColor" stroke-width="3"/>
        <circle cx="80" cy="50" r="9" fill="var(--bg)" stroke="currentColor" stroke-width="3"/>
        <g fill="currentColor" font-family="'JetBrains Mono',monospace" font-weight="700"
           font-size="10" text-anchor="middle" letter-spacing="-0.02em">
          <text x="20" y="53.5">A</text><text x="50" y="53.5">B</text><text x="80" y="53.5">C</text>
        </g>
      </svg>
      <span class="brand-name">abc<span class="dim">-cluster</span><span class="tier"> · seedling</span></span>
    </a>
    <div class="top-spacer"></div>
    <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Toggle light / dark theme">
      <svg class="ti-sun" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.6"/>
        <g stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
          <line x1="12" y1="2" x2="12" y2="4"/><line x1="12" y1="20" x2="12" y2="22"/>
          <line x1="2" y1="12" x2="4" y2="12"/><line x1="20" y1="12" x2="22" y2="12"/>
          <line x1="4.6" y1="4.6" x2="6" y2="6"/><line x1="18" y1="18" x2="19.4" y2="19.4"/>
          <line x1="4.6" y1="19.4" x2="6" y2="18"/><line x1="18" y1="6" x2="19.4" y2="4.6"/>
        </g>
      </svg>
      <svg class="ti-moon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M19.6 17.8a8.4 8.4 0 1 1-9.4-12.6 7 7 0 0 0 9.4 12.6Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
      </svg>
    </button>
  </div>
</header>

<div class="page">
  <div class="login-card">
    <div class="login-eyebrow">workbench · interactive analysis</div>
    <h1 class="login-title">Sign in</h1>
    <p class="login-sub">Use the credentials from your <code class="mono">config.yaml</code></p>

    {error_block}

    <form class="form-shell" method="POST" action="/auth/login" autocomplete="off" novalidate>
      <div class="form-shell-head">
        <span class="label">credentials</span>
        <span class="path">abc-cluster · seedling</span>
      </div>
      <div class="form-shell-body">
        <div class="field">
          <label for="u">Username</label>
          <input id="u" name="username" type="text"
                 autocomplete="off" spellcheck="false"
                 placeholder="e.g. slot-bold_hornbill" required>
          <span class="hint">Your slot handle — find it in <code>config.yaml</code> under <code>user</code></span>
        </div>
        <div class="field">
          <label for="p">Token</label>
          <input id="p" name="password" type="password"
                 autocomplete="off" required>
          <span class="hint">The <code>token</code> value from your <code>config.yaml</code></span>
        </div>
        <input type="hidden" name="next" value="{next_url}">
        <button class="btn primary" type="submit">
          <span>Sign in</span>
          <span class="arrow" aria-hidden="true">→</span>
        </button>
      </div>
    </form>

    <p class="login-footer">
      No access yet? → <a href="https://seedling.abc-cluster.cloud/#access" style="color:var(--accent);text-decoration:none;">claim a slot</a>
    </p>
  </div>
</div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class AuthHandler(BaseHTTPRequestHandler):

    server_version = "abc-auth-svc/2.0"
    sys_version    = ""

    # ---- routing -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path

        if path.startswith("/verify"):
            self._verify_nomad()
        elif path in ("/healthz", "/auth/health"):
            self._ok("OK")
        elif path == "/validate":
            self._validate()
        elif path == "/validate-optional":
            self._validate_optional()
        elif path == "/auth/redeem":
            self._auth_redeem(parsed.query)
        elif path == "/auth/minio-login":
            self._auth_minio_login(parsed.query)
        elif path == "/auth/me":
            self._auth_me()
        elif path == "/auth/login":
            next_url = self._safe_next(parse_qs(parsed.query).get("next", ["/"])[0])
            self._serve_login(next_url=next_url)
        elif path == "/auth/logout":
            self._logout()
        elif path == "/manage/slots":
            self._manage_list_slots()
        elif path.startswith("/manage/slots/"):
            slug = path[len("/manage/slots/"):]
            parts = slug.split("/", 1)
            if len(parts) == 1:
                self._manage_get_slot(parts[0])
            elif len(parts) == 2 and parts[1] == "diag":
                self._manage_diag_slot(parts[0])
            else:
                self._respond(404, "text/plain", b"Not found")
        elif path == "/slots/me/config":
            self._slots_me_config()
        else:
            self._respond(404, "text/plain", b"Not found")

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/auth/login":
            self._login_post()
        elif path == "/auth/cli-token":
            self._cli_token_post()
        elif path == "/auth/exchange":
            self._auth_exchange()
        elif path in ("/workbench/token", "/auth/workbench/token"):
            # Caddy's `handle /auth/*` forwards the prefix UNSTRIPPED, so the CLI's
            # POST <host>/auth/workbench/token arrives here as /auth/workbench/token.
            # Accept both the prefixed and bare forms (mirrors the Go service, which
            # registers both — see abc-auth-svc/internal/authsvc/server.go).
            self._workbench_token_post()
        elif path in ("/auth/secrets/put", "/secrets/put"):
            self._secrets_put()
        elif path in ("/auth/secrets/get", "/secrets/get"):
            self._secrets_get()
        elif path.startswith("/verify"):
            self._verify_nomad()
        elif path == "/slots/claim":
            self._claim_slot()
        elif path.startswith("/manage/slots/"):
            rest  = path[len("/manage/slots/"):]
            parts = rest.split("/", 1)
            if len(parts) == 2:
                slot_name, action = parts
                if action == "rotate":
                    self._manage_rotate(slot_name)
                elif action == "suspend":
                    self._manage_suspend(slot_name)
                elif action == "reactivate":
                    self._manage_reactivate(slot_name)
                elif action == "cred-source":
                    self._manage_cred_source(slot_name)
                else:
                    self._respond(404, "text/plain", b"Not found")
            else:
                self._respond(404, "text/plain", b"Not found")
        else:
            self._respond(404, "text/plain", b"Not found")

    # ---- /verify (Nomad ACL token) ----------------------------------------

    def _verify_nomad(self):
        token = self.headers.get("X-Nomad-Token", "")
        if not token:
            auth = self.headers.get("Authorization", "")
            if auth[:7].lower() == "bearer ":
                token = auth[7:].strip()

        info = _lookup_nomad_token(token)
        if not info:
            body = b"unauthorized: missing or invalid token\n"
            self.send_response(401)
            self.send_header("Content-Type",   "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        headers = _nomad_identity_headers(info)
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    # ---- /auth/me ----------------------------------------------------------
    # Returns authenticated user identity + group list as JSON.
    # Used by the Uppy upload portal to populate the group picker dropdown.
    # Accepts X-Nomad-Token header or Authorization: Bearer <token>.
    # Response: {"user": "gvds", "groups": ["mbhg-hostgen", "multi-group"],
    #            "primary_group": "multi-group", "namespace": "multi-group"}
    # Single-group users: groups list has one element; Uppy shows no dropdown.

    def _auth_me(self):
        import json as _json
        token = self.headers.get("X-Nomad-Token", "")
        if not token:
            auth = self.headers.get("Authorization", "")
            if auth[:7].lower() == "bearer ":
                token = auth[7:].strip()

        if not token:
            body = _json.dumps({"error": "missing token"}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return

        info = _lookup_nomad_token(token)
        if not info:
            body = _json.dumps({"error": "invalid token"}).encode()
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
            return

        hdrs          = _nomad_identity_headers(info)
        policy_str    = hdrs.get("X-Auth-Policies", "")
        user_name     = hdrs.get("X-Auth-User", "")
        # For direct-policy tokens, derive groups from the policy list.
        # For role-based tokens (policy_str="role:…"), look up MinIO group
        # memberships instead — they carry the canonical bucket-access list.
        is_role_based = policy_str.startswith("role:")
        if is_role_based:
            groups = _minio_groups_for_user(user_name) or _groups_from_policies(policy_str)
        else:
            groups = _groups_from_policies(policy_str)
        primary_group = hdrs.get("X-Auth-Namespace", groups[0] if groups else "")
        body = _json.dumps({
            "user":          user_name,
            "groups":        groups,
            "primary_group": primary_group,
            "namespace":     primary_group,
            "role_based":    is_role_based,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)
        print(f"[auth-svc] /auth/me user={hdrs.get('X-Auth-User','?')!r} groups={groups}", file=sys.stderr)

    # ---- /validate ---------------------------------------------------------

    def _validate(self):
        cookies = _parse_cookies(self.headers.get("Cookie", ""))
        token   = cookies.get(SESSION_COOKIE_NAME)
        if token:
            username, ok = _verify_session_token(token)
            if ok:
                # Check slot state via 60-second cache. Non-pool users (e.g. abc-admin)
                # have state="none" and are always allowed through.
                state = _cached_slot_state(username)
                if state in ("suspended", "expired"):
                    # Clear cookie and redirect — user sees suspended/expired message on next login
                    self.send_response(302)
                    self.send_header("Location",   "/auth/login")
                    self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE_NAME, "", 0))
                    self.end_headers()
                    self._log(f"VALIDATE DENIED state={state!r} user={username!r}")
                    return
                self.send_response(200)
                self.send_header("X-Auth-User",    username)
                self.send_header("Remote-User",    username)
                self.send_header("X-WEBAUTH-USER", username)
                self.end_headers()
                return

        orig_uri  = self.headers.get("X-Forwarded-Uri", "/")
        login_url = f"/auth/login?next={quote(orig_uri, safe='')}"
        self.send_response(302)
        self.send_header("Location", login_url)
        self.end_headers()

    # ---- /validate-optional ------------------------------------------------
    # Always returns 200. Sets X-Auth-User / X-WEBAUTH-USER only when a valid
    # abc_session cookie is present. Used by the Grafana Caddy proxy so that
    # unauthenticated visitors reach Grafana's [auth.anonymous] Viewer role
    # rather than being redirected to the login form.

    def _validate_optional(self):
        cookies  = _parse_cookies(self.headers.get("Cookie", ""))
        token    = cookies.get(SESSION_COOKIE_NAME)
        username = None
        if token:
            u, ok = _verify_session_token(token)
            if ok:
                state = _cached_slot_state(u)
                if state not in ("suspended", "expired"):
                    username = u

        self.send_response(200)
        if username:
            self.send_header("X-Auth-User",    username)
            self.send_header("Remote-User",    username)
            self.send_header("X-WEBAUTH-USER", username)
        self.end_headers()

    # ---- POST /auth/cli-token ----------------------------------------------
    # Called by `abc portal open` to obtain a one-time magic link URL.
    # Body (JSON): {"nomad_token": "<token>", "next": "<url>"}
    # Response: {"url": "https://<workbench>/auth/redeem?code=<hex>"}
    # The code is single-use and expires after CLI_TOKEN_TTL seconds (default 60).

    def _cli_token_post(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self._json(400, {"error": "missing request body"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except Exception:
            self._json(400, {"error": "invalid JSON"})
            return

        nomad_token   = (body.get("nomad_token") or "").strip()
        next_url      = (body.get("next") or "/").strip()
        portal        = (body.get("portal") or "").strip().lower()
        minio_password = (body.get("minio_password") or "").strip()
        if not nomad_token:
            self._json(400, {"error": "nomad_token required"})
            return

        # Validate the Nomad token via Nomad ACL self-lookup
        info = _lookup_nomad_token(nomad_token)
        if not info:
            self._json(401, {"error": "invalid or expired Nomad token"})
            return
        # Derive username from the token name (strip pool- prefix, same as NomadWhoamiLabel)
        raw_name = (info.get("Name") or "").strip()
        username = raw_name.removeprefix("pool-") if raw_name else raw_name
        if not username:
            self._json(401, {"error": "could not determine username from token"})
            return

        # Slot state check — suspended/expired users cannot get a magic link
        state = _cached_slot_state(username)
        if state in ("suspended", "expired"):
            self._json(403, {"error": f"slot is {state}"})
            return

        # Always store portal type so _auth_redeem can use it without relying on Host header
        extra = {"portal": portal} if portal else {}
        if portal == "minio":
            # Use the explicitly provided minio_password; fall back to nomad_token
            # (pool users share the same secret for both Nomad and MinIO).
            minio_pw = minio_password or nomad_token
            minio_jwt = _minio_console_login(username, minio_pw)
            if minio_jwt:
                extra["minio_token"] = minio_jwt
            else:
                print(f"[auth-svc] WARNING: MinIO console pre-login failed for {username!r}; "
                      "falling back to credential display", file=sys.stderr)

        code = _cli_codes_issue(username, next_url, extra)
        # Return only the code — the CLI constructs the full redeem URL from
        # its known authBase (public hostname), avoiding the internal Tailscale
        # IP that would appear if we built the URL from the Host header here.
        resp_body = json.dumps({"code": code, "ttl": CLI_TOKEN_TTL}).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.send_header("Cache-Control",  "no-store")
        self.end_headers()
        self.wfile.write(resp_body)
        self._log(f"CLI_TOKEN issued user={username!r} next={next_url!r}")

    # ---- GET /auth/redeem --------------------------------------------------
    # Redeems a one-time magic link code. Sets session cookie, redirects to next_url.
    # Called by the browser after `abc portal open` fires the magic link URL.

    def _auth_redeem(self, query_str: str):
        params = parse_qs(query_str)
        code   = (params.get("code", [""])[0]).strip()
        if not code:
            self.send_response(302)
            self.send_header("Location", "/auth/login?error=missing_code")
            self.end_headers()
            return

        result = _cli_codes_redeem(code)
        if result is None:
            self.send_response(302)
            self.send_header("Location", "/auth/login?error=link_expired")
            self.end_headers()
            self._log("CLI_TOKEN redeem FAILED (invalid/expired code)")
            return

        username, next_url, extra = result
        token = _make_session_token(username)

        # Determine the redirect target after setting the session cookie.
        # The next_url stored in the code was generated by abc-auth-svc itself
        # (not user-supplied) so it is safe to redirect to directly, provided it
        # is within the cluster's trusted domain.  _safe_next is only needed for
        # user-supplied URLs (e.g. the ?next= query param on /auth/login).
        portal_stored = extra.get("portal", "")
        host = self.headers.get("Host", "")
        if portal_stored == "grafana" or "grafana." in host:
            # Grafana needs /login to force auth-proxy re-evaluation and
            # clear any cached anonymous session before landing on /.
            safe_next = "/login"
        elif next_url and _is_trusted_redirect(next_url):
            # Absolute cluster URL stored by the server — redirect directly so
            # upload.seedling.*, grafana.*, etc. all work as next destinations.
            safe_next = next_url
        else:
            safe_next = self._safe_next(next_url)

        self.send_response(302)
        self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE_NAME, token, SESSION_TTL_SECONDS))
        self.send_header("Location",   safe_next)
        self.end_headers()
        self._log(f"CLI_TOKEN redeem OK user={username!r} next={safe_next!r}")

    # ---- GET /auth/minio-login ---------------------------------------------
    # Called by the browser after `abc portal open minio`. This endpoint is
    # served from minio.seedling.abc-cluster.cloud (via the edge Caddy routing
    # /auth/minio-login* → abc-auth-svc) so the MinIO token cookie is set for
    # the correct domain.
    #
    # Redeems the one-time code, sets the MinIO console token cookie, then
    # redirects the browser to the MinIO console root.

    def _auth_minio_login(self, query_str: str):
        params = parse_qs(query_str)
        code   = (params.get("code", [""])[0]).strip()
        if not code:
            self.send_response(302)
            self.send_header("Location", "/?error=missing_code")
            self.end_headers()
            return

        result = _cli_codes_redeem(code)
        if result is None:
            self.send_response(302)
            self.send_header("Location", "/?error=link_expired")
            self.end_headers()
            self._log("MINIO_LOGIN redeem FAILED (invalid/expired code)")
            return

        username, _next, extra = result
        minio_token = extra.get("minio_token", "")

        if not minio_token:
            # Fallback: try a fresh MinIO console login (code may have been issued
            # before MinIO SSO was available, or the pre-login failed earlier)
            minio_token = _minio_console_login(username, "") or ""

        if not minio_token:
            # MinIO SSO unavailable — redirect to MinIO console login page
            self._log(f"MINIO_LOGIN no token for {username!r}, redirecting to login form")
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        # Set the MinIO console token cookie. SameSite=Lax matches MinIO's own
        # behaviour. The cookie is for this domain (minio.seedling.*) because
        # this request came from the browser visiting minio.seedling.abc-cluster.cloud.
        # Secure is gated on COOKIE_SECURE so air-gapped HTTP-only LANs work.
        cookie_parts = [
            f"token={minio_token}", "Path=/", "Max-Age=43200",
            "SameSite=Lax", "HttpOnly",
        ]
        if COOKIE_SECURE:
            cookie_parts.append("Secure")
        cookie = "; ".join(cookie_parts)
        self.send_response(302)
        self.send_header("Set-Cookie", cookie)
        self.send_header("Location",   "/")
        self.end_headers()
        self._log(f"MINIO_LOGIN OK user={username!r}")

    # ---- /auth/login (GET) -------------------------------------------------

    def _serve_login(self, next_url: str = "/", error: str = ""):
        error_block = f'<div class="error-block">{error}</div>' if error else ""
        body = _LOGIN_HTML.format(error_block=error_block, next_url=next_url).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-store")
        self.end_headers()
        self.wfile.write(body)

    # ---- /auth/login (POST) ------------------------------------------------

    def _login_post(self):
        length   = int(self.headers.get("Content-Length", 0))
        body     = self.rfile.read(length).decode(errors="replace")
        params   = parse_qs(body, keep_blank_values=True)
        username = (params.get("username", [""])[0]).strip()
        password = (params.get("password", [""])[0]).strip()
        next_url = self._safe_next(params.get("next", ["/"])[0])

        if not username or not password:
            self._serve_login(next_url, "Username and password are required.")
            return

        if not _validate_minio(username, password):
            self._serve_login(next_url, "Invalid username or password.")
            self._log(f"LOGIN FAIL user={username!r}")
            return

        # MinIO credentials are valid — check slot state in PocketBase.
        # Non-pool users (e.g. abc-admin) won't have a slot row; allow through.
        try:
            slot = _pb_find_slot(f"minio_access_key='{username}'")
            if slot:
                state = slot.get("state", "")
                if state == "suspended":
                    self._serve_login(next_url, "Account suspended. Contact your administrator.")
                    self._log(f"LOGIN BLOCKED suspended user={username!r}")
                    return
                if state == "expired":
                    self._serve_login(next_url, "Account is no longer active.")
                    self._log(f"LOGIN BLOCKED expired user={username!r}")
                    return
        except Exception as e:
            # PocketBase unavailable — log but don't block login.
            print(f"[auth-svc] PocketBase slot check failed for {username!r}: {e}", file=sys.stderr)

        token = _make_session_token(username)
        self.send_response(302)
        self.send_header("Location",   next_url)
        self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE_NAME, token, SESSION_TTL_SECONDS))
        self.end_headers()
        self._log(f"LOGIN OK  user={username!r}")

    # ---- /auth/logout ------------------------------------------------------

    def _logout(self):
        self.send_response(302)
        self.send_header("Location",   "/auth/login")
        self.send_header("Set-Cookie", _cookie_header(SESSION_COOKIE_NAME, "", 0))
        self.end_headers()

    # ---- /workbench/token (POST) -------------------------------------------
    # Laptop-side `abc workbench connect` mints a JupyterHub user token via
    # this endpoint. Auth: the CLI's existing Nomad token (Bearer or
    # X-Nomad-Token header — same pattern as /verify and /auth/me). The
    # JH-admin token is held only by auth-svc.
    #
    # See $ABC_UNIVERSE/brainstorms/abc-workbench/2026-06-01-workbench-connect-laptop-flow.md
    def _workbench_token_post(self):
        # Authenticate the caller (laptop CLI carries a Nomad token).
        token = self.headers.get("X-Nomad-Token", "")
        if not token:
            auth = self.headers.get("Authorization", "")
            if auth[:7].lower() == "bearer ":
                token = auth[7:].strip()
        if not token:
            return self._json(401, {"error": "missing token (provide X-Nomad-Token or Authorization: Bearer)"})

        info = _lookup_nomad_token(token)
        if not info:
            return self._json(401, {"error": "invalid or expired token"})

        raw_name = (info.get("Name") or "").strip()
        if not raw_name:
            return self._json(401, {"error": "could not determine username from token"})

        # Pool tokens: Name = "pool-<pseudonym>" -> JH user = "<pseudonym>" (bare).
        # Caddy's /validate response sets Remote-User: <bare>; JH's HeaderAuthenticator
        # creates / matches the JH user under that bare name, so the mint target MUST
        # be bare too. (Historically this constructed "slot-<bare>" — the only legacy
        # user matching that pattern is "slot-calm_dassie" predating 2026-05-28.)
        # Admin/named tokens: Name = "<user>" -> JH user verbatim.
        if raw_name.startswith("pool-"):
            bare     = raw_name.removeprefix("pool-")
            jh_user  = bare
            abc_user = bare
        else:
            jh_user  = raw_name
            abc_user = raw_name

        # Block suspended/expired slots from minting (defence in depth - JH
        # itself has no slot-state model).
        state = _cached_slot_state(abc_user)
        if state in ("suspended", "expired"):
            return self._json(403, {"error": f"slot is {state}"})

        # Read optional body: { note, expires_in }.
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body_raw = self.rfile.read(length) if length > 0 else b""
        try:
            body = json.loads(body_raw) if body_raw else {}
        except (ValueError, TypeError):
            return self._json(400, {"error": "invalid JSON body"})

        note = (body.get("note") or "").strip() or f"abc-cli-{abc_user}"
        expires_in = body.get("expires_in")
        if expires_in is not None:
            try:
                expires_in = int(expires_in)
            except (TypeError, ValueError):
                return self._json(400, {"error": "expires_in must be an integer (seconds)"})
            if expires_in <= 0:
                return self._json(400, {"error": "expires_in must be positive"})
            # Server-side ceiling: 30d max (CLI default is 7d).
            if expires_in > 30 * 24 * 3600:
                return self._json(400, {"error": "expires_in cannot exceed 30 days (2592000 seconds)"})
        else:
            expires_in = 7 * 24 * 3600  # default 7d

        # Mint via JH admin API.
        try:
            jh_resp = _jh_mint_user_token(jh_user, note, expires_in)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode(errors="replace") if hasattr(e, "read") else ""
            # Classify the 403/404 by probing whether the JH user actually
            # exists. Saves "alloc-exec + journalctl + ssh" hunts: the failure
            # mode is one of three, and they're disambiguated by a single
            # follow-up GET /users/<u>.
            diag = ""
            if e.code in (403, 404):
                exists = _jh_user_exists(jh_user)
                if exists is False:
                    diag = (f" — DIAG: JH user {jh_user!r} not found "
                            f"(GET /users/{jh_user} → 404). Either the mint "
                            f"name is wrong (compare against Caddy Remote-User "
                            f"for this slot), or the user has never logged in "
                            f"via the browser to auto-create.")
                elif exists is True:
                    diag = (f" — DIAG: JH user {jh_user!r} EXISTS — 403 is "
                            f"most likely insufficient scope on the auth-svc "
                            f"role (need 'tokens' + access to target user) or "
                            f"a stale JUPYTERHUB_API_TOKEN. Inspect "
                            f"tljh-custom.py auth-svc-role scopes.")
                else:
                    diag = (" — DIAG: JH user-existence probe failed "
                            "(Hub unreachable or admin token bad)")
            print(f"[auth-svc] hub mint {jh_user!r}: HTTP {e.code}: "
                  f"{err_body}{diag}", file=sys.stderr)
            return self._json(502, {
                "error": f"hub mint failed: HTTP {e.code}",
                "diag":  diag.lstrip(" —") or None,
                "hint":  f"GET /manage/slots/{abc_user}/diag (operator-gated) "
                         f"for a structured readiness report.",
            })
        except Exception as e:
            print(f"[auth-svc] hub mint {jh_user!r}: {e}", file=sys.stderr)
            return self._json(503, {"error": f"hub unreachable: {e}"})

        # Audit (stderr at seedling; XTDB at cloud tier when Jurist lands).
        print(f"[auth-svc] hub-token mint OK: user={jh_user} note={note!r} expires_in={expires_in}", file=sys.stderr)

        self._json(200, {
            "token":      jh_resp.get("token"),
            "id":         jh_resp.get("id"),
            "expires_at": jh_resp.get("expires_at"),
            "scopes":     jh_resp.get("scopes", []),
            "note":       jh_resp.get("note", note),
            "slot":       jh_user,
            "hub_url":    os.getenv("HUB_PUBLIC_URL", "https://workbench.seedling.abc-cluster.cloud"),
        })

    # ---- /slots/claim (POST) -----------------------------------------------

    def _claim_slot(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except Exception:
            self._json(400, {"error": "invalid_json"})
            return

        claim_code = (body.get("claim_code") or "").strip()
        name       = (body.get("name") or "").strip()
        email      = (body.get("email") or "").strip()
        # Phase 1.4: optional cred_source opt-in. Resolution priority:
        #   1. Explicit body field (passed by `abc auth claim --cred-source=…`).
        #   2. Group-level default (`groups.cred_source_default`).
        #   3. Empty / "local" (today's behaviour).
        requested_cred_source = (body.get("cred_source") or "").strip().lower()

        if not claim_code:
            self._json(400, {"error": "claim_code_required"})
            return

        # Validate the requested cred_source early (before locking) so users
        # get a clean error rather than a half-applied claim.
        if requested_cred_source and requested_cred_source not in ("local", "seedling/v1"):
            self._json(400, {"error": "invalid_cred_source",
                              "requested": requested_cred_source,
                              "allowed": ["local", "seedling/v1"]})
            return

        with _claim_lock:
            try:
                # 1. Find unclaimed slot with this code (admin token sees hidden fields)
                slot = _pb_find_slot(f"claim_code='{claim_code}'&&state='unclaimed'")
                if not slot:
                    self._json(404, {"error": "code_invalid_or_used"})
                    return

                # 2. Resolve effective cred_source. If the request didn't
                # specify, fall back to the group-level default.
                effective_cred_source = requested_cred_source
                if not effective_cred_source:
                    gid = slot.get("group")
                    if gid:
                        try:
                            grp = _pb_get(f"/api/collections/groups/records/{gid}")
                            effective_cred_source = (grp.get("cred_source_default") or "").strip().lower()
                        except Exception as e:
                            print(f"[auth-svc] claim: group lookup for cred_source_default failed: {e}",
                                  file=sys.stderr)
                # Normalise empty → local
                if not effective_cred_source:
                    effective_cred_source = "local"

                # 3. Mint opaque + hash if claiming into seedling/v1.
                opaque_for_render = ""
                slot_patch = {
                    "state":            "claimed",
                    "claimed_by_name":  name,
                    "claimed_by_email": email,
                    "claimed_at":       datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000Z"),
                }
                if effective_cred_source == "seedling/v1":
                    opaque_for_render = _mint_opaque_token()
                    slot_patch["cred_source"]       = "seedling/v1"
                    slot_patch["opaque_token_hash"] = _hash_opaque(opaque_for_render)
                # For "local" we deliberately do NOT write an empty cred_source —
                # leaving the field absent preserves perfect parity with pre-Phase-1
                # rows. The renderer treats "" and "local" identically.

                # 4. Apply the patch
                _pb_patch(f"/api/collections/slots/records/{slot['id']}", slot_patch)
            except Exception as e:
                print(f"[auth-svc] claim error: {e}", file=sys.stderr)
                self._json(500, {"error": "internal_error"})
                return

        # Render the config YAML, persist it as a cached blob on the slot
        # record in PocketBase, and use the returned bytes as the response.
        # _persist_slot_config is the single writer for slot.config_yaml —
        # see the module-level docstring above its definition.
        # For seedling/v1 claims we MUST pass the bare opaque now (it'll never
        # exist again — only its hash is persisted).
        try:
            config_yaml = _persist_slot_config(slot["id"], opaque_token=opaque_for_render)
        except Exception as e:
            print(f"[auth-svc] claim: blob render/persist failed for slot={slot['slot_name']!r}: {e}",
                  file=sys.stderr)
            self._json(500, {"error": "config_render_failed"})
            return

        filename   = f"abc-config-{slot['slot_name']}.yaml"
        body_bytes = config_yaml.encode()
        self.send_response(200)
        self.send_header("Content-Type",        "application/yaml")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length",      str(len(body_bytes)))
        self.send_header("Cache-Control",       "no-store")
        self.end_headers()
        self.wfile.write(body_bytes)
        self._log(f"CLAIM OK  slot={slot['slot_name']!r} name={name!r}")

    # ---- /slots/me/config (GET) --------------------------------------------
    # Returns the calling slot's rendered config.yaml from PocketBase. Powers
    # the `abc auth config refresh` CLI verb so a user can re-pull their
    # canonical config on a fresh laptop / second machine / after a rotation
    # without re-using their claim code.
    #
    # Auth: same shape as /verify — the caller's Nomad token, accepted via
    # X-Nomad-Token header OR `Authorization: Bearer <token>`. The token's
    # `Name` field (minus the "pool-" prefix) identifies the slot.
    #
    # Body: the YAML bytes directly (Content-Type: text/yaml) so the CLI can
    # write it to ~/.abc/config.yaml without JSON unwrapping.
    # See: brainstorms/abc-seedling-onboarding/2026-06-01-claim-time-config-dropthrough.md

    def _slots_me_config(self):
        token = self.headers.get("X-Nomad-Token", "")
        if not token:
            auth = self.headers.get("Authorization", "")
            if auth[:7].lower() == "bearer ":
                token = auth[7:].strip()
        if not token:
            self._json(401, {"error": "missing_token"})
            return

        info = _lookup_nomad_token(token)
        if not info:
            self._json(401, {"error": "invalid_or_expired_token"})
            return

        raw_name = (info.get("Name") or "").strip()
        slot_name = raw_name.removeprefix("pool-") if raw_name else ""
        if not slot_name:
            self._json(401, {"error": "could_not_determine_slot"})
            return

        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
        except Exception as e:
            print(f"[auth-svc] /slots/me/config lookup failed for {slot_name!r}: {e}", file=sys.stderr)
            self._json(500, {"error": "internal_error"})
            return

        if not slot:
            self._json(404, {"error": "slot_not_found"})
            return

        if slot.get("state") not in ("claimed",):
            self._json(403, {"error": f"slot_{slot.get('state') or 'unknown'}"})
            return

        blob = slot.get("config_yaml") or ""
        if not blob:
            # Slot exists + is claimed but has no rendered blob yet (claim
            # predates this feature, or the renderer pass hasn't run).
            # Re-render on demand so the caller is never blocked on it.
            try:
                blob = _persist_slot_config(slot["id"])
            except Exception as e:
                print(f"[auth-svc] /slots/me/config render failed for {slot_name!r}: {e}", file=sys.stderr)
                self._json(500, {"error": "config_render_failed"})
                return

        body = blob.encode()
        filename = f"abc-config-{slot_name}.yaml"
        self.send_response(200)
        self.send_header("Content-Type",        "text/yaml")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length",      str(len(body)))
        self.send_header("Cache-Control",       "no-store")
        self.end_headers()
        self.wfile.write(body)
        self._log(f"CONFIG REFRESH slot={slot_name!r}")

    # ---- POST /auth/exchange (Phase 1: cred_source=seedling/v1) ------------
    #
    # The CLI's SeedlingV1CredSource calls this to turn an opaque user token
    # into real Nomad+MinIO credentials (Pattern A — short-form returns full
    # creds; the CLI caches them for 5 min in memory).
    #
    # Auth: Authorization: Bearer <opaque>. We hash the bearer, look up the
    # slot by opaque_token_hash, and return its real creds as JSON if the
    # slot is claimed. Suspended/expired slots are rejected.
    #
    # The bare opaque never leaves the user; only its hash lives on the
    # server. Even with full PocketBase access an operator cannot reconstruct
    # an opaque from a hash, so users still hold a meaningful secret.

    def _auth_exchange(self):
        auth = self.headers.get("Authorization", "")
        if auth[:7].lower() != "bearer ":
            self._json(401, {"error": "missing_bearer_token"})
            return
        opaque = auth[7:].strip()
        if not opaque:
            self._json(401, {"error": "empty_bearer_token"})
            return

        try:
            slot = _pb_find_slot_by_opaque(opaque)
        except Exception as e:
            print(f"[auth-svc] /auth/exchange lookup failed: {e}", file=sys.stderr)
            self._json(500, {"error": "internal_error"})
            return

        if not slot:
            # Same response for "no such opaque" and "wrong state" — don't
            # leak the existence of a token we just suspended.
            self._json(401, {"error": "invalid_or_inactive_token"})
            return

        # Defensive: even though _pb_find_slot_by_opaque filters on
        # cred_source-agnostic state='claimed', double-check the slot is
        # actually opted into the seedling/v1 pathway. A misconfigured slot
        # with an opaque_token_hash but cred_source!='seedling/v1' should not
        # silently exchange.
        if (slot.get("cred_source") or "") != "seedling/v1":
            slot_name = slot.get("slot_name") or "?"
            print(f"[auth-svc] /auth/exchange: slot {slot_name!r} has opaque but cred_source={slot.get('cred_source')!r}",
                  file=sys.stderr)
            self._json(409, {"error": "slot_not_on_seedling_v1"})
            return

        try:
            bundle = _build_creds_bundle(slot)
        except Exception as e:
            print(f"[auth-svc] /auth/exchange build bundle failed for {slot.get('slot_name')!r}: {e}",
                  file=sys.stderr)
            self._json(500, {"error": "build_bundle_failed"})
            return

        self._log(f"AUTH EXCHANGE slot={slot.get('slot_name')!r}")
        self._json(200, bundle)

    # ---- POST /secrets/{put,get} (D2: secret_source=seedling/v1) ------------
    #
    # The CLI's broker secrets backend (internal/secretsource) calls these to
    # store/fetch a USER-OWNED secret (the crypt password, or any `abc secrets`
    # entry) PORTABLY. Unlike the admin nomad backend, the caller holds NO Nomad
    # ACL: we authenticate the opaque (same as /auth/exchange), then read/write a
    # Nomad Variable on the user's behalf using the broker's own management token.
    #
    # Path: abc/users/<slot>/<key> in the slot's group namespace (su-<group>), or
    # the explicit `group` namespace for the job-runtime lane.
    #
    # Trust: MANAGED (operator-readable) — the value lives in plaintext in a Nomad
    # Variable the operator can read. Non-regulated scratch only until the
    # client-side envelope ships. Every op emits an audit line (closes the POPIA
    # §19 unlogged-access gap raised in the security review).

    def _secrets_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length)) or {}
        except Exception:
            return None

    def _secrets_auth_slot(self):
        auth = self.headers.get("Authorization", "")
        if auth[:7].lower() != "bearer ":
            self._json(401, {"error": "missing_bearer_token"})
            return None
        opaque = auth[7:].strip()
        if not opaque:
            self._json(401, {"error": "empty_bearer_token"})
            return None
        try:
            slot = _pb_find_slot_by_opaque(opaque)
        except Exception as e:
            print(f"[auth-svc] /secrets auth lookup failed: {e}", file=sys.stderr)
            self._json(500, {"error": "internal_error"})
            return None
        if not slot:
            self._json(401, {"error": "invalid_or_inactive_token"})
            return None
        return slot

    def _secrets_ns_and_path(self, slot, key, group=""):
        slot_name  = (slot.get("slot_name") or "").strip()
        group_name = (group or _resolve_group_name_from_slot(slot) or "").strip()
        ns   = f"su-{group_name}" if group_name else "default"
        path = f"abc/users/{slot_name}/{key}"
        return ns, path

    def _secrets_put(self):
        slot = self._secrets_auth_slot()
        if not slot:
            return
        body = self._secrets_body()
        if body is None:
            self._json(400, {"error": "bad_json"})
            return
        key   = (body.get("key") or "").strip()
        value = body.get("value")
        group = (body.get("group") or "").strip()
        if not key or value is None:
            self._json(400, {"error": "key_and_value_required"})
            return
        ns, path = self._secrets_ns_and_path(slot, key, group)
        try:
            _nomad_api("PUT", f"/v1/var/{path}?namespace={urllib.parse.quote(ns)}",
                       {"Path": path, "Namespace": ns, "Items": {"value": str(value)}})
        except Exception as e:
            print(f"[auth-svc] /secrets/put store failed: {e}", file=sys.stderr)
            self._json(500, {"error": "store_failed"})
            return
        self._log(f"SECRETS PUT slot={slot.get('slot_name')!r} key={key!r} ns={ns}")
        self._json(200, {"ok": True})

    def _secrets_get(self):
        slot = self._secrets_auth_slot()
        if not slot:
            return
        body = self._secrets_body()
        if body is None:
            self._json(400, {"error": "bad_json"})
            return
        key = (body.get("key") or "").strip()
        if not key:
            self._json(400, {"error": "key_required"})
            return
        ns, path = self._secrets_ns_and_path(slot, key)
        try:
            resp = _nomad_api("GET", f"/v1/var/{path}?namespace={urllib.parse.quote(ns)}")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                self._json(404, {"error": "not_found"})
                return
            print(f"[auth-svc] /secrets/get read failed: {he}", file=sys.stderr)
            self._json(500, {"error": "read_failed"})
            return
        except Exception as e:
            print(f"[auth-svc] /secrets/get read failed: {e}", file=sys.stderr)
            self._json(500, {"error": "read_failed"})
            return
        items = (resp or {}).get("Items") or {}
        val = items.get("value")
        if val is None:
            self._json(404, {"error": "not_found"})
            return
        self._log(f"SECRETS GET slot={slot.get('slot_name')!r} key={key!r} ns={ns}")
        self._json(200, {"value": val})

    # ---- /manage/* — operator token gate -----------------------------------

    def _require_operator(self) -> bool:
        """Return True if request carries a valid operator token, else send 401."""
        token = self.headers.get("X-Operator-Token", "")
        if not OPERATOR_TOKEN or not hmac.compare_digest(token, OPERATOR_TOKEN):
            self._json(401, {"error": "unauthorized"})
            return False
        return True

    # ---- /manage/slots (GET) -----------------------------------------------

    def _manage_list_slots(self):
        if not self._require_operator():
            return
        try:
            resp  = _pb_get(
                "/api/collections/slots/records?perPage=500&skipTotal=1"
                "&fields=id,slot_name,group,state,claimed_by_name,claimed_by_email,claimed_at,minio_access_key"
            )
            self._json(200, resp.get("items", []))
        except Exception as e:
            self._json(500, {"error": str(e)})

    # ---- /manage/slots/:slot (GET) -----------------------------------------

    def _manage_get_slot(self, slot_name: str):
        if not self._require_operator():
            return
        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
            if not slot:
                self._json(404, {"error": "not_found"})
                return
            for f in ("claim_code", "nomad_token_secret", "minio_secret_key"):
                slot.pop(f, None)
            self._json(200, slot)
        except Exception as e:
            self._json(500, {"error": str(e)})

    # ---- /manage/slots/:slot/diag (GET) ------------------------------------
    # Comprehensive readiness probe: returns a structured report of every
    # condition that has to be true for `abc workbench connect` AND browser
    # spawn to work end-to-end. Designed so a single curl answers "why
    # doesn't <slot> work?" without ssh + journalctl + alloc-exec hunts.
    #
    # Output schema:
    #   {slot, pb:{state, minio_access_key, group, …},
    #    jh:{api_url, admin_token_prefix, user_exists, …},
    #    host:{unix_user, workbench_home, minio_creds_file, abc_config_file},
    #    checks:[{check, ok, detail?}],
    #    verdict: "ready" | "blocked_at: <check>, <check>, …",
    #    remediation_hints: [<shell-runnable suggestions>]}
    #
    # Auth: X-Operator-Token (same as the other /manage/* surface).

    def _manage_diag_slot(self, slot_name: str):
        if not self._require_operator():
            return
        import os as _os
        import pwd as _pwd

        report = {
            "slot": slot_name, "pb": {}, "jh": {}, "host": {},
            "checks": [], "verdict": None, "remediation_hints": [],
        }
        def chk(name, ok, detail=None):
            entry = {"check": name, "ok": bool(ok)}
            if detail:
                entry["detail"] = detail
            report["checks"].append(entry)

        # 1) PocketBase row
        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
        except Exception as e:
            chk("pb_row_present", False, f"lookup error: {e}")
            self._json(200, report); return
        if not slot:
            chk("pb_row_present", False, "no record")
            report["verdict"] = "blocked_at: pb_row_present"
            self._json(200, report); return
        chk("pb_row_present", True)
        for k in ("state", "minio_access_key", "group",
                  "nomad_token_accessor", "claimed_at", "claimed_by_name"):
            if k in slot:
                report["pb"][k] = slot[k]
        chk("pb_state_claimed", slot.get("state") == "claimed",
            f"state={slot.get('state')!r}")

        # 2) JH: user presence + admin-token shape
        jh_tok = JUPYTERHUB_API_TOKEN or ""
        report["jh"] = {
            "api_url": JUPYTERHUB_API_URL,
            "admin_token_prefix": (jh_tok[:8] if jh_tok else "(unset)"),
            "admin_token_len": len(jh_tok),
        }
        if not jh_tok:
            chk("jh_admin_token_real", False, "JUPYTERHUB_API_TOKEN unset")
        elif "REPLACE_WITH" in jh_tok:
            chk("jh_admin_token_real", False,
                "placeholder value (install-auth-svc.sh did not substitute)")
        else:
            chk("jh_admin_token_real", len(jh_tok) >= 32)

        exists = _jh_user_exists(slot_name)
        report["jh"]["user_name_checked"] = slot_name
        report["jh"]["user_exists"] = exists
        chk("jh_user_present", exists is True,
            (f"GET /users/{slot_name} → 404" if exists is False
             else ("probe failed" if exists is None else None)))

        # 3) Host: unix user, workbench home, minio-creds, abc-config
        sys_user = f"jupyter-{slot_name}"
        try:
            pw = _pwd.getpwnam(sys_user)
            uid = pw.pw_uid
            report["host"]["unix_user"] = {
                "name": sys_user, "exists": True, "uid": uid}
            chk("unix_user_present", True)
        except KeyError:
            uid = None
            report["host"]["unix_user"] = {"name": sys_user, "exists": False}
            chk("unix_user_present", False,
                f"no system user {sys_user!r} on this host")

        home = f"/data/workbench/{slot_name}/home"
        home_present = _os.path.isdir(home)
        owner_uid = _os.stat(home).st_uid if home_present else None
        report["host"]["workbench_home"] = {
            "path": home,
            "exists": home_present,
            "owner_uid": owner_uid,
            "owner_matches": (uid is not None and owner_uid == uid),
        }
        chk("workbench_home_present", home_present,
            (f"missing: {home}" if not home_present else None))
        if home_present:
            chk("workbench_home_owned_by_user",
                uid is not None and owner_uid == uid,
                (f"owner uid {owner_uid} != {uid}"
                 if uid is not None and owner_uid != uid else None))

        for label, path in (
            ("minio_creds_file", f"/etc/jupyterhub/minio-creds/{slot_name}"),
            ("abc_config_file",  f"/etc/jupyterhub/abc-configs/{slot_name}"),
        ):
            present = _os.path.exists(path)
            report["host"][label] = {"path": path, "exists": present}
            chk(f"{label}_present", present,
                (f"missing: {path}" if not present else None))

        # 4) Verdict + remediation hints
        failed = [c["check"] for c in report["checks"] if not c["ok"]]
        report["verdict"] = "ready" if not failed else \
            "blocked_at: " + ", ".join(failed)

        hints = []
        names = {c["check"] for c in report["checks"] if not c["ok"]}
        if "workbench_home_present" in names \
                or "workbench_home_owned_by_user" in names:
            hints.append(
                f"mkdir -p {home} && "
                f"chown -R {sys_user}:{sys_user} {home} && "
                f"chmod 750 {home}")
        if "jh_user_present" in names:
            hints.append(
                f"User auto-creates on first browser login at "
                f"https://workbench.../ (Caddy injects Remote-User={slot_name}); "
                f"OR pre-create: curl -X POST -H 'Authorization: token <admin>' "
                f"{JUPYTERHUB_API_URL}/users/{slot_name}")
        if "minio_creds_file_present" in names \
                or "abc_config_file_present" in names:
            hints.append(
                f"bash provision-pool-user.sh {slot_name} <minio_secret_key>  "
                f"# OR POST /manage/slots/{slot_name}/rotate to re-mint creds")
        if "jh_admin_token_real" in names:
            hints.append(
                "Re-run install-auth-svc.sh to substitute the "
                "JUPYTERHUB_API_TOKEN placeholder, then alloc-restart auth-svc")
        if "pb_state_claimed" in names \
                and slot.get("state") == "unclaimed":
            hints.append(
                f"Slot {slot_name!r} is unclaimed in PocketBase — "
                f"flow it through POST /slots/claim with a claim_code, "
                f"or manually update the PB record to state='claimed'")
        report["remediation_hints"] = hints
        self._json(200, report)

    # ---- /manage/slots/:slot/rotate (POST) ---------------------------------

    def _manage_rotate(self, slot_name: str):
        if not self._require_operator():
            return
        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
            if not slot:
                self._json(404, {"error": "not_found"})
                return
            if slot.get("state") not in ("claimed", "suspended"):
                self._json(400, {"error": "slot_not_active"})
                return

            muser        = slot.get("minio_access_key", f"slot-{slot_name}")
            old_accessor = slot.get("nomad_token_accessor", "")
            group_name   = self._resolve_group_name(slot)
            role_name    = f"r-su-{group_name}-pool"
            role_id      = _nomad_get_role_id(role_name)

            new_minio_secret = _minio_rotate_secret(muser)
            new_acc, new_sec = _nomad_create_token(slot_name, group_name, role_id or "")

            _pb_patch(f"/api/collections/slots/records/{slot['id']}", {
                "minio_secret_key":     new_minio_secret,
                "nomad_token_accessor": new_acc,
                "nomad_token_secret":   new_sec,
            })

            if old_accessor:
                _nomad_delete_token(old_accessor)

            self._write_creds_files(slot_name, muser, new_minio_secret)

            # Cross-portal coherence on credential rotation:
            #   1. Re-render the config_yaml blob so spawn hook + future
            #      `abc auth config refresh` serve the new creds (else stale).
            #   2. Flush /validate's per-user cache so existing abc_session
            #      cookies signed against the old MinIO password don't grant
            #      access on the next request (mirrors _manage_suspend).
            #   3. Stop any running JupyterHub server so its in-process env
            #      vars (injected at spawn time from the OLD secret) get
            #      reset on next login (mirrors _manage_suspend).
            # See: brainstorms/abc-seedling-onboarding/2026-06-01-claim-time-config-dropthrough.md
            _persist_slot_config(slot["id"])
            _invalidate_slot_cache(muser)
            _jh_stop_server(slot_name)

            self._json(200, {"ok": True})
            self._log(f"ROTATE OK slot={slot_name!r}")
        except Exception as e:
            print(f"[auth-svc] rotate error {slot_name}: {e}", file=sys.stderr)
            self._json(500, {"error": str(e)})

    # ---- /manage/slots/:slot/cred-source (POST) ----------------------------
    #
    # Flip a slot between the `local` and `seedling/v1` credential-source
    # pathways. Body: {"cred_source": "local" | "seedling/v1"}.
    #
    # local → seedling/v1:
    #   - Mint a fresh opaque token, store sha256(opaque) on the slot.
    #   - Re-render the blob in opaque shape (real creds NOT in YAML).
    #   - Return the bare opaque in the response — this is the ONLY moment
    #     it ever leaves the server. The admin must hand it to the user.
    #
    # seedling/v1 → local:
    #   - Clear opaque_token_hash + cred_source on the slot. Existing opaque
    #     tokens immediately stop authenticating against /auth/exchange.
    #   - Re-render the blob in real-creds shape (using the current Nomad +
    #     MinIO creds — no rotation needed; the same creds were always there).
    #
    # In both directions: trigger cross-portal coherence — the user's config
    # blob, the spawn hook's view of it, and any cached state must all flip
    # together. We reuse the same invalidate-cache + JH-bounce pattern as
    # _manage_rotate. (No actual MinIO / Nomad credential rotation happens
    # here — only the BROKER pathway selection changes.)

    def _manage_cred_source(self, slot_name: str):
        if not self._require_operator():
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b""
            body = json.loads(raw) if raw else {}
        except Exception:
            self._json(400, {"error": "bad_json_body"})
            return

        want = (body.get("cred_source") or "").strip().lower()
        if want not in ("local", "seedling/v1"):
            self._json(400, {"error": "invalid_cred_source",
                             "allowed": ["local", "seedling/v1"]})
            return

        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
            if not slot:
                self._json(404, {"error": "not_found"})
                return
            if slot.get("state") != "claimed":
                self._json(400, {"error": "slot_not_claimed"})
                return

            current = (slot.get("cred_source") or "").strip().lower() or "local"
            muser   = slot.get("minio_access_key", f"slot-{slot_name}")

            if want == current:
                self._json(200, {"ok": True, "cred_source": current,
                                  "changed": False})
                return

            response = {"ok": True, "cred_source": want, "changed": True,
                        "previous_cred_source": current}

            if want == "seedling/v1":
                # Mint a fresh opaque + persist hash + re-render blob in opaque shape.
                opaque = _mint_opaque_token()
                _pb_patch(f"/api/collections/slots/records/{slot['id']}", {
                    "cred_source":       "seedling/v1",
                    "opaque_token_hash": _hash_opaque(opaque),
                })
                _persist_slot_config(slot["id"], opaque_token=opaque)
                response["opaque_token"] = opaque
                response["note"] = ("This is the ONLY response containing the "
                                    "bare opaque. Hand it to the user and "
                                    "discard from logs.")
            else:  # want == "local"
                # Clear opaque + cred_source; re-render blob in real-creds shape.
                _pb_patch(f"/api/collections/slots/records/{slot['id']}", {
                    "cred_source":       "",
                    "opaque_token_hash": "",
                })
                _persist_slot_config(slot["id"])

            # Cross-portal coherence — the user's blob shape just flipped:
            #   1. /validate cache may have stale state (cred_source-agnostic
            #      today, but flushing is cheap insurance against future
            #      cred_source-dependent code).
            #   2. JH server bounce so the spawn hook re-reads the new blob.
            _invalidate_slot_cache(muser)
            _jh_stop_server(slot_name)

            self._json(200, response)
            self._log(f"CRED-SOURCE FLIP slot={slot_name!r} {current} → {want}")
        except Exception as e:
            print(f"[auth-svc] cred-source flip error {slot_name}: {e}", file=sys.stderr)
            self._json(500, {"error": str(e)})

    # ---- /manage/slots/:slot/suspend (POST) --------------------------------

    def _manage_suspend(self, slot_name: str):
        if not self._require_operator():
            return
        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
            if not slot:
                self._json(404, {"error": "not_found"})
                return
            if slot.get("state") != "claimed":
                self._json(400, {"error": "slot_not_claimed"})
                return

            muser    = slot.get("minio_access_key", f"slot-{slot_name}")
            accessor = slot.get("nomad_token_accessor", "")

            _mcli_safe("admin", "user", "disable", "sdroot", muser)
            if accessor:
                _nomad_delete_token(accessor)
            self._remove_creds_files(slot_name)

            _pb_patch(f"/api/collections/slots/records/{slot['id']}", {
                "state": "suspended",
            })

            # Kick out any active workbench session immediately
            _invalidate_slot_cache(muser)   # /validate cache → next request denied within ms
            _jh_stop_server(slot_name)       # kill JupyterHub server process

            self._json(200, {"ok": True})
            self._log(f"SUSPEND OK slot={slot_name!r}")
        except Exception as e:
            print(f"[auth-svc] suspend error {slot_name}: {e}", file=sys.stderr)
            self._json(500, {"error": str(e)})

    # ---- /manage/slots/:slot/reactivate (POST) -----------------------------

    def _manage_reactivate(self, slot_name: str):
        if not self._require_operator():
            return
        try:
            slot = _pb_find_slot(f"slot_name='{slot_name}'")
            if not slot:
                self._json(404, {"error": "not_found"})
                return
            if slot.get("state") != "suspended":
                self._json(400, {"error": "slot_not_suspended"})
                return

            muser      = slot.get("minio_access_key", f"slot-{slot_name}")
            group_name = self._resolve_group_name(slot)
            role_name  = f"r-su-{group_name}-pool"
            role_id    = _nomad_get_role_id(role_name)

            _mcli_safe("admin", "user", "enable", "sdroot", muser)
            new_minio_secret = _minio_rotate_secret(muser)
            new_acc, new_sec = _nomad_create_token(slot_name, group_name, role_id or "")

            _pb_patch(f"/api/collections/slots/records/{slot['id']}", {
                "state":                "claimed",
                "minio_secret_key":     new_minio_secret,
                "nomad_token_accessor": new_acc,
                "nomad_token_secret":   new_sec,
            })

            self._write_creds_files(slot_name, muser, new_minio_secret)
            _invalidate_slot_cache(muser)   # flush stale "suspended" from /validate cache
            self._json(200, {"ok": True})
            self._log(f"REACTIVATE OK slot={slot_name!r}")
        except Exception as e:
            print(f"[auth-svc] reactivate error {slot_name}: {e}", file=sys.stderr)
            self._json(500, {"error": str(e)})

    # ---- management helpers ------------------------------------------------

    def _resolve_group_name(self, slot: dict) -> str:
        """Get plain group name string from a slot record (resolves relation ID)."""
        gid = slot.get("group", "")
        if gid and len(gid) == 15:
            try:
                grp = _pb_get(f"/api/collections/groups/records/{gid}")
                return grp.get("name", "")
            except Exception:
                pass
        return slot.get("group_name", "")

    def _write_creds_files(self, slot_name: str, muser: str, msecret: str):
        """Write /etc/jupyterhub/minio-creds/<slot>."""
        creds = f"AWS_ACCESS_KEY_ID={muser}\nAWS_SECRET_ACCESS_KEY={msecret}\n"
        try:
            creds_dir = "/etc/jupyterhub/minio-creds"
            os.makedirs(creds_dir, exist_ok=True)
            cred_path = os.path.join(creds_dir, slot_name)
            with open(cred_path, "w") as f:
                f.write(creds)
            os.chmod(cred_path, 0o600)
        except Exception as e:
            print(f"[auth-svc] warn: creds file write failed for {slot_name}: {e}", file=sys.stderr)

    def _remove_creds_files(self, slot_name: str):
        """Remove creds files for a suspended slot (best-effort)."""
        for path in [
            f"/etc/jupyterhub/minio-creds/{slot_name}",
            f"/root/abc-configs/{slot_name}",
        ]:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except Exception as e:
                print(f"[auth-svc] warn: creds file remove {path}: {e}", file=sys.stderr)

    # ---- helpers -----------------------------------------------------------

    @staticmethod
    def _safe_next(url: str) -> str:
        url = unquote(url).strip()
        if not url.startswith("/"):
            return "/"
        return url

    def _ok(self, msg: str):
        self._respond(200, "text/plain", msg.encode())

    def _respond(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type",   ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control",  "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _log(self, msg: str):
        print(f"[auth-svc] {self.address_string()} — {msg}", file=sys.stderr)

    def log_message(self, fmt, *args):
        pass  # silence default access log; use _log() selectively


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _startup_check():
    """Verify PocketBase connectivity at startup and warm the token cache."""
    if not PB_ADMIN_PASSWORD:
        print("[auth-svc] PocketBase: SKIPPED (PB_ADMIN_PASSWORD not set)", file=sys.stderr)
        return
    try:
        _pb_token()
        print("[auth-svc] PocketBase: connected (admin auth OK)", file=sys.stderr)
    except Exception as e:
        print(f"[auth-svc] PocketBase: connection FAILED — {e}", file=sys.stderr)
        print("[auth-svc] WARNING: slot state checks will not enforce suspensions.", file=sys.stderr)


if __name__ == "__main__":
    print(f"[auth-svc] Starting on {AUTH_SVC_BIND}:{AUTH_SVC_PORT}", file=sys.stderr)
    print(f"[auth-svc] MinIO endpoint:     {MINIO_ENDPOINT}", file=sys.stderr)
    print(f"[auth-svc] Nomad endpoint:     {NOMAD_ADDR}", file=sys.stderr)
    print(f"[auth-svc] PocketBase URL:     {POCKETBASE_URL}", file=sys.stderr)
    print(f"[auth-svc] JupyterHub API URL: {JUPYTERHUB_API_URL}", file=sys.stderr)
    # JH admin-token shape — surface placeholder / blank loud without leaking
    # the real secret. Both drift surfaces from the deploy-drift memory show
    # up here in plain text on every restart.
    _jh_tok = JUPYTERHUB_API_TOKEN or ""
    if not _jh_tok:
        print("[auth-svc] JupyterHub admin token: UNSET — workbench mint WILL fail",
              file=sys.stderr)
    elif "REPLACE_WITH" in _jh_tok:
        print(f"[auth-svc] JupyterHub admin token: PLACEHOLDER ({_jh_tok}) "
              f"— run install-auth-svc.sh to substitute", file=sys.stderr)
    else:
        print(f"[auth-svc] JupyterHub admin token: {_jh_tok[:8]}…"
              f"({len(_jh_tok)} chars)", file=sys.stderr)
    # JH reachability probe — distinguishes "Hub down" / "wrong URL" from
    # "Hub up but token bad". Fails open: never blocks startup.
    try:
        _r = urllib.request.Request(
            f"{JUPYTERHUB_API_URL}",
            headers=({"Authorization": f"token {_jh_tok}"} if _jh_tok else {}))
        with urllib.request.urlopen(_r, timeout=3) as _resp:
            _body = _resp.read(200).decode(errors="replace").strip()
            print(f"[auth-svc] JupyterHub:        reachable "
                  f"(HTTP {_resp.status}, {_body[:80]!r})", file=sys.stderr)
    except urllib.error.HTTPError as _e:
        print(f"[auth-svc] JupyterHub:        reached but HTTP {_e.code} "
              f"({'admin token likely bad' if _e.code in (401, 403) else 'unexpected'})",
              file=sys.stderr)
    except Exception as _e:
        print(f"[auth-svc] JupyterHub:        UNREACHABLE — {_e}",
              file=sys.stderr)
    _startup_check()
    server = ThreadingHTTPServer((AUTH_SVC_BIND, AUTH_SVC_PORT), AuthHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[auth-svc] Shutting down", file=sys.stderr)
