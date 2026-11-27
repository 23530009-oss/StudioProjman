import base64
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

MASTER_SALT_STR = (os.environ.get("MASTER_SALT") or "").strip()
if not MASTER_SALT_STR:
    raise RuntimeError("CRITICAL ERROR: MASTER_SALT secret is not configured!")
MASTER_SALT = MASTER_SALT_STR.encode("utf-8")
QUIET_LOGS = str(os.environ.get("QUIET_LOGS", "0")).strip() == "1"


def _log(msg, verbose=False):
    if verbose and QUIET_LOGS:
        return
    print(msg)


def encrypt_data_aes(plain_text):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    key = hashlib.sha256(MASTER_SALT).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_data_aes(enc_b64):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    key = hashlib.sha256(MASTER_SALT).digest()
    combined = base64.b64decode(enc_b64)
    iv = combined[:16]
    ciphertext = combined[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    raw = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(raw) + unpadder.finalize()
    return decrypted.decode("utf-8")


_ENC_CFG_RAW = (os.environ.get("WORKER_CFG_ENC") or "").strip()
if not _ENC_CFG_RAW:
    raise RuntimeError("CRITICAL ERROR: WORKER_CFG_ENC secret is not configured!")
_CFG = json.loads(decrypt_data_aes(_ENC_CFG_RAW))

_UA = _CFG.get("ua", "TaskWorker/1.0")
_TZ_OFFSET = timedelta(minutes=int(_CFG.get("tz_min", 345)))
_STUDIO_TZ = timezone(_TZ_OFFSET)

STORE_BASE = (os.environ.get("STORE_BASE_URL") or _CFG.get("sb", "")).strip().rstrip("/")
if not STORE_BASE:
    raise RuntimeError("CRITICAL ERROR: Storage endpoint is not configured!")
STORE_TASKS_BASE = f"{STORE_BASE}/{_CFG['n_tasks']}"
STORE_STATUS_BASE = f"{STORE_BASE}/{_CFG['n_status']}"
STORE_SECRETS_BASE = f"{STORE_BASE}/{_CFG['n_secrets']}"
STORE_POOL_URL = f"{STORE_BASE}/{_CFG['n_pool']}"
STORE_AUTH_TOKEN = (os.environ.get("STORE_AUTH_TOKEN") or _CFG.get("sa", "")).strip()
EDGE_HOOK_URL = (os.environ.get("EDGE_HOOK_URL") or _CFG.get("eh", "")).strip().rstrip("/")


def _mask_gha_secret(val):
    if os.environ.get("GITHUB_ACTIONS") == "true" and val:
        s = str(val).strip()
        if len(s) >= 4:
            print(f"::add-mask::{s}", flush=True)


for _secret_val in (
    STORE_BASE,
    STORE_AUTH_TOKEN,
    EDGE_HOOK_URL,
    _CFG.get("t_url", ""),
    _CFG.get("alert_api", ""),
):
    _mask_gha_secret(_secret_val)


def get_max_images_per_account(default=3):
    """Reads only the 2-byte maxImagesPerAccount integer instead of the entire pool node."""
    try:
        req = urllib.request.Request(f"{STORE_STATUS_BASE}/maxImagesPerAccount.json", headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8").strip()
            if raw and raw != "null":
                return int(json.loads(raw))
    except Exception:
        pass
    return default


# Transparent Data Store Auth Token injector
_orig_request = urllib.request.Request


def _store_authenticated_request(url, *args, **kwargs):
    if isinstance(url, str) and STORE_BASE and STORE_BASE in url and STORE_AUTH_TOKEN:
        if "auth=" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}auth={STORE_AUTH_TOKEN}"
    return _orig_request(url, *args, **kwargs)


urllib.request.Request = _store_authenticated_request

_orig_urlopen = urllib.request.urlopen


def _store_authenticated_urlopen(url, *args, **kwargs):
    if isinstance(url, str) and STORE_BASE and STORE_BASE in url and STORE_AUTH_TOKEN:
        if "auth=" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}auth={STORE_AUTH_TOKEN}"
    elif hasattr(url, "full_url") and STORE_BASE and STORE_BASE in url.full_url and STORE_AUTH_TOKEN:
        if "auth=" not in url.full_url:
            sep = "&" if "?" in url.full_url else "?"
            url.full_url = f"{url.full_url}{sep}auth={STORE_AUTH_TOKEN}"
    return _orig_urlopen(url, *args, **kwargs)


urllib.request.urlopen = _store_authenticated_urlopen


def _safe_err(err):
    m = str(err)
    for secret_url, label in (
        (STORE_BASE, "https://[STORE_ENDPOINT]"),
        (EDGE_HOOK_URL, "https://[EDGE_ENDPOINT]"),
        (_CFG.get("t_url", ""), "https://[TARGET_HOST]"),
    ):
        if secret_url and secret_url in m:
            m = m.replace(secret_url, label)
    for tok in (STORE_AUTH_TOKEN, MASTER_SALT_STR, _ENC_CFG_RAW):
        if tok and tok in m:
            m = m.replace(tok, "[SECRET]")
    m = re.sub(r"auth=[a-zA-Z0-9_\-\.]+", "auth=[SECRET]", m)
    return m


def _mask_device(dev):
    if not dev:
        return "[CLIENT_NODE]"
    s = str(dev).strip()
    if len(s) <= 4:
        return "****"
    return f"{s[:3]}***{s[-2:]}"


def _mask_task(tid):
    if not tid:
        return "[TASK_NODE]"
    s = str(tid).strip()
    if len(s) <= 8:
        return "****"
    return f"{s[:5]}***{s[-4:]}"


class TaskExecutionContext:
    def __init__(self, initial_idx, slot_id):
        self.active_idx = initial_idx
        self.slot_id = slot_id
        self.held_locks = {initial_idx} if initial_idx is not None else set()
        self.is_completed = False
        self.swapped_from = None
        self.switch_reason = None

    def record_locked(self, idx):
        if idx is not None:
            self.held_locks.add(idx)

    def record_unlocked(self, idx):
        if idx is not None:
            self.held_locks.discard(idx)

    def release_all_locks(self):
        for idx in list(self.held_locks):
            try:
                atomic_unlock_account(idx, self.slot_id)
            except Exception:
                pass
            self.held_locks.discard(idx)


_POOL_TIMESTAMP_MS = 0
_CACHED_ACCOUNTS = None
_CACHE_TIME = 0


def get_decrypted_pool(force_refresh=False):
    global _POOL_TIMESTAMP_MS, _CACHED_ACCOUNTS, _CACHE_TIME
    now = time.time()
    if not force_refresh and _CACHED_ACCOUNTS is not None and (now - _CACHE_TIME < 300):
        return _CACHED_ACCOUNTS

    req = urllib.request.Request(STORE_POOL_URL, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode("utf-8"))

    enc = data.get("enc", "")
    decrypted = decrypt_data_aes(enc)
    parsed = json.loads(decrypted)
    _POOL_TIMESTAMP_MS = int(parsed.get("timestamp_ms", 0))

    accounts = parsed.get("accounts", [])
    if not accounts:
        raise RuntimeError("No accounts found in decrypted pool!")
    _CACHED_ACCOUNTS = accounts
    _CACHE_TIME = now
    return accounts


def dispatch_admin_alert(message):
    try:
        config_url = f"{STORE_BASE}/{_CFG['n_alert']}"
        api_url = os.environ.get("ALERT_API_URL") or _CFG.get("alert_api", "")
        id_instance = os.environ.get("ALERT_INSTANCE_ID") or os.environ.get("ID_INSTANCE") or ""
        api_token = os.environ.get("ALERT_API_TOKEN") or os.environ.get("API_TOKEN") or ""
        chat_id = os.environ.get("ADMIN_CHAT_ID") or ""
        is_enabled = True

        try:
            req = urllib.request.Request(config_url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=4) as resp:
                cfg = json.loads(resp.read().decode("utf-8"))
                if cfg:
                    is_enabled = cfg.get("enabled", True)
                    api_url = cfg.get("apiUrl", api_url)
                    id_instance = cfg.get("idInstance", id_instance)
                    api_token = cfg.get("apiTokenInstance", api_token)
                    chat_id = cfg.get("recipientChatId", chat_id)
        except Exception:
            pass

        if not is_enabled or not api_url or not id_instance or not api_token or not chat_id:
            return False

        _mask_gha_secret(api_url)
        _mask_gha_secret(api_token)
        _mask_gha_secret(id_instance)
        _mask_gha_secret(chat_id)

        alert_tpl = _CFG.get("alert_tpl", "")
        if not alert_tpl:
            return False

        url = f"{api_url.rstrip('/')}{alert_tpl.format(id_instance=id_instance, api_token=api_token)}"
        payload = {"chatId": chat_id, "message": message}
        data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        send_req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST"
        )
        with urllib.request.urlopen(send_req, timeout=10) as r:
            return r.status in (200, 201)
    except Exception as e:
        _log(f"⚠️ Notice dispatching admin alert: {type(e).__name__}", verbose=True)
        return False


def sync_session_state(context, account_idx):
    if account_idx is None or context is None:
        return False
    try:
        cookies = context.cookies()
        if not cookies:
            return False

        has_auth_token = False
        cookie_map = {}
        skip_cf_ip_cookies = set(_CFG.get("skip_ck", []))
        allowed_domains = tuple(_CFG.get("c_doms", []))
        primary_host = _CFG.get("c_host", "")
        ck_tok = _CFG.get("ck_tok") or []
        tok_hint = ck_tok[0] if ck_tok else ""
        for c in cookies:
            domain = str(c.get("domain", "")).lower()
            name = str(c.get("name", "")).strip()
            val = str(c.get("value", "")).strip()
            if not name or not val or name in skip_cf_ip_cookies:
                continue
            if any(d in domain for d in allowed_domains):
                if tok_hint and tok_hint in name:
                    has_auth_token = True
                if name not in cookie_map or (primary_host and primary_host in domain):
                    cookie_map[name] = val

        if not has_auth_token or not cookie_map:
            return False

        parts = [f"{k}={v}" for k, v in cookie_map.items()]
        cookie_str = "; ".join(parts)
        encrypted_b64 = encrypt_data_aes(cookie_str)
        now_ms = int(time.time() * 1000)

        secret_url = f"{STORE_SECRETS_BASE}/acc_{account_idx}.json"
        patch_payload = {
            "freshCookie": encrypted_b64,
            "lastCookieSync": now_ms
        }
        req = urllib.request.Request(
            secret_url,
            data=json.dumps(patch_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            if r.status in (200, 204):
                try:
                    status_sync_req = urllib.request.Request(
                        f"{STORE_STATUS_BASE}/acc_{account_idx}.json",
                        data=json.dumps({"lastCookieSync": now_ms, "freshCookie": None}).encode("utf-8"),
                        headers={"Content-Type": "application/json", "User-Agent": _UA},
                        method="PATCH"
                    )
                    urllib.request.urlopen(status_sync_req, timeout=5)
                except Exception as e_st:
                    _log(f"⚠️ Sync timestamp notice for Account #{int(account_idx)+1}: {_safe_err(e_st)}", verbose=True)
                _log(f"🔄 Account #{int(account_idx)+1}: Rotated session token synced ({len(parts)} keys)", verbose=True)
                return True
    except Exception as e:
        _log(f"⚠️ Session sync notice for Account #{int(account_idx)+1}: {_safe_err(e)}", verbose=True)
    return False


def get_active_session_blob(account_idx=None):
    accounts = get_decrypted_pool()
    if account_idx is None:
        return accounts[0].get("cookie", "")

    try:
        idx = int(account_idx) % len(accounts)
    except Exception:
        idx = 0

    req_tokens = tuple(_CFG.get("ck_tok") or [])
    for secret_base, label in ((STORE_SECRETS_BASE, "Secrets"), (STORE_STATUS_BASE, "Legacy")):
        try:
            req_fresh = urllib.request.Request(f"{secret_base}/acc_{idx}.json", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req_fresh, timeout=5) as resp:
                stat_obj = json.loads(resp.read().decode("utf-8")) or {}
                fresh_enc = stat_obj.get("freshCookie", "")
                last_sync = int(stat_obj.get("lastCookieSync", 0))

                if fresh_enc and isinstance(fresh_enc, str) and len(fresh_enc) > 30:
                    if _POOL_TIMESTAMP_MS > 0 and last_sync > 0 and last_sync < _POOL_TIMESTAMP_MS:
                        _log(f"📦 Account #{idx + 1}: Baseline pool newer than synced cache; using pool baseline.", verbose=True)
                        break
                    decrypted = decrypt_data_aes(fresh_enc)
                    if decrypted and (not req_tokens or any(t in decrypted for t in req_tokens)):
                        _log(f"🎯 Account #{idx + 1} [Fresh/{label}]", verbose=True)
                        return decrypted
        except Exception as e_fresh:
            _log(f"ℹ️ Account #{idx + 1} session fallback ({label}): {_safe_err(e_fresh)}", verbose=True)

    _log(f"🎯 Account #{idx + 1} [Pool Baseline]", verbose=True)
    return accounts[idx].get("cookie", "")


def inject_session_to_context(context, raw_cookie_str):
    added = 0
    skipped = 0
    target_url = _CFG["t_url"]
    cookie_host = _CFG["c_host"]
    for item in raw_cookie_str.split(";"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        k, v = item.split("=", 1)
        k = k.strip()
        v = v.strip()
        try:
            context.add_cookies([{
                "name": k,
                "value": v,
                "url": target_url,
                "secure": True
            }])
            added += 1
        except Exception:
            try:
                context.add_cookies([{
                    "name": k,
                    "value": v,
                    "domain": cookie_host,
                    "path": "/",
                    "secure": True
                }])
                added += 1
            except Exception:
                skipped += 1
    _log(f"🍪 Context session loaded ({added} keys, skipped={skipped})", verbose=True)


def fetch_slot_data(slot_id):
    url = f"{STORE_TASKS_BASE}/{slot_id}.json"
    for attempt in range(1, 5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = resp.read().decode("utf-8")
                if data and data.strip() != "null":
                    return json.loads(data)
                elif data and data.strip() == "null" and attempt < 4:
                    time.sleep(1.0)
                    continue
        except Exception as e:
            if attempt < 4:
                _log(f"⚠️ Slot fetch retry {attempt}/4 for {_mask_task(slot_id)}: {_safe_err(e)}", verbose=True)
                time.sleep(1.0)
            else:
                print(f"❌ Error fetching slot {_mask_task(slot_id)} after 4 attempts: {_safe_err(e)}")
    return {}


def update_slot_data(slot_id, updates):
    url = f"{STORE_TASKS_BASE}/{slot_id}.json"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(updates).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        print(f"⚠️ Error updating slot {_mask_task(slot_id)}: {_safe_err(e)}")
        return False


_CURRENT_TASK_START = None
_CURRENT_HAD_CUSTOMER_INPUT = False
_CURRENT_TASK_META = {}


def update_task_result(task_id, status, image_b64=None, error=None, account_idx=None, switched_from=None, switch_reason=None):
    url = f"{STORE_TASKS_BASE}/{task_id}/result.json"
    report = {
        "taskId": task_id,
        "status": status,
        "completedAt": time.time()
    }
    if account_idx is not None:
        report["accountIndex"] = int(account_idx)
    if switched_from is not None:
        report["switchedFrom"] = int(switched_from)
        report["switchReason"] = switch_reason or "Redirected"
    if image_b64:
        report["imageBase64"] = image_b64
    if error:
        report["error"] = error

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(report).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"📡 Task {_mask_task(task_id)} result updated: {resp.status} ({status})")
    except Exception as e:
        print(f"⚠️ Error updating task result: {_safe_err(e)}")

    try:
        duration_sec = (time.time() - _CURRENT_TASK_START) if _CURRENT_TASK_START else None
        meta = _CURRENT_TASK_META if _CURRENT_TASK_META.get("taskId") == task_id else {}
        is_task_retry = bool(meta.get("isRetry", False))
        is_prewarm = bool(meta.get("isPrewarm", task_id.startswith("warm_")))
        parent_task_id = meta.get("parentTaskId")
        actual_acc_idx = account_idx if account_idx is not None else meta.get("accountIndex")
        dev_id = meta.get("deviceId", "")
        had_input_flag = bool(_CURRENT_HAD_CUSTOMER_INPUT or meta.get("hadCustomerInput", False))

        push_run_telemetry(
            task_id=task_id,
            status=status,
            account_idx=actual_acc_idx,
            duration_sec=duration_sec,
            is_retry=is_task_retry,
            is_prewarm=is_prewarm,
            parent_task_id=parent_task_id,
            error=error,
            device_id=dev_id,
            had_customer_input=had_input_flag
        )
    except Exception as e_tel:
        _log(f"⚠️ Telemetry push note: {_safe_err(e_tel)}", verbose=True)


def push_run_telemetry(task_id, status, account_idx=None, duration_sec=None, is_retry=False, is_prewarm=False, parent_task_id=None, error=None, device_id=None, had_customer_input=None, is_maintenance=False):
    """Writes execution metadata to telemetry store."""
    if not task_id:
        return
    if _CURRENT_TASK_META.get("taskId") == task_id:
        _CURRENT_TASK_META["lastStatus"] = str(status)
    try:
        run_id = os.environ.get("GITHUB_RUN_ID")
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        html_url = f"https://github.com/{repo}/actions/runs/{run_id}" if (run_id and repo) else None

        telemetry_data = {
            "taskId": task_id,
            "deviceId": device_id or None,
            "runId": int(run_id) if (run_id and run_id.isdigit()) else None,
            "htmlUrl": html_url,
            "accountNumber": (int(account_idx) + 1) if account_idx is not None else None,
            "status": status,
            "durationSec": round(float(duration_sec), 2) if duration_sec is not None else None,
            "isRetry": bool(is_retry),
            "isPrewarm": bool(is_prewarm),
            "isMaintenance": True if is_maintenance else None,
            "hadCustomerInput": bool(had_customer_input) if had_customer_input is not None else (not bool(is_prewarm) and not bool(is_maintenance)),
            "parentTaskId": parent_task_id or None,
            "error": _safe_err(error) if error else None,
            "timestamp": int(time.time() * 1000)
        }
        telemetry_data = {k: v for k, v in telemetry_data.items() if v is not None}

        tel_url = f"{STORE_BASE}/{_CFG['n_tel']}/{urllib.parse.quote(task_id)}.json"
        req = urllib.request.Request(
            tel_url,
            data=json.dumps(telemetry_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PUT"
        )
        with urllib.request.urlopen(req, timeout=10):
            print(f"📊 Telemetry saved for {_mask_task(task_id)}: status={status}, account={telemetry_data.get('accountNumber')}, duration={telemetry_data.get('durationSec')}s")

        if parent_task_id:
            parent_url = f"{STORE_BASE}/{_CFG['n_tel']}/{urllib.parse.quote(parent_task_id)}.json"
            patch_data = {"nextAttemptTaskId": task_id}
            req_p = urllib.request.Request(
                parent_url,
                data=json.dumps(patch_data).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PATCH"
            )
            with urllib.request.urlopen(req_p, timeout=10):
                _log(f"🔗 Telemetry parent link saved: {_mask_task(parent_task_id)} -> {_mask_task(task_id)}", verbose=True)
    except Exception as e:
        print(f"⚠️ Error saving telemetry: {_safe_err(e)}")


def _read_store_leaf(sub_path, timeout=6):
    try:
        req = urllib.request.Request(f"{STORE_BASE}/{sub_path}", headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8").strip()
            if raw and raw != "null":
                return json.loads(raw)
    except Exception:
        pass
    return None


def _verify_parent_retry_authorization(slot_id, device_id, parent_task_id):
    """Independently verifies that this retry task was authorized by the edge gateway."""
    clean_parent = str(parent_task_id or "").strip()
    clean_slot = str(slot_id or "").strip()
    if not clean_parent or not clean_slot:
        return False, "PARENT_TASK_REQUIRED: Missing parentTaskId for retry"

    m_par = re.search(r"_p(\d+)_", clean_parent, re.IGNORECASE)
    m_cur = re.search(r"_p(\d+)_", clean_slot, re.IGNORECASE)
    if m_par and m_cur and m_par.group(1) != m_cur.group(1):
        return False, "PERSON_MISMATCH: Retry target slot does not match parent"

    q_parent = urllib.parse.quote(clean_parent, safe="")
    tasks_node = _CFG["n_tasks"]
    p_status = _read_store_leaf(f"{tasks_node}/{q_parent}/status.json")
    if str(p_status or "").upper() != "COMPLETED":
        return False, "PARENT_NOT_COMPLETED: Parent task is not completed"

    p_retry_used = _read_store_leaf(f"{tasks_node}/{q_parent}/retryUsed.json")
    p_retry_tid = str(_read_store_leaf(f"{tasks_node}/{q_parent}/retryTaskId.json") or "").strip()
    if p_retry_used is not True or p_retry_tid != clean_slot:
        return False, "RETRY_NOT_AUTHORIZED: Server retry binding mismatch"

    p_dev = str(
        _read_store_leaf(f"{tasks_node}/{q_parent}/deviceId.json")
        or _read_store_leaf(f"{tasks_node}/{q_parent}/input/deviceId.json")
        or ""
    ).strip()
    if p_dev and p_dev != device_id:
        return False, "UNAUTHORIZED_RETRY_OWNERSHIP: Parent belongs to another device"

    p_created_raw = _read_store_leaf(f"{tasks_node}/{q_parent}/createdAt.json")
    try:
        p_created_ms = int(p_created_raw or 0)
        if 0 < p_created_ms < 100_000_000_000:
            p_created_ms *= 1000
    except Exception:
        p_created_ms = 0
    if p_created_ms > 0 and ((time.time() * 1000) - p_created_ms > 25 * 60 * 1000):
        return False, "RETRY_WINDOW_EXPIRED: Free retry window exceeded"

    return True, "VERIFIED_RETRY"


def verify_server_device_authorization(device_id, slot_id="", is_retry=False, parent_task_id=None):
    """Server-side device license, trial, credit, and verified-retry enforcement."""
    if not device_id:
        return False, "DEVICE_UNIDENTIFIED: Hardware device ID missing from task payload"

    dev_url = f"{STORE_BASE}/{_CFG['n_devs']}/{device_id}.json"
    try:
        req = urllib.request.Request(dev_url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read().decode("utf-8")
            if not raw or raw.strip() == "null":
                return False, "DEVICE_NOT_FOUND: Device is not registered on server"
            dev = json.loads(raw)
    except Exception as e:
        return False, f"DATABASE_ERROR: Unable to verify device on server ({_safe_err(e)})"

    if not isinstance(dev, dict):
        return False, "DEVICE_CORRUPT: Invalid record for device"

    if not dev.get("enabled", False):
        return False, "DEVICE_LOCKED: Hardware device is disabled or blocked by Administrator"

    now_ms = time.time() * 1000
    is_trial = dev.get("isTrial", False) is True
    trial_until = int(dev.get("trialUntil", 0) or 0)
    is_trial_active = is_trial and trial_until > 0 and now_ms <= trial_until

    if is_trial and trial_until > 0 and now_ms > trial_until:
        try:
            patch_req = urllib.request.Request(
                dev_url,
                data=json.dumps({"enabled": False, "lockReason": "TRIAL_EXPIRED"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PATCH"
            )
            urllib.request.urlopen(patch_req, timeout=5)
        except Exception:
            pass
        return False, "TRIAL_EXPIRED: Free trial duration has expired on server"

    is_verified_retry = False
    if is_retry:
        ok_retry, retry_reason = _verify_parent_retry_authorization(slot_id, device_id, parent_task_id)
        if not ok_retry:
            return False, f"INVALID_RETRY: {retry_reason}"
        is_verified_retry = True
        _log(f"✅ Verified zero-credit retry binding for {_mask_task(slot_id)}", verbose=True)

    is_unlimited = dev.get("unlimited", False) is True
    if not is_unlimited and not is_trial_active and not is_verified_retry:
        credits = int(dev.get("photoCredits", dev.get("photoBalance", 0)) or 0)
        if credits <= 0:
            return False, "CREDITS_EXHAUSTED: Photo credits balance is 0 on server"

    _CURRENT_TASK_META["verifiedRetry"] = is_verified_retry
    _CURRENT_TASK_META["devicePlanFree"] = bool(is_unlimited or is_trial_active)
    _CURRENT_TASK_META["legacyBalance"] = int(dev.get("photoBalance", 0) or 0) if dev.get("photoCredits") is None else 0
    return True, "AUTHORIZED"


def deduct_server_device_credit(device_id):
    """Authoritative server-side credit deduction via ETag CAS."""
    if not device_id:
        return False
    credits_url = f"{STORE_BASE}/{_CFG['n_devs']}/{device_id}/photoCredits.json"
    try:
        if _CURRENT_TASK_META.get("deviceId") == device_id and "devicePlanFree" in _CURRENT_TASK_META:
            if _CURRENT_TASK_META["devicePlanFree"]:
                return True
            legacy_balance = int(_CURRENT_TASK_META.get("legacyBalance", 0))
        else:
            dev_url = f"{STORE_BASE}/{_CFG['n_devs']}/{device_id}.json"
            req = urllib.request.Request(dev_url, headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read().decode("utf-8")
                if not raw or raw.strip() == "null":
                    return False
                dev = json.loads(raw)
            if not isinstance(dev, dict):
                return False

            now_ms = time.time() * 1000
            is_trial_active = dev.get("isTrial", False) is True and int(dev.get("trialUntil", 0) or 0) > now_ms
            if dev.get("unlimited", False) is True or is_trial_active:
                return True

            legacy_balance = int(dev.get("photoBalance", 0) or 0) if dev.get("photoCredits") is None else 0

        import random
        max_attempts = 10
        for attempt in range(max_attempts):
            try:
                get_req = urllib.request.Request(
                    credits_url,
                    headers={_CFG["etag_h"]: "true", "User-Agent": _UA}
                )
                with urllib.request.urlopen(get_req, timeout=8) as resp:
                    etag = resp.headers.get("ETag")
                    raw_val = resp.read().decode("utf-8").strip()
                    if raw_val and raw_val != "null":
                        cur_credits = int(json.loads(raw_val) or 0)
                    else:
                        cur_credits = legacy_balance

                if cur_credits <= 0:
                    _log(f"⚠️ Device {_mask_device(device_id)} already at 0 credits; skipping decrement.", verbose=True)
                    return True

                new_credits = max(0, cur_credits - 1)
                put_headers = {"Content-Type": "application/json", "User-Agent": _UA}
                if etag:
                    put_headers["If-Match"] = etag

                put_req = urllib.request.Request(
                    credits_url,
                    data=json.dumps(new_credits).encode("utf-8"),
                    headers=put_headers,
                    method="PUT"
                )
                with urllib.request.urlopen(put_req, timeout=8):
                    print(f"💳 Server credit updated: {_mask_device(device_id)} {cur_credits} -> {new_credits} (CAS #{attempt + 1})")
                    return True

            except urllib.error.HTTPError as he:
                if he.code == 412:
                    sleep_time = random.uniform(0.06, 0.14) * (attempt + 1)
                    time.sleep(sleep_time)
                    continue
                raise

        print(f"❌ CRITICAL: Atomic credit deduction exhausted {max_attempts} CAS retries for {_mask_device(device_id)}!")
        return False
    except Exception as e:
        print(f"⚠️ Failed to deduct credit on server: {_safe_err(e)}")
        return False


def mark_account_expired(account_idx):
    if account_idx is None:
        return
    try:
        expire_url = f"{STORE_STATUS_BASE}/acc_{account_idx}.json"
        req = urllib.request.Request(
            expire_url,
            data=json.dumps({"isExpired": True, "isBusy": False, "bookedBy": "", "bookedUntil": 0, "freshCookie": None, "lastCookieSync": 0}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        try:
            sec_del = urllib.request.Request(
                f"{STORE_SECRETS_BASE}/acc_{account_idx}.json",
                headers={"User-Agent": _UA},
                method="DELETE"
            )
            urllib.request.urlopen(sec_del, timeout=4)
        except Exception:
            pass
        print(f"⚠️ Marked Account #{int(account_idx)+1} as expired in pool.")

        acc_num = f"#{int(account_idx)+1}"
        now_str = datetime.now(_STUDIO_TZ).strftime("%I:%M %p, %d %b %Y")
        brand = _CFG.get("brand", "STUDIO")
        dispatch_admin_alert(
            f"🔴 *{brand} - SESSION EXPIRED ALERT!* ⚠️\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 *Account:* {acc_num} (`acc_{account_idx}`)\n"
            f"☁️ *Detected By:* Cloud Runner\n"
            f"🕒 *Time:* {now_str}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🛠️ *Action Required:* Please refresh this account's session on your PC Hub!"
        )
    except Exception as ex:
        print(f"Failed to mark expired: {_safe_err(ex)}")


def get_studio_day_string():
    """Returns today's date in configured studio timezone."""
    return datetime.now(_STUDIO_TZ).strftime("%Y-%m-%d")


def has_reset_time_passed(reset_time_str, rate_limited_at_ms=0):
    if not reset_time_str or not isinstance(reset_time_str, str):
        return False
    try:
        clean_str = reset_time_str.strip().upper()
        now_local = datetime.now(_STUDIO_TZ)

        m = re.match(r"^(\d{1,2}):(\d{2})\s*(AM|PM)?$", clean_str)
        if not m:
            return False

        hour = int(m.group(1))
        minute = int(m.group(2))
        ampm = m.group(3)

        if ampm:
            if ampm == "PM" and hour < 12:
                hour += 12
            elif ampm == "AM" and hour == 12:
                hour = 0

        target_dt = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)

        if rate_limited_at_ms and int(rate_limited_at_ms) > 0:
            rl_dt = datetime.fromtimestamp(int(rate_limited_at_ms) / 1000.0, tz=_STUDIO_TZ)
            target_candidate = rl_dt.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if target_candidate < rl_dt:
                target_candidate += timedelta(days=1)
            return now_local >= target_candidate
        return now_local >= target_dt
    except Exception:
        return False


def mark_account_rate_limited(account_idx, reset_time=None):
    if account_idx is None:
        return
    try:
        today_str = get_studio_day_string()
        max_images = get_max_images_per_account(default=3)

        acc_url = f"{STORE_STATUS_BASE}/acc_{account_idx}.json"
        now_ms = int(time.time() * 1000)
        patch_payload = {
            "usage": max_images,
            "quotaDay": today_str,
            "isBusy": False,
            "bookedBy": "",
            "bookedUntil": 0,
            "resetTime": reset_time or "",
            "lastBlockedProbeTime": now_ms,
            "rateLimitedAt": now_ms,
        }

        req = urllib.request.Request(
            acc_url,
            data=json.dumps(patch_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"⚠️ Marked Account #{int(account_idx)+1} rate limited (usage={max_images}, resetTime={reset_time})")
    except Exception as ex:
        print(f"Failed to mark rate limit: {_safe_err(ex)}")


def atomic_lock_account(account_idx, slot_id, device_id=""):
    if account_idx is None:
        return
    try:
        now_ms = int(time.time() * 1000)
        acc_url = f"{STORE_STATUS_BASE}/acc_{account_idx}.json"
        payload = {
            "bookedBy": f"cloud_runner_{slot_id}_{device_id}" if device_id else f"cloud_runner_{slot_id}",
            "bookedUntil": now_ms + 180_000,
            "lastUsed": now_ms,
            "lastHeartbeat": now_ms,
            "isBusy": True
        }
        if device_id:
            payload["lastDevice"] = device_id
        req = urllib.request.Request(
            acc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"🔒 Locked Account #{int(account_idx)+1} for Slot {_mask_task(slot_id)} (isBusy=True)")
    except Exception as e:
        print(f"⚠️ Failed to lock Account #{int(account_idx)+1}: {_safe_err(e)}")


def atomic_unlock_account(account_idx, slot_id):
    if account_idx is None:
        return
    try:
        try:
            req_chk = urllib.request.Request(f"{STORE_STATUS_BASE}/acc_{account_idx}.json", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req_chk, timeout=4) as r_chk:
                stat_obj = json.loads(r_chk.read().decode("utf-8")) or {}
                booked_by = str(stat_obj.get("bookedBy", ""))
                booked_until = int(stat_obj.get("bookedUntil", 0))
                now_ms = int(time.time() * 1000)
                if booked_by and (slot_id not in booked_by) and (booked_until > now_ms):
                    _log(f"ℹ️ Account #{int(account_idx)+1} is active for '{_mask_task(booked_by)}'; skipping unlock.", verbose=True)
                    return
        except Exception:
            pass

        acc_url = f"{STORE_STATUS_BASE}/acc_{account_idx}.json"
        payload = {
            "bookedBy": "",
            "bookedUntil": 0,
            "isBusy": False
        }
        req = urllib.request.Request(
            acc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
        print(f"🔓 Released lock on Account #{int(account_idx)+1} for Slot {_mask_task(slot_id)} (isBusy=False)")
    except Exception as e:
        print(f"⚠️ Failed to unlock Account #{int(account_idx)+1}: {_safe_err(e)}")


def find_and_lock_next_account(slot_id, exclude_indices=None, device_id=""):
    if exclude_indices is None:
        exclude_indices = set()
    else:
        exclude_indices = set(exclude_indices)

    _log(f"🔄 Finding next eligible account (excluding: {exclude_indices})...", verbose=True)
    today_str = get_studio_day_string()
    start_wait = time.time()
    max_wait_seconds = 45

    while True:
        now_ms = int(time.time() * 1000)
        try:
            req = urllib.request.Request(f"{STORE_STATUS_BASE}.json", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req, timeout=8) as resp:
                status_data = json.loads(resp.read().decode("utf-8")) or {}

            max_images = int(status_data.get("maxImagesPerAccount", status_data.get("max_images_per_account", 3)))
            accounts = get_decrypted_pool()
            total_accounts = len(accounts)

            candidates = []
            busy_count = 0

            for i in range(total_accounts):
                if i in exclude_indices:
                    continue
                acc_info = status_data.get(f"acc_{i}", {})
                if acc_info.get("isExpired", False):
                    continue

                booked_until = int(acc_info.get("bookedUntil", 0))
                booked_by = acc_info.get("bookedBy", "")
                if booked_until > now_ms:
                    is_our_slot = booked_by.startswith(f"cloud_runner_{slot_id}")
                    is_pre_reserved = bool(device_id and (booked_by == f"cloud_runner_{device_id}" or booked_by.startswith(f"cloud_runner_{device_id}_p")))
                    if not (is_our_slot or is_pre_reserved):
                        busy_count += 1
                        continue
                    if not is_our_slot and acc_info.get("isBusy", False):
                        busy_count += 1
                        continue

                q_day = acc_info.get("quotaDay", "")
                usage = int(acc_info.get("usage", 0)) if q_day == today_str else 0
                remaining = max(0, max_images - usage)

                reset_time_str = acc_info.get("resetTime", "")
                if remaining == 0 and reset_time_str:
                    rl_time = acc_info.get("lastBlockedProbeTime") or acc_info.get("rateLimitedAt", 0)
                    if has_reset_time_passed(reset_time_str, rl_time):
                        usage = 0
                        remaining = max_images
                        try:
                            acc_patch = {"resetTime": "", "usage": 0}
                            req_p = urllib.request.Request(
                                f"{STORE_STATUS_BASE}/acc_{i}.json",
                                data=json.dumps(acc_patch).encode("utf-8"),
                                headers={"Content-Type": "application/json"},
                                method="PATCH"
                            )
                            urllib.request.urlopen(req_p, timeout=5)
                            _log(f"⏰ Cooldown cleared on Account #{i + 1}", verbose=True)
                        except Exception as e_cd:
                            _log(f"⚠️ Cooldown patch error for acc_{i}: {_safe_err(e_cd)}", verbose=True)

                if remaining > 0:
                    candidates.append((remaining, i))

            if candidates:
                candidates.sort(key=lambda x: -x[0])
                max_rem = candidates[0][0]
                best_candidates = [idx for rem, idx in candidates if rem == max_rem]
                import random
                chosen_idx = random.choice(best_candidates)
            else:
                chosen_idx = None

            if chosen_idx is not None:
                atomic_lock_account(chosen_idx, slot_id, device_id)
                print(f"✅ Switched to Account #{chosen_idx + 1}")
                return chosen_idx, get_active_session_blob(chosen_idx)

            elapsed = time.time() - start_wait
            if busy_count > 0 and elapsed < max_wait_seconds:
                wait_step = min(4, max(2, int(max_wait_seconds - elapsed)))
                _log(f"⏳ Queue wait: {busy_count} busy ({int(elapsed)}s/{max_wait_seconds}s)...", verbose=True)
                time.sleep(wait_step)
                continue

            return None, ""
        except Exception as e:
            print(f"⚠️ Pool scan error: {_safe_err(e)}")
            return None, ""

    return None, ""


def check_auth_expired(page):
    try:
        current_url = (page.url or "").lower()
        if any(tok in current_url for tok in _CFG.get("a_urls", [])):
            return "Redirected to auth login endpoint"
        a_modal = _CFG.get("a_modal")
        if a_modal and page.locator(a_modal).count() > 0:
            if page.locator(a_modal).first.is_visible():
                return "Unauthorized auth modal displayed"
        a_btn = _CFG.get("a_btn")
        if a_btn:
            login_btn = page.locator(a_btn).first
            if login_btn.count() > 0 and login_btn.is_visible():
                return "Prominent login control visible"
        a_oauth = _CFG.get("a_oauth")
        if a_oauth:
            oauth_btn = page.locator(a_oauth).first
            if oauth_btn.count() > 0 and oauth_btn.is_visible():
                return "Auth sign-in screen displayed"
        a_head = _CFG.get("a_head")
        if a_head:
            login_heading = page.locator(a_head).first
            if login_heading.count() > 0 and login_heading.is_visible():
                return "Auth heading screen displayed"
    except Exception:
        pass
    return None


def build_dynamic_user_agent(browser):
    """Builds a fingerprint-consistent User-Agent matching the live browser version & OS."""
    try:
        ver = (browser.version or "").strip()
    except Exception:
        ver = ""
    if not ver or not re.match(r"^\d+\.\d+", ver):
        ver = "136.0.0.0"
    if sys.platform.startswith("win"):
        platform_token = "Windows NT 10.0; Win64; x64"
    elif sys.platform == "darwin":
        platform_token = "Macintosh; Intel Mac OS X 10_15_7"
    else:
        platform_token = "X11; Linux x86_64"
    return f"Mozilla/5.0 ({platform_token}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36"


def detect_gate_challenge(page):
    """Detects bot verification / interstitial gates."""
    try:
        title = (page.title() or "").strip().lower()
        if any(tok in title for tok in _CFG.get("g_titles", [])):
            return f"Gate challenge title detected"
        g_dom = _CFG.get("g_dom")
        if g_dom and page.locator(g_dom).first.count() > 0:
            return "Gate challenge DOM detected"
    except Exception:
        pass
    return None


def wait_through_gate_challenge(page, max_wait_sec=12.0):
    """Waits through transient JS bot challenge up to max_wait_sec."""
    t0 = time.time()
    last_detected = None
    while (time.time() - t0) < max_wait_sec:
        last_detected = detect_gate_challenge(page)
        if not last_detected:
            return None
        time.sleep(1.0)
    return last_detected


def inspect_quota_and_restore_bonus(page, context, account_idx, slot_id=None):
    """Inspects image quota status via composer menu and updates pool state."""
    print(f"🔍 [PROBE] Running quota verification on Account #{account_idx + 1}...")
    try:
        gate_err = wait_through_gate_challenge(page, max_wait_sec=12.0)
        if gate_err:
            raise RuntimeError(f"blocked by gate challenge: {gate_err}")

        for btn_text in _CFG.get("popups", []):
            try:
                btn = page.locator(f'button:has-text("{btn_text}")').first
                if btn.count() > 0 and btn.is_visible():
                    btn.click(timeout=1000)
            except Exception:
                pass

        page.locator(_CFG["sel_comp"]).first.wait_for(state="visible", timeout=20000)

        plus_btn = page.locator(_CFG["sel_plus"]).first
        if plus_btn.count() == 0 or not plus_btn.is_visible():
            print(f"⚠️ [PROBE] Action trigger missing for Account #{account_idx + 1}")
            return False
        plus_btn.click(timeout=5000)
        page.wait_for_timeout(1000)

        img_elem = page.locator(_CFG["sel_probe_item"]).first
        if img_elem.count() == 0:
            page.wait_for_timeout(1500)
            img_elem = page.locator(_CFG["sel_probe_item"]).first

        if img_elem.count() == 0:
            print(f"⚠️ [PROBE] Target option missing for Account #{account_idx + 1}")
            return False

        is_standalone_probe = bool(slot_id and str(slot_id).startswith("probe_acc_"))
        parent_loc = img_elem.locator("..")
        parent_text = parent_loc.inner_text()
        is_item_disabled = False
        try:
            aria_dis = (parent_loc.get_attribute("aria-disabled") or img_elem.get_attribute("aria-disabled") or "").lower()
            data_dis = parent_loc.get_attribute("data-disabled")
            is_item_disabled = (aria_dis == "true") or (data_dis is not None)
        except Exception:
            pass
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass

        p_lower = parent_text.lower()
        time_match = re.search(r"(?:until|after)\s+([0-9]{1,2}:[0-9]{2}\s*(?:AM|PM|am|pm)?)", parent_text, re.IGNORECASE)
        reset_time_str = time_match.group(1).strip() if time_match else ""

        has_zero = bool(re.search(r"(?<!\d)0\s*(?:images?)?\s*left", p_lower)) or ("0 left" in p_lower) or ("0 images left" in p_lower)
        probe_words = _CFG.get("probe_words", [])
        has_limit_phrase = bool(re.search(r"\blimit\b", p_lower)) or any(k in p_lower for k in probe_words)
        is_locked = is_item_disabled or has_zero or (has_limit_phrase and reset_time_str)
        print(f"📋 [PROBE] Account #{account_idx + 1} locked={bool(is_locked)} disabled={is_item_disabled} reset={bool(reset_time_str)}")

        brand = _CFG.get("brand", "STUDIO")
        if is_locked:
            mark_account_rate_limited(account_idx, reset_time_str or None)
            if slot_id:
                atomic_unlock_account(account_idx, slot_id)
                if is_standalone_probe:
                    update_slot_data(slot_id, {"status": "COMPLETED", "result": "BLOCKED", "resetTime": reset_time_str})

            sync_session_state(context, account_idx)

            dispatch_admin_alert(
                f"🔒 *{brand} - COOLDOWN CONFIRMED*\n"
                f"══════════════════════════════\n"
                f"👤 *Account:* #{account_idx + 1}\n"
                f"🚫 *Status:* Confirmed Rate-Limited (0 left)\n"
                f"⏰ *Reset Time:* {reset_time_str or 'Auto-Cooldown'}\n"
                f"══════════════════════════════\n"
                f"Next available account will handle upcoming jobs."
            )
            return True
        else:
            today_str = get_studio_day_string()
            cur_usage = 0
            try:
                req_stat = urllib.request.Request(f"{STORE_STATUS_BASE}/acc_{account_idx}.json", headers={"User-Agent": _UA})
                with urllib.request.urlopen(req_stat, timeout=5) as r_s:
                    st = json.loads(r_s.read().decode("utf-8")) or {}
                    cur_usage = int(st.get("usage", 0)) if st.get("quotaDay") == today_str else 0
            except Exception:
                pass

            new_usage = max(0, cur_usage - 1)
            bonus_patch = {
                "usage": new_usage,
                "quotaDay": today_str,
                "isBusy": False,
                "bookedBy": "",
                "bookedUntil": 0,
                "isExpired": False,
                "resetTime": ""
            }
            req_b = urllib.request.Request(
                f"{STORE_STATUS_BASE}/acc_{account_idx}.json",
                data=json.dumps(bonus_patch).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PATCH"
            )
            with urllib.request.urlopen(req_b, timeout=5):
                pass

            if slot_id:
                atomic_unlock_account(account_idx, slot_id)
                if is_standalone_probe:
                    update_slot_data(slot_id, {"status": "COMPLETED", "result": "BONUS_AWARDED", "newUsage": new_usage})

            sync_session_state(context, account_idx)

            dispatch_admin_alert(
                f"🎉 *{brand} - BONUS QUOTA RESTORED!* ⚡\n"
                f"══════════════════════════════\n"
                f"👤 *Account:* #{account_idx + 1}\n"
                f"🟢 *Status:* Unblocked! (+1 Quota Added)\n"
                f"🎁 *Usage:* Reduced to {new_usage}\n"
                f"══════════════════════════════\n"
                f"Account is ready for jobs!"
            )
            return True
    except Exception as e_probe:
        auth_err = check_auth_expired(page)
        if auth_err:
            print(f"❌ [PROBE] Account #{account_idx + 1} auth expired: {auth_err}")
            mark_account_expired(account_idx)
        else:
            print(f"⚠️ [PROBE] Error: {_safe_err(e_probe)}")
        if slot_id:
            atomic_unlock_account(account_idx, slot_id)
            if str(slot_id).startswith("probe_acc_"):
                update_slot_data(slot_id, {"status": "FAILED", "error": auth_err or _safe_err(e_probe)})
        return False


def execute_render_job(page, slot_id, account_idx, prompt, img_b64, t_start, device_id="", switched_from=None, switch_reason=None, dress_b64=None):
    task_ctx = account_idx if isinstance(account_idx, TaskExecutionContext) else TaskExecutionContext(account_idx, slot_id)
    current_acc_idx = task_ctx.active_idx

    meta = _CURRENT_TASK_META if _CURRENT_TASK_META.get("taskId") == slot_id else {}
    is_task_retry = bool(meta.get("verifiedRetry", False))

    temp_img_path = None
    if img_b64:
        try:
            temp_img_path = os.path.join(tempfile.gettempdir(), f"{slot_id}_in.jpg")
            with open(temp_img_path, "wb") as f:
                f.write(base64.b64decode(img_b64))
            _log(f"💾 Staged input ({os.path.getsize(temp_img_path)} bytes)", verbose=True)
        except Exception as e:
            print(f"⚠️ Error staging input image: {_safe_err(e)}")

    temp_dress_path = None
    if dress_b64:
        try:
            temp_dress_path = os.path.join(tempfile.gettempdir(), f"{slot_id}_dress.jpg")
            with open(temp_dress_path, "wb") as f:
                f.write(base64.b64decode(dress_b64))
            _log(f"👗 Staged attire ({os.path.getsize(temp_dress_path)} bytes)", verbose=True)
        except Exception as e:
            print(f"⚠️ Error staging attire image: {_safe_err(e)}")

    comp_sel = _CFG["sel_comp"]
    composer = page.locator(comp_sel).first

    cf_err = wait_through_gate_challenge(page, max_wait_sec=12.0)
    if cf_err:
        err = f"TRANSIENT_TIMEOUT: GATE_CHALLENGE_BLOCKED on Account #{int(current_acc_idx)+1} ({cf_err})"
        print(f"🛡️ {err}")
        atomic_unlock_account(current_acc_idx, slot_id)
        task_ctx.record_unlocked(current_acc_idx)
        update_task_result(slot_id, "FAILED", error=err, account_idx=current_acc_idx)
        update_slot_data(slot_id, {"status": "FAILED"})
        return False

    composer_ready = False
    try:
        composer.wait_for(state="visible", timeout=22000)
        composer_ready = True
    except Exception:
        pass

    if not composer_ready:
        cf_err = detect_gate_challenge(page)
        if cf_err:
            err = f"TRANSIENT_TIMEOUT: GATE_CHALLENGE_BLOCKED on Account #{int(current_acc_idx)+1} ({cf_err})"
            print(f"🛡️ {err}")
            atomic_unlock_account(current_acc_idx, slot_id)
            task_ctx.record_unlocked(current_acc_idx)
            update_task_result(slot_id, "FAILED", error=err, account_idx=current_acc_idx)
            update_slot_data(slot_id, {"status": "FAILED"})
            return False

        auth_err = check_auth_expired(page)
        old_idx = current_acc_idx
        if auth_err:
            err = f"EXPLICIT_AUTH_EXPIRED: Account #{int(old_idx)+1}: {auth_err}"
            print(f"❌ {err}")
            mark_account_expired(old_idx)
        else:
            print(f"⚠️ Input surface not ready within 30s on Account #{int(old_idx)+1}.")

        atomic_unlock_account(old_idx, slot_id)
        task_ctx.record_unlocked(old_idx)

        new_idx, new_cookie = find_and_lock_next_account(slot_id, exclude_indices=[old_idx], device_id=device_id)
        if new_idx is not None and new_cookie:
            print(f"🚀 Hot-Swap: Switched to Account #{new_idx+1}")
            task_ctx.record_locked(new_idx)
            switched_from = old_idx
            switch_reason = "Redirected" if auth_err else "Composer Timeout"
            update_slot_data(slot_id, {
                "accountIndex": new_idx,
                "switchedFrom": switched_from,
                "switchReason": switch_reason
            })
            try:
                page.context.clear_cookies()
                inject_session_to_context(page.context, new_cookie)
                page.goto(_CFG["t_url"], wait_until="domcontentloaded", timeout=45000)
                time.sleep(1.0)
                for btn_text in _CFG.get("popups", []):
                    btn = page.locator(f'button:has-text("{btn_text}")').first
                    if btn.count() > 0 and btn.is_visible():
                        btn.click(timeout=1000)
                composer = page.locator(comp_sel).first
                composer.wait_for(state="visible", timeout=30000)
                task_ctx.active_idx = new_idx
                current_acc_idx = new_idx
                _CURRENT_TASK_META["accountIndex"] = new_idx
                composer_ready = True
                print(f"✅ Hot-swap Account #{new_idx+1} ready")
            except Exception as e_swap:
                print(f"❌ Hot-swap failed on Account #{new_idx+1}: {_safe_err(e_swap)}")
                atomic_unlock_account(new_idx, slot_id)
                task_ctx.record_unlocked(new_idx)
                update_task_result(slot_id, "FAILED", error=f"TRANSIENT_TIMEOUT: Hot-swap Account #{new_idx+1} failed ({_safe_err(e_swap)})", account_idx=new_idx)
                update_slot_data(slot_id, {"status": "FAILED"})
                return False
        else:
            err = f"TRANSIENT_TIMEOUT: Input not ready within 30s on Account #{int(old_idx)+1} (no fallback available)"
            print(f"❌ {err}")
            update_task_result(slot_id, "FAILED", error=err, account_idx=old_idx)
            update_slot_data(slot_id, {"status": "FAILED"})
            return False

    sync_session_state(page.context, current_acc_idx)

    photo_uploaded = False
    if not temp_img_path or not os.path.exists(temp_img_path):
        err = "FAILED: Cannot render without input image file"
        print(f"❌ {err}")
        update_task_result(slot_id, "FAILED", error=err, account_idx=current_acc_idx)
        update_slot_data(slot_id, {"status": "FAILED"})
        return False

    upload_files = [temp_img_path, temp_dress_path] if temp_dress_path else temp_img_path
    attach_sel = _CFG["sel_att"]

    attached_ok = False
    for upload_attempt in (1, 2):
        if upload_attempt == 2:
            _log("⚠️ Retrying upload after reload...", verbose=True)
            try:
                page.reload(wait_until="domcontentloaded", timeout=30000)
                time.sleep(1.5)
                if detect_gate_challenge(page):
                    break
                for btn_text in _CFG.get("popups", []):
                    btn = page.locator(f'button:has-text("{btn_text}")').first
                    if btn.count() > 0 and btn.is_visible():
                        btn.click(timeout=1000)
                composer = page.locator(comp_sel).first
                composer.wait_for(state="visible", timeout=20000)
            except Exception as e_rel:
                _log(f"⚠️ Upload recovery reload failed: {_safe_err(e_rel)}", verbose=True)
                break

        _log(f"📤 Uploading media (Attempt {upload_attempt}/2)...", verbose=True)
        try:
            try:
                composer.click(timeout=2000)
            except Exception:
                pass
            file_input = page.locator(_CFG["sel_file_nc"]).first
            if file_input.count() == 0:
                file_input = page.locator(_CFG["sel_file"]).first
            file_input.wait_for(state="attached", timeout=12000)
            if temp_dress_path:
                try:
                    file_input.evaluate("el => el.setAttribute('multiple', '')")
                except Exception:
                    pass
            file_input.set_input_files(upload_files)
        except Exception as e:
            if upload_attempt == 2:
                err = f"TRANSIENT_TIMEOUT: File input attach timed out ({_safe_err(e)})"
                print(f"❌ {err}")
                update_task_result(slot_id, "FAILED", error=err, account_idx=current_acc_idx)
                update_slot_data(slot_id, {"status": "FAILED"})
                return False
            continue

        max_loops = 24 if upload_attempt == 1 else 36
        for _ in range(max_loops):
            attach_preview = page.locator(attach_sel)
            cnt = attach_preview.count()
            if cnt > 0 and any(attach_preview.nth(i).is_visible() for i in range(cnt)):
                attached_ok = True
                photo_uploaded = True
                break
            time.sleep(0.5)

        if attached_ok:
            break

    if not attached_ok:
        err = "TRANSIENT_TIMEOUT: Media attachment confirmation timed out"
        print(f"❌ {err}")
        update_task_result(slot_id, "FAILED", error=err, account_idx=current_acc_idx)
        update_slot_data(slot_id, {"status": "FAILED"})
        return False

    print(f"[{time.time() - t_start:.2f}s] [UPLOAD_OK]")

    prompt_sent = False
    composer.fill(prompt)
    time.sleep(0.5)

    send_btn = page.locator(_CFG["sel_send"]).first
    try:
        if send_btn.count() > 0 and send_btn.is_visible():
            for _ in range(15):
                if send_btn.is_enabled():
                    break
                time.sleep(0.2)

            if send_btn.is_enabled():
                send_btn.click(force=True, timeout=2000)
                prompt_sent = True
                _log("🚀 Submitted via control.", verbose=True)
        if not prompt_sent:
            composer.focus()
            page.keyboard.press("Enter")
            prompt_sent = True
            _log("🚀 Submitted via Enter.", verbose=True)
    except Exception:
        try:
            composer.focus()
        except Exception:
            pass
        page.keyboard.press("Enter")
        prompt_sent = True

    submit_confirmed = False
    for _ in range(10):
        stop_loc = page.locator(_CFG["sel_stop"])
        user_msg = page.locator(_CFG["sel_umsg"])
        if stop_loc.count() > 0 or user_msg.count() > 0:
            submit_confirmed = True
            break
        time.sleep(0.5)

    if not submit_confirmed:
        _log("⚠️ Re-submitting prompt...", verbose=True)
        try:
            if send_btn.count() > 0 and send_btn.is_visible() and send_btn.is_enabled():
                send_btn.click(force=True, timeout=2000)
            else:
                composer.click(timeout=2000)
                page.keyboard.press("Enter")
        except Exception:
            pass

    _log("⏳ Waiting for output (up to 90s)...", verbose=True)
    assistant_text = ""
    is_rate_limit = False
    is_auth_expired = False
    generated_img_bytes = None
    gen_start = time.time()
    rl_words = _CFG.get("rl_words", [])
    auth_words = _CFG.get("auth_words", [])

    while (time.time() - gen_start) < 90:
        time.sleep(1.0)
        images = page.locator(_CFG["sel_imgs"]).all()

        if images:
            for img in reversed(images):
                src = img.get_attribute("src")
                if not src or "avatar" in src or "profile" in src:
                    continue

                if src.startswith("blob:"):
                    try:
                        b64_str = page.evaluate("""async (blobUrl) => {
                            const resp = await fetch(blobUrl);
                            const blob = await resp.blob();
                            return new Promise((resolve, reject) => {
                                const reader = new FileReader();
                                reader.onloadend = () => resolve(reader.result.split(',')[1]);
                                reader.onerror = reject;
                                reader.readAsDataURL(blob);
                            });
                        }""", src)
                        if b64_str:
                            generated_img_bytes = base64.b64decode(b64_str)
                            print(f"✅ Extracted blob image ({len(generated_img_bytes)} bytes) in {time.time() - t_start:.2f}s")
                            break
                    except Exception as e_blob:
                        _log(f"⚠️ Blob extract error: {_safe_err(e_blob)}", verbose=True)
                elif src.startswith("http"):
                    try:
                        resp = page.request.get(src, timeout=15000)
                        if resp.status == 200:
                            generated_img_bytes = resp.body()
                            print(f"✅ Downloaded image ({len(generated_img_bytes)} bytes) in {time.time() - t_start:.2f}s")
                            break
                    except Exception as e_http:
                        _log(f"⚠️ Media fetch error: {_safe_err(e_http)}", verbose=True)

            if generated_img_bytes:
                break

        if (time.time() - gen_start) > 2.0 and not generated_img_bytes:
            try:
                msgs = page.locator(_CFG["sel_amsg"]).all_inner_texts()
                if msgs:
                    combined_txt = " ".join(msgs).strip().lower()
                    if len(combined_txt) > 5:
                        if any(w in combined_txt for w in rl_words):
                            print(f"⚡ Rate limit detected in {time.time() - gen_start:.1f}s")
                            is_rate_limit = True
                            assistant_text = combined_txt
                            break

                        if any(w in combined_txt for w in auth_words):
                            print(f"⚡ Auth expiry detected in {time.time() - gen_start:.1f}s")
                            is_auth_expired = True
                            assistant_text = combined_txt
                            break
            except Exception:
                pass

        stop_btn = page.locator(_CFG["sel_stop"])
        if stop_btn.count() == 0 and (time.time() - gen_start) > 8 and images and generated_img_bytes:
            break

    if not generated_img_bytes and not is_rate_limit and not is_auth_expired:
        try:
            msgs = page.locator(_CFG["sel_amsg"]).all_inner_texts()
            assistant_text = " ".join(msgs).strip()
            lower_text = assistant_text.lower()

            if photo_uploaded and prompt_sent and len(lower_text) > 5:
                if any(k in lower_text for k in rl_words):
                    is_rate_limit = True

            if any(k in lower_text for k in auth_words):
                is_auth_expired = True
            else:
                auth_err = check_auth_expired(page)
                if auth_err:
                    is_auth_expired = True
        except Exception:
            pass

    for _tf in (temp_img_path, temp_dress_path):
        if _tf and os.path.exists(_tf):
            try:
                os.remove(_tf)
            except Exception:
                pass

    if generated_img_bytes:
        if device_id and not is_task_retry:
            deduct_server_device_credit(device_id)
        elif is_task_retry:
            _log(f"🔄 Zero-credit retry for {_mask_device(device_id)} ({_mask_task(slot_id)})", verbose=True)

        out_b64 = base64.b64encode(generated_img_bytes).decode("utf-8")
        update_task_result(
            slot_id, "COMPLETED",
            image_b64=out_b64,
            account_idx=current_acc_idx,
            switched_from=switched_from,
            switch_reason=switch_reason
        )
        task_ctx.is_completed = True
        slot_patch = {"status": "COMPLETED", "accountIndex": current_acc_idx}
        if switched_from is not None:
            slot_patch["switchedFrom"] = switched_from
            slot_patch["switchReason"] = switch_reason or "Redirected"
        update_slot_data(slot_id, slot_patch)
        sync_session_state(page.context, current_acc_idx)

        new_usage = 0
        try:
            today_str = get_studio_day_string()
            req_get = urllib.request.Request(f"{STORE_STATUS_BASE}/acc_{current_acc_idx}.json", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req_get, timeout=5) as r_stat:
                acc_stat = json.loads(r_stat.read().decode("utf-8")) or {}

            cur_qday = acc_stat.get("quotaDay", "")
            cur_usage = int(acc_stat.get("usage", 0)) if cur_qday == today_str else 0
            new_usage = cur_usage + 1
            now_ms = int(time.time() * 1000)

            acc_patch = {
                "usage": new_usage,
                "quotaDay": today_str,
                "resetTime": "",
                "lastUsed": now_ms
            }
            req_patch = urllib.request.Request(
                f"{STORE_STATUS_BASE}/acc_{current_acc_idx}.json",
                data=json.dumps(acc_patch).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PATCH"
            )
            with urllib.request.urlopen(req_patch, timeout=5):
                pass
            _log(f"📊 Usage updated for Account #{int(current_acc_idx)+1} -> {new_usage}", verbose=True)
        except Exception as e_usage:
            _log(f"⚠️ Usage update error: {_safe_err(e_usage)}", verbose=True)
        print(f"🎉 Slot {_mask_task(slot_id)} completed successfully in {time.time() - t_start:.2f}s!")

        max_images = get_max_images_per_account(default=3)
        should_auto_probe = (new_usage >= max_images)

        if should_auto_probe:
            print(f"⏳ Account #{int(current_acc_idx)+1} reached limit ({new_usage}/{max_images}); waiting 60s before quota probe...")
            time.sleep(60)
            inspect_quota_and_restore_bonus(page, page.context, current_acc_idx, slot_id=slot_id)

        return True
    else:
        if (is_rate_limit or is_auth_expired) and switched_from is None:
            old_idx = current_acc_idx
            if is_rate_limit:
                time_match = re.search(r"(?:after|until|at|around)\s+([0-9]{1,2}:[0-9]{2}\s*(?:AM|PM|am|pm)?)", assistant_text, re.IGNORECASE)
                reset_time_str = time_match.group(1).strip() if time_match else None
                mark_account_rate_limited(old_idx, reset_time_str)
                err = f"EXPLICIT_RATE_LIMIT: Account #{int(old_idx)+1}"
            else:
                mark_account_expired(old_idx)
                err = f"EXPLICIT_AUTH_EXPIRED: Account #{int(old_idx)+1}"

            print(f"⚠️ {err}")
            atomic_unlock_account(old_idx, slot_id)
            task_ctx.record_unlocked(old_idx)

            new_idx, new_cookie = find_and_lock_next_account(slot_id, exclude_indices=[old_idx], device_id=device_id)
            if new_idx is not None and new_cookie:
                print(f"🚀 Hot-Swap: Switched to Account #{new_idx+1}")
                task_ctx.record_locked(new_idx)
                switched_from = old_idx
                switch_reason = "Rate Limit Redirect" if is_rate_limit else "Auth Expired Redirect"
                update_slot_data(slot_id, {
                    "accountIndex": new_idx,
                    "switchedFrom": switched_from,
                    "switchReason": switch_reason
                })
                try:
                    page.context.clear_cookies()
                    inject_session_to_context(page.context, new_cookie)
                    page.goto(_CFG["t_url"], wait_until="domcontentloaded", timeout=45000)
                    time.sleep(1.0)
                    for btn_text in _CFG.get("popups", []):
                        btn = page.locator(f'button:has-text("{btn_text}")').first
                        if btn.count() > 0 and btn.is_visible():
                            btn.click(timeout=1000)

                    task_ctx.active_idx = new_idx
                    _CURRENT_TASK_META["accountIndex"] = new_idx
                    return execute_render_job(
                        page, slot_id, task_ctx, prompt, img_b64, t_start,
                        device_id=device_id,
                        switched_from=switched_from,
                        switch_reason=switch_reason,
                        dress_b64=dress_b64
                    )
                except Exception as ex_swap:
                    _log(f"⚠️ Hot-swap re-execution failed on Account #{new_idx+1}: {_safe_err(ex_swap)}", verbose=True)
                    atomic_unlock_account(new_idx, slot_id)
                    task_ctx.record_unlocked(new_idx)

        if is_rate_limit:
            time_match = re.search(r"(?:after|until|at|around)\s+([0-9]{1,2}:[0-9]{2}\s*(?:AM|PM|am|pm)?)", assistant_text, re.IGNORECASE)
            reset_time_str = time_match.group(1).strip() if time_match else None
            mark_account_rate_limited(current_acc_idx, reset_time_str)
            err = f"EXPLICIT_RATE_LIMIT: Account #{int(current_acc_idx)+1}"
        elif is_auth_expired:
            mark_account_expired(current_acc_idx)
            err = f"EXPLICIT_AUTH_EXPIRED: Account #{int(current_acc_idx)+1}"
        else:
            err = f"TRANSIENT_TIMEOUT: Output element not detected within 90s"
        print(f"❌ {err}")
        update_task_result(slot_id, "FAILED", error=err, account_idx=current_acc_idx)
        update_slot_data(slot_id, {"status": "FAILED"})
        return False


def process_runner_task(slot_id):
    global _CURRENT_TASK_START, _CURRENT_HAD_CUSTOMER_INPUT, _CURRENT_TASK_META
    _CURRENT_TASK_START = time.time()
    _CURRENT_HAD_CUSTOMER_INPUT = False
    _CURRENT_TASK_META = {"taskId": slot_id}
    from playwright.sync_api import sync_playwright

    print(f"\n==================================================")
    print(f"🚀 PROCESSING TASK / STANDBY SLOT")
    print(f"📋 Slot / Task ID: {_mask_task(slot_id)}")
    print(f"==================================================")

    slot_data = fetch_slot_data(slot_id)
    if not slot_data:
        req_in = urllib.request.Request(f"{STORE_TASKS_BASE}/{slot_id}/input.json", headers={"User-Agent": _UA})
        try:
            with urllib.request.urlopen(req_in, timeout=10) as r:
                inp = json.loads(r.read().decode("utf-8"))
                if inp:
                    slot_data = {"status": inp.get("status", "PENDING"), "input": inp, "accountIndex": inp.get("accountIndex")}
        except Exception:
            pass

    if not slot_data:
        if slot_id.startswith("probe_acc_"):
            try:
                acc_part = slot_id.split("probe_acc_")[1].split("_")[0]
                inferred_acc = int(acc_part)
            except Exception:
                inferred_acc = 0
            slot_data = {
                "status": "PENDING",
                "taskType": "VERIFY_QUOTA",
                "accountIndex": inferred_acc
            }
            print(f"ℹ️ Auto-synthesized probe payload for {_mask_task(slot_id)}: Account #{inferred_acc + 1}")
        else:
            err = f"FAILED: Could not fetch task payload for {slot_id} after 4 retries"
            print(f"❌ {err}")
            update_task_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED"})
            return

    input_data = slot_data.get("input", {})
    initial_status = slot_data.get("status") or input_data.get("status", "PENDING")
    account_idx = slot_data.get("accountIndex")
    if account_idx is None:
        account_idx = input_data.get("accountIndex")

    if initial_status == "CANCELLED":
        print(f"⏹️ Slot {_mask_task(slot_id)} was CANCELLED before boot. Exiting cleanly.")
        dev_early = str(slot_data.get("deviceId") or input_data.get("deviceId") or "").strip()
        push_run_telemetry(
            task_id=slot_id,
            status="CANCELLED",
            account_idx=int(account_idx) if account_idx is not None and str(account_idx).isdigit() else None,
            duration_sec=time.time() - _CURRENT_TASK_START,
            is_prewarm=bool(slot_id.startswith("warm_")),
            device_id=dev_early,
            error="Cancelled by operator before runner boot"
        )
        if account_idx is not None:
            try:
                atomic_unlock_account(int(account_idx), slot_id)
            except Exception:
                pass
        return

    device_id = str(slot_data.get("deviceId") or input_data.get("deviceId") or "").strip()
    _CURRENT_TASK_META.update({
        "deviceId": device_id,
        "isRetry": bool(slot_data.get("isRetry") is True or input_data.get("isRetry") is True),
        "parentTaskId": slot_data.get("parentTaskId") or input_data.get("parentTaskId"),
        "isPrewarm": bool(slot_id.startswith("warm_"))
    })

    raw_cookie = ""
    if account_idx is None or str(account_idx).strip() == "" or str(account_idx).lower() in ("auto", "none", "null"):
        _log(f"🧠 Dynamic dispatch for {_mask_task(slot_id)}...", verbose=True)
        account_idx, raw_cookie = find_and_lock_next_account(slot_id, device_id=device_id)
        if account_idx is None or not raw_cookie:
            err = "ALL_NODES_BUSY: Worker cluster is currently at capacity. Please retry in 1 minute."
            print(f"⚠️ {err} for {_mask_task(slot_id)}")
            update_task_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED", "error": err})
            return
        update_slot_data(slot_id, {"accountIndex": account_idx})
    else:
        try:
            account_idx = int(account_idx)
            is_conflict = False
            try:
                now_ms = int(time.time() * 1000)
                req_chk = urllib.request.Request(f"{STORE_STATUS_BASE}/acc_{account_idx}.json", headers={"User-Agent": _UA})
                with urllib.request.urlopen(req_chk, timeout=6) as r_chk:
                    chk_stat = json.loads(r_chk.read().decode("utf-8")) or {}
                    chk_until = int(chk_stat.get("bookedUntil", 0))
                    chk_by = str(chk_stat.get("bookedBy", ""))
                    chk_busy = bool(chk_stat.get("isBusy", False))
                    if chk_until > now_ms and (chk_busy or chk_by):
                        if not chk_by.startswith(f"cloud_runner_{slot_id}"):
                            is_conflict = True
                            _log(f"⚠️ Account #{account_idx + 1} collision detected; resolving...", verbose=True)
            except Exception:
                pass

            if is_conflict:
                account_idx, raw_cookie = find_and_lock_next_account(slot_id, exclude_indices={account_idx}, device_id=device_id)
                if account_idx is None or not raw_cookie:
                    err = "ALL_NODES_BUSY: Worker cluster is currently at capacity. Please retry in 1 minute."
                    print(f"⚠️ {err} for {_mask_task(slot_id)}")
                    update_task_result(slot_id, "FAILED", error=err)
                    update_slot_data(slot_id, {"status": "FAILED", "error": err})
                    return
                update_slot_data(slot_id, {"accountIndex": account_idx})
            else:
                atomic_lock_account(account_idx, slot_id, device_id)
                raw_cookie = get_active_session_blob(account_idx)
        except Exception:
            err = f"FAILED: Invalid accountIndex '{account_idx}' for {_mask_task(slot_id)}"
            print(f"❌ {err}")
            update_task_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED"})
            return

    task_ctx = TaskExecutionContext(account_idx, slot_id)
    task_type = slot_data.get("taskType") or input_data.get("taskType", "PHOTO_JOB")
    is_quota_probe = (task_type == "VERIFY_QUOTA") or slot_id.startswith("probe_acc_")

    if not device_id:
        try:
            req_acc = urllib.request.Request(f"{STORE_STATUS_BASE}/acc_{account_idx}.json", headers={"User-Agent": _UA})
            with urllib.request.urlopen(req_acc, timeout=6) as r_acc:
                acc_stat = json.loads(r_acc.read().decode("utf-8")) or {}
                device_id = str(acc_stat.get("lastDevice") or acc_stat.get("bookedBy") or "").strip()
                if device_id:
                    _CURRENT_TASK_META["deviceId"] = device_id
                    _log(f"📱 Discovered device from lease: '{_mask_device(device_id)}'", verbose=True)
        except Exception as e_acc:
            _log(f"⚠️ Lease inspect note: {_safe_err(e_acc)}", verbose=True)

    is_retry_flag = bool(slot_data.get("isRetry") is True or input_data.get("isRetry") is True)
    parent_task_val = slot_data.get("parentTaskId") or input_data.get("parentTaskId")
    if not is_quota_probe:
        auth_ok, auth_err = verify_server_device_authorization(
            device_id,
            slot_id=slot_id,
            is_retry=is_retry_flag,
            parent_task_id=parent_task_val,
        )
        if not auth_ok:
            err = f"SERVER_AUTH_REJECTED: {auth_err}"
            print(f"🛑 {err} for {_mask_task(slot_id)} (Device: '{_mask_device(device_id)}').")
            task_ctx.release_all_locks()
            update_task_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED", "error": err})
            return

    initial_status = slot_data.get("status") or input_data.get("status", "PENDING")
    img_b64 = input_data.get("imageBase64", "")
    dress_b64 = input_data.get("dressImageBase64") or None
    prompt = input_data.get("prompt", "Process input")

    is_prewarm = (initial_status == "WARMING") or (not img_b64 and initial_status != "PENDING" and not is_quota_probe)
    _CURRENT_TASK_META.update({
        "taskId": slot_id,
        "deviceId": device_id,
        "accountIndex": account_idx,
        "isRetry": bool(slot_data.get("isRetry") is True or input_data.get("isRetry") is True),
        "parentTaskId": slot_data.get("parentTaskId") or input_data.get("parentTaskId"),
        "isPrewarm": bool(is_prewarm),
        "hadCustomerInput": bool(img_b64)
    })
    t_start = time.time()

    gate_routes = tuple(_CFG.get("g_routes", []))
    abort_routes = tuple(_CFG.get("abort_routes", []))
    target_url = _CFG["t_url"]

    try:
      with sync_playwright() as p, ExitStack() as _pw_stack:
        browser = p.chromium.launch(
            channel="chrome",
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--window-size=1280,850"
            ]
        )
        dynamic_ua = build_dynamic_user_agent(browser)
        context = browser.new_context(
            user_agent=dynamic_ua,
            viewport={"width": 1280, "height": 850},
            device_scale_factor=1,
            locale="en-US"
        )
        context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        inject_session_to_context(context, raw_cookie)
        page = context.new_page()
        shot_guard = {"done": False}
        _pw_stack.callback(lambda: _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard))

        def handle_route(route):
            url = route.request.url.lower()
            rtype = route.request.resource_type
            if any(g in url for g in gate_routes):
                route.continue_()
                return
            if rtype in ["font", "media"]:
                route.abort()
            elif any(blocked in url for blocked in abort_routes):
                route.abort()
            else:
                route.continue_()

        page.route("**/*", handle_route)

        mode_desc = "PROBE" if is_quota_probe else ("STANDBY" if is_prewarm else "DIRECT")
        print(f"🌍 [BOOT] Target init ({mode_desc})...")
        page.goto(target_url, wait_until="domcontentloaded", timeout=45000)

        time.sleep(1.5)
        auth_err = check_auth_expired(page)
        switched_from = None
        switch_reason = None
        if auth_err:
            try:
                pool_accs = get_decrypted_pool()
                baseline_cookie = pool_accs[account_idx].get("cookie", "") if account_idx < len(pool_accs) else ""
            except Exception:
                baseline_cookie = ""
            if raw_cookie != baseline_cookie and baseline_cookie:
                _log(f"⚠️ Account #{account_idx + 1} fresh token rejected; retrying pool baseline...", verbose=True)
                context.clear_cookies()
                inject_session_to_context(context, baseline_cookie)
                page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                time.sleep(1.5)
                auth_err = check_auth_expired(page)
                if not auth_err:
                    _log(f"✅ Account #{account_idx + 1} recovered with baseline cookie.", verbose=True)
                    try:
                        urllib.request.urlopen(urllib.request.Request(
                            f"{STORE_SECRETS_BASE}/acc_{account_idx}.json",
                            method="DELETE"
                        ), timeout=5)
                        urllib.request.urlopen(urllib.request.Request(
                            f"{STORE_STATUS_BASE}/acc_{account_idx}/freshCookie.json",
                            method="DELETE"
                        ), timeout=4)
                    except Exception:
                        pass

        if auth_err:
            print(f"⚠️ Pre-flight auth expired on Account #{account_idx + 1}: {auth_err}")
            mark_account_expired(account_idx)
            atomic_unlock_account(account_idx, slot_id)
            if is_quota_probe:
                update_slot_data(slot_id, {"status": "FAILED", "error": f"Session Expired: {auth_err}"})
                return

            old_idx = account_idx
            task_ctx.record_unlocked(old_idx)
            new_idx, new_cookie = find_and_lock_next_account(slot_id, exclude_indices=[account_idx], device_id=device_id)
            if new_idx is not None and new_cookie:
                switched_from = old_idx
                switch_reason = "Redirected"
                account_idx = new_idx
                task_ctx.active_idx = new_idx
                _CURRENT_TASK_META["accountIndex"] = new_idx
                task_ctx.record_locked(new_idx)
                update_slot_data(slot_id, {
                    "accountIndex": account_idx,
                    "switchedFrom": switched_from,
                    "switchReason": switch_reason
                })
                context.clear_cookies()
                inject_session_to_context(context, new_cookie)
                page.goto(target_url, wait_until="domcontentloaded", timeout=45000)
                time.sleep(1.5)
                auth_err2 = check_auth_expired(page)
                if auth_err2:
                    print(f"❌ Fallback Account #{account_idx + 1} expired: {auth_err2}")
                    mark_account_expired(account_idx)
                    atomic_unlock_account(account_idx, slot_id)
                    update_task_result(slot_id, "FAILED", error="All available accounts expired")
                    update_slot_data(slot_id, {"status": "FAILED"})
                    _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                    return
            else:
                print("❌ No healthy fallback accounts available in pool!")
                update_task_result(slot_id, "FAILED", error="No healthy accounts in pool")
                update_slot_data(slot_id, {"status": "FAILED"})
                _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                return

        if is_quota_probe:
            inspect_quota_and_restore_bonus(page, context, account_idx, slot_id)
            _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
            return

        try:
            for btn_text in _CFG.get("popups", []):
                btn = page.locator(f'button:has-text("{btn_text}")').first
                if btn.count() > 0 and btn.is_visible():
                    btn.click(timeout=1000)
        except Exception:
            pass

        if img_b64:
            current_status = initial_status
            current_input = input_data
            has_input = True
        else:
            current_status = initial_status
            current_input = input_data
            has_input = False
            try:
                req_st0 = urllib.request.Request(f"{STORE_TASKS_BASE}/{slot_id}/status.json", headers={"User-Agent": _UA})
                with urllib.request.urlopen(req_st0, timeout=4) as r_st0:
                    st_val = json.loads(r_st0.read().decode("utf-8"))
                    if st_val:
                        current_status = st_val
            except Exception:
                pass
            if current_status == "CANCELLED":
                print(f"⏹️ Slot {_mask_task(slot_id)} was CANCELLED during boot. Exiting cleanly.")
                push_run_telemetry(
                    task_id=slot_id,
                    status="CANCELLED",
                    account_idx=account_idx,
                    duration_sec=time.time() - t_start,
                    is_prewarm=True,
                    device_id=device_id,
                    error="Cancelled by operator during boot"
                )
                task_ctx.release_all_locks()
                _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                return
            if current_status == "PENDING":
                current_slot = fetch_slot_data(slot_id)
                current_input = current_slot.get("input", {})
                has_input = bool(current_input.get("imageBase64"))

        if is_prewarm and not has_input and current_status != "PENDING":
            cf_err = wait_through_gate_challenge(page, max_wait_sec=12.0)
            if cf_err:
                cf_st = None
                try:
                    req_cf = urllib.request.Request(f"{STORE_TASKS_BASE}/{slot_id}/status.json", headers={"User-Agent": _UA})
                    with urllib.request.urlopen(req_cf, timeout=4) as r_cf:
                        cf_st = json.loads(r_cf.read().decode("utf-8"))
                except Exception:
                    pass
                if cf_st == "CANCELLED":
                    print(f"⏹️ Slot {_mask_task(slot_id)} was CANCELLED during gate wait.")
                    push_run_telemetry(
                        task_id=slot_id,
                        status="CANCELLED",
                        account_idx=account_idx,
                        duration_sec=time.time() - t_start,
                        is_prewarm=True,
                        device_id=device_id,
                        error="Cancelled by operator during boot"
                    )
                    task_ctx.release_all_locks()
                else:
                    err = f"TRANSIENT_TIMEOUT: GATE_CHALLENGE_BLOCKED on Account #{account_idx + 1}"
                    print(f"🛡️ {err}")
                    atomic_unlock_account(account_idx, slot_id)
                    task_ctx.record_unlocked(account_idx)
                    update_task_result(slot_id, "FAILED", error=err, account_idx=account_idx)
                    update_slot_data(slot_id, {"status": "FAILED"})
                _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                return

            try:
                prewarm_composer = page.locator(_CFG["sel_comp"]).first
                prewarm_composer.wait_for(state="visible", timeout=20000)
            except Exception as e_pw:
                late_cf = detect_gate_challenge(page)
                if late_cf:
                    err = f"TRANSIENT_TIMEOUT: Pre-warm blocked by gate challenge on Account #{account_idx + 1} ({late_cf})"
                else:
                    err = f"TRANSIENT_TIMEOUT: Standby input not ready in 20s ({_safe_err(e_pw)})"
                print(f"⚠️ {err}")
                atomic_unlock_account(account_idx, slot_id)
                task_ctx.record_unlocked(account_idx)
                update_task_result(slot_id, "FAILED", error=err, account_idx=account_idx)
                update_slot_data(slot_id, {"status": "FAILED"})
                _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                return

            pre_ready_status = None
            try:
                req_pr = urllib.request.Request(f"{STORE_TASKS_BASE}/{slot_id}/status.json", headers={"User-Agent": _UA})
                with urllib.request.urlopen(req_pr, timeout=4) as r_pr:
                    pre_ready_status = json.loads(r_pr.read().decode("utf-8"))
            except Exception:
                pass

            if pre_ready_status == "CANCELLED":
                print(f"⏹️ Slot {_mask_task(slot_id)} was CANCELLED right before READY.")
                push_run_telemetry(
                    task_id=slot_id,
                    status="CANCELLED",
                    account_idx=account_idx,
                    duration_sec=time.time() - t_start,
                    is_prewarm=True,
                    device_id=device_id,
                    error="Cancelled by operator during standby boot"
                )
                task_ctx.release_all_locks()
                _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                return

            if pre_ready_status != "PENDING":
                update_slot_data(slot_id, {
                    "status": "READY",
                    "warmedAt": int(time.time() * 1000),
                    "accountIndex": account_idx
                })
            push_run_telemetry(
                task_id=slot_id,
                status="READY",
                account_idx=account_idx,
                duration_sec=time.time() - t_start,
                is_prewarm=True,
                device_id=device_id
            )
            print(f"🔥 Runner is WARM & READY in {time.time() - t_start:.2f}s! Standby poll (180s max)...")

            standby_start = time.time()
            task_received = False
            while (time.time() - standby_start) < 180:
                poll_status = None
                try:
                    req_st = urllib.request.Request(f"{STORE_TASKS_BASE}/{slot_id}/status.json", headers={"User-Agent": _UA})
                    with urllib.request.urlopen(req_st, timeout=4) as r_st:
                        poll_status = json.loads(r_st.read().decode("utf-8"))
                except Exception:
                    pass

                if poll_status == "PENDING":
                    poll_slot = fetch_slot_data(slot_id)
                    p_input = poll_slot.get("input", {})
                    for _prop in range(6):
                        if p_input.get("imageBase64"):
                            break
                        time.sleep(0.5)
                        poll_slot = fetch_slot_data(slot_id)
                        p_input = poll_slot.get("input", {})
                    standby_wait = time.time() - standby_start
                    print(f"⚡ Pickup after {standby_wait:.1f}s standby")
                    auth_ok, auth_err = verify_server_device_authorization(
                        device_id,
                        slot_id=slot_id,
                        is_retry=bool(poll_slot.get("isRetry") is True or p_input.get("isRetry") is True),
                        parent_task_id=poll_slot.get("parentTaskId") or p_input.get("parentTaskId"),
                    )
                    if not auth_ok:
                        err = f"SERVER_AUTH_REJECTED: {auth_err}"
                        print(f"🛑 {err} on warm pickup {_mask_task(slot_id)} (Device: '{_mask_device(device_id)}').")
                        task_ctx.release_all_locks()
                        update_task_result(slot_id, "FAILED", error=err)
                        update_slot_data(slot_id, {"status": "FAILED", "error": err})
                        _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                        return
                    t_start = t_start + standby_wait
                    _CURRENT_TASK_START = t_start
                    prompt = p_input.get("prompt", prompt)
                    img_b64 = p_input.get("imageBase64", "")
                    dress_b64 = p_input.get("dressImageBase64", dress_b64)
                    atomic_lock_account(account_idx, slot_id, device_id)
                    update_slot_data(slot_id, {"status": "PROCESSING"})
                    push_run_telemetry(
                        task_id=slot_id,
                        status="PROCESSING",
                        account_idx=account_idx,
                        is_prewarm=True,
                        device_id=device_id,
                        had_customer_input=True
                    )
                    task_received = True
                    break
                elif poll_status == "CANCELLED":
                    print(f"⏹️ Slot {_mask_task(slot_id)} was CANCELLED by operator. Exiting cleanly.")
                    push_run_telemetry(
                        task_id=slot_id,
                        status="CANCELLED",
                        account_idx=account_idx,
                        duration_sec=time.time() - t_start,
                        is_prewarm=True,
                        device_id=device_id,
                        error="Cancelled by operator during standby"
                    )
                    task_ctx.release_all_locks()
                    _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                    return

                time.sleep(0.8)

            if not task_received:
                print(f"⏰ Slot {_mask_task(slot_id)} 180s watchdog expired with no operator input.")
                update_slot_data(slot_id, {"status": "EXPIRED"})
                push_run_telemetry(
                    task_id=slot_id,
                    status="EXPIRED",
                    account_idx=account_idx,
                    duration_sec=time.time() - t_start,
                    is_prewarm=True,
                    device_id=device_id,
                    error="180s watchdog expired with no operator input"
                )
                task_ctx.release_all_locks()
                _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
                return
        else:
            print(f"⚡ Direct task execution (boot: {time.time() - t_start:.2f}s)")
            prompt = current_input.get("prompt", prompt)
            img_b64 = current_input.get("imageBase64", img_b64)
            dress_b64 = current_input.get("dressImageBase64", dress_b64)
            update_slot_data(slot_id, {"status": "PROCESSING"})
            push_run_telemetry(
                task_id=slot_id,
                status="PROCESSING",
                account_idx=account_idx,
                is_prewarm=bool(is_prewarm),
                device_id=device_id,
                had_customer_input=True
            )

        if not is_quota_probe and not img_b64:
            err = "FAILED: No photo attached in task payload"
            print(f"❌ {err}")
            update_task_result(slot_id, "FAILED", error=err, account_idx=task_ctx.active_idx)
            update_slot_data(slot_id, {"status": "FAILED"})
            task_ctx.release_all_locks()
            _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
            return

        try:
            _CURRENT_HAD_CUSTOMER_INPUT = True
            execute_render_job(
                page, slot_id, task_ctx, prompt, img_b64, t_start,
                device_id=device_id,
                switched_from=switched_from,
                switch_reason=switch_reason,
                dress_b64=dress_b64
            )
        finally:
            task_ctx.release_all_locks()
            _close_browser_with_shot(page, browser, slot_id, task_ctx.active_idx, shot_guard)
    finally:
        task_ctx.release_all_locks()


def capture_and_upload_final_screenshot(page, task_id, outcome_hint="", account_idx=None):
    """Captures final browser JPEG (quality=78) and uploads via authenticated edge hook."""
    if not task_id or not page or not EDGE_HOOK_URL:
        return False
    try:
        if page.is_closed():
            return False
        img_bytes = page.screenshot(type="jpeg", quality=78, full_page=False, timeout=6000)
        if not img_bytes or len(img_bytes) < 100:
            return False
        sig = hashlib.sha256(f"{MASTER_SALT_STR}:{task_id}".encode("utf-8")).hexdigest()
        shot_ep = _CFG.get("shot_ep", "/api/runner-screenshot")
        upload_url = f"{EDGE_HOOK_URL}{shot_ep}?taskId={urllib.parse.quote(str(task_id))}"
        headers = {
            "Content-Type": "image/jpeg",
            "X-Worker-Sig": sig,
            "X-Run-Outcome": str(outcome_hint or _CURRENT_TASK_META.get("lastStatus") or "FINISHED")[:40],
            "User-Agent": _UA,
        }
        if account_idx is not None:
            headers["X-Account-Num"] = str(int(account_idx) + 1)
        req = urllib.request.Request(upload_url, data=img_bytes, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=6) as resp:
            if resp.status in (200, 201):
                print(f"📸 Saved final frame ({len(img_bytes) / 1024:.1f} KB JPEG) for {_mask_task(task_id)}")
                return True
    except Exception as e_sh:
        _log(f"ℹ️ Final frame upload skipped for {_mask_task(task_id)}: {_safe_err(e_sh)}", verbose=True)
    return False


def _close_browser_with_shot(page, browser, task_id, account_idx, shot_guard):
    """Guarantees at most one final frame upload per run right before closing browser."""
    if not shot_guard.get("done"):
        shot_guard["done"] = True
        capture_and_upload_final_screenshot(page, task_id, account_idx=account_idx)
    try:
        browser.close()
    except Exception:
        pass


def verify_and_introspect_selectors(page):
    """Introspects live DOM controls with strict empirical guardrails."""
    updates = {}
    _log("🔍 Introspecting live selectors...", verbose=True)

    attach_sel = _CFG["i_att"]
    curr_attach = page.locator(attach_sel).first
    attach_works = False
    try:
        if curr_attach.count() > 0 and curr_attach.is_visible():
            attach_works = True
    except Exception:
        pass

    bad_words = _CFG.get("i_bad", [])
    good_words = _CFG.get("i_good", [])
    if not attach_works:
        try:
            buttons = page.locator('form button, div[class*="composer"] button').all()
            for btn in buttons:
                if not btn.is_visible():
                    continue
                aria = (btn.get_attribute("aria-label") or "").strip()
                tid = (btn.get_attribute("data-testid") or "").strip()
                has_popup = btn.get_attribute("aria-haspopup")

                lower_all = f"{aria} {tid}".lower()
                if any(bad in lower_all for bad in bad_words):
                    continue

                is_candidate = False
                if any(k in lower_all for k in good_words):
                    is_candidate = True
                elif has_popup == "menu" and not any(bad in lower_all for bad in ["model", "account", "settings"]):
                    is_candidate = True

                if is_candidate:
                    btn.click(timeout=2000)
                    page.wait_for_timeout(600)
                    menu_item = page.locator(_CFG["i_menu"]).first
                    if menu_item.count() > 0 and menu_item.is_visible():
                        page.keyboard.press("Escape")
                        new_fragment = f'button[aria-label*="{aria}" i]' if aria else f'[data-testid="{tid}"]'
                        updates["attachButton"] = f"{new_fragment}, {attach_sel}"
                        break
                    else:
                        page.keyboard.press("Escape")
        except Exception as ex:
            _log(f"⚠️ Selector attach scan error: {_safe_err(ex)}", verbose=True)

    prompt_sel = _CFG["i_prompt"]
    curr_prompt = page.locator(prompt_sel).first
    prompt_works = False
    try:
        if curr_prompt.count() > 0 and curr_prompt.is_visible():
            prompt_works = True
    except Exception:
        pass

    if not prompt_works:
        try:
            candidates = page.locator('form [contenteditable="true"], form textarea').all()
            for cand in candidates:
                if cand.is_visible():
                    box = cand.bounding_box()
                    if box and box["width"] > 100 and box["height"] > 20:
                        cid = cand.get_attribute("id")
                        if cid and f"#{cid}" not in prompt_sel:
                            updates["promptInput"] = f"#{cid}, {prompt_sel}"
                            break
        except Exception as ex:
            _log(f"⚠️ Selector prompt scan error: {_safe_err(ex)}", verbose=True)

    return updates


def sync_verified_selectors_to_store(updates):
    try:
        sel_url = f"{STORE_BASE}/{_CFG['n_sel']}"
        req = urllib.request.Request(sel_url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode("utf-8")) or {}

        selectors = data.get("selectors", {})
        changed = False
        for k, v in updates.items():
            if selectors.get(k) != v:
                selectors[k] = v
                changed = True

        if not changed:
            return data.get("version", 2)

        data["version"] = data.get("version", 2) + 1
        data["updatedAt"] = int(time.time() * 1000)
        data["selectors"] = selectors

        req_put = urllib.request.Request(
            sel_url,
            data=json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"),
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="PUT"
        )
        with urllib.request.urlopen(req_put, timeout=8) as r_put:
            if r_put.status in (200, 204):
                _log(f"🎯 Synced updated selectors v{data['version']}", verbose=True)
                return data["version"]
    except Exception as e:
        _log(f"⚠️ Failed to sync selectors: {_safe_err(e)}", verbose=True)
    return None


def cleanup_stale_tasks(max_age_hours=12):
    """Auto-cleanup for ephemeral task nodes older than max_age_hours."""
    _log(f"🧹 Scanning stale tasks >{max_age_hours}h...", verbose=True)
    url = f"{STORE_TASKS_BASE}.json?shallow=true"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    deleted_count = 0
    now_ms = time.time() * 1000
    cutoff_ms = now_ms - (max_age_hours * 3600 * 1000)
    one_hour_ms = 3600 * 1000

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            if not data or data.strip() == "null":
                return 0
            tasks = json.loads(data)
            if not isinstance(tasks, dict):
                return 0

            for task_id in tasks.keys():
                if not str(task_id).startswith(("task_", "warm_", "probe_", "maint_")):
                    continue
                created_at = None
                parts = task_id.split("_")
                if len(parts) >= 2 and parts[1].isdigit():
                    try:
                        created_at = int(parts[1])
                    except Exception:
                        pass

                should_delete = False
                if created_at:
                    if created_at < cutoff_ms:
                        should_delete = True
                    elif now_ms - created_at > one_hour_ms:
                        try:
                            s_url = f"{STORE_TASKS_BASE}/{task_id}/status.json"
                            s_req = urllib.request.Request(s_url, headers={"User-Agent": _UA})
                            with urllib.request.urlopen(s_req, timeout=4) as s_resp:
                                st = (s_resp.read().decode("utf-8") or "").strip('"')
                                if st in ("COMPLETED", "FAILED", "CANCELLED"):
                                    should_delete = True
                        except Exception:
                            pass
                else:
                    try:
                        s_url = f"{STORE_TASKS_BASE}/{task_id}/status.json"
                        s_req = urllib.request.Request(s_url, headers={"User-Agent": _UA})
                        with urllib.request.urlopen(s_req, timeout=4) as s_resp:
                            st = (s_resp.read().decode("utf-8") or "").strip('"')
                            if st in ("COMPLETED", "FAILED", "CANCELLED"):
                                should_delete = True
                    except Exception:
                        pass

                if should_delete:
                    del_url = f"{STORE_TASKS_BASE}/{task_id}.json"
                    del_req = urllib.request.Request(del_url, method="DELETE", headers={"User-Agent": _UA})
                    try:
                        with urllib.request.urlopen(del_req, timeout=5) as del_resp:
                            if del_resp.status in (200, 204):
                                deleted_count += 1
                    except Exception as ex_del:
                        _log(f"⚠️ Cleanup delete failed for {_mask_task(task_id)}: {_safe_err(ex_del)}", verbose=True)

            if deleted_count > 0:
                print(f"🧹 Pruned {deleted_count} stale tasks.")
    except Exception as e:
        _log(f"⚠️ Task cleanup error: {_safe_err(e)}", verbose=True)

    return deleted_count


def run_scheduled_maintenance():
    """Nightly keep-alive, expiry verification, selector check, and daily quota reset."""
    from playwright.sync_api import sync_playwright

    now_local = datetime.now(_STUDIO_TZ).strftime("%I:%M %p, %d %b %Y")
    brand = _CFG.get("brand", "STUDIO")
    print(f"\n==================================================")
    print(f"🌙 SCHEDULED MAINTENANCE & SESSION SYNC")
    print(f"⏰ Time: {now_local}")
    print(f"==================================================")

    dispatch_admin_alert(
        f"🌙 *{brand} - NIGHTLY MAINTENANCE STARTED*\n"
        f"⏰ *Time:* {now_local}\n"
        f"⏳ Inspecting all pool accounts sequentially..."
    )

    accounts = get_decrypted_pool()
    total = len(accounts)
    run_ts = int(time.time() * 1000)
    active_count = 0
    refreshed_count = 0
    expired_count = 0
    cf_blocked_count = 0
    selector_updates = {}
    target_url = _CFG["t_url"]
    session_ep = _CFG["s_ep"]

    with sync_playwright() as p:
        browser = p.chromium.launch(
            channel="chrome",
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--window-size=1280,850"
            ]
        )

        def maintain_single_account(idx, is_retry=False):
            nonlocal active_count, refreshed_count, expired_count, cf_blocked_count
            now_ms = int(time.time() * 1000)

            try:
                check_url = f"{STORE_STATUS_BASE}/acc_{idx}.json"
                req_c = urllib.request.Request(check_url, headers={"User-Agent": _UA})
                with urllib.request.urlopen(req_c, timeout=5) as resp_c:
                    curr_status = json.loads(resp_c.read().decode("utf-8") or "{}")
                    booked_until = curr_status.get("bookedUntil", 0)
                    booked_by = curr_status.get("bookedBy", "")
                    is_busy = curr_status.get("isBusy", False)
                    if is_busy or (booked_until > now_ms and booked_by and booked_by != "nightly_maintenance"):
                        remain_sec = int((booked_until - now_ms) / 1000) if booked_until > now_ms else 0
                        print(f"⏳ Account #{idx+1} busy ({remain_sec}s lease). Deferring.")
                        return "BUSY"
            except Exception as e_check:
                _log(f"Lock check note on Account #{idx+1}: {_safe_err(e_check)}", verbose=True)

            lock_acquired = False
            try:
                lock_url = f"{STORE_STATUS_BASE}/acc_{idx}.json"
                req_l = urllib.request.Request(
                    lock_url,
                    data=json.dumps({"bookedBy": "nightly_maintenance", "bookedUntil": now_ms + 120_000}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PATCH"
                )
                with urllib.request.urlopen(req_l, timeout=5) as resp_l:
                    lock_acquired = resp_l.status in (200, 204)
            except Exception:
                pass

            context = None
            page = None
            acc_start = time.time()
            maint_tid = f"maint_{run_ts}_a{idx + 1:02d}"
            try:
                raw_cookie = get_active_session_blob(idx)
                dynamic_ua = build_dynamic_user_agent(browser)
                context = browser.new_context(
                    user_agent=dynamic_ua,
                    viewport={"width": 1280, "height": 850},
                    device_scale_factor=1,
                    locale="en-US"
                )
                context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
                inject_session_to_context(context, raw_cookie)
                page = context.new_page()

                tag = f"[{'RETRY ' if is_retry else ''}{idx+1}/{total}]"
                print(f"{tag} 🔍 Checking Account #{idx+1}...")

                def _verify_live_session():
                    """Returns (state, detail): 'ACTIVE' | 'EXPIRED' | 'GATE_BLOCKED'."""
                    cf = wait_through_gate_challenge(page, max_wait_sec=15.0)
                    if cf:
                        return "GATE_BLOCKED", cf

                    auth_e = check_auth_expired(page)
                    if auth_e:
                        return "EXPIRED", auth_e

                    try:
                        sess_res = page.evaluate("""async (ep) => {
                            try {
                                const r = await fetch(ep, { credentials: 'include' });
                                if (!r.ok) return { _http: r.status };
                                const ct = (r.headers.get('content-type') || '').toLowerCase();
                                if (!ct.includes('application/json')) return { _non_json: r.status };
                                const data = await r.json();
                                return { _http: r.status, data };
                            } catch (e) { return { _err: String(e) }; }
                        }""", session_ep)
                        if not isinstance(sess_res, dict):
                            sess_res = {"_eval_err": "NonDictResult"}
                    except Exception as e_eval:
                        sess_res = {"_eval_err": type(e_eval).__name__}

                    if "_err" in sess_res or "_eval_err" in sess_res or "_non_json" in sess_res:
                        late_auth = check_auth_expired(page)
                        if late_auth:
                            return "EXPIRED", late_auth
                        tag_err = sess_res.get("_eval_err") or sess_res.get("_non_json") or "FetchError"
                        return "GATE_BLOCKED", f"Transient session check error ({tag_err})"

                    http_code = sess_res.get("_http")
                    if http_code == 401:
                        return "EXPIRED", "HTTP 401 unauthorized session"
                    if http_code != 200:
                        late_auth = check_auth_expired(page)
                        if late_auth:
                            return "EXPIRED", late_auth
                        return "GATE_BLOCKED", f"Transient HTTP {http_code} on session check"

                    payload = sess_res.get("data")
                    has_user = isinstance(payload, dict) and (bool(payload.get("user")) or bool(payload.get("accessToken")))
                    if not has_user:
                        late_cf = detect_gate_challenge(page)
                        if late_cf:
                            return "GATE_BLOCKED", late_cf
                        return "EXPIRED", "HTTP 200 empty auth session payload"

                    try:
                        comp = page.locator(_CFG["sel_comp"]).first
                        comp.wait_for(state="visible", timeout=15000)
                    except Exception:
                        late_cf = detect_gate_challenge(page)
                        if late_cf:
                            return "GATE_BLOCKED", late_cf
                        late_auth = check_auth_expired(page)
                        if late_auth:
                            return "EXPIRED", late_auth

                    return "ACTIVE", "Verified session + input ready"

                page.goto(target_url, wait_until="domcontentloaded", timeout=40000)
                time.sleep(2.0)
                state, detail = _verify_live_session()

                baseline_cookie = accounts[idx].get("cookie", "")
                if state == "EXPIRED" and baseline_cookie and raw_cookie != baseline_cookie:
                    _log(f"⚠️ Account #{idx+1} synced token failed; testing baseline...", verbose=True)
                    context.clear_cookies()
                    inject_session_to_context(context, baseline_cookie)
                    page.goto(target_url, wait_until="domcontentloaded", timeout=40000)
                    time.sleep(2.0)
                    state, detail = _verify_live_session()

                if state == "EXPIRED":
                    _log(f"⚠️ Account #{idx+1} rechecking in 8s...", verbose=True)
                    time.sleep(8.0)
                    try:
                        page.reload(wait_until="domcontentloaded", timeout=30000)
                        time.sleep(2.0)
                        state, detail = _verify_live_session()
                    except Exception as e_re:
                        detail = f"Reload failed: {_safe_err(e_re)}"

                if state == "GATE_BLOCKED":
                    print(f"🛡️ Account #{idx+1} [GATE_BLK] ({detail})")
                    cf_blocked_count += 1
                    capture_and_upload_final_screenshot(page, maint_tid, outcome_hint="MAINT_BLOCKED", account_idx=idx)
                    push_run_telemetry(
                        task_id=maint_tid,
                        status="MAINT_BLOCKED",
                        account_idx=idx,
                        duration_sec=time.time() - acc_start,
                        is_retry=is_retry,
                        is_prewarm=False,
                        error=detail,
                        had_customer_input=False,
                        is_maintenance=True,
                    )
                elif state == "EXPIRED":
                    print(f"❌ Account #{idx+1} [EXPIRED] ({detail})")
                    capture_and_upload_final_screenshot(page, maint_tid, outcome_hint="MAINT_EXPIRED", account_idx=idx)
                    mark_account_expired(idx)
                    expired_count += 1
                    push_run_telemetry(
                        task_id=maint_tid,
                        status="MAINT_EXPIRED",
                        account_idx=idx,
                        duration_sec=time.time() - acc_start,
                        is_retry=is_retry,
                        is_prewarm=False,
                        error=detail,
                        had_customer_input=False,
                        is_maintenance=True,
                    )
                else:
                    active_count += 1
                    for btn_text in _CFG.get("popups", []):
                        try:
                            btn = page.locator(f'button:has-text("{btn_text}")').first
                            if btn.count() > 0 and btn.is_visible():
                                btn.click(timeout=1000)
                        except Exception:
                            pass

                    try:
                        urllib.request.urlopen(urllib.request.Request(
                            f"{STORE_STATUS_BASE}/acc_{idx}.json",
                            data=json.dumps({"isExpired": False}).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="PATCH"
                        ), timeout=4)
                    except Exception:
                        pass

                    time.sleep(1.0)
                    synced = sync_session_state(context, idx)
                    if synced:
                        refreshed_count += 1

                    if not selector_updates:
                        try:
                            discovered = verify_and_introspect_selectors(page)
                            if discovered:
                                selector_updates.update(discovered)
                        except Exception as e_sel:
                            _log(f"⚠️ Selector note: {_safe_err(e_sel)}", verbose=True)

                    capture_and_upload_final_screenshot(page, maint_tid, outcome_hint="MAINT_OK", account_idx=idx)
                    push_run_telemetry(
                        task_id=maint_tid,
                        status="MAINT_OK",
                        account_idx=idx,
                        duration_sec=time.time() - acc_start,
                        is_retry=is_retry,
                        is_prewarm=False,
                        error=None,
                        had_customer_input=False,
                        is_maintenance=True,
                    )
                    print(f"✅ Account #{idx+1} [AUTH_OK]")
                return "DONE"
            except Exception as e_acc:
                safe_msg = _safe_err(e_acc)
                print(f"⚠️ Maintenance error on Account #{idx+1}: {safe_msg}")
                if page:
                    capture_and_upload_final_screenshot(page, maint_tid, outcome_hint="MAINT_ERROR", account_idx=idx)
                push_run_telemetry(
                    task_id=maint_tid,
                    status="MAINT_ERROR",
                    account_idx=idx,
                    duration_sec=time.time() - acc_start,
                    is_retry=is_retry,
                    is_prewarm=False,
                    error=safe_msg,
                    had_customer_input=False,
                    is_maintenance=True,
                )
                return "ERROR"
            finally:
                if lock_acquired:
                    try:
                        atomic_unlock_account(idx, "nightly_maintenance")
                    except Exception:
                        pass
                if context:
                    try:
                        context.close()
                    except Exception:
                        pass

        skipped_for_retry = []
        for idx in range(total):
            res = maintain_single_account(idx, is_retry=False)
            if res == "BUSY":
                skipped_for_retry.append(idx)
            if idx + 1 < total:
                time.sleep(2.5)

        if skipped_for_retry:
            time.sleep(15.0)
            for idx in skipped_for_retry:
                maintain_single_account(idx, is_retry=True)

        browser.close()

    selector_status_msg = "Selectors verified (v2)"
    if selector_updates:
        try:
            new_ver = sync_verified_selectors_to_store(selector_updates)
            if new_ver:
                selector_status_msg = f"Selectors updated to v{new_ver}"
        except Exception as e_sync:
            _log(f"⚠️ Selector sync notice: {_safe_err(e_sync)}", verbose=True)

    pruned_tasks = cleanup_stale_tasks(max_age_hours=12)

    reset_count = 0
    total_cap = 0
    try:
        today_str = get_studio_day_string()
        saved_limit = get_max_images_per_account(default=3)

        live_status_map = {}
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{STORE_STATUS_BASE}.json", headers={"User-Agent": _UA}), timeout=6) as r_ls:
                live_status_map = json.loads(r_ls.read().decode("utf-8")) or {}
        except Exception:
            live_status_map = {}

        now_rst_ms = int(time.time() * 1000)
        pool_patch = {"maxImagesPerAccount": saved_limit}
        for i in range(total):
            acc_cur = live_status_map.get(f"acc_{i}", {}) if isinstance(live_status_map, dict) else {}
            cur_by = str(acc_cur.get("bookedBy") or "")
            cur_until = int(acc_cur.get("bookedUntil") or 0)
            has_live_job = bool(cur_by and cur_by != "nightly_maintenance" and cur_until > now_rst_ms)

            pool_patch[f"acc_{i}/usage"] = 0
            pool_patch[f"acc_{i}/quotaDay"] = today_str
            pool_patch[f"acc_{i}/resetTime"] = ""
            if not has_live_job:
                pool_patch[f"acc_{i}/isBusy"] = False
                pool_patch[f"acc_{i}/bookedBy"] = ""
                pool_patch[f"acc_{i}/bookedUntil"] = 0
        if pool_patch:
            req_rst = urllib.request.Request(
                f"{STORE_STATUS_BASE}.json",
                data=json.dumps(pool_patch).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="PATCH"
            )
            with urllib.request.urlopen(req_rst, timeout=8) as resp_rst:
                if resp_rst.status in (200, 204):
                    reset_count = total
                    total_cap = total * saved_limit
                    print(f"🎯 Daily quota reset complete: {total_cap}/{total_cap} ({today_str})")
    except Exception as e_rst:
        print(f"⚠️ Quota auto-reset notice: {_safe_err(e_rst)}")

    end_local = datetime.now(_STUDIO_TZ).strftime("%I:%M %p, %d %b %Y")
    summary_msg = (
        f"✅ *{brand} - NIGHTLY MAINTENANCE COMPLETED* 🌟\n"
        f"══════════════════════════════\n"
        f"📊 *Total Accounts Inspected:* {total}\n"
        f"🟢 *Active & Kept-Alive:* {active_count}\n"
        f"🔄 *Tokens Rotated & Synced:* {refreshed_count}\n"
        f"🔴 *Confirmed Expired:* {expired_count}\n"
        f"🛡️ *Challenge Skipped (Unchanged):* {cf_blocked_count}\n"
        f"🎯 *Daily Pool Reset:* {total_cap}/{total_cap} Available ({reset_count} Accounts Cleaned ✅)\n"
        f"🎯 *DOM Selectors:* {selector_status_msg}\n"
        f"🧹 *Ephemeral Tasks Pruned:* {pruned_tasks}\n"
        f"⏰ *Completion Time:* {end_local}\n"
        f"══════════════════════════════\n"
        f"🛡️ Sliding session window & pool capacity refreshed."
    )
    dispatch_admin_alert(summary_msg)
    print(f"\n📊 Maintenance summary: active={active_count}/{total}, synced={refreshed_count}, expired={expired_count}, gate_skipped={cf_blocked_count}")


if __name__ == "__main__":
    target_task_id = "test_task"
    if len(sys.argv) > 1:
        target_task_id = sys.argv[1]
    else:
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if event_path and os.path.exists(event_path):
            with open(event_path, "r") as f:
                event_data = json.load(f)
            target_task_id = event_data.get("client_payload", {}).get("task_id", "task_default")

    if target_task_id == "nightly_maintenance" or os.environ.get("RUN_MODE") == "NIGHTLY_MAINTENANCE":
        run_scheduled_maintenance()
    else:
        try:
            process_runner_task(target_task_id)
        except Exception as fatal_e:
            err_msg = f"FATAL_WORKER_CRASH: {_safe_err(fatal_e)}"
            print(f"💥 Unhandled error for {_mask_task(target_task_id)}: {err_msg}")
            try:
                req_st = urllib.request.Request(f"{STORE_TASKS_BASE}/{target_task_id}/status.json", headers={"User-Agent": _UA})
                with urllib.request.urlopen(req_st, timeout=4) as r_st:
                    st = json.loads(r_st.read().decode("utf-8")) or ""
                if st not in ("COMPLETED", "FAILED", "CANCELLED"):
                    update_task_result(target_task_id, "FAILED", error=err_msg)
                    update_slot_data(target_task_id, {"status": "FAILED", "error": err_msg})
            except Exception:
                pass
            raise
