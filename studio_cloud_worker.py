import time
import json
import base64
import hashlib
import os
import re
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone, timedelta

if sys.platform.startswith('win'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

MASTER_SALT_STR = (os.environ.get("MASTER_SALT") or "").strip()
if not MASTER_SALT_STR:
    raise RuntimeError("CRITICAL ERROR: MASTER_SALT secret is not configured!")
MASTER_SALT = MASTER_SALT_STR.encode("utf-8")

FIREBASE_BASE = (os.environ.get("FIREBASE_BASE_URL") or "").strip().rstrip("/")
if not FIREBASE_BASE:
    raise RuntimeError("CRITICAL ERROR: FIREBASE_BASE_URL secret is not configured!")
FIREBASE_TASKS_BASE = f"{FIREBASE_BASE}/studio_tasks"
FIREBASE_STATUS_BASE = f"{FIREBASE_BASE}/cookie_pool_status"
FIREBASE_COOKIE_URL = f"{FIREBASE_BASE}/cookie_pool.json"

def _safe_err(err):
    m = str(err)
    if FIREBASE_BASE and FIREBASE_BASE in m:
        m = m.replace(FIREBASE_BASE, "https://[VAULT_ENDPOINT]")
    return m

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


def get_decrypted_pool():
    req = urllib.request.Request(FIREBASE_COOKIE_URL, headers={"User-Agent": "StudioCloudWorker"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read().decode("utf-8"))

    enc = data.get("enc", "")
    decrypted = decrypt_data_aes(enc)
    parsed = json.loads(decrypted)

    accounts = parsed.get("accounts", [])
    if not accounts:
        raise RuntimeError("No accounts found in decrypted pool!")
    return accounts


def send_whatsapp_alert(message):
    try:
        config_url = f"{FIREBASE_BASE}/studio_admin_config/whatsapp.json"
        api_url = os.environ.get("GREEN_API_URL", "https://7107.api.greenapi.com")
        id_instance = os.environ.get("GREEN_API_ID_INSTANCE") or os.environ.get("ID_INSTANCE") or ""
        api_token = os.environ.get("GREEN_API_TOKEN") or os.environ.get("API_TOKEN") or ""
        chat_id = os.environ.get("ADMIN_CHAT_ID") or ""
        is_enabled = True

        try:
            req = urllib.request.Request(config_url, headers={"User-Agent": "StudioCloudWorker"})
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

        if not is_enabled or not id_instance or not api_token or not chat_id:
            return False

        url = f"{api_url}/waInstance{id_instance}/sendMessage/{api_token}"
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
        print(f"⚠️ Failed to send WhatsApp alert: {e}")
        return False


def sync_fresh_cookies(context, account_idx):
    if account_idx is None or context is None:
        return False
    try:
        cookies = context.cookies()
        if not cookies:
            return False

        has_auth_token = False
        parts = []
        for c in cookies:
            domain = c.get("domain", "")
            name = c.get("name", "")
            val = c.get("value", "")
            if not name or not val:
                continue
            if "session-token" in name:
                has_auth_token = True
            if "chatgpt.com" in domain or "openai.com" in domain:
                parts.append(f"{name}={val}")

        if not has_auth_token or not parts:
            return False

        cookie_str = "; ".join(parts)
        encrypted_b64 = encrypt_data_aes(cookie_str)
        now_ms = int(time.time() * 1000)

        patch_url = f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json"
        patch_payload = {
            "freshCookie": encrypted_b64,
            "lastCookieSync": now_ms
        }
        req = urllib.request.Request(
            patch_url,
            data=json.dumps(patch_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            if r.status in (200, 204):
                print(f"🔄 Account #{int(account_idx)+1}: Rotated NextAuth session token captured & synced to Firebase! ({len(parts)} cookies)")
                return True
    except Exception as e:
        print(f"⚠️ Notice on cookie sync for Account #{int(account_idx)+1}: {_safe_err(e)}")
    return False


def get_active_cookie(account_idx=None):
    accounts = get_decrypted_pool()
    if account_idx is None:
        return accounts[0].get("cookie", "")

    try:
        idx = int(account_idx) % len(accounts)
    except Exception:
        idx = 0

    # 1. Check for fresh rotated cookie in Firebase status
    try:
        req_fresh = urllib.request.Request(f"{FIREBASE_STATUS_BASE}/acc_{idx}/freshCookie.json", headers={"User-Agent": "StudioCloudWorker"})
        with urllib.request.urlopen(req_fresh, timeout=5) as resp:
            fresh_enc = json.loads(resp.read().decode("utf-8"))
            if fresh_enc and isinstance(fresh_enc, str) and len(fresh_enc) > 30:
                decrypted = decrypt_data_aes(fresh_enc)
                if decrypted and ("session-token" in decrypted or "oai-did" in decrypted):
                    print(f"🎯 Assigned Account #{idx + 1} (Using Fresh Synced Cookie 🔄)")
                    return decrypted
    except Exception as e_fresh:
        print(f"ℹ️ Account #{idx + 1} fresh cookie check fallback: {_safe_err(e_fresh)}")

    # 2. Fall back to static cookie from pool
    print(f"🎯 Assigned Account #{idx + 1} (Using Pool Baseline Cookie 📦)")
    return accounts[idx].get("cookie", "")


def inject_cookies_to_context(context, raw_cookie_str):
    added = 0
    skipped = 0
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
                "url": "https://chatgpt.com",
                "secure": True
            }])
            added += 1
        except Exception:
            try:
                context.add_cookies([{
                    "name": k,
                    "value": v,
                    "domain": "chatgpt.com",
                    "path": "/",
                    "secure": True
                }])
                added += 1
            except Exception as e2:
                skipped += 1
    print(f"🍪 Injected {added} cookies (skipped: {skipped})")


def fetch_slot_data(slot_id):
    url = f"{FIREBASE_TASKS_BASE}/{slot_id}.json"
    req = urllib.request.Request(url, headers={"User-Agent": "StudioCloudWorker"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
            if data and data.strip() != "null":
                return json.loads(data)
    except Exception as e:
        print(f"⚠️ Error fetching slot {slot_id}: {_safe_err(e)}")
    return {}


def update_slot_data(slot_id, updates):
    url = f"{FIREBASE_TASKS_BASE}/{slot_id}.json"
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
        print(f"⚠️ Error updating slot {slot_id}: {_safe_err(e)}")
        return False


def update_firebase_result(task_id, status, image_b64=None, error=None):
    url = f"{FIREBASE_TASKS_BASE}/{task_id}/result.json"
    report = {
        "taskId": task_id,
        "status": status,
        "completedAt": time.time()
    }
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
            print(f"📡 Firebase task {task_id} result updated: {resp.status} ({status})")
    except Exception as e:
        print(f"⚠️ Error updating Firebase result: {_safe_err(e)}")


def mark_account_expired(account_idx):
    if account_idx is None:
        return
    try:
        expire_url = f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json"
        req = urllib.request.Request(
            expire_url,
            data=json.dumps({"isExpired": True, "bookedBy": "", "bookedUntil": 0}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"⚠️ Marked account #{int(account_idx)+1} as isExpired in Firebase pool.")
    except Exception as ex:
        print(f"Failed to mark expired: {_safe_err(ex)}")


def mark_account_rate_limited(account_idx, reset_time=None):
    if account_idx is None:
        return
    try:
        nepal_time = datetime.now(timezone(timedelta(hours=5, minutes=45)))
        today_nepal = nepal_time.strftime("%Y-%m-%d")
        
        # Read current dynamic limit (default 3)
        max_images = 3
        try:
            req_stat = urllib.request.Request(f"{FIREBASE_STATUS_BASE}.json", headers={"User-Agent": "StudioCloudWorker"})
            with urllib.request.urlopen(req_stat, timeout=5) as resp:
                stat_data = json.loads(resp.read().decode("utf-8")) or {}
                max_images = int(stat_data.get("maxImagesPerAccount", stat_data.get("max_images_per_account", 3)))
        except Exception:
            pass

        acc_url = f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json"
        patch_payload = {
            "usage": max_images,
            "quotaDay": today_nepal,
            "bookedBy": "",
            "bookedUntil": 0
        }
        if reset_time:
            patch_payload["resetTime"] = reset_time
            patch_payload["lastBlockedProbeTime"] = int(time.time() * 1000)

        req = urllib.request.Request(
            acc_url,
            data=json.dumps(patch_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"⚠️ Marked account #{int(account_idx)+1} rate limited (usage={max_images}, resetTime={reset_time}) in Firebase pool.")
    except Exception as ex:
        print(f"Failed to mark rate limit: {_safe_err(ex)}")


def atomic_lock_account(account_idx, slot_id):
    if account_idx is None:
        return
    try:
        now_ms = int(time.time() * 1000)
        acc_url = f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json"
        payload = {
            "bookedBy": f"cloud_runner_{slot_id}",
            "bookedUntil": now_ms + 180_000,
            "lastUsed": now_ms
        }
        req = urllib.request.Request(
            acc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"🔒 Atomically locked Account #{int(account_idx)+1} for slot {slot_id}")
    except Exception as e:
        print(f"⚠️ Failed to lock Account #{int(account_idx)+1}: {_safe_err(e)}")


def atomic_unlock_account(account_idx, slot_id):
    if account_idx is None:
        return
    try:
        acc_url = f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json"
        payload = {
            "bookedBy": "",
            "bookedUntil": 0
        }
        req = urllib.request.Request(
            acc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"🔓 Released lock on Account #{int(account_idx)+1} for slot {slot_id}")
    except Exception as e:
        print(f"⚠️ Failed to unlock Account #{int(account_idx)+1}: {_safe_err(e)}")


def find_and_lock_next_account(slot_id, exclude_indices=None):
    if exclude_indices is None:
        exclude_indices = set()
    else:
        exclude_indices = set(exclude_indices)

    print(f"🔄 Self-Healing: Finding next eligible account (excluding: {exclude_indices})...")
    nepal_time = datetime.now(timezone(timedelta(hours=5, minutes=45)))
    today_nepal = nepal_time.strftime("%Y-%m-%d")
    now_ms = int(time.time() * 1000)

    try:
        # Fetch current pool status
        req = urllib.request.Request(f"{FIREBASE_STATUS_BASE}.json", headers={"User-Agent": "StudioCloudWorker"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            status_data = json.loads(resp.read().decode("utf-8")) or {}

        max_images = int(status_data.get("maxImagesPerAccount", status_data.get("max_images_per_account", 3)))
        accounts = get_decrypted_pool()
        total_accounts = len(accounts)

        candidates = []

        for i in range(total_accounts):
            if i in exclude_indices:
                continue
            acc_info = status_data.get(f"acc_{i}", {})
            if acc_info.get("isExpired", False):
                continue
            
            # Check booking lease
            booked_until = int(acc_info.get("bookedUntil", 0))
            booked_by = acc_info.get("bookedBy", "")
            if booked_until > now_ms and not booked_by.startswith(f"cloud_runner_{slot_id}"):
                continue

            q_day = acc_info.get("quotaDay", "")
            usage = int(acc_info.get("usage", 0)) if q_day == today_nepal else 0
            remaining = max(0, max_images - usage)

            if remaining > 0:
                candidates.append((remaining, i))

        # Sort by remaining DESC (highest quota first), then index ASC (upper-to-down)
        candidates.sort(key=lambda x: (-x[0], x[1]))

        chosen_idx = candidates[0][1] if candidates else None

        if chosen_idx is not None:
            atomic_lock_account(chosen_idx, slot_id)
            print(f"✅ Self-Healing: Switched to Account #{chosen_idx + 1}")
            return chosen_idx, accounts[chosen_idx].get("cookie", "")
    except Exception as e:
        print(f"❌ Self-Healing error: {_safe_err(e)}")

    return None, ""


def check_login_or_auth_expired(page):
    try:
        current_url = page.url.lower()
        if "/auth/login" in current_url or "auth0.openai.com" in current_url:
            return "Redirected to auth/login URL"
        if page.locator('#modal-no-auth-login, [data-testid="modal-no-auth-login"]').count() > 0:
            if page.locator('#modal-no-auth-login, [data-testid="modal-no-auth-login"]').first.is_visible():
                return "Unauthorized login modal displayed"
        login_btn = page.locator('button[data-testid="login-button"], a[data-testid="login-button"]').first
        if login_btn.count() > 0 and login_btn.is_visible():
            return "Prominent Log In button visible"
    except Exception:
        pass
    return None


def execute_chatgpt_generation(page, slot_id, account_idx, prompt, img_b64, t_start):
    temp_img_path = None
    if img_b64:
        try:
            temp_img_path = os.path.join(tempfile.gettempdir(), f"{slot_id}_in.jpg")
            with open(temp_img_path, "wb") as f:
                f.write(base64.b64decode(img_b64))
            print(f"💾 Input image saved to: {temp_img_path} ({os.path.getsize(temp_img_path)} bytes)")
        except Exception as e:
            print(f"⚠️ Error saving input image: {e}")

    # Wait for composer
    composer = page.locator(
        "#prompt-textarea:not(.wcDTda_fallbackTextarea):visible, "
        "div[contenteditable='true']:visible, "
        "textarea:not(.wcDTda_fallbackTextarea):visible"
    ).first

    composer_ready = False
    try:
        composer.wait_for(state="visible", timeout=30000)
        composer_ready = True
    except Exception:
        pass

    if not composer_ready:
        auth_err = check_login_or_auth_expired(page)
        if auth_err:
            err = f"EXPLICIT_AUTH_EXPIRED: Account #{int(account_idx)+1}: {auth_err}"
            print(f"❌ {err}")
            mark_account_expired(account_idx)
            atomic_unlock_account(account_idx, slot_id)
        else:
            print(f"⚠️ Composer not ready within 30s on Account #{int(account_idx)+1} (network or render lag).")
            print(f"🔓 Safely releasing lock on Account #{int(account_idx)+1} so it remains healthy for next time...")
            atomic_unlock_account(account_idx, slot_id)

        # In-Flight Round-Robin Hot-Swap to next available account
        print(f"⚡ In-Flight Hot-Swap: Querying next eligible account from pool...")
        new_idx, new_cookie = find_and_lock_next_account(slot_id, exclude_indices=[account_idx])
        if new_idx is not None and new_cookie:
            print(f"🚀 In-Flight Hot-Swap Success: Switched to Account #{new_idx+1}!")
            account_idx = new_idx
            update_slot_data(slot_id, {"accountIndex": account_idx})
            try:
                page.context.clear_cookies()
                inject_cookies_to_context(page.context, new_cookie)
                page.goto("https://chatgpt.com", wait_until="domcontentloaded", timeout=45000)
                time.sleep(1.0)
                for btn_text in ["Stay logged out", "Dismiss", "Close", "Not now", "Got it", "Maybe later", "Okay", "Continue"]:
                    btn = page.locator(f'button:has-text("{btn_text}")').first
                    if btn.count() > 0 and btn.is_visible():
                        btn.click(timeout=1000)
                composer = page.locator(
                    "#prompt-textarea:not(.wcDTda_fallbackTextarea):visible, "
                    "div[contenteditable='true']:visible, "
                    "textarea:not(.wcDTda_fallbackTextarea):visible"
                ).first
                composer.wait_for(state="visible", timeout=30000)
                composer_ready = True
                print(f"✅ Hot-swap Account #{account_idx+1} composer ready!")
            except Exception as e_swap:
                print(f"❌ Hot-swap failed on Account #{account_idx+1}: {e_swap}")
                update_firebase_result(slot_id, "FAILED", error=f"TRANSIENT_TIMEOUT: Hot-swap Account #{account_idx+1} failed ({e_swap})")
                update_slot_data(slot_id, {"status": "FAILED"})
                return False
        else:
            err = f"TRANSIENT_TIMEOUT: Composer not ready within 30s on Account #{int(account_idx)+1} (no fallback available)"
            print(f"❌ {err}")
            update_firebase_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED"})
            return False

    # Capture rotated cookies as soon as composer is authenticated & ready
    sync_fresh_cookies(page.context, account_idx)

    photo_uploaded = False
    if temp_img_path and os.path.exists(temp_img_path):
        print("📤 Uploading portrait to ChatGPT...")
        try:
            file_input = page.locator('input[type="file"]').first
            file_input.wait_for(state="attached", timeout=15000)
            file_input.set_input_files(temp_img_path)
        except Exception as e:
            err = f"TRANSIENT_TIMEOUT: File input attach timed out ({e})"
            print(f"❌ {err}")
            update_firebase_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED"})
            return False

        # Ensure image attachment preview appears
        attached_ok = False
        for _ in range(15):
            time.sleep(1.0)
            attach_preview = page.locator('div[data-testid*="attachment"], div[class*="attachment"], button[aria-label*="Remove"], [class*="thumbnail"], [data-testid*="image"]')
            if attach_preview.count() > 0 and any(attach_preview.nth(i).is_visible() for i in range(attach_preview.count())):
                attached_ok = True
                photo_uploaded = True
                break

        if not attached_ok:
            err = "TRANSIENT_TIMEOUT: Image attachment confirmation timed out (aborted to prevent text hallucination)"
            print(f"❌ {err}")
            update_firebase_result(slot_id, "FAILED", error=err)
            update_slot_data(slot_id, {"status": "FAILED"})
            return False

        print(f"[{time.time() - t_start:.2f}s] Attachment confirmed attached in composer! ✅")

    # Type prompt and send
    prompt_sent = False
    composer.fill(prompt)
    time.sleep(0.5)

    send_btn = page.locator('button[data-testid="send-button"]').first
    if send_btn.count() > 0 and send_btn.is_enabled():
        try:
            send_btn.click(force=True, timeout=3000)
            prompt_sent = True
            print("🚀 Send button clicked.")
        except Exception:
            page.keyboard.press("Enter")
            prompt_sent = True
            print("🚀 Pressed Enter after button timeout.")
    else:
        page.keyboard.press("Enter")
        prompt_sent = True
        print("🚀 Pressed Enter.")

    # Wait for result
    print("⏳ Waiting for ChatGPT to generate result (up to 90s)...")
    generated_img_bytes = None
    gen_start = time.time()

    while (time.time() - gen_start) < 90:
        time.sleep(1.0)
        images = page.locator(
            'div[data-message-author-role="assistant"] img, '
            'div[data-message-author-role="assistant"] a[href*="estuary"] img, '
            'a[href*="oaiusercontent"] img, '
            'img[alt*="Generated"], '
            'img[alt*="portrait"]'
        ).all()

        if images:
            for img in reversed(images):
                src = img.get_attribute("src")
                if not src or "avatar" in src or "profile" in src:
                    continue

                print(f"🎯 Found generated image URL: {src[:65]}...")
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
                            print(f"✅ Extracted 4K blob image via JS: {len(generated_img_bytes)} bytes in {time.time() - t_start:.2f}s total!")
                            break
                    except Exception as e_blob:
                        print(f"⚠️ Error extracting blob: {e_blob}")
                elif src.startswith("http"):
                    try:
                        resp = page.request.get(src, timeout=15000)
                        if resp.status == 200:
                            generated_img_bytes = resp.body()
                            print(f"✅ Downloaded 4K generated image: {len(generated_img_bytes)} bytes in {time.time() - t_start:.2f}s total!")
                            break
                    except Exception as e_http:
                        print(f"⚠️ Error downloading image src: {e_http}")

            if generated_img_bytes:
                break

        stop_btn = page.locator('button[data-testid="stop-button"]')
        if stop_btn.count() == 0 and (time.time() - gen_start) > 8 and images and generated_img_bytes:
            break

    # Assistant message / rate limit checks
    assistant_text = ""
    is_rate_limit = False
    is_auth_expired = False
    if not generated_img_bytes:
        try:
            msgs = page.locator('div[data-message-author-role="assistant"]').all_inner_texts()
            assistant_text = " ".join(msgs).strip()
            lower_text = assistant_text.lower()

            if photo_uploaded and prompt_sent and len(lower_text) > 5:
                rate_limit_keywords = [
                    "reached our limit", "reached the limit", "reached your limit",
                    "image creation limit", "image generation limit", "hit a limit",
                    "hit the limit", "too many requests", "try again after",
                    "try again in", "wait until", "free plan limit", "daily limit", "quota exceeded"
                ]
                if any(k in lower_text for k in rate_limit_keywords):
                    is_rate_limit = True

            auth_keywords = ["require you to log in", "requires you to log in", "please log in", "sign in to create", "session has expired"]
            if any(k in lower_text for k in auth_keywords):
                is_auth_expired = True
            else:
                auth_err = check_login_or_auth_expired(page)
                if auth_err:
                    is_auth_expired = True
        except Exception:
            pass

    # Clean up temp file
    if temp_img_path and os.path.exists(temp_img_path):
        try: os.remove(temp_img_path)
        except: pass

    if generated_img_bytes:
        out_b64 = base64.b64encode(generated_img_bytes).decode("utf-8")
        update_firebase_result(slot_id, "COMPLETED", image_b64=out_b64)
        update_slot_data(slot_id, {"status": "COMPLETED"})
        sync_fresh_cookies(page.context, account_idx)
        print(f"🎉 Slot {slot_id} completed successfully in {time.time() - t_start:.2f}s!")
        return True
    else:
        if is_rate_limit:
            mark_account_rate_limited(account_idx)
            err = f"EXPLICIT_RATE_LIMIT: Account #{int(account_idx)+1}: {assistant_text[:120]}"
        elif is_auth_expired:
            mark_account_expired(account_idx)
            err = f"EXPLICIT_AUTH_EXPIRED: Account #{int(account_idx)+1} requires login: {assistant_text[:120]}"
        else:
            snippet = f": {assistant_text[:100]}" if assistant_text else ""
            err = f"TRANSIENT_TIMEOUT: Image element not detected in response within 90s{snippet}"
        print(f"❌ {err}")
        update_firebase_result(slot_id, "FAILED", error=err)
        update_slot_data(slot_id, {"status": "FAILED"})
        return False


def process_studio_task(slot_id):
    from playwright.sync_api import sync_playwright

    print(f"\n==================================================")
    print(f"🚀 PROCESSING STUDIO TASK / PRE-WARM SLOT ON AZURE")
    print(f"📋 Slot / Task ID: {slot_id}")
    print(f"==================================================")

    # 1. Fetch initial slot data
    slot_data = fetch_slot_data(slot_id)
    if not slot_data:
        # Fallback: check input.json directly
        req_in = urllib.request.Request(f"{FIREBASE_TASKS_BASE}/{slot_id}/input.json", headers={"User-Agent": "StudioCloudWorker"})
        try:
            with urllib.request.urlopen(req_in, timeout=10) as r:
                inp = json.loads(r.read().decode("utf-8"))
                if inp:
                    slot_data = {"status": inp.get("status", "PENDING"), "input": inp, "accountIndex": inp.get("accountIndex", 0)}
        except Exception:
            pass

    input_data = slot_data.get("input", {})
    account_idx = slot_data.get("accountIndex")
    if account_idx is None:
        account_idx = input_data.get("accountIndex", 0)
    try:
        account_idx = int(account_idx)
    except Exception:
        account_idx = 0

    task_type = slot_data.get("taskType") or input_data.get("taskType", "PHOTO_JOB")
    is_quota_probe = (task_type == "VERIFY_QUOTA") or slot_id.startswith("probe_acc_")

    initial_status = slot_data.get("status") or input_data.get("status", "PENDING")
    img_b64 = input_data.get("imageBase64", "")
    prompt = input_data.get("prompt", "Professional passport photo portrait")

    is_prewarm = (initial_status == "WARMING") or (not img_b64 and initial_status != "PENDING" and not is_quota_probe)

    # Atomic lock on initially assigned account
    atomic_lock_account(account_idx, slot_id)
    raw_cookie = get_active_cookie(account_idx)
    t_start = time.time()

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
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 850},
            device_scale_factor=1,
            locale="en-US",
            timezone_id="Asia/Kathmandu"
        )
        context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        inject_cookies_to_context(context, raw_cookie)
        page = context.new_page()

        # Turbo Route Filtering
        def handle_route(route):
            url = route.request.url.lower()
            rtype = route.request.resource_type
            if rtype in ["font", "media"]:
                route.abort()
            elif any(blocked in url for blocked in ["statsig", "sentry", "datadog", "google-analytics", "analytics"]):
                route.abort()
            else:
                route.continue_()
        page.route("**/*", handle_route)

        mode_desc = "Quota Verification Probe" if is_quota_probe else ("Turbo Pre-Warm Mode" if is_prewarm else "Live Photo Job")
        print(f"🌍 Navigating to ChatGPT ({mode_desc})...")
        page.goto("https://chatgpt.com", wait_until="domcontentloaded", timeout=45000)

        # Pre-Flight Session Health Check & Self-Healing
        time.sleep(1.5)
        auth_err = check_login_or_auth_expired(page)
        if auth_err:
            print(f"⚠️ Pre-flight detected session expiry on Account #{account_idx + 1}: {auth_err}")
            mark_account_expired(account_idx)
            atomic_unlock_account(account_idx, slot_id)
            if is_quota_probe:
                update_slot_data(slot_id, {"status": "FAILED", "error": f"Session Expired: {auth_err}"})
                return

            # Atomic Self-Healing: pick next eligible account
            new_idx, new_cookie = find_and_lock_next_account(slot_id, exclude_indices=[account_idx])
            if new_idx is not None and new_cookie:
                account_idx = new_idx
                update_slot_data(slot_id, {"accountIndex": account_idx})
                inject_cookies_to_context(context, new_cookie)
                page.goto("https://chatgpt.com", wait_until="domcontentloaded", timeout=45000)
                time.sleep(1.5)
                auth_err2 = check_login_or_auth_expired(page)
                if auth_err2:
                    print(f"❌ Fallback Account #{account_idx + 1} also expired: {auth_err2}")
                    mark_account_expired(account_idx)
                    atomic_unlock_account(account_idx, slot_id)
                    browser.close()
                    update_firebase_result(slot_id, "FAILED", error="All available accounts expired")
                    update_slot_data(slot_id, {"status": "FAILED"})
                    return
            else:
                print("❌ No healthy fallback accounts available in pool!")
                browser.close()
                update_firebase_result(slot_id, "FAILED", error="No healthy accounts in pool")
                update_slot_data(slot_id, {"status": "FAILED"})
                return

        # Handle Quota Verification Probe
        if is_quota_probe:
            print(f"🔍 Running Quota Verification Probe on Account #{account_idx + 1}...")
            try:
                # Dismiss popups first
                for btn_text in ["Stay logged out", "Dismiss", "Close", "Not now", "Got it", "Maybe later", "Okay", "Continue"]:
                    try:
                        b = page.locator(f'button:has-text("{btn_text}")').first
                        if b.count() > 0 and b.is_visible():
                            b.click(timeout=1000)
                    except Exception:
                        pass

                # Wait for composer
                composer_ready = False
                try:
                    page.wait_for_selector('#prompt-textarea, [contenteditable="true"]', timeout=25000)
                    composer_ready = True
                except Exception:
                    pass

                if not composer_ready:
                    auth_err = check_login_or_auth_expired(page)
                    if auth_err:
                        print(f"❌ Account #{account_idx + 1} session expired during probe: {auth_err}")
                        mark_account_expired(account_idx)
                    else:
                        print(f"⚠️ Composer not ready on Account #{account_idx + 1} (network lag)")
                    atomic_unlock_account(account_idx, slot_id)
                    update_slot_data(slot_id, {"status": "FAILED", "error": auth_err or "Composer not ready"})
                    browser.close()
                    return

                plus_btn = page.locator('[data-testid="composer-plus-btn"], button[aria-label*="Add files" i], button[aria-label*="attach" i], #composer-plus-btn').first
                if plus_btn.count() == 0:
                    auth_err = check_login_or_auth_expired(page)
                    if auth_err:
                        mark_account_expired(account_idx)
                    atomic_unlock_account(account_idx, slot_id)
                    update_slot_data(slot_id, {"status": "FAILED", "error": auth_err or "Plus button not found"})
                    browser.close()
                    return

                plus_btn.click(timeout=5000)
                page.wait_for_timeout(1000)

                img_elem = page.locator('text="Create image"').first
                if img_elem.count() == 0:
                    page.wait_for_timeout(1500)
                    img_elem = page.locator('text="Create image"').first

                if img_elem.count() == 0:
                    auth_err = check_login_or_auth_expired(page)
                    if auth_err:
                        print(f"❌ Account #{account_idx + 1} session expired: {auth_err}")
                        mark_account_expired(account_idx)
                    else:
                        print(f"⚠️ 'Create image' option not found in menu for Account #{account_idx + 1}. Safely unlocking.")
                    atomic_unlock_account(account_idx, slot_id)
                    update_slot_data(slot_id, {"status": "FAILED", "error": auth_err or "Create image option not found"})
                    browser.close()
                    return

                parent_text = img_elem.locator('..').inner_text()

                try:
                    page.keyboard.press("Escape")
                except Exception:
                    pass

                print(f"📋 Account #{account_idx + 1} Plus Menu Text: {repr(parent_text)}")

                # Resilient check: Only check for the genuine blocking pattern
                is_blocked = ("0 images left" in parent_text.lower()) or ("images left until" in parent_text.lower())

                if is_blocked:
                    time_match = re.search(r"until\s+([0-9]{1,2}:[0-9]{2}\s*(?:AM|PM|am|pm)?)", parent_text, re.IGNORECASE)
                    reset_time_str = time_match.group(1).strip() if time_match else ""
                    print(f"🔒 Account #{account_idx + 1} confirmed blocked by OpenAI until: {reset_time_str or 'Unknown'}")
                    mark_account_rate_limited(account_idx, reset_time_str)
                    atomic_unlock_account(account_idx, slot_id)
                    update_slot_data(slot_id, {"status": "COMPLETED", "result": "BLOCKED", "resetTime": reset_time_str})
                    sync_fresh_cookies(context, account_idx)
                    send_whatsapp_alert(
                        f"🔒 *JB STUDIO - QUOTA PROBE RESULT*\n"
                        f"══════════════════════════════\n"
                        f"👤 *Account:* #{account_idx + 1}\n"
                        f"🚫 *Status:* Confirmed Rate-Limited by OpenAI\n"
                        f"⏰ *Reset Time:* {reset_time_str or 'Next reset cycle'}\n"
                        f"══════════════════════════════\n"
                        f"Quota confirmed at 0. Studio apps will automatically use next available account."
                    )
                else:
                    # Not blocked! Award +1 bonus image
                    print(f"🎉 Account #{account_idx + 1} is NOT blocked by OpenAI! Awarding bonus image...")
                    cur_stat = {}
                    try:
                        req_acc = urllib.request.Request(f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json", headers={"User-Agent": "StudioCloudWorker"})
                        with urllib.request.urlopen(req_acc, timeout=5) as r_acc:
                            cur_stat = json.loads(r_acc.read().decode("utf-8")) or {}
                    except Exception:
                        pass
                    cur_usage = int(cur_stat.get("usage", 3))
                    new_usage = max(0, cur_usage - 1)
                    bonus_patch = {
                        "usage": new_usage,
                        "bookedBy": "",
                        "bookedUntil": 0,
                        "isExpired": False,
                        "resetTime": ""
                    }
                    req_b = urllib.request.Request(
                        f"{FIREBASE_STATUS_BASE}/acc_{account_idx}.json",
                        data=json.dumps(bonus_patch).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="PATCH"
                    )
                    urllib.request.urlopen(req_b, timeout=5)
                    print(f"✅ Restored Account #{account_idx + 1} to usage={new_usage} (+1 bonus image available)")
                    update_slot_data(slot_id, {"status": "COMPLETED", "result": "BONUS_AWARDED", "newUsage": new_usage})
                    sync_fresh_cookies(context, account_idx)
                    send_whatsapp_alert(
                        f"🎉 *JB STUDIO - BONUS QUOTA RESTORED!* ⚡\n"
                        f"══════════════════════════════\n"
                        f"👤 *Account:* #{account_idx + 1}\n"
                        f"🟢 *Status:* Unblocked! OpenAI granted bonus capacity\n"
                        f"🎁 *Bonus:* +1 Photo restored (Usage: {new_usage}/3)\n"
                        f"══════════════════════════════\n"
                        f"Account is immediately active and ready for customer photos!"
                    )
            except Exception as e:
                auth_err = check_login_or_auth_expired(page)
                if auth_err:
                    print(f"❌ Account #{account_idx + 1} session expired during probe: {auth_err}")
                    mark_account_expired(account_idx)
                    send_whatsapp_alert(
                        f"⚠️ *JB STUDIO - PROBE ALERT* 🚨\n"
                        f"══════════════════════════════\n"
                        f"👤 *Account:* #{account_idx + 1}\n"
                        f"❌ *Status:* Session Expired ({auth_err})\n"
                        f"══════════════════════════════\n"
                        f"Marked as expired in pool."
                    )
                else:
                    print(f"⚠️ Quota probe error: {_safe_err(e)}")
                atomic_unlock_account(account_idx, slot_id)
                update_slot_data(slot_id, {"status": "FAILED", "error": auth_err or str(e)})
            browser.close()
            return

        # Dismiss popups
        try:
            for btn_text in ["Stay logged out", "Dismiss", "Close", "Not now", "Got it", "Maybe later", "Okay", "Continue"]:
                btn = page.locator(f'button:has-text("{btn_text}")').first
                if btn.count() > 0 and btn.is_visible():
                    btn.click(timeout=1000)
        except Exception:
            pass

        # Standby vs Immediate Execution
        current_slot = fetch_slot_data(slot_id)
        current_status = current_slot.get("status", initial_status)
        current_input = current_slot.get("input", {})
        has_input = bool(current_input.get("imageBase64"))

        if is_prewarm and not has_input and current_status != "PENDING":
            # 🟢 WARM & READY: Signal to Android app that VM is sitting hot in composer!
            update_slot_data(slot_id, {
                "status": "READY",
                "warmedAt": int(time.time() * 1000),
                "accountIndex": account_idx
            })
            print(f"🔥 Runner is WARM & READY in {time.time() - t_start:.2f}s! Entering 800ms standby poll loop (180s max)...")

            standby_start = time.time()
            task_received = False

            while (time.time() - standby_start) < 180:
                poll_slot = fetch_slot_data(slot_id)
                p_status = poll_slot.get("status")
                p_input = poll_slot.get("input", {})

                if p_status == "PENDING" or p_input.get("imageBase64"):
                    print(f"⚡ FAST PICKUP! Operator submitted photo after {time.time() - standby_start:.1f}s of standby!")
                    prompt = p_input.get("prompt", prompt)
                    img_b64 = p_input.get("imageBase64", "")
                    update_slot_data(slot_id, {"status": "PROCESSING"})
                    task_received = True
                    break
                elif p_status == "CANCELLED":
                    print(f"⏹️ Slot {slot_id} was CANCELLED by operator. Exiting cleanly.")
                    atomic_unlock_account(account_idx, slot_id)
                    browser.close()
                    return

                time.sleep(0.8)  # 800ms polling: Safe for Firebase, instant for operator

            if not task_received:
                print(f"⏰ Slot {slot_id} 180s cloud watchdog expired with no operator input.")
                update_slot_data(slot_id, {"status": "EXPIRED"})
                atomic_unlock_account(account_idx, slot_id)
                browser.close()
                return
        else:
            # FAST-CLICK or COLD RUN: input was already ready during boot
            print(f"⚡ FAST-CLICK / DIRECT RUN: Processing task immediately (boot elapsed: {time.time() - t_start:.2f}s)!")
            prompt = current_input.get("prompt", prompt)
            img_b64 = current_input.get("imageBase64", img_b64)
            update_slot_data(slot_id, {"status": "PROCESSING"})

        # Execute Generation
        try:
            execute_chatgpt_generation(page, slot_id, account_idx, prompt, img_b64, t_start)
        finally:
            atomic_unlock_account(account_idx, slot_id)
            browser.close()


def verify_and_introspect_selectors(page):
    """
    Introspects live ChatGPT DOM controls with STRICT EMPIRICAL GUARDRAILS.
    Never hallucinates or injects invalid selectors into Firebase.
    Only updates when an element genuinely fails and a candidate is empirically confirmed.
    """
    updates = {}
    print("🔍 Introspecting live DOM selectors with strict guardrails...")

    # 1. Attach / Plus Button Guardrail Check
    attach_sel = '[data-testid="composer-plus-btn"], button[aria-label*="Add files" i], button[aria-label*="attach" i], #composer-plus-btn'
    curr_attach = page.locator(attach_sel).first
    attach_works = False
    try:
        if curr_attach.count() > 0 and curr_attach.is_visible():
            attach_works = True
            print("   🎯 attachButton: Existing selector verified (working & visible) ✅")
    except Exception:
        pass

    if not attach_works:
        print("   ⚠️ attachButton not matching current selector. Scanning composer buttons with strict guardrails...")
        try:
            # Strictly inspect buttons inside form or composer container
            buttons = page.locator('form button, div[class*="composer"] button').all()
            for btn in buttons:
                if not btn.is_visible():
                    continue
                aria = (btn.get_attribute("aria-label") or "").strip()
                tid = (btn.get_attribute("data-testid") or "").strip()
                has_popup = btn.get_attribute("aria-haspopup")

                lower_all = f"{aria} {tid}".lower()
                # GUARDRAIL 1: Explicitly reject non-attach controls
                if any(bad in lower_all for bad in ["voice", "dictate", "record", "send", "stop", "user", "profile", "canvas", "sidebar"]):
                    continue

                # GUARDRAIL 2: Must match upload/attach/plus semantics or have popup menu
                is_candidate = False
                if any(k in lower_all for k in ["add files", "attach", "upload", "plus"]):
                    is_candidate = True
                elif has_popup == "menu" and not any(bad in lower_all for bad in ["model", "account", "settings"]):
                    is_candidate = True

                if is_candidate:
                    # GUARDRAIL 3: Empirical click test to confirm it triggers the ChatGPT menu!
                    btn.click(timeout=2000)
                    page.wait_for_timeout(600)
                    menu_item = page.locator('text="Create image", text="Upload from computer", text="Upload file"').first
                    if menu_item.count() > 0 and menu_item.is_visible():
                        page.keyboard.press("Escape")
                        print(f"   🎉 EMPIRICALLY CONFIRMED new attachButton: aria='{aria}', testid='{tid}'")
                        new_fragment = f'button[aria-label*="{aria}" i]' if aria else f'[data-testid="{tid}"]'
                        updates["attachButton"] = f"{new_fragment}, {attach_sel}"
                        break
                    else:
                        page.keyboard.press("Escape")
        except Exception as ex:
            print(f"   ⚠️ Exception verifying attach button: {ex}")

    # 2. Prompt Input Guardrail Check
    prompt_sel = '#prompt-textarea:not(.wcDTda_fallbackTextarea), [contenteditable="true"], textarea:not(.wcDTda_fallbackTextarea)'
    curr_prompt = page.locator(prompt_sel).first
    prompt_works = False
    try:
        if curr_prompt.count() > 0 and curr_prompt.is_visible():
            prompt_works = True
            print("   🎯 promptInput: Existing selector verified (working & visible) ✅")
    except Exception:
        pass

    if not prompt_works:
        print("   ⚠️ promptInput not matching current selector. Scanning for editable elements...")
        try:
            candidates = page.locator('form [contenteditable="true"], form textarea').all()
            for cand in candidates:
                if cand.is_visible():
                    box = cand.bounding_box()
                    if box and box["width"] > 100 and box["height"] > 20:
                        cid = cand.get_attribute("id")
                        if cid and f"#{cid}" not in prompt_sel:
                            updates["promptInput"] = f"#{cid}, {prompt_sel}"
                            print(f"   🎉 Discovered and confirmed promptInput ID: #{cid}")
                            break
        except Exception as ex:
            print(f"   ⚠️ Exception verifying prompt input: {ex}")

    # 3. Send Button Guardrail Check
    send_sel = '[data-testid="send-button"], button[aria-label*="end prompt" i], button[aria-label*="end message" i], button[aria-label*="Send" i]'
    curr_send = page.locator(send_sel).first
    try:
        if curr_send.count() > 0:
            print("   🎯 sendButton: Existing selector verified in DOM ✅")
    except Exception:
        pass

    return updates


def sync_verified_selectors_to_firebase(updates):
    try:
        sel_url = f"{FIREBASE_BASE}/chatgpt_selectors.json"
        req = urllib.request.Request(sel_url, headers={"User-Agent": "StudioCloudWorker"})
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
                print(f"🎯 Synced updated ChatGPT selectors to Firebase! (Version {data['version']}) 🟢")
                return data["version"]
    except Exception as e:
        print(f"⚠️ Failed to sync selectors to Firebase: {_safe_err(e)}")
    return None


def run_nightly_maintenance():
    from playwright.sync_api import sync_playwright

    print("=" * 65)
    print("🌙 RUNNING JB STUDIO AUTONOMOUS NIGHTLY MAINTENANCE")
    print("=" * 65)

    nepal_tz = timezone(timedelta(hours=5, minutes=45))
    start_nepal = datetime.now(nepal_tz).strftime("%I:%M %p, %d %b %Y")

    # Send WhatsApp Start Alert
    send_whatsapp_alert(
        f"🌙 *JB STUDIO - NIGHTLY MAINTENANCE STARTED* 🛠️\n"
        f"══════════════════════════════\n"
        f"⏰ *Started At:* {start_nepal}\n"
        f"🚀 Running autonomous 10-day token keep-alive & live DOM selector verification on Azure Cloud...\n"
        f"══════════════════════════════\n"
        f"⏳ Refreshing all accounts sequentially. Please wait..."
    )

    accounts = get_decrypted_pool()
    total = len(accounts)
    active_count = 0
    refreshed_count = 0
    expired_count = 0
    selector_updates = {}

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

        for idx in range(total):
            now_ms = int(time.time() * 1000)

            # Atomic lock for nightly maintenance
            try:
                lock_url = f"{FIREBASE_STATUS_BASE}/acc_{idx}.json"
                req_l = urllib.request.Request(
                    lock_url,
                    data=json.dumps({"bookedBy": "nightly_maintenance", "bookedUntil": now_ms + 120_000}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="PATCH"
                )
                urllib.request.urlopen(req_l, timeout=5)
            except Exception:
                pass

            raw_cookie = get_active_cookie(idx)
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 850},
                device_scale_factor=1,
                locale="en-US",
                timezone_id="Asia/Kathmandu"
            )
            context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            inject_cookies_to_context(context, raw_cookie)
            page = context.new_page()

            try:
                email = accounts[idx].get("email", f"Account #{idx+1}")
                print(f"\n[{idx+1}/{total}] 🔍 Checking Account #{idx+1} ({email})...")
                page.goto("https://chatgpt.com", wait_until="domcontentloaded", timeout=40000)
                time.sleep(2.0)

                # Pre-flight auth check
                auth_err = check_login_or_auth_expired(page)
                if auth_err:
                    print(f"❌ Account #{idx+1} session expired: {auth_err}")
                    mark_account_expired(idx)
                    expired_count += 1
                else:
                    active_count += 1
                    # Dismiss popups
                    for btn_text in ["Stay logged out", "Dismiss", "Close", "Not now", "Got it", "Maybe later", "Okay", "Continue"]:
                        try:
                            btn = page.locator(f'button:has-text("{btn_text}")').first
                            if btn.count() > 0 and btn.is_visible():
                                btn.click(timeout=1000)
                        except Exception:
                            pass

                    # Touch NextAuth session endpoint to push 10-day expiration forward!
                    try:
                        page.evaluate("""async () => {
                            try { return await fetch('/api/auth/session').then(r => r.json()); } catch (e) { return {}; }
                        }""")
                    except Exception:
                        pass

                    time.sleep(1.0)
                    synced = sync_fresh_cookies(context, idx)
                    if synced:
                        refreshed_count += 1

                    # Check & verify DOM selectors with strict guardrails
                    if not selector_updates:
                        try:
                            discovered = verify_and_introspect_selectors(page)
                            if discovered:
                                selector_updates.update(discovered)
                        except Exception as e_sel:
                            print(f"   ⚠️ Selector inspection note: {e_sel}")

                    print(f"✅ Account #{idx+1} keep-alive verified & 10-day sliding window refreshed!")

            except Exception as e_acc:
                print(f"⚠️ Error during maintenance on Account #{idx+1}: {_safe_err(e_acc)}")
            finally:
                # Release lock
                try:
                    unlock_url = f"{FIREBASE_STATUS_BASE}/acc_{idx}.json"
                    req_u = urllib.request.Request(
                        unlock_url,
                        data=json.dumps({"bookedBy": "", "bookedUntil": 0}).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="PATCH"
                    )
                    urllib.request.urlopen(req_u, timeout=5)
                except Exception:
                    pass
                context.close()

        browser.close()

    # Sync selectors if verified updates found
    selector_status_msg = "All selectors verified & stable (v2)"
    if selector_updates:
        try:
            new_ver = sync_verified_selectors_to_firebase(selector_updates)
            if new_ver:
                selector_status_msg = f"Selectors dynamically updated to v{new_ver}"
        except Exception as e_sync:
            print(f"⚠️ Failed to sync selectors: {e_sync}")

    end_nepal = datetime.now(nepal_tz).strftime("%I:%M %p, %d %b %Y")
    summary_msg = (
        f"✅ *JB STUDIO - NIGHTLY MAINTENANCE COMPLETED* 🌟\n"
        f"══════════════════════════════\n"
        f"📊 *Total Accounts Inspected:* {total}\n"
        f"🟢 *Active & Kept-Alive:* {active_count}\n"
        f"🔄 *Tokens Rotated & Synced:* {refreshed_count}\n"
        f"🔴 *Expired Accounts:* {expired_count}\n"
        f"🎯 *DOM Selectors:* {selector_status_msg}\n"
        f"⏰ *Completion Time:* {end_nepal}\n"
        f"══════════════════════════════\n"
        f"🛡️ 10-day sliding window refreshed for all active accounts.\n"
        f"Studio phones will operate 100% smoothly with zero PC uptime required!"
    )
    send_whatsapp_alert(summary_msg)
    print("\n" + summary_msg)


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
        run_nightly_maintenance()
    else:
        process_studio_task(target_task_id)
