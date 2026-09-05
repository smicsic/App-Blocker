"""Пароль выхода из AppBlocker_Client и хранилище доверенных Admin-токенов.

Хеширование зеркалит appcore/config_store.py и appcore/network/auth_store.py
основной программы (PBKDF2-HMAC-SHA256, 200 000 итераций) — тот же проверенный
паттерн, скопированный сюда, чтобы Client оставался самостоятельной программой
без зависимости на Source/.
"""
import hashlib
import hmac
import json
import os
import secrets

from paths import PASS_PATH, TRUSTED_ADMINS_PATH


def _hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def has_password():
    return os.path.exists(PASS_PATH)


def set_password(password):
    salt_hex, hash_hex = _hash_password(password)
    with open(PASS_PATH, "w", encoding="utf-8") as f:
        json.dump({"salt": salt_hex, "hash": hash_hex}, f)


def verify_password(password):
    if not password or not has_password():
        return False
    try:
        with open(PASS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        _, candidate_hash = _hash_password(password, data.get("salt"))
        return hmac.compare_digest(candidate_hash, data.get("hash", ""))
    except Exception:
        return False


# ---------- Доверенные администраторы (token -> {"name": ..., "paired_at": ...}) ----------

def load_trusted_admins():
    if not os.path.exists(TRUSTED_ADMINS_PATH):
        return {}
    try:
        with open(TRUSTED_ADMINS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_trusted_admins(admins):
    try:
        with open(TRUSTED_ADMINS_PATH, "w", encoding="utf-8") as f:
            json.dump(admins, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def is_trusted_token(token):
    if not token:
        return False
    return token in load_trusted_admins()


def issue_token(admin_sender, admin_ip=None):
    """Генерирует новый токен доверия для админа, который только что подтверждён пользователем."""
    token = secrets.token_hex(32)
    admins = load_trusted_admins()
    admins[token] = {"sender": admin_sender, "ip": admin_ip}
    save_trusted_admins(admins)
    return token
