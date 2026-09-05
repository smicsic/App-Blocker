"""Пароль вкладки Remote Admin и хранилище доверенных клиентов (Admin-сторона).

Хеширование — тот же алгоритм, что уже используется в
``appcore.config_store.hash_admin_password`` (PBKDF2-HMAC-SHA256, 200 000
итераций): переиспользуем проверенный паттерн вместо нового. Хранится он,
однако, не в ``state``/``config.json``, а в отдельном файле ``Pass`` — так и
задумано: пароль вкладки Remote Admin не связан с паролем выхода из самого
AppBlocker.
"""
import hashlib
import hmac
import json
import os
import secrets

from appcore.paths import ADMIN_PASS_PATH, TRUSTED_CLIENTS_PATH


def _hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def has_password():
    return os.path.exists(ADMIN_PASS_PATH)


def set_password(password):
    salt_hex, hash_hex = _hash_password(password)
    with open(ADMIN_PASS_PATH, "w", encoding="utf-8") as f:
        json.dump({"salt": salt_hex, "hash": hash_hex}, f)


def verify_password(password):
    if not password or not has_password():
        return False
    try:
        with open(ADMIN_PASS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        _, candidate_hash = _hash_password(password, data.get("salt"))
        return hmac.compare_digest(candidate_hash, data.get("hash", ""))
    except Exception:
        return False


def reset_password():
    """Удаляет файл Pass — используется кнопкой «Забыли пароль?» после подтверждения."""
    try:
        if os.path.exists(ADMIN_PASS_PATH):
            os.remove(ADMIN_PASS_PATH)
        return True
    except Exception:
        return False


# ---------- Доверенные клиенты (client_id -> {ip, port, token, name}) ----------

def load_trusted_clients():
    if not os.path.exists(TRUSTED_CLIENTS_PATH):
        return {}
    try:
        with open(TRUSTED_CLIENTS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_trusted_clients(clients):
    try:
        with open(TRUSTED_CLIENTS_PATH, "w", encoding="utf-8") as f:
            json.dump(clients, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def remember_client(client_id, ip, port, token, name=None):
    clients = load_trusted_clients()
    clients[client_id] = {
        "ip": ip,
        "port": port,
        "token": token,
        "name": name or client_id,
    }
    save_trusted_clients(clients)


def get_client_token(client_id):
    return load_trusted_clients().get(client_id, {}).get("token")
