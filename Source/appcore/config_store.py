"""Чтение/запись config.json, состояние защиты и пароль администратора."""
import hashlib
import hmac
import json
import os
import secrets
import shutil
import datetime

from appcore import state
from appcore.i18n import t
from appcore.logging_util import log
from appcore.paths import CONFIG_PATH, CONFIG_BACKUP_PATH, SECURITY_STATE_PATH, STATE_DIR
from appcore.processes import normalize_process_name, sync_primary_process_name


def hash_admin_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )
    return salt.hex(), digest.hex()


def has_admin_password():
    return bool(state.ADMIN_PASSWORD_HASH or state.ADMIN_PASSWORD)


def verify_admin_password(password):
    if not password:
        return False
    if state.ADMIN_PASSWORD_HASH and state.ADMIN_PASSWORD_SALT:
        _, candidate_hash = hash_admin_password(password, state.ADMIN_PASSWORD_SALT)
        return hmac.compare_digest(candidate_hash, state.ADMIN_PASSWORD_HASH)
    return hmac.compare_digest(password, state.ADMIN_PASSWORD)


def set_admin_password(password):
    state.ADMIN_PASSWORD = ""
    state.ADMIN_PASSWORD_SALT, state.ADMIN_PASSWORD_HASH = hash_admin_password(password)


def clear_admin_password():
    state.ADMIN_PASSWORD = ""
    state.ADMIN_PASSWORD_HASH = ""
    state.ADMIN_PASSWORD_SALT = ""


def save_security_state():
    data = {
        "secure_enabled": state.SECURE_ENABLED,
        "security_warning_seen": state.SECURITY_WARNING_SEEN,
    }
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(SECURITY_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"⚠️ Не удалось сохранить состояние защиты: {e}")


def load_security_state():
    if not os.path.exists(SECURITY_STATE_PATH):
        return {}
    try:
        with open(SECURITY_STATE_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        print(f"⚠️ Не удалось прочитать состояние защиты: {e}")
    return {}


def apply_security_state(config=None):
    state_data = load_security_state()
    source = state_data if state_data else (config or {})
    state.SECURE_ENABLED = bool(source.get("secure_enabled", False))
    state.SECURITY_WARNING_SEEN = bool(source.get("security_warning_seen", False))


def save_config(status=None):
    """Сохраняет конфиг, не удаляя список сайтов"""
    data = {}

    # ✅ Если файл уже существует — читаем его, чтобы не потерять blocked_sites
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ Ошибка чтения config.json: {e}")
            data = {}

    if state.ADMIN_PASSWORD and not state.ADMIN_PASSWORD_HASH:
        state.ADMIN_PASSWORD_SALT, state.ADMIN_PASSWORD_HASH = hash_admin_password(state.ADMIN_PASSWORD)
        state.ADMIN_PASSWORD = ""
    data.pop("admin_password", None)

    # ✅ Обновляем только нужные ключи
    if status is None:
        status = "RUNNING" if state.monitoring_active else data.get("status", "EXIT")

    data.update({
        "process_name": state.PROCESS_NAME,
        "blocked_programs": state.BLOCKED_PROGRAMS,
        "admin_password_hash": state.ADMIN_PASSWORD_HASH,
        "admin_password_salt": state.ADMIN_PASSWORD_SALT,
        "status": status,
        "timer_enabled": state.TIMER_ENABLED,
        "timer_end": state.TIMER_END.timestamp() if state.TIMER_END else None,
        "secure_enabled": state.SECURE_ENABLED,
        "security_warning_seen": state.SECURITY_WARNING_SEEN,
        "permanent_lock": state.PERMANENT_LOCK,
        "match_mode": state.MATCH_MODE,
        "block_mode": state.BLOCK_MODE,
        "schedule_enabled": state.SCHEDULE_ENABLED,
        "schedule": state.SCHEDULE,
        "postpone_enabled": state.POSTPONE_ENABLED,
        "postpone_seconds": state.POSTPONE_SECONDS,
        "authenticated": False
    })

    # ✅ Сохраняем обратно
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    try:
        shutil.copy2(CONFIG_PATH, CONFIG_BACKUP_PATH)
    except Exception:
        pass
    save_security_state()


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            config = json.load(f)
        migrated_password = False
        saved_programs = config.get("blocked_programs", [])
        if not saved_programs and config.get("process_name", ""):
            saved_programs = [config.get("process_name", "")]
        state.BLOCKED_PROGRAMS = []
        for program in saved_programs:
            program = normalize_process_name(program)
            if program and program not in state.BLOCKED_PROGRAMS:
                state.BLOCKED_PROGRAMS.append(program)
        sync_primary_process_name()
        state.ADMIN_PASSWORD = config.get("admin_password", "")
        state.ADMIN_PASSWORD_HASH = config.get("admin_password_hash", "")
        state.ADMIN_PASSWORD_SALT = config.get("admin_password_salt", "")
        if state.ADMIN_PASSWORD and not state.ADMIN_PASSWORD_HASH:
            state.ADMIN_PASSWORD_SALT, state.ADMIN_PASSWORD_HASH = hash_admin_password(state.ADMIN_PASSWORD)
            state.ADMIN_PASSWORD = ""
            migrated_password = True
        state.PERMANENT_LOCK = config.get("permanent_lock", False)
        state.MATCH_MODE = config.get("match_mode", "contains")
        if state.MATCH_MODE not in ("contains", "exact"):
            state.MATCH_MODE = "contains"
        # Отсутствующий block_mode означает конфиг прошлой версии — остаёмся в
        # blacklist, чтобы обновление не поменяло поведение молча.
        state.BLOCK_MODE = config.get("block_mode", "blacklist")
        if state.BLOCK_MODE not in ("blacklist", "whitelist"):
            state.BLOCK_MODE = "blacklist"
        from appcore.schedule import normalize_schedule
        state.SCHEDULE = normalize_schedule(config.get("schedule"))
        state.SCHEDULE_ENABLED = bool(config.get("schedule_enabled", False))
        # Отсутствие ключа = конфиг прошлой версии: мягкая блокировка выключена,
        # завершение мгновенное. Это поведение по умолчанию.
        from appcore.postpone import DEFAULT_SECONDS, normalize_seconds
        state.POSTPONE_ENABLED = bool(config.get("postpone_enabled", False))
        state.POSTPONE_SECONDS = normalize_seconds(
            config.get("postpone_seconds", DEFAULT_SECONDS)
        ) or DEFAULT_SECONDS
        state.TIMER_ENABLED = config.get("timer_enabled", False)
        apply_security_state(config)
        end_timestamp = config.get("timer_end")
        if end_timestamp:
            state.TIMER_END = datetime.datetime.fromtimestamp(end_timestamp)
        status = config.get("status", "RUNNING")

        if migrated_password:
            save_config(status=status)
        return status

    if not os.path.exists(CONFIG_PATH):
        try:
            save_config()
            print("🆕 Файл config.json был создан автоматически.")
        except Exception as e:
            print(f"⚠️ Не удалось создать config.json: {e}")
    apply_security_state()
    return "RUNNING"


def export_config(target):
    """Копирует текущий config.json в ``target``.

    Выбор файла остаётся за интерфейсом: во Flet диалог файлов — это сервис
    страницы, а не вызов библиотеки, поэтому модуль принимает готовый путь и не
    тянет за собой слой интерфейса.
    """
    if not target:
        return False
    try:
        save_config(status="RUNNING" if state.monitoring_active else "EXIT")
        shutil.copy2(CONFIG_PATH, target)
        log(t("log_config_exported", path=target))
        return True
    except Exception as e:
        log(t("log_config_export_failed", error=e))
        return False


def import_config(source):
    """Импортирует config.json из файла ``source`` и перезагружает состояние.

    Возвращает True, если импорт и load_config() прошли успешно — в этом случае
    вызывающий (GUI) должен обновить связанные списки/лейблы.
    """
    if not source:
        return False
    try:
        with open(source, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Некорректный формат config")
        shutil.copy2(source, CONFIG_PATH)
        load_config()
        log(t("log_config_imported", path=source))
        return True
    except Exception as e:
        log(t("log_config_import_failed", error=e))
        return False
