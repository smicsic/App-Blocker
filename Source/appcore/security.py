"""Защита от завершения (AppBlockerGuard), автозапуск, диагностика."""
import os
import subprocess
import threading
import time

import psutil

from appcore import state
from appcore.admin import is_admin
from appcore.i18n import t
from appcore.logging_util import log
from appcore.paths import (
    APP_DIR,
    AUTOSTART_DIR,
    GUARD_EXE_NAME,
    GUARD_STARTUP_NAME,
    APP_STARTUP_NAME,
    app_command,
    guard_command,
    guard_target_exists,
)


def is_guard_process_name(name, exe_path=""):
    name = (name or "").lower()
    exe_path = (exe_path or "").lower()
    return (
        name == GUARD_EXE_NAME.lower()
        or exe_path.endswith(GUARD_EXE_NAME.lower())
        or "appblockerguard" in name
    )


def _desktop_file_path(app_name):
    return os.path.join(AUTOSTART_DIR, f"{app_name.lower()}.desktop")


def install_autostart_entry(app_name, command):
    """Пишет .desktop-файл автозапуска в ~/.config/autostart (XDG).

    ``command`` — список argv (см. appcore.paths.app_command/guard_command):
    собранный бинарник запускается одним элементом, а из исходников это
    ``[python3, /путь/AppBlocker.py]`` — сам .py не исполняемый файл, поэтому
    интерпретатор нужно указывать явно.
    """
    if not command or not command[-1] or not os.path.exists(command[-1]):
        return False
    try:
        os.makedirs(AUTOSTART_DIR, exist_ok=True)
        exec_line = " ".join(f'"{part}"' for part in command)
        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={app_name}\n"
            f"Exec={exec_line}\n"
            "Terminal=false\n"
            "Hidden=false\n"
            "X-GNOME-Autostart-enabled=true\n"
        )
        with open(_desktop_file_path(app_name), "w", encoding="utf-8") as f:
            f.write(content)
        return True
    except Exception:
        return False


def remove_autostart_entry(app_name):
    path = _desktop_file_path(app_name)
    try:
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
    except Exception:
        return False


def is_autostart_registered(app_name):
    return os.path.exists(_desktop_file_path(app_name))


def remove_from_startup_everywhere(app_name, process_name):
    """Удаляет .desktop-автозапуск и завершает все процессы с этим именем."""
    removed_any = False
    current_pid = os.getpid()
    process_name = (process_name or "").lower()

    for attempt in range(5):
        killed = False
        try:
            for p in psutil.process_iter(['name', 'pid']):
                try:
                    if p.info.get('pid') == current_pid:
                        continue
                    n = (p.info.get('name') or '').lower()
                    if n == process_name:
                        try:
                            p.kill()
                            killed = True
                        except psutil.AccessDenied:
                            try:
                                p.terminate()
                            except Exception:
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            log(t("log_process_cleanup_error", error=e))

        if killed:
            time.sleep(0.5)
        else:
            break

    if remove_autostart_entry(app_name):
        removed_any = True

    return removed_any


def ensure_startup_entry(app_name, command):
    return install_autostart_entry(app_name, command)


def ensure_app_startup_entries(on_status_update=None):
    app_ok = ensure_startup_entry(APP_STARTUP_NAME, app_command())
    secure_ok = True
    if state.SECURE_ENABLED:
        secure_ok = ensure_startup_entry(GUARD_STARTUP_NAME, guard_command())
    if app_ok and secure_ok:
        log(t("log_startup_configured_both"))
    elif app_ok:
        log(t("log_startup_app_only"))
    else:
        log(t("log_startup_failed"))
    if on_status_update is not None:
        on_status_update()
    return app_ok and secure_ok


def is_process_running_by_name(exe_name):
    exe_name = exe_name.lower()
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info.get("name") or "").lower() == exe_name:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def build_diagnostics():
    import sys
    from appcore.paths import CONFIG_PATH, HOSTS_PATH

    app_exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
    checks = [
        (t("diag_admin_rights"), is_admin()),
        (t("diag_app_exe_found"), os.path.exists(app_exe)),
        (t("diag_guard_exe_found"), guard_target_exists()),
        (t("diag_config_accessible"), os.path.exists(CONFIG_PATH)),
        (t("diag_password_hashed"), bool(state.ADMIN_PASSWORD_HASH and state.ADMIN_PASSWORD_SALT)),
        (t("diag_autostart_app"), is_autostart_registered(APP_STARTUP_NAME)),
        (t("diag_autostart_guard"), is_autostart_registered(GUARD_STARTUP_NAME)),
        (t("diag_guard_running"), is_process_running_by_name(GUARD_EXE_NAME)),
        (t("diag_hosts_access"), os.path.exists(HOSTS_PATH) and os.access(HOSTS_PATH, os.W_OK)),
    ]
    return checks


def run_diagnostics(on_status_update=None):
    checks = build_diagnostics()
    ok_count = sum(1 for _, ok in checks if ok)
    log(t("log_diagnostics_summary", ok=ok_count, total=len(checks)))
    for name, ok in checks:
        log(f"{'✅' if ok else '⚠️'} {name}")
    if on_status_update is not None:
        on_status_update()


def ensure_appblocker_guard():
    """Запускает AppBlockerGuard из той же папки, если его нет."""
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = (proc.info.get('name') or '').lower()
            exe = (proc.info.get('exe') or '').lower()
            if is_guard_process_name(name, exe):
                return False  # уже запущен
        except Exception:
            pass

    if guard_target_exists():
        subprocess.Popen(guard_command(), cwd=APP_DIR)
        return True
    log(t("log_guard_exe_not_found", path=guard_command()[-1]))
    return False


def watch_appblocker_guard():
    """Следит за AppBlockerGuard и перезапускает его при необходимости"""
    print("[Watch] Мониторинг AppBlockerGuard запущен")

    while state.watch_active and not state.shutdown_event.is_set():
        try:
            found = False
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    name = (proc.info.get('name') or '').lower()
                    exe = (proc.info.get('exe') or '').lower()
                    if is_guard_process_name(name, exe):
                        found = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if not found and guard_target_exists() and state.watch_active:
                try:
                    subprocess.Popen(guard_command(), cwd=APP_DIR)
                    print("[Watch] AppBlockerGuard перезапущен")
                except Exception as e:
                    print(f"[Watch] ❌ Ошибка запуска: {e}")
        except Exception as e:
            print(f"[Watch] ⚠️ Ошибка в цикле: {e}")

        state.shutdown_event.wait(1)  # Проверяем каждую секунду, но можем прерваться

    print("[Watch] Мониторинг AppBlockerGuard остановлен")


def start_guard_watch_thread(message_key="log_guard_watch_started"):
    """Единая точка запуска потока наблюдения за AppBlockerGuard (идемпотентно)."""
    if not state.watch_active:
        state.watch_active = True
        threading.Thread(target=watch_appblocker_guard, daemon=True).start()
        log(t(message_key))


def get_app_folder_path():
    from appcore.paths import base_dir
    return os.path.abspath(base_dir())


def copy_app_folder_path(ctx, on_done=None):
    """Копирует путь к папке программы в буфер обмена.

    Буфер обмена во Flet — сервис страницы с асинхронным методом, поэтому запись
    уходит в цикл событий, а результат сообщается колбэком ``on_done(успех)``.
    """
    path = get_app_folder_path()

    async def copy():
        try:
            await ctx.page.clipboard.set(path)
            log(t("log_path_copied", path=path))
            copied = True
        except Exception as e:
            log(t("log_path_copy_failed", error=e))
            copied = False
        if on_done is not None:
            on_done(copied)

    ctx.run_async(copy)


def enable_security_after_consent(on_status_update=None):
    state.SECURE_ENABLED = True
    state.SECURITY_WARNING_SEEN = True
    from appcore.config_store import save_security_state, save_config
    save_security_state()
    save_config()

    if ensure_appblocker_guard():
        log(t("log_guard_activated_generic"))

    ensure_app_startup_entries(on_status_update=on_status_update)

    start_guard_watch_thread()

    if on_status_update is not None:
        on_status_update()
    log(t("log_protection_enabled_by_user"))
