"""Защита от завершения (AppBlockerGuard), автозапуск, диагностика, Defender."""
import json
import os
import subprocess
import threading
import time
import winreg

import psutil

from appcore import state
from appcore.admin import is_admin
from appcore.i18n import t
from appcore.logging_util import log
from appcore.paths import (
    APP_DIR,
    CREATE_NO_WINDOW,
    GUARD_EXE,
    GUARD_EXE_NAME,
    GUARD_STARTUP_NAME,
    LEGACY_GUARD_EXE_NAME,
    LEGACY_GUARD_STARTUP_NAME,
    APP_STARTUP_NAME,
    RUN_SUBKEY,
)


# schtasks и PowerShell пишут в кодировке консоли, а text=True декодирует их
# вывод ANSI-кодировкой системы. Когда они не совпадают, поток-читатель
# subprocess падает с UnicodeDecodeError и печатает трейсбек — хотя returncode,
# который здесь и нужен, читается нормально. Поэтому декодируем «как получится».
CONSOLE_DECODE_ERRORS = "replace"


def is_guard_process_name(name, exe_path=""):
    name = (name or "").lower()
    exe_path = (exe_path or "").lower()
    guard_names = (GUARD_EXE_NAME.lower(), LEGACY_GUARD_EXE_NAME.lower())
    return (
        name in guard_names
        or any(exe_path.endswith(guard_name) for guard_name in guard_names)
        or "appblockerguard" in name
        or "securesystem" in name
    )


def remove_from_startup_everywhere(app_name="AppBlockerGuard", exe_name=GUARD_EXE_NAME):
    """Полностью удаляет приложение из автозагрузки Windows"""
    deleted_any = False
    current_pid = os.getpid()

    print(f"[Cleanup] 🧹 Начинаем очистку {app_name}...")

    # 1) ⚡ ПРИНУДИТЕЛЬНО убить AppBlockerGuard несколько раз
    print(f"[Cleanup] Завершаем все процессы {exe_name}...")
    for attempt in range(5):  # Увеличено до 5 попыток
        killed = False
        try:
            for p in psutil.process_iter(['name', 'pid']):
                try:
                    n = (p.info.get('name') or '').lower()
                    if p.info.get('pid') == current_pid:
                        continue
                    if n == exe_name.lower():
                        print(f"[Cleanup] Завершаю PID {p.info['pid']} (попытка {attempt + 1})")
                        try:
                            p.kill()  # Жёсткое завершение
                            killed = True
                        except psutil.AccessDenied:
                            try:
                                p.terminate()
                            except Exception:
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"[Cleanup] Ошибка при завершении процесса: {e}")

        if killed:
            time.sleep(0.5)  # Уменьшено время ожидания
        else:
            break

    # 2) 🧹 Удаляем из реестра
    print("[Cleanup] Удаляем из реестра...")

    hives = [
        (winreg.HKEY_CURRENT_USER, "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM")
    ]

    run_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
    ]

    for hive, hive_name in hives:
        for run_path in run_paths:
            try:
                # Пробуем без флагов разрядности
                try:
                    with winreg.OpenKey(hive, run_path, 0, winreg.KEY_SET_VALUE) as k:
                        try:
                            winreg.DeleteValue(k, app_name)
                            print(f"[Cleanup] ✅ Удалён из {hive_name}\\{run_path}")
                            deleted_any = True
                        except FileNotFoundError:
                            pass
                except PermissionError:
                    print(f"[Cleanup] ⚠️ Нет прав для {hive_name}\\{run_path}")

                # Пробуем с флагами разрядности
                for view in [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]:
                    try:
                        access = winreg.KEY_SET_VALUE | view
                        with winreg.OpenKey(hive, run_path, 0, access) as k:
                            try:
                                winreg.DeleteValue(k, app_name)
                                print(f"[Cleanup] ✅ Удалён из {hive_name}\\{run_path} (view={view})")
                                deleted_any = True
                            except FileNotFoundError:
                                pass
                    except (PermissionError, OSError):
                        pass
            except Exception as e:
                print(f"[Cleanup] ⚠️ Ошибка при работе с реестром: {e}")

    # 3) 🗑️ Удаляем ярлыки
    print("[Cleanup] Удаляем ярлыки...")

    startup_folders = [
        os.path.join(os.getenv("APPDATA") or "", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.getenv("PROGRAMDATA") or "", r"Microsoft\Windows\Start Menu\Programs\Startup")
    ]

    for folder in startup_folders:
        if folder and os.path.isdir(folder):
            try:
                for filename in os.listdir(folder):
                    if filename.lower().startswith(app_name.lower()) and filename.lower().endswith(".lnk"):
                        shortcut_path = os.path.join(folder, filename)
                        try:
                            os.chmod(shortcut_path, 0o666)
                        except Exception:
                            pass
                        try:
                            os.remove(shortcut_path)
                            print(f"[Cleanup] ✅ Удалён ярлык: {shortcut_path}")
                            deleted_any = True
                        except Exception as e:
                            print(f"[Cleanup] ⚠️ Не удалось удалить {shortcut_path}: {e}")
            except Exception as e:
                print(f"[Cleanup] ⚠️ Ошибка при обходе {folder}: {e}")

    # 4) 🗓️ Удаляем задачу планировщика
    print("[Cleanup] Удаляем задачу планировщика...")
    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", app_name, "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
            text=True,
            errors=CONSOLE_DECODE_ERRORS,
            timeout=5
        )
        if result.returncode == 0:
            print(f"[Cleanup] ✅ Задача '{app_name}' удалена")
            deleted_any = True
    except Exception as e:
        print(f"[Cleanup] ⚠️ Ошибка удаления задачи: {e}")

    print(f"[Cleanup] {'✅ Очистка завершена' if deleted_any else 'ℹ️ Записи не найдены'}")
    return deleted_any


def quote_task_path(path):
    return f'"{path}"'


def install_startup_task(task_name, exe_path):
    if not exe_path or not os.path.exists(exe_path):
        return False
    try:
        result = subprocess.run(
            [
                "schtasks", "/Create",
                "/TN", task_name,
                "/TR", quote_task_path(exe_path),
                "/SC", "ONLOGON",
                "/RL", "HIGHEST",
                "/F",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
            text=True,
            errors=CONSOLE_DECODE_ERRORS,
            timeout=8
        )
        return result.returncode == 0
    except Exception:
        return False


def install_startup_registry(app_name, exe_path):
    if not exe_path or not os.path.exists(exe_path):
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_SUBKEY, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, quote_task_path(exe_path))
        return True
    except Exception:
        return False


def ensure_startup_entry(app_name, exe_path):
    task_ok = install_startup_task(app_name, exe_path)
    reg_ok = install_startup_registry(app_name, exe_path)
    return task_ok or reg_ok


def ensure_app_startup_entries(on_status_update=None):
    import sys
    app_exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
    remove_from_startup_everywhere(LEGACY_GUARD_STARTUP_NAME, LEGACY_GUARD_EXE_NAME)
    app_ok = ensure_startup_entry(APP_STARTUP_NAME, app_exe)
    secure_ok = True
    if state.SECURE_ENABLED:
        secure_ok = ensure_startup_entry(GUARD_STARTUP_NAME, GUARD_EXE)
    if app_ok and secure_ok:
        log(t("log_startup_configured_both"))
    elif app_ok:
        log(t("log_startup_app_only"))
    else:
        log(t("log_startup_failed"))
    if on_status_update is not None:
        on_status_update()
    return app_ok and secure_ok


def is_task_registered(task_name):
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
            text=True,
            errors=CONSOLE_DECODE_ERRORS,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def is_registry_startup_registered(app_name):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_SUBKEY, 0, winreg.KEY_READ) as reg_key:
            winreg.QueryValueEx(reg_key, app_name)
        return True
    except Exception:
        return False


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
        (t("diag_guard_exe_found"), os.path.exists(GUARD_EXE)),
        (t("diag_config_accessible"), os.path.exists(CONFIG_PATH)),
        (t("diag_password_hashed"), bool(state.ADMIN_PASSWORD_HASH and state.ADMIN_PASSWORD_SALT)),
        (t("diag_task_app"), is_task_registered(APP_STARTUP_NAME)),
        (t("diag_task_guard"), is_task_registered(GUARD_STARTUP_NAME)),
        (t("diag_registry_app"), is_registry_startup_registered(APP_STARTUP_NAME)),
        (t("diag_registry_guard"), is_registry_startup_registered(GUARD_STARTUP_NAME)),
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
    from appcore.paths import base_dir

    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = (proc.info.get('name') or '').lower()
            exe = (proc.info.get('exe') or '').lower()
            if is_guard_process_name(name, exe):
                return False  # уже запущен
        except Exception:
            pass

    if os.path.exists(GUARD_EXE):
        subprocess.Popen([GUARD_EXE], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
        return True
    log(t("log_guard_exe_not_found", path=GUARD_EXE))
    return False


def watch_appblocker_guard():
    """Следит за AppBlockerGuard и перезапускает его при необходимости"""
    from appcore.paths import base_dir

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

            if not found and os.path.exists(GUARD_EXE) and state.watch_active:
                try:
                    subprocess.Popen([GUARD_EXE], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
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


def open_antivirus_guide():
    import webbrowser
    from appcore.theme import ANTIVIRUS_GUIDE_URL

    try:
        webbrowser.open(ANTIVIRUS_GUIDE_URL)
    except Exception as e:
        log(t("log_guide_open_failed", error=e))


def open_defender_exclusions_settings():
    from appcore.theme import (
        DEFENDER_EXCLUSIONS_URI,
        DEFENDER_THREAT_SETTINGS_URI,
        WINDOWS_SECURITY_SETTINGS_URI,
    )

    for uri in (DEFENDER_EXCLUSIONS_URI, DEFENDER_THREAT_SETTINGS_URI, WINDOWS_SECURITY_SETTINGS_URI):
        try:
            os.startfile(uri)
            log(t("log_defender_exclusions_opened"))
            return True
        except Exception:
            continue
    log(t("log_defender_exclusions_open_failed"))
    return False


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


def get_defender_exclusion_paths():
    if os.name != "nt":
        return [], None
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        "(Get-MpPreference).ExclusionPath | ConvertTo-Json -Compress",
    ]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors=CONSOLE_DECODE_ERRORS,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as e:
        return None, str(e)

    if result.returncode != 0:
        return None, (result.stderr or result.stdout or "Get-MpPreference returned an error").strip()

    raw = (result.stdout or "").strip()
    if raw.startswith('"') and raw.endswith('"'):
        try:
            unquoted_raw = json.loads(raw)
        except json.JSONDecodeError:
            unquoted_raw = raw.strip('"')
        if isinstance(unquoted_raw, str) and "must be an administrator" in unquoted_raw.lower():
            return None, "admin_required"
    if "must be an administrator" in raw.lower():
        return None, "admin_required"
    if not raw or raw == "null":
        return [], None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = raw
    if isinstance(data, str):
        return [data], None
    if isinstance(data, list):
        return [str(item) for item in data if item], None
    return [], None


def is_path_covered_by_exclusion(app_path, exclusions):
    def normalize_path(value):
        value = os.path.expandvars(str(value)).strip().strip('"')
        value = value.replace("/", "\\")
        value = os.path.abspath(value)
        try:
            value = os.path.realpath(value)
        except Exception:
            pass
        return os.path.normcase(value).rstrip("\\/")

    app_path = normalize_path(app_path)
    for exclusion in exclusions or []:
        if not exclusion:
            continue
        exclusion_path = normalize_path(exclusion)
        if (
            app_path == exclusion_path
            or app_path.startswith(exclusion_path + os.sep)
            or exclusion_path.startswith(app_path + os.sep)
        ):
            return True
    return False


def check_antivirus_exception():
    """Проверяет, добавлена ли папка App Blocker в исключения Defender.

    Возвращает пару ``(найдено, сообщение)`` — показать результат решает
    вызывающий. Раньше функция сама настраивала переданный ей виджет и открывала
    диалог; теперь она ничего не знает об интерфейсе и её можно звать из
    фонового потока, а опрос Defender через PowerShell идёт секунды.
    """
    app_path = get_app_folder_path()
    exclusions, error = get_defender_exclusion_paths()
    if exclusions is None:
        if error == "admin_required":
            message = t("defender_admin_required")
        else:
            message = t("defender_check_unavailable")
        if error:
            log(t("log_defender_check_failed", error=error))
        found = False
    elif is_path_covered_by_exclusion(app_path, exclusions):
        message = t("defender_found")
        found = True
    else:
        message = t("defender_not_found")
        found = False

    log(message)
    return found, message


def enable_security_after_consent(on_status_update=None):
    state.SECURE_ENABLED = True
    state.SECURITY_WARNING_SEEN = True
    from appcore.config_store import save_security_state, save_config
    save_security_state()
    save_config()

    if ensure_appblocker_guard():
        log(t("log_guard_activated_generic"))

    if is_admin():
        ensure_app_startup_entries(on_status_update=on_status_update)
    else:
        ensure_startup_entry(GUARD_STARTUP_NAME, GUARD_EXE)
        log(t("log_protection_enabled_registry_only"))

    start_guard_watch_thread()

    if on_status_update is not None:
        on_status_update()
    log(t("log_protection_enabled_by_user"))
