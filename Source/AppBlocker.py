import psutil
import os
import sys
import threading
import time
import subprocess
import json
import datetime
import winreg
import ctypes
import re
import hashlib
import hmac
import secrets
import shutil
import webbrowser
import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox, filedialog
from threading import Lock, Event

try:
    import pystray
    from PIL import Image, ImageTk, ImageOps, ImageFilter
    TRAY_AVAILABLE = True
except Exception:
    pystray = None
    Image = None
    ImageTk = None
    ImageOps = None
    ImageFilter = None
    TRAY_AVAILABLE = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

APP_BG = "#10051F"
SIDEBAR_BG = "#141126"
TOPBAR_BG = "#17122B"
PANEL_BG = "#171429"
CARD_BG = "#1B1830"
CARD_HOVER = "#272145"
BORDER_COLOR = "#514879"
BORDER_SUBTLE = "#302A4D"
PRIMARY = "#8B5CF6"
PRIMARY_HOVER = "#9D6EFF"
SECONDARY = "#D946EF"
SECONDARY_HOVER = "#E879F9"
ACCENT = "#C084FC"
SUCCESS = "#22C55E"
WARNING = "#F59E0B"
ERROR = "#EF4444"
ERROR_HOVER = "#F87171"
TEXT_MAIN = "#FFFFFF"
TEXT_MUTED = "#A6ADC8"
INPUT_BG = "#151228"
ROW_BG = "#1F1A36"
ROW_HOVER = "#2A2350"
SECONDARY_BG = "#26213F"
SECONDARY_BG_HOVER = "#362D60"
DISABLED_BG = "#1E1A32"
CARD_RADIUS = 24
BUTTON_RADIUS = 16
BORDER_WIDTH = 1
FONT_FAMILY = "Segoe UI"
APP_FONT_FILE = "Huninn-Regular.ttf"
BACKGROUND_IMAGE_FILE = "background_low.jpg"
BACKGROUND_FALLBACK_IMAGE_FILE = "ChatGPT Image 24 июн. 2026 г., 23_48_27.png"
APP_FONT_FAMILY = "Segoe UI"
MONO_FONT_FAMILY = "JetBrains Mono"
EMOJI_FONT_FAMILY = "Segoe UI Emoji"
EMOJI_PATTERN = re.compile(
    "["
    "\U0001F1E6-\U0001F1FF"
    "\U0001F300-\U0001FAFF"
    "\u2600-\u27BF"
    "][\ufe0f]?"
)
ANTIVIRUS_GUIDE_URL = "https://www.youtube.com/watch?v=pG03P8DdJzg"
DEFENDER_EXCLUSIONS_URI = "windowsdefender://exclusions"
DEFENDER_THREAT_SETTINGS_URI = "windowsdefender://threatsettings"
WINDOWS_SECURITY_SETTINGS_URI = "ms-settings:windowsdefender"

PROCESS_NAME = ""
BLOCKED_PROGRAMS = []
ADMIN_PASSWORD = ""
ADMIN_PASSWORD_HASH = ""
ADMIN_PASSWORD_SALT = ""
monitor_thread = None
monitoring_active = False
last_monitor_state = None
SECURE_ENABLED = False  # по умолчанию защита выключена
SECURITY_WARNING_SEEN = False
TIMER_ENABLED = False
PERMANENT_LOCK = False
MATCH_MODE = "contains"
TIMER_END = None
timer_thread = None
APP_CLOSING = False
TRAY_ICON = None
CONFIG_LOCK = Lock()
SECURITY_OFF_WARNING_SHOWN = False
SECURITY_WARNING_DIALOG = None
RUN_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
shutdown_event = Event()
watch_active = False
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
BLOCK_MARKER = "# AppBlocker managed"
APP_STARTUP_NAME = "AppBlocker"
GUARD_STARTUP_NAME = "AppBlockerGuard"
LEGACY_GUARD_STARTUP_NAME = "SecureSystem"
GUARD_EXE_NAME = "AppBlockerGuard.exe"
LEGACY_GUARD_EXE_NAME = "SecureSystem.exe"

EXIT_LOCK = Lock()
SINGLE_INSTANCE_MUTEX_NAME = "Global\\AppBlockerMainInstance"
_single_instance_mutex = None


def ensure_single_instance():
    global _single_instance_mutex
    try:
        kernel32 = ctypes.windll.kernel32
        _single_instance_mutex = kernel32.CreateMutexW(None, False, SINGLE_INSTANCE_MUTEX_NAME)
        return kernel32.GetLastError() != 183
    except Exception:
        return True


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

def base_dir():
    """Безопасный путь для AppBlocker — хранит всё в AppData, но иконку ищет рядом с exe."""
    appdata_path = os.path.join(os.getenv("APPDATA"), "AppBlocker")
    os.makedirs(appdata_path, exist_ok=True)

    # Для иконки и exe возвращаем путь программы
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    return exe_dir

def find_font_path():
    bundle_dir = getattr(sys, "_MEIPASS", None)
    candidates = [
        os.path.join(bundle_dir, APP_FONT_FILE) if bundle_dir else "",
        os.path.join(base_dir(), APP_FONT_FILE),
        os.path.join(base_dir(), "Source", APP_FONT_FILE),
        os.path.join(os.getcwd(), APP_FONT_FILE),
        os.path.join(os.getcwd(), "Source", APP_FONT_FILE),
        os.path.join(os.path.dirname(base_dir()), APP_FONT_FILE),
        os.path.join(os.path.dirname(base_dir()), "Source", APP_FONT_FILE),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None

def load_app_font():
    font_path = find_font_path()
    if not font_path:
        return FONT_FAMILY
    try:
        # FR_PRIVATE keeps the font available to this app without requiring system install.
        FR_PRIVATE = 0x10
        loaded = ctypes.windll.gdi32.AddFontResourceExW(font_path, FR_PRIVATE, 0)
        if loaded:
            return APP_FONT_FAMILY
    except Exception:
        pass
    return APP_FONT_FAMILY

FONT_FAMILY = load_app_font()

def find_icon_path():
    bundle_dir = getattr(sys, "_MEIPASS", None)
    candidates = [
        os.path.join(bundle_dir, "icon.ico") if bundle_dir else "",
        os.path.join(base_dir(), "icon.ico"),
        os.path.join(os.getcwd(), "icon.ico"),
        os.path.join(os.getcwd(), "Program", "icon.ico"),
        os.path.join(os.path.dirname(base_dir()), "icon.ico"),
        os.path.join(os.path.dirname(base_dir()), "Program", "icon.ico"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def find_background_path():
    bundle_dir = getattr(sys, "_MEIPASS", None)
    candidates = []
    for filename in (BACKGROUND_IMAGE_FILE, BACKGROUND_FALLBACK_IMAGE_FILE):
        candidates.extend([
            os.path.join(bundle_dir, filename) if bundle_dir else "",
            os.path.join(base_dir(), filename),
            os.path.join(base_dir(), "Source", filename),
            os.path.join(os.getcwd(), filename),
            os.path.join(os.getcwd(), "Source", filename),
            os.path.join(os.path.dirname(base_dir()), filename),
            os.path.join(os.path.dirname(base_dir()), "Source", filename),
        ])
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None

BACKGROUND_LABEL = None
BACKGROUND_PHOTO = None
BACKGROUND_ORIGINAL = None
BACKGROUND_SIZE = None
BACKGROUND_REFRESH_JOB = None

def install_background_image(window):
    global BACKGROUND_LABEL, BACKGROUND_PHOTO, BACKGROUND_ORIGINAL, BACKGROUND_SIZE, BACKGROUND_REFRESH_JOB
    if Image is None or ImageTk is None or ImageOps is None:
        return
    background_path = find_background_path()
    if not background_path:
        return
    try:
        BACKGROUND_ORIGINAL = Image.open(background_path).convert("RGB")
        if BACKGROUND_ORIGINAL.width > 1920 or BACKGROUND_ORIGINAL.height > 1080:
            BACKGROUND_ORIGINAL.thumbnail((1920, 1080), Image.Resampling.BILINEAR)
        if ImageFilter is not None:
            BACKGROUND_ORIGINAL = BACKGROUND_ORIGINAL.filter(ImageFilter.GaussianBlur(radius=10))
    except Exception:
        return

    BACKGROUND_LABEL = tk.Label(window, bd=0, highlightthickness=0)
    BACKGROUND_LABEL.place(x=0, y=0, relwidth=1, relheight=1)
    BACKGROUND_LABEL.lower()

    def refresh_background(event=None):
        global BACKGROUND_PHOTO, BACKGROUND_SIZE, BACKGROUND_REFRESH_JOB
        BACKGROUND_REFRESH_JOB = None
        if event is not None and event.widget is not window:
            return
        width = max(1, int(window.winfo_width() / 24) * 24)
        height = max(1, int(window.winfo_height() / 24) * 24)
        if width < 80 or height < 80 or BACKGROUND_SIZE == (width, height):
            return
        BACKGROUND_SIZE = (width, height)
        fitted = ImageOps.fit(BACKGROUND_ORIGINAL, (width, height), method=Image.Resampling.BILINEAR)
        dark_overlay = Image.new("RGB", (width, height), APP_BG)
        fitted = Image.blend(fitted, dark_overlay, 0.10)
        BACKGROUND_PHOTO = ImageTk.PhotoImage(fitted)
        BACKGROUND_LABEL.configure(image=BACKGROUND_PHOTO)
        BACKGROUND_LABEL.image = BACKGROUND_PHOTO
        BACKGROUND_LABEL.lower()

    def schedule_refresh(event=None):
        global BACKGROUND_REFRESH_JOB
        if event is not None and event.widget is not window:
            return
        if BACKGROUND_REFRESH_JOB is not None:
            window.after_cancel(BACKGROUND_REFRESH_JOB)
        BACKGROUND_REFRESH_JOB = window.after(120, refresh_background)

    window.bind("<Configure>", schedule_refresh)
    window.after(350, refresh_background)

def set_window_icon(window):
    icon_path = find_icon_path()
    if not icon_path:
        return
    try:
        window.iconbitmap(icon_path)
    except Exception:
        pass
    try:
        window.iconbitmap(default=icon_path)
    except Exception:
        pass
    try:
        window.after(100, lambda: window.iconbitmap(icon_path))
    except Exception:
        pass

def paste_into_entry(entry):
    try:
        text = entry.clipboard_get()
    except Exception:
        return "break"
    try:
        entry.delete("sel.first", "sel.last")
    except Exception:
        pass
    entry.insert("insert", text)
    return "break"

def handle_entry_ctrl_key(event):
    if event.keycode == 86:
        return paste_into_entry(event.widget)
    return None

def is_admin():
    """Проверяет, запущено ли приложение с правами администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def admin_warning_text(action_name):
    return (
        f"{action_name} требует права администратора. "
        "Обычный интерфейс открыт без UAC, но эту операцию нужно запускать от имени администратора."
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
                            except:
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
                        except:
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
            creationflags=0x08000000,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"[Cleanup] ✅ Задача '{app_name}' удалена")
            deleted_any = True
    except Exception as e:
        print(f"[Cleanup] ⚠️ Ошибка удаления задачи: {e}")

    print(f"[Cleanup] {'✅ Очистка завершена' if deleted_any else 'ℹ️ Записи не найдены'}")
    return deleted_any


def exit_app_no_password():
    global monitoring_active, watch_active, APP_CLOSING, PERMANENT_LOCK

    # ✅ ЗАЩИТА: НЕ УДАЛЯЕМ CONFIG ПРИ ПЕРВОМ ЗАПУСКЕ
    if not PROCESS_NAME:
        log("⚠️ Выход отменён: процесс не задан (первый запуск)")
        return

    if not monitoring_active:
        log("⚠️ Выход отменён: мониторинг не был запущен")
        return

    with EXIT_LOCK:
        if APP_CLOSING:
            return
        APP_CLOSING = True

    log("⏰ Выход без пароля (таймер/автоматический)...")

    # ОСТАНАВЛИВАЕМ ПОТОКИ
    monitoring_active = False
    watch_active = False
    PERMANENT_LOCK = False
    shutdown_event.set()
    time.sleep(1.5)

    # ✅ СНАЧАЛА РАЗБЛОКИРУЕМ САЙТЫ
    try:
        sites = load_blocked_sites()
        if sites:
            log(f"🧼 Удаляем {len(sites)} сайтов из hosts...")
            save_blocked_sites([])

            for attempt in range(3):
                if apply_hosts_block([]):
                    log("✅ Все сайты разблокированы")
                    break
                else:
                    log(f"⚠️ Попытка {attempt + 1}/3, повторяю...")
                    time.sleep(0.5)
        else:
            log("ℹ️ Список сайтов пуст")
    except Exception as e:
        log(f"⚠️ Ошибка при очистке сайтов: {e}")

    # ТЕПЕРЬ УДАЛЯЕМ CONFIG
    create_exit_sentinel()
    clear_admin_password()
    save_config(status="EXIT")

    # ЗАВЕРШАЕМ AppBlockerGuard
    for attempt in range(5):
        killed = False
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if is_guard_process_name(proc.info['name']):
                    proc.kill()
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if killed:
            time.sleep(0.3)
        else:
            break

        time.sleep(0.5)

    try:
        log("🧹 config.json сохранён, чтобы не терять настройки защиты")

        sentinel_path = os.path.join(base_dir(), "config.exit.lock")
        if os.path.exists(sentinel_path):
            os.chmod(sentinel_path, 0o666)
            os.remove(sentinel_path)
            log("🧹 config.exit.lock удалён (exit_app_no_password)")
    except Exception as e:
        log(f"⚠️ Ошибка при удалении файлов: {e}")

    remove_from_startup_everywhere(APP_STARTUP_NAME, "AppBlocker.exe")
    remove_from_startup_everywhere(GUARD_STARTUP_NAME, GUARD_EXE_NAME)
    stop_tray_icon()
    root.after(500, root.destroy)

def close_app():
    if not BLOCKED_PROGRAMS:
        return

    for proc in psutil.process_iter():
        try:
            process_name = proc.name().lower()
            matched_program = next((program for program in BLOCKED_PROGRAMS if process_matches_rule(process_name, program)), None)
            if matched_program:
                process_name_full = proc.name()
                proc.terminate()
                log(f"🔴 Приложение '{process_name_full}' (PID: {proc.pid}) завершено. Правило: {matched_program}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
STATE_DIR = os.path.join(os.getenv("APPDATA") or APP_DIR, "AppBlocker")
WELCOME_MARKER_PATH = os.path.join(STATE_DIR, "welcome_seen.marker")
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
CONFIG_BACKUP_PATH = os.path.join(APP_DIR, "config.backup.json")
SECURITY_STATE_PATH = os.path.join(STATE_DIR, "security_state.json")
GUARD_EXE  = os.path.join(APP_DIR, GUARD_EXE_NAME)
EXIT_SENTINEL = os.path.join(APP_DIR, "config.exit.lock")
LOG_DIR = os.path.join(APP_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "appblocker.log")
os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# App Blocker opens without forced UAC. Protected actions check admin rights when used.

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000 if os.name == "nt" else 0)

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

def ensure_app_startup_entries():
    app_exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
    remove_from_startup_everywhere(LEGACY_GUARD_STARTUP_NAME, LEGACY_GUARD_EXE_NAME)
    app_ok = ensure_startup_entry(APP_STARTUP_NAME, app_exe)
    secure_ok = True
    if SECURE_ENABLED:
        secure_ok = ensure_startup_entry(GUARD_STARTUP_NAME, GUARD_EXE)
    if app_ok and secure_ok:
        log("✅ Автозапуск настроен для AppBlocker и AppBlockerGuard")
    elif app_ok:
        log("⚠️ Автозапуск AppBlocker настроен, но AppBlockerGuard не найден или не добавлен")
    else:
        log("⚠️ Не удалось настроить автозапуск. Проверь запуск от имени администратора.")
    update_startup_status_labels()
    return app_ok and secure_ok

def is_task_registered(task_name):
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", task_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
            text=True,
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
    app_exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
    checks = [
        ("Права администратора", is_admin()),
        ("AppBlocker.exe найден", os.path.exists(app_exe)),
        ("AppBlockerGuard.exe найден", os.path.exists(GUARD_EXE)),
        ("config.json доступен", os.path.exists(CONFIG_PATH)),
        ("Пароль защищён хешем", bool(ADMIN_PASSWORD_HASH and ADMIN_PASSWORD_SALT)),
        ("Задача AppBlocker", is_task_registered(APP_STARTUP_NAME)),
        ("Задача AppBlockerGuard", is_task_registered(GUARD_STARTUP_NAME)),
        ("Реестр AppBlocker", is_registry_startup_registered(APP_STARTUP_NAME)),
        ("Реестр AppBlockerGuard", is_registry_startup_registered(GUARD_STARTUP_NAME)),
        ("AppBlockerGuard запущен", is_process_running_by_name(GUARD_EXE_NAME)),
        ("Доступ к hosts", os.path.exists(HOSTS_PATH) and os.access(HOSTS_PATH, os.W_OK)),
    ]
    return checks

def run_diagnostics():
    checks = build_diagnostics()
    ok_count = sum(1 for _, ok in checks if ok)
    log(f"🧪 Диагностика защиты: {ok_count}/{len(checks)} проверок пройдено")
    for name, ok in checks:
        log(f"{'✅' if ok else '⚠️'} {name}")
    update_startup_status_labels()

def update_startup_status_labels():
    try:
        app_task = is_task_registered(APP_STARTUP_NAME)
        secure_task = is_task_registered(GUARD_STARTUP_NAME)
        app_reg = is_registry_startup_registered(APP_STARTUP_NAME)
        secure_reg = is_registry_startup_registered(GUARD_STARTUP_NAME)
        app_startup_status.configure(
            text="Активен" if app_task or app_reg else "Не настроен",
            text_color=PRIMARY if app_task or app_reg else TEXT_MUTED
        )
        secure_startup_status.configure(
            text="Активен" if secure_task or secure_reg else "Не настроен",
            text_color=PRIMARY if secure_task or secure_reg else TEXT_MUTED
        )
        secure_file_status.configure(
            text="Найден" if os.path.exists(GUARD_EXE) else "Не найден",
            text_color=PRIMARY if os.path.exists(GUARD_EXE) else ERROR
        )
    except NameError:
        pass

def has_seen_welcome():
    return os.path.exists(WELCOME_MARKER_PATH)

def mark_welcome_seen():
    try:
        with open(WELCOME_MARKER_PATH, "w", encoding="utf-8") as f:
            f.write(datetime.datetime.now().isoformat())
    except Exception:
        pass

def create_tray_image():
    if not TRAY_AVAILABLE:
        return None
    icon_path = find_icon_path()
    try:
        if icon_path:
            return Image.open(icon_path).resize((64, 64))
    except Exception:
        pass
    image = Image.new("RGB", (64, 64), APP_BG)
    return image

def show_main_window():
    try:
        root.withdraw()
        root.deiconify()
        root.state("normal")
        root.update_idletasks()
        try:
            hwnd = root.winfo_id()
            ctypes.windll.user32.ShowWindow(hwnd, 9)  # SW_RESTORE
            ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass
        root.lift()
        root.attributes("-topmost", True)
        root.after(250, lambda: root.attributes("-topmost", False))
        root.focus_force()
    except Exception:
        pass


def force_show_main_window(repeats=12, interval=350):
    def bring_left(count):
        show_main_window()
        if count > 0:
            root.after(interval, lambda: bring_left(count - 1))

    bring_left(repeats)


def keep_modal_on_top(dialog, interval=250, use_grab=True):
    def keep():
        try:
            if not dialog.winfo_exists():
                return
            dialog.transient(root)
            dialog.attributes("-topmost", True)
            dialog.lift()
            dialog.focus_force()
            dialog.after(interval, keep)
        except Exception:
            pass

    try:
        try:
            root.attributes("-topmost", False)
        except Exception:
            pass
        dialog.transient(root)
        dialog.attributes("-topmost", True)
        dialog.lift()
        dialog.focus_force()
        if use_grab:
            try:
                dialog.grab_set()
            except Exception:
                pass
        dialog.after(50, keep)
    except Exception:
        pass


def hide_to_tray():
    if TRAY_AVAILABLE:
        root.withdraw()
        log("📌 Окно скрыто в трей.")
    else:
        root.iconify()
        log("📌 Окно свернуто. Библиотека трея недоступна.")

def stop_tray_icon():
    global TRAY_ICON
    try:
        if TRAY_ICON:
            TRAY_ICON.stop()
            TRAY_ICON = None
    except Exception:
        pass

def start_tray_icon():
    global TRAY_ICON
    if not TRAY_AVAILABLE or TRAY_ICON:
        return

    def tray_show(icon=None, item=None):
        root.after(0, show_main_window)

    def tray_hide(icon=None, item=None):
        root.after(0, hide_to_tray)

    def tray_exit(icon=None, item=None):
        root.after(0, lambda: (show_main_window(), exit_app()))

    image = create_tray_image()
    if image is None:
        return
    menu = pystray.Menu(
        pystray.MenuItem("Открыть", tray_show),
        pystray.MenuItem("Скрыть", tray_hide),
        pystray.MenuItem("Выход", tray_exit),
    )
    TRAY_ICON = pystray.Icon("App Blocker", image, "App Blocker", menu)
    threading.Thread(target=TRAY_ICON.run, daemon=True).start()

#блокировка сайтов
def normalize_site(site):
    site = site.strip().lower()
    site = re.sub(r"^https?://", "", site)
    site = re.sub(r"^www\.", "", site)
    site = site.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    site = site.split(":", 1)[0].strip(". ")
    if not site:
        return ""
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", site):
        return ""
    if any(part.startswith("-") or part.endswith("-") for part in site.split(".")):
        return ""
    return site

def normalize_sites(sites):
    normalized = []
    for site in sites:
        site = normalize_site(site)
        if site and site not in normalized:
            normalized.append(site)
    return normalized

def parse_sites_input(text):
    return normalize_sites(re.split(r"[\s,;]+", text.strip()))

def hosts_entries_for_site(site):
    hosts = expand_site_hosts(site)
    entries = []
    for host in hosts:
        entries.append(f"0.0.0.0 {host} {BLOCK_MARKER}: {site}\n")
        entries.append(f"127.0.0.1 {host} {BLOCK_MARKER}: {site}\n")
        entries.append(f"::1 {host} {BLOCK_MARKER}: {site}\n")
    return entries

SITE_HOST_ALIASES = {
    "youtube.com": [
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "studio.youtube.com",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com",
        "youtu.be",
        "www.youtu.be",
        "ytimg.com",
        "www.ytimg.com",
        "i.ytimg.com",
        "s.ytimg.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "googlevideo.com",
        "www.googlevideo.com",
    ],
    "youtu.be": [
        "youtu.be",
        "www.youtu.be",
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com",
        "ytimg.com",
        "www.ytimg.com",
        "i.ytimg.com",
        "s.ytimg.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "googlevideo.com",
        "www.googlevideo.com",
    ],
}

BROWSER_PROCESS_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "opera_gx.exe",
    "browser.exe",
    "yandex.exe",
}

def expand_site_hosts(site):
    site = normalize_site(site)
    if not site:
        return []
    aliases = SITE_HOST_ALIASES.get(site, [site, f"www.{site}"])
    expanded = []
    for host in aliases:
        host = normalize_site(host)
        if host and host not in expanded:
            expanded.append(host)
    return expanded

def restart_browsers_for_site_block():
    closed = []
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in BROWSER_PROCESS_NAMES:
                proc.terminate()
                closed.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not closed:
        return
    try:
        gone, alive = psutil.wait_procs(
            [p for p in psutil.process_iter(["name"]) if (p.info.get("name") or "").lower() in BROWSER_PROCESS_NAMES],
            timeout=1.5
        )
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    closed_names = ", ".join(sorted(set(closed)))
    log(f"🔄 Браузеры закрыты для мгновенного применения блокировки: {closed_names}")

def load_blocked_sites():
    """Загружает список сайтов из config.json"""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            return normalize_sites(data.get("blocked_sites", []))
        except Exception as e:
            print(f"Ошибка чтения blocked_sites: {e}")
    return []

def save_blocked_sites(sites):
    """Сохраняет список сайтов в config.json"""
    sites = normalize_sites(sites)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = {}
    data["blocked_sites"] = sites
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)



# -------------- СОХРАНЕНИЕ КОНФИГА ----------------

def apply_hosts_block(sites):
    sites = normalize_sites(sites)
    try:
        if not is_admin():
            log("❌ Нет прав администратора для изменения hosts. Перезапусти App Blocker от имени администратора.")
            return False

        if os.path.exists(HOSTS_PATH) and not os.access(HOSTS_PATH, os.W_OK):
            os.chmod(HOSTS_PATH, 0o666)

        if os.path.exists(HOSTS_PATH):
            with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        else:
            lines = []

        new_lines = [line for line in lines if BLOCK_MARKER not in line]
        if sites:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"{BLOCK_MARKER}: start\n")
            for site in sites:
                new_lines.extend(hosts_entries_for_site(site))
            new_lines.append(f"{BLOCK_MARKER}: end\n")

        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
            f.flush()
            os.fsync(f.fileno())

        for command in (
            ["ipconfig", "/flushdns"],
            ["powershell", "-NoProfile", "-Command", "Clear-DnsClientCache"],
        ):
            try:
                subprocess.run(
                    command,
                    creationflags=CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8
                )
            except Exception:
                pass

        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        missing = []
        for site in sites:
            expected_hosts = expand_site_hosts(site)
            found_site = any(
                f"0.0.0.0 {host} " in content
                or f"127.0.0.1 {host} " in content
                or f"::1 {host} " in content
                for host in expected_hosts
            )
            if not found_site:
                missing.append(site)
        if missing:
            log(f"⚠️ Не все сайты попали в hosts: {', '.join(missing)}")
            return False
        if not sites and BLOCK_MARKER in content:
            log("⚠️ В hosts остались старые записи App Blocker")
            return False

        if sites:
            expanded_count = sum(len(expand_site_hosts(site)) for site in sites)
            log(f"🌐 Блокировка сайтов применена: {len(sites)} правил, {expanded_count} доменов в hosts")
        else:
            log("🧹 Блокировка сайтов очищена")
        return True

    except PermissionError:
        log("❌ Нет прав для изменения hosts. Запусти App Blocker от имени администратора.")
        return False
    except Exception as e:
        log(f"⚠️ Ошибка блокировки сайтов: {e}")
        return False

def normalize_process_name(name):
    return name.strip().lower()

def sync_primary_process_name():
    global PROCESS_NAME
    PROCESS_NAME = BLOCKED_PROGRAMS[0] if BLOCKED_PROGRAMS else ""

def process_matches_rule(process_name, rule):
    process_name = normalize_process_name(process_name)
    rule = normalize_process_name(rule)
    if not process_name or not rule:
        return False
    if MATCH_MODE == "exact":
        return process_name == rule
    return rule in process_name

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
    return bool(ADMIN_PASSWORD_HASH or ADMIN_PASSWORD)

def verify_admin_password(password):
    if not password:
        return False
    if ADMIN_PASSWORD_HASH and ADMIN_PASSWORD_SALT:
        _, candidate_hash = hash_admin_password(password, ADMIN_PASSWORD_SALT)
        return hmac.compare_digest(candidate_hash, ADMIN_PASSWORD_HASH)
    return hmac.compare_digest(password, ADMIN_PASSWORD)

def set_admin_password(password):
    global ADMIN_PASSWORD, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT
    ADMIN_PASSWORD = ""
    ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_HASH = hash_admin_password(password)


def clear_admin_password():
    global ADMIN_PASSWORD, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT
    ADMIN_PASSWORD = ""
    ADMIN_PASSWORD_HASH = ""
    ADMIN_PASSWORD_SALT = ""


def save_security_state():
    data = {
        "secure_enabled": SECURE_ENABLED,
        "security_warning_seen": SECURITY_WARNING_SEEN,
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
    global SECURE_ENABLED, SECURITY_WARNING_SEEN
    state = load_security_state()
    source = state if state else (config or {})
    SECURE_ENABLED = bool(source.get("secure_enabled", False))
    SECURITY_WARNING_SEEN = bool(source.get("security_warning_seen", False))


def save_config(status=None):
    """Сохраняет конфиг, не удаляя список сайтов"""
    global ADMIN_PASSWORD, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT
    data = {}

    # ✅ Если файл уже существует — читаем его, чтобы не потерять blocked_sites
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ Ошибка чтения config.json: {e}")
            data = {}

    if ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH:
        ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_HASH = hash_admin_password(ADMIN_PASSWORD)
        ADMIN_PASSWORD = ""
    data.pop("admin_password", None)

    # ✅ Обновляем только нужные ключи
    if status is None:
        status = "RUNNING" if monitoring_active else data.get("status", "EXIT")

    data.update({
        "process_name": PROCESS_NAME,
        "blocked_programs": BLOCKED_PROGRAMS,
        "admin_password_hash": ADMIN_PASSWORD_HASH,
        "admin_password_salt": ADMIN_PASSWORD_SALT,
        "status": status,
        "timer_enabled": TIMER_ENABLED,
        "timer_end": TIMER_END.timestamp() if TIMER_END else None,
        "secure_enabled": SECURE_ENABLED,
        "security_warning_seen": SECURITY_WARNING_SEEN,
        "permanent_lock": PERMANENT_LOCK,
        "match_mode": MATCH_MODE,
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
    global PROCESS_NAME, BLOCKED_PROGRAMS, ADMIN_PASSWORD, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT, TIMER_ENABLED, TIMER_END, SECURE_ENABLED, SECURITY_WARNING_SEEN, PERMANENT_LOCK, MATCH_MODE
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            config = json.load(f)
        migrated_password = False
        saved_programs = config.get("blocked_programs", [])
        if not saved_programs and config.get("process_name", ""):
            saved_programs = [config.get("process_name", "")]
        BLOCKED_PROGRAMS = []
        for program in saved_programs:
            program = normalize_process_name(program)
            if program and program not in BLOCKED_PROGRAMS:
                BLOCKED_PROGRAMS.append(program)
        sync_primary_process_name()
        ADMIN_PASSWORD = config.get("admin_password", "")
        ADMIN_PASSWORD_HASH = config.get("admin_password_hash", "")
        ADMIN_PASSWORD_SALT = config.get("admin_password_salt", "")
        if ADMIN_PASSWORD and not ADMIN_PASSWORD_HASH:
            ADMIN_PASSWORD_SALT, ADMIN_PASSWORD_HASH = hash_admin_password(ADMIN_PASSWORD)
            ADMIN_PASSWORD = ""
            migrated_password = True
        PERMANENT_LOCK = config.get("permanent_lock", False)
        MATCH_MODE = config.get("match_mode", "contains")
        if MATCH_MODE not in ("contains", "exact"):
            MATCH_MODE = "contains"
        TIMER_ENABLED = config.get("timer_enabled", False)
        apply_security_state(config)
        end_timestamp = config.get("timer_end")
        if end_timestamp:
            TIMER_END = datetime.datetime.fromtimestamp(end_timestamp)
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

def export_config():
    target = filedialog.asksaveasfilename(
        title="Экспорт настроек",
        defaultextension=".json",
        filetypes=[("JSON", "*.json")]
    )
    if not target:
        return
    try:
        save_config(status="RUNNING" if monitoring_active else "EXIT")
        shutil.copy2(CONFIG_PATH, target)
        log(f"✅ Настройки экспортированы: {target}")
    except Exception as e:
        log(f"⚠️ Ошибка экспорта настроек: {e}")

def import_config():
    source = filedialog.askopenfilename(
        title="Импорт настроек",
        filetypes=[("JSON", "*.json")]
    )
    if not source:
        return
    try:
        with open(source, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Некорректный формат config")
        shutil.copy2(source, CONFIG_PATH)
        load_config()
        refresh_blocked_programs_list()
        refresh_sites_list()
        update_status_cards()
        update_startup_status_labels()
        log(f"✅ Настройки импортированы: {source}")
    except Exception as e:
        log(f"⚠️ Ошибка импорта настроек: {e}")

def check_timer():
    global TIMER_ENABLED, TIMER_END
    while True:
        if TIMER_ENABLED and TIMER_END:
            now = datetime.datetime.now()
            if now >= TIMER_END:
                log("⏰ Время работы истекло — программа завершается.")
                if SECURE_ENABLED:
                    for proc in psutil.process_iter(['name']):
                        try:
                            if is_guard_process_name(proc.info['name']):
                                proc.terminate()  # ❌ СЛАБОЕ ЗАВЕРШЕНИЕ!
                                log("🛑 AppBlockerGuard завершён по таймеру.")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                exit_app_no_password()
                break
        time.sleep(1)

def get_user_processes():
    """Возвращает список только не системных процессов"""
    system_names = {
        "system", "idle", "svchost.exe", "smss.exe", "wininit.exe",
        "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "dllhost.exe", "runtimebroker.exe", "searchindexer.exe",
        "explorer.exe", "crossdeviceresume.exe", "fmaudiomonitor.exe",
        "fmservice64.exe", "fnhotkeycapslknumlk.exe", "fnhotkeyutility.exe",
        "intelaudioservice.exe", "lenovoutilityservice.exe",
        "lenovovantage-(genericmessagingaddin).exe",
        "lenovovantage-(lenovogamingsystemaddin).exe",
        "lenovovantage-(vantagecoreaddin).exe", "lenovovantageservice.exe",
        "locator.exe", "lockapp.exe", "lsaiso.exe", "mpdefendercoreservice.exe",
        "msmpeng.exe", "nvdisplay.container.exe", "nahimicservice.exe",
        "ngciso.exe", "nhnotifsys.exe", "nissrv.exe", "openconsole.exe",
        "registry", "rtkauduservice64.exe", "rtkbtmanserv.exe", "searchhost.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "shellhost.exe", "startmenuexperiencehost.exe",
        "system idle process", "textinputhost.exe",
        "wmiregistrationservice.exe", "wudfhost.exe", "wmiapsrv.exe",
        "wmiprvse.exe", "backgroundtaskhost.exe",
        "conhost.exe", "ctfmon.exe", "dwm.exe", "fontdrvhost.exe",
        "fsnotifier.exe", "full-line-inference.exe", "ipf_helper.exe",
        "ipf_uf.exe", "ipfsvc.exe", "jhi_service.exe", "msedgewebview2.exe",
        "powershell.exe", "pycharm64.exe", "python.exe", "sihost.exe",
        "spoolsv.exe", "taskhostw.exe", "unsecapp.exe", "MoUsoCoreWorker.exe", "ApplicationFrameHost.exe",
        "LenovoVantage-(GenericTelemetryAddin).exe",
        "audiodg.exe", "smartscreen.exe", "appblocker.exe", GUARD_EXE_NAME.lower(), "ApplicationFrameHost.exe",
        "CHXSmartScreen.exe", "LADMAutoInstallService.exe", "MpCmdRun.exe","RstMwService.exe",
        "ShellExperienceHost.exe", "WidgetService.exe", "cef_server.exe", "nvcontainer.exe",
        "wlanext.exe"
    }
    processes = []
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if name and name.lower() not in system_names and not name.lower().startswith("windows"):
                processes.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(set(processes))

# Проверка запущен ли процесс
def is_app_running():
    if not BLOCKED_PROGRAMS:
        return False

    for proc in psutil.process_iter():
        try:
            process_name = proc.name().lower()
            if any(process_matches_rule(process_name, program) for program in BLOCKED_PROGRAMS):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def is_blocked_program_running(program):
    program = normalize_process_name(program)
    for proc in psutil.process_iter(["name"]):
        try:
            process_name = (proc.info.get("name") or "").lower()
            if process_matches_rule(process_name, program):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def watch_appblocker_guard():
    """Следит за AppBlockerGuard и перезапускает его при необходимости"""
    global watch_active
    print("[Watch] Мониторинг AppBlockerGuard запущен")

    while watch_active and not shutdown_event.is_set():
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

            if not found and os.path.exists(GUARD_EXE) and watch_active:
                try:
                    subprocess.Popen([GUARD_EXE], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
                    print("[Watch] AppBlockerGuard перезапущен")
                except Exception as e:
                    print(f"[Watch] ❌ Ошибка запуска: {e}")
        except Exception as e:
            print(f"[Watch] ⚠️ Ошибка в цикле: {e}")

        shutdown_event.wait(1)  # Проверяем каждую секунду, но можем прерваться

    print("[Watch] Мониторинг AppBlockerGuard остановлен")

def create_exit_sentinel():
    """Создаёт флажок EXIT и делает его read-only (если возможно)."""
    try:
        if not os.path.exists(EXIT_SENTINEL):
            with open(EXIT_SENTINEL, "w", encoding="utf-8") as s:
                s.write("EXIT\n")
                s.flush()           # 💾 Принудительно записать данные
                os.fsync(s.fileno()) # 🧱 Гарантировать запись на диск
        try:
            os.chmod(EXIT_SENTINEL, 0o444)
        except Exception:
            pass
    except Exception as e:
        log(f"⚠️ Ошибка sentinel: {e}")


# Обновление логов в окне
def insert_textbox_with_emoji(textbox, content):
    widget = getattr(textbox, "_textbox", None)
    if widget is None:
        textbox.insert("end", content)
        return

    try:
        widget.tag_configure("emoji", font=(EMOJI_FONT_FAMILY, 13))
        start_index = widget.index("end-1c")
        widget.insert("end", content)
        end_index = widget.index("end-1c")
        inserted = widget.get(start_index, end_index)
        for match in EMOJI_PATTERN.finditer(inserted):
            emoji_start = f"{start_index}+{match.start()}c"
            emoji_end = f"{start_index}+{match.end()}c"
            widget.tag_add("emoji", emoji_start, emoji_end)
    except Exception:
        textbox.insert("end", content)


def log(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass
    text_log.configure(state="normal")   # временно разрешаем редактирование
    insert_textbox_with_emoji(text_log, f"{message}\n")
    text_log.see("end")
    text_log.configure(state="disabled") # снова блокируем пользователя

def clear_logs():
    text_log.configure(state="normal")
    text_log.delete("0.0", "end")
    insert_textbox_with_emoji(text_log, "🛡 Логи очищены.")
    text_log.configure(state="disabled")
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Логи очищены в интерфейсе\n")
    except Exception:
        pass

# Поток фоновой проверки
def monitor_process():
    global monitoring_active, last_monitor_state
    while monitoring_active:
        if not BLOCKED_PROGRAMS:
            time.sleep(1)  # Ждем, пока процесс будет задан
            continue

        if is_app_running():
            if last_monitor_state != "running":
                log("🔍 Найдена заблокированная программа. Закрываю...")
            last_monitor_state = "running"
            close_app()
        else:
            if last_monitor_state != "clear":
                log("✅ Заблокированные программы не запущены.")
            last_monitor_state = "clear"
        try:
            root.after(0, refresh_blocked_programs_list)
        except Exception:
            pass
        time.sleep(2)

# Обработчик кнопки "Начать"
def start_monitoring():
    global PROCESS_NAME, monitor_thread, monitoring_active, watch_active, PERMANENT_LOCK

    input_name = normalize_process_name(entry_process.get())
    if input_name and input_name not in BLOCKED_PROGRAMS:
        BLOCKED_PROGRAMS.append(input_name)
        sync_primary_process_name()
        save_config()
        refresh_blocked_programs_list()
        refresh_process_list()
    elif not input_name:
        sync_primary_process_name()

    if not BLOCKED_PROGRAMS:
        log("❗ Для блокировки программ добавьте хотя бы одну программу. Сайты блокируются отдельно во вкладке «Сайты».")
        return

    input_name = PROCESS_NAME

    # ✅ СРАЗУ БЛОКИРУЕМ ВСЕ ТУМБЛЕРЫ НАВСЕГДА
    secure_switch.configure(state="disabled")
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    try:
        remove_btn.configure(state="disabled")
    except:
        pass
    for widget in timer_frame.winfo_children():
        widget.configure(state="disabled")

    has_admin_rights = is_admin()
    if SECURE_ENABLED and ensure_appblocker_guard():
        log("🛡 AppBlockerGuard активирован")

    if has_admin_rights:
        ensure_app_startup_entries()
    else:
        if SECURE_ENABLED:
            ensure_startup_entry(GUARD_STARTUP_NAME, GUARD_EXE)
            log("ℹ️ Мониторинг программ запущен без прав администратора: AppBlockerGuard активирован, автозапуск через реестр настроен.")
        else:
            log("ℹ️ Мониторинг программ запущен без прав администратора: расширенный автозапуск пропущен.")
    # ✅ ИСПРАВЛЕНО: Активируем watch_active и запускаем поток
    if SECURE_ENABLED and not watch_active:
        watch_active = True  # 🔥 КРИТИЧНО!
        threading.Thread(target=watch_appblocker_guard, daemon=True).start()
        log("👁️ Мониторинг AppBlockerGuard запущен")

    if monitoring_active and input_name == PROCESS_NAME:
        log(f"⚠️ Мониторинг процесса '{PROCESS_NAME}' уже активен.")
        return

    if monitoring_active and input_name != PROCESS_NAME:
        log(f"🔄 Изменение процесса на '{input_name}'. Перезапуск мониторинга.")

    PROCESS_NAME = input_name

    # 🧱 УСТАНАВЛИВАЕМ ПЕРМАНЕНТНУЮ БЛОКИРОВКУ
    PERMANENT_LOCK = True
    save_config()
    log("🔒 Вечная блокировка активирована — переключатели больше нельзя изменить.")

    root.title(f"Blocker: {len(BLOCKED_PROGRAMS)} programs")

    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_process, daemon=True)
        monitor_thread.start()
        log(f"🚀 Мониторинг процесса '{PROCESS_NAME}' запущен.")
    else:
        log(f"✅ Мониторинг продолжен для процесса '{PROCESS_NAME}'.")

    entry_process.configure(state="disabled")
    add_program_btn.configure(state="disabled")
    remove_program_btn.configure(state="disabled")
    big_start_btn.configure(state="disabled")
    update_status_cards()
    refresh_process_list()

    save_config()


def get_app_folder_path():
    return os.path.abspath(base_dir())


def open_antivirus_guide():
    try:
        webbrowser.open(ANTIVIRUS_GUIDE_URL)
    except Exception as e:
        log(f"Не удалось открыть инструкцию: {e}")


def open_defender_exclusions_settings():
    for uri in (DEFENDER_EXCLUSIONS_URI, DEFENDER_THREAT_SETTINGS_URI, WINDOWS_SECURITY_SETTINGS_URI):
        try:
            os.startfile(uri)
            log("Открыт раздел исключений Windows Security.")
            return True
        except Exception:
            continue
    log("⚠️ Не удалось открыть раздел исключений Windows Security.")
    return False


def copy_app_folder_path():
    path = get_app_folder_path()
    try:
        root.clipboard_clear()
        root.clipboard_append(path)
        root.update_idletasks()
        log(f"Путь App Blocker скопирован: {path}")
        return True
    except Exception as e:
        log(f"Не удалось скопировать путь: {e}")
        return False


def custom_info_dialog(title, message, accent=PRIMARY):
    dialog = ctk.CTkToplevel(root)
    dialog.title(title)
    dialog.geometry("560x260")
    dialog.resizable(False, False)
    dialog.configure(fg_color=APP_BG)
    dialog.grab_set()
    dialog.transient(root)
    set_window_icon(dialog)

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
    panel.pack(fill="both", expand=True, padx=18, pady=18)
    ctk.CTkLabel(panel, text=title, font=(FONT_FAMILY, 20, "bold"), text_color=accent).pack(pady=(22, 10))
    ctk.CTkLabel(panel, text=message, font=(FONT_FAMILY, 14), text_color=TEXT_MAIN, wraplength=480, justify="left").pack(padx=28, pady=(0, 18), fill="x")

    ok_btn = ctk.CTkButton(panel, text="OK", width=150, height=40, command=dialog.destroy)
    ok_btn.pack(pady=(0, 20))
    ok_btn.configure(fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    dialog.bind("<Escape>", lambda event: dialog.destroy())
    keep_modal_on_top(dialog)
    dialog.wait_window()


def custom_yes_no_dialog(title, message):
    result = {"confirmed": False}
    dialog = ctk.CTkToplevel(root)
    dialog.title(title)
    dialog.geometry("500x240")
    dialog.resizable(False, False)
    dialog.configure(fg_color=APP_BG)
    dialog.grab_set()
    dialog.transient(root)
    set_window_icon(dialog)

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
    panel.pack(fill="both", expand=True, padx=18, pady=18)
    ctk.CTkLabel(panel, text=title, font=(FONT_FAMILY, 20, "bold"), text_color=PRIMARY).pack(pady=(24, 10))
    ctk.CTkLabel(panel, text=message, font=(FONT_FAMILY, 14), text_color=TEXT_MAIN, wraplength=420).pack(padx=28, pady=(0, 20))

    row = ctk.CTkFrame(panel, fg_color="transparent")
    row.pack(pady=(0, 22))

    def confirm():
        result["confirmed"] = True
        dialog.destroy()

    def cancel():
        result["confirmed"] = False
        dialog.destroy()

    yes_btn = ctk.CTkButton(row, text="Да", width=140, height=40, command=confirm)
    yes_btn.pack(side="left", padx=8)
    yes_btn.configure(fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    no_btn = ctk.CTkButton(row, text="Нет", width=140, height=40, command=cancel)
    no_btn.pack(side="left", padx=8)
    no_btn.configure(fg_color=DISABLED_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    dialog.bind("<Escape>", lambda event: cancel())
    keep_modal_on_top(dialog)
    dialog.wait_window()
    return result["confirmed"]


def show_security_disabled_dialog():
    global SECURITY_WARNING_DIALOG
    try:
        if SECURITY_WARNING_DIALOG is not None and SECURITY_WARNING_DIALOG.winfo_exists():
            SECURITY_WARNING_DIALOG.lift()
            SECURITY_WARNING_DIALOG.focus_force()
            return
    except Exception:
        SECURITY_WARNING_DIALOG = None

    dialog = ctk.CTkToplevel(root)
    SECURITY_WARNING_DIALOG = dialog
    dialog.title("Защита выключена")
    dialog.geometry("620x300")
    dialog.resizable(False, False)
    dialog.configure(fg_color=APP_BG)
    dialog.transient(root)
    # ВАЖНО: скрываем до момента grab_set
    dialog.withdraw()
    set_window_icon(dialog)

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
    panel.pack(fill="both", expand=True, padx=18, pady=18)
    ctk.CTkLabel(panel, text="Защита приложения выключена", font=(FONT_FAMILY, 22, "bold"), text_color=PRIMARY).pack(pady=(24, 10))
    ctk.CTkLabel(
        panel,
        text="Защита приложения выключена, его можно легко закрыть из диспетчера задач. Зайдите в настройки и включите ее.",
        font=(FONT_FAMILY, 14),
        text_color=TEXT_MAIN,
        wraplength=520,
        justify="center"
    ).pack(padx=34, pady=(0, 22))

    buttons = ctk.CTkFrame(panel, fg_color="transparent")
    buttons.pack(pady=(0, 24))

    def enable():
        global SECURITY_WARNING_DIALOG
        SECURITY_WARNING_DIALOG = None
        try:
            dialog.grab_release()
        except Exception:
            pass
        dialog.destroy()
        show_frame("settings")

    def decline():
        global SECURITY_WARNING_DIALOG
        SECURITY_WARNING_DIALOG = None
        try:
            dialog.grab_release()
        except Exception:
            pass
        dialog.destroy()

    enable_btn = ctk.CTkButton(buttons, text="Включить", width=160, height=42, command=enable)
    enable_btn.pack(side="left", padx=10)
    enable_btn.configure(fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    decline_btn = ctk.CTkButton(buttons, text="Отказаться", width=160, height=42, command=decline)
    decline_btn.pack(side="left", padx=10)
    decline_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    dialog.bind("<Escape>", lambda event: decline())
    dialog.protocol("WM_DELETE_WINDOW", decline)

    def show_dialog():
        try:
            if not dialog.winfo_exists():
                return
            dialog.deiconify()   # показываем только сейчас
            dialog.grab_set()
            dialog.lift()
            dialog.focus_force()
        except Exception:
            pass

    dialog.after(600, show_dialog)

def maybe_warn_security_disabled():
    global SECURITY_OFF_WARNING_SHOWN
    if SECURITY_OFF_WARNING_SHOWN or SECURE_ENABLED:
        return
    SECURITY_OFF_WARNING_SHOWN = True
    show_security_disabled_dialog()


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


def check_antivirus_exception(show_dialog=True, status_label=None):
    app_path = get_app_folder_path()
    exclusions, error = get_defender_exclusion_paths()
    if exclusions is None:
        if error == "admin_required":
            message = "⚠️ Windows Defender не даёт проверить исключения без прав администратора. Если папка уже добавлена, нажмите ‘Я добавил, включить’."
        else:
            message = "⚠️ Не удалось проверить исключения Windows Defender. Если вы используете другой антивирус, добавьте путь вручную и нажмите ‘Я добавил, включить’."
        if error:
            log(f"⚠️ Проверка исключения Defender не выполнена: {error}")
        found = False
    elif is_path_covered_by_exclusion(app_path, exclusions):
        message = "✅ Папка App Blocker найдена в исключениях Windows Defender."
        found = True
    else:
        message = "⚠️ Папка не найдена в исключениях Windows Defender. Если вы используете другой антивирус, добавьте путь вручную и нажмите ‘Я добавил, включить’."
        found = False

    if status_label is not None:
        status_label.configure(text=message, text_color=SUCCESS if found else WARNING)
    if show_dialog:
        custom_info_dialog("Проверка исключения", message, accent=SUCCESS if found else WARNING)
    log(message)
    return found


def enable_security_after_consent():
    global SECURE_ENABLED, SECURITY_WARNING_SEEN, watch_active
    SECURE_ENABLED = True
    SECURITY_WARNING_SEEN = True
    save_security_state()
    save_config()

    if ensure_appblocker_guard():
        log("🛡 AppBlockerGuard активирован")

    if is_admin():
        ensure_app_startup_entries()
    else:
        ensure_startup_entry(GUARD_STARTUP_NAME, GUARD_EXE)
        log("ℹ️ Защита включена. Автозапуск через реестр настроен, расширенная задача Windows требует прав администратора.")

    if not watch_active:
        watch_active = True
        threading.Thread(target=watch_appblocker_guard, daemon=True).start()
        log("👁️ Мониторинг AppBlockerGuard запущен")

    update_status_cards()
    update_startup_status_labels()
    log("🛡 Защита включена пользователем.")


def show_security_protection_dialog():
    result = {"confirmed": False}
    app_path = get_app_folder_path()
    dialog = ctk.CTkToplevel(root)
    dialog.title("Включить системную защиту?")
    dialog.geometry("760x620")
    dialog.minsize(720, 580)
    dialog.configure(fg_color=APP_BG)
    dialog.transient(root)
    set_window_icon(dialog)

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
    panel.pack(fill="both", expand=True, padx=18, pady=18)

    ctk.CTkLabel(panel, text="Включить системную защиту?", font=(FONT_FAMILY, 24, "bold"), text_color=PRIMARY).pack(pady=(22, 10))

    message = (
        "App Blocker использует автозагрузку, AppBlockerGuard (SecureSystem) и защиту от завершения. "
        "Из-за этого антивирус может ошибочно заблокировать программу.\n\n"
        "Чтобы защита работала стабильно, добавьте папку App Blocker в исключения антивируса.\n\n"
        "Вы можете доверять программе: исходный код открыт и доступен для проверки:\n"
        "https://github.com/smicsic/App-Blocker/blob/master/Source/SecureSystem.py"
    )
    ctk.CTkLabel(panel, text=message, font=(FONT_FAMILY, 14), text_color=TEXT_MAIN, wraplength=660, justify="left").pack(padx=30, pady=(0, 16), fill="x")

    ctk.CTkLabel(panel, text="Папка программы", font=(FONT_FAMILY, 13, "bold"), text_color=TEXT_MUTED).pack(anchor="w", padx=30, pady=(2, 6))
    path_box = ctk.CTkTextbox(panel, height=58, fg_color=CARD_BG, border_color=BORDER_COLOR, border_width=BORDER_WIDTH, text_color=TEXT_MAIN, font=(MONO_FONT_FAMILY, 13), corner_radius=BUTTON_RADIUS)
    path_box.pack(fill="x", padx=30, pady=(0, 14))
    path_box.insert("1.0", app_path)
    path_box.configure(state="disabled")

    status_label = ctk.CTkLabel(panel, text="", font=(FONT_FAMILY, 13), text_color=TEXT_MUTED, wraplength=660, justify="left")
    status_label.pack(fill="x", padx=30, pady=(0, 14))

    action_row = ctk.CTkFrame(panel, fg_color="transparent")
    action_row.pack(fill="x", padx=30, pady=(0, 14))

    def copy_and_mark():
        if copy_app_folder_path():
            status_label.configure(text="Путь скопирован. Добавьте эту папку в исключения антивируса.", text_color=ACCENT)

    copy_btn = ctk.CTkButton(action_row, text="Скопировать путь", width=150, height=38, command=copy_and_mark)
    copy_btn.pack(side="left", padx=(0, 8))
    copy_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    guide_btn = ctk.CTkButton(action_row, text="Открыть инструкцию", width=160, height=38, command=open_antivirus_guide)
    guide_btn.pack(side="left", padx=8)
    guide_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    check_btn = ctk.CTkButton(action_row, text="Проверить", width=140, height=38, command=lambda: check_antivirus_exception(show_dialog=False, status_label=status_label))
    check_btn.pack(side="left", padx=8)
    check_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    open_exclusions_btn = ctk.CTkButton(action_row, text="Открыть исключения", width=170, height=38, command=open_defender_exclusions_settings)
    open_exclusions_btn.pack(side="left", padx=8)
    open_exclusions_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    bottom_row = ctk.CTkFrame(panel, fg_color="transparent")
    bottom_row.pack(pady=(10, 24))

    def enable():
        result["confirmed"] = True
        dialog.destroy()

    def cancel():
        result["confirmed"] = False
        dialog.destroy()

    enable_btn = ctk.CTkButton(bottom_row, text="Я добавил, включить", width=190, height=42, command=enable)
    enable_btn.pack(side="left", padx=8)
    enable_btn.configure(fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    cancel_btn = ctk.CTkButton(bottom_row, text="Отмена", width=150, height=42, command=cancel)
    cancel_btn.pack(side="left", padx=8)
    cancel_btn.configure(fg_color=ERROR, hover_color=ERROR_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

    # СТАЛО:
    dialog.bind("<Escape>", lambda event: cancel())
    dialog.protocol("WM_DELETE_WINDOW", cancel)

    def show_protection_dialog():
        try:
            if not dialog.winfo_exists():
                return
            dialog.deiconify()
            dialog.grab_set()
            dialog.lift()
            dialog.focus_force()
        except Exception:
            pass

    dialog.withdraw()
    dialog.after(600, show_protection_dialog)
    dialog.wait_window()
    return result["confirmed"]

def toggle_secure_mode():
    global SECURE_ENABLED, SECURITY_WARNING_SEEN
    requested_enabled = secure_switch.get() == 1

    if requested_enabled:
        if SECURE_ENABLED:
            sync_secure_switch_ui()
            return
        if SECURITY_WARNING_SEEN:
            confirmed = custom_yes_no_dialog("Включить системную защиту?", "Включить системную защиту?")
        else:
            confirmed = show_security_protection_dialog()

        if confirmed:
            enable_security_after_consent()
            secure_switch.select()
            sync_secure_switch_ui()
        else:
            SECURE_ENABLED = False
            save_security_state()
            save_config()
            secure_switch.deselect()
            sync_secure_switch_ui()
            update_status_cards()
            log("ℹ️ Защита не включена пользователем.")
        return

    SECURE_ENABLED = False
    save_security_state()
    save_config()
    sync_secure_switch_ui()
    update_status_cards()
    update_startup_status_labels()
    log("🧰 Защита от завершения отключена")


def sync_secure_switch_ui():
    try:
        if SECURE_ENABLED:
            secure_switch.select()
            secure_switch.configure(
                text="Защита от завершения включена",
                progress_color=PRIMARY,
                button_color=PRIMARY,
                button_hover_color=PRIMARY_HOVER,
                text_color=TEXT_MAIN
            )
            secure_state_label.configure(text="Активна: AppBlockerGuard будет защищать приложение от закрытия.", text_color=PRIMARY)
        else:
            secure_switch.deselect()
            secure_switch.configure(
                text="Защита от завершения выключена",
                progress_color=SECONDARY_BG,
                button_color=TEXT_MUTED,
                button_hover_color=TEXT_MAIN,
                text_color=TEXT_MUTED
            )
            secure_state_label.configure(text="Выключена: приложение можно закрыть через диспетчер задач.", text_color=TEXT_MUTED)
    except NameError:
        pass


def on_close():
    hide_to_tray()

def ensure_appblocker_guard():
    """Запускает AppBlockerGuard из той же папки, если его нет."""
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = (proc.info.get('name') or '').lower()
            exe  = (proc.info.get('exe')  or '').lower()
            if is_guard_process_name(name, exe):
                return False  # уже запущен
        except:
            pass

    if os.path.exists(GUARD_EXE):
        subprocess.Popen([GUARD_EXE], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
        return True
    log(f"⚠️ AppBlockerGuard.exe не найден: {GUARD_EXE}")
    return False


def exit_app():
    global monitoring_active, watch_active, APP_CLOSING, PERMANENT_LOCK

    password_input = custom_password_dialog(
        "Выход",
        "Введите пароль администратора для выхода:"
    )

    if not verify_admin_password(password_input):
        messagebox.showerror("Ошибка", "Неверный пароль! Выход запрещён.")
        return

    with EXIT_LOCK:
        if APP_CLOSING:
            return
        APP_CLOSING = True

    # Сразу после "with EXIT_LOCK:" и проверки APP_CLOSING
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                _d = json.load(f)
            _d["authenticated"] = False
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(_d, f, indent=2)
    except Exception:
        pass

    log("🚪 Начинаем процедуру выхода...")

    # ✅ ШАГ 1: ОСТАНАВЛИВАЕМ ПОТОКИ
    log("🛑 Останавливаем фоновые потоки...")
    monitoring_active = False
    watch_active = False
    PERMANENT_LOCK = False
    shutdown_event.set()
    time.sleep(1.5)
    log("✅ Потоки остановлены")

    # ✅ ШАГ 2: РАЗБЛОКИРУЕМ САЙТЫ (ДО УДАЛЕНИЯ CONFIG!)
    try:
        sites = load_blocked_sites()
        if sites:
            log(f"🧼 Удаляем {len(sites)} сайтов из hosts...")

            # Очищаем список в памяти
            save_blocked_sites([])

            # Применяем изменения в hosts (с повторами)
            for attempt in range(3):
                if apply_hosts_block([]):
                    log("✅ Все сайты разблокированы")
                    break
                else:
                    log(f"⚠️ Попытка {attempt + 1}/3 не удалась, повторяю...")
                    time.sleep(0.5)
            else:
                log("❌ Не удалось полностью очистить hosts после 3 попыток")
        else:
            log("ℹ️ Список заблокированных сайтов пуст")
    except Exception as e:
        log(f"⚠️ Ошибка при разблокировке сайтов: {e}")

    # ✅ ШАГ 3: Записываем EXIT
    try:
        create_exit_sentinel()
        clear_admin_password()
        save_config(status="EXIT")
        log("📝 EXIT записан в config.json")
    except Exception as e:
        log(f"⚠️ Ошибка при записи EXIT: {e}")

    # ✅ ШАГ 4: ЗАВЕРШАЕМ AppBlockerGuard
    log("🧨 Завершаем AppBlockerGuard...")
    for attempt in range(5):
        killed = False
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if is_guard_process_name(proc.info['name']):
                    try:
                        proc.kill()
                        log(f"🛑 AppBlockerGuard PID {proc.info['pid']} завершён")
                        killed = True
                    except psutil.AccessDenied:
                        proc.terminate()
                        killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if killed:
            time.sleep(0.3)
        else:
            break

    time.sleep(0.5)

    try:
        log("🧹 config.json сохранён, чтобы не терять настройки защиты")

        sentinel_path = os.path.join(base_dir(), "config.exit.lock")
        if os.path.exists(sentinel_path):
            os.chmod(sentinel_path, 0o666)
            os.remove(sentinel_path)
            log("🧹 config.exit.lock удалён")
    except Exception as e:
        log(f"⚠️ Ошибка при удалении файлов: {e}")


    # ✅ ШАГ 5: УДАЛЯЕМ ИЗ АВТОЗАГРУЗКИ
    log("🧹 Удаляем из автозагрузки...")
    removed_app = remove_from_startup_everywhere(APP_STARTUP_NAME, "AppBlocker.exe")
    removed_secure = remove_from_startup_everywhere(GUARD_STARTUP_NAME, GUARD_EXE_NAME)
    removed = removed_app or removed_secure
    log("✅ Автозагрузка очищена" if removed else "ℹ️ Записи не найдены")

    # ✅ ШАГ 7: ЗАКРЫВАЕМ ПРИЛОЖЕНИЕ
    log("👋 Завершение работы...")
    stop_tray_icon()
    root.after(1000, root.destroy)

def custom_password_dialog(title, message):
    dialog = ctk.CTkToplevel(root)
    dialog.title(title)
    dialog.geometry("520x280")
    dialog.resizable(False, False)
    dialog.configure(fg_color=APP_BG)
    dialog.grab_set()
    dialog.transient(root)
    set_window_icon(dialog)

    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - dialog.winfo_reqwidth()) // 2
    y = (dialog.winfo_screenheight() - dialog.winfo_reqheight()) // 2
    dialog.geometry(f"+{x}+{y}")

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
    panel.pack(fill="both", expand=True, padx=18, pady=18)

    title_label = ctk.CTkLabel(panel, text=title, font=(FONT_FAMILY, 20, "bold"), text_color=PRIMARY)
    title_label.pack(pady=(22, 8))

    label = ctk.CTkLabel(panel, text=message, font=(FONT_FAMILY, 14), text_color=TEXT_MAIN, wraplength=430, justify="center")
    label.pack(pady=(0, 16))

    entry = ctk.CTkEntry(panel, show="*", width=320, height=38)
    entry.pack(pady=4)
    entry.configure(
        fg_color=INPUT_BG,
        border_color=BORDER_COLOR,
        text_color=TEXT_MAIN,
        placeholder_text_color=TEXT_MUTED,
        font=(FONT_FAMILY, 14),
        corner_radius=BUTTON_RADIUS
    )
    entry.focus_set()

    result = {"password": None}

    def on_ok():
        result["password"] = entry.get()
        dialog.destroy()

    def on_cancel():
        result["password"] = None
        dialog.destroy()

    btn_frame = ctk.CTkFrame(panel, fg_color="transparent")
    btn_frame.pack(pady=22)

    ok_btn = ctk.CTkButton(btn_frame, text="✅ ОК", width=130, height=38, command=on_ok)
    ok_btn.pack(side="left", padx=10)
    ok_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 14, "bold"), corner_radius=BUTTON_RADIUS)

    cancel_btn = ctk.CTkButton(btn_frame, text="✕ Отмена", width=130, height=38, command=on_cancel)
    cancel_btn.pack(side="left", padx=10)
    cancel_btn.configure(fg_color=ERROR, hover_color=ERROR_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 14, "bold"), corner_radius=BUTTON_RADIUS)

    entry.bind("<Return>", lambda e: on_ok())
    entry.bind("<Escape>", lambda e: on_cancel())
    entry.bind("<<Paste>>", lambda event: paste_into_entry(entry))
    entry.bind("<Control-v>", lambda event: paste_into_entry(entry))
    entry.bind("<Control-V>", lambda event: paste_into_entry(entry))
    entry.bind("<Control-KeyPress>", handle_entry_ctrl_key)

    dialog.wait_window()
    return result["password"]

def custom_info_dialog(title, message):
    dialog = ctk.CTkToplevel(root)
    dialog.title(title)
    dialog.geometry("560x330")
    dialog.resizable(False, False)
    dialog.configure(fg_color=APP_BG)
    dialog.grab_set()
    dialog.transient(root)
    set_window_icon(dialog)

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
    panel.pack(fill="both", expand=True, padx=18, pady=18)
    ctk.CTkLabel(panel, text=title, font=(FONT_FAMILY, 20, "bold"), text_color=PRIMARY).pack(pady=(22, 10))
    ctk.CTkLabel(
        panel,
        text=message,
        font=(FONT_FAMILY, 14),
        text_color=TEXT_MAIN,
        wraplength=470,
        justify="left"
    ).pack(padx=30, pady=(0, 18), fill="x")
    ok_btn = ctk.CTkButton(panel, text="Продолжить", width=160, height=38, command=dialog.destroy)
    ok_btn.pack(pady=(0, 20))
    ok_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 14, "bold"), corner_radius=BUTTON_RADIUS)
    dialog.wait_window()

def refresh_process_list():
    for child in process_list_frame.winfo_children():
        child.destroy()

    processes = get_user_processes()
    if not processes:
        empty_label = ctk.CTkLabel(
            process_list_frame,
            text="Активных пользовательских процессов не найдено.",
            text_color=TEXT_MUTED,
            font=(FONT_FAMILY, 13)
        )
        empty_label.pack(anchor="w", padx=12, pady=12)
        return

    header = ctk.CTkLabel(
        process_list_frame,
        text=f"Найдено процессов: {len(processes)}",
        text_color=TEXT_MUTED,
        font=(FONT_FAMILY, 12, "bold")
    )
    header.pack(anchor="w", padx=12, pady=(10, 6))

    for name in processes:
        normalized_name = normalize_process_name(name)
        is_blocked = normalized_name in BLOCKED_PROGRAMS
        row = ctk.CTkFrame(process_list_frame, fg_color=ROW_BG, corner_radius=BUTTON_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
        row.pack(fill="x", padx=10, pady=4)

        name_label = ctk.CTkLabel(
            row,
            text=name,
            text_color=TEXT_MAIN,
            font=(MONO_FONT_FAMILY, 12),
            anchor="w"
        )
        name_label.pack(side="left", fill="x", expand=True, padx=12, pady=8)

        action_btn = ctk.CTkButton(
            row,
            text="Удалить" if is_blocked else "Добавить",
            width=92,
            height=30,
            command=lambda value=normalized_name: toggle_process_from_list(value)
        )
        action_btn.pack(side="right", padx=8, pady=6)
        if is_blocked:
            action_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 12, "bold"), corner_radius=BUTTON_RADIUS)
            if monitoring_active or PERMANENT_LOCK:
                action_btn.configure(text="Защищено", state="disabled", fg_color=DISABLED_BG, text_color=TEXT_MUTED)
        else:
            action_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 12, "bold"), corner_radius=BUTTON_RADIUS)

    log("🔄 Список процессов обновлён.")

def toggle_process_from_list(program):
    program = normalize_process_name(program)
    if not program:
        return
    if program in BLOCKED_PROGRAMS:
        if monitoring_active or PERMANENT_LOCK:
            log(f"🔒 {program} нельзя удалить после запуска блокировки.")
            refresh_process_list()
            return
        BLOCKED_PROGRAMS.remove(program)
        log(f"🗑️ {program} удалён из списка блокировки.")
    else:
        BLOCKED_PROGRAMS.append(program)
        log(f"✅ {program} добавлен в список блокировки.")
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list()
    refresh_process_list()

def remove_saved_blocked_program(program):
    program = normalize_process_name(program)
    if not program:
        return
    if monitoring_active or PERMANENT_LOCK:
        log(f"🔒 {program} нельзя удалить после запуска блокировки.")
        refresh_blocked_programs_list()
        return
    if program not in BLOCKED_PROGRAMS:
        refresh_blocked_programs_list()
        return
    BLOCKED_PROGRAMS.remove(program)
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list()
    refresh_process_list()
    log(f"🗑️ {program} удалён из списка блокировки.")

def refresh_blocked_programs_list():
    for child in blocked_programs_box.winfo_children():
        child.destroy()
    if BLOCKED_PROGRAMS:
        for program in BLOCKED_PROGRAMS:
            status = "запущена" if is_blocked_program_running(program) else "не запущена"
            marker = "●" if status == "запущена" else "○"
            row = ctk.CTkFrame(
                blocked_programs_box,
                fg_color=ROW_BG,
                corner_radius=BUTTON_RADIUS,
                border_width=BORDER_WIDTH,
                border_color=BORDER_COLOR
            )
            row.pack(fill="x", padx=8, pady=5)

            label = ctk.CTkLabel(
                row,
                text=f"{marker} {program} - {status}",
                font=(MONO_FONT_FAMILY, 12),
                text_color=TEXT_MAIN,
                anchor="w"
            )
            label.pack(side="left", fill="x", expand=True, padx=(12, 8), pady=9)

            can_delete = not (monitoring_active or PERMANENT_LOCK)
            delete_btn = ctk.CTkButton(
                row,
                text="Удалить" if can_delete else "Защищено",
                width=92,
                height=30,
                command=lambda p=program: remove_saved_blocked_program(p)
            )
            delete_btn.pack(side="right", padx=8, pady=7)
            delete_btn.configure(
                fg_color=ERROR if can_delete else DISABLED_BG,
                hover_color=ERROR_HOVER if can_delete else DISABLED_BG,
                text_color=TEXT_MAIN if can_delete else TEXT_MUTED,
                font=(FONT_FAMILY, 12, "bold"),
                corner_radius=BUTTON_RADIUS,
                state="normal" if can_delete else "disabled"
            )
    else:
        empty_label = ctk.CTkLabel(
            blocked_programs_box,
            text="Список пуст. Добавьте программы перед запуском.",
            font=(FONT_FAMILY, 13),
            text_color=TEXT_MUTED,
            anchor="w"
        )
        empty_label.pack(fill="x", padx=12, pady=12)
    update_status_cards()

def update_status_cards():
    try:
        programs_status_value.configure(text=f"{len(BLOCKED_PROGRAMS)} в списке")
        monitor_status_value.configure(
            text="Активен" if monitoring_active else "Ожидает",
            text_color=PRIMARY if monitoring_active else TEXT_MAIN
        )
        secure_status_value.configure(
            text="Активна" if SECURE_ENABLED else "Выкл.",
            text_color=PRIMARY if SECURE_ENABLED else TEXT_MUTED
        )
    except NameError:
        pass

def add_blocked_program(silent=False):
    program = normalize_process_name(entry_process.get())
    if not program:
        if not silent:
            log("⚠️ Введите название программы для блокировки.")
        return
    if program in BLOCKED_PROGRAMS:
        if not silent:
            log(f"ℹ️ {program} уже есть в списке блокировки.")
        return
    BLOCKED_PROGRAMS.append(program)
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list()
    refresh_process_list()
    entry_process.delete(0, "end")
    if not silent:
        log(f"✅ Программа {program} добавлена в список блокировки.")

def remove_blocked_program():
    program = normalize_process_name(entry_process.get())
    if not program:
        log("⚠️ Введите название программы для удаления из списка.")
        return
    if program not in BLOCKED_PROGRAMS:
        log(f"ℹ️ {program} не найдена в списке блокировки.")
        return
    BLOCKED_PROGRAMS.remove(program)
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list()
    refresh_process_list()
    entry_process.delete(0, "end")
    log(f"🗑️ Программа {program} удалена из списка блокировки.")

def show_frame(frame):
    """Переключение между разделами интерфейса"""
    # Скрываем все фреймы
    button_start.pack_forget()
    frame_logs.pack_forget()
    about_frame.pack_forget()
    settings_frame.pack_forget()
    sites_frame.pack_forget()  # ✅ Добавлено!

    # Показываем нужный фрейм
    if frame == "monitor":
        button_start.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        frame_logs.pack(side="right", fill="y")
    elif frame == "about":
        about_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
    elif frame == "settings":
        settings_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
    elif frame == "sites":
        sites_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        refresh_sites_list()  # ✅ Обновляем список сайтов при открытии

    try:
        update_nav_state(frame)
    except NameError:
        pass

# ----------------- Интерфейс -----------------
if not ensure_single_instance():
    sys.exit(0)

root = ctk.CTk()
root.title("App Blocker")
root.geometry("1220x720")
set_window_icon(root)
root.resizable(True, True)
root.configure(fg_color=APP_BG)
install_background_image(root)

# Верхний фрейм с вводом и кнопками
frame_input = ctk.CTkFrame(root, fg_color=TOPBAR_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
frame_input.pack(padx=16, pady=(14, 6), fill='x')

label_process = ctk.CTkLabel(frame_input, text="Название процесса:")
label_process.pack(side="left", padx=5)
label_process.configure(text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"))

entry_process = ctk.CTkEntry(frame_input, width=220, placeholder_text="chrome.exe")
entry_process.pack(side="left", padx=5, fill="x", expand=True)
entry_process.configure(fg_color=INPUT_BG, border_color=BORDER_COLOR, text_color=TEXT_MAIN, placeholder_text_color=TEXT_MUTED, font=(FONT_FAMILY, 14), corner_radius=BUTTON_RADIUS)
entry_process.bind("<<Paste>>", lambda event: paste_into_entry(entry_process))
entry_process.bind("<Control-v>", lambda event: paste_into_entry(entry_process))
entry_process.bind("<Control-V>", lambda event: paste_into_entry(entry_process))
entry_process.bind("<Control-KeyPress>", handle_entry_ctrl_key)

# Левая панель навигации
nav_frame = ctk.CTkFrame(root, width=188, corner_radius=CARD_RADIUS, fg_color=SIDEBAR_BG, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
nav_frame.pack(side="left", fill="y", padx=(16, 6), pady=(8, 16))
nav_frame.pack_propagate(False)

# Центральная панель
button_start = ctk.CTkFrame(root, fg_color="transparent")
button_start.pack(side="left", fill="both", expand=True, padx=12, pady=16)

status_cards_frame = ctk.CTkFrame(button_start, fg_color="transparent")
status_cards_frame.pack(fill="x", pady=(0, 14))

programs_status_card = ctk.CTkFrame(status_cards_frame, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
programs_status_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
ctk.CTkLabel(programs_status_card, text="Программы", text_color=TEXT_MUTED, font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=18, pady=(14, 0))
programs_status_value = ctk.CTkLabel(programs_status_card, text="0 в списке", text_color=PRIMARY, font=(FONT_FAMILY, 21, "bold"))
programs_status_value.pack(anchor="w", padx=18, pady=(4, 14))

monitor_status_card = ctk.CTkFrame(status_cards_frame, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
monitor_status_card.pack(side="left", fill="both", expand=True, padx=8)
ctk.CTkLabel(monitor_status_card, text="Мониторинг", text_color=TEXT_MUTED, font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=18, pady=(14, 0))
monitor_status_value = ctk.CTkLabel(monitor_status_card, text="Ожидает", text_color=TEXT_MAIN, font=(FONT_FAMILY, 21, "bold"))
monitor_status_value.pack(anchor="w", padx=18, pady=(4, 14))

secure_status_card = ctk.CTkFrame(status_cards_frame, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
secure_status_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
ctk.CTkLabel(secure_status_card, text="Защита", text_color=TEXT_MUTED, font=(FONT_FAMILY, 12, "bold")).pack(anchor="w", padx=18, pady=(14, 0))
secure_status_value = ctk.CTkLabel(secure_status_card, text="Активна", text_color=PRIMARY, font=(FONT_FAMILY, 21, "bold"))
secure_status_value.pack(anchor="w", padx=18, pady=(4, 14))

button_refresh = ctk.CTkButton(frame_input, text="Обновить процессы", command=refresh_process_list)
button_refresh.pack(side="left", padx=5)
button_refresh.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

add_program_btn = ctk.CTkButton(frame_input, text="Добавить", width=100, command=add_blocked_program)
add_program_btn.pack(side="left", padx=5)
add_program_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

remove_program_btn = ctk.CTkButton(frame_input, text="Удалить", width=100, command=remove_blocked_program)
remove_program_btn.pack(side="left", padx=5)
remove_program_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

big_start_btn = ctk.CTkButton(button_start, text="🚀 Начать блокировку программ", width=300, height=50, command=start_monitoring)
big_start_btn.pack(pady=(0, 18))
big_start_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 16, "bold"), corner_radius=BUTTON_RADIUS)

ctk.CTkLabel(button_start, text="Заблокированные программы", font=(FONT_FAMILY, 15, "bold"), text_color=TEXT_MAIN).pack(pady=(0, 5))
blocked_programs_box = ctk.CTkScrollableFrame(
    button_start,
    height=120,
    width=400,
    fg_color=INPUT_BG,
    border_color=BORDER_COLOR,
    border_width=BORDER_WIDTH,
    corner_radius=CARD_RADIUS
)
blocked_programs_box.pack(pady=(0, 10), fill="x")

ctk.CTkLabel(button_start, text="Активные процессы", font=(FONT_FAMILY, 15, "bold"), text_color=TEXT_MAIN).pack(pady=(5, 0))
process_list_frame = ctk.CTkScrollableFrame(
    button_start,
    height=300,
    width=400,
    fg_color=INPUT_BG,
    border_color=BORDER_COLOR,
    border_width=BORDER_WIDTH,
    corner_radius=CARD_RADIUS
)
process_list_frame.pack(pady=10, fill="both", expand=True)

# Левая панель навигации (добавь после создания nav_frame)
ctk.CTkLabel(nav_frame, text="APP BLOCKER", font=(FONT_FAMILY, 16, "bold"), text_color=PRIMARY).pack(pady=(22, 18))
nav_monitor_btn = ctk.CTkButton(nav_frame, text="Мониторинг", width=155, height=42, command=lambda: show_frame("monitor"))
nav_monitor_btn.pack(pady=8)
nav_sites_btn = ctk.CTkButton(nav_frame, text="🌐 Сайты", width=155, height=42, command=lambda: show_frame("sites"))
nav_sites_btn.pack(pady=8)
nav_settings_btn = ctk.CTkButton(nav_frame, text="Настройки", width=155, height=42, command=lambda: show_frame("settings"))
nav_settings_btn.pack(pady=8)
nav_about_btn = ctk.CTkButton(nav_frame, text="О программе", width=155, height=42, command=lambda: show_frame("about"))
nav_about_btn.pack(pady=8)
for nav_btn in (nav_monitor_btn, nav_sites_btn, nav_settings_btn, nav_about_btn):
    nav_btn.configure(fg_color="transparent", hover_color=CARD_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 14, "bold"), corner_radius=BUTTON_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)

NAV_BUTTONS = {
    "monitor": nav_monitor_btn,
    "sites": nav_sites_btn,
    "settings": nav_settings_btn,
    "about": nav_about_btn,
}

def update_nav_state(active_frame):
    for frame_name, nav_btn in NAV_BUTTONS.items():
        is_active = frame_name == active_frame
        nav_btn.configure(
            fg_color=PRIMARY if is_active else "transparent",
            hover_color=SECONDARY_HOVER if is_active else CARD_HOVER,
            border_color=ACCENT if is_active else BORDER_COLOR,
            text_color=TEXT_MAIN if is_active else TEXT_MUTED,
        )

button_exit = ctk.CTkButton(
    frame_input,
    text="Выйти",
    command=exit_app,
    fg_color=ERROR,
    hover_color=ERROR_HOVER,
    text_color="white"
)
button_exit.pack(side="left", padx=5)
button_exit.configure(font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

# Фрейм под логи
frame_logs = ctk.CTkFrame(root, width=360)
frame_logs.pack(side="right", fill="y")
frame_logs.configure(fg_color=PANEL_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
frame_logs.pack_propagate(False)

ctk.CTkLabel(frame_logs, text="Логи", font=(FONT_FAMILY, 18, "bold"), text_color=TEXT_MAIN).pack(pady=18)
clear_logs_btn = ctk.CTkButton(frame_logs, text="Очистить", width=120, command=clear_logs)
clear_logs_btn.pack(pady=(0, 8))
clear_logs_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)
text_log = ctk.CTkTextbox(frame_logs, width=330, height=500)
text_log.pack(padx=10, pady=(0, 10), fill="both", expand=True)
insert_textbox_with_emoji(text_log, "🛡 Готов к блокировке...")
#невозможность редачить логи
text_log.configure(state="disabled")
text_log.configure(fg_color=INPUT_BG, border_color=BORDER_COLOR, border_width=BORDER_WIDTH, text_color=TEXT_MAIN, font=(MONO_FONT_FAMILY, 12), corner_radius=CARD_RADIUS)

# ================== О ПРОГРАММЕ ==================
about_frame = ctk.CTkFrame(root, fg_color="transparent")
about_frame.pack_forget()  # скрыт по умолчанию

ctk.CTkLabel(about_frame, text="О программе", font=(FONT_FAMILY, 20, "bold"), text_color=TEXT_MAIN).pack(pady=18)

about_text = ctk.CTkTextbox(about_frame, width=600, height=500)
about_text.pack(padx=20, pady=10, fill="both", expand=True)
about_text.configure(fg_color=CARD_BG, border_color=BORDER_COLOR, border_width=BORDER_WIDTH, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13), corner_radius=CARD_RADIUS)

about_text.insert("end", "🛡 App Blocker — инструмент для блокировки процессов.\n")
about_text.insert("end", "\n\n📌 Версия: 2.0.0")
about_text.insert("end", "\n👨‍💻 Разработчик: smics_play 🧍 | 🤝 Помощь: ChatGPT 5 🤖, Claude AI 🤖")
about_text.insert("end", "\n\n📝 Описание:\n🧱 App Blocker — система блокировки процессов с защитой от завершения.\n\n"
                          "App Blocker — это простой, но очень защищённый инструмент для мониторинга и блокировки выбранных приложений.\n"
                          "Он автоматически завершает процессы, которые не должны запускаться (например: браузеры, игры и т.д.), и защищает сам себя от закрытия.\n\n"
                          "📌 Подходит для:\n"
                          "• Контроля рабочего времени сотрудников в офисе.\n"
                          "• Ограничения доступа к развлекательным программам в школах.\n"
                          "• Установки ограничений на личных ПК.\n\n"
                          "⚡ Новые функции 2.2.0 (releas):\n"
                          "🔐 Пароль на выход — закрыть App Blocker можно только по паролю.\n"
                          "🛡 AppBlockerGuard.exe — защита от завершения.\n"
                          "♻️ Автовосстановление — процессы AppBlocker и AppBlockerGuard поднимают друг друга.\n"
                          "🧠 EXIT через config.json — корректное завершение с записью статуса.\n"
                          "💾 Сохранение пароля и процесса — повторный ввод не требуется.\n"
                          "🧹 Очистка после выхода — AppBlockerGuard удаляет config.json.\n"
                          "🧾 Готовые exe-файлы — не нужен Python.\n\n"
                          "🧰 Основные функции:\n"
                          "📡 Мониторинг выбранного процесса в реальном времени.\n"
                          "🛑 Автоматическое завершение запрещённых приложений.\n"
                          "🔍 Просмотр активных не системных процессов.\n"
                          "🔄 Ручное обновление списка процессов.\n"
                          "⏳ Таймер\n"
                          "🖥 Современный интерфейс с логами событий.\n\n"
                          "🧭 Использование:\n"
                          "🔑 Установи пароль администратора при первом запуске.\n"
                          "🧱 Укажи процесс, который нужно блокировать (например chrome.exe).\n"
                          "🕵️‍♂️ Нажми «Начать» — процесс будет автоматически завершаться при запуске.\n"
                          "🚫 Завершить App Blocker можно только по паролю.\n\n"
                          "⚠️ Примечание:\n"
                          "Инструмент создан для образовательных и офисных целей.\n"
                          "Автор не несёт ответственности за использование программы в злоумышленных целях.\n"
                          "Используйте ответственно и не нарушайте права пользователей ⚖️\n\n"
                          "✨ Раздел 'О программе' обновляется с новыми версиями! \n\n"
                          "Программа полностью бесплатная, кто может поддержите пожалуйста автора:\n USDT Trc 20 - TSyWGrCkn12LojGEK9urQmWr9ojPimzgBw \n Solana ErQZHWvNHnWQrX2HXbAULTn46uBFkao6aPfarFjKsHva \n Btc bc1qg2a9tnykvdw6sh57hre3mzst8pz3ga5xc7xtye")
about_text.delete("0.0", "end")
about_text.insert("end", """APP BLOCKER
Версия: 2.5.0 Beta

App Blocker — это инструмент для ограничения запуска выбранных программ и сайтов на Windows.
Приложение отслеживает список заблокированных процессов, автоматически завершает их при запуске и позволяет блокировать сайты через системный файл hosts.

Что есть в версии 2.5.0 Beta:

* Новый фиолетово-розовый интерфейс в стиле современного desktop-приложения.
* Фоновое изображение с мягкими абстрактными переливами.
* Блокировка нескольких программ одновременно.
* Удобный список активных процессов с кнопками добавления.
* Отдельный список заблокированных программ на главном экране.
* Мониторинг активных процессов в реальном времени.
* Защита от закрытия через AppBlockerGuard.
* Защита по умолчанию выключена и включается вручную в настройках.
* Предупреждение перед включением защиты.
* Подсказки по добавлению папки программы в исключения антивируса.
* Кнопки для копирования пути программы, открытия инструкции и проверки исключений Windows Defender.
* Автовосстановление мониторинга после перезапуска.
* Автозапуск через планировщик задач и реестр Windows.
* Блокировка сайтов через hosts.
* Расширенная блокировка YouTube и связанных доменов.
* Автоматическое закрытие браузеров для быстрого применения блокировки сайтов.
* Таймер работы и режим постоянной блокировки.
* Логи в интерфейсе и отдельный файл логов.
* Трей-иконка для скрытия приложения.
* Импорт и экспорт настроек.
* Диагностика защиты и автозапуска.
* Пароль администратора хранится в виде хеша.
* Исправлена проблема с кодировкой текста.
* Улучшена работа с emoji в логах.
* Исправлена вставка Ctrl+V в поля ввода.
* Исправлены ошибки запуска при отсутствии некоторых файлов рядом с exe.

Как пользоваться:

Программы:

1. Добавьте процессы вручную или кнопкой рядом с активным процессом.
2. Нажмите “Начать блокировку программ”.

Сайты:

1. Откройте вкладку “Сайты”.
2. Добавьте домены.
3. Нажмите “Включить”.

Защита:

1. Откройте вкладку “Настройки”.
2. Включите “Защиту от завершения”.
3. При необходимости добавьте папку App Blocker в исключения антивируса.
4. Используйте кнопки “Скопировать путь”, “Открыть инструкцию” или “Проверить исключение”.

Программы и сайты работают независимо. Можно блокировать только сайты, только программы или оба режима вместе.

Beta-предупреждение:

Версия 2.5.0 Beta находится в активной разработке. Возможны баги в интерфейсе, автозапуске, работе защиты, блокировке сайтов или сборке exe. Перед использованием в важных задачах проверьте настройки на своём ПК и убедитесь, что пароль выхода сохранён.

Разработчик: smics_play
Помощь в разработке: ChatGPT и Claude AI

Используйте программу ответственно и только на компьютерах, где у вас есть право на такие ограничения.
""")
about_text.configure(state="disabled")

# ================== БЛОКИРОВКА САЙТОВ ==================
sites_frame = ctk.CTkFrame(root, fg_color="transparent")
sites_frame.pack_forget()

ctk.CTkLabel(sites_frame, text="Блокировка сайтов", font=(FONT_FAMILY, 20, "bold"), text_color=TEXT_MAIN).pack(pady=18)

sites_status_label = ctk.CTkLabel(sites_frame, text="0 сайтов в блокировке", font=(FONT_FAMILY, 15, "bold"), text_color=TEXT_MUTED)
sites_status_label.pack(pady=(0, 8))

sites_listbox = ctk.CTkTextbox(sites_frame, width=500, height=300)
sites_listbox.pack(pady=10)
sites_listbox.configure(state="disabled")
sites_listbox.configure(fg_color=CARD_BG, border_color=BORDER_COLOR, border_width=BORDER_WIDTH, text_color=TEXT_MAIN, font=(MONO_FONT_FAMILY, 12), corner_radius=CARD_RADIUS)

site_entry = ctk.CTkEntry(sites_frame, width=420, placeholder_text="youtube.com, vk.com или https://example.com/page")
site_entry.pack(pady=5)
site_entry.configure(fg_color=INPUT_BG, border_color=BORDER_COLOR, text_color=TEXT_MAIN, placeholder_text_color=TEXT_MUTED, font=(FONT_FAMILY, 14), corner_radius=BUTTON_RADIUS)
site_entry.bind("<<Paste>>", lambda event: paste_into_entry(site_entry))
site_entry.bind("<Control-v>", lambda event: paste_into_entry(site_entry))
site_entry.bind("<Control-V>", lambda event: paste_into_entry(site_entry))
site_entry.bind("<Control-KeyPress>", handle_entry_ctrl_key)

def refresh_sites_list():
    sites = load_blocked_sites()
    sites_listbox.configure(state="normal")
    sites_listbox.delete("0.0", "end")
    if sites:
        for s in sites:
            sites_listbox.insert("end", f"{s}\n")
    else:
        sites_listbox.insert("end", "Список пуст. Можно добавить несколько сайтов через пробел, запятую или с новой строки.")
    sites_listbox.configure(state="disabled")
    sites_status_label.configure(text=f"{len(sites)} сайтов в блокировке")

def add_site():
    new_sites = parse_sites_input(site_entry.get())
    if not new_sites:
        log("⚠️ Введите домен сайта: youtube.com, vk.com, example.org")
        return
    sites = load_blocked_sites()
    target_sites = normalize_sites(sites + new_sites)
    added = [site for site in new_sites if site not in sites]
    if added:
        save_blocked_sites(target_sites)
        site_entry.delete(0, "end")
        refresh_sites_list()
        log(f"✅ Добавлено сайтов в список: {len(added)}. Нажмите «Включить», чтобы применить блокировку.")
    else:
        log("ℹ️ Эти сайты уже есть в блокировке.")

def apply_sites_from_config():
    sites = load_blocked_sites()
    if apply_hosts_block(sites):
        refresh_sites_list()
        log("✅ Список сайтов применён повторно.")

def start_site_blocking():
    global watch_active
    typed_sites = parse_sites_input(site_entry.get())
    sites = normalize_sites(load_blocked_sites() + typed_sites)
    if not sites:
        log("❗ Добавьте хотя бы один сайт перед запуском блокировки сайтов.")
        return

    if typed_sites:
        save_blocked_sites(sites)
        site_entry.delete(0, "end")

    if not apply_hosts_block(sites):
        return
    restart_browsers_for_site_block()

    save_config(status="RUNNING")
    ensure_app_startup_entries()

    if SECURE_ENABLED and ensure_appblocker_guard():
        log("🛡 AppBlockerGuard активирован для блокировки сайтов")

    if SECURE_ENABLED and not watch_active:
        watch_active = True
        threading.Thread(target=watch_appblocker_guard, daemon=True).start()
        log("👁️ Мониторинг AppBlockerGuard запущен для сайтов")

    refresh_sites_list()
    update_status_cards()
    log(f"🌐 Блокировка сайтов включена отдельно: {len(sites)}")

def remove_site():
    remove_sites = parse_sites_input(site_entry.get())
    if not remove_sites:
        log("⚠️ Введите сайт для удаления.")
        return
    sites = load_blocked_sites()
    target_sites = [site for site in sites if site not in remove_sites]
    removed = [site for site in remove_sites if site in sites]
    if removed:
        if apply_hosts_block(target_sites):
            save_blocked_sites(target_sites)
            site_entry.delete(0, "end")
            refresh_sites_list()
            log(f"🗑️ Удалено сайтов: {len(removed)}")
    else:
        log("ℹ️ Таких сайтов нет в списке блокировки.")

def clear_all_sites():
    if apply_hosts_block([]):
        save_blocked_sites([])
        refresh_sites_list()
        site_entry.delete(0, "end")
        log("🧹 Все сайты удалены из блокировки.")

btn_frame = ctk.CTkFrame(sites_frame, fg_color="transparent")
btn_frame.pack(pady=10)

add_btn = ctk.CTkButton(btn_frame, text="➕ Добавить", width=120, command=add_site)
add_btn.pack(side="left", padx=5)
add_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

remove_btn = ctk.CTkButton(btn_frame, text="❌ Удалить", width=120, command=remove_site)
remove_btn.pack(side="left", padx=5)
remove_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

apply_sites_btn = ctk.CTkButton(btn_frame, text="🌐 Включить", width=120, command=start_site_blocking)
apply_sites_btn.pack(side="left", padx=5)
apply_sites_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

clear_sites_btn = ctk.CTkButton(btn_frame, text="🧹 Очистить всё", width=130, command=clear_all_sites)
clear_sites_btn.pack(side="left", padx=5)
clear_sites_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

# ================== НАСТРОЙКИ ==================
settings_frame = ctk.CTkFrame(root, fg_color="transparent")
settings_frame.pack_forget()

ctk.CTkLabel(settings_frame, text="Настройки", font=(FONT_FAMILY, 20, "bold"), text_color=TEXT_MAIN).pack(pady=18)
settings_content = ctk.CTkScrollableFrame(settings_frame, fg_color="transparent")
settings_content.pack(fill="both", expand=True, padx=30, pady=(0, 20))

# Состояние защиты
def make_status_row(parent, label_text):
    row = ctk.CTkFrame(parent, fg_color="transparent")
    row.pack(fill="x", padx=22, pady=3)
    ctk.CTkLabel(row, text=label_text, font=(FONT_FAMILY, 13, "bold"), text_color=TEXT_MAIN).pack(side="left")
    value = ctk.CTkLabel(row, text="Проверяется...", font=(FONT_FAMILY, 13), text_color=TEXT_MUTED)
    value.pack(side="right")
    return value

startup_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
startup_card.pack(fill="x", pady=(0, 18))
ctk.CTkLabel(startup_card, text="Состояние защиты", font=(FONT_FAMILY, 16, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=22, pady=(18, 8))
app_startup_status = make_status_row(startup_card, "Автозапуск AppBlocker")
secure_startup_status = make_status_row(startup_card, "Автозапуск AppBlockerGuard")
secure_file_status = make_status_row(startup_card, "Файл AppBlockerGuard.exe")
diagnostics_btn = ctk.CTkButton(startup_card, text="Проверить защиту", width=180, command=run_diagnostics)
diagnostics_btn.pack(anchor="w", padx=22, pady=(12, 18))
diagnostics_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

# Конфигурация
config_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
config_card.pack(fill="x", pady=(0, 18))
ctk.CTkLabel(config_card, text="Конфигурация", font=(FONT_FAMILY, 16, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=22, pady=(18, 4))
config_description = ctk.CTkLabel(
    config_card,
    text=f"Настройки можно экспортировать в JSON. Логи пишутся в: {LOG_PATH}",
    font=(FONT_FAMILY, 12),
    text_color=TEXT_MUTED,
    wraplength=620,
    justify="left"
)
config_description.pack(anchor="w", padx=22, pady=(0, 12))
config_buttons = ctk.CTkFrame(config_card, fg_color="transparent")
config_buttons.pack(anchor="w", padx=22, pady=(0, 18))
export_config_btn = ctk.CTkButton(config_buttons, text="Экспорт", width=120, command=export_config)
export_config_btn.pack(side="left", padx=(0, 8))
export_config_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)
import_config_btn = ctk.CTkButton(config_buttons, text="Импорт", width=120, command=import_config)
import_config_btn.pack(side="left", padx=8)
import_config_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

# Блокировка процессов
def set_match_mode(value):
    global MATCH_MODE
    MATCH_MODE = "exact" if value == "Точное имя" else "contains"
    save_config()
    refresh_blocked_programs_list()
    log(f"🎯 Режим совпадения процессов: {value}")

match_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
match_card.pack(fill="x", pady=(0, 18))
ctk.CTkLabel(match_card, text="Блокировка процессов", font=(FONT_FAMILY, 16, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=22, pady=(18, 4))
ctk.CTkLabel(
    match_card,
    text="Точное имя закрывает только полное совпадение вроде steam.exe. Режим «Содержит» ловит похожие процессы и помощники.",
    font=(FONT_FAMILY, 12),
    text_color=TEXT_MUTED,
    wraplength=620,
    justify="left"
).pack(anchor="w", padx=22, pady=(0, 12))
match_mode_selector = ctk.CTkSegmentedButton(match_card, values=["Содержит", "Точное имя"], command=set_match_mode)
match_mode_selector.pack(anchor="w", padx=22, pady=(0, 18))
match_mode_selector.set("Точное имя" if MATCH_MODE == "exact" else "Содержит")

# Таймер
def toggle_timer_mode():
    global TIMER_ENABLED
    TIMER_ENABLED = timer_switch.get() == 1
    if TIMER_ENABLED:
        timer_frame.pack(pady=5)
    else:
        timer_frame.pack_forget()
    save_config()
    state = "включён ⏳" if TIMER_ENABLED else "отключён ❌"
    log(f"⏳ Таймер {state}")

def parse_timer_end_time(value):
    value = value.strip()
    if not re.fullmatch(r"\d{1,2}:\d{2}", value):
        raise ValueError
    hour_text, minute_text = value.split(":")
    hour = int(hour_text)
    minute = int(minute_text)
    if hour > 23 or minute > 59:
        raise ValueError

    now = datetime.datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return target

def set_timer():
    global TIMER_END, timer_thread

    if not timer_entry.get().strip():
        log("⚠️ Введите время окончания в формате HH:MM")
        return

    try:
        TIMER_END = parse_timer_end_time(timer_entry.get())
        save_config()
        log(f"⏳ Таймер установлен до {TIMER_END.strftime('%H:%M')}")

        # 🚀 Если таймер включен — запускаем поток проверки
        if TIMER_ENABLED:
            if timer_thread is None or not timer_thread.is_alive():
                timer_thread = threading.Thread(target=check_timer, daemon=True)
                timer_thread.start()
                log("🕒 Таймер запущен")
                # ⛔ Блокируем возможность менять таймер
                timer_switch.configure(state="disabled")
                timer_entry.configure(state="disabled")
                for widget in timer_frame.winfo_children():
                    widget.configure(state="disabled")

    except ValueError:
        log("⚠️ Введите корректное время в формате HH:MM, например 23:30")

timer_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
timer_card.pack(fill="x", pady=(0, 18))
ctk.CTkLabel(timer_card, text="Таймер завершения", font=(FONT_FAMILY, 16, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=22, pady=(18, 4))
timer_switch = ctk.CTkSwitch(
    timer_card,
    text="Ограничение по времени",
    command=toggle_timer_mode
)
timer_switch.pack(anchor="w", padx=22, pady=(8, 6))
timer_switch.configure(progress_color=PRIMARY, button_color=PRIMARY, button_hover_color=PRIMARY_HOVER, text_color=TEXT_MAIN)

timer_description = ctk.CTkLabel(
    timer_card,
    text="Укажите точное время окончания блокировки в формате HH:MM. Если время уже прошло, таймер сработает завтра.",
    font=(FONT_FAMILY, 12),
    text_color=TEXT_MUTED,
    wraplength=620,
    justify="left"
)
timer_description.pack(anchor="w", padx=22, pady=(0, 12))


timer_frame = ctk.CTkFrame(timer_card, fg_color="transparent")
ctk.CTkLabel(timer_frame, text="Время окончания:", text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold")).pack(side="left", padx=5)
timer_entry = ctk.CTkEntry(timer_frame, width=110, placeholder_text="23:30")
timer_entry.pack(side="left", padx=5)
timer_entry.configure(fg_color=INPUT_BG, border_color=BORDER_COLOR, text_color=TEXT_MAIN, placeholder_text_color=TEXT_MUTED, font=(FONT_FAMILY, 14), corner_radius=BUTTON_RADIUS)
timer_set_btn = ctk.CTkButton(timer_frame, text="✅ Установить", command=set_timer)
timer_set_btn.pack(side="left", padx=5)
timer_set_btn.configure(fg_color=PRIMARY, hover_color=SECONDARY_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

# по умолчанию скрыт
if not TIMER_ENABLED:
    timer_frame.pack_forget()
else:
    timer_switch.select()
    timer_frame.pack(pady=5)

secure_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=CARD_RADIUS, border_width=BORDER_WIDTH, border_color=BORDER_COLOR)
secure_card.pack(fill="x")
ctk.CTkLabel(secure_card, text="Системная защита", font=(FONT_FAMILY, 16, "bold"), text_color=TEXT_MAIN).pack(anchor="w", padx=22, pady=(18, 4))
secure_switch = ctk.CTkSwitch(
    secure_card,
    text="Защита от завершения",
    command=toggle_secure_mode
)
secure_switch.pack(anchor="w", padx=22, pady=(8, 6))
secure_switch.configure(progress_color=PRIMARY, button_color=PRIMARY, button_hover_color=PRIMARY_HOVER, text_color=TEXT_MAIN)

secure_state_label = ctk.CTkLabel(
    secure_card,
    text="",
    font=(FONT_FAMILY, 13, "bold"),
    text_color=TEXT_MUTED
)
secure_state_label.pack(anchor="w", padx=22, pady=(0, 6))

secure_description = ctk.CTkLabel(
    secure_card,
    text="Использует SecureSystem и автозапуск. Для стабильной работы может потребоваться исключение антивируса.",
    font=(FONT_FAMILY, 12),
    text_color=TEXT_MUTED,
    wraplength=620,
    justify="left"
)
secure_description.pack(anchor="w", padx=22, pady=(0, 12))

secure_tools_row = ctk.CTkFrame(secure_card, fg_color="transparent")
secure_tools_row.pack(anchor="w", padx=22, pady=(0, 18))

antivirus_guide_btn = ctk.CTkButton(
    secure_tools_row,
    text="Инструкция",
    width=135,
    height=36,
    command=open_antivirus_guide
)
antivirus_guide_btn.pack(side="left", padx=(0, 8))
antivirus_guide_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

copy_app_path_btn = ctk.CTkButton(
    secure_tools_row,
    text="Скопировать путь",
    width=165,
    height=36,
    command=copy_app_folder_path
)
copy_app_path_btn.pack(side="left", padx=8)
copy_app_path_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

check_defender_btn = ctk.CTkButton(
    secure_tools_row,
    text="Проверить исключение",
    width=190,
    height=36,
    command=check_antivirus_exception
)
check_defender_btn.pack(side="left", padx=8)
check_defender_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

open_exclusions_settings_btn = ctk.CTkButton(
    secure_tools_row,
    text="Открыть исключения",
    width=175,
    height=36,
    command=open_defender_exclusions_settings
)
open_exclusions_settings_btn.pack(side="left", padx=8)
open_exclusions_settings_btn.configure(fg_color=SECONDARY_BG, hover_color=SECONDARY_BG_HOVER, text_color=TEXT_MAIN, font=(FONT_FAMILY, 13, "bold"), corner_radius=BUTTON_RADIUS)

root.protocol("WM_DELETE_WINDOW", on_close)
start_tray_icon()

# Запуск GUI
log("Введите название процесса и нажмите 'Начать'.")
root.after(450, refresh_process_list)

# ----------------- АВТО ЗАПУСК -----------------
startup_status = load_config()
launched_by_guard = "--guard-restart" in sys.argv
refresh_blocked_programs_list()
update_startup_status_labels()
try:
    match_mode_selector.set("Точное имя" if MATCH_MODE == "exact" else "Содержит")
except NameError:
    pass
startup_sites = load_blocked_sites()
guard_recovery_active = launched_by_guard and SECURE_ENABLED
should_restore_monitoring = bool(BLOCKED_PROGRAMS) and (
    startup_status == "RUNNING" or guard_recovery_active or PERMANENT_LOCK
)
should_restore_sites = bool(startup_sites) and (
    startup_status == "RUNNING" or guard_recovery_active
)


if PERMANENT_LOCK:
    secure_switch.configure(state="disabled")
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    remove_btn.configure(state="disabled")
    add_program_btn.configure(state="disabled")
    remove_program_btn.configure(state="disabled")
    for widget in timer_frame.winfo_children():
        widget.configure(state="disabled")
    log("🔐 Перманентная блокировка активна — переключатели навсегда заблокированы.")

# Синхронизация UI с конфигом
sync_secure_switch_ui()

if TIMER_ENABLED and TIMER_END and datetime.datetime.now() < TIMER_END:
    timer_switch.select()
    timer_frame.pack(pady=5)
    log(f"⏳ Таймер активен до {TIMER_END.strftime('%H:%M:%S')}")
else:
    # ✅ НЕ ТРОГАЕМ СОСТОЯНИЕ ТУМБЛЕРА ЕСЛИ БЫЛА ПЕРМАНЕНТНАЯ БЛОКИРОВКА
    if not PERMANENT_LOCK:
        timer_switch.deselect()
    timer_frame.pack_forget()


if TIMER_ENABLED:
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    for widget in timer_frame.winfo_children():
        widget.configure(state="disabled")
    log("🔒 Переключатель таймера и поля ввода заблокированы (автозагрузка)")
need_restore_window = False

if not has_admin_password():
    root.iconify()
    if not has_seen_welcome():
        custom_info_dialog(
            "Первичная настройка",
            "App Blocker будет завершать выбранные программы и может восстанавливать мониторинг после перезапуска Windows.\n\n"
            "Сейчас нужно создать пароль администратора. Он потребуется для выхода и изменения защищённых сценариев.\n\n"
            "Сохраните пароль: без него корректный выход будет невозможен."
        )
        mark_welcome_seen()
    new_admin_password = custom_password_dialog(
        "Пароль администратора",
        "Введите пароль, который будет использоваться для выхода:",
    )
    if not new_admin_password:
        messagebox.showerror("Ошибка", "Пароль не задан! Программа будет закрыта.")
        root.destroy()
        sys.exit(0)
    set_admin_password(new_admin_password)
    save_config(status="EXIT")
    APP_CLOSING = False
    need_restore_window = True
else:
    _startup_config = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                _startup_config = json.load(f)
        except Exception:
            pass
    if launched_by_guard and SECURE_ENABLED:
        log("🛡 AppBlocker восстановлен AppBlockerGuard после завершения процесса.")
        save_config(status="RUNNING" if startup_status == "RUNNING" else "EXIT")
        APP_CLOSING = False
        need_restore_window = True
    else:
        root.iconify()
        authenticated = False
        for attempt in range(3):
            password_input = custom_password_dialog("Пароль администратора", "Введите пароль администратора для входа:")
            if verify_admin_password(password_input):
                authenticated = True
                break
            if password_input is None:
                break
            messagebox.showerror("Ошибка", "Неверный пароль! Попробуйте снова.")
        if not authenticated:
            messagebox.showerror("Ошибка", "Доступ заблокирован без правильного пароля.")
            root.destroy()
            sys.exit(0)
        log("🔓 Пароль администратора подтверждён.")
        save_config(status="RUNNING" if startup_status == "RUNNING" else "EXIT")
        APP_CLOSING = False
        need_restore_window = True

if need_restore_window:
    force_show_main_window(repeats=4 if launched_by_guard else 2, interval=350)
    root.after(5000, maybe_warn_security_disabled)

has_admin_rights_at_startup = is_admin()

guard_should_run_at_startup = SECURE_ENABLED and (
    startup_status == "RUNNING" or should_restore_monitoring or should_restore_sites or launched_by_guard
)

if guard_should_run_at_startup:
    if ensure_appblocker_guard():
        log("🛡 AppBlockerGuard запущен при старте AppBlocker")
    if has_admin_rights_at_startup:
        ensure_app_startup_entries()
    else:
        ensure_startup_entry(GUARD_STARTUP_NAME, GUARD_EXE)
        log("ℹ️ AppBlockerGuard запущен без прав администратора; задача автозапуска с повышенными правами будет настроена при запуске от администратора.")
    if not watch_active:
        watch_active = True
        threading.Thread(target=watch_appblocker_guard, daemon=True).start()
        log("👁️ Мониторинг AppBlockerGuard активирован")
elif SECURE_ENABLED:
    log("ℹ️ Защита включена, но блокировка не активна — AppBlockerGuard не запускается до старта блокировки.")

if should_restore_monitoring or should_restore_sites:
    if has_admin_rights_at_startup:
        ensure_app_startup_entries()
        if ensure_appblocker_guard():
            log("🛡 Система защиты от завершения запущена")
    else:
        log("ℹ️ App Blocker открыт без прав администратора: автозапуск, AppBlockerGuard и восстановление hosts пропущены.")
elif startup_status == "EXIT":
    log("ℹ️ Найден статус EXIT — автозапуск блокировок пропущен.")

if should_restore_monitoring:
    sync_primary_process_name()
    entry_process.insert(0, PROCESS_NAME)
    entry_process.configure(state="disabled")
    add_program_btn.configure(state="disabled")
    remove_program_btn.configure(state="disabled")
    big_start_btn.configure(state="disabled")
    monitoring_active = True
    monitor_thread = threading.Thread(target=monitor_process, daemon=True)
    monitor_thread.start()
    update_status_cards()
    refresh_process_list()
    save_config(status="RUNNING")
    if guard_recovery_active:
        force_show_main_window(repeats=3, interval=350)
    log(f"✅ Автовосстановление мониторинга для программ: {', '.join(BLOCKED_PROGRAMS)}")

if should_restore_sites:
    if not has_admin_rights_at_startup:
        log("ℹ️ Блокировка сайтов не восстановлена: для записи hosts нужны права администратора.")
    elif apply_hosts_block(startup_sites):
        refresh_sites_list()
        log(f"🌐 Автовосстановление блокировки сайтов: {len(startup_sites)}")

if has_admin_rights_at_startup and (should_restore_monitoring or should_restore_sites) and SECURE_ENABLED and not watch_active:
    watch_active = True
    threading.Thread(target=watch_appblocker_guard, daemon=True).start()
    log("👁️ Мониторинг AppBlockerGuard активирован")
else:
    if watch_active:
        log("ℹ️ Мониторинг AppBlockerGuard уже активен")

# 🕒 Таймер
if TIMER_ENABLED and TIMER_END and datetime.datetime.now() < TIMER_END:
    log(f"⏳ Таймер активен до {TIMER_END.strftime('%H:%M:%S')}")
    timer_thread = threading.Thread(target=check_timer, daemon=True)
    timer_thread.start()
elif TIMER_ENABLED and TIMER_END and datetime.datetime.now() >= TIMER_END:
    clear_admin_password()
    save_config(status="EXIT")
    create_exit_sentinel()
    log("⏰ Время работы истекло — программа завершается.")
    if SECURE_ENABLED:
        for proc in psutil.process_iter(['name']):
            try:
                if is_guard_process_name(proc.info['name']):
                    proc.terminate()
                    log("🛑 AppBlockerGuard завершён по таймеру.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    exit_app_no_password()

root.mainloop()


