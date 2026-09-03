"""Пути к ресурсам, конфигу и логам приложения."""
import os
import subprocess
import sys


def base_dir():
    """Безопасный путь для AppBlocker — хранит всё в AppData, но иконку ищет рядом с exe."""
    appdata_path = os.path.join(os.getenv("APPDATA"), "AppBlocker")
    os.makedirs(appdata_path, exist_ok=True)

    # Для иконки и exe возвращаем путь программы
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))
        exe_dir = os.path.dirname(exe_dir)  # appcore/ -> Source/

    return exe_dir


def find_font_path(filename):
    bundle_dir = getattr(sys, "_MEIPASS", None)
    candidates = [
        os.path.join(bundle_dir, filename) if bundle_dir else "",
        os.path.join(base_dir(), filename),
        os.path.join(base_dir(), "Source", filename),
        os.path.join(os.getcwd(), filename),
        os.path.join(os.getcwd(), "Source", filename),
        os.path.join(os.path.dirname(base_dir()), filename),
        os.path.join(os.path.dirname(base_dir()), "Source", filename),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


FLET_CLIENT_DIR_NAME = "flet"


def find_flet_client_dir():
    """Ищет папку с flet.exe — клиентом Flet, который и рисует окно.

    Клиент не входит в пакет ``flet-desktop``: при первом запуске тот скачивает
    его (около 100 МБ) в ``%USERPROFILE%\\.flet`` с GitHub. Для собранной
    программы это не годится — App Blocker поднимается при входе в Windows и
    перезапускается AppBlockerGuard, то есть может стартовать без интернета.

    Поэтому клиент кладётся рядом с exe папкой ``flet`` (как остальные файлы
    программы), а найденный путь передаётся Flet через ``FLET_VIEW_PATH``.
    Если папки нет, возвращаем None — тогда Flet скачает клиент сам, что
    нормально при запуске из исходников.
    """
    bundle_dir = getattr(sys, "_MEIPASS", None)
    candidates = [
        os.path.join(APP_DIR, FLET_CLIENT_DIR_NAME),
        os.path.join(bundle_dir, FLET_CLIENT_DIR_NAME) if bundle_dir else "",
        os.path.join(os.getcwd(), FLET_CLIENT_DIR_NAME),
    ]
    for path in candidates:
        if path and os.path.isfile(os.path.join(path, "flet.exe")):
            return path
    return None


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


RUN_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
BLOCK_MARKER = "# AppBlocker managed"
APP_STARTUP_NAME = "AppBlocker"
GUARD_STARTUP_NAME = "AppBlockerGuard"
LEGACY_GUARD_STARTUP_NAME = "SecureSystem"
GUARD_EXE_NAME = "AppBlockerGuard.exe"
LEGACY_GUARD_EXE_NAME = "SecureSystem.exe"

if getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # appcore/ -> Source/

STATE_DIR = os.path.join(os.getenv("APPDATA") or APP_DIR, "AppBlocker")
WELCOME_MARKER_PATH = os.path.join(STATE_DIR, "welcome_seen.marker")
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
CONFIG_BACKUP_PATH = os.path.join(APP_DIR, "config.backup.json")
SECURITY_STATE_PATH = os.path.join(STATE_DIR, "security_state.json")
# Статистика живёт в APPDATA рядом с остальным состоянием: config.json
# пользователи экспортируют и импортируют, история блокировок там лишняя.
STATS_PATH = os.path.join(STATE_DIR, "stats.json")
GUARD_EXE = os.path.join(APP_DIR, GUARD_EXE_NAME)
EXIT_SENTINEL = os.path.join(APP_DIR, "config.exit.lock")
LOG_DIR = os.path.join(APP_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "appblocker.log")
os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# App Blocker opens without forced UAC. Protected actions check admin rights when used.
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000 if os.name == "nt" else 0)
