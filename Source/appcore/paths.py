"""Пути к ресурсам, конфигу и логам приложения."""
import os
import sys


def _xdg_dir(env_var, default_subdir):
    """XDG Base Directory: берёт путь из переменной окружения или дефолт в $HOME."""
    value = os.getenv(env_var)
    if value:
        return os.path.join(value, "AppBlocker")
    return os.path.join(os.path.expanduser("~"), default_subdir, "AppBlocker")


def base_dir():
    """Возвращает папку программы (рядом с exe/скриптом), где ищем иконку и ресурсы."""
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
    """Ищет папку с клиентом Flet, который и рисует окно.

    Клиент не входит в пакет ``flet-desktop``: при первом запуске тот скачивает
    его (около 100 МБ) в ``~/.flet`` с GitHub. Для собранной программы это не
    годится — App Blocker поднимается при входе в систему и перезапускается
    AppBlockerGuard, то есть может стартовать без интернета.

    Поэтому клиент кладётся рядом с программой в папку ``flet`` (как остальные
    файлы программы), а найденный путь передаётся Flet через ``FLET_VIEW_PATH``.
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
        if path and os.path.isfile(os.path.join(path, "flet")):
            return path
    return None


def find_icon_path():
    bundle_dir = getattr(sys, "_MEIPASS", None)
    names = ("icon.png", "icon.ico")
    search_dirs = [
        bundle_dir,
        base_dir(),
        os.getcwd(),
        os.path.join(os.getcwd(), "Program"),
        os.path.dirname(base_dir()),
        os.path.join(os.path.dirname(base_dir()), "Program"),
    ]
    for name in names:
        for directory in search_dirs:
            if not directory:
                continue
            path = os.path.join(directory, name)
            if os.path.exists(path):
                return path
    return None


HOSTS_PATH = "/etc/hosts"
BLOCK_MARKER = "# AppBlocker managed"
APP_STARTUP_NAME = "AppBlocker"
GUARD_STARTUP_NAME = "AppBlockerGuard"
GUARD_EXE_NAME = "AppBlockerGuard"

if os.environ.get("FLATPAK_ID"):
    APP_DIR = os.path.join(os.path.expanduser("~/.var/app"), os.environ["FLATPAK_ID"])
elif getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # appcore/ -> Source/

if os.environ.get("SNAP"):
    APP_DIR = os.environ.get("SNAP_USER_COMMON", os.path.expanduser("~/.local/share/appblocker"))
elif os.environ.get("FLATPAK_ID"):
    APP_DIR = os.path.join(os.path.expanduser("~/.var/app"), os.environ["FLATPAK_ID"])
elif getattr(sys, 'frozen', False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # appcore/ -> Source/

# Конфиг и состояние — по стандарту XDG Base Directory: настройки в
# $XDG_CONFIG_HOME (обычно ~/.config), данные и статистика в
# $XDG_DATA_HOME (обычно ~/.local/share). Всё, что раньше жило в одном
# %APPDATA%\AppBlocker, для простоты по-прежнему держим вместе — в STATE_DIR.
STATE_DIR = _xdg_dir("XDG_DATA_HOME", ".local/share")
AUTOSTART_DIR = os.path.join(
    os.getenv("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"),
    "autostart",
)
WELCOME_MARKER_PATH = os.path.join(STATE_DIR, "welcome_seen.marker")
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
CONFIG_BACKUP_PATH = os.path.join(APP_DIR, "config.backup.json")
SECURITY_STATE_PATH = os.path.join(STATE_DIR, "security_state.json")
# Статистика живёт в STATE_DIR рядом с остальным состоянием: config.json
# пользователи экспортируют и импортируют, история блокировок там лишняя.
STATS_PATH = os.path.join(STATE_DIR, "stats.json")
GUARD_EXE = os.path.join(APP_DIR, GUARD_EXE_NAME)
GUARD_SCRIPT = os.path.join(APP_DIR, "AppBlockerGuard.py")
EXIT_SENTINEL = os.path.join(APP_DIR, "config.exit.lock")
LOG_DIR = os.path.join(APP_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "appblocker.log")
SINGLE_INSTANCE_LOCK_PATH = os.path.join(STATE_DIR, "appblocker.lock")
os.makedirs(STATE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ---------- Remote Admin ----------
# Пароль вкладки Remote Admin хранится отдельно от обычного config.json, в
# XDG_CONFIG_HOME/AppBlocker/Pass — тот же путь и формат, что использует
# AppBlockerGuard.Client для своего пароля выхода (см. AppBlocker_Client/auth.py).
REMOTE_ADMIN_CONFIG_DIR = _xdg_dir("XDG_CONFIG_HOME", ".config")
ADMIN_PASS_PATH = os.path.join(REMOTE_ADMIN_CONFIG_DIR, "Pass")
TRUSTED_CLIENTS_PATH = os.path.join(REMOTE_ADMIN_CONFIG_DIR, "remote_admin_clients.json")
REMOTE_ADMIN_SETTINGS_PATH = os.path.join(REMOTE_ADMIN_CONFIG_DIR, "remote_admin_settings.json")
os.makedirs(REMOTE_ADMIN_CONFIG_DIR, exist_ok=True)

# App Blocker открывается без запроса root. Действия, требующие root
# (запись /etc/hosts), поднимают права точечно через pkexec.


def app_command():
    """Команда запуска самого AppBlocker для автозапуска/перезапуска.

    В собранной версии ``sys.executable`` — это сам бинарник AppBlocker
    (PyInstaller встраивает интерпретатор внутрь). При запуске из исходников
    это системный python3, поэтому нужно явно указать ему запускаемый скрипт —
    иначе .desktop-автозапуск получил бы ``Exec=/путь/AppBlocker.py``, а такой
    файл сам по себе не исполняемый.
    """
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(sys.argv[0])]


def guard_command():
    """Команда запуска AppBlockerGuard: собранный бинарник либо
    ``<python> AppBlockerGuard.py`` при запуске из исходников (см. app_command)."""
    if getattr(sys, 'frozen', False):
        return [GUARD_EXE]
    return [sys.executable, GUARD_SCRIPT]


def guard_target_exists():
    """True, если то, что запустит guard_command(), реально есть на диске."""
    if getattr(sys, 'frozen', False):
        return os.path.exists(GUARD_EXE)
    return os.path.exists(GUARD_SCRIPT)
