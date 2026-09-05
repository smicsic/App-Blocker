"""Пути AppBlocker_Client. Самостоятельный модуль — не импортирует ничего из Source/."""
import os
import sys


def _xdg_dir(env_var, default_subdir):
    value = os.getenv(env_var)
    if value:
        return os.path.join(value, "AppBlocker")
    return os.path.join(os.path.expanduser("~"), default_subdir, "AppBlocker")


# Пароль выхода — тот же путь и формат, что использует вкладка Remote Admin
# на стороне AppBlocker_Admin (appcore/network/auth_store.py): общий механизм,
# но независимо настраиваемый на каждой машине.
CONFIG_DIR = _xdg_dir("XDG_CONFIG_HOME", ".config")
PASS_PATH = os.path.join(CONFIG_DIR, "Pass")

# Собственные данные клиента — отдельно от Pass, чтобы не путать с Admin.
CLIENT_DIR = os.path.join(CONFIG_DIR, "Client")
TRUSTED_ADMINS_PATH = os.path.join(CLIENT_DIR, "trusted_admins.json")
CLIENT_CONFIG_PATH = os.path.join(CLIENT_DIR, "client_config.json")
LOG_PATH = os.path.join(CLIENT_DIR, "client.log")

# XDG-автозапуск — фиксированный путь $XDG_CONFIG_HOME/autostart, БЕЗ
# подпапки AppBlocker: рабочий стол ищет .desktop-файлы именно там, а не
# внутри директории конкретного приложения (в отличие от CONFIG_DIR/CLIENT_DIR
# выше, которые — собственное хранилище программы).
AUTOSTART_DIR = os.path.join(
    os.getenv("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config"),
    "autostart",
)

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(CLIENT_DIR, exist_ok=True)


def app_command():
    """Команда автозапуска: собранный бинарник либо ``<python> main.py`` из исходников."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.join(APP_DIR, "main.py")]
