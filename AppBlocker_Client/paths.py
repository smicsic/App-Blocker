"""Пути AppBlocker_Client (Windows). Самостоятельный модуль — не импортирует ничего из Source/."""
import os
import sys

# Пароль выхода — тот же путь и формат, что использует вкладка Remote Admin
# на стороне AppBlocker_Admin (appcore/network/auth_store.py): общий механизм,
# но независимо настраиваемый на каждой машине.
CONFIG_DIR = os.path.join(os.getenv("APPDATA") or os.path.expanduser("~"), "AppBlocker")
PASS_PATH = os.path.join(CONFIG_DIR, "Pass")

# Собственные данные клиента — отдельно от Pass, чтобы не путать с Admin.
CLIENT_DIR = os.path.join(CONFIG_DIR, "Client")
TRUSTED_ADMINS_PATH = os.path.join(CLIENT_DIR, "trusted_admins.json")
CLIENT_CONFIG_PATH = os.path.join(CLIENT_DIR, "client_config.json")
LOG_PATH = os.path.join(CLIENT_DIR, "client.log")

# Автозапуск — реестровый ключ Run текущего пользователя, тот же приём, что и
# у самого AppBlocker (appcore/security.py в основной программе).
AUTOSTART_RUN_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_VALUE_NAME = "AppBlockerClient"

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(CLIENT_DIR, exist_ok=True)


def app_command():
    """Команда автозапуска: собранный exe либо ``<python> main.py`` из исходников."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.join(APP_DIR, "main.py")]
