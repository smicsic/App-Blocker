"""Проверка прав root."""
import os


def is_admin():
    """Проверяет, запущено ли приложение с правами root."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def admin_warning_text(action_name):
    return (
        f"{action_name} требует прав root. "
        "Обычный интерфейс открыт без повышения прав, но эту операцию нужно подтвердить через pkexec."
    )
