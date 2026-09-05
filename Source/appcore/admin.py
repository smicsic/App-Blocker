"""Проверка прав администратора."""
import ctypes


def is_admin():
    """Проверяет, запущено ли приложение с правами администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def admin_warning_text(action_name):
    return (
        f"{action_name} требует права администратора. "
        "Обычный интерфейс открыт без UAC, но эту операцию нужно запускать от имени администратора."
    )
