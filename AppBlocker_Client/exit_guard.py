"""Блокировка выхода из AppBlocker_Client без пароля.

Тот же приём, что и защита выхода в основном AppBlocker
(appcore/lifecycle.py::exit_app): окно перехватывает закрытие
(``page.window.prevent_close = True``) и запрашивает пароль, прежде чем
реально закрыться. Здесь это единственная линия защиты — ученик/сотрудник не
должен иметь возможность просто закрыть программу через крестик или трей.
"""
import flet as ft

import auth
import blocklist
from connection_handler import log
from dialogs import show_password_dialog


def install(page, on_confirmed_exit):
    """Вешает обработчик закрытия окна. ``on_confirmed_exit()`` вызывается после верного пароля."""
    page.window.prevent_close = True

    def request_exit():
        if not auth.has_password():
            # Пароль ещё не задан (первый запуск) — закрыть можно свободно,
            # иначе программу нельзя будет остановить вообще никак.
            log("👋 Выход без пароля (пароль ещё не задан).")
            blocklist.stop_monitor()
            on_confirmed_exit()
            return

        def on_password(password):
            if password and auth.verify_password(password):
                log("👋 Пароль подтверждён, закрываю AppBlocker Client.")
                blocklist.stop_monitor()
                on_confirmed_exit()
            else:
                log("🚫 Попытка закрыть AppBlocker Client с неверным паролем отклонена.")

        show_password_dialog(page, "Выход из AppBlocker Client",
                              "Для закрытия программы введите пароль.", on_password)

    def on_window_event(event):
        if event.type == ft.WindowEventType.CLOSE:
            request_exit()

    page.window.on_event = on_window_event
    return request_exit
