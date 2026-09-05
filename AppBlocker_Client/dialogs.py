"""Минимальные модальные окна AppBlocker_Client: согласие на подключение и пароль выхода.

Не блокирующие, как и в основном приложении: результат приходит в колбэк
``on_result``, а не возвращается из функции — синхронные обработчики Flet
выполняются прямо в цикле asyncio, ждать внутри них нельзя.
"""
import flet as ft

BG = "#101014"
CARD_BG = "#17171C"
PRIMARY = "#0078F2"
ERROR = "#E5484D"
TEXT_MAIN = "#FFFFFF"
TEXT_MUTED = "#8E8E9A"


def _resolve_once(callback):
    done = {"value": False}

    def resolve(*args):
        if done["value"]:
            return
        done["value"] = True
        if callback is not None:
            callback(*args)

    return resolve


def show_consent_dialog(page, sender, ip, on_result):
    """«Разрешить подключение администратора? [Да] [Нет]»."""
    resolve = _resolve_once(on_result)

    def confirm(event=None):
        page.pop_dialog()
        resolve(True)

    def cancel(event=None):
        page.pop_dialog()
        resolve(False)

    dialog = ft.AlertDialog(
        modal=True,
        bgcolor=CARD_BG,
        title=ft.Text("Разрешить подключение администратора?", size=18, weight=ft.FontWeight.BOLD, color=TEXT_MAIN),
        content=ft.Text(
            f"Компьютер \"{sender}\" ({ip}) запрашивает управление AppBlocker Client "
            "на этом устройстве: блокировку и разблокировку программ.",
            size=14, color=TEXT_MUTED,
        ),
        actions=[
            ft.Button("Да", on_click=confirm,
                      style=ft.ButtonStyle(bgcolor=PRIMARY, color=TEXT_MAIN)),
            ft.Button("Нет", on_click=cancel,
                      style=ft.ButtonStyle(bgcolor=ERROR, color=TEXT_MAIN)),
        ],
        actions_alignment=ft.MainAxisAlignment.CENTER,
        on_dismiss=lambda event: resolve(False),
    )
    page.show_dialog(dialog)


def show_password_dialog(page, title_text, message, on_result):
    """Запрашивает пароль. ``on_result(пароль)`` либо ``on_result(None)`` при отмене."""
    resolve = _resolve_once(on_result)
    password_field = ft.TextField(password=True, can_reveal_password=True, width=280, autofocus=True)

    def submit(event=None):
        value = password_field.value or ""
        page.pop_dialog()
        resolve(value)

    def cancel(event=None):
        page.pop_dialog()
        resolve(None)

    password_field.on_submit = submit

    dialog = ft.AlertDialog(
        modal=True,
        bgcolor=CARD_BG,
        title=ft.Text(title_text, size=18, weight=ft.FontWeight.BOLD, color=TEXT_MAIN),
        content=ft.Column(
            [ft.Text(message, size=14, color=TEXT_MUTED), password_field],
            spacing=12, tight=True,
        ),
        actions=[
            ft.Button("OK", on_click=submit, style=ft.ButtonStyle(bgcolor=PRIMARY, color=TEXT_MAIN)),
            ft.Button("Отмена", on_click=cancel, style=ft.ButtonStyle(bgcolor=ERROR, color=TEXT_MAIN)),
        ],
        actions_alignment=ft.MainAxisAlignment.CENTER,
        on_dismiss=lambda event: resolve(None),
    )
    page.show_dialog(dialog)


def show_info_dialog(page, title_text, message, on_close=None):
    resolve = _resolve_once(on_close)

    def close(event=None):
        page.pop_dialog()
        resolve()

    dialog = ft.AlertDialog(
        modal=True,
        bgcolor=CARD_BG,
        title=ft.Text(title_text, size=18, weight=ft.FontWeight.BOLD, color=TEXT_MAIN),
        content=ft.Text(message, size=14, color=TEXT_MUTED),
        actions=[ft.Button("OK", on_click=close, style=ft.ButtonStyle(bgcolor=PRIMARY, color=TEXT_MAIN))],
        actions_alignment=ft.MainAxisAlignment.CENTER,
        on_dismiss=lambda event: resolve(),
    )
    page.show_dialog(dialog)
