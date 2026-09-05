"""AppBlocker Client — самостоятельная программа-сервер для удалённого администрирования.

Работает как сервер всегда (LAN и WAN): поднимает TCP/UDP на 55400
(connection_handler.py) и, если включён WAN в client_config.json, держит
соединение с relay-сервером. Закрыть программу без пароля нельзя
(exit_guard.py) — иначе защита ничего не стоила бы.
"""
import json
import os
import sys

# См. AppBlocker.py в Source/ основной программы: без этого print() с эмодзи
# в логах роняет windowed-exe с UnicodeEncodeError на не-UTF-8 кодовой странице
# консоли (например, cp1251).
for _stream in (sys.stdout, sys.stderr):
    if _stream is not None and hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except Exception:
            pass

import flet as ft

import auth
import connection_handler
import exit_guard
from paths import AUTOSTART_RUN_SUBKEY, AUTOSTART_VALUE_NAME, CLIENT_CONFIG_PATH, app_command
from protocol import DEFAULT_PORT

try:
    import pystray
    from PIL import Image
    TRAY_AVAILABLE = True
except Exception:
    pystray = None
    Image = None
    TRAY_AVAILABLE = False

_tray_icon = None


def _ui(page, callback, *args):
    """Выполняет callback в цикле событий Flet — безопасно из потока трея."""

    async def runner():
        callback(*args)

    try:
        page.run_task(runner)
    except Exception:
        pass


def load_client_config():
    if not os.path.exists(CLIENT_CONFIG_PATH):
        return {"wan_enabled": False, "relay_url": ""}
    try:
        with open(CLIENT_CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"wan_enabled": False, "relay_url": ""}


def _install_autostart():
    """Реестровый автозапуск (HKCU\\...\\Run) — тот же приём, что у самого
    AppBlocker (appcore/security.py в основной программе)."""
    try:
        import winreg

        command = app_command()
        target = command[-1]
        if not os.path.exists(target):
            return
        quoted = " ".join(f'"{part}"' for part in command)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_SUBKEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, AUTOSTART_VALUE_NAME, 0, winreg.REG_SZ, quoted)
        connection_handler.log("✅ Автозапуск AppBlocker Client настроен.")
    except Exception as e:
        connection_handler.log(f"⚠️ Не удалось настроить автозапуск: {e}")


def _start_tray(page, on_exit_request):
    global _tray_icon
    if not TRAY_AVAILABLE or _tray_icon:
        return False

    image = Image.new("RGB", (64, 64), "#0078F2")

    def tray_show(icon=None, item=None):
        def show():
            page.window.visible = True
            page.window.minimized = False
            page.update()

        _ui(page, show)

    def tray_exit(icon=None, item=None):
        _ui(page, on_exit_request)

    menu = pystray.Menu(
        pystray.MenuItem("Открыть", tray_show),
        pystray.MenuItem("Выход", tray_exit),
    )
    _tray_icon = pystray.Icon("AppBlocker Client", image, "AppBlocker Client — подключено", menu)
    import threading
    threading.Thread(target=_tray_icon.run, daemon=True).start()
    return True


def main(page: ft.Page):
    page.title = "AppBlocker Client"
    page.window.width = 420
    page.window.height = 260
    page.window.resizable = False

    connection_handler.set_page(page)

    def on_confirmed_exit():
        if _tray_icon:
            try:
                _tray_icon.stop()
            except Exception:
                pass

        async def destroy():
            try:
                await page.window.destroy()
            except Exception:
                pass

        page.run_task(destroy)

    request_exit = exit_guard.install(page, on_confirmed_exit)

    has_tray = _start_tray(page, request_exit)
    if has_tray:
        page.window.skip_task_bar = True

    status_text = ft.Text("Ожидает подключений администратора на порту 55400...", size=13)
    page.add(ft.Column(
        [
            ft.Text("AppBlocker Client", size=20, weight=ft.FontWeight.BOLD),
            status_text,
            ft.Text("Закрыть программу можно только с паролем.", size=12, color="#8E8E9A"),
        ],
        spacing=10,
    ))

    # Окно должно полностью инициализироваться (и хотя бы раз отрисоваться)
    # ДО того, как его прятать — иначе клиент Flet не успевает создать окно
    # вообще, считает сессию пустой и завершает процесс целиком. Поэтому
    # сворачиваем/прячем с небольшой отложенной задачей, а не синхронно здесь.
    async def hide_after_start():
        import asyncio
        await asyncio.sleep(0.3)
        if has_tray:
            # Без трея прятать окно нельзя — вернуть его будет нечем.
            page.window.visible = False
        else:
            page.window.minimized = True
        page.update()

    page.run_task(hide_after_start)

    async def startup():
        await connection_handler.start_tcp_server(DEFAULT_PORT)
        await connection_handler.start_udp_discovery_responder(DEFAULT_PORT)

        config = load_client_config()
        if config.get("wan_enabled") and config.get("relay_url"):
            page.run_task(connection_handler.run_wan_client, config["relay_url"])
            status_text.value = "Подключение к глобальному режиму (relay)..."
            page.update()

        _install_autostart()

        if not auth.has_password():
            from dialogs import show_password_dialog

            def on_first_password(password):
                if password:
                    auth.set_password(password)
                    connection_handler.log("🔐 Пароль выхода задан при первом запуске.")

            show_password_dialog(
                page,
                "Задайте пароль выхода",
                "Этот пароль потребуется, чтобы закрыть AppBlocker Client. Сохраните его — без него программу не закрыть.",
                on_first_password,
            )

    page.run_task(startup)


def run():
    ft.run(main)


if __name__ == "__main__":
    run()
