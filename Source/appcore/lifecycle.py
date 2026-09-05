"""Единственный экземпляр, выход из приложения, трей-иконка, таймер завершения.

Функции получают ``ctx`` (``gui.context.AppContext``) вместо окна Tk: через него
доступны страница Flet и мост в её цикл событий. Трей остался на pystray — он
живёт в своём потоке и от библиотеки интерфейса не зависит.
"""
import datetime
import fcntl
import os
import threading
import time

import psutil

from appcore import state
from appcore.i18n import t
from appcore.logging_util import log
from appcore.paths import (
    APP_STARTUP_NAME,
    EXIT_SENTINEL,
    GUARD_STARTUP_NAME,
    SINGLE_INSTANCE_LOCK_PATH,
    WELCOME_MARKER_PATH,
    base_dir,
    find_icon_path,
)
from appcore.security import is_guard_process_name, remove_from_startup_everywhere
from appcore.sites import apply_hosts_block, load_blocked_sites, save_blocked_sites

try:
    import pystray
    from PIL import Image
    TRAY_AVAILABLE = True
except Exception:
    pystray = None
    Image = None
    TRAY_AVAILABLE = False


def ensure_single_instance():
    """Блокировка через flock на файле — держим дескриптор живым весь процесс.

    Файл не удаляем: важна только эксклюзивная блокировка, а не факт
    существования файла. Если процесс упадёт, ядро снимет блокировку само.
    """
    try:
        lock_file = open(SINGLE_INSTANCE_LOCK_PATH, "w")
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state._single_instance_lock_file = lock_file
        return True
    except OSError:
        return False
    except Exception:
        return True


def has_seen_welcome():
    return os.path.exists(WELCOME_MARKER_PATH)


def mark_welcome_seen():
    try:
        with open(WELCOME_MARKER_PATH, "w", encoding="utf-8") as f:
            f.write(datetime.datetime.now().isoformat())
    except Exception:
        pass


def create_exit_sentinel():
    """Создаёт флажок EXIT и делает его read-only (если возможно)."""
    try:
        if not os.path.exists(EXIT_SENTINEL):
            with open(EXIT_SENTINEL, "w", encoding="utf-8") as s:
                s.write("EXIT\n")
                s.flush()           # 💾 Принудительно записать данные
                os.fsync(s.fileno())  # 🧱 Гарантировать запись на диск
        try:
            os.chmod(EXIT_SENTINEL, 0o444)
        except Exception:
            pass
    except Exception as e:
        log(t("log_sentinel_error", error=e))


def show_main_window(ctx):
    """Показывает и выводит окно на передний план.

    Порядок важен: пока окно скрыто или свёрнуто, вывести его вперёд нельзя,
    поэтому сначала снимаем оба состояния, затем поднимаем. Кратковременный
    ``always_on_top`` нужен, чтобы Windows не отказала в смене фокуса чужому
    активному окну; сразу снимать его нельзя — окно должно успеть подняться.
    """
    async def bring_up():
        window = ctx.page.window
        try:
            window.visible = True
            window.minimized = False
            window.always_on_top = True
            window.update()
            await window.to_front()
            window.focused = True
            window.update()
        except Exception:
            pass

    def drop_topmost():
        try:
            ctx.page.window.always_on_top = False
            ctx.page.window.update()
        except Exception:
            pass

    ctx.run_async(bring_up)
    ctx.later(250, drop_topmost)


def force_show_main_window(ctx, repeats=12, interval=350):
    """Повторяет показ окна несколько раз.

    Одной попытки мало: сразу после старта (особенно когда приложение поднял
    AppBlockerGuard) окно ещё не готово, и запрос на передний план теряется.
    """
    def bring_left(count):
        show_main_window(ctx)
        if count > 0:
            ctx.later(interval, bring_left, count - 1)

    bring_left(repeats)


def hide_to_tray(ctx):
    def hide():
        window = ctx.page.window
        if TRAY_AVAILABLE:
            window.visible = False
            window.update()
            log(t("log_window_hidden_to_tray"))
        else:
            # Без трея прятать окно нельзя — вернуть его будет нечем.
            window.minimized = True
            window.update()
            log(t("log_window_minimized_no_tray"))

    ctx.ui(hide)


def create_tray_image():
    if not TRAY_AVAILABLE:
        return None
    from appcore.theme import APP_BG

    icon_path = find_icon_path()
    try:
        if icon_path:
            return Image.open(icon_path).resize((64, 64))
    except Exception:
        pass
    image = Image.new("RGB", (64, 64), APP_BG)
    return image


def stop_tray_icon():
    try:
        if state.TRAY_ICON:
            state.TRAY_ICON.stop()
            state.TRAY_ICON = None
    except Exception:
        pass


def start_tray_icon(ctx, on_exit):
    """on_exit: функция без аргументов, вызывается по клику 'Выход' в трее."""
    if not TRAY_AVAILABLE or state.TRAY_ICON:
        return

    def tray_show(icon=None, item=None):
        show_main_window(ctx)

    def tray_hide(icon=None, item=None):
        hide_to_tray(ctx)

    def tray_exit(icon=None, item=None):
        show_main_window(ctx)
        ctx.ui(on_exit)

    image = create_tray_image()
    if image is None:
        return
    # Подписи задаём вызываемыми объектами: pystray дёргает их при открытии
    # меню, поэтому пункты трея следуют за сменой языка без пересборки иконки.
    menu = pystray.Menu(
        pystray.MenuItem(lambda item: t("tray_open"), tray_show),
        pystray.MenuItem(lambda item: t("tray_hide"), tray_hide),
        pystray.MenuItem(lambda item: t("tray_exit"), tray_exit),
    )
    state.TRAY_ICON = pystray.Icon("App Blocker", image, "App Blocker", menu)
    threading.Thread(target=state.TRAY_ICON.run, daemon=True).start()


def on_close(ctx):
    hide_to_tray(ctx)


def _unblock_all_sites():
    try:
        sites = load_blocked_sites()
        if sites:
            log(t("log_removing_sites_from_hosts", count=len(sites)))
            save_blocked_sites([])

            for attempt in range(3):
                if apply_hosts_block([]):
                    log(t("log_all_sites_unblocked"))
                    break
                else:
                    log(t("log_retry_attempt", attempt=attempt + 1))
                    time.sleep(0.5)
        else:
            log(t("log_sites_list_empty"))
    except Exception as e:
        log(t("log_unblock_sites_error", error=e))


def _kill_guard_processes(log_each=False):
    for attempt in range(5):
        killed = False
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if is_guard_process_name(proc.info['name']):
                    try:
                        proc.kill()
                        if log_each:
                            log(t("log_guard_pid_terminated", pid=proc.info['pid']))
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


def _remove_exit_sentinel_file():
    try:
        log(t("log_config_saved_for_settings"))
        if os.path.exists(EXIT_SENTINEL):
            os.chmod(EXIT_SENTINEL, 0o666)
            os.remove(EXIT_SENTINEL)
            log(t("log_sentinel_removed"))
    except Exception as e:
        log(t("log_file_removal_error", error=e))


def _destroy_window(ctx):
    """Закрывает окно приложения и завершает процесс."""
    async def destroy():
        try:
            await ctx.page.window.destroy()
        except Exception:
            pass

    ctx.run_async(destroy)


def exit_app_no_password(ctx):
    """Выход по истечении таймера — без запроса пароля.

    Блокирующая функция (ждёт остановки потоков и переписывает hosts): вызывать
    только из фонового потока, иначе встанет цикл событий Flet.
    """
    from appcore.config_store import clear_admin_password, save_config

    if not state.PROCESS_NAME:
        log(t("log_exit_cancelled_no_process"))
        return

    if not state.monitoring_active:
        log(t("log_exit_cancelled_no_monitoring"))
        return

    with state.EXIT_LOCK:
        if state.APP_CLOSING:
            return
        state.APP_CLOSING = True

    log(t("log_exit_no_password"))

    state.monitoring_active = False
    state.watch_active = False
    state.PERMANENT_LOCK = False
    state.shutdown_event.set()
    time.sleep(1.5)

    _unblock_all_sites()

    create_exit_sentinel()
    clear_admin_password()
    save_config(status="EXIT")

    _kill_guard_processes()

    _remove_exit_sentinel_file()

    remove_from_startup_everywhere(APP_STARTUP_NAME, "appblocker")
    remove_from_startup_everywhere(GUARD_STARTUP_NAME, "appblockerguard")
    stop_tray_icon()
    ctx.later(500, _destroy_window, ctx)


def exit_app(ctx):
    """Спрашивает пароль и, если он верный, выполняет выход в фоновом потоке."""
    from appcore.config_store import verify_admin_password
    from gui.dialogs import error_dialog, password_dialog

    def on_password(password_input):
        if not verify_admin_password(password_input):
            error_dialog(ctx, t("dialog_wrong_password"))
            return
        # Сам выход блокирующий — уносим его из цикла событий.
        ctx.run_bg(_perform_exit, ctx)

    password_dialog(ctx, t("dialog_exit_title"), t("dialog_exit_message"), on_password)


def _perform_exit(ctx):
    """Полная процедура выхода. Блокирующая — только из фонового потока."""
    from appcore.config_store import clear_admin_password, save_config
    import json
    from appcore.paths import CONFIG_PATH

    with state.EXIT_LOCK:
        if state.APP_CLOSING:
            return
        state.APP_CLOSING = True

    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                _d = json.load(f)
            _d["authenticated"] = False
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(_d, f, indent=2)
    except Exception:
        pass

    log(t("log_exit_starting"))

    log(t("log_stopping_threads"))
    state.monitoring_active = False
    state.watch_active = False
    state.PERMANENT_LOCK = False
    # Закрываем интервал статистики до сна: иначе время блокировки не запишется.
    try:
        from appcore.stats import end_session
        end_session()
    except Exception:
        pass
    state.shutdown_event.set()
    time.sleep(1.5)
    log(t("log_threads_stopped"))

    try:
        sites = load_blocked_sites()
        if sites:
            log(t("log_removing_sites_from_hosts", count=len(sites)))
            save_blocked_sites([])
            for attempt in range(3):
                if apply_hosts_block([]):
                    log(t("log_all_sites_unblocked"))
                    break
                else:
                    log(t("log_retry_attempt_final", attempt=attempt + 1))
                    time.sleep(0.5)
            else:
                log(t("log_hosts_cleanup_failed"))
        else:
            log(t("log_blocked_sites_list_empty"))
    except Exception as e:
        log(t("log_unblock_sites_error2", error=e))

    try:
        create_exit_sentinel()
        clear_admin_password()
        save_config(status="EXIT")
        log(t("log_exit_written"))
    except Exception as e:
        log(t("log_exit_write_error", error=e))

    log(t("log_terminating_guard"))
    _kill_guard_processes(log_each=True)
    time.sleep(0.5)

    _remove_exit_sentinel_file()

    log(t("log_removing_from_startup"))
    removed_app = remove_from_startup_everywhere(APP_STARTUP_NAME, "appblocker")
    removed_secure = remove_from_startup_everywhere(GUARD_STARTUP_NAME, "appblockerguard")
    removed = removed_app or removed_secure
    log(t("log_startup_cleared") if removed else t("log_startup_entries_not_found"))

    log(t("log_shutting_down"))
    stop_tray_icon()
    ctx.later(1000, _destroy_window, ctx)


def check_timer(ctx):
    while True:
        if state.TIMER_ENABLED and state.TIMER_END:
            now = datetime.datetime.now()
            if now >= state.TIMER_END:
                log(t("log_time_expired"))
                if state.SECURE_ENABLED:
                    for proc in psutil.process_iter(['name']):
                        try:
                            if is_guard_process_name(proc.info['name']):
                                proc.terminate()  # ❌ СЛАБОЕ ЗАВЕРШЕНИЕ!
                                log(t("log_guard_terminated_by_timer"))
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                # Уже в фоновом потоке — можно звать блокирующий выход напрямую.
                exit_app_no_password(ctx)
                break
        time.sleep(1)
