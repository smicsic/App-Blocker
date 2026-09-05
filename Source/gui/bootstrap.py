"""Стартовая последовательность: пароль администратора, восстановление
состояния после перезапуска Windows/AppBlockerGuard, запуск таймера.

Последовательность разбита на этапы, соединённые колбэками, а не выстроена
одним потоком инструкций, как в версии на CustomTkinter. Там запрос пароля
блокировал выполнение до ответа (``wait_window()``), и всё, что дальше, просто
шло следующей строкой. Во Flet синхронный обработчик выполняется прямо в цикле
событий, поэтому ждать ответа внутри него нельзя — окно бы не отрисовалось.

Этапы такие:
  1. ``main``            — окно, конфиг, синхронизация интерфейса;
  2. ``_ask_password``   — создание либо проверка пароля администратора;
  3. ``_continue``       — восстановление защиты, мониторинга и сайтов (в фоне).
"""
import datetime
import os
import sys
import threading

import flet as ft
import psutil

from appcore import state
from appcore.config_store import (
    has_admin_password,
    load_config,
    save_config,
    set_admin_password,
    clear_admin_password,
    verify_admin_password,
)
from appcore.lifecycle import (
    check_timer,
    create_exit_sentinel,
    exit_app_no_password,
    force_show_main_window,
    has_seen_welcome,
    mark_welcome_seen,
)
from appcore.i18n import load_language, t
from appcore.logging_util import log
from appcore.paths import find_flet_client_dir
from appcore.processes import monitor_process, sync_primary_process_name
from appcore.security import (
    ensure_app_startup_entries,
    ensure_appblocker_guard,
    is_guard_process_name,
    start_guard_watch_thread,
)
from appcore.sites import apply_hosts_block, load_blocked_sites
from appcore.stats import start_session
from gui.dialogs import error_dialog, info_dialog, password_dialog, show_security_disabled_dialog
from gui.shell import build_main_window

PASSWORD_ATTEMPTS = 3


def maybe_warn_security_disabled(ctx):
    if state.SECURITY_OFF_WARNING_SHOWN or state.SECURE_ENABLED:
        return
    state.SECURITY_OFF_WARNING_SHOWN = True
    show_security_disabled_dialog(ctx, on_enable_navigate=lambda: ctx.show_frame("settings"))


def _quit(ctx, message):
    """Показывает причину отказа и закрывает приложение."""
    async def destroy():
        try:
            await ctx.page.window.destroy()
        except Exception:
            sys.exit(0)

    error_dialog(ctx, message, on_close=lambda: ctx.run_async(destroy))


def main(page: ft.Page):
    load_language()
    ctx = build_main_window(page)

    log(t("log_enter_process_and_start"))
    ctx.later(450, ctx.refresh_process_list)

    # ----------------- АВТО ЗАПУСК -----------------
    startup_status = load_config()
    launched_by_guard = "--guard-restart" in sys.argv
    ctx.refresh_blocked_programs_list()
    ctx.update_startup_status_labels()
    ctx.sync_match_mode_selector()
    ctx.sync_block_mode_selector()
    # Вкладка настроек собирается до load_config(), поэтому сохранённые значения
    # мягкой блокировки и таймера нужно подтянуть в интерфейс здесь — иначе
    # переключатели показывают значения по умолчанию, а не то, что в config.json.
    ctx.sync_postpone_ui()
    ctx.sync_timer_ui()
    ctx.sync_secure_switch_ui()

    startup_sites = load_blocked_sites()
    guard_recovery_active = launched_by_guard and state.SECURE_ENABLED
    should_restore_monitoring = bool(state.BLOCKED_PROGRAMS) and (
        startup_status == "RUNNING" or guard_recovery_active or state.PERMANENT_LOCK
    )
    should_restore_sites = bool(startup_sites) and (
        startup_status == "RUNNING" or guard_recovery_active
    )

    if state.PERMANENT_LOCK:
        ctx.lock_controls_after_start()
        log(t("log_permanent_lock_active"))

    if state.TIMER_ENABLED and state.TIMER_END and datetime.datetime.now() < state.TIMER_END:
        log(t("log_timer_active_until", time=state.TIMER_END.strftime('%H:%M:%S')))

    if state.TIMER_ENABLED:
        ctx.lock_timer_controls()
        log(t("log_timer_switch_locked"))

    _ask_password(
        ctx,
        startup_status=startup_status,
        launched_by_guard=launched_by_guard,
        guard_recovery_active=guard_recovery_active,
        should_restore_monitoring=should_restore_monitoring,
        should_restore_sites=should_restore_sites,
        startup_sites=startup_sites,
    )


def _ask_password(ctx, **startup):
    """Второй этап: пароль администратора.

    Окно при этом НЕ сворачивается, в отличие от версии на Tk: там диалог был
    отдельным окном верхнего уровня, а здесь он живёт внутри главного окна —
    свернув его, мы спрятали бы и сам запрос пароля.
    """
    launched_by_guard = startup["launched_by_guard"]
    startup_status = startup["startup_status"]

    def finish_authenticated():
        save_config(status="RUNNING" if startup_status == "RUNNING" else "EXIT")
        state.APP_CLOSING = False
        force_show_main_window(ctx, repeats=4 if launched_by_guard else 2, interval=350)
        ctx.later(5000, maybe_warn_security_disabled, ctx)
        _continue(ctx, **startup)

    # ---------- Пароля ещё нет: создаём ----------
    if not has_admin_password():
        def ask_new_password():
            def on_new_password(new_password):
                if not new_password:
                    _quit(ctx, t("dialog_no_password_set"))
                    return
                set_admin_password(new_password)
                finish_authenticated()

            password_dialog(
                ctx,
                t("dialog_admin_password_title"),
                t("dialog_admin_password_new_message"),
                on_new_password,
            )

        if not has_seen_welcome():
            mark_welcome_seen()
            info_dialog(
                ctx,
                t("dialog_first_setup_title"),
                t("dialog_first_setup_message"),
                on_close=ask_new_password,
            )
        else:
            ask_new_password()
        return

    # ---------- Приложение поднял AppBlockerGuard: пароль не спрашиваем ----------
    if launched_by_guard and state.SECURE_ENABLED:
        log(t("log_guard_restored_app"))
        finish_authenticated()
        return

    # ---------- Обычный вход: до трёх попыток ----------
    def ask(attempt):
        def on_password(password_input):
            if verify_admin_password(password_input):
                log(t("log_admin_password_confirmed"))
                finish_authenticated()
                return
            if password_input is None or attempt + 1 >= PASSWORD_ATTEMPTS:
                _quit(ctx, t("dialog_access_denied"))
                return
            error_dialog(
                ctx,
                t("dialog_wrong_password_retry"),
                on_close=lambda: ask(attempt + 1),
            )

        password_dialog(
            ctx,
            t("dialog_admin_password_title"),
            t("dialog_admin_password_login_message"),
            on_password,
        )

    ask(0)


def _continue(ctx, startup_status, launched_by_guard, guard_recovery_active,
              should_restore_monitoring, should_restore_sites, startup_sites):
    """Третий этап: восстановление защиты, мониторинга и сайтов.

    Целиком уезжает в фоновый поток: здесь и запуск guard, и правка реестра, и
    запись hosts — на цикле событий это остановило бы весь интерфейс.
    """
    def work():
        guard_should_run_at_startup = state.SECURE_ENABLED and (
            startup_status == "RUNNING" or should_restore_monitoring or should_restore_sites
            or launched_by_guard
        )

        if guard_should_run_at_startup:
            if ensure_appblocker_guard():
                log(t("log_guard_started_at_boot"))
            ensure_app_startup_entries(on_status_update=ctx.update_startup_status_labels)
            start_guard_watch_thread("log_guard_watch_started_startup")
        elif state.SECURE_ENABLED:
            log(t("log_protection_enabled_not_active"))

        if should_restore_monitoring or should_restore_sites:
            ensure_app_startup_entries(on_status_update=ctx.update_startup_status_labels)
            if ensure_appblocker_guard():
                log(t("log_termination_protection_started"))
        elif startup_status == "EXIT":
            log(t("log_exit_status_found"))

        if should_restore_monitoring:
            sync_primary_process_name()
            state.monitoring_active = True
            start_session()
            state.monitor_thread = threading.Thread(
                target=monitor_process,
                args=(lambda: ctx.ui(ctx.refresh_blocked_programs_list),),
                daemon=True
            )
            state.monitor_thread.start()
            ctx.ui(ctx.update_status_cards)
            ctx.ui(ctx.refresh_process_list)
            save_config(status="RUNNING")
            if guard_recovery_active:
                force_show_main_window(ctx, repeats=3, interval=350)
            log(t("log_monitoring_restored", programs=', '.join(state.BLOCKED_PROGRAMS)))

        if should_restore_sites:
            if apply_hosts_block(startup_sites):
                ctx.ui(ctx.refresh_sites_list)
                log(t("log_sites_restored", count=len(startup_sites)))

        if ((should_restore_monitoring or should_restore_sites)
                and state.SECURE_ENABLED and not state.watch_active):
            start_guard_watch_thread("log_guard_watch_started_startup")
        elif state.watch_active:
            log(t("log_guard_monitoring_already_active"))

        # 🗓 Расписание: поток стартует после восстановления состояния, чтобы
        # первая проверка окна видела уже поднятый мониторинг и не дублировала его.
        ctx.start_schedule_watcher()

        # 🕒 Таймер
        now = datetime.datetime.now()
        if state.TIMER_ENABLED and state.TIMER_END and now < state.TIMER_END:
            log(t("log_timer_active_until", time=state.TIMER_END.strftime('%H:%M:%S')))
            state.timer_thread = threading.Thread(target=check_timer, args=(ctx,), daemon=True)
            state.timer_thread.start()
        elif state.TIMER_ENABLED and state.TIMER_END and now >= state.TIMER_END:
            clear_admin_password()
            save_config(status="EXIT")
            create_exit_sentinel()
            log(t("log_time_expired"))
            if state.SECURE_ENABLED:
                for proc in psutil.process_iter(['name']):
                    try:
                        if is_guard_process_name(proc.info['name']):
                            proc.terminate()
                            log(t("log_guard_terminated_by_timer"))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            exit_app_no_password(ctx)

    ctx.run_bg(work)


def run():
    # Клиент Flet ищем рядом с программой и показываем на него путь: иначе при
    # первом запуске он полезет скачиваться с GitHub (см. find_flet_client_dir).
    if not os.environ.get("FLET_VIEW_PATH"):
        client_dir = find_flet_client_dir()
        if client_dir:
            os.environ["FLET_VIEW_PATH"] = client_dir

    ft.run(main)
