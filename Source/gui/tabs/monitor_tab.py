"""Вкладка «Мониторинг»: статус, список процессов, блокировка программ."""
import threading

import flet as ft

from appcore import state
from appcore.config_store import save_config
from appcore.i18n import register_retranslate, t
from appcore.logging_util import log
from appcore.processes import (
    get_user_processes,
    is_blocked_program_running,
    monitor_process,
    normalize_process_name,
    sync_primary_process_name,
)
from appcore.security import ensure_app_startup_entries, ensure_appblocker_guard, start_guard_watch_thread
from appcore.stats import end_session, start_session
from appcore.theme import PRIMARY, TEXT_MAIN, TEXT_MUTED
from gui.animations import fly_in_rows
from gui.common import (
    card,
    danger_button,
    primary_button,
    row_surface,
    scroll_column,
    secondary_button,
    stat_card,
    stretch_column,
    sunken_box,
    text,
)


def refresh_process_list(ctx):
    rows = []
    processes = get_user_processes()

    if not processes:
        rows.append(text(t("monitor_no_processes_found"), color=TEXT_MUTED))
    else:
        rows.append(text(t("monitor_processes_found", count=len(processes)), size=12,
                         bold=True, color=TEXT_MUTED))
        for name in processes:
            normalized_name = normalize_process_name(name)
            is_blocked = normalized_name in state.BLOCKED_PROGRAMS
            locked = state.monitoring_active or state.PERMANENT_LOCK

            if is_blocked and locked:
                action = secondary_button(t("monitor_action_protected"), None, width=110,
                                          height=30, size=12, disabled=True)
            elif is_blocked:
                action = secondary_button(
                    t("monitor_action_remove"),
                    lambda e, value=normalized_name: toggle_process_from_list(ctx, value),
                    width=110, height=30, size=12,
                )
            else:
                action = primary_button(
                    t("monitor_action_add"),
                    lambda e, value=normalized_name: toggle_process_from_list(ctx, value),
                    width=110, height=30, size=12,
                )

            rows.append(row_surface(ft.Row(
                [
                    text(name, size=12, mono=True, expand=True, no_wrap=True,
                         overflow=ft.TextOverflow.ELLIPSIS),
                    action,
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            )))

    # Строки влетают слева каскадом. Готовим их до отправки списка клиенту:
    # сначала он получает сдвинутое состояние, а возврат на место приходит
    # отдельным сообщением — только тогда Flet покажет движение, а не результат.
    ctx.process_list.controls = fly_in_rows(ctx, rows)
    ctx.refresh(ctx.process_list)
    log(t("log_process_list_refreshed"))


def toggle_process_from_list(ctx, program):
    program = normalize_process_name(program)
    if not program:
        return
    if program in state.BLOCKED_PROGRAMS:
        if state.monitoring_active or state.PERMANENT_LOCK:
            log(t("log_program_locked_cant_remove", program=program))
            refresh_process_list(ctx)
            return
        state.BLOCKED_PROGRAMS.remove(program)
        log(t("log_program_removed", program=program))
    else:
        state.BLOCKED_PROGRAMS.append(program)
        log(t("log_program_added", program=program))
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list(ctx)
    refresh_process_list(ctx)


def remove_saved_blocked_program(ctx, program):
    program = normalize_process_name(program)
    if not program:
        return
    if state.monitoring_active or state.PERMANENT_LOCK:
        log(t("log_program_locked_cant_remove", program=program))
        refresh_blocked_programs_list(ctx)
        return
    if program not in state.BLOCKED_PROGRAMS:
        refresh_blocked_programs_list(ctx)
        return
    state.BLOCKED_PROGRAMS.remove(program)
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list(ctx)
    refresh_process_list(ctx)
    log(t("log_program_removed", program=program))


def refresh_blocked_programs_list(ctx):
    # Заголовок списка зависит от режима блокировки, поэтому обновляем его здесь:
    # эта функция вызывается и при переключении blacklist/whitelist.
    ctx.blocked_list_title.value = blocked_list_title_text()

    # Этот список пересобирает поток мониторинга каждые 2 секунды, чтобы обновить
    # отметку «запущена / не запущена». Влёт запускаем только для программ,
    # которых в списке ещё не было: иначе строки прыгают влево каждые 2 секунды,
    # и выглядит это как заглючившая анимация.
    shown_before = getattr(ctx, "blocked_rows_shown", frozenset())
    new_rows = []

    rows = []
    if state.BLOCKED_PROGRAMS:
        can_delete = not (state.monitoring_active or state.PERMANENT_LOCK)
        for program in state.BLOCKED_PROGRAMS:
            running = is_blocked_program_running(program)
            status = t("monitor_row_status_running") if running else t("monitor_row_status_not_running")
            marker = "●" if running else "○"

            if can_delete:
                # Разрушающее действие спокойного цвета, красный — только на
                # наведении: ряд ярко-красных кнопок в списке смотрится дёшево.
                delete_btn = danger_button(
                    t("monitor_action_remove"),
                    lambda e, p=program: remove_saved_blocked_program(ctx, p),
                    width=110, height=30, size=12,
                )
            else:
                delete_btn = secondary_button(t("monitor_action_protected"), None,
                                              width=110, height=30, size=12, disabled=True)

            row = row_surface(ft.Row(
                [
                    text(f"{marker} {program} - {status}", size=12, mono=True, expand=True,
                         no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                    delete_btn,
                ],
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            ))
            rows.append(row)
            if program not in shown_before:
                new_rows.append(row)
    else:
        rows.append(text(
            t("monitor_allowed_list_empty") if state.BLOCK_MODE == "whitelist"
            else t("monitor_blocked_list_empty"),
            color=TEXT_MUTED,
        ))

    ctx.blocked_rows_shown = frozenset(state.BLOCKED_PROGRAMS)
    fly_in_rows(ctx, new_rows)
    ctx.blocked_programs_list.controls = rows
    ctx.refresh(ctx.blocked_list_title, ctx.blocked_programs_list)
    update_status_cards(ctx)


def blocked_list_title_text():
    """Заголовок списка зависит от режима: в whitelist это разрешённые программы."""
    if state.BLOCK_MODE == "whitelist":
        return t("monitor_allowed_programs_title")
    return t("monitor_blocked_programs_title")


def start_button_offers_block_now():
    """True, если кнопку надо превратить в «Заблокировать сейчас».

    Такое состояние возникает после «Отменить» в мягкой блокировке: мониторинг
    работает, но программа в передышке. Без этого отменить передышку было бы
    нечем — обычная кнопка запуска в этот момент отключена.
    """
    from appcore import postpone

    return state.monitoring_active and postpone.has_exemptions()


def refresh_start_button(ctx):
    """Приводит большую кнопку в соответствие с состоянием блокировки."""
    button = getattr(ctx, "big_start_btn", None)
    if button is None:
        return
    if start_button_offers_block_now():
        button.disabled = False
        button.content = t("monitor_block_now_btn")
    elif state.monitoring_active:
        button.disabled = True
        button.content = t("monitor_start_btn")
    else:
        button.disabled = False
        button.content = t("monitor_start_btn")
    ctx.refresh(button)


def block_now(ctx):
    """Отменяет передышку, выданную кнопкой «Отменить», и закрывает программы."""
    from appcore import postpone
    from appcore.processes import terminate_now

    postpone.clear_exemptions()
    log(t("log_postpone_exemption_cleared"))
    terminate_now()
    refresh_blocked_programs_list(ctx)
    refresh_start_button(ctx)


def on_start_button(ctx):
    """Одна кнопка на два сценария — запуск блокировки или снятие передышки."""
    if start_button_offers_block_now():
        # Завершение процессов идёт через psutil и может занять время.
        ctx.run_bg(block_now, ctx)
    else:
        ctx.run_bg(start_monitoring, ctx)


def update_status_cards(ctx):
    # Состояние кнопки зависит от передышек, а они истекают по времени —
    # обновляем здесь, эта функция вызывается на каждой итерации мониторинга.
    refresh_start_button(ctx)

    ctx.programs_status_value.value = t("monitor_processes_count", count=len(state.BLOCKED_PROGRAMS))
    ctx.monitor_status_value.value = (
        t("monitor_status_active") if state.monitoring_active else t("monitor_status_waiting")
    )
    ctx.monitor_status_value.color = PRIMARY if state.monitoring_active else TEXT_MAIN
    ctx.secure_status_value.value = (
        t("monitor_secure_on") if state.SECURE_ENABLED else t("monitor_secure_off")
    )
    ctx.secure_status_value.color = PRIMARY if state.SECURE_ENABLED else TEXT_MUTED
    ctx.refresh(ctx.programs_status_value, ctx.monitor_status_value, ctx.secure_status_value)


def start_monitor_thread(ctx):
    """Поднимает поток мониторинга. False, если он уже работает.

    Выделено из start_monitoring, чтобы расписание могло включать мониторинг,
    не задействуя перманентную блокировку и настройку автозапуска.
    """
    if state.monitoring_active:
        return False
    state.monitoring_active = True
    start_session()
    state.monitor_thread = threading.Thread(
        target=monitor_process,
        args=(lambda: ctx.ui(refresh_blocked_programs_list, ctx),),
        daemon=True
    )
    state.monitor_thread.start()
    return True


def stop_monitor_thread():
    """Останавливает мониторинг: цикл monitor_process выходит по флагу сам."""
    if not state.monitoring_active:
        return False
    state.monitoring_active = False
    state.last_monitor_state = None
    end_session()
    return True


def start_monitoring(ctx):
    """Запускает блокировку. Блокирующая (реестр, задачи, guard) — только из потока."""
    sync_primary_process_name()

    if not state.BLOCKED_PROGRAMS:
        # В whitelist-режиме пустой список означал бы «завершать всё пользовательское»,
        # поэтому подсказка другая, но запуск запрещён в обоих режимах.
        log(t("log_whitelist_needs_programs") if state.BLOCK_MODE == "whitelist"
            else t("log_add_at_least_one_program"))
        return

    # ✅ СРАЗУ БЛОКИРУЕМ ВСЕ ТУМБЛЕРЫ НАВСЕГДА
    ctx.ui(ctx.lock_controls_after_start)

    if state.SECURE_ENABLED and ensure_appblocker_guard():
        log(t("log_guard_activated"))

    ensure_app_startup_entries(on_status_update=ctx.update_startup_status_labels)

    if state.SECURE_ENABLED:
        start_guard_watch_thread()

    if state.monitoring_active:
        log(t("log_monitoring_already_active", process=state.PROCESS_NAME))
        return

    # 🧱 УСТАНАВЛИВАЕМ ПЕРМАНЕНТНУЮ БЛОКИРОВКУ
    state.PERMANENT_LOCK = True
    save_config()
    log(t("log_permanent_lock_activated"))

    ctx.ui(ctx.set_window_title, t("window_title_blocker", count=len(state.BLOCKED_PROGRAMS)))

    start_monitor_thread(ctx)
    log(t("log_monitoring_started", process=state.PROCESS_NAME))

    ctx.ui(refresh_start_button, ctx)
    ctx.ui(update_status_cards, ctx)
    ctx.ui(refresh_process_list, ctx)

    save_config()


def build(ctx):
    """Строит содержимое вкладки «Мониторинг» и возвращает её корневой контрол."""
    programs_card, programs_card_title, programs_status_value = stat_card(
        t("monitor_processes_card_title"), t("monitor_processes_count", count=0))
    monitor_card, monitor_card_title, monitor_status_value = stat_card(
        t("monitor_status_card_title"), t("monitor_status_waiting"))
    secure_card, secure_card_title, secure_status_value = stat_card(
        t("monitor_secure_card_title"), t("monitor_secure_on"))
    monitor_status_value.color = TEXT_MAIN

    big_start_btn = primary_button(
        t("monitor_start_btn"), lambda e: on_start_button(ctx),
        width=300, height=50, size=16,
    )

    blocked_list_title = text(blocked_list_title_text(), size=15, bold=True)
    blocked_programs_list = scroll_column(spacing=5, expand=True)
    active_list_title = text(t("monitor_active_processes_title"), size=15, bold=True)
    process_list = scroll_column(spacing=4, expand=True)

    # Оба списка живут в ОДНОЙ общей карточке, чтобы между ними не было видно
    # шва другого цвета — раньше это были два отдельных блока со своими рамками.
    lists_card = card(
        stretch_column(
            [
                blocked_list_title,
                sunken_box(blocked_programs_list, height=160),
                active_list_title,
                sunken_box(process_list, expand=True),
            ],
            expand=True,
        ),
        padding=ft.Padding.symmetric(vertical=16, horizontal=18),
        expand=True,
    )

    monitor_frame = stretch_column(
        [
            ft.Row([programs_card, monitor_card, secure_card], spacing=16),
            ft.Row([big_start_btn], alignment=ft.MainAxisAlignment.CENTER),
            lists_card,
        ],
        spacing=14,
        expand=True,
    )

    ctx.monitor_frame = monitor_frame
    ctx.programs_status_value = programs_status_value
    ctx.monitor_status_value = monitor_status_value
    ctx.secure_status_value = secure_status_value
    ctx.blocked_list_title = blocked_list_title
    ctx.blocked_programs_list = blocked_programs_list
    ctx.process_list = process_list
    ctx.big_start_btn = big_start_btn

    def retranslate_monitor():
        programs_card_title.value = t("monitor_processes_card_title")
        monitor_card_title.value = t("monitor_status_card_title")
        secure_card_title.value = t("monitor_secure_card_title")
        active_list_title.value = t("monitor_active_processes_title")
        refresh_start_button(ctx)
        # Перерисовываем оба списка: их строки и кнопки собираются из t() на месте.
        refresh_blocked_programs_list(ctx)
        refresh_process_list(ctx)
        ctx.refresh(programs_card_title, monitor_card_title, secure_card_title, active_list_title)

    register_retranslate(retranslate_monitor)

    ctx.refresh_process_list = lambda: refresh_process_list(ctx)
    ctx.refresh_blocked_programs_list = lambda: refresh_blocked_programs_list(ctx)
    ctx.update_status_cards = lambda: update_status_cards(ctx)
    ctx.start_monitoring = lambda: ctx.run_bg(start_monitoring, ctx)
    ctx.refresh_start_button = lambda: refresh_start_button(ctx)

    return monitor_frame
