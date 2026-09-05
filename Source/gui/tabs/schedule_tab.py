"""Вкладка «Расписание»: интервалы автоматической блокировки по дням недели."""
import flet as ft

from appcore import state
from appcore.config_store import save_config
from appcore.i18n import register_retranslate, t
from appcore.logging_util import log
from appcore.schedule import (
    DAY_KEYS,
    DAY_LABEL_KEYS,
    describe_current_state,
    format_intervals,
    has_any_interval,
    is_schedule_active_now,
    parse_intervals_input,
    start_schedule_thread,
)
from appcore.security import ensure_appblocker_guard
from appcore.theme import PRIMARY, TEXT_MUTED
from gui.common import (
    card,
    description,
    entry,
    primary_button,
    scroll_column,
    secondary_button,
    switch,
    text,
)


def refresh_schedule_status(ctx):
    """Обновляет строку состояния под переключателем."""
    ctx.schedule_status_value.value = describe_current_state()
    ctx.schedule_status_value.color = (
        PRIMARY if (state.SCHEDULE_ENABLED and is_schedule_active_now()) else TEXT_MUTED
    )
    ctx.refresh(ctx.schedule_status_value)


def load_schedule_into_entries(ctx):
    """Заполняет поля ввода значениями из state.SCHEDULE."""
    for day, field in ctx.schedule_entries.items():
        field.value = format_intervals(state.SCHEDULE.get(day, []))
        ctx.refresh(field)
    refresh_schedule_status(ctx)


def save_schedule(ctx):
    """Разбирает все семь полей и сохраняет расписание в config.json.

    При ошибке в любом дне ничего не сохраняем: лучше оставить прежнее
    расписание, чем записать половину.
    """
    parsed = {}
    for day, field in ctx.schedule_entries.items():
        try:
            parsed[day] = parse_intervals_input(field.value or "")
        except ValueError as bad_value:
            log(t("log_schedule_invalid", day=t(DAY_LABEL_KEYS[day]), value=bad_value))
            return False

    state.SCHEDULE = parsed
    save_config()
    load_schedule_into_entries(ctx)
    log(t("log_schedule_saved", count=sum(len(v) for v in parsed.values())))
    if state.SCHEDULE_ENABLED and not has_any_interval():
        log(t("log_schedule_no_intervals"))
    # Пересчитываем окно сразу: расписание могли изменить внутри активного окна.
    reevaluate_window(ctx)
    return True


def clear_schedule(ctx):
    for field in ctx.schedule_entries.values():
        field.value = ""
        ctx.refresh(field)
    state.SCHEDULE = {day: [] for day in DAY_KEYS}
    save_config()
    refresh_schedule_status(ctx)
    log(t("log_schedule_cleared"))
    reevaluate_window(ctx)


def toggle_schedule(ctx):
    state.SCHEDULE_ENABLED = bool(ctx.schedule_switch.value)
    save_config()
    log(t("log_schedule_enabled") if state.SCHEDULE_ENABLED else t("log_schedule_disabled"))
    if state.SCHEDULE_ENABLED and not has_any_interval():
        log(t("log_schedule_no_intervals"))
    refresh_schedule_status(ctx)
    reevaluate_window(ctx)


def reevaluate_window(ctx):
    """Сравнивает фактическое окно с текущим состоянием и догоняет разницу.

    Нужно после правки расписания или переключателя: фоновый поток проверяет
    раз в 20 секунд, а реакция на действие пользователя должна быть сразу.
    """
    active = state.SCHEDULE_ENABLED and is_schedule_active_now()
    if active == state.SCHEDULE_WINDOW_ACTIVE:
        return
    state.SCHEDULE_WINDOW_ACTIVE = active
    # Обе процедуры трогают hosts и планировщик — уносим их из цикла событий.
    ctx.run_bg(on_window_start if active else on_window_end, ctx)


def _apply_scheduled_sites(ctx):
    """Включает блокировку сайтов на время окна расписания."""
    from appcore.sites import apply_hosts_block, load_blocked_sites

    sites = load_blocked_sites()
    if not sites:
        return
    if apply_hosts_block(sites):
        state.SCHEDULE_APPLIED_SITES = True
        ctx.ui(ctx.refresh_sites_list)


def _clear_scheduled_sites(ctx):
    """Снимает hosts-блокировку, но только если её поставило расписание."""
    from appcore.sites import apply_hosts_block

    if not state.SCHEDULE_APPLIED_SITES:
        return
    if state.SITES_BLOCKED_MANUALLY or state.PERMANENT_LOCK:
        # Пользователь включал сайты сам — расписание это не отменяет.
        return
    if apply_hosts_block([]):
        state.SCHEDULE_APPLIED_SITES = False
        ctx.ui(ctx.refresh_sites_list)


def on_window_start(ctx):
    """Начало окна: поднимаем мониторинг и блокировку сайтов.

    Блокирующая функция (hosts, запуск guard) — вызывается только из потока.
    """
    from gui.tabs.monitor_tab import start_monitor_thread
    from appcore.processes import sync_primary_process_name

    log(t("log_schedule_window_started"))

    if not state.BLOCKED_PROGRAMS:
        log(t("log_schedule_needs_programs"))
    else:
        sync_primary_process_name()
        if start_monitor_thread(ctx):
            state.SCHEDULE_STARTED_MONITORING = True
            log(t("log_schedule_monitoring_started"))
            if state.SECURE_ENABLED and ensure_appblocker_guard():
                log(t("log_guard_activated"))
            save_config(status="RUNNING")
            ctx.ui(ctx.update_status_cards)
            ctx.ui(ctx.refresh_blocked_programs_list)

    _apply_scheduled_sites(ctx)
    ctx.ui(refresh_schedule_status, ctx)


def on_window_end(ctx):
    """Конец окна: выключаем только то, что включило само расписание.

    Блокирующая функция (hosts) — вызывается только из потока.
    """
    from gui.tabs.monitor_tab import stop_monitor_thread

    log(t("log_schedule_window_ended"))

    if state.PERMANENT_LOCK:
        # Вечную блокировку расписание снимать не вправе.
        log(t("log_schedule_window_end_permanent"))
    elif state.SCHEDULE_STARTED_MONITORING:
        if stop_monitor_thread():
            log(t("log_schedule_monitoring_stopped"))
            save_config(status="EXIT")
        state.SCHEDULE_STARTED_MONITORING = False
        ctx.ui(ctx.update_status_cards)
        ctx.ui(ctx.refresh_blocked_programs_list)

    _clear_scheduled_sites(ctx)
    ctx.ui(refresh_schedule_status, ctx)


def start_watcher(ctx):
    """Запускает фоновый поток расписания.

    Колбэки приходят из потока расписания, поэтому обе процедуры так и остаются
    в фоне — они блокирующие. В цикл событий Flet они возвращаются точечно,
    только чтобы обновить контролы (см. ``ctx.ui`` внутри них).
    """
    start_schedule_thread(
        on_window_start=lambda: on_window_start(ctx),
        on_window_end=lambda: on_window_end(ctx),
    )


def build(ctx):
    schedule_switch = switch(t("schedule_enable_switch"), bool(state.SCHEDULE_ENABLED),
                             lambda e: toggle_schedule(ctx))
    schedule_description = description(t("schedule_description"))
    schedule_note = description(t("schedule_note"))
    schedule_status_caption = text(t("schedule_status_label"), size=13, bold=True)
    schedule_status_value = text(describe_current_state(), size=13, color=TEXT_MUTED)

    top_card = card(ft.Column([
        schedule_switch,
        schedule_description,
        schedule_note,
        ft.Row([schedule_status_caption, schedule_status_value], spacing=8),
    ], spacing=10, tight=True))

    schedule_entries = {}
    day_captions = {}
    day_rows = []
    for day in DAY_KEYS:
        caption_label = text(t(DAY_LABEL_KEYS[day]), size=13, bold=True, width=130)
        field = entry(hint=t("schedule_placeholder"), expand=True)
        day_rows.append(ft.Row([caption_label, field], spacing=8))
        schedule_entries[day] = field
        day_captions[day] = caption_label

    save_btn = primary_button(t("schedule_save_btn"), lambda e: save_schedule(ctx), width=230)
    clear_btn = secondary_button(t("schedule_clear_btn"), lambda e: clear_schedule(ctx), width=160)

    days_card = card(ft.Column(
        day_rows + [ft.Row([save_btn, clear_btn], spacing=8)],
        spacing=10,
        tight=True,
    ))

    schedule_frame = scroll_column([top_card, days_card], spacing=18)

    ctx.schedule_frame = schedule_frame
    ctx.schedule_switch = schedule_switch
    ctx.schedule_entries = schedule_entries
    ctx.schedule_status_value = schedule_status_value
    ctx.refresh_schedule_status = lambda: refresh_schedule_status(ctx)
    ctx.start_schedule_watcher = lambda: start_watcher(ctx)

    load_schedule_into_entries(ctx)

    def retranslate_schedule():
        schedule_switch.label = t("schedule_enable_switch")
        schedule_description.value = t("schedule_description")
        schedule_note.value = t("schedule_note")
        schedule_status_caption.value = t("schedule_status_label")
        save_btn.content = t("schedule_save_btn")
        clear_btn.content = t("schedule_clear_btn")
        for day_key, caption_label in day_captions.items():
            caption_label.value = t(DAY_LABEL_KEYS[day_key])
        for field in schedule_entries.values():
            field.hint_text = t("schedule_placeholder")
        refresh_schedule_status(ctx)
        ctx.refresh(schedule_frame)

    register_retranslate(retranslate_schedule)

    return schedule_frame
