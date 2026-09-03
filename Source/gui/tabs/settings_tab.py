"""Вкладка «Настройки»: автозапуск/диагностика, конфиг, режим совпадения, таймер, защита."""
import datetime
import re
import threading

import flet as ft

from appcore import state
from appcore.config_store import export_config, import_config, save_config, save_security_state
from appcore.i18n import register_retranslate, t
from appcore.logging_util import log
from appcore.paths import APP_STARTUP_NAME, GUARD_STARTUP_NAME, LOG_PATH, guard_target_exists
from appcore.security import (
    enable_security_after_consent,
    is_autostart_registered,
    run_diagnostics as security_run_diagnostics,
)
from appcore.lifecycle import check_timer
from appcore.theme import ERROR, PRIMARY, TEXT_MUTED
from gui.common import (
    card,
    description,
    entry,
    primary_button,
    scroll_column,
    secondary_button,
    segmented,
    segmented_selection,
    status_row,
    switch,
    text,
)


def update_startup_status_labels(ctx):
    """Обновляет три строки состояния защиты.

    Проверка лезет в файловую систему (~/.config/autostart), поэтому вся работа
    идёт в фоновом потоке, а в цикл событий возвращается только запись результата.
    """
    def work():
        app_ready = is_autostart_registered(APP_STARTUP_NAME)
        secure_ready = is_autostart_registered(GUARD_STARTUP_NAME)
        guard_exists = guard_target_exists()

        def apply():
            ctx.app_startup_status.value = (
                t("settings_status_active") if app_ready else t("settings_status_not_configured")
            )
            ctx.app_startup_status.color = PRIMARY if app_ready else TEXT_MUTED
            ctx.secure_startup_status.value = (
                t("settings_status_active") if secure_ready else t("settings_status_not_configured")
            )
            ctx.secure_startup_status.color = PRIMARY if secure_ready else TEXT_MUTED
            ctx.secure_file_status.value = (
                t("settings_status_found") if guard_exists else t("settings_status_not_found")
            )
            ctx.secure_file_status.color = PRIMARY if guard_exists else ERROR
            ctx.refresh(ctx.app_startup_status, ctx.secure_startup_status, ctx.secure_file_status)

        ctx.ui(apply)

    ctx.run_bg(work)


def run_diagnostics(ctx):
    ctx.run_bg(
        security_run_diagnostics,
        lambda: update_startup_status_labels(ctx),
    )


def refresh_security_ui(ctx):
    ctx.update_status_cards()
    ctx.update_startup_status_labels()


async def export_config_dialog(ctx):
    """Спрашивает путь и выгружает config.json."""
    target = await ctx.file_picker.save_file(
        dialog_title=t("dialog_export_settings_title"),
        file_name="config.json",
        file_type=ft.FilePickerFileType.CUSTOM,
        allowed_extensions=["json"],
    )
    if target:
        ctx.run_bg(export_config, target)


async def import_config_dialog(ctx):
    """Спрашивает файл, импортирует его и обновляет связанные списки."""
    files = await ctx.file_picker.pick_files(
        dialog_title=t("dialog_import_settings_title"),
        file_type=ft.FilePickerFileType.CUSTOM,
        allowed_extensions=["json"],
    )
    if not files:
        return

    def work():
        if import_config(files[0].path):
            ctx.ui(ctx.refresh_blocked_programs_list)
            ctx.ui(ctx.refresh_sites_list)
            ctx.ui(ctx.update_status_cards)
            ctx.ui(ctx.update_startup_status_labels)
            ctx.ui(sync_match_mode_selector, ctx)
            ctx.ui(sync_block_mode_selector, ctx)
            ctx.ui(sync_postpone_ui, ctx)

    ctx.run_bg(work)


def set_match_mode(ctx, value):
    if block_mode_is_locked():
        sync_match_mode_selector(ctx)
        lock_mode_selectors(ctx)
        log(t("log_block_mode_locked"))
        return
    state.MATCH_MODE = value
    save_config()
    ctx.refresh_blocked_programs_list()
    log(t("log_match_mode_changed", mode=match_mode_label(value)))


def match_mode_label(value):
    return t("settings_match_exact") if value == "exact" else t("settings_match_contains")


def block_mode_label(value):
    return (t("settings_block_mode_whitelist") if value == "whitelist"
            else t("settings_block_mode_blacklist"))


def block_mode_is_locked():
    """Режим нельзя менять после запуска блокировки."""
    return state.PERMANENT_LOCK or state.monitoring_active


def set_block_mode(ctx, value):
    """Переключает blacklist/whitelist и сохраняет режим в config.json."""
    if value == state.BLOCK_MODE:
        return

    if block_mode_is_locked():
        # Возвращаем переключатель в фактическое состояние и объясняем причину.
        sync_block_mode_selector(ctx)
        lock_mode_selectors(ctx)
        log(t("log_block_mode_locked"))
        return

    state.BLOCK_MODE = value
    save_config()
    ctx.refresh_blocked_programs_list()
    ctx.refresh_process_list()
    log(t("log_block_mode_changed", mode=block_mode_label(value)))
    if value == "whitelist" and not state.BLOCKED_PROGRAMS:
        log(t("log_whitelist_needs_programs"))


def toggle_postpone_mode(ctx):
    """Включает/выключает мягкую блокировку.

    Правило намеренно асимметричное: выключить задержку можно в любой момент —
    это делает блокировку строже. А включить её при уже запущенной блокировке
    нельзя: так можно было бы ослабить действующую блокировку задним числом.
    """
    from appcore import postpone

    requested = bool(ctx.postpone_switch.value)
    if requested and not state.POSTPONE_ENABLED and block_mode_is_locked():
        sync_postpone_ui(ctx)
        log(t("log_block_mode_locked"))
        return

    state.POSTPONE_ENABLED = requested
    if not state.POSTPONE_ENABLED:
        postpone.clear_exemptions()
    save_config()
    sync_postpone_ui(ctx)
    log(t("log_postpone_enabled", seconds=state.POSTPONE_SECONDS) if state.POSTPONE_ENABLED
        else t("log_postpone_disabled"))


def set_postpone_seconds(ctx):
    from appcore.postpone import MAX_SECONDS, MIN_SECONDS, normalize_seconds

    seconds = normalize_seconds(ctx.postpone_entry.value or "")
    if seconds is None:
        log(t("log_postpone_seconds_invalid", minimum=MIN_SECONDS, maximum=MAX_SECONDS))
        return
    state.POSTPONE_SECONDS = seconds
    save_config()
    sync_postpone_ui(ctx)
    log(t("log_postpone_seconds_set", seconds=seconds))


def sync_postpone_ui(ctx):
    """Приводит переключатель, поле и подпись в соответствие с состоянием."""
    ctx.postpone_switch.value = bool(state.POSTPONE_ENABLED)
    ctx.postpone_row.visible = bool(state.POSTPONE_ENABLED)
    ctx.postpone_entry.value = str(state.POSTPONE_SECONDS)
    ctx.postpone_current_label.value = t("settings_postpone_current", seconds=state.POSTPONE_SECONDS)
    ctx.refresh(ctx.postpone_switch, ctx.postpone_row, ctx.postpone_entry,
                ctx.postpone_current_label)


def lock_mode_selectors(ctx):
    """Блокирует переключатели режимов после старта блокировки.

    Режим блокировки и режим совпадения имён — оба влияют на то, какие процессы
    будут закрыты, поэтому после запуска их менять нельзя: иначе переключением
    можно ослабить уже включённую блокировку.
    """
    # postpone_switch здесь намеренно нет: его блокировка не давала бы выключить
    # задержку, то есть мешала бы сделать блокировку строже. Ограничение на
    # включение проверяется в toggle_postpone_mode.
    for attribute in ("block_mode_selector", "match_mode_selector"):
        selector = getattr(ctx, attribute, None)
        if selector is None:
            continue
        selector.disabled = True
        ctx.refresh(selector)


def sync_block_mode_selector(ctx):
    """Приводит переключатель режима в соответствие с ``state.BLOCK_MODE``.

    Выбор — список, а не множество: см. пояснение в ``gui.common.segmented``.
    """
    ctx.block_mode_selector.selected = [state.BLOCK_MODE]
    ctx.refresh(ctx.block_mode_selector)


def sync_match_mode_selector(ctx):
    """Приводит переключатель совпадения в соответствие с ``state.MATCH_MODE``."""
    ctx.match_mode_selector.selected = [state.MATCH_MODE]
    ctx.refresh(ctx.match_mode_selector)


def toggle_timer_mode(ctx):
    state.TIMER_ENABLED = bool(ctx.timer_switch.value)
    ctx.timer_row.visible = state.TIMER_ENABLED
    ctx.refresh(ctx.timer_row)
    save_config()
    label = t("timer_state_on") if state.TIMER_ENABLED else t("timer_state_off")
    log(t("log_timer_state", state=label))


def parse_timer_end_time(value):
    value = value.strip()
    if not re.fullmatch(r"\d{1,2}:\d{2}", value):
        raise ValueError
    hour_text, minute_text = value.split(":")
    hour = int(hour_text)
    minute = int(minute_text)
    if hour > 23 or minute > 59:
        raise ValueError

    now = datetime.datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return target


def set_timer(ctx):
    raw_value = (ctx.timer_entry.value or "").strip()
    if not raw_value:
        log(t("log_enter_timer_time"))
        return

    try:
        state.TIMER_END = parse_timer_end_time(raw_value)
        save_config()
        log(t("log_timer_set", time=state.TIMER_END.strftime('%H:%M')))

        if state.TIMER_ENABLED:
            if state.timer_thread is None or not state.timer_thread.is_alive():
                state.timer_thread = threading.Thread(target=check_timer, args=(ctx,), daemon=True)
                state.timer_thread.start()
                log(t("log_timer_started"))
                lock_timer_controls(ctx)

    except ValueError:
        log(t("log_timer_invalid"))


def lock_timer_controls(ctx):
    """Запирает таймер: после запуска отсчёт нельзя ни отменить, ни сдвинуть."""
    ctx.timer_switch.disabled = True
    ctx.timer_entry.disabled = True
    ctx.timer_set_btn.disabled = True
    ctx.refresh(ctx.timer_switch, ctx.timer_entry, ctx.timer_set_btn)


def sync_timer_ui(ctx):
    """Показывает поле ввода, если таймер включён."""
    ctx.timer_switch.value = bool(state.TIMER_ENABLED)
    ctx.timer_row.visible = bool(state.TIMER_ENABLED)
    ctx.refresh(ctx.timer_switch, ctx.timer_row)


def sync_secure_switch_ui(ctx):
    if state.SECURE_ENABLED:
        ctx.secure_switch.value = True
        ctx.secure_switch.label = t("settings_secure_switch_label_on")
        ctx.secure_state_label.value = t("settings_secure_state_active")
        ctx.secure_state_label.color = PRIMARY
    else:
        ctx.secure_switch.value = False
        ctx.secure_switch.label = t("settings_secure_switch_label_off")
        ctx.secure_state_label.value = t("settings_secure_state_inactive")
        ctx.secure_state_label.color = TEXT_MUTED
    ctx.refresh(ctx.secure_switch, ctx.secure_state_label)


def toggle_secure_mode(ctx):
    from gui.dialogs import show_security_protection_dialog, yes_no_dialog

    requested_enabled = bool(ctx.secure_switch.value)

    if requested_enabled:
        if state.SECURE_ENABLED:
            sync_secure_switch_ui(ctx)
            return

        def on_answer(confirmed):
            if confirmed:
                # Включение защиты ставит задачи и реестр — это в фоновый поток.
                ctx.run_bg(_enable_security, ctx)
            else:
                state.SECURE_ENABLED = False
                save_security_state()
                save_config()
                sync_secure_switch_ui(ctx)
                ctx.update_status_cards()
                log(t("log_secure_not_enabled_by_user"))

        if state.SECURITY_WARNING_SEEN:
            yes_no_dialog(ctx, t("dialog_enable_protection_question"),
                          t("dialog_enable_protection_question"), on_answer)
        else:
            show_security_protection_dialog(ctx, on_answer)
        return

    state.SECURE_ENABLED = False
    save_security_state()
    save_config()
    sync_secure_switch_ui(ctx)
    ctx.update_status_cards()
    ctx.update_startup_status_labels()
    log(t("log_secure_disabled"))


def _enable_security(ctx):
    enable_security_after_consent(on_status_update=lambda: ctx.ui(refresh_security_ui, ctx))
    ctx.ui(sync_secure_switch_ui, ctx)


def build(ctx):
    from appcore.security import copy_app_folder_path

    # ---------- Состояние защиты ----------
    startup_card_title = text(t("settings_protection_state_title"), size=16, bold=True)
    app_startup_row, app_startup_caption, app_startup_status = status_row(
        t("settings_startup_app_label"), t("settings_status_checking"))
    secure_startup_row, secure_startup_caption, secure_startup_status = status_row(
        t("settings_startup_guard_label"), t("settings_status_checking"))
    secure_file_row, secure_file_caption, secure_file_status = status_row(
        t("settings_guard_file_label"), t("settings_status_checking"))
    diagnostics_btn = secondary_button(t("settings_check_protection_btn"),
                                       lambda e: run_diagnostics(ctx), width=200)

    startup_card = card(ft.Column([
        startup_card_title,
        app_startup_row,
        secure_startup_row,
        secure_file_row,
        diagnostics_btn,
    ], spacing=10, tight=True))

    ctx.app_startup_status = app_startup_status
    ctx.secure_startup_status = secure_startup_status
    ctx.secure_file_status = secure_file_status

    # ---------- Конфигурация ----------
    config_card_title = text(t("settings_config_title"), size=16, bold=True)
    config_description = description(t("settings_config_description", log_path=LOG_PATH))
    export_config_btn = primary_button(
        t("settings_export_btn"),
        lambda e: ctx.run_async(export_config_dialog, ctx), width=130)
    import_config_btn = secondary_button(
        t("settings_import_btn"),
        lambda e: ctx.run_async(import_config_dialog, ctx), width=130)

    config_card = card(ft.Column([
        config_card_title,
        config_description,
        ft.Row([export_config_btn, import_config_btn], spacing=8),
    ], spacing=10, tight=True))

    # ---------- Режим блокировки и режим совпадения ----------
    block_mode_card_title = text(t("settings_block_mode_title"), size=16, bold=True)
    block_mode_description = description(t("settings_block_mode_description"))
    block_mode_selector = segmented(
        [
            ("blacklist", t("settings_block_mode_blacklist")),
            ("whitelist", t("settings_block_mode_whitelist")),
        ],
        state.BLOCK_MODE,
        lambda e: set_block_mode(ctx, segmented_selection(e, state.BLOCK_MODE)),
    )
    ctx.block_mode_selector = block_mode_selector

    match_card_title = text(t("settings_match_title"), size=16, bold=True)
    match_description = description(t("settings_match_description"))
    match_mode_selector = segmented(
        [
            ("contains", t("settings_match_contains")),
            ("exact", t("settings_match_exact")),
        ],
        state.MATCH_MODE,
        lambda e: set_match_mode(ctx, segmented_selection(e, state.MATCH_MODE)),
    )
    ctx.match_mode_selector = match_mode_selector

    match_card = card(ft.Column([
        block_mode_card_title,
        block_mode_description,
        block_mode_selector,
        ft.Container(height=6),
        match_card_title,
        match_description,
        match_mode_selector,
    ], spacing=10, tight=True))

    # ---------- Мягкая блокировка ----------
    postpone_card_title = text(t("settings_postpone_title"), size=16, bold=True)
    postpone_switch = switch(t("settings_postpone_switch"), bool(state.POSTPONE_ENABLED),
                             lambda e: toggle_postpone_mode(ctx))
    postpone_description = description(t("settings_postpone_description"))
    postpone_seconds_caption = text(t("settings_postpone_seconds_label"), size=13, bold=True)
    postpone_entry = entry(hint=t("settings_postpone_placeholder"), width=110,
                           on_submit=lambda e: set_postpone_seconds(ctx))
    postpone_set_btn = primary_button(t("settings_postpone_set_btn"),
                                      lambda e: set_postpone_seconds(ctx), width=150)
    postpone_row = ft.Row([postpone_seconds_caption, postpone_entry, postpone_set_btn],
                          spacing=8, visible=bool(state.POSTPONE_ENABLED))
    postpone_current_label = description("")

    postpone_card = card(ft.Column([
        postpone_card_title,
        postpone_switch,
        postpone_description,
        postpone_row,
        postpone_current_label,
    ], spacing=10, tight=True))

    ctx.postpone_switch = postpone_switch
    ctx.postpone_entry = postpone_entry
    ctx.postpone_row = postpone_row
    ctx.postpone_current_label = postpone_current_label

    # ---------- Таймер ----------
    timer_card_title = text(t("settings_timer_title"), size=16, bold=True)
    timer_switch = switch(t("settings_timer_switch_label"), bool(state.TIMER_ENABLED),
                          lambda e: toggle_timer_mode(ctx))
    timer_description = description(t("settings_timer_description"))
    timer_end_caption = text(t("settings_timer_end_label"), size=13, bold=True)
    timer_entry = entry(hint=t("settings_timer_placeholder"), width=130,
                        on_submit=lambda e: set_timer(ctx))
    timer_set_btn = primary_button(t("settings_timer_set_btn"), lambda e: set_timer(ctx), width=150)
    timer_row = ft.Row([timer_end_caption, timer_entry, timer_set_btn], spacing=8,
                       visible=bool(state.TIMER_ENABLED))

    timer_card = card(ft.Column([
        timer_card_title,
        timer_switch,
        timer_description,
        timer_row,
    ], spacing=10, tight=True))

    ctx.timer_switch = timer_switch
    ctx.timer_entry = timer_entry
    ctx.timer_set_btn = timer_set_btn
    ctx.timer_row = timer_row

    # ---------- Системная защита ----------
    secure_card_title = text(t("settings_secure_title"), size=16, bold=True)
    secure_switch = switch(t("settings_secure_switch_label_off"), bool(state.SECURE_ENABLED),
                           lambda e: toggle_secure_mode(ctx))
    secure_state_label = text("", size=13, bold=True, color=TEXT_MUTED)
    secure_description = description(t("settings_secure_description"))

    copy_app_path_btn = secondary_button(t("settings_copy_path_btn"),
                                         lambda e: copy_app_folder_path(ctx), width=180)

    secure_card = card(ft.Column([
        secure_card_title,
        secure_switch,
        secure_state_label,
        secure_description,
        ft.Row([copy_app_path_btn], spacing=8, wrap=True, run_spacing=8),
    ], spacing=10, tight=True))

    ctx.secure_switch = secure_switch
    ctx.secure_state_label = secure_state_label

    settings_frame = scroll_column(
        [startup_card, config_card, match_card, postpone_card, timer_card, secure_card],
        spacing=18,
    )
    ctx.settings_frame = settings_frame

    sync_postpone_ui(ctx)
    sync_secure_switch_ui(ctx)

    def retranslate_settings():
        startup_card_title.value = t("settings_protection_state_title")
        app_startup_caption.value = t("settings_startup_app_label")
        secure_startup_caption.value = t("settings_startup_guard_label")
        secure_file_caption.value = t("settings_guard_file_label")
        diagnostics_btn.content = t("settings_check_protection_btn")
        config_card_title.value = t("settings_config_title")
        config_description.value = t("settings_config_description", log_path=LOG_PATH)
        export_config_btn.content = t("settings_export_btn")
        import_config_btn.content = t("settings_import_btn")
        block_mode_card_title.value = t("settings_block_mode_title")
        block_mode_description.value = t("settings_block_mode_description")
        match_card_title.value = t("settings_match_title")
        match_description.value = t("settings_match_description")
        # Подписи сегментов — вложенные Text: значения сегментов не меняются,
        # поэтому пересобирать переключатель, как в версии на Tk, не нужно.
        block_mode_selector.segments[0].label.value = t("settings_block_mode_blacklist")
        block_mode_selector.segments[1].label.value = t("settings_block_mode_whitelist")
        match_mode_selector.segments[0].label.value = t("settings_match_contains")
        match_mode_selector.segments[1].label.value = t("settings_match_exact")
        postpone_card_title.value = t("settings_postpone_title")
        postpone_switch.label = t("settings_postpone_switch")
        postpone_description.value = t("settings_postpone_description")
        postpone_seconds_caption.value = t("settings_postpone_seconds_label")
        postpone_entry.hint_text = t("settings_postpone_placeholder")
        postpone_set_btn.content = t("settings_postpone_set_btn")
        timer_card_title.value = t("settings_timer_title")
        timer_switch.label = t("settings_timer_switch_label")
        timer_description.value = t("settings_timer_description")
        timer_end_caption.value = t("settings_timer_end_label")
        timer_entry.hint_text = t("settings_timer_placeholder")
        timer_set_btn.content = t("settings_timer_set_btn")
        secure_card_title.value = t("settings_secure_title")
        secure_description.value = t("settings_secure_description")
        copy_app_path_btn.content = t("settings_copy_path_btn")
        sync_postpone_ui(ctx)
        sync_secure_switch_ui(ctx)
        update_startup_status_labels(ctx)
        ctx.refresh(settings_frame)

    register_retranslate(retranslate_settings)

    ctx.update_startup_status_labels = lambda: update_startup_status_labels(ctx)
    ctx.sync_secure_switch_ui = lambda: sync_secure_switch_ui(ctx)
    ctx.sync_match_mode_selector = lambda: sync_match_mode_selector(ctx)
    ctx.sync_block_mode_selector = lambda: sync_block_mode_selector(ctx)
    ctx.sync_postpone_ui = lambda: sync_postpone_ui(ctx)
    ctx.sync_timer_ui = lambda: sync_timer_ui(ctx)
    ctx.lock_timer_controls = lambda: lock_timer_controls(ctx)
    ctx.lock_mode_selectors = lambda: lock_mode_selectors(ctx)
    ctx.toggle_secure_mode = lambda: toggle_secure_mode(ctx)
    ctx.run_diagnostics = lambda: run_diagnostics(ctx)

    return settings_frame
