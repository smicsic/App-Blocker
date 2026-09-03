"""Вкладка «Статистика»: дашборд по срабатываниям блокировки и экспорт в CSV.

Данные читаются из stats.json через appcore.stats — вкладка только показывает
посчитанное и ничего не считает сама.
"""
import datetime

import flet as ft

from appcore.i18n import register_retranslate, t
from appcore.logging_util import log
from appcore.stats import (
    clear_stats,
    export_stats_csv,
    format_duration,
    load_stats,
    summarize,
)
from appcore.theme import TEXT_MAIN, TEXT_MUTED
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

# Сколько последних событий показываем в списке: файл может хранить тысячи,
# а перерисовка каждой строки контролами дорогая.
RECENT_EVENTS_LIMIT = 60


def refresh_stats(ctx):
    """Перечитывает stats.json и обновляет все показатели вкладки."""
    data = load_stats()
    totals = summarize(data)

    ctx.stats_today_value.value = str(totals["today_count"])
    ctx.stats_week_value.value = str(totals["week_count"])
    ctx.stats_time_today_value.value = format_duration(totals["today_seconds"])
    ctx.stats_time_total_value.value = format_duration(totals["total_seconds"])
    ctx.stats_total_events_label.value = t("stats_total_events", count=totals["total_events"])

    # ---------- Топ-3 ----------
    if totals["top_targets"]:
        ctx.stats_top_box.controls = [
            row_surface(text(
                t("stats_top_row", position=position, target=target, count=count),
                size=12, mono=True,
            ))
            for position, (target, count) in enumerate(totals["top_targets"], start=1)
        ]
    else:
        ctx.stats_top_box.controls = [text(t("stats_top_empty"), color=TEXT_MUTED)]

    # ---------- Последние события ----------
    events = data.get("events", [])
    if not events:
        ctx.stats_events_box.controls = [text(t("stats_events_empty"), color=TEXT_MUTED)]
    else:
        rows = []
        for event in reversed(events[-RECENT_EVENTS_LIMIT:]):
            try:
                moment = datetime.datetime.fromisoformat(event.get("timestamp", ""))
                stamp = moment.strftime("%d.%m %H:%M:%S")
            except Exception:
                stamp = "—"
            kind_key = "stats_kind_site" if event.get("kind") == "site" else "stats_kind_program"
            rows.append(row_surface(ft.Row([
                text(stamp, size=12, mono=True, color=TEXT_MUTED, width=110),
                text(event.get("target", ""), size=12, mono=True, color=TEXT_MAIN, expand=True,
                     no_wrap=True, overflow=ft.TextOverflow.ELLIPSIS),
                text(t(kind_key), size=11, color=TEXT_MUTED),
            ], spacing=8)))
        ctx.stats_events_box.controls = fly_in_rows(ctx, rows)

    ctx.refresh(
        ctx.stats_today_value, ctx.stats_week_value, ctx.stats_time_today_value,
        ctx.stats_time_total_value, ctx.stats_total_events_label,
        ctx.stats_top_box, ctx.stats_events_box,
    )


async def export_csv(ctx):
    target = await ctx.file_picker.save_file(
        dialog_title=t("dialog_export_stats_title"),
        file_name="appblocker-stats.csv",
        file_type=ft.FilePickerFileType.CUSTOM,
        allowed_extensions=["csv"],
    )
    if target:
        ctx.run_bg(export_stats_csv, target)


def clear_history(ctx):
    from gui.dialogs import yes_no_dialog

    def on_answer(confirmed):
        if not confirmed:
            return
        if clear_stats():
            log(t("log_stats_cleared"))
        refresh_stats(ctx)

    yes_no_dialog(ctx, t("dialog_clear_stats_title"), t("dialog_clear_stats_message"), on_answer)


def build(ctx):
    # ---------- Показатели ----------
    today_card, today_caption, stats_today_value = stat_card(t("stats_card_today"))
    week_card, week_caption, stats_week_value = stat_card(t("stats_card_week"))
    time_today_card, time_today_caption, stats_time_today_value = stat_card(t("stats_card_time_today"))
    time_total_card, time_total_caption, stats_time_total_value = stat_card(t("stats_card_time_total"))

    # ---------- Топ-3 ----------
    stats_top_title = text(t("stats_top_title"), size=16, bold=True)
    stats_top_box = ft.Column(spacing=4, tight=True,
                              horizontal_alignment=ft.CrossAxisAlignment.STRETCH)
    top_card = card(stretch_column([stats_top_title, sunken_box(stats_top_box)], tight=True))

    # ---------- Последние события ----------
    stats_events_title = text(t("stats_events_title"), size=16, bold=True)
    stats_events_box = scroll_column(spacing=4, expand=True)
    stats_total_events_label = text("", size=12, color=TEXT_MUTED)

    export_csv_btn = primary_button(t("stats_export_csv_btn"),
                                    lambda e: ctx.run_async(export_csv, ctx), width=190)
    refresh_btn = secondary_button(t("stats_refresh_btn"), lambda e: refresh_stats(ctx), width=150)
    # Разрушающее действие: краснеет только при наведении.
    clear_btn = danger_button(t("stats_clear_btn"), lambda e: clear_history(ctx), width=190)

    events_card = card(
        stretch_column([
            stats_events_title,
            sunken_box(stats_events_box, expand=True),
            stats_total_events_label,
            ft.Row([export_csv_btn, refresh_btn, clear_btn], spacing=8, wrap=True, run_spacing=8),
        ], expand=True),
        expand=True,
    )

    stats_frame = stretch_column(
        [
            ft.Row([today_card, week_card, time_today_card, time_total_card], spacing=12),
            top_card,
            events_card,
        ],
        spacing=18,
        expand=True,
    )

    ctx.stats_frame = stats_frame
    ctx.stats_today_value = stats_today_value
    ctx.stats_week_value = stats_week_value
    ctx.stats_time_today_value = stats_time_today_value
    ctx.stats_time_total_value = stats_time_total_value
    ctx.stats_top_box = stats_top_box
    ctx.stats_events_box = stats_events_box
    ctx.stats_total_events_label = stats_total_events_label
    ctx.refresh_stats = lambda: refresh_stats(ctx)

    refresh_stats(ctx)

    def retranslate_stats():
        today_caption.value = t("stats_card_today")
        week_caption.value = t("stats_card_week")
        time_today_caption.value = t("stats_card_time_today")
        time_total_caption.value = t("stats_card_time_total")
        stats_top_title.value = t("stats_top_title")
        stats_events_title.value = t("stats_events_title")
        export_csv_btn.content = t("stats_export_csv_btn")
        refresh_btn.content = t("stats_refresh_btn")
        clear_btn.content = t("stats_clear_btn")
        # Строки списков и подписи времени собираются из t() на месте.
        refresh_stats(ctx)
        ctx.refresh(stats_frame)

    register_retranslate(retranslate_stats)

    return stats_frame
