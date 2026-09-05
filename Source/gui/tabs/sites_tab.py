"""Вкладка «Сайты»: блокировка доменов через hosts."""
import flet as ft

from appcore import state
from appcore.config_store import save_config
from appcore.i18n import register_retranslate, t
from appcore.logging_util import log
from appcore.security import ensure_app_startup_entries, ensure_appblocker_guard, start_guard_watch_thread
from appcore.sites import (
    apply_hosts_block,
    load_blocked_sites,
    normalize_sites,
    parse_sites_input,
    restart_browsers_for_site_block,
    save_blocked_sites,
)
from appcore.theme import TEXT_MUTED
from gui.common import (
    danger_button,
    entry,
    primary_button,
    row_surface,
    scroll_column,
    secondary_button,
    stretch_column,
    sunken_box,
    text,
)


def refresh_sites_list(ctx):
    sites = load_blocked_sites()
    if sites:
        ctx.sites_list.controls = [
            row_surface(text(site, size=12, mono=True)) for site in sites
        ]
    else:
        ctx.sites_list.controls = [text(t("sites_list_empty"), color=TEXT_MUTED)]
    ctx.sites_status_label.value = t("sites_count", count=len(sites))
    ctx.refresh(ctx.sites_list, ctx.sites_status_label)


def _clear_entry(ctx):
    ctx.site_entry.value = ""
    ctx.refresh(ctx.site_entry)


def add_site(ctx):
    new_sites = parse_sites_input(ctx.site_entry.value or "")
    if not new_sites:
        log(t("log_enter_site_domain"))
        return
    sites = load_blocked_sites()
    target_sites = normalize_sites(sites + new_sites)
    added = [site for site in new_sites if site not in sites]
    if added:
        save_blocked_sites(target_sites)
        _clear_entry(ctx)
        refresh_sites_list(ctx)
        log(t("log_sites_added", count=len(added)))
    else:
        log(t("log_sites_already_blocked"))


def start_site_blocking(ctx):
    """Включает блокировку сайтов. Блокирующая (hosts, реестр) — только из потока."""
    typed_sites = parse_sites_input(ctx.site_entry.value or "")
    sites = normalize_sites(load_blocked_sites() + typed_sites)
    if not sites:
        log(t("log_add_at_least_one_site"))
        return

    if typed_sites:
        save_blocked_sites(sites)
        ctx.ui(_clear_entry, ctx)

    if not apply_hosts_block(sites):
        return
    # Помечаем ручное включение: расписание не должно снимать эту блокировку,
    # когда закончится его собственное окно.
    state.SITES_BLOCKED_MANUALLY = True
    restart_browsers_for_site_block()

    save_config(status="RUNNING")
    ensure_app_startup_entries(on_status_update=ctx.update_startup_status_labels)

    if state.SECURE_ENABLED and ensure_appblocker_guard():
        log(t("log_guard_activated_for_sites"))

    if state.SECURE_ENABLED:
        start_guard_watch_thread("log_guard_watch_started_sites")

    ctx.ui(refresh_sites_list, ctx)
    ctx.ui(ctx.update_status_cards)
    log(t("log_sites_enabled", count=len(sites)))


def remove_site(ctx):
    """Убирает домены из списка. Блокирующая (hosts) — только из потока."""
    remove_sites = parse_sites_input(ctx.site_entry.value or "")
    if not remove_sites:
        log(t("log_enter_site_to_remove"))
        return
    sites = load_blocked_sites()
    target_sites = [site for site in sites if site not in remove_sites]
    removed = [site for site in remove_sites if site in sites]
    if removed:
        if apply_hosts_block(target_sites):
            save_blocked_sites(target_sites)
            ctx.ui(_clear_entry, ctx)
            ctx.ui(refresh_sites_list, ctx)
            log(t("log_sites_removed", count=len(removed)))
    else:
        log(t("log_sites_not_in_list"))


def clear_all_sites(ctx):
    """Снимает блокировку со всех сайтов. Блокирующая — только из потока."""
    if apply_hosts_block([]):
        state.SITES_BLOCKED_MANUALLY = False
        save_blocked_sites([])
        ctx.ui(refresh_sites_list, ctx)
        ctx.ui(_clear_entry, ctx)
        log(t("log_sites_cleared"))


def build(ctx):
    sites_status_label = text(t("sites_count", count=0), size=15, bold=True, color=TEXT_MUTED)
    sites_list = scroll_column(spacing=4, expand=True)
    # Без expand: в колонке он растягивал бы поле по ВЕРТИКАЛИ и оставлял пустую
    # полосу до кнопок. По ширине поле и так занимает всю строку — колонка
    # растягивает детей сама (см. stretch_column).
    site_entry = entry(hint=t("sites_entry_placeholder"),
                       on_submit=lambda e: add_site(ctx))

    add_btn = primary_button(t("sites_add_btn"), lambda e: add_site(ctx), width=130)
    remove_btn = secondary_button(t("sites_remove_btn"),
                                  lambda e: ctx.run_bg(remove_site, ctx), width=130)
    apply_sites_btn = primary_button(t("sites_enable_btn"),
                                     lambda e: ctx.run_bg(start_site_blocking, ctx), width=140)
    # Разрушающее действие: краснеет только при наведении.
    clear_sites_btn = danger_button(t("sites_clear_all_btn"),
                                    lambda e: ctx.run_bg(clear_all_sites, ctx), width=150)

    sites_frame = stretch_column(
        [
            sites_status_label,
            sunken_box(sites_list, expand=True),
            site_entry,
            ft.Row(
                [add_btn, remove_btn, apply_sites_btn, clear_sites_btn],
                spacing=8,
                wrap=True,
                run_spacing=8,
            ),
        ],
        spacing=12,
        expand=True,
    )

    ctx.sites_frame = sites_frame
    ctx.sites_status_label = sites_status_label
    ctx.sites_list = sites_list
    ctx.site_entry = site_entry
    # Используется вкладкой «Мониторинг» для блокировки после запуска.
    ctx.remove_site_btn = remove_btn

    def retranslate_sites():
        site_entry.hint_text = t("sites_entry_placeholder")
        add_btn.content = t("sites_add_btn")
        remove_btn.content = t("sites_remove_btn")
        apply_sites_btn.content = t("sites_enable_btn")
        clear_sites_btn.content = t("sites_clear_all_btn")
        refresh_sites_list(ctx)
        ctx.refresh(site_entry, add_btn, remove_btn, apply_sites_btn, clear_sites_btn)

    register_retranslate(retranslate_sites)

    ctx.refresh_sites_list = lambda: refresh_sites_list(ctx)
    ctx.add_site = lambda: add_site(ctx)
    ctx.remove_site = lambda: ctx.run_bg(remove_site, ctx)
    ctx.clear_all_sites = lambda: ctx.run_bg(clear_all_sites, ctx)
    ctx.start_site_blocking = lambda: ctx.run_bg(start_site_blocking, ctx)

    return sites_frame
