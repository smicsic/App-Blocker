"""Вкладка «Remote Admin»: удалённое управление клиентами AppBlocker_Client.

Вкладка защищена собственным паролем (appcore.network.auth_store, файл Pass —
не путать с паролем выхода из самого AppBlocker). До ввода пароля показывается
только форма входа; после — управление клиентами. Сетевые вызовы асинхронные
(``ctx.run_async``) — тот же мост в цикл событий Flet, что используют
остальные вкладки для фоновой работы.
"""
import flet as ft

from appcore.i18n import register_retranslate, t
from appcore.logging_util import log
from appcore.network import auth_store
from appcore.network.admin_connector import send_command as lan_send_command
from appcore.network.admin_connector_wan import send_command as wan_send_command
from appcore.network.lan_discovery import scan as lan_scan
from appcore.network.protocol import (
    ACTION_BLOCK,
    ACTION_GET_STATUS,
    ACTION_PING,
    ACTION_UNBLOCK,
    DEFAULT_PORT,
)
from appcore.theme import ERROR, PRIMARY, SUCCESS, TEXT_MUTED
from gui.common import (
    card,
    description,
    entry,
    primary_button,
    row_surface,
    scroll_column,
    secondary_button,
    switch,
    text,
)
from gui.dialogs import yes_no_dialog

ALL_CLIENTS_KEY = "*"

ACTION_LABEL_KEYS = {
    ACTION_BLOCK: "log_remote_admin_action_block",
    ACTION_UNBLOCK: "log_remote_admin_action_unblock",
    ACTION_GET_STATUS: "log_remote_admin_action_status",
    ACTION_PING: "log_remote_admin_action_ping",
}

# client_id -> {"ip": str, "port": int, "online": bool}
_clients = {}


def _mode_is_wan(ctx):
    return bool(ctx.remote_admin_mode_switch.value)


def _sync_mode_ui(ctx):
    wan = _mode_is_wan(ctx)
    ctx.remote_admin_relay_row.visible = wan
    ctx.remote_admin_scan_btn.visible = not wan
    ctx.remote_admin_manual_ip_entry.visible = not wan
    ctx.remote_admin_manual_add_btn.visible = not wan
    ctx.refresh(ctx.remote_admin_relay_row, ctx.remote_admin_scan_btn,
                ctx.remote_admin_manual_ip_entry, ctx.remote_admin_manual_add_btn)


def _refresh_target_options(ctx):
    options = [ft.dropdown.DropdownOption(key=ALL_CLIENTS_KEY, text=t("remote_admin_all_clients_option"))]
    for client_id in sorted(_clients):
        options.append(ft.dropdown.DropdownOption(key=client_id, text=client_id))
    ctx.remote_admin_target_dropdown.options = options
    if ctx.remote_admin_target_dropdown.value not in {o.key for o in options}:
        ctx.remote_admin_target_dropdown.value = ALL_CLIENTS_KEY
    ctx.refresh(ctx.remote_admin_target_dropdown)


def _render_clients(ctx):
    rows = []
    for client_id in sorted(_clients):
        info = _clients[client_id]
        status_color = SUCCESS if info.get("online") else TEXT_MUTED
        status_label = t("remote_admin_status_online") if info.get("online") else t("remote_admin_status_offline")
        rows.append(row_surface(ft.Row(
            [
                text(client_id, size=13, bold=True, expand=True),
                text(info.get("ip", ""), size=12, mono=True, color=TEXT_MUTED),
                text(status_label, size=12, color=status_color),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )))
    if not rows:
        rows = [text(t("remote_admin_clients_empty"), color=TEXT_MUTED)]
    ctx.remote_admin_clients_list.controls = rows
    ctx.remote_admin_clients_status.value = t("remote_admin_clients_count", count=len(_clients))
    ctx.refresh(ctx.remote_admin_clients_list, ctx.remote_admin_clients_status)
    _refresh_target_options(ctx)


async def _scan_task(ctx):
    log(t("log_remote_admin_scanning"))
    found = await lan_scan(timeout=2.0, port=DEFAULT_PORT)
    for client in found:
        entry_data = _clients.setdefault(client.client_id, {})
        entry_data["ip"] = client.ip
        entry_data["port"] = client.port
        entry_data["online"] = True
    log(t("log_remote_admin_scan_done", count=len(found)))
    _render_clients(ctx)


async def _manual_add_task(ctx):
    ip = (ctx.remote_admin_manual_ip_entry.value or "").strip()
    if not ip:
        return
    response = await lan_send_command(ip, DEFAULT_PORT, ACTION_PING, timeout=4.0)
    if response.status == "ok":
        _clients[response.client_id] = {"ip": ip, "port": DEFAULT_PORT, "online": True}
        log(t("log_remote_admin_manual_added", client_id=response.client_id, ip=ip))
        ctx.remote_admin_manual_ip_entry.value = ""
        ctx.refresh(ctx.remote_admin_manual_ip_entry)
        _render_clients(ctx)
    else:
        log(t("log_remote_admin_manual_add_failed", ip=ip, message=response.message))


def _selected_client_ids(ctx):
    value = ctx.remote_admin_target_dropdown.value or ALL_CLIENTS_KEY
    if value == ALL_CLIENTS_KEY:
        return list(_clients.keys())
    return [value] if value in _clients else []


async def _command_task(ctx, action):
    target = (ctx.remote_admin_target_entry.value or "").strip() or None
    if action in (ACTION_BLOCK, ACTION_UNBLOCK) and not target:
        log(t("log_remote_admin_target_required"))
        return

    client_ids = _selected_client_ids(ctx)
    if not client_ids:
        log(t("log_remote_admin_no_clients"))
        return

    action_label = t(ACTION_LABEL_KEYS.get(action, action))
    wan = _mode_is_wan(ctx)
    relay_url = (ctx.remote_admin_relay_entry.value or "").strip()

    for client_id in client_ids:
        info = _clients.get(client_id, {})
        try:
            if wan:
                if not relay_url:
                    log(t("log_remote_admin_relay_missing"))
                    return
                response = await wan_send_command(relay_url, client_id, action, target=target)
            else:
                response = await lan_send_command(
                    info.get("ip"), info.get("port", DEFAULT_PORT), action,
                    target=target, client_id=client_id,
                )
        except Exception as e:
            log(t("log_remote_admin_command_error", client=client_id, action=action_label, error=e))
            continue

        _clients.setdefault(client_id, {})["online"] = response.status in ("ok", "denied")
        if response.status == "ok":
            log(t("log_remote_admin_command_ok", client=response.client_id or client_id,
                  action=action_label, message=response.message))
        elif response.status == "denied":
            log(t("log_remote_admin_command_denied", client=client_id))
        else:
            log(t("log_remote_admin_command_failed", client=client_id,
                  action=action_label, message=response.message))

    _render_clients(ctx)


def _unlock(ctx):
    ctx.remote_admin_lock_view.visible = False
    ctx.remote_admin_content_view.visible = True
    ctx.refresh(ctx.remote_admin_lock_view, ctx.remote_admin_content_view)


def _apply_lock_mode(ctx):
    first_time = not auth_store.has_password()
    ctx.remote_admin_is_first_time = first_time
    ctx.remote_admin_lock_title.value = (
        t("remote_admin_set_password_title") if first_time else t("remote_admin_enter_password_title")
    )
    ctx.remote_admin_lock_description.value = (
        t("remote_admin_set_password_description") if first_time else t("remote_admin_enter_password_description")
    )
    ctx.remote_admin_unlock_btn.content = (
        t("remote_admin_set_password_btn") if first_time else t("remote_admin_unlock_btn")
    )
    ctx.remote_admin_forgot_btn.visible = not first_time
    ctx.remote_admin_password_entry.value = ""
    ctx.remote_admin_password_status.value = ""
    ctx.refresh(
        ctx.remote_admin_lock_title, ctx.remote_admin_lock_description,
        ctx.remote_admin_unlock_btn, ctx.remote_admin_forgot_btn,
        ctx.remote_admin_password_entry, ctx.remote_admin_password_status,
    )


def _submit_password(ctx):
    value = ctx.remote_admin_password_entry.value or ""
    if ctx.remote_admin_is_first_time:
        if len(value) < 4:
            ctx.remote_admin_password_status.value = t("remote_admin_password_too_short")
            ctx.refresh(ctx.remote_admin_password_status)
            return
        auth_store.set_password(value)
        log(t("log_remote_admin_password_set"))
        _unlock(ctx)
        return

    if auth_store.verify_password(value):
        _unlock(ctx)
    else:
        ctx.remote_admin_password_status.value = t("remote_admin_wrong_password")
        ctx.refresh(ctx.remote_admin_password_status)


def _forgot_password(ctx):
    def on_answer(confirmed):
        if not confirmed:
            return
        auth_store.reset_password()
        log(t("log_remote_admin_password_reset"))
        _apply_lock_mode(ctx)

    yes_no_dialog(
        ctx,
        t("remote_admin_forgot_password_title"),
        t("remote_admin_forgot_password_confirm"),
        on_answer,
    )


def build(ctx):
    # ---------- Экран блокировки паролем ----------
    lock_title = text("", size=18, bold=True)
    lock_description = description("")
    password_entry = entry(hint=t("remote_admin_password_hint"), password=True, width=280,
                            on_submit=lambda e: _submit_password(ctx))
    password_status = text("", size=13, color=ERROR)
    unlock_btn = primary_button("", lambda e: _submit_password(ctx), width=200)
    forgot_btn = secondary_button(t("remote_admin_forgot_password_btn"),
                                   lambda e: _forgot_password(ctx), width=220, visible=False)

    lock_card = card(ft.Column(
        [lock_title, lock_description, password_entry, password_status, unlock_btn, forgot_btn],
        spacing=12, tight=True,
    ), padding=24)
    lock_view = ft.Container(content=lock_card, alignment=ft.alignment.Alignment(0, 0), expand=True)

    # ---------- Режим LAN/WAN ----------
    mode_switch = switch(t("remote_admin_mode_wan_label"), False, lambda e: _sync_mode_ui(ctx))
    relay_entry = entry(hint=t("remote_admin_relay_hint"), width=380)
    relay_row = ft.Row(
        [text(t("remote_admin_relay_label"), size=13), relay_entry],
        visible=False, spacing=8,
    )
    mode_card = card(ft.Column([
        text(t("remote_admin_mode_title"), size=16, bold=True),
        description(t("remote_admin_mode_description")),
        mode_switch,
        relay_row,
    ], spacing=10, tight=True))

    # ---------- Клиенты ----------
    scan_btn = primary_button(t("remote_admin_scan_btn"), lambda e: ctx.run_async(_scan_task, ctx), width=180)
    manual_ip_entry = entry(hint=t("remote_admin_manual_ip_hint"), width=200)
    manual_add_btn = secondary_button(t("remote_admin_manual_add_btn"),
                                       lambda e: ctx.run_async(_manual_add_task, ctx), width=170)
    clients_status = text(t("remote_admin_clients_count", count=0), size=13, color=TEXT_MUTED)
    clients_list = scroll_column(spacing=6, expand=False, height=200)

    clients_card = card(ft.Column([
        text(t("remote_admin_clients_title"), size=16, bold=True),
        ft.Row([scan_btn, manual_ip_entry, manual_add_btn], spacing=8, wrap=True, run_spacing=8),
        clients_status,
        clients_list,
    ], spacing=10, tight=True))

    # ---------- Команды ----------
    target_dropdown = ft.Dropdown(
        value=ALL_CLIENTS_KEY,
        options=[ft.dropdown.DropdownOption(key=ALL_CLIENTS_KEY, text=t("remote_admin_all_clients_option"))],
        width=260,
    )
    target_entry = entry(hint=t("remote_admin_target_hint"), width=260)
    block_btn = primary_button(t("remote_admin_block_btn"),
                                lambda e: ctx.run_async(_command_task, ctx, ACTION_BLOCK), width=150)
    unblock_btn = secondary_button(t("remote_admin_unblock_btn"),
                                    lambda e: ctx.run_async(_command_task, ctx, ACTION_UNBLOCK), width=150)
    status_btn = secondary_button(t("remote_admin_status_btn"),
                                   lambda e: ctx.run_async(_command_task, ctx, ACTION_GET_STATUS), width=150)
    ping_btn = secondary_button(t("remote_admin_ping_btn"),
                                 lambda e: ctx.run_async(_command_task, ctx, ACTION_PING), width=150)

    commands_card = card(ft.Column([
        text(t("remote_admin_commands_title"), size=16, bold=True),
        description(t("remote_admin_commands_description")),
        ft.Row([text(t("remote_admin_target_client_label"), size=13), target_dropdown], spacing=8),
        target_entry,
        ft.Row([block_btn, unblock_btn, status_btn, ping_btn], spacing=8, wrap=True, run_spacing=8),
    ], spacing=10, tight=True))

    content_view = ft.Container(
        content=scroll_column([mode_card, clients_card, commands_card], spacing=18),
        expand=True, visible=False,
    )

    root = ft.Column([lock_view, content_view], expand=True)

    # ---------- ctx refs ----------
    ctx.remote_admin_lock_view = lock_view
    ctx.remote_admin_content_view = content_view
    ctx.remote_admin_lock_title = lock_title
    ctx.remote_admin_lock_description = lock_description
    ctx.remote_admin_password_entry = password_entry
    ctx.remote_admin_password_status = password_status
    ctx.remote_admin_unlock_btn = unlock_btn
    ctx.remote_admin_forgot_btn = forgot_btn
    ctx.remote_admin_is_first_time = not auth_store.has_password()
    ctx.remote_admin_mode_switch = mode_switch
    ctx.remote_admin_relay_row = relay_row
    ctx.remote_admin_relay_entry = relay_entry
    ctx.remote_admin_scan_btn = scan_btn
    ctx.remote_admin_manual_ip_entry = manual_ip_entry
    ctx.remote_admin_manual_add_btn = manual_add_btn
    ctx.remote_admin_clients_list = clients_list
    ctx.remote_admin_clients_status = clients_status
    ctx.remote_admin_target_dropdown = target_dropdown
    ctx.remote_admin_target_entry = target_entry

    _apply_lock_mode(ctx)
    _render_clients(ctx)

    def retranslate():
        _apply_lock_mode(ctx)
        mode_switch.label = t("remote_admin_mode_wan_label")
        relay_entry.hint_text = t("remote_admin_relay_hint")
        scan_btn.content = t("remote_admin_scan_btn")
        manual_ip_entry.hint_text = t("remote_admin_manual_ip_hint")
        manual_add_btn.content = t("remote_admin_manual_add_btn")
        target_entry.hint_text = t("remote_admin_target_hint")
        block_btn.content = t("remote_admin_block_btn")
        unblock_btn.content = t("remote_admin_unblock_btn")
        status_btn.content = t("remote_admin_status_btn")
        ping_btn.content = t("remote_admin_ping_btn")
        _render_clients(ctx)
        ctx.refresh(root)

    register_retranslate(retranslate)

    return root
