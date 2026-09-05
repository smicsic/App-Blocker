"""Приём подключений от Admin: TCP-команды, UDP-discovery, WAN через relay.

Consent-диалог и выполнение команды идут в одном asyncio-цикле, что и Flet-
страница (``main.py`` поднимает серверы через ``page.run_task``), поэтому
диалог можно показывать прямо из обработчика подключения — ждать ответ
пользователя через ``await`` безопасно, это не блокирует ничего постороннего.
"""
import asyncio
import json
import socket

import auth
import blocklist
from protocol import (
    ACTION_BLOCK,
    ACTION_DISCOVER,
    ACTION_GET_STATUS,
    ACTION_PING,
    ACTION_UNBLOCK,
    DEFAULT_PORT,
    Command,
    Response,
    read_json_line,
    write_json_line,
)

CLIENT_ID = socket.gethostname() or "AppBlockerClient"

_page = None


def set_page(page):
    global _page
    _page = page


def log(message):
    import datetime
    from paths import LOG_PATH

    line = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(line)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


async def _ask_consent(sender, ip):
    """Показывает диалог согласия и ждёт ответа пользователя. Без интерфейса — всегда отказ."""
    if _page is None:
        return False

    loop = asyncio.get_event_loop()
    future = loop.create_future()

    def on_result(accepted):
        if not future.done():
            future.set_result(bool(accepted))

    from dialogs import show_consent_dialog

    show_consent_dialog(_page, sender, ip, on_result)
    return await future


def _execute(command):
    if command.action == ACTION_BLOCK:
        if not command.target:
            return Response(status="error", client_id=CLIENT_ID, message="target не указан")
        blocklist.block(command.target)
        log(f"🚫 Заблокировано по команде Admin: {command.target}")
        return Response(status="ok", client_id=CLIENT_ID, message=f"Заблокировано: {command.target}",
                         blocked_apps=blocklist.blocked_apps())

    if command.action == ACTION_UNBLOCK:
        if not command.target:
            return Response(status="error", client_id=CLIENT_ID, message="target не указан")
        blocklist.unblock(command.target)
        log(f"✅ Разблокировано по команде Admin: {command.target}")
        return Response(status="ok", client_id=CLIENT_ID, message=f"Разблокировано: {command.target}",
                         blocked_apps=blocklist.blocked_apps())

    if command.action == ACTION_GET_STATUS:
        return Response(status="ok", client_id=CLIENT_ID, message="OK", blocked_apps=blocklist.blocked_apps())

    if command.action == ACTION_PING:
        return Response(status="ok", client_id=CLIENT_ID, message="pong")

    return Response(status="error", client_id=CLIENT_ID, message=f"Неизвестное действие: {command.action}")


async def process_command(command, sender_ip):
    """Проверяет доверие (или запрашивает согласие) и выполняет команду."""
    if auth.is_trusted_token(command.token):
        return _execute(command)

    accepted = await _ask_consent(command.sender, sender_ip)
    if not accepted:
        log(f"🚫 Подключение от {command.sender} ({sender_ip}) отклонено пользователем.")
        return Response(status="denied", client_id=CLIENT_ID, message="Подключение отклонено пользователем")

    token = auth.issue_token(command.sender, sender_ip)
    log(f"✅ Подключение от {command.sender} ({sender_ip}) разрешено, выдан новый токен доверия.")
    response = _execute(command)
    response.issued_token = token
    return response


# ---------- LAN: TCP-команды ----------

async def _handle_tcp_connection(reader, writer):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else "?"
    try:
        raw = await asyncio.wait_for(read_json_line(reader), timeout=10.0)
        if raw is None:
            return
        command = Command.from_dict(raw)
        response = await process_command(command, ip)
        write_json_line(writer, response)
        await writer.drain()
    except Exception as e:
        log(f"⚠️ Ошибка обработки подключения от {ip}: {e}")
        try:
            write_json_line(writer, Response(status="error", client_id=CLIENT_ID, message="internal error"))
            await writer.drain()
        except Exception:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_tcp_server(port=DEFAULT_PORT):
    server = await asyncio.start_server(_handle_tcp_connection, "0.0.0.0", port)
    log(f"🖥 TCP-сервер команд слушает на порту {port}")
    return server


# ---------- LAN: UDP-discovery ----------

class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, port):
        self.transport = None
        self.port = port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            payload = json.loads(data.decode("utf-8", errors="replace"))
        except Exception:
            return
        if payload.get("action") != ACTION_DISCOVER:
            return
        reply = json.dumps({"status": "ok", "client_id": CLIENT_ID, "tcp_port": self.port}).encode("utf-8")
        try:
            self.transport.sendto(reply, addr)
        except Exception:
            pass

    def error_received(self, exc):
        pass


async def start_udp_discovery_responder(port=DEFAULT_PORT):
    loop = asyncio.get_event_loop()
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _DiscoveryProtocol(port), local_addr=("0.0.0.0", port), allow_broadcast=True,
    )
    log(f"📡 UDP-discovery слушает на порту {port}")
    return transport


# ---------- WAN: постоянное соединение с relay-сервером ----------

async def run_wan_client(relay_url, reconnect_delay=5.0):
    """Держит соединение с relay и отвечает на команды, приходящие через него.

    Переподключается при разрыве — WAN-режим не должен требовать ручного
    вмешательства, если relay перезапустился или сеть моргнула.
    """
    try:
        import websockets
    except Exception:
        log("⚠️ Библиотека websockets не установлена — WAN-режим недоступен.")
        return

    while True:
        try:
            async with websockets.connect(relay_url) as ws:
                log(f"🌐 Подключено к relay-серверу: {relay_url}")
                await ws.send(json.dumps({"to": None, "from": CLIENT_ID, "payload": {"hello": "client"}}))
                async for raw in ws:
                    try:
                        envelope = json.loads(raw)
                        payload = envelope.get("payload") or {}
                        if "action" not in payload:
                            continue
                        command = Command.from_dict(payload)
                        response = await process_command(command, envelope.get("from", "relay"))
                        await ws.send(json.dumps(
                            {"to": envelope.get("from"), "from": CLIENT_ID, "payload": response.to_dict()},
                            ensure_ascii=False,
                        ))
                    except Exception as e:
                        log(f"⚠️ Ошибка обработки сообщения relay: {e}")
        except Exception as e:
            log(f"⚠️ Соединение с relay потеряно: {e}. Повтор через {reconnect_delay:.0f} с.")
            await asyncio.sleep(reconnect_delay)
