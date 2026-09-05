"""Отправка команд клиентам через WebSocket relay (WAN-режим).

Формат сообщений между Admin/Client и relay — конверт::

    {"to": "<client_id>" | "*", "from": "<admin_id>", "payload": {...Command/Response...}}

Сама команда/ответ (``payload``) — та же схема, что в LAN-режиме
(``appcore.network.protocol``), relay её не трогает, только маршрутизирует по
``to``. Каждый вызов открывает своё WebSocket-соединение с relay, отправляет
один конверт и ждёт ответный — это проще, чем держать одно долгоживущее
соединение ради отдельных команд, и не мешает Client держать своё постоянное
соединение (см. AppBlocker_Client/connection_handler.py).
"""
import asyncio
import json
import time
import uuid

from appcore.network import auth_store
from appcore.network.protocol import Command, Response

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except Exception:
    websockets = None
    WEBSOCKETS_AVAILABLE = False


def admin_identity():
    """Устойчивый идентификатор этого Admin для relay (не меняется между запусками)."""
    from appcore.paths import REMOTE_ADMIN_CONFIG_DIR
    import os

    id_path = os.path.join(REMOTE_ADMIN_CONFIG_DIR, "admin_id")
    if os.path.exists(id_path):
        try:
            with open(id_path, "r", encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value
        except Exception:
            pass
    value = f"admin-{uuid.uuid4().hex[:12]}"
    try:
        with open(id_path, "w", encoding="utf-8") as f:
            f.write(value)
    except Exception:
        pass
    return value


async def send_command(relay_url, client_id, action, target=None, timeout=8.0):
    """Отправляет команду конкретному client_id через relay и ждёт ответ."""
    if not WEBSOCKETS_AVAILABLE:
        return Response(status="error", client_id=client_id, message="Библиотека websockets не установлена")

    token = auth_store.get_client_token(client_id)
    command = Command(action=action, target=target, token=token, timestamp=time.time())
    envelope = {"to": client_id, "from": admin_identity(), "payload": command.to_dict()}

    try:
        async with websockets.connect(relay_url, open_timeout=timeout) as ws:
            await ws.send(json.dumps(envelope, ensure_ascii=False))
            raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    except Exception as e:
        return Response(status="error", client_id=client_id, message=f"Ошибка relay: {e}")

    try:
        incoming = json.loads(raw)
        payload = incoming.get("payload", incoming)
        response = Response.from_dict(payload)
    except Exception as e:
        return Response(status="error", client_id=client_id, message=f"Некорректный ответ relay: {e}")

    if response.issued_token and response.client_id:
        auth_store.remember_client(response.client_id, ip="relay", port=0, token=response.issued_token)

    return response
