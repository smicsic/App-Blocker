"""WebSocket-relay для WAN-режима Remote Admin.

Ничего не знает о протоколе Command/Response — только маршрутизирует конверты
``{"to": id | "*" | None, "from": id, "payload": {...}}`` между подключёнными
Admin и Client по значению ``to``. Реальная авторизация — на уровне
Command.token, который проверяет Client (см. AppBlocker_Client/auth.py);
relay — просто провод, ему доверять не обязательно, только соединение с ним
должно идти по wss:// в проде.

Деплой: одна команда ``python server.py``, порт берётся из $PORT (стандарт для
Railway/Render) или 8765 по умолчанию.
"""
import asyncio
import json
import logging
import os

import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("relay")

# id -> websocket
_connections = {}


async def _register(ws, client_id):
    _connections[client_id] = ws
    log.info("connected: %s (total=%d)", client_id, len(_connections))


async def _unregister(client_id):
    _connections.pop(client_id, None)
    log.info("disconnected: %s (total=%d)", client_id, len(_connections))


async def _forward(envelope):
    to = envelope.get("to")
    payload = json.dumps(envelope, ensure_ascii=False)

    if to in (None, "*"):
        # Широковещательно всем, кроме отправителя — используется, когда Admin
        # шлёт команду сразу "всем клиентам".
        sender = envelope.get("from")
        targets = [ws for cid, ws in _connections.items() if cid != sender]
    else:
        target_ws = _connections.get(to)
        targets = [target_ws] if target_ws is not None else []

    for ws in targets:
        try:
            await ws.send(payload)
        except Exception:
            continue


async def handler(ws):
    client_id = None
    try:
        async for raw in ws:
            try:
                envelope = json.loads(raw)
            except Exception:
                continue

            sender = envelope.get("from")
            if sender and client_id is None:
                client_id = sender
                await _register(ws, client_id)

            await _forward(envelope)
    finally:
        if client_id:
            await _unregister(client_id)


async def main():
    port = int(os.environ.get("PORT", "8765"))
    async with websockets.serve(handler, "0.0.0.0", port):
        log.info("relay listening on 0.0.0.0:%d", port)
        await asyncio.Future()  # работает, пока процесс не остановят


if __name__ == "__main__":
    asyncio.run(main())
