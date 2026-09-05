"""Отправка команд клиентам по TCP (LAN-режим) и учёт токенов пар Admin/Client."""
import asyncio
import time

from appcore.network import auth_store
from appcore.network.protocol import (
    ACTION_PING,
    Command,
    Response,
    read_json_line,
    write_json_line,
)


async def send_command(ip, port, action, target=None, timeout=5.0, client_id=None):
    """Открывает TCP-соединение, отправляет одну команду, читает один ответ, закрывает.

    Если для ``client_id`` уже есть сохранённый токен пары — подставляется
    автоматически. Если Client в ответе прислал ``issued_token`` (только что
    подтверждённый пейринг), он сохраняется в trusted_clients для следующих
    команд — вызывающему коду ничего дополнительно делать не нужно.
    """
    token = auth_store.get_client_token(client_id) if client_id else None
    command = Command(action=action, target=target, token=token, timestamp=time.time())

    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
    try:
        write_json_line(writer, command)
        await writer.drain()
        raw = await asyncio.wait_for(read_json_line(reader), timeout=timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if raw is None:
        return Response(status="error", client_id=client_id or "", message="Пустой ответ от клиента")

    response = Response.from_dict(raw)

    if response.issued_token and response.client_id:
        auth_store.remember_client(response.client_id, ip, port, response.issued_token)

    return response


async def ping(ip, port, client_id=None, timeout=3.0):
    return await send_command(ip, port, ACTION_PING, client_id=client_id, timeout=timeout)
