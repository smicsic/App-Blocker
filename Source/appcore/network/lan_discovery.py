"""UDP broadcast discovery: находит AppBlocker_Client в локальной сети (Admin-сторона)."""
import asyncio
import json
import socket
from dataclasses import dataclass

from appcore.network.protocol import ACTION_DISCOVER, DEFAULT_PORT


@dataclass
class DiscoveredClient:
    client_id: str
    ip: str
    port: int


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, results):
        self.results = results
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            payload = json.loads(data.decode("utf-8", errors="replace"))
        except Exception:
            return
        client_id = payload.get("client_id")
        port = payload.get("tcp_port", DEFAULT_PORT)
        if client_id:
            # Один и тот же клиент может ответить несколько раз (несколько
            # сетевых интерфейсов) — оставляем последний ответ.
            self.results[client_id] = DiscoveredClient(client_id=client_id, ip=addr[0], port=port)

    def error_received(self, exc):
        pass


async def scan(timeout=2.0, port=DEFAULT_PORT):
    """Рассылает discovery-broadcast и timeout секунд собирает ответы.

    Возвращает список DiscoveredClient. Ошибки сети (например, broadcast
    запрещён в песочнице/контейнере) не прерывают вызывающий код — просто
    возвращается пустой список, а вкладка Remote Admin предлагает добавить
    клиента по IP вручную.
    """
    results = {}
    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setblocking(False)
    sock.bind(("0.0.0.0", 0))

    transport = None
    try:
        transport, _protocol_instance = await loop.create_datagram_endpoint(
            lambda: _DiscoveryProtocol(results), sock=sock
        )
        message = json.dumps({"action": ACTION_DISCOVER, "sender": "admin"}).encode("utf-8")
        try:
            transport.sendto(message, ("255.255.255.255", port))
        except Exception:
            pass
        await asyncio.sleep(timeout)
    except Exception:
        pass
    finally:
        if transport is not None:
            transport.close()

    return list(results.values())
