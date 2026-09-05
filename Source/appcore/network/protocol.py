"""Протокол команд Remote Admin — общий для AppBlocker_Admin и AppBlocker_Client.

Этот файл дублируется дословно в обеих программах (``appcore/network/protocol.py``
здесь и ``AppBlocker_Client/protocol.py``): Client — самостоятельная программа и
не должен зависеть от исходников Admin, поэтому вместо общего пакета — копия.
При правке протокола нужно поправить оба файла одинаково.

Транспорт (сырой TCP в LAN-режиме или текстовый фрейм WebSocket в WAN-режиме)
не важен для этого модуля: он только описывает форму сообщений и их
сериализацию. Для TCP используется framing "один JSON-объект на строку"
(newline-delimited JSON) — простой и достаточный, так как ни один из полей не
содержит сырых переводов строк.
"""
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, List


DEFAULT_PORT = 55400  # общий порт: TCP для команд, UDP для discovery-broadcast

# Действия, которые понимает Client.
ACTION_BLOCK = "block"
ACTION_UNBLOCK = "unblock"
ACTION_GET_STATUS = "get_status"
ACTION_PING = "ping"
ACTION_DISCOVER = "discover"  # только для UDP-broadcast, не идёт по TCP

# Возможные статусы в Response.
STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_DENIED = "denied"  # пользователь на Client отклонил подключение


@dataclass
class Command:
    """Команда от Admin к Client."""

    action: str
    sender: str = "admin"
    target: Optional[str] = None
    token: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data):
        return cls(
            action=data.get("action", ""),
            sender=data.get("sender", "admin"),
            target=data.get("target"),
            token=data.get("token"),
            timestamp=data.get("timestamp", time.time()),
        )

    @classmethod
    def from_json(cls, raw):
        return cls.from_dict(json.loads(raw))


@dataclass
class Response:
    """Ответ от Client к Admin.

    ``issued_token`` заполняется только один раз — когда пользователь на
    Client только что подтвердил подключение и получил новый токен доверия.
    В протоколе задачи этого поля не было явно, но оно нужно, чтобы пара
    Admin/Client могла договориться о токене без отдельного запроса
    "pair_request": пейринг происходит прозрачно на первой же команде.
    """

    status: str
    client_id: str
    message: str = ""
    blocked_apps: List[str] = field(default_factory=list)
    issued_token: Optional[str] = None

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data):
        return cls(
            status=data.get("status", "error"),
            client_id=data.get("client_id", ""),
            message=data.get("message", ""),
            blocked_apps=list(data.get("blocked_apps", []) or []),
            issued_token=data.get("issued_token"),
        )

    @classmethod
    def from_json(cls, raw):
        return cls.from_dict(json.loads(raw))


async def read_json_line(reader, limit=65536):
    """Читает одну NDJSON-строку из asyncio.StreamReader. None на EOF/пустой строке."""
    raw = await reader.readline()
    if not raw:
        return None
    raw = raw.decode("utf-8", errors="replace").strip()
    if not raw:
        return None
    if len(raw) > limit:
        raise ValueError("message too large")
    return json.loads(raw)


def write_json_line(writer, obj):
    """Пишет один объект (dict или объект с to_dict()) как NDJSON-строку."""
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()
    line = json.dumps(obj, ensure_ascii=False) + "\n"
    writer.write(line.encode("utf-8"))
