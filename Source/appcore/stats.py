"""Статистика блокировок: события и сессии в отдельном stats.json.

Файл держим отдельно от config.json, чтобы история событий не мешалась с
настройками (config.json перезаписывается целиком при каждом save_config, а
ещё его импортируют/экспортируют пользователи).

Два типа записей:
  * ``events`` — по одной на каждое срабатывание блокировки (программа или сайт);
  * ``sessions`` — интервалы, когда мониторинг был активен, чтобы считать
    суммарное время блокировки.
"""
import csv
import datetime
import json
import os
from threading import Lock

from appcore.i18n import t
from appcore.logging_util import log
from appcore.paths import STATS_PATH

# Верхняя граница истории: файл читается целиком, поэтому не даём ему расти
# бесконечно — старые события вытесняются новыми.
MAX_EVENTS = 5000

_STATS_LOCK = Lock()


def _read_stats_unlocked():
    if not os.path.exists(STATS_PATH):
        return {"events": [], "sessions": []}
    try:
        with open(STATS_PATH, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except Exception:
        return {"events": [], "sessions": []}
    if not isinstance(data, dict):
        return {"events": [], "sessions": []}
    events = data.get("events")
    sessions = data.get("sessions")
    return {
        "events": events if isinstance(events, list) else [],
        "sessions": sessions if isinstance(sessions, list) else [],
    }


def _write_stats_unlocked(data):
    try:
        os.makedirs(os.path.dirname(STATS_PATH), exist_ok=True)
        with open(STATS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        return True
    except Exception:
        return False


def load_stats():
    """Читает stats.json. Возвращает словарь с ключами events/sessions."""
    with _STATS_LOCK:
        return _read_stats_unlocked()


def _append_events_unlocked(data, entries):
    data["events"].extend(entries)
    if len(data["events"]) > MAX_EVENTS:
        data["events"] = data["events"][-MAX_EVENTS:]


def record_block_events(entries):
    """Записывает пачку срабатываний одним обращением к файлу.

    Важно для whitelist-режима: там за одну итерацию мониторинга может
    завершиться сразу много процессов, и запись по одному событию перечитывала
    бы и перезаписывала stats.json десятки раз за такт.

    ``entries`` — список кортежей ``(target, kind, action, rule)``.
    """
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    prepared = []
    for target, kind, action, rule in entries:
        if not target:
            continue
        entry = {
            "timestamp": timestamp,
            "target": target,
            "kind": kind,
            "action": action,
        }
        if rule:
            entry["rule"] = rule
        prepared.append(entry)
    if not prepared:
        return
    with _STATS_LOCK:
        data = _read_stats_unlocked()
        _append_events_unlocked(data, prepared)
        _write_stats_unlocked(data)


def record_block_event(target, kind="program", action="terminated", rule=None):
    """Записывает одно срабатывание блокировки.

    ``target`` — имя процесса или домен, ``kind`` — "program"/"site",
    ``action`` — что сделали, ``rule`` — по какому правилу сработало.
    """
    record_block_events([(target, kind, action, rule)])


def record_site_events(sites, action="blocked"):
    """Записывает срабатывание блокировки сайтов пачкой (по записи на домен)."""
    record_block_events([(site, "site", action, None) for site in (sites or [])])


def start_session():
    """Открывает интервал активной блокировки, если он ещё не открыт."""
    with _STATS_LOCK:
        data = _read_stats_unlocked()
        if data["sessions"] and not data["sessions"][-1].get("end"):
            return
        data["sessions"].append({
            "start": datetime.datetime.now().isoformat(timespec="seconds"),
            "end": None,
        })
        _write_stats_unlocked(data)


def end_session():
    """Закрывает последний открытый интервал блокировки."""
    with _STATS_LOCK:
        data = _read_stats_unlocked()
        if not data["sessions"]:
            return
        last = data["sessions"][-1]
        if last.get("end"):
            return
        last["end"] = datetime.datetime.now().isoformat(timespec="seconds")
        _write_stats_unlocked(data)


def _parse_timestamp(value):
    try:
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return None


def _session_seconds(session, since=None):
    """Длительность интервала в секундах; открытый интервал считаем до «сейчас»."""
    start = _parse_timestamp(session.get("start"))
    if start is None:
        return 0
    end = _parse_timestamp(session.get("end")) if session.get("end") else datetime.datetime.now()
    if end is None:
        return 0
    if since is not None and start < since:
        start = since
    if end <= start:
        return 0
    return int((end - start).total_seconds())


def format_duration(total_seconds):
    """Секунды -> «5 ч 07 мин» / «12 мин» для карточек дашборда."""
    total_seconds = max(0, int(total_seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes = remainder // 60
    if hours:
        return t("stats_duration_hm", hours=hours, minutes=f"{minutes:02d}")
    return t("stats_duration_m", minutes=minutes)


def summarize(data=None):
    """Считает показатели дашборда: события за день/неделю, время, топ-3."""
    data = data if data is not None else load_stats()
    now = datetime.datetime.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    # «Неделя» = последние 7 суток, включая сегодняшний день.
    week_start = today_start - datetime.timedelta(days=6)

    today_count = 0
    week_count = 0
    counts_by_target = {}
    for event in data.get("events", []):
        moment = _parse_timestamp(event.get("timestamp"))
        if moment is None:
            continue
        if moment >= today_start:
            today_count += 1
        if moment >= week_start:
            week_count += 1
            target = event.get("target")
            if target:
                counts_by_target[target] = counts_by_target.get(target, 0) + 1

    sessions = data.get("sessions", [])
    today_seconds = sum(_session_seconds(s, since=today_start) for s in sessions)
    week_seconds = sum(_session_seconds(s, since=week_start) for s in sessions)
    total_seconds = sum(_session_seconds(s) for s in sessions)

    top_targets = sorted(counts_by_target.items(), key=lambda item: (-item[1], item[0]))[:3]

    return {
        "today_count": today_count,
        "week_count": week_count,
        "today_seconds": today_seconds,
        "week_seconds": week_seconds,
        "total_seconds": total_seconds,
        "top_targets": top_targets,
        "total_events": len(data.get("events", [])),
    }


def clear_stats():
    """Полностью очищает историю статистики."""
    with _STATS_LOCK:
        return _write_stats_unlocked({"events": [], "sessions": []})


def export_stats_csv(target):
    """Выгружает историю событий в CSV по пути ``target`` (см. export_config)."""
    if not target:
        return False
    data = load_stats()
    events = data.get("events", [])
    try:
        # utf-8-sig — чтобы Excel открыл файл с кириллицей без «кракозябр».
        # newline="" — требование модуля csv, иначе в Windows будут пустые строки.
        with open(target, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                t("stats_csv_date"),
                t("stats_csv_time"),
                t("stats_csv_target"),
                t("stats_csv_kind"),
                t("stats_csv_action"),
                t("stats_csv_rule"),
            ])
            for event in events:
                moment = _parse_timestamp(event.get("timestamp"))
                date_text = moment.strftime("%Y-%m-%d") if moment else ""
                time_text = moment.strftime("%H:%M:%S") if moment else ""
                writer.writerow([
                    date_text,
                    time_text,
                    event.get("target", ""),
                    event.get("kind", ""),
                    event.get("action", ""),
                    event.get("rule", ""),
                ])
        log(t("log_stats_exported", path=target, count=len(events)))
        return True
    except Exception as e:
        log(t("log_stats_export_failed", error=e))
        return False
