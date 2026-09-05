"""Расписание блокировки по дням недели.

Структура в config.json::

    "schedule_enabled": true,
    "schedule": {
      "monday": [{"start": "09:00", "end": "18:00"}],
      ...
      "sunday": []
    }

Фоновый поток сравнивает текущее время с интервалами и сообщает GUI, что окно
блокировки началось или закончилось. Важное правило: расписание умеет только
**включать** блокировку. Если пользователь уже нажал «Начать блокировку
программ» (``state.PERMANENT_LOCK``), окончание окна ничего не выключает —
иначе расписание стало бы способом обойти вечную блокировку.
"""
import datetime
import re

from appcore import state
from appcore.i18n import t

# Порядок совпадает с datetime.weekday(): понедельник — 0, воскресенье — 6.
DAY_KEYS = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")

DAY_LABEL_KEYS = {
    "monday": "schedule_day_monday",
    "tuesday": "schedule_day_tuesday",
    "wednesday": "schedule_day_wednesday",
    "thursday": "schedule_day_thursday",
    "friday": "schedule_day_friday",
    "saturday": "schedule_day_saturday",
    "sunday": "schedule_day_sunday",
}

_TIME_PATTERN = re.compile(r"^(\d{1,2}):(\d{2})$")
# Разделители интервалов: запятая, точка с запятой или перевод строки.
_SPLIT_PATTERN = re.compile(r"[,;\n]+")


def empty_schedule():
    return {day: [] for day in DAY_KEYS}


def parse_time_to_minutes(value):
    """'09:30' -> 570. Возвращает None, если формат неверный."""
    match = _TIME_PATTERN.match((value or "").strip())
    if not match:
        return None
    hour, minute = int(match.group(1)), int(match.group(2))
    if hour > 23 or minute > 59:
        return None
    return hour * 60 + minute


def format_minutes(total_minutes):
    return f"{total_minutes // 60:02d}:{total_minutes % 60:02d}"


def parse_intervals_input(text):
    """Разбирает строку вида '09:00-18:00, 20:00-22:00'.

    Возвращает список ``[{"start": "09:00", "end": "18:00"}, ...]``.
    Бросает ValueError с человекочитаемым куском текста, если формат неверный.
    """
    intervals = []
    for chunk in _SPLIT_PATTERN.split(text or ""):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Допускаем как дефис, так и тире — пользователи вставляют разное.
        parts = re.split(r"\s*[-–—]\s*", chunk)
        if len(parts) != 2:
            raise ValueError(chunk)
        start_minutes = parse_time_to_minutes(parts[0])
        end_minutes = parse_time_to_minutes(parts[1])
        if start_minutes is None or end_minutes is None:
            raise ValueError(chunk)
        if start_minutes == end_minutes:
            # Нулевая длительность смысла не имеет, а 24 часа задаются 00:00-23:59.
            raise ValueError(chunk)
        intervals.append({
            "start": format_minutes(start_minutes),
            "end": format_minutes(end_minutes),
        })
    return intervals


def format_intervals(intervals):
    """Обратная операция для поля ввода."""
    parts = []
    for interval in intervals or []:
        start = interval.get("start")
        end = interval.get("end")
        if start and end:
            parts.append(f"{start}-{end}")
    return ", ".join(parts)


def normalize_schedule(raw):
    """Приводит структуру из config.json к безопасному виду.

    Мусор и некорректные интервалы отбрасываются: расписание не должно ломать
    запуск приложения, если файл правили руками.
    """
    result = empty_schedule()
    if not isinstance(raw, dict):
        return result
    for day in DAY_KEYS:
        entries = raw.get(day)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            start_minutes = parse_time_to_minutes(entry.get("start"))
            end_minutes = parse_time_to_minutes(entry.get("end"))
            if start_minutes is None or end_minutes is None or start_minutes == end_minutes:
                continue
            result[day].append({
                "start": format_minutes(start_minutes),
                "end": format_minutes(end_minutes),
            })
    return result


def has_any_interval(schedule=None):
    schedule = schedule if schedule is not None else state.SCHEDULE
    return any(schedule.get(day) for day in DAY_KEYS)


def is_schedule_active_now(now=None):
    """True, если текущий момент попадает в один из интервалов расписания.

    Интервал с ``end`` меньше ``start`` считается ночным (22:00-02:00): он
    начинается в свой день и заканчивается на следующий, поэтому проверяем ещё
    и вчерашний день.
    """
    schedule = state.SCHEDULE or {}
    if not has_any_interval(schedule):
        return False

    now = now or datetime.datetime.now()
    minutes = now.hour * 60 + now.minute

    today = DAY_KEYS[now.weekday()]
    for interval in schedule.get(today, []):
        start = parse_time_to_minutes(interval.get("start"))
        end = parse_time_to_minutes(interval.get("end"))
        if start is None or end is None:
            continue
        if start < end:
            if start <= minutes < end:
                return True
        elif minutes >= start:
            # Ночной интервал, который начался сегодня и идёт за полночь.
            return True

    yesterday = DAY_KEYS[(now.weekday() - 1) % 7]
    for interval in schedule.get(yesterday, []):
        start = parse_time_to_minutes(interval.get("start"))
        end = parse_time_to_minutes(interval.get("end"))
        if start is None or end is None:
            continue
        if start > end and minutes < end:
            # Ночной интервал, начавшийся вчера и ещё не закончившийся.
            return True

    return False


def describe_current_state():
    """Текст для строки статуса на вкладке расписания."""
    if not state.SCHEDULE_ENABLED:
        return t("schedule_status_off")
    if not has_any_interval():
        return t("schedule_status_empty")
    return t("schedule_status_active") if is_schedule_active_now() else t("schedule_status_inactive")


def start_schedule_thread(on_window_start, on_window_end, check_interval=20):
    """Запускает фоновую проверку расписания.

    ``on_window_start`` / ``on_window_end`` вызываются только на переходе
    границы окна, а не на каждой итерации. Колбэки выполняются в этом потоке,
    поэтому обновление контролов они обязаны возвращать в цикл событий
    интерфейса сами (через ``ctx.ui``).
    """
    import threading

    if state.schedule_thread is not None and state.schedule_thread.is_alive():
        return state.schedule_thread

    def loop():
        while not state.shutdown_event.is_set():
            try:
                active = state.SCHEDULE_ENABLED and is_schedule_active_now()
                if active != state.SCHEDULE_WINDOW_ACTIVE:
                    state.SCHEDULE_WINDOW_ACTIVE = active
                    if active:
                        on_window_start()
                    else:
                        on_window_end()
            except Exception:
                # Поток расписания не должен умирать из-за разовой ошибки.
                pass
            state.shutdown_event.wait(check_interval)

    state.schedule_thread = threading.Thread(target=loop, daemon=True)
    state.schedule_thread.start()
    return state.schedule_thread
