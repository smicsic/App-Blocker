"""Мягкая блокировка: диалог с обратным отсчётом вместо мгновенного закрытия.

Модуль умышленно ничего не знает об интерфейсе. Поток мониторинга вызывает
``request()``, тот дёргает обработчик, который зарегистрировал слой интерфейса —
а уже он возвращает вызов в цикл событий Flet (``ctx.ui``). Менять контролы из
чужого потока нельзя, поэтому граница проходит именно здесь.

Порядок такой:
  1. ``close_app()`` нашёл процессы под закрытие;
  2. если мягкая блокировка включена — ``request()`` вместо завершения;
  3. интерфейс показывает отсчёт и по итогу зовёт ``resolve(action)``;
  4. ``resolve()`` завершает процессы (для close_now/timeout) либо ставит
     программу в исключение на время (для cancel) и пишет статистику.
"""
import time

from appcore import state
from appcore.i18n import t
from appcore.logging_util import log

DEFAULT_SECONDS = 60
MIN_SECONDS = 5
MAX_SECONDS = 3600

# Сколько программу не трогаем после нажатия «Отменить». Без задержки следующая
# же итерация мониторинга (через 2 секунды) открыла бы диалог снова, и отмена
# теряла бы смысл. Но и навсегда освобождать нельзя — иначе один клик отключает
# блокировку до перезапуска.
CANCEL_COOLDOWN_SECONDS = 300

# Минимальный промежуток между окнами отсчёта. Одна программа нередко поднимает
# несколько процессов с разными именами (лаунчер и его помощники), а передышка
# выдаётся по имени — только тем, что были в закрытом окне. Без этой паузы
# следующий такт мониторинга открывал бы окно для соседнего имени, и так по
# кругу: пользователь видит окно за окном и не может работать.
MIN_DIALOG_INTERVAL_SECONDS = 20

ACTION_CLOSE_NOW = "close_now"
ACTION_CANCEL = "cancel"
ACTION_TIMEOUT = "timeout"
ACTION_PROCESS_GONE = "process_gone"

# Как действия попадают в stats.json.
_STATS_ACTIONS = {
    ACTION_CLOSE_NOW: "postpone_close_now",
    ACTION_CANCEL: "postpone_cancel",
    ACTION_TIMEOUT: "postpone_timeout",
}

_request_handler = None
# Что именно сейчас показано в диалоге: имена процессов и, для whitelist-режима,
# список разрешённых программ (текст сообщения от режима зависит).
_pending = {"names": [], "allowed": []}


def set_request_handler(handler):
    """Регистрирует функцию ``handler(names, allowed_names)`` из слоя интерфейса."""
    global _request_handler
    _request_handler = handler


def normalize_seconds(value, fallback=DEFAULT_SECONDS):
    """Приводит длительность к допустимым границам. None, если это не число."""
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if seconds < MIN_SECONDS or seconds > MAX_SECONDS:
        return None
    return seconds


def is_enabled():
    return bool(state.POSTPONE_ENABLED) and state.POSTPONE_SECONDS > 0


def is_exempt(process_name):
    """True, если программу не трогаем — пользователь нажал «Отменить»."""
    if not process_name:
        return False
    now = time.monotonic()
    with state.POSTPONE_LOCK:
        until = state.POSTPONE_EXEMPT_UNTIL.get(process_name)
        if until is None:
            return False
        if now >= until:
            state.POSTPONE_EXEMPT_UNTIL.pop(process_name, None)
            return False
        return True


def mark_exempt(process_names):
    until = time.monotonic() + CANCEL_COOLDOWN_SECONDS
    with state.POSTPONE_LOCK:
        for name in process_names:
            if name:
                state.POSTPONE_EXEMPT_UNTIL[name] = until


def clear_exemptions():
    with state.POSTPONE_LOCK:
        state.POSTPONE_EXEMPT_UNTIL.clear()


def has_exemptions():
    """Есть ли программы, которые сейчас не трогаем после «Отменить».

    Попутно выбрасывает истёкшие записи, чтобы словарь не разрастался и чтобы
    интерфейс сам возвращался в обычное состояние, когда передышка кончилась.
    """
    now = time.monotonic()
    with state.POSTPONE_LOCK:
        for name in [n for n, until in state.POSTPONE_EXEMPT_UNTIL.items() if now >= until]:
            state.POSTPONE_EXEMPT_UNTIL.pop(name, None)
        return bool(state.POSTPONE_EXEMPT_UNTIL)


def dialog_is_active():
    with state.POSTPONE_LOCK:
        return state.POSTPONE_DIALOG_ACTIVE


def pending_names():
    with state.POSTPONE_LOCK:
        return list(_pending["names"])


def request(process_names, allowed_names):
    """Просит интерфейс показать отсчёт. Вызывается из потока мониторинга.

    Возвращает True, если диалог запрошен или уже открыт — в этом случае
    вызывающий НЕ должен завершать процессы. False означает, что мягкую
    блокировку применить не удалось и нужно действовать как раньше.
    """
    if not is_enabled() or state.APP_CLOSING:
        return False
    process_names = [name for name in process_names if name]
    if not process_names:
        return False

    with state.POSTPONE_LOCK:
        if state.POSTPONE_DIALOG_ACTIVE:
            # Диалог уже висит: ничего не завершаем и второй не открываем.
            return True
        since_last = time.monotonic() - state.POSTPONE_LAST_RESOLVED_AT
        in_pause = bool(state.POSTPONE_LAST_RESOLVED_AT) and since_last < MIN_DIALOG_INTERVAL_SECONDS
        last_action = state.POSTPONE_LAST_ACTION
        if not in_pause:
            state.POSTPONE_DIALOG_ACTIVE = True

    if in_pause:
        # Окно только что закрыли. Второе не открываем, но и не молчим: переносим
        # последнее решение на процессы, поднявшиеся сразу после. Иначе пауза
        # была бы дырой, в которой ничего не спрашивают и ничего не завершают —
        # выглядит как «мягкая блокировка не работает».
        if last_action == ACTION_CANCEL:
            mark_exempt(process_names)
            return True
        # Пользователь уже выбрал «закрыть» — завершаем без повторного вопроса.
        return False

    with state.POSTPONE_LOCK:
        _pending["names"] = list(process_names)
        _pending["allowed"] = list(allowed_names or [])

    handler = _request_handler
    if handler is None:
        # Показать некому (интерфейс не поднялся) — откатываемся на мгновенное.
        _release()
        return False

    try:
        handler(list(process_names), list(allowed_names or []))
    except Exception as e:
        _release()
        log(t("log_postpone_failed", error=e))
        return False

    log(t("log_postpone_shown", programs=", ".join(process_names),
          seconds=state.POSTPONE_SECONDS))
    return True


def _release():
    with state.POSTPONE_LOCK:
        state.POSTPONE_DIALOG_ACTIVE = False
        _pending["names"] = []
        _pending["allowed"] = []


def targets_still_running():
    """Работает ли ещё хоть один процесс, из-за которого открыт диалог.

    Нужно, чтобы закрыть диалог самому, если пользователь тем временем закрыл
    программу вручную.
    """
    from appcore.processes import collect_terminate_targets, normalize_process_name

    names = pending_names()
    if not names:
        return False
    try:
        running = {normalize_process_name(name) for _, name, _ in collect_terminate_targets()}
    except Exception:
        # Не смогли проверить — считаем, что процесс жив: закрывать диалог
        # молча опаснее, чем оставить отсчёт идти.
        return True
    return any(normalize_process_name(name) in running for name in names)


def resolve(action):
    """Завершает сценарий мягкой блокировки. Вызывается слоем интерфейса."""
    from appcore.processes import terminate_now
    from appcore.stats import record_block_events

    with state.POSTPONE_LOCK:
        names = list(_pending["names"])
        # Пауза начинается только от реального выбора пользователя, и отметку
        # ставим здесь, а не в _release(): при сбое показа окна откат на
        # мгновенное завершение не должен её запускать. «Программа закрылась
        # сама» решением не считается — переносить на новые процессы нечего, и
        # следующее обнаружение должно снова спросить.
        if action != ACTION_PROCESS_GONE:
            state.POSTPONE_LAST_RESOLVED_AT = time.monotonic()
            state.POSTPONE_LAST_ACTION = action
    _release()

    if action == ACTION_CANCEL:
        mark_exempt(names)
        log(t("log_postpone_cancelled", programs=", ".join(names),
              minutes=CANCEL_COOLDOWN_SECONDS // 60))
    elif action == ACTION_PROCESS_GONE:
        # Программу закрыли сами — просто убираем диалог, ничего не завершаем.
        log(t("log_postpone_process_gone", programs=", ".join(names)))
    else:
        if action == ACTION_TIMEOUT:
            log(t("log_postpone_timeout", programs=", ".join(names)))
        else:
            log(t("log_postpone_close_now", programs=", ".join(names)))
        # Пересобираем список заново: держать psutil.Process всё время отсчёта
        # нельзя — процесс мог завершиться, а его PID достаться другому.
        terminate_now(record_action=_STATS_ACTIONS.get(action, "terminated"))
        return

    stats_action = _STATS_ACTIONS.get(action)
    if stats_action:
        record_block_events([(name, "program", stats_action, None) for name in names])
