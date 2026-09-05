"""Запись логов в файл и (опционально) в текстовый виджет интерфейса."""
import datetime
import os
from threading import Lock

from appcore.paths import LOG_PATH

_ui_sink = None  # callable(message: str) -> None, устанавливается GUI-слоем

# log() вызывается из потоков мониторинга, расписания и защиты, а очистка — из
# потока интерфейса. Без общего лока усечение файла может попасть между
# открытием и записью чужой строки.
_FILE_LOCK = Lock()


def set_ui_sink(sink):
    """Регистрирует функцию, которая получает каждое сообщение лога для показа в интерфейсе."""
    global _ui_sink
    _ui_sink = sink


def log(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _FILE_LOCK:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass
    if _ui_sink is not None:
        try:
            _ui_sink(f"{message}\n")
        except Exception:
            pass


def clear_log_file():
    """Очищает файл лога, оставляя одну отметку о том, когда это произошло.

    Открытие в режиме ``"w"`` усекает файл — прежние записи удаляются
    безвозвратно. Отметку оставляем намеренно: пустой файл лога не отличить от
    сломанной записи, а одна строка сразу говорит, что журнал сбросили вручную.

    Возвращает True, если файл удалось перезаписать.
    """
    from appcore.i18n import t

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _FILE_LOCK:
            with open(LOG_PATH, "w", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {t('logs_cleared')}\n")
                f.flush()
                os.fsync(f.fileno())
        return True
    except Exception:
        return False
