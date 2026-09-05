"""Общее изменяемое состояние приложения.

Другие модули импортируют этот модуль целиком (``from appcore import state``)
и читают/пишут атрибуты напрямую (``state.BLOCKED_PROGRAMS``), что заменяет
глобальные переменные, которые раньше жили в одном файле AppBlocker.py.
"""
from threading import Lock, Event

PROCESS_NAME = ""
BLOCKED_PROGRAMS = []
ADMIN_PASSWORD = ""
ADMIN_PASSWORD_HASH = ""
ADMIN_PASSWORD_SALT = ""
monitor_thread = None
monitoring_active = False
last_monitor_state = None
SECURE_ENABLED = False  # по умолчанию защита выключена
SECURITY_WARNING_SEEN = False
TIMER_ENABLED = False
PERMANENT_LOCK = False
MATCH_MODE = "contains"
# "blacklist" — завершаем только выбранные программы (поведение по умолчанию),
# "whitelist" — завершаем всё пользовательское, кроме выбранных программ.
BLOCK_MODE = "blacklist"
TIMER_END = None
timer_thread = None
# Расписание по дням недели: {"monday": [{"start": "09:00", "end": "18:00"}], ...}
# Ключи перечислены явно, чтобы свежий config.json сразу имел полную структуру
# (appcore.schedule здесь не импортируем — state не должен ни от чего зависеть).
SCHEDULE = {
    "monday": [], "tuesday": [], "wednesday": [], "thursday": [],
    "friday": [], "saturday": [], "sunday": [],
}
SCHEDULE_ENABLED = False
schedule_thread = None
# None означает «ещё не проверяли»: первая же проверка сработает как переход
# границы окна, поэтому запуск приложения внутри окна включит блокировку.
SCHEDULE_WINDOW_ACTIVE = None
# True, если мониторинг подняло расписание — только такой мониторинг оно и
# вправе останавливать по окончании окна.
SCHEDULE_STARTED_MONITORING = False
# То же для сайтов: расписание снимает hosts-блокировку только если само её и
# поставило и пользователь не включал блокировку сайтов вручную.
SCHEDULE_APPLIED_SITES = False
SITES_BLOCKED_MANUALLY = False
APP_CLOSING = False
TRAY_ICON = None
CONFIG_LOCK = Lock()
SECURITY_OFF_WARNING_SHOWN = False
SECURITY_WARNING_DIALOG = None
shutdown_event = Event()
watch_active = False

# ---------- Мягкая блокировка (postpone) ----------
# Выключена по умолчанию: блокировка мгновенная. Включение добавляет окно с
# обратным отсчётом перед закрытием программы.
POSTPONE_ENABLED = False
POSTPONE_SECONDS = 60
# True, пока открыт диалог отсчёта. Защита от того, чтобы плодить по диалогу
# на каждую итерацию мониторинга (та идёт раз в 2 секунды).
POSTPONE_DIALOG_ACTIVE = False
# {имя процесса: время по monotonic, до которого его не трогаем} — заполняется,
# когда пользователь нажал «Отменить».
POSTPONE_EXEMPT_UNTIL = {}
# Когда последний раз закрывали окно отсчёта (по monotonic). Нужно, чтобы окна
# не шли чередой: программа может поднимать несколько процессов с разными
# именами, и передышка по имени от следующего окна не спасает.
POSTPONE_LAST_RESOLVED_AT = 0.0
# Что пользователь выбрал в последнем окне. В течение паузы это решение
# переносится на процессы, поднявшиеся сразу после, — иначе пауза превращалась
# бы в дыру, где не спрашивают и не завершают.
POSTPONE_LAST_ACTION = None
# Разделяемое состояние postpone читает поток мониторинга и пишет поток
# интерфейса, поэтому доступ к нему только под этим локом.
POSTPONE_LOCK = Lock()

EXIT_LOCK = Lock()
SINGLE_INSTANCE_MUTEX_NAME = "Global\\AppBlockerMainInstance"
_single_instance_mutex = None
