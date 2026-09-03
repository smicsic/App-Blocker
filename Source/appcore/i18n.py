"""Локализация интерфейса. Русский — язык по умолчанию, английский — второй.

``t(key, **kwargs)`` возвращает строку для текущего языка (с подстановкой
параметров через ``str.format``). Виджеты, которым нужно "живое" обновление
текста при смене языка, регистрируются через ``register_retranslate`` —
их callback вызывается сразу после переключения языка.
"""
import json
import os

LANGUAGES = ("ru", "en")
DEFAULT_LANGUAGE = "ru"

_current_language = DEFAULT_LANGUAGE
_retranslate_callbacks = []

LANGUAGE_STATE_FILENAME = "language.json"


def _state_path():
    from appcore.paths import STATE_DIR
    return os.path.join(STATE_DIR, LANGUAGE_STATE_FILENAME)


def load_language():
    global _current_language
    try:
        with open(_state_path(), "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        lang = data.get("language")
        if lang in LANGUAGES:
            _current_language = lang
    except Exception:
        pass
    return _current_language


def save_language():
    try:
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump({"language": _current_language}, f, indent=2)
    except Exception:
        pass


def get_language():
    return _current_language


def register_retranslate(callback):
    """Регистрирует функцию без аргументов, вызываемую после смены языка."""
    _retranslate_callbacks.append(callback)


def set_language(lang):
    global _current_language
    if lang not in LANGUAGES or lang == _current_language:
        return
    _current_language = lang
    save_language()
    for callback in list(_retranslate_callbacks):
        try:
            callback()
        except Exception:
            pass


def t(key, **kwargs):
    entry = TRANSLATIONS.get(key)
    if entry is None:
        return key
    template = entry.get(_current_language, entry.get(DEFAULT_LANGUAGE, key))
    if kwargs:
        try:
            return template.format(**kwargs)
        except Exception:
            return template
    return template


TRANSLATIONS = {}


def add(key, ru, en):
    TRANSLATIONS[key] = {"ru": ru, "en": en}


# ==================== Общее / топбар / навигация ====================
add("nav_title", "APP BLOCKER", "APP BLOCKER")
add("nav_monitor", "Мониторинг", "Monitor")
# Иконки пунктов навигации рисует сам Flet (ft.Icons), поэтому в подписях их нет.
add("nav_sites", "Сайты", "Websites")
add("nav_settings", "Настройки", "Settings")
add("nav_about", "О программе", "About")
add("btn_refresh_processes", "Обновить процессы", "Refresh processes")
add("btn_exit", "Выйти", "Exit")
add("language_button", "Language", "Language")
add("language_dialog_title", "Язык / Language", "Язык / Language")
add("language_ru", "Русский", "Русский")
add("language_en", "English", "English")

# ==================== Панель логов ====================
add("logs_title", "Логи", "Logs")
add("logs_clear_btn", "Очистить", "Clear")
add("logs_ready", "🛡 Готов к блокировке...", "🛡 Ready to block...")
add("logs_cleared", "🛡 Логи очищены.", "🛡 Logs cleared.")
add("log_ui_refresh_failed",
    "⚠️ Не удалось обновить интерфейс: {error}",
    "⚠️ Failed to refresh the interface: {error}")
add("log_log_file_clear_failed",
    "⚠️ Не удалось очистить файл логов: {path}",
    "⚠️ Failed to clear the log file: {path}")

# ==================== Вкладка «Мониторинг» ====================
add("monitor_title", "Мониторинг программ", "Program monitoring")
add("monitor_processes_card_title", "Программы", "Programs")
add("monitor_processes_count", "{count} в списке", "{count} in the list")
add("monitor_status_card_title", "Мониторинг", "Monitor")
add("monitor_status_waiting", "Ожидает", "Waiting")
add("monitor_status_active", "Активен", "Active")
add("monitor_secure_card_title", "Защита", "Protection")
add("monitor_secure_on", "Активна", "On")
add("monitor_secure_off", "Выкл.", "Off")
add("monitor_start_btn", "🚀 Начать блокировку программ", "🚀 Start blocking programs")
add("monitor_block_now_btn", "🚫 Заблокировать сейчас", "🚫 Block now")
add("monitor_blocked_programs_title", "Заблокированные программы", "Blocked programs")
add("monitor_active_processes_title", "Активные процессы", "Active processes")
add("monitor_no_processes_found", "Активных пользовательских процессов не найдено.", "No active user processes found.")
add("monitor_processes_found", "Найдено процессов: {count}", "Processes found: {count}")
add("monitor_action_remove", "Удалить", "Remove")
add("monitor_action_add", "Добавить", "Add")
add("monitor_action_protected", "Защищено", "Protected")
add("monitor_blocked_list_empty", "Список пуст. Добавьте программы перед запуском.", "The list is empty. Add programs before starting.")
add("monitor_row_status_running", "запущена", "running")
add("monitor_row_status_not_running", "не запущена", "not running")

add("log_process_list_refreshed", "🔄 Список процессов обновлён.", "🔄 Process list refreshed.")
add("log_program_locked_cant_remove", "🔒 {program} нельзя удалить после запуска блокировки.", "🔒 {program} can't be removed after blocking has started.")
add("log_program_removed", "🗑️ {program} удалён из списка блокировки.", "🗑️ {program} removed from the block list.")
add("log_program_added", "✅ {program} добавлен в список блокировки.", "✅ {program} added to the block list.")
add("log_add_at_least_one_program", "❗ Для блокировки программ добавьте хотя бы одну программу. Сайты блокируются отдельно во вкладке «Сайты».", "❗ Add at least one program to start blocking. Websites are blocked separately on the Websites tab.")
add("log_guard_activated", "🛡 AppBlockerGuard активирован", "🛡 AppBlockerGuard activated")
add("log_monitoring_no_admin_with_guard", "ℹ️ Мониторинг программ запущен: AppBlockerGuard активирован, автозапуск настроен.", "ℹ️ Program monitoring started: AppBlockerGuard is active, autostart configured.")
add("log_monitoring_no_admin_no_guard", "ℹ️ Мониторинг программ запущен без прав администратора: расширенный автозапуск пропущен.", "ℹ️ Program monitoring started without administrator rights: extended startup setup skipped.")
add("log_monitoring_already_active", "⚠️ Мониторинг процесса '{process}' уже активен.", "⚠️ Monitoring for process '{process}' is already active.")
add("log_permanent_lock_activated", "🔒 Вечная блокировка активирована — переключатели больше нельзя изменить.", "🔒 Permanent lock activated — switches can no longer be changed.")
add("log_monitoring_started", "🚀 Мониторинг процесса '{process}' запущен.", "🚀 Monitoring for process '{process}' started.")
add("window_title_blocker", "Blocker: {count} programs", "Blocker: {count} programs")

# ==================== Вкладка «Сайты» ====================
add("sites_title", "Блокировка сайтов", "Website blocking")
add("sites_count", "{count} сайтов в блокировке", "{count} sites blocked")
add("sites_list_empty", "Список пуст. Можно добавить несколько сайтов через пробел, запятую или с новой строки.", "The list is empty. You can add multiple sites separated by spaces, commas, or new lines.")
add("sites_entry_placeholder", "youtube.com, vk.com или https://example.com/page", "youtube.com, vk.com or https://example.com/page")
add("sites_add_btn", "➕ Добавить", "➕ Add")
add("sites_remove_btn", "❌ Удалить", "❌ Remove")
add("sites_enable_btn", "🌐 Включить", "🌐 Enable")
add("sites_clear_all_btn", "🧹 Очистить всё", "🧹 Clear all")

add("log_enter_site_domain", "⚠️ Введите домен сайта: youtube.com, vk.com, example.org", "⚠️ Enter a site domain: youtube.com, vk.com, example.org")
add("log_sites_added", "✅ Добавлено сайтов в список: {count}. Нажмите «Включить», чтобы применить блокировку.", "✅ Added {count} site(s) to the list. Click \"Enable\" to apply the block.")
add("log_sites_already_blocked", "ℹ️ Эти сайты уже есть в блокировке.", "ℹ️ These sites are already blocked.")
add("log_add_at_least_one_site", "❗ Добавьте хотя бы один сайт перед запуском блокировки сайтов.", "❗ Add at least one site before starting website blocking.")
add("log_guard_activated_for_sites", "🛡 AppBlockerGuard активирован для блокировки сайтов", "🛡 AppBlockerGuard activated for website blocking")
add("log_sites_enabled", "🌐 Блокировка сайтов включена отдельно: {count}", "🌐 Website blocking enabled separately: {count}")
add("log_enter_site_to_remove", "⚠️ Введите сайт для удаления.", "⚠️ Enter a site to remove.")
add("log_sites_removed", "🗑️ Удалено сайтов: {count}", "🗑️ Removed {count} site(s)")
add("log_sites_not_in_list", "ℹ️ Таких сайтов нет в списке блокировки.", "ℹ️ These sites are not in the block list.")
add("log_sites_cleared", "🧹 Все сайты удалены из блокировки.", "🧹 All sites removed from blocking.")

# ==================== Вкладка «Настройки» ====================
add("settings_title", "Настройки", "Settings")
add("settings_protection_state_title", "Состояние защиты", "Protection status")
add("settings_startup_app_label", "Автозапуск AppBlocker", "AppBlocker autostart")
add("settings_startup_guard_label", "Автозапуск AppBlockerGuard", "AppBlockerGuard autostart")
add("settings_guard_file_label", "Файл AppBlockerGuard", "AppBlockerGuard file")
add("settings_status_checking", "Проверяется...", "Checking...")
add("settings_status_active", "Активен", "Active")
add("settings_status_not_configured", "Не настроен", "Not configured")
add("settings_status_found", "Найден", "Found")
add("settings_status_not_found", "Не найден", "Not found")
add("settings_check_protection_btn", "Проверить защиту", "Check protection")
add("settings_config_title", "Конфигурация", "Configuration")
add("settings_config_description", "Настройки можно экспортировать в JSON. Логи пишутся в: {log_path}", "Settings can be exported to JSON. Logs are written to: {log_path}")
add("settings_export_btn", "Экспорт", "Export")
add("settings_import_btn", "Импорт", "Import")
add("settings_match_title", "Блокировка процессов", "Process blocking")
add("settings_match_description", "Точное имя закрывает только полное совпадение вроде steam.exe. Режим «Содержит» ловит похожие процессы и помощники.", "Exact name only closes a full match like steam.exe. \"Contains\" mode also catches similar processes and helpers.")
add("settings_match_contains", "Содержит", "Contains")
add("settings_match_exact", "Точное имя", "Exact name")
add("settings_timer_title", "Таймер завершения", "Shutdown timer")
add("settings_timer_switch_label", "Ограничение по времени", "Time limit")
add("settings_timer_description", "Укажите точное время окончания блокировки в формате HH:MM. Если время уже прошло, таймер сработает завтра.", "Specify the exact end time for blocking in HH:MM format. If the time has already passed, the timer will trigger tomorrow.")
add("settings_timer_end_label", "Время окончания:", "End time:")
add("settings_timer_placeholder", "23:30", "23:30")
add("settings_timer_set_btn", "✅ Установить", "✅ Set")
add("settings_secure_title", "Системная защита", "System protection")
add("settings_secure_switch_label_on", "Защита от завершения включена", "Termination protection is on")
add("settings_secure_switch_label_off", "Защита от завершения выключена", "Termination protection is off")
add("settings_secure_state_active", "Активна: AppBlockerGuard будет защищать приложение от закрытия.", "Active: AppBlockerGuard will protect the app from being closed.")
add("settings_secure_state_inactive", "Выключена: приложение можно закрыть через диспетчер задач.", "Off: the app can be closed via Task Manager.")
add("settings_secure_description", "Использует AppBlockerGuard и автозапуск при входе в систему.", "Uses AppBlockerGuard and autostart at login.")
add("settings_copy_path_btn", "Скопировать путь", "Copy path")

# -------------------- Режим блокировки (blacklist / whitelist) --------------------
add("settings_block_mode_title", "Режим блокировки", "Blocking mode")
add("settings_block_mode_description",
    "«Чёрный список» завершает только выбранные программы. «Белый список» наоборот: "
    "разрешает работать только выбранным программам, а остальные пользовательские "
    "процессы завершает. Системные процессы, антивирус, Проводник, Диспетчер задач и "
    "сам App Blocker не завершаются никогда.",
    "\"Blacklist\" terminates only the selected programs. \"Whitelist\" does the opposite: "
    "only the selected programs may run, and other processes of your user account are "
    "terminated. System processes, antivirus, Explorer, Task Manager, and App Blocker "
    "itself are never terminated.")
add("settings_block_mode_blacklist", "Чёрный список", "Blacklist")
add("settings_block_mode_whitelist", "Белый список", "Whitelist")
add("block_rule_not_in_whitelist", "нет в белом списке", "not in the whitelist")
add("log_block_mode_changed", "🔀 Режим блокировки: {mode}", "🔀 Blocking mode: {mode}")
add("log_block_mode_locked",
    "🔒 Режим блокировки нельзя менять после запуска блокировки.",
    "🔒 The blocking mode can't be changed after blocking has started.")
add("log_block_mode_failed",
    "⚠️ Не удалось переключить режим блокировки: {error}",
    "⚠️ Failed to switch the blocking mode: {error}")
add("monitor_allowed_programs_title", "Разрешённые программы", "Allowed programs")
add("monitor_allowed_list_empty",
    "Список пуст. В режиме «Белый список» добавьте программы, которым разрешено работать.",
    "The list is empty. In \"Whitelist\" mode, add the programs that are allowed to run.")
add("log_whitelist_needs_programs",
    "❗ В режиме «Белый список» сначала добавьте программы, которым разрешено работать.",
    "❗ In \"Whitelist\" mode, first add the programs that are allowed to run.")

# -------------------- Мягкая блокировка (postpone) --------------------
add("settings_postpone_title", "Мягкая блокировка", "Soft blocking")
add("settings_postpone_switch", "Мягкая блокировка (с задержкой)", "Soft blocking (with delay)")
add("settings_postpone_description",
    "Вместо мгновенного закрытия программы App Blocker покажет окно с обратным "
    "отсчётом: можно закрыть сразу или отменить закрытие. Если ничего не нажать, "
    "программа закроется по истечении отсчёта. Выключено — блокировка мгновенная.",
    "Instead of closing a program instantly, App Blocker shows a window with a "
    "countdown: you can close it right away or cancel. If you do nothing, the program "
    "is closed when the countdown ends. When off, blocking is instant.")
add("settings_postpone_seconds_label", "Задержка, секунд:", "Delay, seconds:")
add("settings_postpone_placeholder", "60", "60")
add("settings_postpone_set_btn", "✅ Установить", "✅ Set")
add("settings_postpone_current", "Сейчас: {seconds} с", "Now: {seconds} s")

add("log_postpone_enabled", "⏳ Мягкая блокировка включена: задержка {seconds} с", "⏳ Soft blocking enabled: {seconds} s delay")
add("log_postpone_disabled", "⚡ Мягкая блокировка выключена — закрытие мгновенное.", "⚡ Soft blocking disabled — closing is instant.")
add("log_postpone_seconds_set", "⏳ Задержка мягкой блокировки: {seconds} с", "⏳ Soft blocking delay: {seconds} s")
add("log_postpone_seconds_invalid",
    "⚠️ Введите задержку числом от {minimum} до {maximum} секунд.",
    "⚠️ Enter the delay as a number between {minimum} and {maximum} seconds.")
add("log_postpone_shown", "⏳ Мягкая блокировка: {programs} — отсчёт {seconds} с", "⏳ Soft blocking: {programs} — {seconds} s countdown")
add("log_postpone_close_now", "🔴 Закрыто по кнопке «Закрыть сейчас»: {programs}", "🔴 Closed via \"Close now\": {programs}")
add("log_postpone_timeout", "⏰ Отсчёт истёк, закрываю: {programs}", "⏰ Countdown expired, closing: {programs}")
add("log_postpone_cancelled",
    "🚫 Закрытие отменено: {programs}. Не буду трогать {minutes} мин.",
    "🚫 Closing cancelled: {programs}. Leaving it alone for {minutes} min.")
add("log_postpone_process_gone", "✅ Программа закрылась сама: {programs}", "✅ The program closed on its own: {programs}")
add("log_postpone_exemption_cleared", "🚫 Передышка отменена — блокирую сейчас.", "🚫 Reprieve cancelled — blocking now.")
add("log_monitor_iteration_failed",
    "⚠️ Сбой в цикле блокировки: {error}",
    "⚠️ Failure in the blocking loop: {error}")
add("log_dialog_close_failed",
    "⚠️ Не удалось закрыть модальное окно: {error}",
    "⚠️ Failed to close the modal window: {error}")
add("log_postpone_failed", "⚠️ Не удалось показать окно мягкой блокировки: {error}", "⚠️ Failed to show the soft blocking window: {error}")

add("postpone_dialog_title", "Мягкая блокировка", "Soft blocking")
add("postpone_message_one", "Программа {program} будет закрыта", "The program {program} will be closed")
add("postpone_message_many", "Программы {programs} будут закрыты", "The programs {programs} will be closed")
add("postpone_message_whitelist",
    "Все программы кроме {allowed} будут закрыты",
    "All programs except {allowed} will be closed")
add("postpone_countdown", "Закрытие через {seconds} с", "Closing in {seconds} s")
add("postpone_close_now_btn", "Закрыть сейчас", "Close now")
add("postpone_cancel_btn", "Отменить", "Cancel")

add("log_match_mode_changed", "🎯 Режим совпадения процессов: {mode}", "🎯 Process match mode: {mode}")
add("log_timer_state", "⏳ Таймер {state}", "⏳ Timer {state}")
add("timer_state_on", "включён ⏳", "enabled ⏳")
add("timer_state_off", "отключён ❌", "disabled ❌")
add("log_enter_timer_time", "⚠️ Введите время окончания в формате HH:MM", "⚠️ Enter the end time in HH:MM format")
add("log_timer_set", "⏳ Таймер установлен до {time}", "⏳ Timer set until {time}")
add("log_timer_started", "🕒 Таймер запущен", "🕒 Timer started")
add("log_timer_invalid", "⚠️ Введите корректное время в формате HH:MM, например 23:30", "⚠️ Enter a valid time in HH:MM format, e.g. 23:30")
add("log_secure_not_enabled_by_user", "ℹ️ Защита не включена пользователем.", "ℹ️ Protection was not enabled by the user.")
add("log_secure_disabled", "🧰 Защита от завершения отключена", "🧰 Termination protection disabled")

# ==================== Вкладка «О программе» ====================
add("about_title", "О программе", "About")
add("about_body",
    """APP BLOCKER
Версия: 3.0.0

App Blocker — это инструмент для ограничения запуска выбранных программ и сайтов на Linux.
Приложение отслеживает список процессов, завершает запрещённые при запуске и позволяет блокировать сайты через системный файл hosts.

ЧТО ЕСТЬ В ВЕРСИИ 3.0.0

Блокировка программ:

* Два режима: «Чёрный список» завершает выбранные программы, «Белый список» разрешает работать только выбранным.
* В режиме «Белый список» системное защищено двумя независимыми барьерами: списком «никогда не завершать» (ядро ОС, графическая сессия, сетевые и звуковые службы, сам App Blocker и AppBlockerGuard) и проверкой владельца процесса — завершаются только процессы вашей учётной записи, поэтому системные службы отсекаются сами, без перечисления имён.
* Защищены сам процесс приложения и цепочка его родителей: при запуске из исходников режим не завершит ни Python, ни среду разработки.
* Два режима совпадения имён: «Содержит» и «Точное имя».
* Мониторинг активных процессов в реальном времени и автовосстановление после перезапуска.

Мягкая блокировка (по умолчанию выключена, включается в настройках):

* Вместо мгновенного завершения показывается окно с обратным отсчётом.
* «Закрыть сейчас» завершает немедленно, «Отменить» оставляет программу работать и не спрашивает ещё 5 минут.
* Если не нажать ничего, программа закрывается по истечении отсчёта.
* Длительность задержки настраивается, по умолчанию 60 секунд.
* Если программа закрылась сама, окно исчезает без лишних вопросов.
* Пока окно открыто, второе не появляется.
* Выключение переключателя возвращает мгновенное завершение.

Расписание по дням недели:

* Интервалы на каждый день, блокировка включается сама.
* Несколько интервалов в день: 09:00-18:00, 20:00-22:00.
* Работают интервалы через полночь (22:00-02:00), в том числе на стыке недели.
* Расписание умеет только включать блокировку: вечную блокировку окончание интервала не снимает, а ручную блокировку сайтов расписание не отменяет.

Статистика:

* Срабатываний за сегодня и за 7 дней.
* Суммарное время, которое блокировка была активна.
* Топ-3 самых часто блокируемых программ и сайтов.
* Лента последних событий и экспорт истории в CSV (Excel открывает кириллицу без «кракозябр»).
* История хранится отдельно от настроек, в файле stats.json.

Сайты:

* Блокировка через системный файл hosts, без ограничения на число доменов.
* Автоматическая очистка DNS-кэша и закрытие браузеров для мгновенного применения.
* Работает независимо от блокировки программ.

Защита и безопасность:

* AppBlockerGuard: защита от завершения и автовосстановление.
* Автозапуск при входе в систему через .desktop-файл (XDG autostart).
* Пароль администратора хранится в виде PBKDF2-хеша.
* После запуска блокировки запираются все переключатели, которыми её можно ослабить.
* Мягкую блокировку при этом выключить можно всегда — это делает блокировку строже, — а включить на ходу нельзя.
* Диагностика защиты и автозапуска, импорт и экспорт настроек, резервная копия конфигурации.

Интерфейс:

* Русский и английский языки, переключение кнопкой Language без перезапуска.
* Тёмная тема в духе Epic Games Store: почти чёрный нейтральный фон и один акцентный синий.
* Боковая панель раскрывается при наведении курсора.
* Подсветка под курсором: на карточках и пунктах навигации светится круг, следящий за мышью.
* Строки списков влетают слева каскадом.
* Плавное растворение при переключении разделов.
* Трей-иконка, панель логов и карточки состояния.

ГЛАВНОЕ ИЗМЕНЕНИЕ ВЕРСИИ

Интерфейс переписан с CustomTkinter на Flet. Это дало то, что раньше было недостижимо: круг подсветки под курсором (в CustomTkinter надпись кнопки рисовалась отдельной непрозрачной меткой и закрывала градиент) и влёт строк слева (у прежнего менеджера раскладки не было отрицательных смещений, а обход через сжатие ширины оставлял на экране пиксели прежних кадров).

ЧТО ИСПРАВЛЕНО

* Переключатель режима вешал приложение намертво: пересборка сегментированной кнопки уничтожала ту самую кнопку, чей обработчик выполнялся.
* Модальные окна могли захватить ввод, не будучи видимыми — приложение выглядело зависшим, а нажать было нечего.
* Диалоги не центрировались и появлялись в углу.
* Анимация ширины не сходилась при масштабе экрана больше 100%.
* Раскрытие боковой панели превращало текст в кашу из остатков кадров.
* Кнопка «Очистить» дописывала отметку в файл логов вместо его очистки.
* Сохранённый язык не восстанавливался при запуске, а переводы применялись только к боковой панели.
* Сохранённое состояние мягкой блокировки не подхватывалось интерфейсом.
* Мягкую блокировку нельзя было включить при активной вечной блокировке.
* После «Отменить» большая кнопка оставалась неактивной — теперь она превращается в «Заблокировать сейчас».
* Режим блокировки и режим совпадения имён можно было менять после запуска блокировки.
* Часть имён в списке исключений системных процессов была записана в другом регистре и не совпадала никогда: MpCmdRun.exe (Defender) и RstMwService.exe (Intel RST) считались обычными пользовательскими процессами.

Разработчик: smics_play
Помощь в разработке: ChatGPT и Claude AI

Используйте программу ответственно и только на компьютерах, где у вас есть право на такие ограничения.
""",
    """APP BLOCKER
Version: 3.0.0

App Blocker is a tool for restricting the launch of selected programs and websites on Linux.
The app watches the process list, terminates blocked programs when they start, and can block websites through the system hosts file.

WHAT'S IN VERSION 3.0.0

Program blocking:

* Two modes: "Blacklist" terminates the selected programs, "Whitelist" lets only the selected ones run.
* In "Whitelist" mode the system is protected by two independent barriers: a never-terminate list (OS core, graphical session, network and audio services, App Blocker itself and AppBlockerGuard) and a process owner check — only processes of your own account are terminated, so system services are excluded by themselves, without listing their names.
* The application's own process and its parent chain are protected: when run from source, the mode will not terminate Python or your IDE.
* Two name matching modes: "Contains" and "Exact name".
* Real-time monitoring of active processes and auto-recovery after a restart.

Soft blocking (disabled by default, enabled in the settings):

* Instead of terminating instantly, a window with a countdown is shown.
* "Close now" terminates immediately, "Cancel" leaves the program running and does not ask again for 5 minutes.
* If you do nothing, the program is closed when the countdown ends.
* The delay is configurable, 60 seconds by default.
* If the program closes on its own, the window disappears without further questions.
* While the window is open, a second one is never shown.
* Turning the switch off restores instant termination.

Weekly schedule:

* Intervals for every day; blocking turns on by itself.
* Several intervals per day: 09:00-18:00, 20:00-22:00.
* Overnight intervals work (22:00-02:00), including across the week boundary.
* The schedule can only turn blocking on: the end of an interval does not lift the permanent lock, and the schedule never cancels manual website blocking.

Statistics:

* Blocking events today and over the last 7 days.
* Total time blocking has been active.
* Top 3 most frequently blocked programs and sites.
* A feed of recent events and history export to CSV (Excel opens Cyrillic correctly).
* History is stored separately from the settings, in stats.json.

Websites:

* Blocking through the system hosts file, with no limit on the number of domains.
* Automatic DNS cache flushing and browser closing for instant effect.
* Works independently of program blocking.

Protection and security:

* AppBlockerGuard: termination protection and auto-recovery.
* Autostart at login via a .desktop file (XDG autostart).
* The administrator password is stored as a PBKDF2 hash.
* Once blocking starts, everything that could weaken it is locked.
* Soft blocking can still be switched off at any time — that makes blocking stricter — but it cannot be switched on while blocking is already running.
* Protection and autostart diagnostics, settings import and export, configuration backup.

Interface:

* Russian and English, switched with the Language button without a restart.
* Dark theme in the spirit of the Epic Games Store: an almost black neutral background and a single blue accent.
* The sidebar expands on hover.
* Cursor spotlight: cards and navigation items glow with a circle that follows the mouse.
* List rows fly in from the left in a cascade.
* Smooth fade when switching sections.
* Tray icon, log panel and status cards.

THE KEY CHANGE OF THIS VERSION

The interface was rewritten from CustomTkinter to Flet. This made possible what was out of reach before: the cursor spotlight (in CustomTkinter a button's label was drawn by a separate opaque widget that covered the gradient) and rows flying in from the left (the old layout manager had no negative offsets, and working around it by shrinking the width left pixels of previous frames on screen).

WHAT WAS FIXED

* The mode switch froze the application solid: rebuilding the segmented button destroyed the very button whose handler was running.
* Modal windows could grab input while not being visible — the app looked frozen with nothing to click.
* Dialogs were not centred and appeared in the corner.
* The width animation did not converge at display scaling above 100%.
* Expanding the sidebar turned text into a mess of leftover frames.
* The "Clear" button appended a note to the log file instead of clearing it.
* The saved language was not restored at startup, and translations were applied to the sidebar only.
* The saved soft blocking state was not picked up by the interface.
* Soft blocking could not be enabled while the permanent lock was active.
* After "Cancel" the main button stayed disabled — it now turns into "Block now".
* The blocking mode and name matching mode could be changed after blocking had started.
* Part of the names in the system process exclusion list were written in a different case and never matched: MpCmdRun.exe (Defender) and RstMwService.exe (Intel RST) were treated as ordinary user processes.

Developer: smics_play
Development help: ChatGPT and Claude AI

Use the program responsibly and only on computers where you have the right to impose such restrictions.
""")

# ==================== Вкладка «Расписание» ====================
add("nav_schedule", "Расписание", "Schedule")
add("schedule_title", "Расписание блокировки", "Blocking schedule")
add("schedule_enable_switch", "Включить расписание", "Enable schedule")
add("schedule_description",
    "Укажите для каждого дня интервалы, когда блокировка включается сама. "
    "Формат: 09:00-18:00. Несколько интервалов — через запятую. "
    "Интервал через полночь тоже работает: 22:00-02:00.",
    "Set the intervals for each day when blocking turns on by itself. "
    "Format: 09:00-18:00. Separate multiple intervals with commas. "
    "Overnight intervals work too: 22:00-02:00.")
add("schedule_note",
    "Расписание только включает блокировку. Если блокировка уже запущена вручную "
    "(вечная блокировка), окончание интервала её не снимет.",
    "The schedule can only turn blocking on. If blocking was already started manually "
    "(permanent lock), the end of an interval will not lift it.")
add("schedule_placeholder", "09:00-18:00, 20:00-22:00", "09:00-18:00, 20:00-22:00")
add("schedule_save_btn", "💾 Сохранить расписание", "💾 Save schedule")
add("schedule_clear_btn", "🧹 Очистить всё", "🧹 Clear all")
add("schedule_status_off", "Расписание выключено", "Schedule is off")
add("schedule_status_empty", "Интервалы не заданы", "No intervals set")
add("schedule_status_active", "Сейчас идёт окно блокировки", "A blocking window is active now")
add("schedule_status_inactive", "Сейчас вне окна блокировки", "Currently outside a blocking window")
add("schedule_status_label", "Состояние:", "Status:")
add("schedule_day_monday", "Понедельник", "Monday")
add("schedule_day_tuesday", "Вторник", "Tuesday")
add("schedule_day_wednesday", "Среда", "Wednesday")
add("schedule_day_thursday", "Четверг", "Thursday")
add("schedule_day_friday", "Пятница", "Friday")
add("schedule_day_saturday", "Суббота", "Saturday")
add("schedule_day_sunday", "Воскресенье", "Sunday")

add("log_schedule_saved", "🗓 Расписание сохранено. Интервалов: {count}", "🗓 Schedule saved. Intervals: {count}")
add("log_schedule_invalid", "⚠️ {day}: непонятный интервал «{value}». Формат: 09:00-18:00", "⚠️ {day}: can't read the interval \"{value}\". Format: 09:00-18:00")
add("log_schedule_cleared", "🧹 Расписание очищено.", "🧹 Schedule cleared.")
add("log_schedule_enabled", "🗓 Расписание включено.", "🗓 Schedule enabled.")
add("log_schedule_disabled", "🗓 Расписание выключено.", "🗓 Schedule disabled.")
add("log_schedule_no_intervals", "⚠️ Расписание включено, но интервалы не заданы.", "⚠️ The schedule is enabled, but no intervals are set.")
add("log_schedule_window_started", "🗓 Начало окна блокировки по расписанию.", "🗓 Scheduled blocking window started.")
add("log_schedule_window_ended", "🗓 Окно блокировки по расписанию закончилось.", "🗓 Scheduled blocking window ended.")
add("log_schedule_window_end_permanent", "🔒 Окно расписания закончилось, но вечная блокировка остаётся активной.", "🔒 The scheduled window ended, but the permanent lock stays active.")
add("log_schedule_needs_programs", "⚠️ Окно расписания началось, но список программ пуст — блокировать нечего.", "⚠️ A scheduled window started, but the program list is empty — nothing to block.")
add("log_schedule_monitoring_started", "🚀 Мониторинг запущен по расписанию.", "🚀 Monitoring started by the schedule.")
add("log_schedule_monitoring_stopped", "🛑 Мониторинг остановлен по расписанию.", "🛑 Monitoring stopped by the schedule.")
add("log_schedule_sites_no_admin", "ℹ️ Сайты по расписанию не переключены: для записи hosts нужны права администратора.", "ℹ️ Scheduled site blocking skipped: writing hosts requires administrator rights.")

# ==================== Вкладка «Статистика» ====================
add("nav_stats", "Статистика", "Statistics")
add("stats_title", "Статистика блокировок", "Blocking statistics")
add("stats_card_today", "Срабатываний сегодня", "Blocks today")
add("stats_card_week", "Срабатываний за 7 дней", "Blocks in 7 days")
add("stats_card_time_today", "Блокировка активна сегодня", "Blocking active today")
add("stats_card_time_total", "Всего под блокировкой", "Total time blocked")
add("stats_top_title", "Топ-3 за 7 дней", "Top 3 in 7 days")
add("stats_top_empty", "Пока нет ни одного срабатывания.", "No blocking events yet.")
add("stats_top_row", "{position}. {target} — {count}", "{position}. {target} — {count}")
add("stats_events_title", "Последние события", "Recent events")
add("stats_events_empty", "История пуста.", "History is empty.")
add("stats_kind_program", "программа", "program")
add("stats_kind_site", "сайт", "site")
add("stats_duration_hm", "{hours} ч {minutes} мин", "{hours} h {minutes} min")
add("stats_duration_m", "{minutes} мин", "{minutes} min")
add("stats_refresh_btn", "Обновить", "Refresh")
add("stats_export_csv_btn", "Экспорт в CSV", "Export to CSV")
add("stats_clear_btn", "Очистить историю", "Clear history")
add("stats_total_events", "Всего событий в истории: {count}", "Total events in history: {count}")
add("dialog_export_stats_title", "Экспорт статистики", "Export statistics")
add("dialog_clear_stats_title", "Очистить историю?", "Clear history?")
add("dialog_clear_stats_message",
    "Вся история срабатываний блокировки будет удалена. Действие нельзя отменить.",
    "The entire blocking history will be deleted. This cannot be undone.")
add("stats_csv_date", "Дата", "Date")
add("stats_csv_time", "Время", "Time")
add("stats_csv_target", "Программа/сайт", "Program/site")
add("stats_csv_kind", "Тип", "Type")
add("stats_csv_action", "Действие", "Action")
add("stats_csv_rule", "Правило", "Rule")
add("log_stats_exported", "✅ Статистика выгружена в CSV ({count} событий): {path}", "✅ Statistics exported to CSV ({count} events): {path}")
add("log_stats_export_failed", "⚠️ Ошибка экспорта статистики: {error}", "⚠️ Statistics export error: {error}")
add("log_stats_cleared", "🧹 История статистики очищена.", "🧹 Statistics history cleared.")

# ==================== Диалоги ====================
add("dialog_exit_title", "Выход", "Exit")
add("dialog_exit_message", "Введите пароль администратора для выхода:", "Enter the administrator password to exit:")
add("dialog_admin_password_title", "Пароль администратора", "Administrator password")
add("dialog_admin_password_new_message", "Введите пароль, который будет использоваться для выхода:", "Enter the password that will be used to exit:")
add("dialog_admin_password_login_message", "Введите пароль администратора для входа:", "Enter the administrator password to sign in:")
add("dialog_ok", "✅ ОК", "✅ OK")
add("dialog_cancel", "✕ Отмена", "✕ Cancel")
add("dialog_password_hint", "Пароль", "Password")
add("dialog_continue", "Продолжить", "Continue")
add("dialog_yes", "Да", "Yes")
add("dialog_no", "Нет", "No")
add("dialog_error_title", "Ошибка", "Error")
add("dialog_wrong_password", "Неверный пароль! Выход запрещён.", "Wrong password! Exit denied.")
add("dialog_wrong_password_retry", "Неверный пароль! Попробуйте снова.", "Wrong password! Try again.")
add("dialog_no_password_set", "Пароль не задан! Программа будет закрыта.", "No password set! The program will close.")
add("dialog_access_denied", "Доступ заблокирован без правильного пароля.", "Access denied without the correct password.")
add("dialog_first_setup_title", "Первичная настройка", "Initial setup")
add("dialog_first_setup_message",
    "App Blocker будет завершать выбранные программы и может восстанавливать мониторинг после перезапуска системы.\n\n"
    "Сейчас нужно создать пароль администратора. Он потребуется для выхода и изменения защищённых сценариев.\n\n"
    "Сохраните пароль: без него корректный выход будет невозможен.",
    "App Blocker will terminate the selected programs and may restore monitoring after the system restarts.\n\n"
    "Now you need to create an administrator password. It will be required to exit and change protected scenarios.\n\n"
    "Save the password: without it, a correct exit will be impossible.")
add("dialog_security_disabled_title", "Защита выключена", "Protection is off")
add("dialog_security_disabled_heading", "Защита приложения выключена", "App protection is off")
add("dialog_security_disabled_message",
    "Защита приложения выключена, его можно легко закрыть из диспетчера задач. Зайдите в настройки и включите ее.",
    "App protection is off — it can easily be closed from Task Manager. Go to Settings and enable it.")
add("dialog_enable_btn", "Включить", "Enable")
add("dialog_decline_btn", "Отказаться", "Decline")
add("dialog_enable_protection_question", "Включить системную защиту?", "Enable system protection?")
add("dialog_protection_message",
    "App Blocker использует автозапуск, AppBlockerGuard и защиту от завершения.\n\n"
    "Вы можете доверять программе: исходный код открыт и доступен для проверки:\n"
    "https://github.com/smicsic/App-Blocker",
    "App Blocker uses autostart, AppBlockerGuard, and termination protection.\n\n"
    "You can trust the program: the source code is open and available for review:\n"
    "https://github.com/smicsic/App-Blocker")
add("dialog_program_folder_label", "Папка программы", "Program folder")
add("dialog_path_copied", "Путь скопирован.", "Path copied.")
add("dialog_i_added_enable_btn", "Включить", "Enable")
add("dialog_cancel_plain", "Отмена", "Cancel")

# ==================== Диагностика / автозапуск ====================
add("log_startup_configured_both", "✅ Автозапуск настроен для AppBlocker и AppBlockerGuard", "✅ Autostart configured for AppBlocker and AppBlockerGuard")
add("log_startup_app_only", "⚠️ Автозапуск AppBlocker настроен, но AppBlockerGuard не найден или не добавлен", "⚠️ AppBlocker autostart configured, but AppBlockerGuard was not found or added")
add("log_startup_failed", "⚠️ Не удалось настроить автозапуск.", "⚠️ Failed to configure autostart.")
add("log_diagnostics_summary", "🧪 Диагностика защиты: {ok}/{total} проверок пройдено", "🧪 Protection diagnostics: {ok}/{total} checks passed")
add("diag_admin_rights", "Права root", "Root rights")
add("diag_app_exe_found", "AppBlocker найден", "AppBlocker found")
add("diag_guard_exe_found", "AppBlockerGuard найден", "AppBlockerGuard found")
add("diag_config_accessible", "config.json доступен", "config.json accessible")
add("diag_password_hashed", "Пароль защищён хешем", "Password protected by hash")
add("diag_autostart_app", "Автозапуск AppBlocker", "AppBlocker autostart")
add("diag_autostart_guard", "Автозапуск AppBlockerGuard", "AppBlockerGuard autostart")
add("diag_guard_running", "AppBlockerGuard запущен", "AppBlockerGuard running")
add("diag_hosts_access", "Доступ к hosts", "hosts file access")
add("log_guard_exe_not_found", "⚠️ AppBlockerGuard не найден: {path}", "⚠️ AppBlockerGuard not found: {path}")
add("log_path_copied", "Путь App Blocker скопирован: {path}", "App Blocker path copied: {path}")
add("log_path_copy_failed", "Не удалось скопировать путь: {error}", "Failed to copy the path: {error}")
add("log_guard_activated_generic", "🛡 AppBlockerGuard активирован", "🛡 AppBlockerGuard activated")
add("log_protection_enabled_by_user", "🛡 Защита включена пользователем.", "🛡 Protection enabled by the user.")
add("log_process_cleanup_error", "⚠️ Ошибка при завершении процесса: {error}", "⚠️ Error while terminating a process: {error}")

# ==================== Конфигурация (импорт/экспорт) ====================
add("dialog_export_settings_title", "Экспорт настроек", "Export settings")
add("dialog_import_settings_title", "Импорт настроек", "Import settings")
add("log_config_exported", "✅ Настройки экспортированы: {path}", "✅ Settings exported: {path}")
add("log_config_export_failed", "⚠️ Ошибка экспорта настроек: {error}", "⚠️ Settings export error: {error}")
add("log_config_imported", "✅ Настройки импортированы: {path}", "✅ Settings imported: {path}")
add("log_config_import_failed", "⚠️ Ошибка импорта настроек: {error}", "⚠️ Settings import error: {error}")

# ==================== Жизненный цикл / выход ====================
add("log_sentinel_error", "⚠️ Ошибка sentinel: {error}", "⚠️ Sentinel error: {error}")
add("log_window_hidden_to_tray", "📌 Окно скрыто в трей.", "📌 Window hidden to tray.")
add("log_window_minimized_no_tray", "📌 Окно свернуто. Библиотека трея недоступна.", "📌 Window minimized. Tray library is unavailable.")
add("log_removing_sites_from_hosts", "🧼 Удаляем {count} сайтов из hosts...", "🧼 Removing {count} site(s) from hosts...")
add("log_all_sites_unblocked", "✅ Все сайты разблокированы", "✅ All sites unblocked")
add("log_retry_attempt", "⚠️ Попытка {attempt}/3, повторяю...", "⚠️ Attempt {attempt}/3, retrying...")
add("log_sites_list_empty", "ℹ️ Список сайтов пуст", "ℹ️ The site list is empty")
add("log_unblock_sites_error", "⚠️ Ошибка при очистке сайтов: {error}", "⚠️ Error clearing sites: {error}")
add("log_guard_pid_terminated", "🛑 AppBlockerGuard PID {pid} завершён", "🛑 AppBlockerGuard PID {pid} terminated")
add("log_config_saved_for_settings", "🧹 config.json сохранён, чтобы не терять настройки защиты", "🧹 config.json saved to keep protection settings")
add("log_sentinel_removed", "🧹 config.exit.lock удалён", "🧹 config.exit.lock removed")
add("log_file_removal_error", "⚠️ Ошибка при удалении файлов: {error}", "⚠️ Error removing files: {error}")
add("log_exit_cancelled_no_process", "⚠️ Выход отменён: процесс не задан (первый запуск)", "⚠️ Exit cancelled: no process set (first run)")
add("log_exit_cancelled_no_monitoring", "⚠️ Выход отменён: мониторинг не был запущен", "⚠️ Exit cancelled: monitoring was not running")
add("log_exit_no_password", "⏰ Выход без пароля (таймер/автоматический)...", "⏰ Exiting without a password (timer/automatic)...")
add("log_exit_starting", "🚪 Начинаем процедуру выхода...", "🚪 Starting the exit procedure...")
add("log_stopping_threads", "🛑 Останавливаем фоновые потоки...", "🛑 Stopping background threads...")
add("log_threads_stopped", "✅ Потоки остановлены", "✅ Threads stopped")
add("log_retry_attempt_final", "⚠️ Попытка {attempt}/3 не удалась, повторяю...", "⚠️ Attempt {attempt}/3 failed, retrying...")
add("log_hosts_cleanup_failed", "❌ Не удалось полностью очистить hosts после 3 попыток", "❌ Failed to fully clean up hosts after 3 attempts")
add("log_blocked_sites_list_empty", "ℹ️ Список заблокированных сайтов пуст", "ℹ️ The blocked sites list is empty")
add("log_unblock_sites_error2", "⚠️ Ошибка при разблокировке сайтов: {error}", "⚠️ Error unblocking sites: {error}")
add("log_exit_written", "📝 EXIT записан в config.json", "📝 EXIT written to config.json")
add("log_exit_write_error", "⚠️ Ошибка при записи EXIT: {error}", "⚠️ Error writing EXIT: {error}")
add("log_terminating_guard", "🧨 Завершаем AppBlockerGuard...", "🧨 Terminating AppBlockerGuard...")
add("log_removing_from_startup", "🧹 Удаляем из автозагрузки...", "🧹 Removing from startup...")
add("log_startup_cleared", "✅ Автозагрузка очищена", "✅ Startup entries cleared")
add("log_startup_entries_not_found", "ℹ️ Записи не найдены", "ℹ️ No entries found")
add("log_shutting_down", "👋 Завершение работы...", "👋 Shutting down...")
add("log_time_expired", "⏰ Время работы истекло — программа завершается.", "⏰ Time is up — the program is shutting down.")
add("log_guard_terminated_by_timer", "🛑 AppBlockerGuard завершён по таймеру.", "🛑 AppBlockerGuard terminated by the timer.")

# ==================== Процессы ====================
add("log_process_terminated", "🔴 Приложение '{name}' (PID: {pid}) завершено. Правило: {rule}", "🔴 Application '{name}' (PID: {pid}) terminated. Rule: {rule}")
add("log_blocked_program_found", "🔍 Найдена заблокированная программа. Закрываю...", "🔍 A blocked program was found. Closing it...")
add("log_no_blocked_programs_running", "✅ Заблокированные программы не запущены.", "✅ No blocked programs are running.")

# ==================== Сайты (hosts) ====================
add("log_browsers_closed", "🔄 Браузеры закрыты для мгновенного применения блокировки: {names}", "🔄 Browsers closed to instantly apply blocking: {names}")
add("log_hosts_no_admin", "❌ Не удалось изменить hosts: доступ через pkexec не подтверждён.", "❌ Failed to modify hosts: pkexec access was not granted.")
add("log_hosts_pkexec_failed", "❌ pkexec не смог записать /etc/hosts: {error}", "❌ pkexec failed to write /etc/hosts: {error}")
add("log_hosts_missing_sites", "⚠️ Не все сайты попали в hosts: {sites}", "⚠️ Not all sites made it into hosts: {sites}")
add("log_hosts_old_entries_remain", "⚠️ В hosts остались старые записи App Blocker", "⚠️ Old App Blocker entries remain in hosts")
add("log_hosts_applied", "🌐 Блокировка сайтов применена: {rules} правил, {domains} доменов в hosts", "🌐 Website blocking applied: {rules} rule(s), {domains} domain(s) in hosts")
add("log_hosts_cleared", "🧹 Блокировка сайтов очищена", "🧹 Website blocking cleared")
add("log_hosts_no_admin2", "❌ Нет прав для изменения hosts.", "❌ No rights to modify hosts.")
add("log_hosts_block_error", "⚠️ Ошибка блокировки сайтов: {error}", "⚠️ Website blocking error: {error}")

# ==================== Трей ====================
add("tray_open", "Открыть", "Open")
add("tray_hide", "Скрыть", "Hide")
add("tray_exit", "Выход", "Exit")

# ==================== Bootstrap (запуск) ====================
add("log_enter_process_and_start", "Введите название процесса и нажмите 'Начать'.", "Enter a process name and click 'Start'.")
add("log_permanent_lock_active", "🔐 Перманентная блокировка активна — переключатели навсегда заблокированы.", "🔐 Permanent lock is active — switches are locked forever.")
add("log_timer_active_until", "⏳ Таймер активен до {time}", "⏳ Timer active until {time}")
add("log_timer_switch_locked", "🔒 Переключатель таймера и поля ввода заблокированы (автозагрузка)", "🔒 Timer switch and input fields are locked (startup)")
add("log_guard_restored_app", "🛡 AppBlocker восстановлен AppBlockerGuard после завершения процесса.", "🛡 AppBlocker was restored by AppBlockerGuard after the process ended.")
add("log_admin_password_confirmed", "🔓 Пароль администратора подтверждён.", "🔓 Administrator password confirmed.")
add("log_guard_started_at_boot", "🛡 AppBlockerGuard запущен при старте AppBlocker", "🛡 AppBlockerGuard started when AppBlocker launched")
add("log_protection_enabled_not_active", "ℹ️ Защита включена, но блокировка не активна — AppBlockerGuard не запускается до старта блокировки.", "ℹ️ Protection is enabled, but blocking is not active — AppBlockerGuard won't start until blocking begins.")
add("log_termination_protection_started", "🛡 Система защиты от завершения запущена", "🛡 Termination protection system started")
add("log_exit_status_found", "ℹ️ Найден статус EXIT — автозапуск блокировок пропущен.", "ℹ️ EXIT status found — automatic block restore skipped.")
add("log_monitoring_restored", "✅ Автовосстановление мониторинга для программ: {programs}", "✅ Monitoring auto-restored for programs: {programs}")
add("log_sites_restored", "🌐 Автовосстановление блокировки сайтов: {count}", "🌐 Website blocking auto-restored: {count}")
add("log_guard_monitoring_already_active", "ℹ️ Мониторинг AppBlockerGuard уже активен", "ℹ️ AppBlockerGuard monitoring is already active")
add("log_guard_watch_started", "👁️ Мониторинг AppBlockerGuard запущен", "👁️ AppBlockerGuard monitoring started")
add("log_guard_watch_started_startup", "👁️ Мониторинг AppBlockerGuard активирован", "👁️ AppBlockerGuard monitoring activated")
add("log_guard_watch_started_sites", "👁️ Мониторинг AppBlockerGuard запущен для сайтов", "👁️ AppBlockerGuard monitoring started for websites")
