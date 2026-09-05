# 🧱 App Blocker

### Современная система блокировки приложений и сайтов для Windows

**Версия:** 3.0.0
**Автор:** Вова (@smics_play)

> 🐧 **Есть версия для Linux.** В репозитории на GitHub App Blocker распространяется
> в виде двух отдельных папок: `Windows/` (эта версия) и `Linux/` (порт на
> systemd, `/etc/hosts`, `pkexec` и XDG-автозапуск вместо реестра и Task
> Scheduler). Функциональность одинаковая, но реализация системно-специфичных
> частей разная — если вы на Linux, используйте папку `Linux/` и её README.

---

# 📖 О проекте

**App Blocker** — современная программа для Windows, предназначенная для ограничения доступа к приложениям и веб-сайтам.

Программа позволяет блокировать выбранные процессы, ограничивать доступ к сайтам, защищать себя от завершения и автоматически восстанавливать свою работу после перезапуска системы.

В отличие от обычных блокировщиков процессов, App Blocker использует отдельный защитный модуль **AppBlockerGuard**, который обеспечивает дополнительный уровень безопасности и стабильности.

Программа отлично подходит для:

* 🏫 Учебных заведений
* 🏢 Офисов
* 👨‍👩‍👧 Родительского контроля
* 💻 Домашнего использования
* 🔒 Рабочих компьютеров

---

# 🚀 Возможности

## 🖥 Блокировка приложений

* Блокировка нескольких программ одновременно
* Мониторинг процессов в режиме реального времени
* Автоматическое завершение запрещённых приложений
* Работа в фоновом режиме
* Просмотр активных процессов
* Два режима совпадения имён: «Содержит» и «Точное имя»
* Автоматическое восстановление мониторинга после перезапуска

---

## ⚫⚪ Два режима блокировки

* **Чёрный список** — завершаются только выбранные программы (поведение по умолчанию)
* **Белый список** — работать разрешено только выбранным программам, остальные пользовательские процессы завершаются

Системные процессы в режиме «Белый список» защищены **двумя независимыми барьерами**:

1. Список «никогда не завершать»: ядро ОС, вход в систему, Проводник, антивирус, обновления, Диспетчер задач, сам App Blocker и AppBlockerGuard.
2. Проверка владельца процесса — завершаются только процессы вашей учётной записи. Службы под `SYSTEM` и `LOCAL SERVICE` отсекаются **структурно**, без перечисления имён, поэтому защита не зависит ни от конкретного компьютера, ни от языка Windows.

Дополнительно защищены сам процесс приложения и вся цепочка его родителей — при запуске из исходников режим не завершит ни Python, ни среду разработки.

---

## ⏳ Мягкая блокировка (по умолчанию выключена)

Включается переключателем в настройках. Вместо мгновенного завершения программа показывает окно с обратным отсчётом:

* **Закрыть сейчас** — завершить немедленно
* **Отменить** — оставить программу работать; повторный вопрос не задаётся ещё 5 минут
* Если не нажать ничего, программа закрывается по истечении отсчёта
* Длительность задержки настраивается (по умолчанию 60 секунд)
* Если программа закрылась сама, окно исчезает без лишних вопросов
* Пока окно открыто, второе не появляется — одна программа не «спамит» диалогами

Обратное выключение переключателя возвращает мгновенное завершение.

---

## 🗓 Расписание по дням недели

* Интервалы на каждый день недели, блокировка включается сама
* Несколько интервалов в день: `09:00-18:00, 20:00-22:00`
* Работают интервалы через полночь: `22:00-02:00` — в том числе на стыке недели
* Фоновая проверка каждые 20 секунд, реакция на правку расписания — сразу

Расписание умеет только **включать** блокировку. Если блокировка уже запущена вручную (вечная блокировка), окончание интервала её не снимает — иначе расписание стало бы способом обойти защиту. Останавливается только то, что расписание само и включило: ручную блокировку сайтов оно не отменяет.

---

## 📊 Статистика

* Срабатываний за сегодня и за 7 дней
* Суммарное время, которое блокировка была активна
* Топ-3 самых часто блокируемых программ и сайтов
* Лента последних событий с временем, целью и типом
* **Экспорт в CSV**: разделитель `;` и кодировка UTF-8 с BOM — Excel открывает кириллицу без «кракозябр» и сам раскладывает по столбцам

История хранится в отдельном файле `stats.json` в `%APPDATA%\AppBlocker` и не смешивается с настройками: `config.json` пользователи экспортируют и импортируют, история блокировок там лишняя.

---

## 🌐 Блокировка сайтов

* Блокировка сайтов через системный файл **hosts**
* Неограниченное количество доменов
* Мгновенное применение изменений
* Автоматическая очистка DNS-кэша
* Независимая работа от блокировки приложений

---

## 🛡 Система защиты

* AppBlockerGuard
* Защита от завершения через Диспетчер задач
* Автоматическое восстановление компонентов
* Автозапуск приложения
* Проверка целостности конфигурации
* Корректное завершение работы

После запуска блокировки запираются все переключатели, которыми её можно ослабить: режим блокировки, режим совпадения имён, таймер, защита. Мягкую блокировку при этом **выключить можно всегда** — это делает блокировку строже, — а включить на ходу нельзя.

---

## 🔐 Безопасность

* Пароль администратора
* Хранение пароля в виде PBKDF2-хеша
* Импорт и экспорт настроек
* Автоматическое резервное копирование конфигурации
* Подробный журнал событий

---

## 🌍 Два языка интерфейса

* Русский и английский, переключение кнопкой **Language** в правом верхнем углу
* Меняется весь интерфейс — вкладки, диалоги, журнал событий
* Перевод применяется сразу, без перезапуска
* Выбор языка сохраняется между запусками

---

## 🎨 Интерфейс

* Тёмная тема в духе Epic Games Store: почти чёрный нейтральный фон, один акцентный синий, малые радиусы скругления
* Боковая панель раскрывается при наведении курсора
* Подсветка под курсором: на карточках светится круг, следящий за мышью
* Строки списков влетают слева каскадом
* Плавное растворение при переключении разделов
* Карточки состояния, встроенная диагностика, поддержка системного трея

---

# ✨ Что нового в версии 3.0.0

## Переход на Flet

Интерфейс переписан с CustomTkinter на **Flet** (Flutter под капотом). Это дало то, что на Tk было принципиально недостижимо:

* **Круг подсветки под курсором.** В CustomTkinter надпись кнопки рисуется отдельным непрозрачным `Label`, и любой градиент оказывался закрыт прямоугольником вокруг текста. Приходилось светлеть кнопкой целиком, пересчитывая цвет 60 раз в секунду.
* **Влёт строк слева.** У `pack` нет отрицательных смещений, вынести строку за левый край было нельзя. Обход через сжатие ширины оставлял на экране пиксели прежних кадров, а надёжно чинила это только синхронная перерисовка, из-за которой приложение зависало.
* Плавность теперь считает движок, а не подобранные замером константы кадра.

## Новые возможности

* Режим **белого списка** с двухуровневой защитой системных процессов
* **Мягкая блокировка** с обратным отсчётом (по умолчанию выключена)
* **Расписание** по дням недели, с интервалами через полночь
* Вкладка **статистики** и экспорт истории в **CSV**
* **Два языка** интерфейса с переключением на ходу

## Новое оформление

* Палитра переведена с фиолетово-розовой на нейтральную тёмную с одним синим акцентом
* Радиусы скругления уменьшены с 24/16 до 8/4 — «таблетки» читались как дешёвый шаблон
* Фон стал почти плоским: цветные пятна в тёмном интерфейсе выглядят дёшево
* Шрифт заменён на системный Segoe UI, моношрифт — на Consolas (есть в любой Windows, в отличие от JetBrains Mono)
* Красный убран из постоянного вида разрушающих кнопок — включается только при наведении
* Активный раздел навигации выделен подложкой и синей полосой, а не залит синим целиком

## Исправленные ошибки

**Интерфейс**

* Переключатель режима вешал приложение намертво: `configure(values=...)` у сегментированной кнопки уничтожал ту самую кнопку, чей обработчик в этот момент выполнялся
* Модальные окна могли захватить ввод, **не будучи видимыми** — приложение выглядело зависшим, а нажать было нечего. `CTkToplevel` на короткое время скрывает себя для перерисовки заголовка, и захват ввода происходил раньше показа. Теперь ввод забирается только после того, как окно реально отображено
* Диалоги не центрировались и появлялись в углу каскадом
* Анимация ширины не сходилась при масштабе экрана больше 100%: текущая ширина читалась в физических пикселях, а цель задавалась в логических
* Боковая панель при раскрытии пересчитывала раскладку всего окна, и текст превращался в кашу из остатков кадров. Теперь панель наезжает поверх содержимого, а не раздвигает его
* Каждая кнопка держала свой таймер анимации; при движении мышью по списку одновременно догорали десятки кнопок. Сведено к одному общему такту
* Первая строка журнала склеивалась со следующей записью из-за пропущенного перевода строки

**Логика**

* Кнопка «Очистить» дописывала отметку в файл журнала вместо его очистки; теперь файл усекается, а запись идёт под общей блокировкой, потому что журнал пишут несколько потоков
* Сохранённый язык не восстанавливался при запуске: `load_language()` не вызывался вообще
* Переводы применялись только к боковой панели — содержимое вкладок оставалось на прежнем языке
* Сохранённое состояние мягкой блокировки не подхватывалось интерфейсом: вкладка настроек собирается **до** чтения конфига, и переключатель показывал значение по умолчанию
* Мягкую блокировку нельзя было включить при активной вечной блокировке, потому что переключатель запирался целиком
* После «Отменить» большая кнопка оставалась неактивной, и снять передышку было нечем — теперь она превращается в «Заблокировать сейчас»
* Режим блокировки и режим совпадения имён можно было менять после запуска блокировки, ослабляя её задним числом
* В списке исключений системных процессов часть имён была записана в другом регистре и **не совпадала никогда** — из-за этого `MpCmdRun.exe` (Defender) и `RstMwService.exe` (Intel RST) считались обычными пользовательскими процессами

---

# 📂 Структура проекта

```text
App-Blocker
│
├── Program                     скомпилированная версия
│   ├── AppBlocker.exe
│   ├── AppBlockerGuard.exe
│   ├── config.json
│   └── flet\                   клиент Flet (см. раздел о сборке)
│
├── Source
│   ├── AppBlocker.py           точка входа
│   ├── AppBlockerGuard.py      защитный модуль (независим от appcore)
│   │
│   ├── appcore                 логика, без интерфейса
│   │   ├── state.py            общее изменяемое состояние
│   │   ├── config_store.py     config.json, пароль, импорт/экспорт
│   │   ├── processes.py        мониторинг и завершение процессов
│   │   ├── postpone.py         мягкая блокировка с отсчётом
│   │   ├── schedule.py         расписание по дням недели
│   │   ├── stats.py            stats.json, показатели, экспорт CSV
│   │   ├── sites.py            блокировка сайтов через hosts
│   │   ├── security.py         AppBlockerGuard, автозапуск, диагностика
│   │   ├── lifecycle.py        запуск, трей, таймер, выход
│   │   ├── i18n.py             переводы RU/EN
│   │   ├── logging_util.py     журнал в файл и в интерфейс
│   │   ├── paths.py            пути к конфигу, логам, состоянию
│   │   ├── theme.py            палитра и геометрия
│   │   └── admin.py            права администратора
│   │
│   └── gui                     интерфейс на Flet
│       ├── shell.py            окно, навигация, панель логов, роутинг
│       ├── bootstrap.py        стартовая последовательность
│       ├── context.py          общий контекст и мост в цикл событий
│       ├── common.py           фабрики контролов в оформлении приложения
│       ├── animations.py       подсветка под курсором, влёт строк
│       ├── dialogs.py          модальные окна
│       └── tabs                по файлу на вкладку
│           ├── monitor_tab.py
│           ├── sites_tab.py
│           ├── schedule_tab.py
│           ├── stats_tab.py
│           ├── settings_tab.py
│           └── about_tab.py
│
├── requirements.txt
└── README.md
```

Файлы состояния лежат в `%APPDATA%\AppBlocker`: `stats.json`, `language.json`, `security_state.json`. Настройки (`config.json`) и журнал — рядом с исполняемым файлом, поэтому у сборок в разных папках свои настройки.

---

# 📥 Быстрый запуск

1. Скачайте последнюю версию из раздела Releases.
2. Распакуйте архив.
3. Запустите AppBlocker.exe.
4. Настройте блокируемые приложения и сайты.
5. При необходимости включите систему защиты.
6. Начните мониторинг.

---

# ⚠ Важно

Для корректной работы режима защиты может потребоваться добавить папку программы в исключения антивируса.

Исходный код проекта полностью открыт и доступен для проверки на GitHub.

---

# 🛠 Сборка из исходного кода

### Требования

* Python 3.10+
* flet (интерфейс)
* psutil
* pillow
* pystray
* pyinstaller

```bash
pip install -r requirements.txt
```

### Запуск из исходников

```bash
cd Source && python AppBlocker.py
```

### Сборка

```bash
pyinstaller Source/AppBlocker.spec
```

```bash
pyinstaller Source/AppBlockerGuard.spec
```

### Клиент Flet рядом с exe

Окно рисует отдельная программа — `flet.exe` (около 100 МБ). В пакет `flet-desktop`
она не входит: при первом запуске Flet скачивает её с GitHub в `%USERPROFILE%\.flet`.
Для собранной версии так нельзя — App Blocker стартует при входе в Windows и
перезапускается AppBlockerGuard, то есть может подниматься без интернета.

Поэтому клиент кладётся папкой `flet` рядом с `AppBlocker.exe`:

```text
Program\
  AppBlocker.exe
  AppBlockerGuard.exe
  icon.ico
  flet\
    flet.exe
    ...
```

Взять её можно из кеша после первого запуска из исходников:

```bash
xcopy /E /I "%USERPROFILE%\.flet\client\flet-desktop-full-<версия>\flet" "Program\flet"
```

Если раздавать папку неудобно, клиент можно встроить в сам exe. Тогда файл
получится примерно на 100 МБ больше и будет распаковываться в temp при каждом
запуске:

```bash
set BUNDLE_FLET_CLIENT=1 && pyinstaller Source/AppBlocker.spec
```

---

# ❤️ Поддержать проект

### USDT (TRC20)

```text
TSyWGrCkn12LojGEK9urQmWr9ojPimzgBw
```

### Solana

```text
ErQZHWvNHnWQrX2HXbAULTn46uBFkao6aPfarFjKsHva
```

### Bitcoin

```text
bc1qg2a9tnykvdw6sh57hre3mzst8pz3ga5xc7xtye
```

Спасибо за поддержку ❤️

---

# ⚠ Отказ от ответственности

Проект предназначен исключительно для образовательных, административных и организационных целей.

Используйте App Blocker только на компьютерах, где вы имеете право ограничивать доступ к программам и сайтам.

---

# 👨‍💻 Автор

**Вова (@smics_play)**

Разработано с ❤️ на Python.

---
---

# 🧱 App Blocker

### Modern Application & Website Blocking System for Windows

**Version:** 3.0.0
**Developer:** Vova (@smics_play)

> 🐧 **A Linux version exists too.** On GitHub, App Blocker ships as two
> separate folders in the same repository: `Windows/` (this version) and
> `Linux/` (a port to systemd, `/etc/hosts`, `pkexec`, and XDG autostart
> instead of the registry and Task Scheduler). Functionality is the same, but
> OS-specific internals differ — if you're on Linux, use the `Linux/` folder
> and its own README.

---

# 📖 About

**App Blocker** is a modern Windows application designed to restrict access to selected applications and websites.

The software allows users to block processes, restrict websites, protect itself against termination and automatically recover its services after system restart.

Unlike traditional process blockers, App Blocker includes a dedicated protection module called **AppBlockerGuard**, providing an additional layer of security and stability.

Perfect for:

* 🏫 Schools
* 🏢 Offices
* 👨‍👩‍👧 Parental Control
* 💻 Home Computers
* 🔒 Workstations

---

# 🚀 Features

## 🖥 Application Blocking

* Block multiple applications simultaneously
* Real-time process monitoring
* Automatic termination of blocked software
* Background monitoring
* Active process viewer
* Two name matching modes: "Contains" and "Exact name"
* Automatic monitoring recovery after a restart

---

## ⚫⚪ Two Blocking Modes

* **Blacklist** — only the selected programs are terminated (default behaviour)
* **Whitelist** — only the selected programs may run; other processes of your user account are terminated

In whitelist mode, system processes are protected by **two independent barriers**:

1. A never-terminate list: OS core, logon, Explorer, antivirus, updates, Task Manager, App Blocker itself and AppBlockerGuard.
2. A process owner check — only processes of your own account are terminated. Services running as `SYSTEM` or `LOCAL SERVICE` are excluded **structurally**, without listing their names, so the protection does not depend on the particular machine or on the Windows display language.

The application's own process and its whole parent chain are protected too — when run from source, the mode will not terminate Python or your IDE.

---

## ⏳ Soft Blocking (disabled by default)

Enabled with a switch in the settings. Instead of terminating instantly, the app shows a window with a countdown:

* **Close now** — terminate immediately
* **Cancel** — leave the program running; you will not be asked again for 5 minutes
* If you do nothing, the program is closed when the countdown ends
* The delay is configurable (60 seconds by default)
* If the program closes on its own, the window disappears without further questions
* While the window is open, a second one is never shown — one program cannot spam dialogs

Turning the switch back off restores instant termination.

---

## 🗓 Weekly Schedule

* Intervals for every day of the week; blocking turns on by itself
* Several intervals per day: `09:00-18:00, 20:00-22:00`
* Overnight intervals work: `22:00-02:00` — including across the week boundary
* Background check every 20 seconds; edits to the schedule take effect immediately

The schedule can only **turn blocking on**. If blocking was already started manually (permanent lock), the end of an interval will not lift it — otherwise the schedule would become a way around the protection. It only stops what it started itself: manual website blocking is never cancelled by the schedule.

---

## 📊 Statistics

* Blocking events today and over the last 7 days
* Total time blocking has been active
* Top 3 most frequently blocked programs and sites
* A feed of recent events with time, target and type
* **CSV export** with `;` as the delimiter and UTF-8 with BOM — Excel opens Cyrillic correctly and splits the columns by itself

History is stored in a separate `stats.json` file under `%APPDATA%\AppBlocker` and is kept apart from the settings: `config.json` is exported and imported by users, and the blocking history has no place there.

---

## 🌐 Website Blocking

* Website blocking through the Windows hosts file
* Unlimited domain support
* Instant activation
* Automatic DNS cache flushing
* Independent website management

---

## 🛡 Protection

* AppBlockerGuard protection module
* Task Manager termination protection
* Automatic component recovery
* Startup protection
* Configuration integrity verification
* Safe shutdown handling

Once blocking starts, everything that could weaken it is locked: blocking mode, name matching mode, timer, protection. Soft blocking can still be **switched off at any time** — that makes blocking stricter — but it cannot be switched on while blocking is already running.

---

## 🔐 Security

* Administrator password
* Secure PBKDF2 password hashing
* Import & Export configuration
* Automatic configuration backup
* Detailed activity logs

---

## 🌍 Two Interface Languages

* Russian and English, switched with the **Language** button in the top right corner
* The whole interface changes — tabs, dialogs, activity log
* Translations apply instantly, without a restart
* The chosen language is remembered between launches

---

## 🎨 User Interface

* Dark theme in the spirit of the Epic Games Store: an almost black neutral background, a single blue accent, small corner radii
* The sidebar expands on hover
* Cursor spotlight: cards glow with a circle that follows the mouse
* List rows fly in from the left in a cascade
* Smooth fade when switching sections
* Status cards, built-in diagnostics, system tray support

---

# ✨ What's New in Version 3.0.0

## Move to Flet

The interface was rewritten from CustomTkinter to **Flet** (Flutter under the hood). This made possible what was fundamentally out of reach on Tk:

* **The cursor spotlight.** In CustomTkinter a button's label is drawn by a separate opaque `Label`, so any gradient ended up hidden behind the rectangle around the text. The whole button had to be lightened instead, recomputing the colour 60 times per second.
* **Rows flying in from the left.** `pack` has no negative offsets, so a row could not be placed beyond the left edge. Working around it by shrinking the width left pixels of previous frames on screen, and the only reliable fix was a synchronous repaint that froze the application.
* Smoothness is now the engine's job, not a matter of frame constants tuned by measurement.

## New Features

* **Whitelist mode** with two-level protection of system processes
* **Soft blocking** with a countdown (disabled by default)
* A weekly **schedule** with overnight intervals
* A **statistics** tab and history export to **CSV**
* **Two interface languages** switchable on the fly

## New Look

* The palette moved from purple-and-pink to neutral dark with a single blue accent
* Corner radii reduced from 24/16 to 8/4 — "pills" read as a cheap template
* The background became almost flat: coloured blobs look cheap in a dark interface
* The font was replaced with the system Segoe UI, and the monospace font with Consolas (present in every Windows, unlike JetBrains Mono)
* Red is no longer the permanent colour of destructive buttons — it appears on hover only
* The active navigation item is marked with a surface and a blue bar instead of being filled with blue

## Fixed Bugs

**Interface**

* The mode switch froze the application solid: `configure(values=...)` on the segmented button destroyed the very button whose handler was running at that moment
* Modal windows could grab input **while not being visible** — the app looked frozen with nothing to click. `CTkToplevel` briefly hides itself to redraw its title bar, and the input grab happened before the window was shown. Input is now taken only after the window is actually on screen
* Dialogs were not centred and appeared cascaded in the corner
* The width animation did not converge at display scaling above 100%: the current width was read in physical pixels while the target was set in logical ones
* Expanding the sidebar forced a re-layout of the whole window, and text turned into a mess of leftover frames. The panel now overlays the content instead of pushing it aside
* Every button kept its own animation timer, so sweeping the mouse across a list left dozens of buttons fading at once. Reduced to a single shared tick
* The first log line was glued to the next entry because of a missing newline

**Logic**

* The "Clear" button appended a note to the log file instead of clearing it; the file is now truncated, and writing happens under a shared lock because several threads write the log
* The saved language was not restored at startup: `load_language()` was never called
* Translations were applied to the sidebar only — tab contents stayed in the previous language
* The saved soft blocking state was not picked up by the interface: the settings tab is built **before** the config is read, so the switch showed the default value
* Soft blocking could not be enabled while the permanent lock was active, because the switch was locked entirely
* After "Cancel" the main button stayed disabled with no way to lift the reprieve — it now turns into "Block now"
* The blocking mode and name matching mode could be changed after blocking had started, weakening it retroactively
* Part of the names in the system process exclusion list were written in a different case and **never matched** — because of that `MpCmdRun.exe` (Defender) and `RstMwService.exe` (Intel RST) were treated as ordinary user processes

---

# 📂 Project Structure

```text
App-Blocker
│
├── Program                     compiled release
│   ├── AppBlocker.exe
│   ├── AppBlockerGuard.exe
│   ├── config.json
│   └── flet\                   Flet client (see the build section)
│
├── Source
│   ├── AppBlocker.py           entry point
│   ├── AppBlockerGuard.py      protection module (independent of appcore)
│   │
│   ├── appcore                 logic, no interface
│   │   ├── state.py            shared mutable state
│   │   ├── config_store.py     config.json, password, import/export
│   │   ├── processes.py        process monitoring and termination
│   │   ├── postpone.py         soft blocking with a countdown
│   │   ├── schedule.py         weekly schedule
│   │   ├── stats.py            stats.json, metrics, CSV export
│   │   ├── sites.py            website blocking via hosts
│   │   ├── security.py         AppBlockerGuard, startup, diagnostics
│   │   ├── lifecycle.py        startup, tray, timer, exit
│   │   ├── i18n.py             RU/EN translations
│   │   ├── logging_util.py     log to file and to the interface
│   │   ├── paths.py            paths to config, logs, state
│   │   ├── theme.py            palette and geometry
│   │   └── admin.py            administrator rights
│   │
│   └── gui                     Flet interface
│       ├── shell.py            window, navigation, log panel, routing
│       ├── bootstrap.py        startup sequence
│       ├── context.py          shared context and event loop bridge
│       ├── common.py           control factories in the app's styling
│       ├── animations.py       cursor spotlight, row fly-in
│       ├── dialogs.py          modal windows
│       └── tabs                one file per tab
│           ├── monitor_tab.py
│           ├── sites_tab.py
│           ├── schedule_tab.py
│           ├── stats_tab.py
│           ├── settings_tab.py
│           └── about_tab.py
│
├── requirements.txt
└── README.md
```

State files live in `%APPDATA%\AppBlocker`: `stats.json`, `language.json`, `security_state.json`. Settings (`config.json`) and the log sit next to the executable, so builds in different folders keep their own settings.

---

# 📥 Quick Start

1. Download the latest release.
2. Extract the archive.
3. Run AppBlocker.exe.
4. Configure blocked applications and websites.
5. Enable Protection Mode if required.
6. Start monitoring.

---

# ⚠ Important

Protection Mode may require adding the App Blocker folder to your antivirus exclusions.

The entire source code is open and available for inspection on GitHub.

---

# 🛠 Build from Source

### Requirements

* Python 3.10+
* flet (user interface)
* psutil
* pillow
* pystray
* pyinstaller

```bash
pip install -r requirements.txt
```

### Run from source

```bash
cd Source && python AppBlocker.py
```

### Build

```bash
pyinstaller Source/AppBlocker.spec
```

```bash
pyinstaller Source/AppBlockerGuard.spec
```

### Flet client next to the exe

The window is drawn by a separate program — `flet.exe` (about 100 MB). It is not
part of the `flet-desktop` package: on first run Flet downloads it from GitHub into
`%USERPROFILE%\.flet`. That does not work for a built release — App Blocker starts
at Windows logon and is restarted by AppBlockerGuard, so it may come up with no
internet connection.

That is why the client ships as a `flet` folder next to `AppBlocker.exe`:

```text
Program\
  AppBlocker.exe
  AppBlockerGuard.exe
  icon.ico
  flet\
    flet.exe
    ...
```

You can take it from the cache after the first run from source:

```bash
xcopy /E /I "%USERPROFILE%\.flet\client\flet-desktop-full-<version>\flet" "Program\flet"
```

If shipping a folder is inconvenient, the client can be embedded into the exe
itself. The file then grows by roughly 100 MB and is unpacked into temp on every
launch:

```bash
set BUNDLE_FLET_CLIENT=1 && pyinstaller Source/AppBlocker.spec
```

---

# ❤️ Support the Project

### USDT (TRC20)

```text
TSyWGrCkn12LojGEK9urQmWr9ojPimzgBw
```

### Solana

```text
ErQZHWvNHnWQrX2HXbAULTn46uBFkao6aPfarFjKsHva
```

### Bitcoin

```text
bc1qg2a9tnykvdw6sh57hre3mzst8pz3ga5xc7xtye
```

Thank you for supporting the project ❤️

---

# ⚠ Disclaimer

This project is intended for educational, administrative and productivity purposes.

Use App Blocker only on computers where you are authorized to restrict access to applications and websites.

---

# 👨‍💻 Developer

**Vova (@smics_play)**

Developed with ❤️ using Python.
