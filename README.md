# 🧱 App Blocker

### Современная система блокировки приложений и сайтов для Linux

**Версия:** 3.0.0
**Автор:** Вова (@smics_play)

> 🪟 **Есть версия для Windows.** В репозитории на GitHub App Blocker
> распространяется в виде двух отдельных папок: `Linux/` (эта версия, порт на
> systemd, `/etc/hosts`, `pkexec` и XDG-автозапуск) и `Windows/` (оригинальная
> версия на реестре и Task Scheduler). Функциональность одинаковая, но
> реализация системно-специфичных частей разная — если вы на Windows,
> используйте папку `Windows/` и её README.

---

# 📖 О проекте

**App Blocker** — современная программа для Linux, предназначенная для ограничения доступа к приложениям и веб-сайтам.

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

1. Список «никогда не завершать»: ядро ОС, графическая сессия и её окружение, сетевые и звуковые службы, сам App Blocker и AppBlockerGuard.
2. Проверка владельца процесса — завершаются только процессы вашей учётной записи. Системные службы отсекаются **структурно**, по владельцу процесса (root вместо вас), без перечисления имён, поэтому защита не зависит ни от конкретного компьютера, ни от дистрибутива.

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

История хранится в отдельном файле `stats.json` в `~/.local/share/AppBlocker` и не смешивается с настройками: `config.json` пользователи экспортируют и импортируют, история блокировок там лишняя.

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

Ниже — дерево папки `Linux/` из репозитория (в текущем виде это корень
проекта) с описанием каждого файла. Соседняя папка `Windows/` устроена так же,
но с Windows-специфичными модулями вместо перечисленных ниже.

```text
Linux/
│
├── AppBlocker.spec              PyInstaller-спека для сборки из корня репозитория
├── icon.ico                     иконка в формате Windows, унаследована при портировании;
│                                 используется как запасной вариант при поиске иконки
├── icon.png                     PNG-иконка для окна/трея и Linux-сборки (сделана из icon.ico)
├── requirements.txt             зависимости Python + заметка про системные пакеты для трея
├── version1.txt                 номер версии сборки
├── README.md                    этот файл
│
├── Program/                     папка "готовой" версии программы
│   ├── AppBlocker.exe           ⚠ старый Windows-бинарник, оставлен как исторический артефакт
│   ├── AppBlockerGuard.exe      ⚠ старый Windows-бинарник — после Linux-сборки замените
│   │                              оба на `AppBlocker`/`AppBlockerGuard` без расширения
│   ├── AppBlocker.desktop       шаблон XDG-лаунчера (пункт в меню приложений);
│   │                              Exec=/Icon= нужно поправить под реальный путь установки
│   └── icon.png                 копия иконки рядом со собранной программой
│
├── installer_output/
│   └── AppBlockerSetup.exe      инсталлятор Windows-версии (NSIS/Inno) — к Linux не относится,
│                                  оставлен от предыдущей версии, для Linux-сборки не создаётся
│
├── build/, dist/                служебные каталоги PyInstaller (кэш и результат сборки);
│                                  создаются заново при каждой сборке
│
└── Source/                      исходный код
    ├── AppBlocker.py            точка входа — вызывает gui.bootstrap.run()
    ├── AppBlocker.py.bak        архивная копия монолитного AppBlocker.py (3327 строк)
    │                              до разделения на appcore/gui; программой не используется
    ├── AppBlockerGuard.py       защитный модуль-наблюдатель, отдельный процесс;
    │                              не импортирует appcore — минимальные зависимости для
    │                              отдельной PyInstaller-сборки
    ├── AppBlocker.spec          более полная спека сборки (запускается из Source/):
    │                              бандлит шрифт Huninn, иконку, опционально клиент Flet
    ├── AppBlockerGuard.spec     спека сборки защитного модуля
    ├── config.json              файл настроек (пример/дев-конфиг)
    ├── config.backup.json       его резервная копия
    ├── Huninn-Regular.ttf       шрифт, встроенный в интерфейс по умолчанию (см. appcore/theme.py)
    ├── logs/appblocker.log      файл журнала (создаётся программой при запуске)
    │
    ├── appcore/                 вся логика, без интерфейса
    │   ├── __init__.py          пустой, помечает пакет
    │   ├── admin.py             проверка root-прав (os.geteuid())
    │   ├── config_store.py      config.json, хеш пароля админа (PBKDF2), импорт/экспорт
    │   ├── i18n.py              таблицы переводов RU/EN и переключение языка
    │   ├── lifecycle.py         единственный экземпляр (flock), окно, трей, выход, таймер
    │   ├── logging_util.py      запись в файл лога и опционально в виджет интерфейса
    │   ├── paths.py             все пути: XDG-конфиг/данные, /etc/hosts, автозапуск,
    │   │                          поиск иконки/шрифта/клиента Flet
    │   ├── postpone.py          состояние «мягкой блокировки» (диалог с отсчётом),
    │   │                          ничего не знает об интерфейсе
    │   ├── processes.py         список защищённых процессов, сопоставление правил,
    │   │                          мониторинг и завершение процессов
    │   ├── schedule.py          расписание блокировки по дням недели
    │   ├── security.py          AppBlockerGuard (запуск/слежение), автозапуск через
    │   │                          .desktop-файлы (XDG), диагностика
    │   ├── sites.py             блокировка сайтов через /etc/hosts (с эскалацией через
    │   │                          pkexec), очистка DNS-кэша, список браузеров
    │   ├── state.py             общее изменяемое состояние приложения
    │   ├── stats.py             статистика (stats.json), экспорт в CSV
    │   └── theme.py             цвета, радиусы, шрифты
    │
    └── gui/                     интерфейс на Flet
        ├── __init__.py          пустой
        ├── animations.py        подсветка под курсором, влёт строк списка
        ├── bootstrap.py         стартовая последовательность (пароль, восстановление состояния)
        ├── common.py            фабрики контролов (кнопки, поля, карточки) в едином стиле
        ├── context.py           общий контекст интерфейса, мост между потоками
        │                          и циклом событий Flet
        ├── dialogs.py           модальные окна (пароль, подтверждения, отсчёт мягкой блокировки)
        ├── shell.py             главное окно: навигация, панель логов, роутинг вкладок
        └── tabs/                по файлу на вкладку
            ├── __init__.py
            ├── about_tab.py     вкладка «О программе»
            ├── monitor_tab.py   вкладка «Мониторинг» (список процессов, блокировка)
            ├── schedule_tab.py  вкладка «Расписание»
            ├── settings_tab.py  вкладка «Настройки» (автозапуск/диагностика, конфиг,
            │                      режимы, таймер, защита)
            ├── sites_tab.py     вкладка «Сайты»
            └── stats_tab.py     вкладка «Статистика»
```

Файлы состояния лежат в `~/.local/share/AppBlocker` (XDG data): `stats.json`, `language.json`, `security_state.json`, lock-файл единственного экземпляра. Настройки (`config.json`) и журнал — рядом с исполняемым файлом, поэтому у сборок в разных папках свои настройки. Автозапуск живёт отдельно, в `~/.config/autostart/*.desktop`.

В `Source/` два файла `AppBlocker.spec` (корневой и внутри `Source/`) — это не дубль по ошибке: корневой строит из корня репозитория и содержит минимальный набор данных, а `Source/AppBlocker.spec` запускается из `Source/` и бандлит шрифт, иконку и (опционально) клиент Flet. Пользуйтесь тем, который удобнее для вашего процесса сборки — собирают один и тот же `AppBlocker.py`.

---

# 📥 Быстрый запуск

1. Скачайте последнюю версию из раздела Releases (папка `Linux/`).
2. Распакуйте архив.
3. Запустите бинарник `AppBlocker` (или ярлык из меню приложений, если поставили `.desktop`-файл).
4. Настройте блокируемые приложения и сайты.
5. При необходимости включите систему защиты.
6. Начните мониторинг.

---

# ⚠ Важно

Исходный код проекта полностью открыт и доступен для проверки на GitHub.

---

# 🐧 App Blocker на Linux

Начиная с этой версии, App Blocker портирован с Windows на Linux. Ниже — что
изменилось по сравнению с Windows-версией.

## Установка (Linux)

### Способ 1 — через Snap Store (рекомендуется, одна команда)

```bash
sudo snap install appblocker
```

Готово! Приложение появится в меню приложений и будет обновляться автоматически.

### Способ 2 — из исходников

См. раздел ниже про сборку из исходного кода.

### Установка системных зависимостей

Иконка в трее у `pystray` на Linux рисуется через GTK/AppIndicator, это
системные пакеты, а не pip-зависимости:

```bash
# Debian / Ubuntu
sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1
```

На дистрибутивах без этого пакета трей отключается сам — приложение сворачивает
окно вместо скрытия в трей и продолжает работать.

### Требования

* Python 3.10+
* flet, psutil, pillow, pystray, pyinstaller (см. `requirements.txt`)

```bash
pip install -r requirements.txt
```

### Запуск из исходников

```bash
cd Source && python3 AppBlocker.py
```

### Сборка

```bash
pyinstaller AppBlocker.spec
pyinstaller Source/AppBlockerGuard.spec
```

### Клиент Flet рядом с бинарником

Окно рисует отдельная программа — клиент Flet (около 100 МБ). В пакет
`flet-desktop` она не входит: при первом запуске Flet скачивает её с GitHub в
`~/.flet`. Для собранной версии так нельзя — App Blocker стартует при входе в
систему и перезапускается AppBlockerGuard, то есть может подниматься без
интернета. Поэтому клиент кладётся папкой `flet` рядом с бинарником:

```text
Program/
  AppBlocker
  AppBlockerGuard
  icon.png
  flet/
    flet
    ...
```

Взять её можно из кеша после первого запуска из исходников:

```bash
cp -r ~/.flet/client/flet-desktop-light-<версия>/flet Program/flet
```

### Запись hosts и права root

Блокировка сайтов правит `/etc/hosts`, а это требует root. Приложению не нужно
запускаться целиком от root: при каждой записи hosts оно точечно поднимает
права через `pkexec` (диалог polkit с паролем), а не требует sudo на старте.

### Автозапуск

Вместо реестра Windows и Task Scheduler автозапуск AppBlocker и AppBlockerGuard
делается через XDG: `.desktop`-файлы кладутся в `~/.config/autostart/`. Никаких
привилегий для этого не нужно — файл автозапуска пишется от имени
пользователя.

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

### Modern Application & Website Blocking System for Linux

**Version:** 3.0.0
**Developer:** Vova (@smics_play)

> 🪟 **A Windows version exists too.** On GitHub, App Blocker ships as two
> separate folders in the same repository: `Linux/` (this version — a port to
> systemd, `/etc/hosts`, `pkexec`, and XDG autostart) and `Windows/` (the
> original version, built on the registry and Task Scheduler). Functionality
> is the same, but OS-specific internals differ — if you're on Windows, use
> the `Windows/` folder and its own README.

---

# 📖 About

**App Blocker** is a modern Linux application designed to restrict access to selected applications and websites.

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

1. A never-terminate list: OS core, the graphical session and its environment, network and audio services, App Blocker itself and AppBlockerGuard.
2. A process owner check — only processes of your own account are terminated. System services are excluded **structurally**, by process owner (root instead of you), without listing their names, so the protection does not depend on the particular machine or distribution.

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

History is stored in a separate `stats.json` file under `~/.local/share/AppBlocker` and is kept apart from the settings: `config.json` is exported and imported by users, and the blocking history has no place there.

---

## 🌐 Website Blocking

* Website blocking through the system hosts file (`/etc/hosts`)
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

Below is the tree of the repository's `Linux/` folder (in this working copy
it's the project root), with a description of every file. The sibling
`Windows/` folder is laid out the same way, but with Windows-specific modules
instead of the ones listed below.

```text
Linux/
│
├── AppBlocker.spec              PyInstaller spec for building from the repo root
├── icon.ico                     Windows-format icon, inherited from the port;
│                                 used as a fallback when looking up the icon
├── icon.png                     PNG icon for the window/tray and Linux build (made from icon.ico)
├── requirements.txt             Python dependencies + a note on system packages for the tray
├── version1.txt                 build version number
├── README.md                    this file
│
├── Program/                     "ready to run" copy of the program
│   ├── AppBlocker.exe           ⚠ old Windows binary, kept as a historical artifact
│   ├── AppBlockerGuard.exe      ⚠ old Windows binary — after a Linux build, replace both
│   │                              with the extension-less `AppBlocker`/`AppBlockerGuard`
│   ├── AppBlocker.desktop       XDG launcher template (app-menu entry); adjust
│   │                              Exec=/Icon= to the real install path
│   └── icon.png                 icon copy next to the built program
│
├── installer_output/
│   └── AppBlockerSetup.exe      Windows installer (NSIS/Inno) — not relevant to Linux,
│                                  kept from the previous version, not produced by a Linux build
│
├── build/, dist/                PyInstaller working directories (build cache and output);
│                                  regenerated on every build
│
└── Source/                      source code
    ├── AppBlocker.py            entry point — just calls gui.bootstrap.run()
    ├── AppBlocker.py.bak        archived copy of the monolithic AppBlocker.py (3327 lines)
    │                              from before the appcore/gui split; unused by the program
    ├── AppBlockerGuard.py       watchdog protection module, a separate process;
    │                              does not import appcore — minimal dependencies for
    │                              its own standalone PyInstaller build
    ├── AppBlocker.spec          fuller build spec (run from inside Source/): bundles
    │                              the Huninn font, the icon, and optionally the Flet client
    ├── AppBlockerGuard.spec     build spec for the protection module
    ├── config.json              settings file (sample/dev config)
    ├── config.backup.json       its backup copy
    ├── Huninn-Regular.ttf       the font bundled as the interface's default (see appcore/theme.py)
    ├── logs/appblocker.log      log file (created by the program at runtime)
    │
    ├── appcore/                 all the logic, no interface
    │   ├── __init__.py          empty, marks the package
    │   ├── admin.py             root check (os.geteuid())
    │   ├── config_store.py      config.json, admin password hash (PBKDF2), import/export
    │   ├── i18n.py              RU/EN translation tables and language switching
    │   ├── lifecycle.py         single instance (flock), window, tray, exit, timer
    │   ├── logging_util.py      log to file and, optionally, to the interface widget
    │   ├── paths.py             every path: XDG config/data, /etc/hosts, autostart,
    │   │                          icon/font/Flet-client lookup
    │   ├── postpone.py          "soft blocking" countdown dialog state, knows nothing
    │   │                          about the interface
    │   ├── processes.py         protected process list, rule matching, process
    │   │                          monitoring and termination
    │   ├── schedule.py          weekly blocking schedule
    │   ├── security.py          AppBlockerGuard (start/watch), XDG `.desktop` autostart,
    │   │                          diagnostics
    │   ├── sites.py             website blocking via /etc/hosts (elevated through
    │   │                          pkexec), DNS cache flush, browser process list
    │   ├── state.py             the app's shared mutable state
    │   ├── stats.py             statistics (stats.json), CSV export
    │   └── theme.py             colors, radii, fonts
    │
    └── gui/                     the Flet interface
        ├── __init__.py          empty
        ├── animations.py        cursor spotlight, list row fly-in
        ├── bootstrap.py         startup sequence (password, state recovery)
        ├── common.py            control factories (buttons, fields, cards) in a shared style
        ├── context.py           shared interface context, the bridge between threads
        │                          and the Flet event loop
        ├── dialogs.py           modal windows (password, confirmations, soft-block countdown)
        ├── shell.py             main window: navigation, log panel, tab routing
        └── tabs/                one file per tab
            ├── __init__.py
            ├── about_tab.py     "About" tab
            ├── monitor_tab.py   "Monitoring" tab (process list, blocking)
            ├── schedule_tab.py  "Schedule" tab
            ├── settings_tab.py  "Settings" tab (autostart/diagnostics, config,
            │                      modes, timer, protection)
            ├── sites_tab.py     "Websites" tab
            └── stats_tab.py     "Statistics" tab
```

State files live in `~/.local/share/AppBlocker` (XDG data): `stats.json`, `language.json`, `security_state.json`, the single-instance lock file. Settings (`config.json`) and the log sit next to the executable, so builds in different folders keep their own settings. Autostart lives separately, in `~/.config/autostart/*.desktop`.

There are two `AppBlocker.spec` files (one at the repo root, one inside `Source/`) — that's not an accidental duplicate: the root one builds from the repo root with a minimal set of bundled data, while `Source/AppBlocker.spec` runs from inside `Source/` and bundles the font, the icon, and optionally the Flet client. Use whichever fits your build process — both build the same `AppBlocker.py`.

---

# 📥 Quick Start

1. Download the latest release (the `Linux/` folder).
2. Extract the archive.
3. Run the `AppBlocker` binary (or the app-menu shortcut if you installed the `.desktop` file).
4. Configure blocked applications and websites.
5. Enable Protection Mode if required.
6. Start monitoring.

---

# ⚠ Important

The entire source code is open and available for inspection on GitHub.

---

# 🐧 App Blocker on Linux

As of this version, App Blocker has been ported from Windows to Linux. Here is
what changed compared to the Windows version.

## Installation (Linux)

### Method 1 — via Snap Store (recommended, one command)

```bash
sudo snap install appblocker
```

Done! The app will appear in your applications menu and update automatically.

### Method 2 — from source

See the section below for building from source.

### System dependencies

On Linux, `pystray`'s tray icon is drawn through GTK/AppIndicator — a system
package, not a pip dependency:

```bash
# Debian / Ubuntu
sudo apt install python3-gi gir1.2-ayatanaappindicator3-0.1
```

On distributions without that package the tray disables itself — the app
minimizes the window instead of hiding to tray and keeps working.

### Requirements

* Python 3.10+
* flet, psutil, pillow, pystray, pyinstaller (see `requirements.txt`)

```bash
pip install -r requirements.txt
```

### Run from source

```bash
cd Source && python3 AppBlocker.py
```

### Build

```bash
pyinstaller AppBlocker.spec
pyinstaller Source/AppBlockerGuard.spec
```

### Flet client next to the binary

The window is drawn by a separate program — the Flet client (about 100 MB). It
is not part of the `flet-desktop` package: on first run Flet downloads it from
GitHub into `~/.flet`. That does not work for a built release — App Blocker
starts at login and is restarted by AppBlockerGuard, so it may come up with no
internet connection. That is why the client ships as a `flet` folder next to
the binary:

```text
Program/
  AppBlocker
  AppBlockerGuard
  icon.png
  flet/
    flet
    ...
```

You can take it from the cache after the first run from source:

```bash
cp -r ~/.flet/client/flet-desktop-light-<version>/flet Program/flet
```

### Writing hosts and root rights

Website blocking edits `/etc/hosts`, which requires root. The app itself does
not need to run as root: each hosts write elevates on its own through
`pkexec` (a polkit password prompt) instead of requiring sudo at startup.

### Autostart

Instead of the Windows registry and Task Scheduler, AppBlocker and
AppBlockerGuard autostart through XDG: `.desktop` files are placed in
`~/.config/autostart/`. No elevated privileges are needed — the autostart file
is written as the regular user.

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
