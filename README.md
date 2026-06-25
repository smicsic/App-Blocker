# 🧱 App Blocker

### Современная система блокировки приложений и сайтов для Windows

**Версия:** 2.5.0 Beta
**Автор:** Вова (@smics_play)

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
* Различные режимы поиска процессов
* Автоматическое восстановление мониторинга

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

---

## 🔐 Безопасность

* Пароль администратора
* Хранение пароля в виде PBKDF2-хеша
* Импорт и экспорт настроек
* Автоматическое резервное копирование конфигурации
* Подробный журнал событий

---

## 🎨 Интерфейс

* Полностью новый современный интерфейс
* Фиолетово-розовая цветовая схема
* Красивый абстрактный фон
* Современные карточки состояния
* Встроенная диагностика
* Поддержка системного трея
* Кастомные окна приложения

---

# ✨ Что нового в версии 2.5.0

* Полностью переработан дизайн приложения
* Новый современный интерфейс
* Добавлен красивый фон приложения
* Добавлена поддержка системного трея
* Улучшена работа AppBlockerGuard
* Улучшена система защиты
* Улучшена система паролей
* Добавлены импорт и экспорт конфигурации
* Добавлено автоматическое резервное копирование настроек
* Улучшена система логирования
* Добавлена диагностика системы
* Улучшена стабильность приложения
* Исправлено большое количество ошибок предыдущих версий

---

# 📂 Структура проекта

```text
App-Blocker
│
├── Program
│   ├── AppBlocker.exe
│   ├── AppBlockerGuard.exe
│   └── config.json
│
├── Source
│   ├── AppBlocker.py
│   ├── AppBlockerGuard.py
│   └── Assets
│
└── README.md
```

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
* customtkinter
* psutil
* pillow
* pystray
* pyinstaller

### Сборка

```bash
pyinstaller --onefile --noconsole AppBlocker.py
pyinstaller --onefile --noconsole AppBlockerGuard.py
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

# 🧱 App Blocker

### Modern Application & Website Blocking System for Windows

**Version:** 2.5.0 Beta
**Developer:** Vova (@smics_play)

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
* Multiple matching modes
* Automatic monitoring recovery

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

---

## 🔐 Security

* Administrator password
* Secure PBKDF2 password hashing
* Import & Export configuration
* Automatic configuration backup
* Detailed activity logs

---

## 🎨 User Interface

* Completely redesigned modern UI
* Purple & Pink theme
* Beautiful abstract background
* Modern status cards
* Built-in diagnostics
* System tray support
* Custom application dialogs

---

# ✨ What's New in Version 2.5.0

* Completely redesigned interface
* Brand new modern UI
* Added dynamic application background
* Added system tray support
* Improved AppBlockerGuard
* Improved protection system
* Improved password security
* Added configuration import/export
* Added automatic configuration backup
* Improved logging system
* Added diagnostics tools
* Improved application stability
* Fixed numerous bugs from previous versions

---

# 📂 Project Structure

```text
App-Blocker
│
├── Program
│   ├── AppBlocker.exe
│   ├── AppBlockerGuard.exe
│   └── config.json
│
├── Source
│   ├── AppBlocker.py
│   ├── AppBlockerGuard.py
│   └── Assets
│
└── README.md
```

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
* customtkinter
* psutil
* pillow
* pystray
* pyinstaller

### Build

```bash
pyinstaller --onefile --noconsole AppBlocker.py
pyinstaller --onefile --noconsole AppBlockerGuard.py
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
