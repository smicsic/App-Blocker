# 🧱 App Blocker

### Защищённая система блокировки приложений и сайтов для Windows

**Автор:** Вова (@smics_play)
**Назначение:** школы, офисы, учебные заведения и домашние ПК 🏫💼

---

## 📖 О проекте

**App Blocker** — это система контроля и ограничения доступа к программам и веб-сайтам для операционной системы Windows.

В отличие от обычных блокировщиков процессов, App Blocker использует дополнительный защитный модуль **SecureSystem**, который обеспечивает защиту от завершения, автоматическое восстановление компонентов и сохранение настроек между запусками.

Программа может использоваться для контроля рабочего времени сотрудников, ограничения доступа к играм и развлекательным ресурсам, родительского контроля и организации учебного процесса.

---

# 🚀 Возможности

### 🛡 Защита системы

* Защита от завершения через Диспетчер задач
* Автоматический запуск SecureSystem
* Взаимное восстановление процессов
* Защита конфигурации приложения
* Контроль корректного завершения работы

### 🖥 Контроль приложений

* Мониторинг выбранных процессов в реальном времени
* Автоматическое завершение запрещённых программ
* Работа в фоновом режиме
* Просмотр активных процессов пользователя
* Быстрое обновление списка процессов

### 🌐 Блокировка сайтов

* Блокировка сайтов через системный файл hosts
* Поддержка неограниченного списка доменов
* Мгновенное применение изменений
* Автоматическое восстановление настроек

### ⚙ Дополнительные функции

* Пароль администратора
* Автоматическое сохранение настроек
* Таймер автоматического отключения
* Встроенный журнал действий
* Готовые EXE-файлы без необходимости установки Python

---

# ✨ Что нового в версии 2.4.0

* Полностью переработана структура проекта
* Добавлена блокировка сайтов
* Улучшена система защиты SecureSystem
* Улучшено сохранение настроек
* Улучшена система паролей
* Добавлен таймер автоматического завершения
* Улучшена стабильность работы
* Исправлены ошибки предыдущих версий

---

# 📂 Структура проекта

```text
App-Blocker
│
├── Program
│   ├── AppBlocker.exe
│   └── SecureSystem.exe
│
├── Source
│   ├── AppBlocker.py
│   ├── SecureSystem.py
│   ├── AppBlocker.spec
│   └── SecureSystem.spec
│
└── README.md
```

---

# 📥 Быстрый запуск

1. Скачайте последнюю версию из раздела **Releases**
2. Откройте папку **Program**
3. Запустите **AppBlocker.exe** от имени администратора
4. Настройте параметры блокировки
5. Наслаждайтесь работой программы

---

# 🛠 Сборка из исходного кода

### Требования

* Python 3.10+
* psutil
* customtkinter
* pyfiglet

### Сборка

```bash
pyinstaller --onefile --noconsole AppBlocker.py
pyinstaller --onefile --noconsole SecureSystem.py
```

---

# ❤️ Поддержать проект

Если вам понравился проект и вы хотите поддержать его развитие, можете отправить донат:

### USDT (TRC20)

```text
TSyWGrCkn12LojGEK9urQmWr9ojPimzgBw
```

### Solana (SOL)

```text
ErQZHWvNHnWQrX2HXbAULTn46uBFkao6aPfarFjKsHva
```

### Bitcoin (BTC)

```text
bc1qg2a9tnykvdw6sh57hre3mzst8pz3ga5xc7xtye
```

Спасибо за поддержку ❤️

---

# ⚠️ Отказ от ответственности

Данный проект предназначен для образовательного, административного и офисного использования.

Автор не несёт ответственности за возможное неправильное использование программы третьими лицами.

---

# 👨‍💻 Автор

**Вова (@smics_play)**

Разработано с использованием Python ❤️

---

# 🧱 App Blocker

### Secure Application and Website Blocking System for Windows

**Author:** Vova (@smics_play)
**Purpose:** Schools, offices, educational institutions, and personal computers 🏫💼

---

# 📖 About the Project

**App Blocker** is a powerful Windows application designed to monitor, restrict, and block selected programs and websites.

Unlike ordinary process blockers, App Blocker includes an additional protection module called **SecureSystem**, providing self-defense against termination, automatic process recovery, and persistent configuration management.

The software is suitable for workplace productivity control, educational environments, parental control, and any situation where reliable application restrictions are required.

---

# 🚀 Features

## 🛡 Security & Protection

* Protection against termination via Task Manager
* Automatic SecureSystem startup
* Mutual process recovery system
* Configuration protection
* Secure shutdown verification

## 🖥 Application Control

* Real-time process monitoring
* Automatic termination of blocked applications
* Background operation
* Active process viewer
* Quick process list refresh

## 🌐 Website Blocking

* Website blocking through the Windows hosts file
* Support for unlimited domains
* Instant application of changes
* Automatic configuration restoration

## ⚙ Additional Features

* Administrator password protection
* Automatic settings saving
* Auto-shutdown timer
* Built-in activity logs
* Ready-to-use EXE files (no Python installation required)

---

# ✨ What's New in Version 2.4.0

* Completely redesigned project structure
* Added website blocking functionality
* Improved SecureSystem protection module
* Enhanced settings persistence
* Improved password system
* Added automatic shutdown timer
* Increased stability and reliability
* Fixed issues from previous versions

---

# 📂 Project Structure

```text
App-Blocker
│
├── Program
│   ├── AppBlocker.exe
│   └── SecureSystem.exe
│
├── Source
│   ├── AppBlocker.py
│   ├── SecureSystem.py
│   ├── AppBlocker.spec
│   └── SecureSystem.spec
│
└── README.md
```

---

# 📥 Quick Start

1. Download the latest version from the **Releases** section.
2. Open the **Program** folder.
3. Run **AppBlocker.exe** as Administrator.
4. Configure your blocking settings.
5. Enjoy secure application control.

---

# 🛠 Building from Source

## Requirements

* Python 3.10+
* psutil
* customtkinter
* pyfiglet

## Build Commands

```bash
pyinstaller --onefile --noconsole AppBlocker.py
pyinstaller --onefile --noconsole SecureSystem.py
```

---

# ❤️ Support the Project

If you enjoy the project and would like to support future development, donations are greatly appreciated.

## USDT (TRC20)

```text
TSyWGrCkn12LojGEK9urQmWr9ojPimzgBw
```

## Solana (SOL)

```text
ErQZHWvNHnWQrX2HXbAULTn46uBFkao6aPfarFjKsHva
```

## Bitcoin (BTC)

```text
bc1qg2a9tnykvdw6sh57hre3mzst8pz3ga5xc7xtye
```

Thank you for supporting the project ❤️

---

# ⚠ Disclaimer

This project is intended for educational, administrative, parental control, and office productivity purposes.

The author is not responsible for any misuse or unauthorized use of this software by third parties.

Please use responsibly and respect the rights of other users.

---

# 👨‍💻 Author

**Vova (@smics_play)**

Developed with Python ❤️
