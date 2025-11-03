import psutil
import os
import sys
import threading
import time
import subprocess
import json
import pyfiglet
import datetime
import winreg
import ctypes
import requests
import tempfile
import shutil
import customtkinter as ctk
from tkinter import simpledialog, messagebox
from threading import Lock, Event

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PROCESS_NAME = ""
ADMIN_PASSWORD = ""
monitor_thread = None
monitoring_active = False
SECURE_ENABLED = True  # по умолчанию включена защита
TIMER_ENABLED = False
PERMANENT_LOCK = False
TIMER_END = None
timer_thread = None
APP_CLOSING = False
CONFIG_LOCK = Lock()
RUN_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
shutdown_event = Event()
watch_active = False
HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
BLOCK_MARKER = "# AppBlocker managed"
EXIT_LOCK = Lock()

def is_admin():
    """Проверяет, запущено ли приложение с правами администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def remove_from_startup_everywhere(app_name="SecureSystem", exe_name="SecureSystem.exe"):
    """Полностью удаляет приложение из автозагрузки Windows"""
    deleted_any = False

    print(f"[Cleanup] 🧹 Начинаем очистку {app_name}...")

    # 1) ⚡ ПРИНУДИТЕЛЬНО убить SecureSystem несколько раз
    print(f"[Cleanup] Завершаем все процессы {exe_name}...")
    for attempt in range(5):  # Увеличено до 5 попыток
        killed = False
        try:
            for p in psutil.process_iter(['name', 'pid']):
                try:
                    n = (p.info.get('name') or '').lower()
                    if n == exe_name.lower():
                        print(f"[Cleanup] Завершаю PID {p.info['pid']} (попытка {attempt + 1})")
                        try:
                            p.kill()  # Жёсткое завершение
                            killed = True
                        except psutil.AccessDenied:
                            try:
                                p.terminate()
                            except:
                                pass
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            print(f"[Cleanup] Ошибка при завершении процесса: {e}")

        if killed:
            time.sleep(0.5)  # Уменьшено время ожидания
        else:
            break

    # 2) 🧹 Удаляем из реестра
    print("[Cleanup] Удаляем из реестра...")

    hives = [
        (winreg.HKEY_CURRENT_USER, "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM")
    ]

    run_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
    ]

    for hive, hive_name in hives:
        for run_path in run_paths:
            try:
                # Пробуем без флагов разрядности
                try:
                    with winreg.OpenKey(hive, run_path, 0, winreg.KEY_SET_VALUE) as k:
                        try:
                            winreg.DeleteValue(k, app_name)
                            print(f"[Cleanup] ✅ Удалён из {hive_name}\\{run_path}")
                            deleted_any = True
                        except FileNotFoundError:
                            pass
                except PermissionError:
                    print(f"[Cleanup] ⚠️ Нет прав для {hive_name}\\{run_path}")

                # Пробуем с флагами разрядности
                for view in [winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY]:
                    try:
                        access = winreg.KEY_SET_VALUE | view
                        with winreg.OpenKey(hive, run_path, 0, access) as k:
                            try:
                                winreg.DeleteValue(k, app_name)
                                print(f"[Cleanup] ✅ Удалён из {hive_name}\\{run_path} (view={view})")
                                deleted_any = True
                            except FileNotFoundError:
                                pass
                    except (PermissionError, OSError):
                        pass
            except Exception as e:
                print(f"[Cleanup] ⚠️ Ошибка при работе с реестром: {e}")

    # 3) 🗑️ Удаляем ярлыки
    print("[Cleanup] Удаляем ярлыки...")

    startup_folders = [
        os.path.join(os.getenv("APPDATA") or "", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.getenv("PROGRAMDATA") or "", r"Microsoft\Windows\Start Menu\Programs\Startup")
    ]

    for folder in startup_folders:
        if folder and os.path.isdir(folder):
            try:
                for filename in os.listdir(folder):
                    if filename.lower().startswith(app_name.lower()) and filename.lower().endswith(".lnk"):
                        shortcut_path = os.path.join(folder, filename)
                        try:
                            os.chmod(shortcut_path, 0o666)
                        except:
                            pass
                        try:
                            os.remove(shortcut_path)
                            print(f"[Cleanup] ✅ Удалён ярлык: {shortcut_path}")
                            deleted_any = True
                        except Exception as e:
                            print(f"[Cleanup] ⚠️ Не удалось удалить {shortcut_path}: {e}")
            except Exception as e:
                print(f"[Cleanup] ⚠️ Ошибка при обходе {folder}: {e}")

    # 4) 🗓️ Удаляем задачу планировщика
    print("[Cleanup] Удаляем задачу планировщика...")
    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", app_name, "/F"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=0x08000000,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"[Cleanup] ✅ Задача '{app_name}' удалена")
            deleted_any = True
    except Exception as e:
        print(f"[Cleanup] ⚠️ Ошибка удаления задачи: {e}")

    print(f"[Cleanup] {'✅ Очистка завершена' if deleted_any else 'ℹ️ Записи не найдены'}")
    return deleted_any


def exit_app_no_password():
    global monitoring_active, watch_active, APP_CLOSING

    # ✅ ЗАЩИТА: НЕ УДАЛЯЕМ CONFIG ПРИ ПЕРВОМ ЗАПУСКЕ
    if not PROCESS_NAME:
        log("⚠️ Выход отменён: процесс не задан (первый запуск)")
        return

    if not monitoring_active:
        log("⚠️ Выход отменён: мониторинг не был запущен")
        return

    with EXIT_LOCK:
        if APP_CLOSING:
            return
        APP_CLOSING = True

    log("⏰ Выход без пароля (таймер/автоматический)...")

    # ОСТАНАВЛИВАЕМ ПОТОКИ
    monitoring_active = False
    watch_active = False
    shutdown_event.set()
    time.sleep(1.5)

    # ✅ СНАЧАЛА РАЗБЛОКИРУЕМ САЙТЫ
    try:
        sites = load_blocked_sites()
        if sites:
            log(f"🧼 Удаляем {len(sites)} сайтов из hosts...")
            save_blocked_sites([])

            for attempt in range(3):
                if apply_hosts_block([]):
                    log("✅ Все сайты разблокированы")
                    break
                else:
                    log(f"⚠️ Попытка {attempt + 1}/3, повторяю...")
                    time.sleep(0.5)
        else:
            log("ℹ️ Список сайтов пуст")
    except Exception as e:
        log(f"⚠️ Ошибка при очистке сайтов: {e}")

    # ТЕПЕРЬ УДАЛЯЕМ CONFIG
    create_exit_sentinel()
    save_config(status="EXIT")

    # ЗАВЕРШАЕМ SecureSystem
    for attempt in range(5):
        killed = False
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == "securesystem.exe":
                    proc.kill()
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if killed:
            time.sleep(0.3)
        else:
            break

        time.sleep(0.5)

    try:
        if os.path.exists(CONFIG_PATH):
            os.chmod(CONFIG_PATH, 0o666)
            os.remove(CONFIG_PATH)
            log("🧹 config.json удалён (exit_app_no_password)")

        sentinel_path = os.path.join(base_dir(), "config.exit.lock")
        if os.path.exists(sentinel_path):
            os.chmod(sentinel_path, 0o666)
            os.remove(sentinel_path)
            log("🧹 config.exit.lock удалён (exit_app_no_password)")
    except Exception as e:
        log(f"⚠️ Ошибка при удалении файлов: {e}")

    remove_from_startup_everywhere("SecureSystem", "SecureSystem.exe")
    root.after(500, root.destroy)

def close_app():
    global PROCESS_NAME
    if not PROCESS_NAME:
        return

    for proc in psutil.process_iter():
        try:
            if PROCESS_NAME in proc.name().lower():
                process_name_full = proc.name()
                proc.terminate()
                log(f"🔴 Приложение '{process_name_full}' (PID: {proc.pid}) завершено.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

def base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

APP_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__))
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
SECURE_EXE  = os.path.join(APP_DIR, "SecureSystem.exe")
EXIT_SENTINEL = os.path.join(APP_DIR, "config.exit.lock")

if not is_admin():
    print("⚠️ Программа запущена без прав администратора — выполняем перезапуск...")
    try:
        # перезапускаем AppBlocker с правами администратора
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    except Exception as e:
        print(f"❌ Не удалось перезапустить с правами администратора: {e}")
    sys.exit(0)

# Флаг, чтобы не мигало консольное окно при запуске процессов
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000 if os.name == "nt" else 0)

#блокировка сайтов
def load_blocked_sites():
    """Загружает список сайтов из config.json"""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("blocked_sites", [])
    return []

def save_blocked_sites(sites):
    """Сохраняет список сайтов в config.json"""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = {}
    data["blocked_sites"] = sites
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def apply_hosts_block(sites):
    """Перезаписывает hosts, добавляя/удаляя заблокированные сайты (устойчиво к read-only)"""
    try:
        # ✅ Снимаем флаг "только чтение"
        if os.path.exists(HOSTS_PATH) and not os.access(HOSTS_PATH, os.W_OK):
            os.chmod(HOSTS_PATH, 0o666)

        # ✅ Читаем текущие строки (с обработкой ошибок)
        if os.path.exists(HOSTS_PATH):
            try:
                with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception as e:
                log(f"⚠️ Ошибка чтения hosts: {e}")
                lines = []
        else:
            lines = []

        # ✅ ИСПРАВЛЕНО: Убираем ТОЛЬКО строки с маркером, оставляем остальные
        new_lines = []
        for line in lines:
            # Пропускаем только строки с нашим маркером
            if BLOCK_MARKER in line:
                continue
            # ВСЕ ОСТАЛЬНЫЕ СТРОКИ СОХРАНЯЕМ
            new_lines.append(line)

        # ✅ Добавляем новые блокировки (если список не пуст)
        if sites:
            # Добавляем пустую строку перед нашими записями для читаемости
            if new_lines and not new_lines[-1].endswith('\n'):
                new_lines.append('\n')

            for site in sites:
                new_lines.append(f"127.0.0.1 {site} {BLOCK_MARKER}\n")
                new_lines.append(f"127.0.0.1 www.{site} {BLOCK_MARKER}\n")

        # ✅ Перезаписываем файл
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
            f.flush()
            os.fsync(f.fileno())

        # ✅ Обновляем DNS
        subprocess.run(["ipconfig", "/flushdns"], creationflags=CREATE_NO_WINDOW,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if sites:
            log(f"🌐 Hosts обновлён: {len(sites)} сайтов заблокировано")
        else:
            log("🧼 Hosts очищен от блокировок")

        # ✅ Проверяем результат
        with open(HOSTS_PATH, "r", encoding="utf-8") as f:
            content = f.read()
            if sites and BLOCK_MARKER not in content:
                log("⚠️ КРИТИЧНО: Блокировки не применились!")
                return False
            if not sites and BLOCK_MARKER in content:
                log("⚠️ КРИТИЧНО: Маркеры остались в hosts!")
                return False

        return True

    except PermissionError:
        log("❌ Нет прав для изменения hosts! Запусти от администратора.")
        return False
    except Exception as e:
        log(f"⚠️ Ошибка при блокировке сайтов: {e}")
        return False

# -------------- СОХРАНЕНИЕ КОНФИГА ----------------

def save_config(status="RUNNING"):
    """Сохраняет конфиг, не удаляя список сайтов"""
    data = {}

    # ✅ Если файл уже существует — читаем его, чтобы не потерять blocked_sites
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"⚠️ Ошибка чтения config.json: {e}")
            data = {}

    # ✅ Обновляем только нужные ключи
    data.update({
        "process_name": PROCESS_NAME,
        "admin_password": ADMIN_PASSWORD,
        "status": status,
        "timer_enabled": TIMER_ENABLED,
        "timer_end": TIMER_END.timestamp() if TIMER_END else None,
        "secure_enabled": SECURE_ENABLED,
        "permanent_lock": PERMANENT_LOCK
    })

    # ✅ Сохраняем обратно
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def load_config():
    global PROCESS_NAME, ADMIN_PASSWORD, TIMER_ENABLED, TIMER_END, SECURE_ENABLED, PERMANENT_LOCK  # ← ДОБАВЬ PERMANENT_LOCK
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
        PROCESS_NAME = config.get("process_name", "")
        ADMIN_PASSWORD = config.get("admin_password", "")
        PERMANENT_LOCK = config.get("permanent_lock", False)
        TIMER_ENABLED = config.get("timer_enabled", False)
        SECURE_ENABLED = config.get("secure_enabled", True)
        end_timestamp = config.get("timer_end")
        if end_timestamp:
            TIMER_END = datetime.datetime.fromtimestamp(end_timestamp)
        return config.get("status", "RUNNING")

    if not os.path.exists(CONFIG_PATH):
        try:
            save_config()
            print("🆕 Файл config.json был создан автоматически.")
        except Exception as e:
            print(f"⚠️ Не удалось создать config.json: {e}")
    return "RUNNING"

def check_timer():
    global TIMER_ENABLED, TIMER_END
    while True:
        if TIMER_ENABLED and TIMER_END:
            now = datetime.datetime.now()
            if now >= TIMER_END:
                log("⏰ Время работы истекло — программа завершается.")
                if SECURE_ENABLED:
                    for proc in psutil.process_iter(['name']):
                        try:
                            if proc.info['name'] and proc.info['name'].lower() == "securesystem.exe":
                                proc.terminate()  # ❌ СЛАБОЕ ЗАВЕРШЕНИЕ!
                                log("🛑 SecureSystem завершён по таймеру.")
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                exit_app_no_password()
                break
        time.sleep(1)

def get_user_processes():
    """Возвращает список только не системных процессов"""
    system_names = {
        "system", "idle", "svchost.exe", "smss.exe", "wininit.exe",
        "csrss.exe", "winlogon.exe", "services.exe", "lsass.exe",
        "dllhost.exe", "runtimebroker.exe", "searchindexer.exe",
        "explorer.exe", "crossdeviceresume.exe", "fmaudiomonitor.exe",
        "fmservice64.exe", "fnhotkeycapslknumlk.exe", "fnhotkeyutility.exe",
        "intelaudioservice.exe", "lenovoutilityservice.exe",
        "lenovovantage-(genericmessagingaddin).exe",
        "lenovovantage-(lenovogamingsystemaddin).exe",
        "lenovovantage-(vantagecoreaddin).exe", "lenovovantageservice.exe",
        "locator.exe", "lockapp.exe", "lsaiso.exe", "mpdefendercoreservice.exe",
        "msmpeng.exe", "nvdisplay.container.exe", "nahimicservice.exe",
        "ngciso.exe", "nhnotifsys.exe", "nissrv.exe", "openconsole.exe",
        "registry", "rtkauduservice64.exe", "rtkbtmanserv.exe", "searchhost.exe",
        "securityhealthservice.exe", "securityhealthsystray.exe",
        "shellhost.exe", "startmenuexperiencehost.exe",
        "system idle process", "textinputhost.exe",
        "wmiregistrationservice.exe", "wudfhost.exe", "wmiapsrv.exe",
        "wmiprvse.exe", "backgroundtaskhost.exe",
        "conhost.exe", "ctfmon.exe", "dwm.exe", "fontdrvhost.exe",
        "fsnotifier.exe", "full-line-inference.exe", "ipf_helper.exe",
        "ipf_uf.exe", "ipfsvc.exe", "jhi_service.exe", "msedgewebview2.exe",
        "powershell.exe", "pycharm64.exe", "python.exe", "sihost.exe",
        "spoolsv.exe", "taskhostw.exe", "unsecapp.exe", "MoUsoCoreWorker.exe", "ApplicationFrameHost.exe",
        "LenovoVantage-(GenericTelemetryAddin).exe",
        "audiodg.exe", "smartscreen.exe", "appblocker.exe", "securesystem.exe", "ApplicationFrameHost.exe",
        "CHXSmartScreen.exe", "LADMAutoInstallService.exe", "MpCmdRun.exe","RstMwService.exe",
        "ShellExperienceHost.exe", "WidgetService.exe", "cef_server.exe", "nvcontainer.exe",
        "wlanext.exe"
    }
    processes = []
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if name and name.lower() not in system_names and not name.lower().startswith("windows"):
                processes.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(set(processes))

# Проверка запущен ли процесс
def is_app_running():
    global PROCESS_NAME
    if not PROCESS_NAME:
        return False

    for proc in psutil.process_iter():
        try:
            if PROCESS_NAME in proc.name().lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def watch_secure_system():
    """Следит за SecureSystem и перезапускает его при необходимости"""
    global watch_active
    print("[Watch] Мониторинг SecureSystem запущен")

    while watch_active and not shutdown_event.is_set():
        try:
            found = False
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    name = (proc.info.get('name') or '').lower()
                    exe = (proc.info.get('exe') or '').lower()
                    if 'securesystem' in name or (exe and exe.endswith('securesystem.exe')):
                        found = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            if not found and os.path.exists(SECURE_EXE) and watch_active:
                try:
                    subprocess.Popen([SECURE_EXE], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
                    print("[Watch] SecureSystem перезапущен")
                except Exception as e:
                    print(f"[Watch] ❌ Ошибка запуска: {e}")
        except Exception as e:
            print(f"[Watch] ⚠️ Ошибка в цикле: {e}")

        shutdown_event.wait(1)  # Проверяем каждую секунду, но можем прерваться

    print("[Watch] Мониторинг SecureSystem остановлен")

def create_exit_sentinel():
    """Создаёт флажок EXIT и делает его read-only (если возможно)."""
    try:
        if not os.path.exists(EXIT_SENTINEL):
            with open(EXIT_SENTINEL, "w", encoding="utf-8") as s:
                s.write("EXIT\n")
                s.flush()           # 💾 Принудительно записать данные
                os.fsync(s.fileno()) # 🧱 Гарантировать запись на диск
        try:
            os.chmod(EXIT_SENTINEL, 0o444)
        except Exception:
            pass
    except Exception as e:
        log(f"⚠️ Ошибка sentinel: {e}")


# Обновление логов в окне
def log(message: str):
    text_log.configure(state="normal")   # временно разрешаем редактирование
    text_log.insert("end", f"{message}\n")
    text_log.see("end")
    text_log.configure(state="disabled") # снова блокируем пользователя

# Поток фоновой проверки
def monitor_process():
    global PROCESS_NAME, monitoring_active
    while monitoring_active:
        if not PROCESS_NAME:
            time.sleep(1)  # Ждем, пока процесс будет задан
            continue

        if is_app_running():
            log(f"🔍 Процесс '{PROCESS_NAME}' запущен. Пытаюсь закрыть...")
            close_app()
        else:
            log(f"✅ Процесс '{PROCESS_NAME}' не запущен.")
        time.sleep(2)

# Обработчик кнопки "Начать"
def start_monitoring():
    global PROCESS_NAME, monitor_thread, monitoring_active, watch_active, PERMANENT_LOCK

    # ✅ СРАЗУ БЛОКИРУЕМ ВСЕ ТУМБЛЕРЫ НАВСЕГДА
    secure_switch.configure(state="disabled")
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    try:
        remove_btn.configure(state="disabled")
    except:
        pass
    for widget in timer_frame.winfo_children():
        widget.configure(state="disabled")

    if SECURE_ENABLED and ensure_secure_system():
        log("🛡 SecureSystem активирован")

    # ✅ ИСПРАВЛЕНО: Активируем watch_active и запускаем поток
    if SECURE_ENABLED and not watch_active:
        watch_active = True  # 🔥 КРИТИЧНО!
        threading.Thread(target=watch_secure_system, daemon=True).start()
        log("👁️ Мониторинг SecureSystem запущен")

    input_name = entry_process.get().strip().lower()

    if not input_name:
        log("❗ Введите название процесса, прежде чем начать.")
        return

    if monitoring_active and input_name == PROCESS_NAME:
        log(f"⚠️ Мониторинг процесса '{PROCESS_NAME}' уже активен.")
        return

    if monitoring_active and input_name != PROCESS_NAME:
        log(f"🔄 Изменение процесса на '{input_name}'. Перезапуск мониторинга.")

    PROCESS_NAME = input_name

    # 🧱 УСТАНАВЛИВАЕМ ПЕРМАНЕНТНУЮ БЛОКИРОВКУ
    PERMANENT_LOCK = True
    save_config()
    log("🔒 Вечная блокировка активирована — переключатели больше нельзя изменить.")

    root.title(f"Blocker для: {PROCESS_NAME}")

    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_process, daemon=True)
        monitor_thread.start()
        log(f"🚀 Мониторинг процесса '{PROCESS_NAME}' запущен.")
    else:
        log(f"✅ Мониторинг продолжен для процесса '{PROCESS_NAME}'.")

    entry_process.configure(state="disabled")
    big_start_btn.configure(state="disabled")

    save_config()


def toggle_secure_mode():
    global SECURE_ENABLED
    SECURE_ENABLED = secure_switch.get() == 1
    state = "включена 🟢" if SECURE_ENABLED else "отключена 🔴"
    log(f"🧰 Защита от завершения {state}")
    save_config()  # Добавлено

# Обработка закрытия окна
def on_close():
    log("❗ Нажат крестик, но окно не будет закрыто.")

def ensure_secure_system():
    """Запускает SecureSystem из той же папки, если его нет."""
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = (proc.info.get('name') or '').lower()
            exe  = (proc.info.get('exe')  or '').lower()
            if 'securesystem' in name or (exe and exe.endswith('securesystem.exe')):
                return False  # уже запущен
        except:
            pass

    if os.path.exists(SECURE_EXE):
        subprocess.Popen([SECURE_EXE], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
        return True
    return False


def exit_app():
    global monitoring_active, watch_active, APP_CLOSING

    password_input = custom_password_dialog(
        "Выход",
        "Введите пароль администратора для выхода:"
    )

    if password_input != ADMIN_PASSWORD:
        messagebox.showerror("Ошибка", "Неверный пароль! Выход запрещён.")
        return

    with EXIT_LOCK:
        if APP_CLOSING:
            return
        APP_CLOSING = True

    log("🚪 Начинаем процедуру выхода...")

    # ✅ ШАГ 1: ОСТАНАВЛИВАЕМ ПОТОКИ
    log("🛑 Останавливаем фоновые потоки...")
    monitoring_active = False
    watch_active = False
    shutdown_event.set()
    time.sleep(1.5)
    log("✅ Потоки остановлены")

    # ✅ ШАГ 2: РАЗБЛОКИРУЕМ САЙТЫ (ДО УДАЛЕНИЯ CONFIG!)
    try:
        sites = load_blocked_sites()
        if sites:
            log(f"🧼 Удаляем {len(sites)} сайтов из hosts...")

            # Очищаем список в памяти
            save_blocked_sites([])

            # Применяем изменения в hosts (с повторами)
            for attempt in range(3):
                if apply_hosts_block([]):
                    log("✅ Все сайты разблокированы")
                    break
                else:
                    log(f"⚠️ Попытка {attempt + 1}/3 не удалась, повторяю...")
                    time.sleep(0.5)
            else:
                log("❌ Не удалось полностью очистить hosts после 3 попыток")
        else:
            log("ℹ️ Список заблокированных сайтов пуст")
    except Exception as e:
        log(f"⚠️ Ошибка при разблокировке сайтов: {e}")

    # ✅ ШАГ 3: Записываем EXIT
    try:
        create_exit_sentinel()
        save_config(status="EXIT")
        log("📝 EXIT записан в config.json")
    except Exception as e:
        log(f"⚠️ Ошибка при записи EXIT: {e}")

    # ✅ ШАГ 4: ЗАВЕРШАЕМ SecureSystem
    log("🧨 Завершаем SecureSystem...")
    for attempt in range(5):
        killed = False
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == "securesystem.exe":
                    try:
                        proc.kill()
                        log(f"🛑 SecureSystem PID {proc.info['pid']} завершён")
                        killed = True
                    except psutil.AccessDenied:
                        proc.terminate()
                        killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if killed:
            time.sleep(0.3)
        else:
            break

    time.sleep(0.5)

    try:
        if os.path.exists(CONFIG_PATH):
            os.chmod(CONFIG_PATH, 0o666)
            os.remove(CONFIG_PATH)
            log("🧹 config.json удалён после завершения SecureSystem")

        sentinel_path = os.path.join(base_dir(), "config.exit.lock")
        if os.path.exists(sentinel_path):
            os.chmod(sentinel_path, 0o666)
            os.remove(sentinel_path)
            log("🧹 config.exit.lock удалён")
    except Exception as e:
        log(f"⚠️ Ошибка при удалении файлов: {e}")


    # ✅ ШАГ 5: УДАЛЯЕМ ИЗ АВТОЗАГРУЗКИ
    log("🧹 Удаляем из автозагрузки...")
    removed = remove_from_startup_everywhere("SecureSystem", "SecureSystem.exe")
    log("✅ Автозагрузка очищена" if removed else "ℹ️ Записи не найдены")

    # ✅ ШАГ 7: ЗАКРЫВАЕМ ПРИЛОЖЕНИЕ
    log("👋 Завершение работы...")
    root.after(1000, root.destroy)

def custom_password_dialog(title, message):
    # Создаём кастомное модальное окно
    dialog = ctk.CTkToplevel(root)
    dialog.title(title)
    dialog.geometry("450x200")
    dialog.resizable(False, False)
    dialog.grab_set()  # блокирует основное окно
    dialog.transient(root)  # поверх главного окна
    dialog.iconbitmap(os.path.join(base_dir(), "icon.ico"))

    # Центрирование
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - dialog.winfo_reqwidth()) // 2
    y = (dialog.winfo_screenheight() - dialog.winfo_reqheight()) // 2
    dialog.geometry(f"+{x}+{y}")

    dialog.iconbitmap(os.path.join(base_dir(), "icon.ico"))

    # Текст
    label = ctk.CTkLabel(dialog, text=message, font=("Arial", 14))
    label.pack(pady=20)

    # Поле для пароля
    entry = ctk.CTkEntry(dialog, show="*", width=250)
    entry.pack(pady=5)
    entry.focus_set()

    result = {"password": None}

    def on_ok():
        result["password"] = entry.get()
        dialog.destroy()

    def on_cancel():
        result["password"] = None
        dialog.destroy()

    # Кнопки
    btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
    btn_frame.pack(pady=20)

    ctk.CTkButton(btn_frame, text="✅ ОК", width=100, command=on_ok).pack(side="left", padx=10)
    ctk.CTkButton(btn_frame, text="❌ Отмена", width=100, fg_color="#d62828", hover_color="#a71e1e", command=on_cancel).pack(side="left", padx=10)

    # Нажатие Enter и Esc
    entry.bind("<Return>", lambda e: on_ok())
    entry.bind("<Escape>", lambda e: on_cancel())

    dialog.wait_window()
    return result["password"]

def refresh_process_list():
    process_box.configure(state="normal")  # временно разрешаем редактирование
    process_box.delete("0.0", "end")  # очищаем поле (в CTkTextbox с 0.0!)
    process_box.insert("end", "🔍 Активные не системные процессы:\n\n")
    processes = get_user_processes()
    for name in processes:
        process_box.insert("end", f" {name}\n")
    process_box.insert("end", f"\n✅ Всего процессов которые можно мониторить: {len(processes)}")
    process_box.configure(state="disabled")  # снова блокируем
    log("🔄 Список процессов обновлён.")

def show_frame(frame):
    """Переключение между разделами интерфейса"""
    # Скрываем все фреймы
    button_start.pack_forget()
    frame_logs.pack_forget()
    about_frame.pack_forget()
    settings_frame.pack_forget()
    sites_frame.pack_forget()  # ✅ Добавлено!

    # Показываем нужный фрейм
    if frame == "monitor":
        button_start.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        frame_logs.pack(side="right", fill="y")
    elif frame == "about":
        about_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
    elif frame == "settings":
        settings_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
    elif frame == "sites":
        sites_frame.pack(side="left", fill="both", expand=True, padx=20, pady=20)
        refresh_sites_list()  # ✅ Обновляем список сайтов при открытии

# ----------------- Интерфейс -----------------
root = ctk.CTk()
root.title("App Blocker")
root.geometry("900x700")
root.iconbitmap(os.path.join(base_dir(), "icon.ico"))
root.resizable(True, True)

# Верхний фрейм с вводом и кнопками
frame_input = ctk.CTkFrame(root)
frame_input.pack(padx=10, pady=(10, 5), fill='x')

label_process = ctk.CTkLabel(frame_input, text="Название процесса:")
label_process.pack(side="left", padx=5)

entry_process = ctk.CTkEntry(frame_input, width=200, placeholder_text="chrome.exe")
entry_process.pack(side="left", padx=5, fill="x", expand=True)

# Левая панель навигации
nav_frame = ctk.CTkFrame(root, width=180, corner_radius=0)
nav_frame.pack(side="left", fill="y")

# Центральная панель
button_start = ctk.CTkFrame(root, fg_color="transparent")
button_start.pack(side="left", fill="both", expand=True, padx=20, pady=20)

button_refresh = ctk.CTkButton(frame_input, text="Обновить процессы", command=refresh_process_list)
button_refresh.pack(side="left", padx=5)

big_start_btn = ctk.CTkButton(button_start, text="🚀 Начать блокировку", width=300, height=50, command=start_monitoring)
big_start_btn.pack(pady=30)

process_box = ctk.CTkTextbox(button_start, height=300, width=400)
process_box.pack(pady=10, fill="both", expand=True)
process_box.configure(state="disabled", cursor="arrow")  # ⛔ запрещаем редактировать

# Левая панель навигации (добавь после создания nav_frame)
ctk.CTkLabel(nav_frame, text="Меню", font=("Arial", 20, "bold")).pack(pady=20)
ctk.CTkButton(nav_frame, text="Мониторинг", width=160, command=lambda: show_frame("monitor")).pack(pady=10)
ctk.CTkButton(nav_frame, text="🌐 Сайты", width=160, command=lambda: show_frame("sites")).pack(pady=10)  # ✅
ctk.CTkButton(nav_frame, text="Настройки", width=160, command=lambda: show_frame("settings")).pack(pady=10)
ctk.CTkButton(nav_frame, text="О программе", width=160, command=lambda: show_frame("about")).pack(pady=10)

button_exit = ctk.CTkButton(
    frame_input,
    text="Выйти",
    command=exit_app,
    fg_color="#d62828",
    hover_color="#a71e1e",
    text_color="white"
)
button_exit.pack(side="left", padx=5)

# Фрейм под логи
frame_logs = ctk.CTkFrame(root, width=300)
frame_logs.pack(side="right", fill="y")

ctk.CTkLabel(frame_logs, text="Логи", font=("Arial", 20, "bold")).pack(pady=20)
text_log = ctk.CTkTextbox(frame_logs, width=280, height=500)
text_log.pack(padx=10, pady=10)
text_log.insert("end", "🛡 Готов к блокировке...")
#невозможность редачить логи
text_log.configure(state="disabled")

# ================== О ПРОГРАММЕ ==================
about_frame = ctk.CTkFrame(root, fg_color="transparent")
about_frame.pack_forget()  # скрыт по умолчанию

ctk.CTkLabel(about_frame, text="О программе", font=("Arial", 22, "bold")).pack(pady=20)

about_text = ctk.CTkTextbox(about_frame, width=600, height=500)
about_text.pack(padx=20, pady=10, fill="both", expand=True)

about_text.insert("end", "🛡 App Blocker — инструмент для блокировки процессов.\n")
about_text.insert("end", "\n\n📌 Версия: 2.0.0")
about_text.insert("end", "\n👨‍💻 Разработчик: smics_play 🧍 | 🤝 Помощь: ChatGPT 5 🤖, Claude AI 🤖")
about_text.insert("end", "\n\n📝 Описание:\n🧱 App Blocker — система блокировки процессов с защитой от завершения.\n\n"
                          "App Blocker — это простой, но очень защищённый инструмент для мониторинга и блокировки выбранных приложений.\n"
                          "Он автоматически завершает процессы, которые не должны запускаться (например: браузеры, игры и т.д.), и защищает сам себя от закрытия.\n\n"
                          "📌 Подходит для:\n"
                          "• Контроля рабочего времени сотрудников в офисе.\n"
                          "• Ограничения доступа к развлекательным программам в школах.\n"
                          "• Установки ограничений на личных ПК.\n\n"
                          "⚡ Новые функции 2.2.0 (releas):\n"
                          "🔐 Пароль на выход — закрыть App Blocker можно только по паролю.\n"
                          "🛡 SecureSystem.exe — защита от завершения.\n"
                          "♻️ Автовосстановление — процессы AppBlocker и SecureSystem поднимают друг друга.\n"
                          "🧠 EXIT через config.json — корректное завершение с записью статуса.\n"
                          "💾 Сохранение пароля и процесса — повторный ввод не требуется.\n"
                          "🧹 Очистка после выхода — SecureSystem удаляет config.json.\n"
                          "🧾 Готовые exe-файлы — не нужен Python.\n\n"
                          "🧰 Основные функции:\n"
                          "📡 Мониторинг выбранного процесса в реальном времени.\n"
                          "🛑 Автоматическое завершение запрещённых приложений.\n"
                          "🔍 Просмотр активных не системных процессов.\n"
                          "🔄 Ручное обновление списка процессов.\n"
                          "⏳ Таймер\n"
                          "🖥 Современный интерфейс с логами событий.\n\n"
                          "🧭 Использование:\n"
                          "🔑 Установи пароль администратора при первом запуске.\n"
                          "🧱 Укажи процесс, который нужно блокировать (например chrome.exe).\n"
                          "🕵️‍♂️ Нажми «Начать» — процесс будет автоматически завершаться при запуске.\n"
                          "🚫 Завершить App Blocker можно только по паролю.\n\n"
                          "⚠️ Примечание:\n"
                          "Инструмент создан для образовательных и офисных целей.\n"
                          "Автор не несёт ответственности за использование программы в злоумышленных целях.\n"
                          "Используйте ответственно и не нарушайте права пользователей ⚖️\n\n"
                          "✨ Раздел 'О программе' обновляется с новыми версиями! \n\n"
                          "программа бесплатная, поддержите автора:\n4441 1111 5818 7579 (mono)\n4314 1402 1489 7073 (ПУМБ) \n5168 7521 2074 2567 (ПРИВАТ)")
about_text.configure(state="disabled")

# ================== БЛОКИРОВКА САЙТОВ ==================
sites_frame = ctk.CTkFrame(root, fg_color="transparent")
sites_frame.pack_forget()

ctk.CTkLabel(sites_frame, text="Блокировка сайтов 🌐", font=("Arial", 22, "bold")).pack(pady=20)

sites_listbox = ctk.CTkTextbox(sites_frame, width=500, height=300)
sites_listbox.pack(pady=10)
sites_listbox.configure(state="disabled")

site_entry = ctk.CTkEntry(sites_frame, width=300, placeholder_text="Например: youtube.com")
site_entry.pack(pady=5)

def refresh_sites_list():
    sites = load_blocked_sites()
    sites_listbox.configure(state="normal")
    sites_listbox.delete("0.0", "end")
    for s in sites:
        sites_listbox.insert("end", f"{s}\n")
    sites_listbox.configure(state="disabled")

def add_site():
    site = site_entry.get().strip().lower()
    if not site:
        log("⚠️ Введи сайт!")
        return
    sites = load_blocked_sites()
    if site not in sites:
        sites.append(site)
        save_blocked_sites(sites)
        apply_hosts_block(sites)
        refresh_sites_list()
        log(f"✅ Сайт {site} добавлен в блок.")
    else:
        log(f"ℹ️ {site} уже заблокирован.")

def remove_site():
    site = site_entry.get().strip().lower()
    if not site:
        log("⚠️ Введи сайт для удаления!")
        return
    sites = load_blocked_sites()
    if site in sites:
        sites.remove(site)
        save_blocked_sites(sites)
        apply_hosts_block(sites)
        refresh_sites_list()
        log(f"🗑️ Сайт {site} удалён из блока.")
    else:
        log(f"ℹ️ {site} не найден в списке блокировок.")

btn_frame = ctk.CTkFrame(sites_frame, fg_color="transparent")
btn_frame.pack(pady=10)

add_btn = ctk.CTkButton(btn_frame, text="➕ Добавить", width=120, command=add_site)
add_btn.pack(side="left", padx=5)

remove_btn = ctk.CTkButton(btn_frame, text="❌ Удалить", width=120, command=remove_site)
remove_btn.pack(side="left", padx=5)

# ================== НАСТРОЙКИ ==================
settings_frame = ctk.CTkFrame(root, fg_color="transparent")
settings_frame.pack_forget()

ctk.CTkLabel(settings_frame, text="Настройки", font=("Arial", 22, "bold")).pack(pady=20)

# Таймер
def toggle_timer_mode():
    global TIMER_ENABLED
    TIMER_ENABLED = timer_switch.get() == 1
    if TIMER_ENABLED:
        timer_frame.pack(pady=5)
    else:
        timer_frame.pack_forget()
    save_config()
    state = "включён ⏳" if TIMER_ENABLED else "отключён ❌"
    log(f"⏳ Таймер {state}")

def set_timer():
    global TIMER_END, timer_thread

    if not timer_entry.get().strip():
        log("⚠️ Введите время перед запуском таймера")
        return

    try:
        minutes = int(timer_entry.get().strip())
        TIMER_END = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
        save_config()
        log(f"⏳ Таймер установлен на {minutes} мин. Завершение в {TIMER_END.strftime('%H:%M:%S')}")

        # 🚀 Если таймер включен — запускаем поток проверки
        if TIMER_ENABLED:
            if timer_thread is None or not timer_thread.is_alive():
                timer_thread = threading.Thread(target=check_timer, daemon=True)
                timer_thread.start()
                log("🕒 Таймер запущен")
                # ⛔ Блокируем возможность менять таймер
                timer_switch.configure(state="disabled")
                timer_entry.configure(state="disabled")
                for widget in timer_frame.winfo_children():
                    widget.configure(state="disabled")

    except ValueError:
        log("⚠️ Введите корректное число минут")

timer_switch = ctk.CTkSwitch(
    settings_frame,
    text="⏳ Ограничение по времени",
    command=toggle_timer_mode
)
timer_switch.pack(pady=10)

timer_description = ctk.CTkLabel(
    settings_frame,
    text="Если включить таймер ⏳ — программа автоматически завершится\nпосле указанного времени.",
    font=("Arial", 12),
    text_color="gray"
)
timer_description.pack(pady=(0, 10))


timer_frame = ctk.CTkFrame(settings_frame, fg_color="transparent")
ctk.CTkLabel(timer_frame, text="Введите время (минуты):").pack(side="left", padx=5)
timer_entry = ctk.CTkEntry(timer_frame, width=100)
timer_entry.pack(side="left", padx=5)
ctk.CTkButton(timer_frame, text="✅ Установить", command=set_timer).pack(side="left", padx=5)

# по умолчанию скрыт
if not TIMER_ENABLED:
    timer_frame.pack_forget()
else:
    timer_switch.select()
    timer_frame.pack(pady=5)

secure_switch = ctk.CTkSwitch(
    settings_frame,
    text="🛡 Защита от завершения",
    command=toggle_secure_mode
)
secure_switch.select()  # по умолчанию включен
secure_switch.pack(pady=10)

secure_description = ctk.CTkLabel(
    settings_frame,
    text="Отключение защиты функция в разроботке ✍️ \n защита работает по умолчанию от всего!!!",
    font=("Arial", 12),
    text_color="gray"
)
secure_description.pack(pady=(0, 10))

# Перехват крестика
root.protocol("WM_DELETE_WINDOW", on_close)

# Запуск GUI
log("Введите название процесса и нажмите 'Начать'.")
refresh_process_list()

# ----------------- АВТО ЗАПУСК -----------------
load_config()

if PERMANENT_LOCK:
    secure_switch.configure(state="disabled")
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    remove_btn.configure(state="disabled")
    for widget in timer_frame.winfo_children():
        widget.configure(state="disabled")
    log("🔐 Перманентная блокировка активна — переключатели навсегда заблокированы.")

# Синхронизация UI с конфигом
if SECURE_ENABLED:
    secure_switch.select()
else:
    secure_switch.deselect()

if TIMER_ENABLED and TIMER_END and datetime.datetime.now() < TIMER_END:
    timer_switch.select()
    timer_frame.pack(pady=5)
    timer_thread = threading.Thread(target=check_timer, daemon=True)
    timer_thread.start()
    log(f"⏳ Таймер активен до {TIMER_END.strftime('%H:%M:%S')}")
else:
    # ✅ НЕ ТРОГАЕМ СОСТОЯНИЕ ТУМБЛЕРА ЕСЛИ БЫЛА ПЕРМАНЕНТНАЯ БЛОКИРОВКА
    if not PERMANENT_LOCK:
        timer_switch.deselect()
    timer_frame.pack_forget()

if SECURE_ENABLED:
    secure_switch.configure(state="disabled")

if TIMER_ENABLED:
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    for widget in timer_frame.winfo_children():
        widget.configure(state="disabled")
    log("🔒 Переключатель таймера и поля ввода заблокированы (автозагрузка)")

if not ADMIN_PASSWORD:
    # показываем диалог до входа в mainloop — но НЕ скрываем окно полностью
    # Вместо withdraw — минимизируем
    root.iconify()

    ADMIN_PASSWORD = custom_password_dialog(
        "Пароль администратора",
        "Введите пароль, который будет использоваться для выхода:",
    )

    if not ADMIN_PASSWORD:
        messagebox.showerror("Ошибка", "Пароль не задан! Программа будет закрыта.")
        root.destroy()
        sys.exit(0)

    # ✅ СОХРАНЯЕМ ПАРОЛЬ И ПРИНУДИТЕЛЬНО СБРАСЫВАЕМ ФЛАГИ
    save_config(status="RUNNING")  # ← Явно указываем статус!

    # ✅ СБРОС ФЛАГОВ, ЧТОБЫ НЕ СРАБОТАЛ exit_app_no_password()
    APP_CLOSING = False

    root.after(100, lambda: (
        root.deiconify(),
        root.lift(),
        root.focus_force(),
    ))

if ensure_secure_system():
    log("🛡 Система защиты от завершения запущенна")

if PROCESS_NAME:
    entry_process.insert(0, PROCESS_NAME)
    entry_process.configure(state="disabled")
    big_start_btn.configure(state="disabled")
    monitoring_active = True
    threading.Thread(target=monitor_process, daemon=True).start()
    log(f"✅ Автовосстановление мониторинга для '{PROCESS_NAME}'")

if SECURE_ENABLED and not watch_active:  # ← Добавьте проверку!
    watch_active = True
    threading.Thread(target=watch_secure_system, daemon=True).start()
    log("👁️ Мониторинг SecureSystem активирован")
else:
    if watch_active:
        log("ℹ️ Мониторинг SecureSystem уже активен")

# 🕒 Таймер
if TIMER_ENABLED and TIMER_END and datetime.datetime.now() < TIMER_END:
    log(f"⏳ Таймер активен до {TIMER_END.strftime('%H:%M:%S')}")
    timer_thread = threading.Thread(target=check_timer, daemon=True)
    timer_thread.start()
elif TIMER_ENABLED and TIMER_END and datetime.datetime.now() >= TIMER_END:
    save_config(status="EXIT")
    create_exit_sentinel()
    log("⏰ Время работы истекло — программа завершается.")
    if SECURE_ENABLED:
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == "securesystem.exe":
                    proc.terminate()
                    log("🛑 SecureSystem завершён по таймеру.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    exit_app_no_password()

root.mainloop()