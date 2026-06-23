import psutil
import os
import sys
import threading
import time
import subprocess
import json
import datetime
import winreg
import ctypes
import re
import customtkinter as ctk
from tkinter import messagebox
from threading import Lock, Event

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

APP_BG = "#020604"
SIDEBAR_BG = "#07100c"
TOPBAR_BG = "#09140f"
PANEL_BG = "#08110d"
CARD_BG = "#0d1c15"
CARD_HOVER = "#12281d"
BORDER_GREEN = "#164a32"
ACCENT_GREEN = "#20e070"
ACCENT_GREEN_DARK = "#0e8f49"
ACCENT_GREEN_HOVER = "#22c767"
TEXT_MAIN = "#f4fff8"
TEXT_MUTED = "#8fb79f"
DANGER = "#c53030"
DANGER_HOVER = "#8f1f1f"

PROCESS_NAME = ""
BLOCKED_PROGRAMS = []
ADMIN_PASSWORD = ""
monitor_thread = None
monitoring_active = False
last_monitor_state = None
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

def base_dir():
    """Безопасный путь для AppBlocker — хранит всё в AppData, но иконку ищет рядом с exe."""
    appdata_path = os.path.join(os.getenv("APPDATA"), "AppBlocker")
    os.makedirs(appdata_path, exist_ok=True)

    # Для иконки и exe возвращаем путь программы
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    return exe_dir

def find_icon_path():
    bundle_dir = getattr(sys, "_MEIPASS", None)
    candidates = [
        os.path.join(bundle_dir, "icon.ico") if bundle_dir else "",
        os.path.join(base_dir(), "icon.ico"),
        os.path.join(os.getcwd(), "icon.ico"),
        os.path.join(os.getcwd(), "Program", "icon.ico"),
        os.path.join(os.path.dirname(base_dir()), "icon.ico"),
        os.path.join(os.path.dirname(base_dir()), "Program", "icon.ico"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None

def set_window_icon(window):
    icon_path = find_icon_path()
    if not icon_path:
        return
    try:
        window.iconbitmap(icon_path)
    except Exception:
        pass
    try:
        window.iconbitmap(default=icon_path)
    except Exception:
        pass
    try:
        window.after(100, lambda: window.iconbitmap(icon_path))
    except Exception:
        pass

def paste_into_entry(entry):
    try:
        text = entry.clipboard_get()
    except Exception:
        return "break"
    try:
        entry.delete("sel.first", "sel.last")
    except Exception:
        pass
    entry.insert("insert", text)
    return "break"

def handle_entry_ctrl_key(event):
    if event.keycode == 86:
        return paste_into_entry(event.widget)
    return None

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
    if not BLOCKED_PROGRAMS:
        return

    for proc in psutil.process_iter():
        try:
            process_name = proc.name().lower()
            matched_program = next((program for program in BLOCKED_PROGRAMS if program in process_name), None)
            if matched_program:
                process_name_full = proc.name()
                proc.terminate()
                log(f"🔴 Приложение '{process_name_full}' (PID: {proc.pid}) завершено. Правило: {matched_program}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

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
def normalize_site(site):
    site = site.strip().lower()
    site = re.sub(r"^https?://", "", site)
    site = re.sub(r"^www\.", "", site)
    site = site.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    site = site.split(":", 1)[0].strip(". ")
    if not site:
        return ""
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", site):
        return ""
    if any(part.startswith("-") or part.endswith("-") for part in site.split(".")):
        return ""
    return site

def normalize_sites(sites):
    normalized = []
    for site in sites:
        site = normalize_site(site)
        if site and site not in normalized:
            normalized.append(site)
    return normalized

def parse_sites_input(text):
    return normalize_sites(re.split(r"[\s,;]+", text.strip()))

def hosts_entries_for_site(site):
    hosts = [site, f"www.{site}"]
    entries = []
    for host in hosts:
        entries.append(f"0.0.0.0 {host} {BLOCK_MARKER}: {site}\n")
        entries.append(f"::1 {host} {BLOCK_MARKER}: {site}\n")
    return entries

def load_blocked_sites():
    """Загружает список сайтов из config.json"""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            return normalize_sites(data.get("blocked_sites", []))
        except Exception as e:
            print(f"Ошибка чтения blocked_sites: {e}")
    return []

def save_blocked_sites(sites):
    """Сохраняет список сайтов в config.json"""
    sites = normalize_sites(sites)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = {}
    data["blocked_sites"] = sites
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def apply_hosts_block(sites):
    """Перезаписывает hosts, добавляя/удаляя заблокированные сайты (устойчиво к read-only)"""
    sites = normalize_sites(sites)
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
                new_lines.extend(hosts_entries_for_site(site))

        # ✅ Перезаписываем файл
        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
            f.flush()
            os.fsync(f.fileno())

        # ✅ Обновляем DNS
        subprocess.run(["ipconfig", "/flushdns"], creationflags=CREATE_NO_WINDOW,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)

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

def apply_hosts_block(sites):
    sites = normalize_sites(sites)
    try:
        if os.path.exists(HOSTS_PATH) and not os.access(HOSTS_PATH, os.W_OK):
            os.chmod(HOSTS_PATH, 0o666)

        if os.path.exists(HOSTS_PATH):
            with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        else:
            lines = []

        new_lines = [line for line in lines if BLOCK_MARKER not in line]
        if sites:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"{BLOCK_MARKER}: start\n")
            for site in sites:
                new_lines.extend(hosts_entries_for_site(site))
            new_lines.append(f"{BLOCK_MARKER}: end\n")

        with open(HOSTS_PATH, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
            f.flush()
            os.fsync(f.fileno())

        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=8
            )
        except Exception:
            pass

        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        missing = [site for site in sites if f" {site} " not in content and f" www.{site} " not in content]
        if missing:
            log(f"⚠️ Не все сайты попали в hosts: {', '.join(missing)}")
            return False
        if not sites and BLOCK_MARKER in content:
            log("⚠️ В hosts остались старые записи App Blocker")
            return False

        if sites:
            log(f"🌐 Блокировка сайтов применена: {len(sites)}")
        else:
            log("🧹 Блокировка сайтов очищена")
        return True

    except PermissionError:
        log("❌ Нет прав для изменения hosts. Запусти App Blocker от имени администратора.")
        return False
    except Exception as e:
        log(f"⚠️ Ошибка блокировки сайтов: {e}")
        return False

def normalize_process_name(name):
    return name.strip().lower()

def sync_primary_process_name():
    global PROCESS_NAME
    PROCESS_NAME = BLOCKED_PROGRAMS[0] if BLOCKED_PROGRAMS else ""

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
        "blocked_programs": BLOCKED_PROGRAMS,
        "admin_password": ADMIN_PASSWORD,
        "status": status,
        "timer_enabled": TIMER_ENABLED,
        "timer_end": TIMER_END.timestamp() if TIMER_END else None,
        "secure_enabled": SECURE_ENABLED,
        "permanent_lock": PERMANENT_LOCK,
        "authenticated": True
    })

    # ✅ Сохраняем обратно
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def load_config():
    global PROCESS_NAME, BLOCKED_PROGRAMS, ADMIN_PASSWORD, TIMER_ENABLED, TIMER_END, SECURE_ENABLED, PERMANENT_LOCK  # ← ДОБАВЬ PERMANENT_LOCK
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
        saved_programs = config.get("blocked_programs", [])
        if not saved_programs and config.get("process_name", ""):
            saved_programs = [config.get("process_name", "")]
        BLOCKED_PROGRAMS = []
        for program in saved_programs:
            program = normalize_process_name(program)
            if program and program not in BLOCKED_PROGRAMS:
                BLOCKED_PROGRAMS.append(program)
        sync_primary_process_name()
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
    if not BLOCKED_PROGRAMS:
        return False

    for proc in psutil.process_iter():
        try:
            process_name = proc.name().lower()
            if any(program in process_name for program in BLOCKED_PROGRAMS):
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

def clear_logs():
    text_log.configure(state="normal")
    text_log.delete("0.0", "end")
    text_log.insert("end", "🛡 Логи очищены.")
    text_log.configure(state="disabled")

# Поток фоновой проверки
def monitor_process():
    global monitoring_active, last_monitor_state
    while monitoring_active:
        if not BLOCKED_PROGRAMS:
            time.sleep(1)  # Ждем, пока процесс будет задан
            continue

        if is_app_running():
            if last_monitor_state != "running":
                log("🔍 Найдена заблокированная программа. Закрываю...")
            last_monitor_state = "running"
            close_app()
        else:
            if last_monitor_state != "clear":
                log("✅ Заблокированные программы не запущены.")
            last_monitor_state = "clear"
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

    input_name = normalize_process_name(entry_process.get())
    if input_name and input_name not in BLOCKED_PROGRAMS:
        BLOCKED_PROGRAMS.append(input_name)
        refresh_blocked_programs_list()
    sync_primary_process_name()
    save_config()
    if not input_name:
        input_name = PROCESS_NAME

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

    root.title(f"Blocker: {len(BLOCKED_PROGRAMS)} programs")

    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_process, daemon=True)
        monitor_thread.start()
        log(f"🚀 Мониторинг процесса '{PROCESS_NAME}' запущен.")
    else:
        log(f"✅ Мониторинг продолжен для процесса '{PROCESS_NAME}'.")

    entry_process.configure(state="disabled")
    add_program_btn.configure(state="disabled")
    remove_program_btn.configure(state="disabled")
    big_start_btn.configure(state="disabled")
    update_status_cards()

    save_config()


def toggle_secure_mode():
    global SECURE_ENABLED
    SECURE_ENABLED = secure_switch.get() == 1
    state = "включена 🟢" if SECURE_ENABLED else "отключена 🔴"
    log(f"🧰 Защита от завершения {state}")
    update_status_cards()
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

    # Сразу после "with EXIT_LOCK:" и проверки APP_CLOSING
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                _d = json.load(f)
            _d["authenticated"] = False
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(_d, f, indent=2)
    except Exception:
        pass

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
    dialog = ctk.CTkToplevel(root)
    dialog.title(title)
    dialog.geometry("520x280")
    dialog.resizable(False, False)
    dialog.configure(fg_color=APP_BG)
    dialog.grab_set()
    dialog.transient(root)
    set_window_icon(dialog)

    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() - dialog.winfo_reqwidth()) // 2
    y = (dialog.winfo_screenheight() - dialog.winfo_reqheight()) // 2
    dialog.geometry(f"+{x}+{y}")

    panel = ctk.CTkFrame(dialog, fg_color=PANEL_BG, corner_radius=18, border_width=1, border_color=BORDER_GREEN)
    panel.pack(fill="both", expand=True, padx=18, pady=18)

    title_label = ctk.CTkLabel(panel, text=title, font=("Arial", 22, "bold"), text_color=ACCENT_GREEN)
    title_label.pack(pady=(22, 8))

    label = ctk.CTkLabel(panel, text=message, font=("Arial", 14), text_color=TEXT_MAIN, wraplength=430, justify="center")
    label.pack(pady=(0, 16))

    entry = ctk.CTkEntry(panel, show="*", width=320, height=38)
    entry.pack(pady=4)
    entry.configure(
        fg_color="#030a07",
        border_color=BORDER_GREEN,
        text_color=TEXT_MAIN,
        placeholder_text_color=TEXT_MUTED,
        corner_radius=10
    )
    entry.focus_set()

    result = {"password": None}

    def on_ok():
        result["password"] = entry.get()
        dialog.destroy()

    def on_cancel():
        result["password"] = None
        dialog.destroy()

    btn_frame = ctk.CTkFrame(panel, fg_color="transparent")
    btn_frame.pack(pady=22)

    ok_btn = ctk.CTkButton(btn_frame, text="✅ ОК", width=130, height=38, command=on_ok)
    ok_btn.pack(side="left", padx=10)
    ok_btn.configure(fg_color=ACCENT_GREEN_DARK, hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN, corner_radius=10)

    cancel_btn = ctk.CTkButton(btn_frame, text="✕ Отмена", width=130, height=38, command=on_cancel)
    cancel_btn.pack(side="left", padx=10)
    cancel_btn.configure(fg_color=DANGER, hover_color=DANGER_HOVER, text_color=TEXT_MAIN, corner_radius=10)

    entry.bind("<Return>", lambda e: on_ok())
    entry.bind("<Escape>", lambda e: on_cancel())
    entry.bind("<<Paste>>", lambda event: paste_into_entry(entry))
    entry.bind("<Control-v>", lambda event: paste_into_entry(entry))
    entry.bind("<Control-V>", lambda event: paste_into_entry(entry))
    entry.bind("<Control-KeyPress>", handle_entry_ctrl_key)

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

def refresh_blocked_programs_list():
    blocked_programs_box.configure(state="normal")
    blocked_programs_box.delete("0.0", "end")
    if BLOCKED_PROGRAMS:
        for program in BLOCKED_PROGRAMS:
            blocked_programs_box.insert("end", f"{program}\n")
    else:
        blocked_programs_box.insert("end", "Список пуст. Добавьте программы перед запуском.")
    blocked_programs_box.configure(state="disabled")
    update_status_cards()

def update_status_cards():
    try:
        programs_status_value.configure(text=f"{len(BLOCKED_PROGRAMS)} в списке")
        monitor_status_value.configure(
            text="Активен" if monitoring_active else "Ожидает",
            text_color=ACCENT_GREEN if monitoring_active else TEXT_MAIN
        )
        secure_status_value.configure(
            text="Активна" if SECURE_ENABLED else "Выкл.",
            text_color=ACCENT_GREEN if SECURE_ENABLED else TEXT_MUTED
        )
    except NameError:
        pass

def add_blocked_program(silent=False):
    program = normalize_process_name(entry_process.get())
    if not program:
        if not silent:
            log("⚠️ Введите название программы для блокировки.")
        return
    if program in BLOCKED_PROGRAMS:
        if not silent:
            log(f"ℹ️ {program} уже есть в списке блокировки.")
        return
    BLOCKED_PROGRAMS.append(program)
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list()
    entry_process.delete(0, "end")
    if not silent:
        log(f"✅ Программа {program} добавлена в список блокировки.")

def remove_blocked_program():
    program = normalize_process_name(entry_process.get())
    if not program:
        log("⚠️ Введите название программы для удаления из списка.")
        return
    if program not in BLOCKED_PROGRAMS:
        log(f"ℹ️ {program} не найдена в списке блокировки.")
        return
    BLOCKED_PROGRAMS.remove(program)
    sync_primary_process_name()
    save_config()
    refresh_blocked_programs_list()
    entry_process.delete(0, "end")
    log(f"🗑️ Программа {program} удалена из списка блокировки.")

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
root.geometry("1120x720")
set_window_icon(root)
root.resizable(True, True)
root.configure(fg_color=APP_BG)

# Верхний фрейм с вводом и кнопками
frame_input = ctk.CTkFrame(root, fg_color=TOPBAR_BG, corner_radius=14, border_width=1, border_color=BORDER_GREEN)
frame_input.pack(padx=14, pady=(14, 6), fill='x')

label_process = ctk.CTkLabel(frame_input, text="Название процесса:")
label_process.pack(side="left", padx=5)
label_process.configure(text_color=TEXT_MAIN, font=("Arial", 13, "bold"))

entry_process = ctk.CTkEntry(frame_input, width=220, placeholder_text="chrome.exe")
entry_process.pack(side="left", padx=5, fill="x", expand=True)
entry_process.configure(fg_color="#030a07", border_color=BORDER_GREEN, text_color=TEXT_MAIN, placeholder_text_color=TEXT_MUTED)
entry_process.bind("<<Paste>>", lambda event: paste_into_entry(entry_process))
entry_process.bind("<Control-v>", lambda event: paste_into_entry(entry_process))
entry_process.bind("<Control-V>", lambda event: paste_into_entry(entry_process))
entry_process.bind("<Control-KeyPress>", handle_entry_ctrl_key)

# Левая панель навигации
nav_frame = ctk.CTkFrame(root, width=190, corner_radius=18, fg_color=SIDEBAR_BG, border_width=1, border_color=BORDER_GREEN)
nav_frame.pack(side="left", fill="y", padx=(14, 6), pady=(8, 14))
nav_frame.pack_propagate(False)

# Центральная панель
button_start = ctk.CTkFrame(root, fg_color="transparent")
button_start.pack(side="left", fill="both", expand=True, padx=10, pady=14)

status_cards_frame = ctk.CTkFrame(button_start, fg_color="transparent")
status_cards_frame.pack(fill="x", pady=(0, 14))

programs_status_card = ctk.CTkFrame(status_cards_frame, fg_color=CARD_BG, corner_radius=16, border_width=1, border_color=BORDER_GREEN)
programs_status_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
ctk.CTkLabel(programs_status_card, text="Программы", text_color=TEXT_MUTED, font=("Arial", 12, "bold")).pack(anchor="w", padx=18, pady=(14, 0))
programs_status_value = ctk.CTkLabel(programs_status_card, text="0 в списке", text_color=ACCENT_GREEN, font=("Arial", 24, "bold"))
programs_status_value.pack(anchor="w", padx=18, pady=(4, 14))

monitor_status_card = ctk.CTkFrame(status_cards_frame, fg_color=CARD_BG, corner_radius=16, border_width=1, border_color=BORDER_GREEN)
monitor_status_card.pack(side="left", fill="both", expand=True, padx=8)
ctk.CTkLabel(monitor_status_card, text="Мониторинг", text_color=TEXT_MUTED, font=("Arial", 12, "bold")).pack(anchor="w", padx=18, pady=(14, 0))
monitor_status_value = ctk.CTkLabel(monitor_status_card, text="Ожидает", text_color=TEXT_MAIN, font=("Arial", 24, "bold"))
monitor_status_value.pack(anchor="w", padx=18, pady=(4, 14))

secure_status_card = ctk.CTkFrame(status_cards_frame, fg_color=CARD_BG, corner_radius=16, border_width=1, border_color=BORDER_GREEN)
secure_status_card.pack(side="left", fill="both", expand=True, padx=(8, 0))
ctk.CTkLabel(secure_status_card, text="Защита", text_color=TEXT_MUTED, font=("Arial", 12, "bold")).pack(anchor="w", padx=18, pady=(14, 0))
secure_status_value = ctk.CTkLabel(secure_status_card, text="Активна", text_color=ACCENT_GREEN, font=("Arial", 24, "bold"))
secure_status_value.pack(anchor="w", padx=18, pady=(4, 14))

button_refresh = ctk.CTkButton(frame_input, text="Обновить процессы", command=refresh_process_list)
button_refresh.pack(side="left", padx=5)
button_refresh.configure(fg_color="#155b3a", hover_color="#1b774a", text_color=TEXT_MAIN, corner_radius=10)

add_program_btn = ctk.CTkButton(frame_input, text="Добавить", width=100, command=add_blocked_program)
add_program_btn.pack(side="left", padx=5)
add_program_btn.configure(fg_color=ACCENT_GREEN_DARK, hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN, corner_radius=10)

remove_program_btn = ctk.CTkButton(frame_input, text="Удалить", width=100, command=remove_blocked_program)
remove_program_btn.pack(side="left", padx=5)
remove_program_btn.configure(fg_color="#2a3330", hover_color="#3e4b46", text_color=TEXT_MAIN, corner_radius=10)

big_start_btn = ctk.CTkButton(button_start, text="🚀 Начать блокировку", width=300, height=50, command=start_monitoring)
big_start_btn.pack(pady=(0, 18))
big_start_btn.configure(fg_color=ACCENT_GREEN_DARK, hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN, font=("Arial", 18, "bold"), corner_radius=14)

ctk.CTkLabel(button_start, text="Заблокированные программы", font=("Arial", 16, "bold")).pack(pady=(0, 5))
blocked_programs_box = ctk.CTkTextbox(button_start, height=120, width=400)
blocked_programs_box.pack(pady=(0, 10), fill="x")
blocked_programs_box.configure(state="disabled", cursor="arrow")
blocked_programs_box.configure(fg_color="#050b08", border_color="#1f6b45", border_width=1, text_color=TEXT_MAIN, corner_radius=14)

ctk.CTkLabel(button_start, text="Активные процессы", font=("Arial", 16, "bold")).pack(pady=(5, 0))
process_box = ctk.CTkTextbox(button_start, height=300, width=400)
process_box.pack(pady=10, fill="both", expand=True)
process_box.configure(state="disabled", cursor="arrow")  # ⛔ запрещаем редактировать
process_box.configure(fg_color="#050b08", border_color="#1f6b45", border_width=1, text_color=TEXT_MAIN, corner_radius=14)

# Левая панель навигации (добавь после создания nav_frame)
ctk.CTkLabel(nav_frame, text="APP BLOCKER", font=("Arial", 18, "bold"), text_color=ACCENT_GREEN).pack(pady=(22, 18))
nav_monitor_btn = ctk.CTkButton(nav_frame, text="Мониторинг", width=155, height=42, command=lambda: show_frame("monitor"))
nav_monitor_btn.pack(pady=8)
nav_sites_btn = ctk.CTkButton(nav_frame, text="🌐 Сайты", width=155, height=42, command=lambda: show_frame("sites"))
nav_sites_btn.pack(pady=8)
nav_settings_btn = ctk.CTkButton(nav_frame, text="Настройки", width=155, height=42, command=lambda: show_frame("settings"))
nav_settings_btn.pack(pady=8)
nav_about_btn = ctk.CTkButton(nav_frame, text="О программе", width=155, height=42, command=lambda: show_frame("about"))
nav_about_btn.pack(pady=8)
for nav_btn in (nav_monitor_btn, nav_sites_btn, nav_settings_btn, nav_about_btn):
    nav_btn.configure(fg_color=CARD_BG, hover_color=CARD_HOVER, text_color=TEXT_MAIN, corner_radius=12, border_width=1, border_color=BORDER_GREEN)

button_exit = ctk.CTkButton(
    frame_input,
    text="Выйти",
    command=exit_app,
    fg_color=DANGER,
    hover_color=DANGER_HOVER,
    text_color="white"
)
button_exit.pack(side="left", padx=5)
button_exit.configure(corner_radius=10)

# Фрейм под логи
frame_logs = ctk.CTkFrame(root, width=270)
frame_logs.pack(side="right", fill="y")
frame_logs.configure(fg_color=PANEL_BG, corner_radius=18, border_width=1, border_color=BORDER_GREEN)
frame_logs.pack_propagate(False)

ctk.CTkLabel(frame_logs, text="Логи", font=("Arial", 20, "bold"), text_color=ACCENT_GREEN).pack(pady=20)
clear_logs_btn = ctk.CTkButton(frame_logs, text="Очистить", width=120, command=clear_logs)
clear_logs_btn.pack(pady=(0, 8))
clear_logs_btn.configure(fg_color="#155b3a", hover_color="#1b774a", text_color=TEXT_MAIN, corner_radius=10)
text_log = ctk.CTkTextbox(frame_logs, width=245, height=500)
text_log.pack(padx=10, pady=(0, 10), fill="both", expand=True)
text_log.insert("end", "🛡 Готов к блокировке...")
#невозможность редачить логи
text_log.configure(state="disabled")
text_log.configure(fg_color="#030a07", border_color=BORDER_GREEN, border_width=1, text_color=TEXT_MAIN, corner_radius=14)

# ================== О ПРОГРАММЕ ==================
about_frame = ctk.CTkFrame(root, fg_color="transparent")
about_frame.pack_forget()  # скрыт по умолчанию

ctk.CTkLabel(about_frame, text="О программе", font=("Arial", 22, "bold"), text_color=ACCENT_GREEN).pack(pady=20)

about_text = ctk.CTkTextbox(about_frame, width=600, height=500)
about_text.pack(padx=20, pady=10, fill="both", expand=True)
about_text.configure(fg_color=CARD_BG, border_color=BORDER_GREEN, border_width=1, text_color=TEXT_MAIN, corner_radius=16)

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
                          "Программа полностью бесплатная, кто может поддержите пожалуйста автора:\n USDT Trc 20 - TSyWGrCkn12LojGEK9urQmWr9ojPimzgBw \n Solana ErQZHWvNHnWQrX2HXbAULTn46uBFkao6aPfarFjKsHva \n Btc bc1qg2a9tnykvdw6sh57hre3mzst8pz3ga5xc7xtye")
about_text.delete("0.0", "end")
about_text.insert("end", """APP BLOCKER
Версия: 2.4.0 Beta

App Blocker - это инструмент для ограничения запуска выбранных программ и сайтов на Windows.
Приложение отслеживает список заблокированных процессов и автоматически завершает их при запуске.

Что есть в версии 2.4.0 Beta:

- Блокировка нескольких программ одновременно.
- Отдельный список заблокированных программ прямо на главном экране.
- Мониторинг активных процессов в реальном времени.
- Защита от закрытия через SecureSystem.
- Автовосстановление мониторинга после перезапуска.
- Блокировка сайтов через hosts.
- Таймер работы и режим постоянной блокировки.
- Новый черно-зеленый интерфейс с карточками статуса.
- Более чистые логи с кнопкой очистки.
- Исправлена вставка Ctrl+V в поле ввода программы.
- Исправлена ошибка запуска при отсутствии icon.ico рядом с exe.

Как пользоваться:

1. Введите название программы, например steam или chrome.exe.
2. Нажмите "Добавить".
3. Повторите это для всех программ, которые нужно заблокировать.
4. Нажмите "Начать блокировку".

После запуска мониторинга программа будет закрывать все процессы, совпадающие с правилами из списка.
Например, правило steam также может закрывать steam.exe и steamwebhelper.exe.

Beta-предупреждение:

Версия 2.4.0 Beta находится в активной разработке. Возможны баги в интерфейсе, автозапуске,
работе защиты или сборке exe. Перед использованием в важных задачах проверьте настройки
на своем ПК и убедитесь, что пароль выхода сохранен.

Разработчик: smics_play
Помощь в разработке: ChatGPT и Claude AI

Используйте программу ответственно и только на компьютерах, где у вас есть право на такие ограничения.
""")
about_text.configure(state="disabled")

# ================== БЛОКИРОВКА САЙТОВ ==================
sites_frame = ctk.CTkFrame(root, fg_color="transparent")
sites_frame.pack_forget()

ctk.CTkLabel(sites_frame, text="Блокировка сайтов 🌐", font=("Arial", 22, "bold"), text_color=ACCENT_GREEN).pack(pady=20)

sites_status_label = ctk.CTkLabel(sites_frame, text="0 сайтов в блокировке", font=("Arial", 15, "bold"), text_color=TEXT_MUTED)
sites_status_label.pack(pady=(0, 8))

sites_listbox = ctk.CTkTextbox(sites_frame, width=500, height=300)
sites_listbox.pack(pady=10)
sites_listbox.configure(state="disabled")
sites_listbox.configure(fg_color=CARD_BG, border_color=BORDER_GREEN, border_width=1, text_color=TEXT_MAIN, corner_radius=16)

site_entry = ctk.CTkEntry(sites_frame, width=420, placeholder_text="youtube.com, vk.com или https://example.com/page")
site_entry.pack(pady=5)
site_entry.configure(fg_color="#030a07", border_color=BORDER_GREEN, text_color=TEXT_MAIN, placeholder_text_color=TEXT_MUTED)
site_entry.bind("<<Paste>>", lambda event: paste_into_entry(site_entry))
site_entry.bind("<Control-v>", lambda event: paste_into_entry(site_entry))
site_entry.bind("<Control-V>", lambda event: paste_into_entry(site_entry))
site_entry.bind("<Control-KeyPress>", handle_entry_ctrl_key)

def refresh_sites_list():
    sites = load_blocked_sites()
    sites_listbox.configure(state="normal")
    sites_listbox.delete("0.0", "end")
    if sites:
        for s in sites:
            sites_listbox.insert("end", f"{s}\n")
    else:
        sites_listbox.insert("end", "Список пуст. Можно добавить несколько сайтов через пробел, запятую или с новой строки.")
    sites_listbox.configure(state="disabled")
    sites_status_label.configure(text=f"{len(sites)} сайтов в блокировке")

def add_site():
    new_sites = parse_sites_input(site_entry.get())
    if not new_sites:
        log("⚠️ Введите домен сайта: youtube.com, vk.com, example.org")
        return
    sites = load_blocked_sites()
    target_sites = normalize_sites(sites + new_sites)
    added = [site for site in new_sites if site not in sites]
    if added:
        if apply_hosts_block(target_sites):
            save_blocked_sites(target_sites)
            site_entry.delete(0, "end")
            refresh_sites_list()
            log(f"✅ Добавлено сайтов: {len(added)}")
    else:
        log("ℹ️ Эти сайты уже есть в блокировке.")

def apply_sites_from_config():
    sites = load_blocked_sites()
    if apply_hosts_block(sites):
        refresh_sites_list()
        log("✅ Список сайтов применён повторно.")

def remove_site():
    remove_sites = parse_sites_input(site_entry.get())
    if not remove_sites:
        log("⚠️ Введите сайт для удаления.")
        return
    sites = load_blocked_sites()
    target_sites = [site for site in sites if site not in remove_sites]
    removed = [site for site in remove_sites if site in sites]
    if removed:
        if apply_hosts_block(target_sites):
            save_blocked_sites(target_sites)
            site_entry.delete(0, "end")
            refresh_sites_list()
            log(f"🗑️ Удалено сайтов: {len(removed)}")
    else:
        log("ℹ️ Таких сайтов нет в списке блокировки.")

def clear_all_sites():
    if apply_hosts_block([]):
        save_blocked_sites([])
        refresh_sites_list()
        site_entry.delete(0, "end")
        log("🧹 Все сайты удалены из блокировки.")

btn_frame = ctk.CTkFrame(sites_frame, fg_color="transparent")
btn_frame.pack(pady=10)

add_btn = ctk.CTkButton(btn_frame, text="➕ Добавить", width=120, command=add_site)
add_btn.pack(side="left", padx=5)
add_btn.configure(fg_color=ACCENT_GREEN_DARK, hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN, corner_radius=10)

remove_btn = ctk.CTkButton(btn_frame, text="❌ Удалить", width=120, command=remove_site)
remove_btn.pack(side="left", padx=5)
remove_btn.configure(fg_color="#123c2a", hover_color="#1b5f3f", text_color=TEXT_MAIN, corner_radius=10)

apply_sites_btn = ctk.CTkButton(btn_frame, text="↻ Применить", width=120, command=apply_sites_from_config)
apply_sites_btn.pack(side="left", padx=5)
apply_sites_btn.configure(fg_color="#155b3a", hover_color="#1b774a", text_color=TEXT_MAIN, corner_radius=10)

clear_sites_btn = ctk.CTkButton(btn_frame, text="🧹 Очистить всё", width=130, command=clear_all_sites)
clear_sites_btn.pack(side="left", padx=5)
clear_sites_btn.configure(fg_color="#2a3330", hover_color="#3e4b46", text_color=TEXT_MAIN, corner_radius=10)

# ================== НАСТРОЙКИ ==================
settings_frame = ctk.CTkFrame(root, fg_color="transparent")
settings_frame.pack_forget()

ctk.CTkLabel(settings_frame, text="Настройки", font=("Arial", 22, "bold"), text_color=ACCENT_GREEN).pack(pady=20)
settings_content = ctk.CTkFrame(settings_frame, fg_color="transparent")
settings_content.pack(fill="both", expand=True, padx=30, pady=(0, 20))

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

def parse_timer_end_time(value):
    value = value.strip()
    if not re.fullmatch(r"\d{1,2}:\d{2}", value):
        raise ValueError
    hour_text, minute_text = value.split(":")
    hour = int(hour_text)
    minute = int(minute_text)
    if hour > 23 or minute > 59:
        raise ValueError

    now = datetime.datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return target

def set_timer():
    global TIMER_END, timer_thread

    if not timer_entry.get().strip():
        log("⚠️ Введите время окончания в формате HH:MM")
        return

    try:
        TIMER_END = parse_timer_end_time(timer_entry.get())
        save_config()
        log(f"⏳ Таймер установлен до {TIMER_END.strftime('%H:%M')}")

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
        log("⚠️ Введите корректное время в формате HH:MM, например 23:30")

timer_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=16, border_width=1, border_color=BORDER_GREEN)
timer_card.pack(fill="x", pady=(0, 18))
ctk.CTkLabel(timer_card, text="Таймер завершения", font=("Arial", 18, "bold"), text_color=ACCENT_GREEN).pack(anchor="w", padx=22, pady=(18, 4))
timer_switch = ctk.CTkSwitch(
    timer_card,
    text="Ограничение по времени",
    command=toggle_timer_mode
)
timer_switch.pack(anchor="w", padx=22, pady=(8, 6))
timer_switch.configure(progress_color=ACCENT_GREEN_DARK, button_color=ACCENT_GREEN, button_hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN)

timer_description = ctk.CTkLabel(
    timer_card,
    text="Укажите точное время окончания блокировки в формате HH:MM. Если время уже прошло, таймер сработает завтра.",
    font=("Arial", 12),
    text_color=TEXT_MUTED,
    wraplength=620,
    justify="left"
)
timer_description.pack(anchor="w", padx=22, pady=(0, 12))


timer_frame = ctk.CTkFrame(timer_card, fg_color="transparent")
ctk.CTkLabel(timer_frame, text="Время окончания:", text_color=TEXT_MAIN, font=("Arial", 13, "bold")).pack(side="left", padx=5)
timer_entry = ctk.CTkEntry(timer_frame, width=110, placeholder_text="23:30")
timer_entry.pack(side="left", padx=5)
timer_entry.configure(fg_color="#030a07", border_color=BORDER_GREEN, text_color=TEXT_MAIN, placeholder_text_color=TEXT_MUTED)
timer_set_btn = ctk.CTkButton(timer_frame, text="✅ Установить", command=set_timer)
timer_set_btn.pack(side="left", padx=5)
timer_set_btn.configure(fg_color=ACCENT_GREEN_DARK, hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN, corner_radius=10)

# по умолчанию скрыт
if not TIMER_ENABLED:
    timer_frame.pack_forget()
else:
    timer_switch.select()
    timer_frame.pack(pady=5)

secure_card = ctk.CTkFrame(settings_content, fg_color=CARD_BG, corner_radius=16, border_width=1, border_color=BORDER_GREEN)
secure_card.pack(fill="x")
ctk.CTkLabel(secure_card, text="Системная защита", font=("Arial", 18, "bold"), text_color=ACCENT_GREEN).pack(anchor="w", padx=22, pady=(18, 4))
secure_switch = ctk.CTkSwitch(
    secure_card,
    text="Защита от завершения",
    command=toggle_secure_mode
)
secure_switch.select()  # по умолчанию включен
secure_switch.pack(anchor="w", padx=22, pady=(8, 6))
secure_switch.configure(progress_color=ACCENT_GREEN_DARK, button_color=ACCENT_GREEN, button_hover_color=ACCENT_GREEN_HOVER, text_color=TEXT_MAIN)

secure_description = ctk.CTkLabel(
    secure_card,
    text="SecureSystem следит за App Blocker и возвращает мониторинг после перезапуска. Для стабильной работы оставляйте защиту включённой.",
    font=("Arial", 12),
    text_color=TEXT_MUTED,
    wraplength=620,
    justify="left"
)
secure_description.pack(anchor="w", padx=22, pady=(0, 18))

# Перехват крестика
root.protocol("WM_DELETE_WINDOW", on_close)

# Запуск GUI
log("Введите название процесса и нажмите 'Начать'.")
refresh_process_list()

# ----------------- АВТО ЗАПУСК -----------------
load_config()
refresh_blocked_programs_list()


if PERMANENT_LOCK:
    secure_switch.configure(state="disabled")
    timer_switch.configure(state="disabled")
    timer_entry.configure(state="disabled")
    remove_btn.configure(state="disabled")
    add_program_btn.configure(state="disabled")
    remove_program_btn.configure(state="disabled")
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
need_restore_window = False

if not ADMIN_PASSWORD:
    root.iconify()
    ADMIN_PASSWORD = custom_password_dialog(
        "Пароль администратора",
        "Введите пароль, который будет использоваться для выхода:",
    )
    if not ADMIN_PASSWORD:
        messagebox.showerror("Ошибка", "Пароль не задан! Программа будет закрыта.")
        root.destroy()
        sys.exit(0)
    save_config(status="RUNNING")
    APP_CLOSING = False
    need_restore_window = True
else:
    _startup_config = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                _startup_config = json.load(f)
        except Exception:
            pass
    _already_authenticated = _startup_config.get("authenticated", False)
    if _already_authenticated:
        log("🔄 Автовосстановление — пароль не требуется.")
        APP_CLOSING = False
        need_restore_window = True
    else:
        root.iconify()
        authenticated = False
        for attempt in range(3):
            password_input = custom_password_dialog("Пароль администратора", "Введите пароль администратора для входа:")
            if password_input == ADMIN_PASSWORD:
                authenticated = True
                break
            if password_input is None:
                break
            messagebox.showerror("Ошибка", "Неверный пароль! Попробуйте снова.")
        if not authenticated:
            messagebox.showerror("Ошибка", "Доступ заблокирован без правильного пароля.")
            root.destroy()
            sys.exit(0)
        log("🔓 Пароль администратора подтверждён.")
        save_config(status="RUNNING")
        APP_CLOSING = False
        need_restore_window = True

if need_restore_window:
    root.after(100, lambda: (
        root.deiconify(),
        root.lift(),
        root.focus_force(),
    ))

if ensure_secure_system():
    log("🛡 Система защиты от завершения запущенна")

if BLOCKED_PROGRAMS:
    entry_process.insert(0, PROCESS_NAME)
    entry_process.configure(state="disabled")
    add_program_btn.configure(state="disabled")
    remove_program_btn.configure(state="disabled")
    big_start_btn.configure(state="disabled")
    monitoring_active = True
    threading.Thread(target=monitor_process, daemon=True).start()
    update_status_cards()
    log(f"✅ Автовосстановление мониторинга для программ: {', '.join(BLOCKED_PROGRAMS)}")

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

