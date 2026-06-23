import psutil
import time
import os
import sys
import json
import subprocess
import winreg

CHECK_INTERVAL = 0.5
APP_NAME = "AppBlocker.exe"

def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def config_path():
    return os.path.join(base_dir(), "config.json")

def sentinel_path():
    return os.path.join(base_dir(), "config.exit.lock")

def get_status():
    try:
        if os.path.exists(config_path()):
            with open(config_path(), "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("status", "RUNNING")
    except Exception as e:
        print(f"[SecureSystem] ⚠️ Ошибка чтения config.json: {e}")
    return "RUNNING"

def add_to_startup():
    exe_path = os.path.join(base_dir(), "SecureSystem.exe")
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "SecureSystem"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_ALL_ACCESS) as reg_key:
            try:
                value, _ = winreg.QueryValueEx(reg_key, app_name)
                if value == exe_path:
                    return  # Уже есть — не трогаем
            except FileNotFoundError:
                pass
            winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, exe_path)
            print(f"[SecureSystem] ✅ Добавлен в автозагрузку: {exe_path}")
    except Exception as e:
        print(f"[SecureSystem] ⚠️ Ошибка при добавлении в автозагрузку: {e}")

    try:
        # Открываем ключ автозагрузки
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, app_name, 0, winreg.REG_SZ, exe_path)
            print(f"[SecureSystem] ✅ Добавлен в автозагрузку: {exe_path}")
    except Exception as e:
        print(f"[SecureSystem] ⚠️ Ошибка при добавлении в автозагрузку: {e}")

def is_exit_flag_set():
    """Проверяет наличие sentinel-файла (config.exit.lock)"""
    return os.path.exists(sentinel_path())

def is_appblocker_running():
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = (proc.info.get('name') or "").lower()
            exe = (proc.info.get('exe') or "").lower()
            if "appblocker" in name or exe.endswith(APP_NAME.lower()):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def restart_appblocker():
    app_path = os.path.join(base_dir(), APP_NAME)
    try:
        if os.path.exists(app_path):
            creationflags = 0x08000000 if os.name == "nt" else 0
            subprocess.Popen([app_path], cwd=base_dir(), creationflags=creationflags)
            print(f"[SecureSystem] 🔄 Перезапуск AppBlocker: {time.strftime('%H:%M:%S')}")
        else:
            print(f"[SecureSystem] ❌ Не найден {app_path}")
    except Exception as e:
        print(f"[SecureSystem] ❌ Ошибка перезапуска: {e}")

def cleanup_files():
    """🧹 Удаляет sentinel и config, но только если статус = EXIT"""
    print("[SecureSystem] 🧹 Запуск очистки...")
    time.sleep(1.0)  # 🕐 даём AppBlocker время закрыться

    # --- Удаление config.json ---
    for attempt in range(5):
        try:
            if os.path.exists(config_path()):
                with open(config_path(), "r", encoding="utf-8") as f:
                    data = json.load(f)
                    status = data.get("status", "RUNNING")

                if status == "EXIT":
                    os.chmod(config_path(), 0o666)
                    os.remove(config_path())
                    print(f"[SecureSystem] ✅ config.json удалён (попытка {attempt+1})")
                    break
                else:
                    print(f"[SecureSystem] ⏩ config.json сохранён (status={status})")
                    break
            else:
                print("[SecureSystem] ℹ️ config.json не найден")
                break
        except PermissionError:
            print(f"[SecureSystem] 🔒 config.json занят (попытка {attempt+1}), жду 1 сек...")
            time.sleep(1)
        except Exception as e:
            print(f"[SecureSystem] ⚠️ Ошибка при удалении config.json: {e}")
            break
    else:
        print("[SecureSystem] ❌ Не удалось удалить config.json после 5 попыток")

    # --- Удаление sentinel ---
    try:
        if os.path.exists(sentinel_path()):
            os.chmod(sentinel_path(), 0o666)
            os.remove(sentinel_path())
            print("[SecureSystem] ✅ config.exit.lock удалён")
    except Exception as e:
        print(f"[SecureSystem] ⚠️ Ошибка при удалении sentinel: {e}")

def main():
    print(f"[SecureSystem] 🔐 Запуск. Папка: {base_dir()}")
    add_to_startup()
    print("[SecureSystem] 🛡️ Мониторинг AppBlocker активирован")

    if not is_appblocker_running():
        restart_appblocker()
        time.sleep(1)

    while True:
        try:
            status = get_status()

            # 🔥 теперь SecureSystem реагирует только на статус EXIT
            if status == "EXIT" or is_exit_flag_set():
                print(f"[SecureSystem] 🛑 Получен сигнал завершения (status={status})")
                cleanup_files()
                print("[SecureSystem] ✅ Завершено корректно")
                break

            if not is_appblocker_running():
                print(f"[SecureSystem] ⚠️ AppBlocker не найден. Перезапуск… ({time.strftime('%H:%M:%S')})")
                restart_appblocker()

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("[SecureSystem] 🛑 Принудительное завершение")
            break
        except Exception as e:
            print(f"[SecureSystem] ❌ Ошибка цикла: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
