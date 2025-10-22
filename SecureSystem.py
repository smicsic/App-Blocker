# SecureSystem.py
import psutil
import time
import os
import sys
import json
import subprocess

CHECK_INTERVAL = 0.5
APP_NAME = "AppBlocker.exe"

def base_dir():
    # Папка, где лежит сам .exe (или .py в режиме отладки)
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def status_path():
    return os.path.join(base_dir(), "config.json")

def get_status():
    """Читает статус из config.json в папке с SecureSystem.exe"""
    config_path = os.path.join(base_dir(), "config.json")
    try:
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("status", "RUNNING")
    except Exception as e:
        print(f"[SecureSystem] ⚠️ Ошибка чтения config.json: {e}")
    return "RUNNING"

def is_appblocker_running():
    """Проверяет, запущен ли AppBlocker"""
    for proc in psutil.process_iter(['name', 'exe']):
        try:
            name = (proc.info.get('name') or "").lower()
            if "appblocker" in name:
                return True
            # Доп. проверка по пути на случай переименований
            exe = (proc.info.get('exe') or "").lower()
            if exe and exe.endswith(APP_NAME.lower()):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

def restart_appblocker():
    """Запускает AppBlocker из той же папки, что и SecureSystem"""
    app_path = os.path.join(base_dir(), APP_NAME)
    try:
        if os.path.exists(app_path):
            # cwd=base_dir() — чтобы все относительные пути у AppBlocker были из этой папки
            # CREATE_NO_WINDOW — без моргания консоли
            creationflags = 0x08000000 if os.name == "nt" else 0
            subprocess.Popen([app_path], cwd=base_dir(), creationflags=creationflags)
            print(f"[SecureSystem] 🔄 Перезапуск AppBlocker: {time.strftime('%H:%M:%S')}")
        else:
            print(f"[SecureSystem] ❌ Не найден {app_path}")
    except Exception as e:
        print(f"[SecureSystem] ❌ Ошибка перезапуска: {e}")

def main():
    print(f"[SecureSystem] 🔐 Запуск. Папка: {base_dir()}")
    print("[SecureSystem] 🛡️  Мониторинг AppBlocker активирован")

    # Стартуем AppBlocker сразу, если он не запущен
    if not is_appblocker_running():
        restart_appblocker()
        time.sleep(1)

    while True:
        try:
            # Корректное завершение по команде из файла
            if get_status() == "EXIT":
                print("[SecureSystem] 🛑 Получен EXIT. Завершение…")
                break

            # Держим AppBlocker живым
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

    # Чистим статусный файл, чтобы не залипал EXIT на следующий запуск
    try:
        config_path = status_path()
        if os.path.exists(config_path):
            os.remove(config_path)
            print(f"[SecureSystem] 🧹 config.json удалён после EXIT")
    except Exception as e:
        print(f"[SecureSystem] ⚠️ Ошибка при удалении config.json: {e}")

    print("[SecureSystem] ✅ Завершено")

if __name__ == "__main__":
    main()
