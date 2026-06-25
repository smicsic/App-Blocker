import json
import os
import subprocess
import sys
import time
import winreg

import psutil


CHECK_INTERVAL = 0.5
APP_NAME = "AppBlocker.exe"
TASK_NAME = "AppBlockerGuard"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000 if os.name == "nt" else 0)


def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def config_path():
    return os.path.join(base_dir(), "config.json")


def sentinel_path():
    return os.path.join(base_dir(), "config.exit.lock")


def get_status():
    if not os.path.exists(config_path()):
        return "EXIT"
    try:
        with open(config_path(), "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        return data.get("status", "RUNNING")
    except Exception as e:
        print(f"[AppBlockerGuard] Config read error: {e}")
        return "RUNNING"


def add_to_startup():
    exe_path = os.path.join(base_dir(), "AppBlockerGuard.exe")
    if not os.path.exists(exe_path):
        print(f"[AppBlockerGuard] Startup skipped: {exe_path} not found")
        return

    quoted_exe = f'"{exe_path}"'
    try:
        result = subprocess.run(
            [
                "schtasks", "/Create",
                "/TN", TASK_NAME,
                "/TR", quoted_exe,
                "/SC", "ONLOGON",
                "/RL", "HIGHEST",
                "/F",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW,
            text=True,
            timeout=8,
        )
        if result.returncode == 0:
            print(f"[AppBlockerGuard] Scheduled task updated: {exe_path}")
        else:
            print(f"[AppBlockerGuard] Scheduled task failed: {result.stderr.strip()}")
    except Exception as e:
        print(f"[AppBlockerGuard] Scheduled task error: {e}")

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE) as reg_key:
            winreg.SetValueEx(reg_key, TASK_NAME, 0, winreg.REG_SZ, quoted_exe)
        print(f"[AppBlockerGuard] Registry startup updated: {exe_path}")
    except Exception as e:
        print(f"[AppBlockerGuard] Registry startup error: {e}")


def is_exit_flag_set():
    return os.path.exists(sentinel_path())


def is_appblocker_running():
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            name = (proc.info.get("name") or "").lower()
            exe = (proc.info.get("exe") or "").lower()
            if name == APP_NAME.lower() or exe.endswith(APP_NAME.lower()):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def restart_appblocker():
    app_path = os.path.join(base_dir(), APP_NAME)
    try:
        if os.path.exists(app_path):
            subprocess.Popen([app_path, "--guard-restart"], cwd=base_dir(), creationflags=CREATE_NO_WINDOW)
            print(f"[AppBlockerGuard] AppBlocker restart: {time.strftime('%H:%M:%S')}")
        else:
            print(f"[AppBlockerGuard] AppBlocker not found: {app_path}")
    except Exception as e:
        print(f"[AppBlockerGuard] AppBlocker restart error: {e}")


def cleanup_files():
    print("[AppBlockerGuard] Cleanup started")
    time.sleep(1.0)

    if os.path.exists(config_path()):
        print("[AppBlockerGuard] config.json kept to preserve user settings")
    else:
        print("[AppBlockerGuard] config.json not found")

    try:
        if os.path.exists(sentinel_path()):
            os.chmod(sentinel_path(), 0o666)
            os.remove(sentinel_path())
            print("[AppBlockerGuard] config.exit.lock removed")
    except Exception as e:
        print(f"[AppBlockerGuard] sentinel cleanup error: {e}")


def main():
    print(f"[AppBlockerGuard] Started in: {base_dir()}")

    status = get_status()
    if status == "EXIT" or is_exit_flag_set():
        print(f"[AppBlockerGuard] Exit state detected at startup, status={status}")
        cleanup_files()
        return

    add_to_startup()
    print("[AppBlockerGuard] AppBlocker monitor active")

    if not is_appblocker_running():
        restart_appblocker()
        time.sleep(1)

    while True:
        try:
            status = get_status()
            if status == "EXIT" or is_exit_flag_set():
                print(f"[AppBlockerGuard] Exit signal received, status={status}")
                cleanup_files()
                break

            if not is_appblocker_running():
                print(f"[AppBlockerGuard] AppBlocker not found. Restarting at {time.strftime('%H:%M:%S')}")
                restart_appblocker()

            time.sleep(CHECK_INTERVAL)
        except KeyboardInterrupt:
            print("[AppBlockerGuard] Interrupted")
            break
        except Exception as e:
            print(f"[AppBlockerGuard] Loop error: {e}")
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
