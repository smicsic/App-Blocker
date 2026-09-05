"""Минимальный автономный движок блокировки процессов для AppBlocker_Client.

Урезанная версия appcore/processes.py основного приложения: только то, что
нужно для команд block/unblock/get_status — список запрещённых имён (по
подстроке, как режим «Содержит» в основном AppBlocker) и фоновый цикл
завершения. Никакого whitelist-режима, работы с сайтами и т.п. — Client
занимается только тем, что ему прикажет Admin.
"""
import threading
import time

import psutil

_lock = threading.Lock()
_blocked_apps = set()
_monitor_thread = None
_monitor_active = False


def _normalize(name):
    return (name or "").strip().lower()


def blocked_apps():
    with _lock:
        return sorted(_blocked_apps)


def block(app_name):
    name = _normalize(app_name)
    if not name:
        return False
    with _lock:
        _blocked_apps.add(name)
    _ensure_monitor()
    return True


def unblock(app_name):
    name = _normalize(app_name)
    with _lock:
        _blocked_apps.discard(name)
    return True


def _matches_blocked(process_name):
    process_name = _normalize(process_name)
    if not process_name:
        return False
    with _lock:
        rules = list(_blocked_apps)
    return any(rule in process_name for rule in rules)


def _terminate_matching():
    for proc in psutil.process_iter(["name"]):
        try:
            name = proc.info.get("name") or ""
            if _matches_blocked(name):
                proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def _monitor_loop():
    global _monitor_active
    while _monitor_active:
        with _lock:
            has_rules = bool(_blocked_apps)
        if has_rules:
            try:
                _terminate_matching()
            except Exception:
                pass
        time.sleep(2)


def _ensure_monitor():
    global _monitor_thread, _monitor_active
    if _monitor_active:
        return
    _monitor_active = True
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    _monitor_thread.start()


def stop_monitor():
    global _monitor_active
    _monitor_active = False
