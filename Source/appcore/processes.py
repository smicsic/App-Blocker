"""Работа со списком процессов и мониторинг заблокированных программ."""
import os
import time

import psutil

from appcore import state
from appcore.i18n import t
from appcore.logging_util import log


def normalize_process_name(name):
    return name.strip().lower()


# ==================== Защита от завершения критичных процессов ====================
# Отдельный «никогда не завершать» список. Он нужен именно для whitelist-режима:
# там мы завершаем всё, что НЕ выбрал пользователь, поэтому список системного
# должен быть надёжным, а не косметическим фильтром для списка процессов в UI
# (тот список — get_user_processes() — заточен под конкретную машину и для
# решений об убийстве процессов не годится).
def _lower_names(names):
    """Приводит набор имён к нижнему регистру.

    Сравнение всегда идёт с normalize_process_name(), то есть по нижнему
    регистру. Запись в другом регистре не совпала бы никогда. Приводим набор
    один раз при загрузке, чтобы регистр перестал иметь значение.
    """
    return frozenset(name.lower() for name in names)


CRITICAL_PROCESS_NAMES = _lower_names({
    # Ядро ОС и вход в систему
    "systemd", "systemd-logind", "systemd-journald", "systemd-udevd",
    "systemd-resolved", "systemd-networkd", "systemd-oomd", "init", "kthreadd",
    "dbus-daemon", "dbus-broker", "polkitd", "udisksd", "upowerd", "rtkit-daemon",
    "logind", "accounts-daemon",
    # Графическая сессия: без этого пользователь останется без рабочего стола
    "xorg", "x", "xwayland", "gdm", "gdm3", "sddm", "lightdm", "lightdm-gtk-greeter",
    "gnome-shell", "gnome-session-binary", "gnome-session", "plasmashell",
    "kwin_x11", "kwin_wayland", "kwin", "sway", "swaybg", "hyprland", "weston",
    "xfwm4", "xfce4-session", "xfdesktop", "lxqt-session", "mate-session",
    "cinnamon", "cinnamon-session",
    # Системные шины и оборудование
    "networkmanager", "network-manager", "wpa_supplicant", "networkd-dispatcher",
    "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber", "bluetoothd",
    # Само приложение и его защита. flet — окно приложения: клиент Flet
    # запускается ДОЧЕРНИМ процессом, а _self_process_names() обходит только
    # родителей, поэтому сам он под защиту не попадает и нужен здесь по имени.
    # Без этого whitelist-режим закрыл бы собственное окно программы.
    "appblocker", "appblockerguard", "python3", "python", "flet",
})


def _self_process_names():
    """Имена текущего процесса и его родителей.

    Нужно, чтобы whitelist-режим не завершил сам App Blocker: при запуске из
    исходников это python3, при запуске из сборки — appblocker, а родителем
    может быть IDE или терминал, из которого приложение запущено.
    """
    names = set()
    try:
        current = psutil.Process(os.getpid())
        names.add(normalize_process_name(current.name()))
        for parent in current.parents():
            try:
                names.add(normalize_process_name(parent.name()))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return names


_SELF_PROCESS_NAMES = _self_process_names()


def _current_username():
    """Имя владельца текущего процесса или None, если определить не удалось."""
    try:
        return psutil.Process(os.getpid()).username()
    except Exception:
        return None


_CURRENT_USERNAME = _current_username()


def is_protected_process(process_name):
    """True, если процесс нельзя завершать ни при каких настройках.

    Защищаем объединение трёх наборов: критичное для системы, сам App Blocker с
    родителями и всё, что не показывается в списке активных процессов. Последнее
    даёт инвариант «не предлагаем блокировать — не завершаем»; перезащитить
    процесс безопасно, недозащитить — нет.
    """
    process_name = normalize_process_name(process_name)
    if not process_name:
        return True
    if (
        process_name in CRITICAL_PROCESS_NAMES
        or process_name in _SELF_PROCESS_NAMES
        or process_name in NON_USER_PROCESS_NAMES
    ):
        return True
    return False


def is_own_user_process(proc):
    """True, если процесс принадлежит текущему пользователю.

    Это структурная замена списку имён: службы работают под SYSTEM /
    LOCAL SERVICE / NETWORK SERVICE, поэтому в whitelist-режиме они отсекаются
    сами, без перечисления их имён. Сравниваем с владельцем своего процесса,
    поэтому проверка не зависит от языка системы.
    """
    if _CURRENT_USERNAME is None:
        return False
    try:
        return proc.username() == _CURRENT_USERNAME
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def sync_primary_process_name():
    state.PROCESS_NAME = state.BLOCKED_PROGRAMS[0] if state.BLOCKED_PROGRAMS else ""


def process_matches_rule(process_name, rule):
    process_name = normalize_process_name(process_name)
    rule = normalize_process_name(rule)
    if not process_name or not rule:
        return False
    if state.MATCH_MODE == "exact":
        return process_name == rule
    return rule in process_name


def _build_non_user_process_names():
    """Имена, которые не показываем в списке «Активные процессы».

    Раньше этот набор жил внутри get_user_processes(). Он вынесен наружу, чтобы
    whitelist-режим мог соблюдать простое правило: **если процесс не предлагается
    пользователю как блокируемый, то мы его и не завершаем**. Иначе два списка
    расходятся, и режим убивает то, что интерфейс даже не показывает.
    """
    from appcore.paths import GUARD_EXE_NAME

    system_names = {
        "system", "idle", "kthreadd", "init",
        "systemd", "systemd-logind", "systemd-journald", "systemd-udevd",
        "systemd-resolved", "systemd-networkd", "systemd-oomd",
        "dbus-daemon", "dbus-broker", "polkitd", "udisksd", "upowerd",
        "rtkit-daemon", "accounts-daemon",
        "gdm", "gdm3", "sddm", "lightdm", "lightdm-gtk-greeter",
        "gnome-shell", "gnome-session-binary", "gnome-session",
        "plasmashell", "kwin_x11", "kwin_wayland", "kwin",
        "sway", "swaybg", "hyprland", "weston",
        "xorg", "x", "xwayland",
        "xfwm4", "xfce4-session", "xfdesktop", "lxqt-session",
        "mate-session", "cinnamon", "cinnamon-session",
        "networkmanager", "network-manager", "wpa_supplicant",
        "networkd-dispatcher", "bluetoothd",
        "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber",
        "cron", "crond", "atd",
        "appblocker", GUARD_EXE_NAME.lower(), "python3", "python",
    }
    return _lower_names(system_names)


NON_USER_PROCESS_NAMES = _build_non_user_process_names()


def get_user_processes():
    """Возвращает список процессов, которые можно предложить заблокировать.

    Фильтр — тот же ``is_protected_process()``, по которому принимается решение о
    завершении. Так инвариант работает в обе стороны: чего нет в списке, то и не
    завершается, а что нельзя завершить — то и не предлагается. Раньше фильтр
    смотрел только NON_USER_PROCESS_NAMES, и защищённые процессы всё равно
    попадали в список с кнопкой «Добавить»: нажатие ничего не давало, а окно
    самого приложения (flet) выглядело так, будто его можно заблокировать.
    """
    processes = []
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
            if name and not is_protected_process(name):
                processes.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(set(processes))


def process_is_allowed(process_name):
    """True, если процесс разрешён в whitelist-режиме (совпал со списком)."""
    return any(process_matches_rule(process_name, program) for program in state.BLOCKED_PROGRAMS)


def should_terminate_process(proc, process_name):
    """Решает, подлежит ли процесс завершению при текущем режиме блокировки.

    Возвращает ``(нужно_завершить, правило)`` — правило попадает в лог и в
    статистику, чтобы было видно, из-за чего процесс закрыли.
    """
    process_name = normalize_process_name(process_name)
    if not process_name:
        return False, None

    if state.BLOCK_MODE == "whitelist":
        # Пустой список разрешённых означал бы «завершить всё пользовательское» —
        # такой режим не запускаем, это защита от случайной блокировки системы.
        if not state.BLOCKED_PROGRAMS:
            return False, None
        # Порядок проверок важен для скорости: сначала дешёвые (поиск в set и
        # сравнение строк), и только для оставшихся кандидатов — is_own_user_process,
        # внутри которого системный вызов разбора SID владельца процесса.
        if is_protected_process(process_name):
            return False, None
        if process_is_allowed(process_name):
            return False, None
        if not is_own_user_process(proc):
            return False, None
        return True, t("block_rule_not_in_whitelist")

    matched_program = next(
        (program for program in state.BLOCKED_PROGRAMS if process_matches_rule(process_name, program)),
        None
    )
    return bool(matched_program), matched_program


def is_app_running():
    """True, если есть хотя бы один процесс, подлежащий завершению."""
    if not state.BLOCKED_PROGRAMS:
        return False

    for proc in psutil.process_iter(["name"]):
        try:
            process_name = (proc.info.get("name") or "").lower()
            should_terminate, _ = should_terminate_process(proc, process_name)
            if should_terminate:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def is_blocked_program_running(program):
    program = normalize_process_name(program)
    for proc in psutil.process_iter(["name"]):
        try:
            process_name = (proc.info.get("name") or "").lower()
            if process_matches_rule(process_name, program):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False


def collect_terminate_targets():
    """Список ``(proc, имя, правило)`` процессов, подлежащих завершению сейчас."""
    targets = []
    for proc in psutil.process_iter(["name"]):
        try:
            process_name_full = proc.info.get("name") or ""
            should_terminate, matched_rule = should_terminate_process(proc, process_name_full)
            if should_terminate:
                targets.append((proc, process_name_full, matched_rule))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return targets


def terminate_targets(targets, record_action="terminated"):
    """Завершает переданные процессы и одной записью пишет статистику."""
    from appcore.stats import record_block_events

    terminated = []
    for proc, process_name_full, matched_rule in targets:
        try:
            proc.terminate()
            log(t("log_process_terminated", name=process_name_full, pid=proc.pid, rule=matched_rule))
            terminated.append((process_name_full, "program", record_action, matched_rule))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    # Одна запись в stats.json на всю итерацию, а не на каждый процесс.
    record_block_events(terminated)


def terminate_now(record_action="terminated"):
    """Пересобирает список процессов и завершает их.

    Отдельная функция нужна мягкой блокировке: между показом диалога и решением
    пользователя проходит до минуты, и держать всё это время объекты
    ``psutil.Process`` нельзя — процесс мог завершиться, а его PID достаться
    совсем другой программе.
    """
    terminate_targets(collect_terminate_targets(), record_action=record_action)


def close_app():
    if not state.BLOCKED_PROGRAMS:
        return

    from appcore import postpone

    targets = collect_terminate_targets()
    if not targets:
        return

    if not postpone.is_enabled():
        terminate_targets(targets)
        return

    # Программы, для которых пользователь нажал «Отменить», не трогаем совсем:
    # ни завершать, ни спрашивать снова до истечения передышки.
    targets = [
        target for target in targets
        if not postpone.is_exempt(normalize_process_name(target[1]))
    ]
    if not targets:
        return

    names = sorted({normalize_process_name(name) for _, name, _ in targets})
    allowed = list(state.BLOCKED_PROGRAMS) if state.BLOCK_MODE == "whitelist" else []
    if postpone.request(names, allowed):
        return  # ждём решения пользователя — сейчас ничего не закрываем
    # Мягкую блокировку применить не удалось — ведём себя как раньше.
    terminate_targets(targets)


def monitor_process(on_tick=None):
    """Фоновый поток проверки заблокированных программ.

    ``on_tick`` вызывается на каждой итерации (используется GUI, чтобы
    обновить список программ через ``ctx.ui``).
    """
    while state.monitoring_active:
        if not state.BLOCKED_PROGRAMS:
            time.sleep(1)  # Ждем, пока процесс будет задан
            continue

        if is_app_running():
            if state.last_monitor_state != "running":
                log(t("log_blocked_program_found"))
            state.last_monitor_state = "running"
            try:
                close_app()
            except Exception as error:
                # Без этого любое исключение убивало бы поток мониторинга без
                # следа: флаг monitoring_active остаётся поднятым, интерфейс
                # показывает «Активен», а блокировки уже нет.
                log(t("log_monitor_iteration_failed", error=error))
        else:
            if state.last_monitor_state != "clear":
                log(t("log_no_blocked_programs_running"))
            state.last_monitor_state = "clear"
        if on_tick is not None:
            try:
                on_tick()
            except Exception:
                pass
        time.sleep(2)
