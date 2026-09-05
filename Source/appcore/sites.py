"""Блокировка сайтов через файл hosts."""
import json
import os
import re
import subprocess

import psutil

from appcore.admin import is_admin
from appcore.i18n import t
from appcore.logging_util import log
from appcore.paths import CONFIG_PATH, HOSTS_PATH, BLOCK_MARKER, CREATE_NO_WINDOW


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


SITE_HOST_ALIASES = {
    "youtube.com": [
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "studio.youtube.com",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com",
        "youtu.be",
        "www.youtu.be",
        "ytimg.com",
        "www.ytimg.com",
        "i.ytimg.com",
        "s.ytimg.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "googlevideo.com",
        "www.googlevideo.com",
    ],
    "youtu.be": [
        "youtu.be",
        "www.youtu.be",
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "youtube-nocookie.com",
        "www.youtube-nocookie.com",
        "ytimg.com",
        "www.ytimg.com",
        "i.ytimg.com",
        "s.ytimg.com",
        "youtubei.googleapis.com",
        "youtube.googleapis.com",
        "googlevideo.com",
        "www.googlevideo.com",
    ],
}

BROWSER_PROCESS_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "opera_gx.exe",
    "browser.exe",
    "yandex.exe",
}


def expand_site_hosts(site):
    site = normalize_site(site)
    if not site:
        return []
    aliases = SITE_HOST_ALIASES.get(site, [site, f"www.{site}"])
    expanded = []
    for host in aliases:
        host = normalize_site(host)
        if host and host not in expanded:
            expanded.append(host)
    return expanded


def hosts_entries_for_site(site):
    hosts = expand_site_hosts(site)
    entries = []
    for host in hosts:
        entries.append(f"0.0.0.0 {host} {BLOCK_MARKER}: {site}\n")
        entries.append(f"127.0.0.1 {host} {BLOCK_MARKER}: {site}\n")
        entries.append(f"::1 {host} {BLOCK_MARKER}: {site}\n")
    return entries


def restart_browsers_for_site_block():
    closed = []
    for proc in psutil.process_iter(["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name in BROWSER_PROCESS_NAMES:
                proc.terminate()
                closed.append(name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not closed:
        return
    try:
        gone, alive = psutil.wait_procs(
            [p for p in psutil.process_iter(["name"]) if (p.info.get("name") or "").lower() in BROWSER_PROCESS_NAMES],
            timeout=1.5
        )
        for proc in alive:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except Exception:
        pass
    closed_names = ", ".join(sorted(set(closed)))
    log(t("log_browsers_closed", names=closed_names))


def load_blocked_sites():
    """Загружает список сайтов из config.json"""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
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
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except Exception:
            data = {}
    else:
        data = {}
    data["blocked_sites"] = sites
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def apply_hosts_block(sites):
    sites = normalize_sites(sites)
    try:
        if not is_admin():
            log(t("log_hosts_no_admin"))
            return False

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

        for command in (
            ["ipconfig", "/flushdns"],
            ["powershell", "-NoProfile", "-Command", "Clear-DnsClientCache"],
        ):
            try:
                subprocess.run(
                    command,
                    creationflags=CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=8
                )
            except Exception:
                pass

        with open(HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        missing = []
        for site in sites:
            expected_hosts = expand_site_hosts(site)
            found_site = any(
                f"0.0.0.0 {host} " in content
                or f"127.0.0.1 {host} " in content
                or f"::1 {host} " in content
                for host in expected_hosts
            )
            if not found_site:
                missing.append(site)
        if missing:
            log(t("log_hosts_missing_sites", sites=", ".join(missing)))
            return False
        if not sites and BLOCK_MARKER in content:
            log(t("log_hosts_old_entries_remain"))
            return False

        if sites:
            expanded_count = sum(len(expand_site_hosts(site)) for site in sites)
            log(t("log_hosts_applied", rules=len(sites), domains=expanded_count))
            # Для статистики: hosts-блокировка не даёт «попыток захода», поэтому
            # фиксируем сам факт применения блокировки к домену.
            from appcore.stats import record_site_events
            record_site_events(sites, action="blocked")
        else:
            log(t("log_hosts_cleared"))
        return True

    except PermissionError:
        log(t("log_hosts_no_admin2"))
        return False
    except Exception as e:
        log(t("log_hosts_block_error", error=e))
        return False
