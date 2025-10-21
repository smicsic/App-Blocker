import psutil
import tkinter as tk
import threading
import time
import pyfiglet

text = "Hello Robocode !"
font = "slant"
banner = pyfiglet.figlet_format(text, font = font)

smics = pyfiglet.figlet_format("by smics_play", font = "slant")

PROCESS_NAME = ""
monitor_thread = None
monitoring_active = False


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
        # новые дополнения
        "conhost.exe", "ctfmon.exe", "dwm.exe", "fontdrvhost.exe",
        "fsnotifier.exe", "full-line-inference.exe", "ipf_helper.exe",
        "ipf_uf.exe", "ipfsvc.exe", "jhi_service.exe", "msedgewebview2.exe",
        "powershell.exe", "pycharm64.exe", "python.exe", "sihost.exe",
        "spoolsv.exe", "taskhostw.exe", "unsecapp.exe", "MoUsoCoreWorker.exe", "ApplicationFrameHost.exe"
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


# Обновление логов в окне
def log(message):
    text_log.insert(tk.END, f"{message}\n")
    text_log.see(tk.END)


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
    global PROCESS_NAME, monitor_thread, monitoring_active

    # 1. Получаем ввод из поля
    input_name = entry_process.get().strip().lower()

    if not input_name:
        log("❗ Введите название процесса, прежде чем начать.")
        return

    if monitoring_active and input_name == PROCESS_NAME:
        log(f"⚠️ Мониторинг процесса '{PROCESS_NAME}' уже активен.")
        return

    if monitoring_active and input_name != PROCESS_NAME:
        log(f"🔄 Изменение процесса на '{input_name}'. Перезапуск мониторинга.")
        # Останавливать старый поток не нужно, он использует PROCESS_NAME

    # 2. Обновляем глобальную переменную и заголовок
    PROCESS_NAME = input_name
    root.title(f"Blocker для: {PROCESS_NAME}")

    # 3. Запускаем поток, если он еще не запущен
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_process, daemon=True)
        monitor_thread.start()
        log(f"🚀 Мониторинг процесса '{PROCESS_NAME}' запущен.")
    else:
        # Если поток уже запущен, он автоматически подхватит новое значение PROCESS_NAME
        log(f"✅ Мониторинг продолжен для процесса '{PROCESS_NAME}'.")

    # Деактивируем поле ввода и кнопку после запуска (опционально)
    entry_process.config(state=tk.DISABLED)
    button_start.config(state=tk.DISABLED)


# Обработка закрытия окна
def on_close():
    log("❗ Нажат крестик, но окно не будет закрыто.")


# ----------------- Интерфейс -----------------

root = tk.Tk()
root.title("App Blocker")
root.geometry("900x700")
root.resizable(False, False)

# 1. Фрейм для ввода
frame_input = tk.Frame(root)
frame_input.pack(padx=10, pady=(10, 5), fill='x')

# Лейбл
label_process = tk.Label(frame_input, text="Название процесса (например, chrome.exe):")
label_process.pack(side=tk.LEFT)

# Поле ввода
entry_process = tk.Entry(frame_input, width=20)
entry_process.pack(side=tk.LEFT, padx=5, expand=True, fill='x')
# entry_process.insert(0, "chrome.exe") # Можно добавить значение по умолчанию

# Кнопка "Начать"
button_start = tk.Button(frame_input, text="Начать", command=start_monitoring)
button_start.pack(side=tk.LEFT)

# Текстовый лог
text_log = tk.Text(root, wrap="word", height=15, bg="black", fg="lime", font=("Courier New", 10))
text_log.pack(padx=10, pady=5, fill='both', expand=True)

# Текстовое поле для вывода
text_box = tk.Text(root, wrap="word", height=6, bg="black", fg="lime", font=("Courier New", 10))
text_box.pack(padx=10, pady=5, fill='both', expand=True)

def refresh_process_list():
    text_box.delete('1.0', tk.END)  # очищаем поле
    text_box.insert(tk.END, smics)
    text_box.insert(tk.END, "🔍 Активные не системные процессы:\n\n")
    processes = get_user_processes()
    for name in processes:
        text_box.insert(tk.END, f" {name}\n")
    text_box.insert(tk.END, f"\n✅ Всего процессов которые можно мониторить: {len(processes)}")
    log("🔄 Список процессов обновлен.")

button_refresh = tk.Button(frame_input, text="Обновить процессы", command=refresh_process_list)
button_refresh.pack(side=tk.LEFT, padx=5)

# Перехват крестика
root.protocol("WM_DELETE_WINDOW", on_close)

# Запуск GUI
log(banner)
log("Введите название процесса и нажмите 'Начать'.")
refresh_process_list()
root.mainloop()