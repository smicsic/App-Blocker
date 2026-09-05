"""Точка входа App Blocker.

Интерфейс построен на Flet. Вся логика разложена по пакетам:
  - ``appcore``  — состояние, конфиг, процессы, сайты, защита, жизненный цикл (без GUI)
  - ``gui``      — окно, диалоги и вкладки интерфейса (``gui/shell.py`` — каркас окна,
                   ``gui/tabs/`` — по файлу на каждую вкладку)
"""
import sys

# В собранном windowed-exe stdout/stderr привязаны к кодовой странице консоли
# (например, cp1251), а не к UTF-8 — print() с эмодзи в логах (их в коде много)
# роняет процесс с UnicodeEncodeError ещё до того, как откроется окно. errors=
# "replace" делает то же самое вырождение, что и обычный терминал с неполным
# шрифтом: нечитаемый символ, а не падение всего приложения.
for _stream in (sys.stdout, sys.stderr):
    if _stream is not None and hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except Exception:
            pass

from gui.bootstrap import run

if __name__ == "__main__":
    run()
