"""Общий контекст интерфейса и мост между потоками и циклом событий Flet.

Виджеты, которые нужны сразу нескольким вкладкам (например, кнопка запуска
блокировки процессов отключает переключатель таймера с вкладки «Настройки»),
хранятся здесь как обычные атрибуты. Каждый модуль вкладки создаёт свои
контролы и вешает нужные наружу ссылки на этот объект в конце своей функции
``build(ctx)``.

Про потоки. Flet выполняет синхронные обработчики событий ПРЯМО в цикле
asyncio, а не в отдельном потоке. Из этого два следствия, определяющие весь
остальной код интерфейса:

  * блокировать обработчик нельзя — встанет всё приложение, поэтому долгие
    операции (hosts, реестр, subprocess, sleep) уходят в ``run_bg``;
  * менять контролы из чужого потока напрямую тоже нельзя — очередь отправки
    сообщений клиенту живёт в цикле событий, поэтому вызовы возвращаются в него
    через ``ui`` и ``later``.

``ui`` и ``later`` — прямая замена ``root.after(0, ...)`` и ``root.after(ms, ...)``
из версии на CustomTkinter.
"""
import asyncio


class AppContext:
    def __init__(self, page):
        self.page = page
        self._refresh_failure_reported = False

    # ---------- Мост в цикл событий ----------

    def ui(self, callback, *args):
        """Выполняет callback в цикле событий Flet. Безопасно из любого потока."""

        async def runner():
            callback(*args)

        try:
            self.page.run_task(runner)
        except Exception:
            pass

    def later(self, milliseconds, callback, *args):
        """Выполняет callback через заданную задержку в цикле событий Flet."""

        async def runner():
            await asyncio.sleep(milliseconds / 1000)
            callback(*args)

        try:
            self.page.run_task(runner)
        except Exception:
            pass

    def run_bg(self, callback, *args):
        """Уносит блокирующую работу в поток, чтобы не вставал цикл событий."""
        try:
            self.page.run_thread(callback, *args)
        except Exception:
            pass

    def run_async(self, coroutine_function, *args):
        """Запускает корутину в цикле событий (нужно для async-методов Flet)."""
        try:
            self.page.run_task(coroutine_function, *args)
        except Exception:
            pass

    # ---------- Обновление интерфейса ----------

    def refresh(self, *controls):
        """Отправляет клиенту изменения контролов (или всей страницы)."""
        if controls:
            # Ошибку по отдельному контролу глушим: он мог быть уже снят со
            # страницы — при перерисовке списков это норма.
            for control in controls:
                try:
                    control.update()
                except Exception:
                    continue
            return

        try:
            self.page.update()
        except Exception as error:
            self._report_refresh_failure(error)

    def _report_refresh_failure(self, error):
        """Пишет в лог первый сбой отправки страницы.

        Молчать здесь нельзя: отправка страницы падает целиком, если хотя бы
        один контрол не упаковывается (так было с ``selected={...}`` у
        сегментированной кнопки — множества упаковщик Flet не умеет). Внешне это
        выглядит как «раздел не переключается», и без записи в лог причину
        приходится искать наугад.

        Сообщаем один раз за сеанс: сбой повторяется на каждом обновлении и
        забил бы всю панель логов.
        """
        if self._refresh_failure_reported:
            return
        self._refresh_failure_reported = True
        from appcore.i18n import t
        from appcore.logging_util import log

        log(t("log_ui_refresh_failed", error=error))
