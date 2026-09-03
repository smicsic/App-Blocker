"""Модальные окна (пароль, инфо, да/нет, мягкая блокировка, защита).

Все диалоги здесь НЕ блокирующие: результат приходит в колбэк, а не возвращается
из функции. В версии на CustomTkinter работало наоборот — ``wait_window()``
запускал вложенный цикл событий и функция возвращала уже готовый ответ.

Так сделано не для красоты, а по устройству Flet: синхронные обработчики
выполняются прямо в цикле asyncio, и ожидание внутри обработчика останавливает
весь обмен с клиентом — окно не отрисуется, а нажать в нём будет нечего.
Поэтому вызывающий код передаёт продолжение: ``on_result(значение)``.
"""
import flet as ft

from appcore import state
from appcore.i18n import t
from appcore.theme import (
    BORDER_COLOR,
    BORDER_WIDTH,
    CARD_BG,
    CARD_RADIUS,
    ERROR,
    MONO_FONT_FAMILY,
    PANEL_BG,
    PRIMARY,
    TEXT_MAIN,
    TEXT_MUTED,
    WARNING,
)
from gui.common import (
    entry,
    primary_button,
    secondary_button,
    solid_danger_button,
    text,
)


def _dialog(title_text, body_controls, action_controls, accent=PRIMARY, on_dismiss=None,
            width=480, scrollable=False):
    """Собирает AlertDialog в оформлении приложения."""
    return ft.AlertDialog(
        modal=True,
        bgcolor=PANEL_BG,
        shape=ft.RoundedRectangleBorder(radius=CARD_RADIUS),
        title=text(title_text, size=20, bold=True, color=accent),
        content=ft.Container(
            content=ft.Column(body_controls, spacing=14, tight=True),
            width=width,
        ),
        actions=action_controls,
        actions_alignment=ft.MainAxisAlignment.CENTER,
        actions_padding=ft.Padding.only(left=0, top=0, right=0, bottom=20),
        content_padding=ft.Padding.symmetric(vertical=10, horizontal=24),
        title_padding=ft.Padding.only(left=24, top=22, right=24, bottom=6),
        scrollable=scrollable,
        on_dismiss=on_dismiss,
    )


def _close(ctx, dialog):
    """Закрывает конкретное окно. Повторный вызов безвреден.

    Сбой закрытия не глушим: если окно останется на экране, следующее ляжет
    поверх него, и приложение окажется наглухо закрыто модальными окнами.
    Внешне это выглядит как «программа перестала работать», а без записи в лог
    причину пришлось бы искать наугад.
    """
    try:
        if getattr(dialog, "open", False) or dialog.page is not None:
            ctx.page.pop_dialog()
    except Exception as error:
        from appcore.logging_util import log

        log(t("log_dialog_close_failed", error=error))
        # Пробуем закрыть напрямую: страница могла потерять окно из стека.
        try:
            dialog.open = False
            ctx.refresh(dialog)
        except Exception:
            pass


def _resolve_once(callback):
    """Гарантирует единственный вызов колбэка.

    К результату ведут несколько путей — кнопки, клавиши, закрытие окна,
    истёкший отсчёт — и все они не должны срабатывать дважды.
    """
    done = {"value": False}

    def resolve(*args):
        if done["value"]:
            return
        done["value"] = True
        if callback is not None:
            callback(*args)

    return resolve


def password_dialog(ctx, title_text, message, on_result):
    """Запрашивает пароль. ``on_result(пароль)`` либо ``on_result(None)`` при отмене."""
    resolve = _resolve_once(on_result)
    password_field = entry(hint=t("dialog_password_hint"), password=True, width=320, autofocus=True)

    def submit(event=None):
        value = password_field.value or ""
        _close(ctx, dialog)
        resolve(value)

    def cancel(event=None):
        _close(ctx, dialog)
        resolve(None)

    password_field.on_submit = submit

    dialog = _dialog(
        title_text,
        [
            text(message, size=14, text_align=ft.TextAlign.CENTER),
            ft.Row([password_field], alignment=ft.MainAxisAlignment.CENTER),
        ],
        [
            primary_button(t("dialog_ok"), submit, width=130, height=38),
            solid_danger_button(t("dialog_cancel"), cancel, width=130, height=38),
        ],
        # Закрытие окна мимо кнопок — это отмена, иначе вызывающий код никогда
        # не получит ответ и стартовая последовательность встанет.
        on_dismiss=lambda event: resolve(None),
    )
    ctx.page.show_dialog(dialog)


def info_dialog(ctx, title_text, message, accent=PRIMARY, on_close=None):
    """Сообщение с одной кнопкой. ``on_close`` вызывается после закрытия."""
    resolve = _resolve_once(on_close)

    def close(event=None):
        _close(ctx, dialog)
        resolve()

    dialog = _dialog(
        title_text,
        [text(message, size=14, selectable=True)],
        [primary_button(t("dialog_continue"), close, width=160, height=38)],
        accent=accent,
        on_dismiss=lambda event: resolve(),
        width=520,
    )
    ctx.page.show_dialog(dialog)


def error_dialog(ctx, message, on_close=None):
    """Замена ``messagebox.showerror`` из версии на Tk."""
    info_dialog(ctx, t("dialog_error_title"), message, accent=ERROR, on_close=on_close)


def yes_no_dialog(ctx, title_text, message, on_result):
    """Вопрос с двумя ответами. ``on_result(True|False)``."""
    resolve = _resolve_once(on_result)

    def confirm(event=None):
        _close(ctx, dialog)
        resolve(True)

    def cancel(event=None):
        _close(ctx, dialog)
        resolve(False)

    dialog = _dialog(
        title_text,
        [text(message, size=14, text_align=ft.TextAlign.CENTER)],
        [
            primary_button(t("dialog_yes"), confirm, width=140, height=40),
            secondary_button(t("dialog_no"), cancel, width=140, height=40),
        ],
        on_dismiss=lambda event: resolve(False),
    )
    ctx.page.show_dialog(dialog)


def postpone_message_text(names, allowed_names):
    """Текст окна мягкой блокировки — зависит от режима блокировки."""
    if state.BLOCK_MODE == "whitelist":
        return t("postpone_message_whitelist", allowed=", ".join(allowed_names) or "—")
    if len(names) == 1:
        return t("postpone_message_one", program=names[0])
    return t("postpone_message_many", programs=", ".join(names))


def show_postpone_dialog(ctx, names, allowed_names, seconds, on_resolve, still_running):
    """Окно с обратным отсчётом перед закрытием программ.

    ``still_running`` — функция без аргументов: если она вернёт False, значит
    программу закрыли сами и окно надо убрать без лишних действий.

    Отсчёт идёт через ``ctx.later``, то есть в цикле событий Flet, — так же, как
    раньше через ``dialog.after``. Обновления списков и логов, которые поток
    мониторинга присылает всё это время, продолжают приходить.
    """
    from appcore.postpone import (
        ACTION_CANCEL,
        ACTION_CLOSE_NOW,
        ACTION_PROCESS_GONE,
        ACTION_TIMEOUT,
    )

    resolve = _resolve_once(on_resolve)
    remaining = {"seconds": int(seconds)}
    # Признак закрытия держим сами. Полагаться на dialog.page нельзя: после
    # page.pop_dialog() ссылка на страницу остаётся заполненной, и отсчёт
    # продолжал идти после закрытия окна — раз в секунду вызывая still_running(),
    # то есть полный обход процессов, и так до конца минуты на каждое окно.
    closed = {"value": False}
    countdown_label = text(
        t("postpone_countdown", seconds=seconds), size=26, bold=True, color=WARNING,
        text_align=ft.TextAlign.CENTER,
    )

    def finish(action):
        closed["value"] = True
        _close(ctx, dialog)
        resolve(action)

    def on_dismiss(event=None):
        # Окно закрыли мимо кнопок — считаем это отменой и глушим отсчёт.
        closed["value"] = True
        resolve(ACTION_CANCEL)

    def tick():
        if closed["value"]:
            # Окно уже закрыто — сценарий завершён другим путём.
            return
        # Программу могли закрыть вручную — тогда убираем окно молча.
        try:
            if not still_running():
                finish(ACTION_PROCESS_GONE)
                return
        except Exception:
            pass
        remaining["seconds"] -= 1
        if remaining["seconds"] <= 0:
            finish(ACTION_TIMEOUT)
            return
        countdown_label.value = t("postpone_countdown", seconds=remaining["seconds"])
        ctx.refresh(countdown_label)
        ctx.later(1000, tick)

    dialog = _dialog(
        t("postpone_dialog_title"),
        [
            text(
                postpone_message_text(names, allowed_names),
                size=14,
                text_align=ft.TextAlign.CENTER,
            ),
            ft.Row([countdown_label], alignment=ft.MainAxisAlignment.CENTER),
        ],
        [
            primary_button(t("postpone_close_now_btn"), lambda e: finish(ACTION_CLOSE_NOW),
                           width=170, height=40),
            secondary_button(t("postpone_cancel_btn"), lambda e: finish(ACTION_CANCEL),
                             width=170, height=40),
        ],
        # Закрытие мимо кнопок считаем отменой — то же, что нажать «Отменить».
        on_dismiss=on_dismiss,
        width=520,
    )
    ctx.page.show_dialog(dialog)
    ctx.later(1000, tick)
    return dialog


def show_security_disabled_dialog(ctx, on_enable_navigate):
    """Предупреждение о том, что защита выключена, с переходом в настройки."""
    if state.SECURITY_WARNING_DIALOG is not None:
        # Окно уже висит — второе не открываем.
        return

    def enable(event=None):
        state.SECURITY_WARNING_DIALOG = None
        _close(ctx, dialog)
        on_enable_navigate()

    def decline(event=None):
        state.SECURITY_WARNING_DIALOG = None
        _close(ctx, dialog)

    dialog = _dialog(
        t("dialog_security_disabled_heading"),
        [text(t("dialog_security_disabled_message"), size=14, text_align=ft.TextAlign.CENTER)],
        [
            primary_button(t("dialog_enable_btn"), enable, width=160, height=42),
            secondary_button(t("dialog_decline_btn"), decline, width=160, height=42),
        ],
        on_dismiss=lambda event: setattr(state, "SECURITY_WARNING_DIALOG", None),
        width=560,
    )
    state.SECURITY_WARNING_DIALOG = dialog
    ctx.page.show_dialog(dialog)


def show_security_protection_dialog(ctx, on_result):
    """Большое окно про исключения антивируса. ``on_result(True|False)``."""
    from appcore.security import (
        check_antivirus_exception,
        copy_app_folder_path,
        get_app_folder_path,
        open_antivirus_guide,
        open_defender_exclusions_settings,
    )
    from appcore.theme import ACCENT, SUCCESS

    resolve = _resolve_once(on_result)
    app_path = get_app_folder_path()
    status_label = text("", size=13, color=TEXT_MUTED)

    def copy_and_mark(event=None):
        def done(copied):
            if copied:
                status_label.value = t("dialog_path_copied")
                status_label.color = ACCENT
                ctx.refresh(status_label)

        copy_app_folder_path(ctx, on_done=done)

    def check_exclusions(event=None):
        # Опрос Defender идёт через PowerShell — только в фоновом потоке.
        def work():
            found, message = check_antivirus_exception()
            status_label.value = message
            status_label.color = SUCCESS if found else WARNING
            ctx.ui(ctx.refresh, status_label)

        status_label.value = t("settings_status_checking")
        status_label.color = TEXT_MUTED
        ctx.refresh(status_label)
        ctx.run_bg(work)

    def enable(event=None):
        _close(ctx, dialog)
        resolve(True)

    def cancel(event=None):
        _close(ctx, dialog)
        resolve(False)

    dialog = _dialog(
        t("dialog_enable_protection_question"),
        [
            text(t("dialog_protection_message"), size=14),
            text(t("dialog_program_folder_label"), size=13, bold=True, color=TEXT_MUTED),
            ft.Container(
                content=ft.Text(
                    app_path,
                    size=13,
                    color=TEXT_MAIN,
                    font_family=MONO_FONT_FAMILY,
                    selectable=True,
                ),
                bgcolor=CARD_BG,
                border=ft.Border.all(BORDER_WIDTH, BORDER_COLOR),
                border_radius=CARD_RADIUS,
                padding=12,
            ),
            status_label,
            ft.Row(
                [
                    secondary_button(t("settings_copy_path_btn"), copy_and_mark, width=150),
                    secondary_button(t("dialog_open_guide_btn"), open_antivirus_guide, width=160),
                    secondary_button(t("dialog_check_btn"), check_exclusions, width=140),
                    secondary_button(t("settings_open_exclusions_btn"),
                                     open_defender_exclusions_settings, width=180),
                ],
                wrap=True,
                spacing=8,
                run_spacing=8,
            ),
        ],
        [
            primary_button(t("dialog_i_added_enable_btn"), enable, width=200, height=42),
            solid_danger_button(t("dialog_cancel_plain"), cancel, width=150, height=42),
        ],
        on_dismiss=lambda event: resolve(False),
        width=660,
        scrollable=True,
    )
    ctx.page.show_dialog(dialog)
