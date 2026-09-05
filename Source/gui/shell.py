"""Каркас интерфейса: окно, топбар, боковая навигация, панель логов, роутинг.

Строит оболочку приложения и подключает к ней вкладки из ``gui/tabs``.

Заметная разница с версией на CustomTkinter: почти весь код оформления оттуда
исчез. Подложку-градиент рисует ``ft.LinearGradient`` вместо картинки, собранной
через PIL; подсветку кнопок под курсором — сам Flet вместо покадровой анимации
цвета на канве; раскрытие боковой панели — ``animate`` на ширине контейнера
вместо ручного таймера. Заодно пропала подгонка цвета скруглённых углов под
пиксели фона: Flet рисует прозрачность честно, поэтому подбирать нечего.
"""
import flet as ft

from appcore import logging_util, state
from appcore.i18n import get_language, register_retranslate, set_language, t
from appcore.logging_util import log
from appcore.lifecycle import exit_app, on_close, start_tray_icon
from appcore.paths import LOG_PATH, find_font_path, find_icon_path
from appcore.theme import (
    APP_BG,
    APP_FONT_FAMILY,
    APP_FONT_FILE,
    BACKDROP_TOP,
    BORDER_COLOR,
    BORDER_WIDTH,
    CARD_HOVER,
    CARD_RADIUS,
    ERROR,
    FONT_FAMILY,
    MONO_FONT_FAMILY,
    PANEL_BG,
    PRIMARY,
    SECONDARY_BG,
    SIDEBAR_BG,
    TEXT_MAIN,
    TEXT_MUTED,
)
from gui.animations import spotlight_surface
from gui.common import card, secondary_button, stretch_column, sunken_box, text, title
from gui.context import AppContext
from gui.tabs import about_tab, monitor_tab, remote_admin_tab, schedule_tab, settings_tab, sites_tab, stats_tab

NAV_COLLAPSED_WIDTH = 64
NAV_EXPANDED_WIDTH = 205
LOGS_PANEL_WIDTH = 360
# Сколько строк держим в панели логов. Список растёт всё время работы программы,
# а перерисовка контролов дороже, чем строк в текстовом поле Tk.
LOG_LINES_LIMIT = 500

# Иконки пунктов навигации: в свёрнутой панели шириной 64 пикселя подписи не
# влезают. В версии на Tk здесь были эмодзи со отдельным шрифтом — Flet рисует
# иконки Material сам.
NAV_ITEMS = (
    ("monitor", "nav_monitor", ft.Icons.SHIELD_OUTLINED, "monitor_title"),
    ("sites", "nav_sites", ft.Icons.LANGUAGE, "sites_title"),
    ("schedule", "nav_schedule", ft.Icons.CALENDAR_MONTH_OUTLINED, "schedule_title"),
    ("stats", "nav_stats", ft.Icons.INSIGHTS_OUTLINED, "stats_title"),
    ("settings", "nav_settings", ft.Icons.SETTINGS_OUTLINED, "settings_title"),
    ("remote_admin", "nav_remote_admin", ft.Icons.ADMIN_PANEL_SETTINGS_OUTLINED, "remote_admin_title"),
    ("about", "nav_about", ft.Icons.INFO_OUTLINE, "about_title"),
)


def build_main_window(page):
    """Собирает окно и возвращает готовый ``AppContext``."""
    from appcore.lifecycle import ensure_single_instance
    import sys

    if not ensure_single_instance():
        sys.exit(0)

    ctx = AppContext(page)

    # ---------- Окно ----------
    page.title = "App Blocker"
    page.bgcolor = APP_BG
    page.padding = 0
    page.theme_mode = ft.ThemeMode.DARK
    page.theme = ft.Theme(font_family=FONT_FAMILY)
    page.window.width = 1220
    page.window.height = 720
    page.window.min_width = 900
    page.window.min_height = 600
    # Крестик не закрывает программу, а прячет её в трей, поэтому системное
    # закрытие перехватываем и обрабатываем сами.
    page.window.prevent_close = True

    icon_path = find_icon_path()
    if icon_path:
        page.window.icon = icon_path

    # Фирменный шрифт регистрируем, если файл нашёлся: вернуть его можно одной
    # строкой в appcore/theme.py (FONT_FAMILY = APP_FONT_FAMILY).
    font_path = find_font_path(APP_FONT_FILE)
    if font_path:
        page.fonts = {APP_FONT_FAMILY: font_path}

    # Диалог выбора файла и буфер обмена — сервисы страницы, а не вызовы
    # библиотеки: их нужно один раз зарегистрировать и потом переиспользовать.
    file_picker = ft.FilePicker()
    page.services.append(file_picker)
    ctx.file_picker = file_picker

    # ---------- Топбар ----------
    def language_button_text():
        """Кнопка всегда подписана «Language», а рядом — текущий язык."""
        return f"{t('language_button')}: {get_language().upper()}"

    def language_items():
        current = get_language()
        return [
            ft.PopupMenuItem(
                content=text(f"{'✓ ' if code == current else '   '}{t(key)}", size=13),
                on_click=lambda e, c=code: switch_language(c),
            )
            for code, key in (("ru", "language_ru"), ("en", "language_en"))
        ]

    def switch_language(code):
        set_language(code)
        language_btn.content = text(language_button_text(), size=13, bold=True)
        language_btn.items = language_items()
        ctx.refresh(language_btn)

    language_btn = ft.PopupMenuButton(
        content=ft.Container(
            content=text(language_button_text(), size=13, bold=True),
            bgcolor=SECONDARY_BG,
            border_radius=4,
            padding=ft.Padding.symmetric(vertical=9, horizontal=14),
        ),
        items=language_items(),
        bgcolor=PANEL_BG,
        tooltip=None,
    )

    button_refresh = secondary_button(t("btn_refresh_processes"),
                                      lambda e: ctx.refresh_process_list(), width=190)
    # Нейтральная кнопка, краснеющая при наведении: постоянное красное пятно
    # в правом верхнем углу перетягивает внимание с основного действия.
    button_exit = ft.Button(
        t("btn_exit"),
        on_click=lambda e: exit_app(ctx),
        width=110,
        height=36,
        style=ft.ButtonStyle(
            bgcolor={ft.ControlState.DEFAULT: SECONDARY_BG, ft.ControlState.HOVERED: ERROR},
            color=TEXT_MAIN,
            shape=ft.RoundedRectangleBorder(radius=4),
            text_style=ft.TextStyle(size=13, weight=ft.FontWeight.BOLD, font_family=FONT_FAMILY),
            elevation=0,
        ),
    )

    topbar = ft.Row(
        [button_refresh, language_btn, button_exit],
        alignment=ft.MainAxisAlignment.END,
        spacing=8,
    )

    # ---------- Боковая навигация ----------
    # Панель начинает свёрнутой, поэтому и заголовок сразу сокращённый: полное
    # «APP BLOCKER» в 64 пикселя не влезает и переносится в четыре строки.
    nav_title_label = text("AB", size=15, bold=True, no_wrap=True)
    nav_state = {"expanded": False, "active": "monitor"}
    nav_labels = {}
    nav_icons = {}
    nav_markers = {}
    nav_rows = {}

    def make_nav_item(frame_name, label_key, icon):
        """Пункт навигации: тонкая акцентная полоса слева, иконка и подпись.

        Полоса — отдельный узкий контейнер: у активного пункта она синяя, у
        остальных совпадает с фоном панели и потому не видна. Так активный
        раздел выделен светлой подложкой и полосой, а не залит целиком синим —
        иначе акцентный цвет становится самым крупным пятном в окне.

        Под курсором пункт светится тем же кругом, что и карточки: раньше здесь
        была плоская смена подложки, и дока отличалась от остального окна.
        """
        marker = ft.Container(width=3, height=38, bgcolor=SIDEBAR_BG, border_radius=2)
        icon_control = ft.Icon(icon, size=20, color=TEXT_MUTED)
        label = text(t(label_key), size=14, color=TEXT_MUTED, no_wrap=True, visible=False)

        detector, surface = spotlight_surface(
            ft.Row(
                [marker, icon_control, label],
                spacing=12,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            SIDEBAR_BG,
            border_radius=4,
            padding=ft.Padding.only(right=8),
            height=42,
            on_click=lambda e: show_frame(frame_name),
        )

        nav_labels[frame_name] = label
        nav_icons[frame_name] = icon_control
        nav_markers[frame_name] = marker
        # Наружу отдаём внутренний контейнер: именно у него меняется подложка
        # при смене активного раздела, а подсветка берёт базовый цвет оттуда же.
        nav_rows[frame_name] = surface
        return detector

    nav_items = [make_nav_item(name, label_key, icon) for name, label_key, icon, _ in NAV_ITEMS]

    nav_panel = ft.Container(
        content=ft.Column(
            [ft.Container(content=nav_title_label, padding=ft.Padding.only(left=14, top=10, right=0, bottom=10))] + nav_items,
            spacing=2,
        ),
        width=NAV_COLLAPSED_WIDTH,
        bgcolor=SIDEBAR_BG,
        border=ft.Border.all(BORDER_WIDTH, BORDER_COLOR),
        border_radius=CARD_RADIUS,
        padding=ft.Padding.symmetric(vertical=14, horizontal=8),
        animate=ft.Animation(140, ft.AnimationCurve.EASE_OUT),
        on_hover=lambda e: set_nav_expanded(e.data == "true"),
    )

    def set_nav_expanded(expanded):
        """Раскрывает панель под курсором.

        Подписи появляются вместе с шириной: в 64 пикселя они не помещаются и
        обрезались бы. Заголовок в свёрнутом виде сокращён до «AB».
        """
        if expanded == nav_state["expanded"]:
            return
        nav_state["expanded"] = expanded
        nav_panel.width = NAV_EXPANDED_WIDTH if expanded else NAV_COLLAPSED_WIDTH
        nav_title_label.value = t("nav_title") if expanded else "AB"
        for label in nav_labels.values():
            label.visible = expanded
        ctx.refresh(nav_panel)

    # Наружу — чтобы состояние доки можно было задать не только мышью.
    ctx.nav_set_expanded = set_nav_expanded

    def update_nav_state(active_frame):
        """Активный раздел — светлая подложка, белый текст и синяя полоса слева."""
        nav_state["active"] = active_frame
        for frame_name, _, _, _ in NAV_ITEMS:
            is_active = frame_name == active_frame
            nav_rows[frame_name].bgcolor = CARD_HOVER if is_active else SIDEBAR_BG
            nav_markers[frame_name].bgcolor = PRIMARY if is_active else SIDEBAR_BG
            nav_icons[frame_name].color = TEXT_MAIN if is_active else TEXT_MUTED
            nav_labels[frame_name].color = TEXT_MAIN if is_active else TEXT_MUTED
            nav_labels[frame_name].weight = (
                ft.FontWeight.BOLD if is_active else ft.FontWeight.NORMAL
            )
        ctx.refresh(nav_panel)

    # ---------- Вкладки ----------
    frames = {
        "monitor": monitor_tab.build(ctx),
        "sites": sites_tab.build(ctx),
        "schedule": schedule_tab.build(ctx),
        "stats": stats_tab.build(ctx),
        "settings": settings_tab.build(ctx),
        "remote_admin": remote_admin_tab.build(ctx),
        "about": about_tab.build(ctx),
    }
    frame_titles = {name: title_key for name, _, _, title_key in NAV_ITEMS}

    content_title = title(t(frame_titles["monitor"]))
    # Смена раздела с растворением: без него содержимое подменяется рывком, что
    # особенно заметно на вкладках разной высоты. AnimatedSwitcher сам держит
    # старый контрол на время перехода.
    content_body = ft.AnimatedSwitcher(
        content=frames["monitor"],
        transition=ft.AnimatedSwitcherTransition.FADE,
        duration=180,
        reverse_duration=120,
        switch_in_curve=ft.AnimationCurve.EASE_OUT,
        switch_out_curve=ft.AnimationCurve.EASE_IN,
        expand=True,
    )
    content_area = card(
        stretch_column([content_title, content_body], spacing=16, expand=True),
        padding=ft.Padding.symmetric(vertical=20, horizontal=26),
        expand=True,
    )

    # ---------- Панель логов ----------
    logs_title_label = text(t("logs_title"), size=16, bold=True)
    clear_logs_btn = secondary_button(t("logs_clear_btn"), lambda e: clear_logs(),
                                      width=110, height=30, size=12)
    log_view = ft.ListView(spacing=2, auto_scroll=True, expand=True, padding=8)

    def log_line(content):
        return ft.Text(
            content.rstrip("\n"),
            size=12,
            color=TEXT_MAIN,
            font_family=MONO_FONT_FAMILY,
            selectable=True,
        )

    log_view.controls.append(log_line(t("logs_ready")))

    logs_panel = ft.Container(
        content=stretch_column(
            [
                ft.Row([logs_title_label, clear_logs_btn],
                       alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                sunken_box(log_view, expand=True, padding=0),
            ],
            spacing=10,
            expand=True,
        ),
        width=LOGS_PANEL_WIDTH,
        bgcolor=PANEL_BG,
        border=ft.Border.all(BORDER_WIDTH, BORDER_COLOR),
        border_radius=CARD_RADIUS,
        padding=ft.Padding.symmetric(vertical=16, horizontal=14),
    )

    def append_log_line(content):
        log_view.controls.append(log_line(content))
        if len(log_view.controls) > LOG_LINES_LIMIT:
            del log_view.controls[:-LOG_LINES_LIMIT]
        ctx.refresh(log_view)

    def _log_ui_sink(content):
        # log() зовут потоки мониторинга, расписания и защиты — возвращаемся в
        # цикл событий, менять контролы из чужого потока нельзя.
        ctx.ui(append_log_line, content)

    logging_util.set_ui_sink(_log_ui_sink)

    def clear_logs():
        # Сначала файл, потом список: если запись не удалась, сообщение об ошибке
        # добавится в уже очищенный список, а не будет им затёрто.
        file_cleared = logging_util.clear_log_file()
        log_view.controls.clear()
        log_view.controls.append(log_line(t("logs_cleared")))
        ctx.refresh(log_view)
        if not file_cleared:
            log(t("log_log_file_clear_failed", path=LOG_PATH))

    ctx.clear_logs = clear_logs

    # ---------- Переключение вкладок ----------
    def show_frame(frame_name):
        """Переключение между разделами интерфейса."""
        content_title.value = t(frame_titles[frame_name])
        content_body.content = frames[frame_name]
        # Панель логов нужна только на «Мониторинге»: там она показывает, что
        # делает блокировка прямо сейчас. На остальных вкладках она бы просто
        # отнимала треть окна у содержимого.
        logs_panel.visible = frame_name == "monitor"

        if frame_name == "sites":
            ctx.refresh_sites_list()
        elif frame_name == "schedule":
            ctx.refresh_schedule_status()
        elif frame_name == "stats":
            # Перечитываем stats.json при каждом открытии: события пишет поток
            # мониторинга, и на экране должны быть свежие цифры.
            ctx.refresh_stats()

        update_nav_state(frame_name)
        ctx.refresh()

    ctx.show_frame = show_frame

    # ---------- Сборка окна ----------
    body = ft.Row(
        [nav_panel, content_area, logs_panel],
        spacing=12,
        expand=True,
        vertical_alignment=ft.CrossAxisAlignment.STRETCH,
    )

    page.add(
        ft.Container(
            content=ft.Column([topbar, body], spacing=12, expand=True),
            expand=True,
            padding=ft.Padding.symmetric(vertical=14, horizontal=16),
            # Подложка почти плоская: сверху чуть светлее, к низу темнее. Это
            # даёт ощущение глубины, но не превращается в «обои» — цветные пятна
            # в тёмном интерфейсе сразу читаются как дешёвые.
            gradient=ft.LinearGradient(
                begin=ft.Alignment.TOP_CENTER,
                end=ft.Alignment.BOTTOM_CENTER,
                colors=[BACKDROP_TOP, APP_BG],
            ),
        )
    )

    update_nav_state("monitor")

    # ---------- Служебные операции окна ----------
    def set_window_title(value):
        page.title = value
        ctx.refresh()

    def lock_controls_after_start():
        """Запирает всё, чем можно ослабить уже запущенную блокировку."""
        ctx.lock_timer_controls()
        ctx.lock_mode_selectors()
        ctx.secure_switch.disabled = True
        remove_site_btn = getattr(ctx, "remove_site_btn", None)
        if remove_site_btn is not None:
            remove_site_btn.disabled = True
        ctx.refresh(ctx.secure_switch)
        if remove_site_btn is not None:
            ctx.refresh(remove_site_btn)

    ctx.set_window_title = set_window_title
    ctx.lock_controls_after_start = lock_controls_after_start

    def on_window_event(event):
        if event.type == ft.WindowEventType.CLOSE:
            on_close(ctx)

    page.window.on_event = on_window_event

    # ---------- Мягкая блокировка ----------
    def request_postpone_dialog(names, allowed_names):
        """Вызывается из потока мониторинга — переводим показ в цикл событий."""
        from appcore import postpone
        from gui.dialogs import show_postpone_dialog

        def show():
            try:
                show_postpone_dialog(
                    ctx,
                    names,
                    allowed_names,
                    state.POSTPONE_SECONDS,
                    on_resolve=lambda action: ctx.run_bg(postpone.resolve, action),
                    still_running=postpone.targets_still_running,
                )
            except Exception as e:
                # Иначе флаг «диалог открыт» остался бы висеть навсегда и мягкая
                # блокировка больше никогда не сработала бы.
                ctx.run_bg(postpone.resolve, postpone.ACTION_CLOSE_NOW)
                log(t("log_postpone_failed", error=e))

        ctx.ui(show)

    from appcore import postpone as _postpone
    _postpone.set_request_handler(request_postpone_dialog)

    start_tray_icon(ctx, on_exit=lambda: exit_app(ctx))

    def retranslate_shell():
        button_exit.content = t("btn_exit")
        button_refresh.content = t("btn_refresh_processes")
        language_btn.content = ft.Container(
            content=text(language_button_text(), size=13, bold=True),
            bgcolor=SECONDARY_BG,
            border_radius=4,
            padding=ft.Padding.symmetric(vertical=9, horizontal=14),
        )
        language_btn.items = language_items()
        nav_title_label.value = t("nav_title") if nav_state["expanded"] else "AB"
        for frame_name, label_key, _, _ in NAV_ITEMS:
            nav_labels[frame_name].value = t(label_key)
        content_title.value = t(frame_titles[nav_state["active"]])
        logs_title_label.value = t("logs_title")
        clear_logs_btn.content = t("logs_clear_btn")
        ctx.refresh()

    register_retranslate(retranslate_shell)

    ctx.refresh()
    return ctx
