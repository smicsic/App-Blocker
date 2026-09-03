"""Фабрики контролов Flet в оформлении приложения.

В версии на CustomTkinter каждый виджет создавался, а потом ещё раз
настраивался через ``configure(fg_color=..., hover_color=..., font=...)`` — это
и давало по три строки на кнопку. Здесь стиль задаётся один раз в фабрике,
поэтому вкладки описывают только структуру и текст.

Заодно отсюда пропали помощники, которые в Tk были обязательными, а во Flet не
нужны: вставка из буфера по Ctrl+V (TextField умеет сама), подбор цвета
скруглённых углов под фоновую картинку (Flet рисует прозрачность честно) и
удержание модального окна поверх родителя (этим занимается page.show_dialog).
"""
import flet as ft

from appcore.theme import (
    BORDER_COLOR,
    BORDER_WIDTH,
    BUTTON_RADIUS,
    CARD_BG,
    CARD_RADIUS,
    DISABLED_BG,
    ERROR,
    ERROR_HOVER,
    FONT_FAMILY,
    INPUT_BG,
    MONO_FONT_FAMILY,
    PRIMARY,
    PRIMARY_HOVER,
    SECONDARY_BG,
    SECONDARY_BG_HOVER,
    SECONDARY_HOVER,
    TEXT_MAIN,
    TEXT_MUTED,
)


# ---------- Текст ----------

def text(value, size=13, bold=False, color=TEXT_MAIN, mono=False, **kwargs):
    return ft.Text(
        value,
        size=size,
        weight=ft.FontWeight.BOLD if bold else ft.FontWeight.NORMAL,
        color=color,
        font_family=MONO_FONT_FAMILY if mono else FONT_FAMILY,
        **kwargs,
    )


def title(value, size=22):
    return text(value, size=size, bold=True)


def caption(value, size=12):
    """Приглушённая подпись над значением — как в карточках статуса."""
    return text(value, size=size, bold=True, color=TEXT_MUTED)


# Предельная ширина абзаца пояснения. В версии на CustomTkinter то же ограничение
# задавалось через wraplength=620: карточка занимает всю ширину окна, и без
# ограничения строка растягивается на весь экран, а такую длину глаз уже не держит.
DESCRIPTION_WIDTH = 760


def description(value):
    """Пояснение под заголовком карточки: мелкое, серое, с переносами."""
    return text(value, size=12, color=TEXT_MUTED, width=DESCRIPTION_WIDTH)


# ---------- Поверхности ----------

def card(content, padding=None, expand=False, bgcolor=CARD_BG, **kwargs):
    """Карточка: фон, тонкая рамка, мягкое скругление."""
    return ft.Container(
        content=content,
        bgcolor=bgcolor,
        border=ft.Border.all(BORDER_WIDTH, BORDER_COLOR),
        border_radius=CARD_RADIUS,
        padding=padding if padding is not None else ft.Padding.symmetric(vertical=18, horizontal=22),
        expand=expand,
        **kwargs,
    )


def row_surface(content, **kwargs):
    """Строка списка: чуть светлее подложки, с рамкой и малым скруглением."""
    from appcore.theme import ROW_BG

    return ft.Container(
        content=content,
        bgcolor=ROW_BG,
        border=ft.Border.all(BORDER_WIDTH, BORDER_COLOR),
        border_radius=BUTTON_RADIUS,
        padding=ft.Padding.symmetric(vertical=7, horizontal=12),
        **kwargs,
    )


def sunken_box(content, height=None, expand=False, padding=8):
    """«Вдавленная» область под списки: темнее карточки, без рамки."""
    return ft.Container(
        content=content,
        bgcolor=INPUT_BG,
        border_radius=BUTTON_RADIUS,
        padding=padding,
        height=height,
        expand=expand,
    )


def scroll_column(controls=None, spacing=10, expand=True, **kwargs):
    """Прокручиваемая колонка — замена CTkScrollableFrame.

    Дети растягиваются на всю ширину: в списках это строки, а по умолчанию Flet
    сжимает контрол до размера содержимого, и строка из одного слова получалась
    узкой полоской вместо ряда во всю ширину.
    """
    kwargs.setdefault("horizontal_alignment", ft.CrossAxisAlignment.STRETCH)
    return ft.Column(
        controls=controls if controls is not None else [],
        scroll=ft.ScrollMode.AUTO,
        spacing=spacing,
        expand=expand,
        **kwargs,
    )


def stretch_column(controls, spacing=8, expand=False, **kwargs):
    """Колонка, дети которой занимают всю ширину (заголовок + область списка)."""
    return ft.Column(
        controls=controls,
        spacing=spacing,
        expand=expand,
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
        **kwargs,
    )


# ---------- Кнопки ----------

def _button_style(bgcolor, hover_color, color=TEXT_MAIN, size=13):
    return ft.ButtonStyle(
        bgcolor={
            ft.ControlState.DEFAULT: bgcolor,
            ft.ControlState.HOVERED: hover_color,
            ft.ControlState.DISABLED: DISABLED_BG,
        },
        color={
            ft.ControlState.DEFAULT: color,
            ft.ControlState.DISABLED: TEXT_MUTED,
        },
        shape=ft.RoundedRectangleBorder(radius=BUTTON_RADIUS),
        text_style=ft.TextStyle(size=size, weight=ft.FontWeight.BOLD, font_family=FONT_FAMILY),
        elevation=0,
        padding=ft.Padding.symmetric(vertical=0, horizontal=16),
    )


def primary_button(label, on_click, width=None, height=36, size=13, **kwargs):
    """Основное действие: акцентный синий."""
    return ft.Button(
        label,
        on_click=on_click,
        width=width,
        height=height,
        style=_button_style(PRIMARY, SECONDARY_HOVER, size=size),
        **kwargs,
    )


def secondary_button(label, on_click, width=None, height=36, size=13, **kwargs):
    """Второстепенное действие: нейтральная серая кнопка."""
    return ft.Button(
        label,
        on_click=on_click,
        width=width,
        height=height,
        style=_button_style(SECONDARY_BG, SECONDARY_BG_HOVER, size=size),
        **kwargs,
    )


def danger_button(label, on_click, width=None, height=36, size=13, **kwargs):
    """Разрушающее действие: спокойная кнопка, краснеющая при наведении.

    Постоянно красная кнопка в списке или в углу окна перетягивает внимание с
    основного действия, поэтому красный включается только под курсором.
    """
    return ft.Button(
        label,
        on_click=on_click,
        width=width,
        height=height,
        style=_button_style(SECONDARY_BG, ERROR, size=size),
        **kwargs,
    )


def solid_danger_button(label, on_click, width=None, height=36, size=13, **kwargs):
    """Красная кнопка для отказа в модальном окне, где выбор всего один."""
    return ft.Button(
        label,
        on_click=on_click,
        width=width,
        height=height,
        style=_button_style(ERROR, ERROR_HOVER, size=size),
        **kwargs,
    )


# ---------- Поля ввода и переключатели ----------

def entry(hint=None, width=None, password=False, value="", on_submit=None, **kwargs):
    return ft.TextField(
        value=value,
        hint_text=hint,
        hint_style=ft.TextStyle(color=TEXT_MUTED, size=13, font_family=FONT_FAMILY),
        width=width,
        height=40,
        password=password,
        can_reveal_password=password,
        on_submit=on_submit,
        bgcolor=INPUT_BG,
        color=TEXT_MAIN,
        border_color=BORDER_COLOR,
        focused_border_color=PRIMARY,
        border_radius=BUTTON_RADIUS,
        border_width=BORDER_WIDTH,
        cursor_color=PRIMARY,
        content_padding=ft.Padding.symmetric(vertical=8, horizontal=12),
        text_style=ft.TextStyle(size=14, font_family=FONT_FAMILY),
        **kwargs,
    )


def switch(label, value, on_change, **kwargs):
    return ft.Switch(
        label=label,
        value=value,
        on_change=on_change,
        active_color=PRIMARY,
        thumb_color=PRIMARY_HOVER,
        label_text_style=ft.TextStyle(size=13, color=TEXT_MAIN, font_family=FONT_FAMILY),
        **kwargs,
    )


def segmented(options, selected_value, on_change):
    """Сегментированный переключатель.

    ``options`` — список пар ``(значение, подпись)``. Значения стабильные
    (``"blacklist"``, ``"exact"``), а не подписи: в версии на CustomTkinter
    сегменты опознавались по видимому тексту, и при смене языка приходилось
    пересобирать весь контрол, чтобы сравнения снова совпали.

    Выбор задаём СПИСКОМ, хотя тип поля называется set: упаковщик сообщений Flet
    множества не умеет и роняет отправку страницы целиком (``can not serialize
    'set' object``). Со списком контрол ведёт себя точно так же.
    """
    return ft.SegmentedButton(
        segments=[
            ft.Segment(value=value, label=text(label, size=13, bold=True))
            for value, label in options
        ],
        selected=[selected_value],
        allow_empty_selection=False,
        allow_multiple_selection=False,
        on_change=on_change,
        style=ft.ButtonStyle(
            bgcolor={
                ft.ControlState.DEFAULT: SECONDARY_BG,
                ft.ControlState.SELECTED: PRIMARY,
                ft.ControlState.DISABLED: DISABLED_BG,
            },
            color={
                ft.ControlState.DEFAULT: TEXT_MAIN,
                ft.ControlState.DISABLED: TEXT_MUTED,
            },
            side=ft.BorderSide(BORDER_WIDTH, BORDER_COLOR),
            shape=ft.RoundedRectangleBorder(radius=BUTTON_RADIUS),
        ),
    )


def segmented_selection(event, fallback):
    """Достаёт выбранное значение из события SegmentedButton.

    Flet присылает выбор коллекцией (переключатель умеет и мультивыбор), а нам
    всегда нужно одно значение — ``fallback`` страхует от пустого выбора.
    """
    selected = getattr(event.control, "selected", None) or set()
    for value in selected:
        return value
    return fallback


# ---------- Составные блоки ----------

def status_row(caption_text, value_text=""):
    """Строка «подпись — значение». Возвращает обе метки: подпись нужна для
    перевода на месте, значение — для обновления статуса."""
    caption_label = text(caption_text, size=13, bold=True)
    value_label = text(value_text, size=13, color=TEXT_MUTED)
    row = ft.Row(
        [caption_label, value_label],
        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
    )
    return row, caption_label, value_label


def spotlight_card(content, padding=None, expand=False, base_color=CARD_BG):
    """Карточка, под курсором которой светится круг.

    Внешне это обычная карточка, но фон рисуется радиальным градиентом с центром
    в позиции мыши. Подробности и причины — в ``gui/animations.py``.

    Возвращает только внешний контрол: содержимое карточки вызывающий уже держит
    в руках, а внутренний контейнер ему не нужен.
    """
    from gui.animations import spotlight_surface

    detector, _surface = spotlight_surface(
        content,
        base_color,
        border=ft.Border.all(BORDER_WIDTH, BORDER_COLOR),
        border_radius=CARD_RADIUS,
        padding=padding if padding is not None else ft.Padding.symmetric(vertical=18, horizontal=22),
        expand=expand,
    )
    return detector


def stat_card(caption_text, value_text="—", expand=True):
    """Карточка-показатель: приглушённая подпись сверху, крупное значение снизу."""
    caption_label = caption(caption_text)
    value_label = text(value_text, size=21, bold=True, color=PRIMARY)
    container = spotlight_card(
        ft.Column([caption_label, value_label], spacing=2, tight=True),
        padding=ft.Padding.symmetric(vertical=14, horizontal=18),
        expand=expand,
    )
    return container, caption_label, value_label


def tab_page(title_text, body, scrollable_body=False):
    """Каркас вкладки: заголовок сверху, содержимое под ним.

    Возвращает пару ``(контейнер, заголовок)`` — заголовок нужен вкладкам для
    перевода при смене языка.
    """
    title_label = title(title_text)
    content = body if not scrollable_body else scroll_column([body])
    return card(
        ft.Column(
            [title_label, content],
            spacing=16,
            expand=True,
        ),
        padding=ft.Padding.symmetric(vertical=22, horizontal=30),
        expand=True,
    ), title_label
