"""Анимации интерфейса: подсветка под курсором и влёт строк списка.

В версии на CustomTkinter обе анимации приходилось считать покадрово, и обе
упирались в ограничения Tk:

* Круг подсветки под курсором был **недостижим**: CTkButton рисует надпись
  отдельным непрозрачным ``tkinter.Label``, и любой градиент на канве
  оказывался закрыт прямоугольником вокруг текста. Приходилось светлеть кнопкой
  целиком, меняя ``fg_color`` вручную 60 раз в секунду.
* Влёт строки слева тоже был **недостижим**: ``pack`` не умеет отрицательных
  смещений, вынести строку за левый край нельзя. Обход через сжатие ширины
  оставлял на экране пиксели прежних кадров — Tk не перерисовывал освобождённую
  область, а надёжно чинила это только синхронная перерисовка, из-за которой
  приложение зависало.

Flet рисует через Flutter, поэтому здесь описывается только конечное состояние,
а промежуточные кадры считает движок: ни таймеров, ни ручной интерполяции
цвета, ни борьбы с остаточными пикселями. Отсюда же пропала подгонка скорости
кадра — плавность обеспечивает движок, а не подобранные замером константы.
"""
import flet as ft

from appcore.theme import BUTTON_RADIUS

# ---------- Подсветка под курсором ----------
# Радиус круга в долях размера контрола: 0.6 даёт мягкое пятно примерно на две
# трети кнопки, а не резкий диск.
SPOTLIGHT_RADIUS = 0.6
# Насколько центр круга светлее основного цвета. Значение заметное намеренно:
# на почти чёрном фоне слабая подсветка не читается вовсе.
SPOTLIGHT_LIGHTEN = 0.42
SPOTLIGHT_DURATION = 90

# Троттлинг события наведения, миллисекунды. Задаётся Flutter-стороне через
# hover_interval, поэтому лишние события НЕ доходят до Python и не идут по
# сокету вообще. Фильтровать их уже в обработчике почти бесполезно: сообщение к
# этому моменту принято и разобрано, а именно на этом и уходило процессорное
# время — при быстром движении мыши событий больше сотни в секунду.
# 50 мс = 20 кадров в секунду: для мягкого пятна света глаз разницы не видит.
SPOTLIGHT_HOVER_INTERVAL_MS = 50
# Порог смещения центра, ниже которого перерисовку не запрашиваем. Работает уже
# после троттлинга и отсекает дрожание мыши на месте.
SPOTLIGHT_MIN_SHIFT = 0.05
# Троттлинг события изменения размера. По умолчанию во Flet 10 мс — при
# растягивании окна это событие от каждой карточки сто раз в секунду.
SPOTLIGHT_SIZE_INTERVAL_MS = 200

# ---------- Влёт строк ----------
# Стартовое смещение в долях ширины строки: -0.35 = левее своего места на треть.
FLY_IN_OFFSET = -0.35
FLY_IN_DURATION = 260
# Задержка соседних строк друг за другом — даёт «каскад», а не общий рывок.
FLY_IN_STAGGER_MS = 28
# Предел задержки: при двадцати строках без ограничения последняя ждала бы
# больше половины секунды.
FLY_IN_MAX_DELAY_MS = 260


def hex_to_rgb(value):
    value = str(value).lstrip("#")
    if len(value) != 6:
        return None
    try:
        return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))
    except ValueError:
        return None


def rgb_to_hex(rgb):
    return "#{:02x}{:02x}{:02x}".format(*(max(0, min(255, int(round(c)))) for c in rgb))


def lighten(color, amount):
    """Смешивает цвет с белым: 0 — без изменений, 1 — белый."""
    rgb = hex_to_rgb(color)
    if rgb is None:
        return color
    return rgb_to_hex(tuple(c + (255 - c) * amount for c in rgb))


# Цвет подсветки считается разбором и сборкой hex-строки. Базовых цветов всего
# несколько на всё приложение, а событий наведения — десятки в секунду, поэтому
# результат запоминаем.
_GLOW_CACHE = {}


def glow_color_for(base_color):
    cached = _GLOW_CACHE.get(base_color)
    if cached is None:
        cached = lighten(base_color, SPOTLIGHT_LIGHTEN)
        _GLOW_CACHE[base_color] = cached
    return cached


def spotlight_surface(
    content,
    base_color,
    glow_color=None,
    border=None,
    border_radius=BUTTON_RADIUS,
    padding=None,
    on_click=None,
    expand=False,
    width=None,
    height=None,
    tooltip=None,
):
    """Поверхность, под курсором которой светится круг.

    Круг — ``RadialGradient``, центр которого переставляется по событию наведения.
    ``GestureDetector`` берётся потому, что ``on_hover`` у ``Container`` сообщает
    только вход и выход, а нам нужно непрерывное движение мыши.

    Размер контрола узнаём из ``on_size_change``: центр градиента задаётся в
    долях (-1..1), а событие наведения приносит пиксели, и без размера одно в
    другое не перевести. У растягивающихся карточек ширина заранее неизвестна.

    Возвращает пару ``(внешний контрол, внутренний контейнер)`` — внутренний
    нужен вызывающему, чтобы менять цвет или содержимое.
    """
    glow = glow_color if glow_color is not None else lighten(base_color, SPOTLIGHT_LIGHTEN)
    size = {"width": 0, "height": 0}
    last_center = {"x": None, "y": None}

    surface = ft.Container(
        content=content,
        bgcolor=base_color,
        border=border,
        border_radius=border_radius,
        padding=padding,
        expand=expand,
        width=width,
        height=height,
        tooltip=tooltip,
        on_click=on_click,
        animate=ft.Animation(SPOTLIGHT_DURATION, ft.AnimationCurve.EASE_OUT),
    )

    def paint(center_x, center_y):
        # Базовый цвет читаем из самого контейнера, а не из замыкания: у пунктов
        # навигации подложка меняется при смене активного раздела, и жёстко
        # запомненный цвет вернул бы кнопку к прежнему виду после наведения.
        base = surface.bgcolor or base_color
        surface.gradient = ft.RadialGradient(
            center=ft.Alignment(center_x, center_y),
            radius=SPOTLIGHT_RADIUS,
            colors=[glow if glow_color is not None else glow_color_for(base), base],
            stops=[0.0, 1.0],
        )

    def clear():
        surface.gradient = None

    def on_size_change(event):
        size["width"] = event.width or 0
        size["height"] = event.height or 0

    def _push():
        # Контрол может быть уже снят со страницы (списки пересобираются) —
        # тогда отправка просто не нужна.
        try:
            surface.update()
        except Exception:
            pass

    def on_hover(event):
        position = getattr(event, "local_position", None)
        if position is None or not size["width"] or not size["height"]:
            # Размер ещё не пришёл — светим ровно по центру: без размера доли
            # посчитать не из чего, а это лучше, чем ничего.
            center_x, center_y = 0.0, 0.0
        else:
            # Пиксели -> доли (-1..1): левый край = -1, центр = 0, правый = 1.
            center_x = max(-1.0, min(1.0, position.x / size["width"] * 2 - 1))
            center_y = max(-1.0, min(1.0, position.y / size["height"] * 2 - 1))

        # on_hover приходит на каждое движение мыши. Без этого порога на каждый
        # пиксель уходило бы сообщение клиенту, а глаз разницы всё равно не видит.
        if last_center["x"] is not None:
            if (abs(center_x - last_center["x"]) < SPOTLIGHT_MIN_SHIFT
                    and abs(center_y - last_center["y"]) < SPOTLIGHT_MIN_SHIFT):
                return
        last_center["x"], last_center["y"] = center_x, center_y
        paint(center_x, center_y)
        _push()

    def on_exit(event=None):
        last_center["x"] = last_center["y"] = None
        clear()
        _push()

    detector = ft.GestureDetector(
        content=surface,
        on_hover=on_hover,
        on_exit=on_exit,
        on_size_change=on_size_change,
        hover_interval=SPOTLIGHT_HOVER_INTERVAL_MS,
        # По умолчанию 10 мс: при растягивании окна каждая карточка присылала бы
        # событие сто раз в секунду, а размер нам нужен изредка.
        size_change_interval=SPOTLIGHT_SIZE_INTERVAL_MS,
        mouse_cursor=ft.MouseCursor.CLICK if on_click is not None else None,
        expand=expand,
    )
    return detector, surface


def fly_in(control, index=0, offset=FLY_IN_OFFSET, duration=FLY_IN_DURATION):
    """Готовит контрол к влёту слева: сдвигает и делает прозрачным.

    Само движение запускает ``launch_fly_in`` — Flet анимирует переход между
    двумя состояниями, поэтому сначала нужно показать контрол сдвинутым, а
    вернуть на место уже следующим сообщением.
    """
    control.offset = ft.Offset(offset, 0)
    control.opacity = 0
    control.animate_offset = ft.Animation(duration, ft.AnimationCurve.EASE_OUT)
    control.animate_opacity = ft.Animation(duration, ft.AnimationCurve.EASE_OUT)
    return min(FLY_IN_MAX_DELAY_MS, index * FLY_IN_STAGGER_MS)


def launch_fly_in(ctx, delayed_controls):
    """Возвращает подготовленные контролы на место — они влетают слева направо.

    ``delayed_controls`` — пары ``(задержка, контрол)``; задержка даёт каскад.
    Перевод в цикл событий обязателен: смену состояния клиент должен получить
    ОТДЕЛЬНЫМ сообщением, иначе он увидит только конечное положение и анимации
    не будет.
    """
    for delay, control in delayed_controls:
        # Нижняя граница не ради каскада, а ради порядка сообщений: клиент должен
        # успеть получить сдвинутое состояние, иначе увидит сразу конечное.
        ctx.later(max(20, delay), _settle, ctx, control)


def _settle(ctx, control):
    control.offset = ft.Offset(0, 0)
    control.opacity = 1
    ctx.refresh(control)


def fly_in_rows(ctx, rows):
    """Готовит и запускает влёт для списка строк одним вызовом."""
    delayed = []
    for index, row in enumerate(rows):
        # Заглушки вроде «список пуст» — это ft.Text, у него нет offset.
        if isinstance(row, ft.Container):
            delayed.append((fly_in(row, index=index), row))
    if delayed:
        launch_fly_in(ctx, delayed)
    return rows
