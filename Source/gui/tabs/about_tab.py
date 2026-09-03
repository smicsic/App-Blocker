"""Вкладка «О программе»: статичное описание и версия."""
from appcore.i18n import register_retranslate, t
from gui.common import scroll_column, sunken_box, text


def build(ctx):
    about_body = text(t("about_body"), size=13, selectable=True)
    about_frame = sunken_box(scroll_column([about_body]), expand=True, padding=18)

    def retranslate_about():
        about_body.value = t("about_body")
        ctx.refresh(about_body)

    register_retranslate(retranslate_about)

    ctx.about_frame = about_frame
    return about_frame
