# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_all

spec_dir = os.path.dirname(os.path.abspath(globals().get('__file__', 'AppBlocker.spec')))
if not os.path.exists(os.path.join(spec_dir, 'AppBlocker.py')):
    spec_dir = os.getcwd()
if not os.path.exists(os.path.join(spec_dir, 'AppBlocker.py')):
    spec_dir = os.path.abspath(SPECPATH)


def asset_path(*parts):
    return os.path.join(spec_dir, *parts)


datas = []
datas += [(asset_path('..', 'Program', 'icon.ico'), '.')]
datas += [(asset_path('Huninn-Regular.ttf'), '.')]
binaries = []
hiddenimports = []
tmp_ret = collect_all('psutil')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('pystray')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('websockets')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
# Flet собирает контролы по имени класса через реестр, поэтому импорты модулей
# контролов PyInstaller в коде не видит — забираем пакеты целиком.
tmp_ret = collect_all('flet')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('flet_desktop')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

# ---------------------------------------------------------------------------
# Клиент Flet (flet.exe и его DLL, ~100 МБ) в пакет flet-desktop НЕ входит: при
# первом запуске тот скачивает его с GitHub в %USERPROFILE%\.flet. Для готовой
# программы это неприемлемо — App Blocker стартует при входе в Windows и
# перезапускается AppBlockerGuard, то есть может подниматься без интернета.
#
# Поэтому клиент кладётся ПАПКОЙ РЯДОМ с AppBlocker.exe (см. README и
# appcore.paths.find_flet_client_dir), а не внутрь exe: один файл на 100 МБ
# пришлось бы распаковывать в temp при каждом запуске.
#
# BUNDLE_FLET_CLIENT=1 включает встраивание клиента в exe — вариант для
# «одного файла», если раздавать папку неудобно.
# ---------------------------------------------------------------------------
if os.environ.get('BUNDLE_FLET_CLIENT') == '1':
    import flet_desktop
    from flet_desktop import ensure_client_cached

    client_dir = os.path.join(str(ensure_client_cached()), 'flet')
    if not os.path.isdir(client_dir):
        raise SystemExit(f'Клиент Flet не найден: {client_dir}')
    datas += [(client_dir, 'flet')]


a = Analysis(
    ['AppBlocker.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Интерфейс переехал на Flet: если tkinter останется в сборке, он только
        # утяжелит её на несколько мегабайт.
        'tkinter',
        'customtkinter',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AppBlocker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=[asset_path('..', 'Program', 'icon.ico')],
    uac_admin=True,
)
