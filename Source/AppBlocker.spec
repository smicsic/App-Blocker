# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_all

spec_dir = os.path.dirname(os.path.abspath(globals().get('__file__', 'AppBlocker.spec')))
if not os.path.exists(os.path.join(spec_dir, 'AppBlocker.py')):
    spec_dir = os.getcwd()
if not os.path.exists(os.path.join(spec_dir, 'AppBlocker.py')):
    spec_dir = os.path.dirname(os.path.abspath(SPECPATH))


def asset_path(*parts):
    return os.path.join(spec_dir, *parts)

datas = []
datas += [(asset_path('icon.ico'), '.')]
datas += [(asset_path('Source', 'Huninn-Regular.ttf'), '.')]
datas += [(asset_path('Source', 'background_low.jpg'), '.')]
binaries = []
hiddenimports = []
tmp_ret = collect_all('psutil')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('pyfiglet')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]
tmp_ret = collect_all('pystray')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['AppBlocker.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    icon=['icon.ico'],
)
