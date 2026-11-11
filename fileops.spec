# -*- mode: python ; coding: utf-8 -*-
a = Analysis(['fileops.py'], pathex=[], binaries=[], datas=[], hiddenimports=[], hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False, optimize=0)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='fileops', debug=False, bootloader_ignore_signals=False, strip=False, upx=False, console=True)
