# ruff: noqa: F821
from PyInstaller.utils.hooks import collect_dynamic_libs

datas = []
binaries = []
for package in ("pkcs11", "cryptography"):
    binaries += collect_dynamic_libs(package)

hiddenimports = [
    "simplysign_pdf_validator",
    "pyhanko.pdf_utils.font.opentype",
    "pyhanko.pdf_utils.incremental_writer",
    "pyhanko.pdf_utils.reader",
    "pyhanko.sign.fields",
    "pyhanko.sign.pkcs11",
    "pyhanko.sign.signers",
    "pyhanko.sign.timestamps",
    "pyhanko.sign.validation",
    "pyhanko.sign.validation.status",
    "pyhanko_certvalidator",
    "pkcs11",
    "cryptography",
    "fontTools",
    "uharfbuzz",
]

EXCLUDED_MODULES = (
    "pyhanko.__main__",
    "pyhanko.cli",
    "click",
    "platformdirs",
    "yaml",
    "PIL",
    "barcode",
)

a = Analysis(
    ["simplysign_pdf_signer.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=list(EXCLUDED_MODULES),
    noarchive=False,
    optimize=2,
)
if any(
    module == prefix or module.startswith(f"{prefix}.")
    for module, *_ in a.pure
    for prefix in EXCLUDED_MODULES
):
    raise RuntimeError("production_helper_dependency_surface_invalid")

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SimplySignPdfSigner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=True,
)
