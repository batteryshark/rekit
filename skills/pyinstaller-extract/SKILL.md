# PyInstaller Extractor

Carve the Python back out of a **PyInstaller** executable. Pure-stdlib, static,
read-only. The first half of the Python-from-a-binary chain:
`pyinstaller-extract` → `pyc-decompile` → `py-covert-scan`.

## When to use

A suspicious standalone executable that's actually a frozen Python app (PyInstaller
is the most common packer for Python malware). This pulls the bundled `.pyc` modules
out so you can decompile and read them — without running the binary.

## What it does

- Finds the PyInstaller **CArchive** appended to the executable (the `MEI` cookie),
  reads its table of contents, and extracts every entry (modules, data, bundled
  native libs) to the output dir.
- Unpacks the inner **PYZ** archive into individual **`.pyc`** files under
  `PYZ-contents/`, reconstructing each header from the PYZ's embedded magic so a
  decompiler can read them.
- Reports the target **Python version** and entry types.

Static: it parses byte structures and `marshal.loads` the PYZ TOC (that's
*deserialization*, not execution — code objects are never run). It never launches
the executable or imports any extracted module.

## Usage

```bash
skillpack run pyinstaller-extract ./suspicious.exe ./out
# then decompile the recovered modules:
skillpack run pyc-decompile ./out/PYZ-contents/app.pyc ./src
```

Non-PyInstaller input → `{"isPyInstaller": false, "note": "…"}`.

## Prerequisites

- **python3 ≥ 3.8** — pure stdlib, nothing to vendor.

## Note

Decompilation of the recovered `.pyc` is `pyc-decompile`'s job and works best on
CPython 3.7–3.8 targets; newer bytecode extracts fine here but may be out of the
decompiler's range (it will say so).
