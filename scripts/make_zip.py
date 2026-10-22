import sys, zipfile, pathlib
src = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2])
skip_dirs = {"__pycache__", ".venv", ".python_packages", "tests"}
skip_files = {"local.settings.json", ".funcignore"}
if out.exists(): out.unlink()
n = 0
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in sorted(src.rglob("*")):
        if p.is_dir() or skip_dirs & set(p.relative_to(src).parts) or p.name in skip_files or p.suffix == ".pyc":
            continue
        z.write(p, p.relative_to(src).as_posix()); n += 1
print(f"{out}  files={n}  size={out.stat().st_size} bytes")
with zipfile.ZipFile(out) as z:
    for i in z.infolist(): print("  ", i.filename)
