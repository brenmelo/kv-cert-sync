"""Build the two function packages that the ARM templates deploy.

    deploy/packages/sync/released-package.zip    <- src/sync   (copies certificates into the destination vaults)
    deploy/packages/renew/released-package.zip   <- src/renew  (requests / renews certificates at the CA)

Each package holds only the source of one function app (function_app.py, host.json, requirements.txt and the Python package).
No dependency is bundled: the Functions service installs requirements.txt during a remote build, so the archive is small and the
same on Windows, macOS and Linux.

The archives are reproducible, byte for byte: entries are sorted, timestamps and permissions are fixed, text files use LF line
endings and nothing is compressed. That is what lets CI prove that the committed zip files are exactly what the source produces.

    python scripts/build_packages.py            rebuild the packages
    python scripts/build_packages.py --check    exit 1 if a committed package differs from a fresh build (used by CI)

The file name `released-package.zip` is required by the Flex Consumption "OneDeploy" extension.
"""
import argparse
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FILE = "released-package.zip"
APPS = {"sync": ROOT / "src" / "sync", "renew": ROOT / "src" / "renew"}

SKIP_DIRS = {"__pycache__", ".venv", ".python_packages", "tests", ".pytest_cache"}
SKIP_FILES = {"local.settings.json", ".funcignore"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
TEXT_SUFFIXES = {".py", ".json", ".txt", ".md", ".yml", ".yaml"}

FIXED_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest time a zip entry can carry
FIXED_MODE = 0o100644 << 16  # regular file, rw-r--r--
UNIX = 3


def package_path(app: str) -> Path:
    return ROOT / "deploy" / "packages" / app / PACKAGE_FILE


def source_files(src: Path) -> list[Path]:
    """The files that go into a package, sorted by their posix path."""
    found = []
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        if p.is_dir() or SKIP_DIRS & set(rel.parts) or p.name in SKIP_FILES or p.suffix in SKIP_SUFFIXES:
            continue
        found.append(p)
    return sorted(found, key=lambda p: p.relative_to(src).as_posix())


def build(src: Path) -> bytes:
    """The package for one function app, as bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for p in source_files(src):
            data = p.read_bytes()
            if p.suffix in TEXT_SUFFIXES:
                data = data.replace(b"\r\n", b"\n")  # a Windows checkout must produce the same bytes
            info = zipfile.ZipInfo(p.relative_to(src).as_posix(), date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = UNIX
            info.external_attr = FIXED_MODE
            z.writestr(info, data)
    return buf.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="do not write; fail if a committed package is out of date")
    args = ap.parse_args()

    stale = []
    for app, src in APPS.items():
        out = package_path(app)
        fresh = build(src)
        if args.check:
            ok = out.is_file() and out.read_bytes() == fresh
            print(f"{'ok   ' if ok else 'STALE'} {out.relative_to(ROOT).as_posix()}")
            if not ok:
                stale.append(app)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(fresh)
        with zipfile.ZipFile(out) as z:
            names = z.namelist()
        print(f"{out.relative_to(ROOT).as_posix()}  {len(names)} files  {len(fresh)} bytes")

    if stale:
        print(f"\nOut of date: {', '.join(stale)}. Run: python scripts/build_packages.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
