#!/usr/bin/env python3
"""
notalsonefiler.py
Build a single .pyz archive bundling all notals* and optionally cursedelver* modules,
with embedded build metadata, compression, and a self-contained __main__ entrypoint.
"""

import os
import sys
import zipfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

OUTPUT_PYZ = "notals.pyz"
BUILD_VERSION = "1.2"
BUILD_TIMESTAMP = datetime.utcnow().isoformat() + "Z"

# ------------------------------------------------------------
# Source collection
# ------------------------------------------------------------
def collect_sources():
    """Find all relevant .py files and directories to include."""
    base_dir = Path(".").resolve()
    sources, include_dirs = [], []

    prefixes = ("notals", "cursedelver", "curses")

    # Top-level Python files
    for py_file in base_dir.glob("*.py"):
        if py_file.name.startswith(prefixes):
            sources.append(py_file)

    # Recursive dirs
    for p in base_dir.iterdir():
        if p.is_dir() and p.name.startswith(prefixes):
            include_dirs.append(p.name)

    return sources, include_dirs


def copy_recursive(src_dir, dst_dir):
    """Recursively copy .py files preserving structure."""
    for root, dirs, files in os.walk(src_dir):
        for d in dirs:
            (Path(dst_dir) / Path(root).relative_to(src_dir) / d).mkdir(parents=True, exist_ok=True)
        for f in files:
            if f.endswith(".py"):
                full_src = Path(root) / f
                arc_rel = Path(root).relative_to(src_dir) / f
                dst_file = Path(dst_dir) / arc_rel
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(full_src, dst_file)


# ------------------------------------------------------------
# Build logic
# ------------------------------------------------------------
def build_pyz(output=OUTPUT_PYZ):
    """Build a compressed pyz archive with metadata."""
    sources, include_dirs = collect_sources()
    tempdir = Path(tempfile.mkdtemp())

    try:
        # Copy root .py files
        for src in sources:
            shutil.copy(src, tempdir / src.name)

        # Optional alias shim: let "import notals" resolve even if inside pyz
        #(tempdir / "notals.py").write_text("from notals import *\n")

        # Copy directories
        for d in include_dirs:
            copy_recursive(Path(d), tempdir / d)

        # Write runtime entrypoint
        main_py = tempdir / "__main__.py"
        main_py.write_text(MAIN_PYZ_ENTRYPOINT)

        pyz_path = Path(output).absolute()
        with zipfile.ZipFile(pyz_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(tempdir):
                for f in files:
                    full = Path(root) / f
                    arcname = full.relative_to(tempdir)
                    info = zipfile.ZipInfo(arcname.as_posix())
                    info.date_time = (2020, 1, 1, 0, 0, 0)
                    info.compress_type = zipfile.ZIP_DEFLATED
                    with open(full, "rb") as fh:
                        zf.writestr(info, fh.read())

            # Embed metadata
            meta = f"BUILD_VERSION={BUILD_VERSION}\nBUILD_TIMESTAMP={BUILD_TIMESTAMP}\n"
            zf.writestr("__build_info__.txt", meta.encode("utf-8"))

        os.chmod(pyz_path, os.stat(pyz_path).st_mode | 0o111)
        print(f"✅ Built {pyz_path}")

    finally:
        try:
            ans = input(f"Delete temporary build directory {tempdir}? [y/N]: ").strip().lower()
        except EOFError:
            ans = "n"
        if ans == "y":
            shutil.rmtree(tempdir)
        else:
            print(f"Temporary directory left at: {tempdir}")


# ------------------------------------------------------------
# Embedded runtime for the .pyz
# ------------------------------------------------------------
MAIN_PYZ_ENTRYPOINT = """#!/usr/bin/env python3
\"\"\"Runtime entrypoint for notals.pyz.\"\"\"
import sys, os, json, zipfile, traceback

def usage():
    print("Usage:")
    print("  notals.pyz [directory]       Browse a directory (default: cwd)")
    print("  notals.pyz --delve <file>    Use Delver on a specific file (if bundled)")
    print("  notals.pyz --advertise       Show Delver capabilities (if available)")
    print("  notals.pyz --version         Show build info")
    sys.exit(1)

def print_version():
    try:
        with zipfile.ZipFile(sys.argv[0], 'r') as zf:
            info = zf.read('__build_info__.txt').decode('utf-8', 'ignore')
        print("notals.pyz build info:")
        print(info.strip())
    except Exception as e:
        print("Cannot read build info:", e)
    sys.exit(0)

def try_import_delver():
    try:
        import cursedelvermeta as delver
        return delver
    except ImportError:
        try:
            import cursedelver as delver
            return delver
        except ImportError:
            return None
            
def load_embedded_pyz_delvers():
    here = os.path.dirname(sys.argv[0])
    for name in ("cursedelver.pyz", "cursedelvermeta.pyz"):
        candidate = os.path.join(here, name)
        if os.path.isfile(candidate) and candidate not in sys.path:
            sys.path.insert(0, candidate)


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg in ('--help', '-h', None):
        usage()
    if arg in ('--version', '-V'):
        print_version()

    load_embedded_pyz_delvers()
    delver = try_import_delver()


    if arg == '--advertise':
        if not delver:
            print("Delver not available.")
            sys.exit(1)
        print(json.dumps(delver.advertiseDelveableFileExtensions(as_json=True), indent=2))
        return

    if arg == '--delve' and len(sys.argv) > 2:
        if not delver:
            print("Delver not available.")
            sys.exit(1)
        target = sys.argv[2]
        try:
            delver.delve(target)
        except Exception:
            traceback.print_exc()
            sys.exit(1)
        return

    target = arg or os.getcwd()

    if os.path.isdir(target):
        try:
            import notals
        except ImportError:
            print("notals module missing from archive.")
            sys.exit(1)
        notals.run(target)
        return

    if os.path.isfile(target):
        # Ensure embedded .pyz delvers are loadable
        load_embedded_pyz_delvers()
        delver = try_import_delver()
        if not delver:
            print("Delver not available.")
            sys.exit(1)
        try:
            delver.delve(target)
        except Exception:
            traceback.print_exc()
            sys.exit(1)
        return

    print(f"Path not found: {target}")
    sys.exit(1)

if __name__ == "__main__":
    main()
"""

# ------------------------------------------------------------
# Build trigger
# ------------------------------------------------------------
if __name__ == "__main__":
    build_pyz()

