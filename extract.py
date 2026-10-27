from pathlib import Path
import shutil
import subprocess
import sys


base_dir = Path(__file__).resolve().parent
archive = base_dir / "baressi site ha.rar"
destination = base_dir / "extracted"
extractor = shutil.which("bsdtar")

if not archive.is_file():
    sys.exit(f"Archive not found: {archive}")

if extractor is None:
    sys.exit("bsdtar is not installed or is not available on PATH.")

destination.mkdir(exist_ok=True)
result = subprocess.run(
    [extractor, "-xf", str(archive), "-C", str(destination)],
    check=False,
)

if result.returncode != 0:
    sys.exit(result.returncode)

print(f"Extracted files to: {destination}")