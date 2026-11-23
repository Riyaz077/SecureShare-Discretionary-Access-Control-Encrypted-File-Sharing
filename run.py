"""Convenience launcher for the Streamlit app on Windows, macOS and Linux."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
raise SystemExit(subprocess.call([
    sys.executable, "-m", "streamlit", "run", str(ROOT / "app.py"),
], cwd=ROOT))
