from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    """Run the repository's top-level `generate_protobuf.py` using the same Python interpreter.

    This helper makes it easy to expose a Poetry console script without importing
    the generator as a module (which may execute code at import time).
    """
    # project root is four levels up from this file: generate_cli.py -> tools -> sliver -> src
    root = Path(__file__).resolve().parents[3]
    script = root / "generate_protobuf.py"
    if not script.exists():
        print(f"generate_protobuf.py not found at {script}", file=sys.stderr)
        return 2

    cmd = [sys.executable, str(script)]
    try:
        return subprocess.run(cmd, check=True).returncode
    except subprocess.CalledProcessError as e:
        return e.returncode


if __name__ == "__main__":
    raise SystemExit(main())
