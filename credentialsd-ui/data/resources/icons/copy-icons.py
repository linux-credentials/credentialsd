#!/usr/bin/python3
from pathlib import Path
import shutil
import sys


src_dir = Path(sys.argv[1])
build_dir = Path(sys.argv[2])
paths = [Path(p) for p in sys.argv[3:]]

for p in paths:
    rel_path = p.relative_to(src_dir)
    target = build_dir / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, target)

# Touch the file to update modification time
(build_dir / "icons-copied").touch()
