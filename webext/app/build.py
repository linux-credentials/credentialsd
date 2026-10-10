#!/usr/bin/env python3

from pathlib import Path
import shutil
import sys
import zipapp


source_dir = sys.argv[1]
private_dir = sys.argv[2]
output_name = sys.argv[3]
files = [Path(x).resolve() for x in sys.argv[4:]]

for f in files:
    shutil.copy2(f, private_dir)


def is_source_file(path: Path):
    path.resolve() in files


zipapp.create_archive(
    private_dir, target=output_name, interpreter="/usr/bin/env python3"
)
