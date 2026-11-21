#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != Linux ]]; then echo "NAGAMERAH hanya mendukung Linux." >&2; exit 1; fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python >=3.10 required"' || exit 1
if command -v pipx >/dev/null; then pipx install . --force; else echo "pipx tidak ditemukan. Install: sudo apt install pipx python3-venv"; exit 1; fi
echo "NAGAMERAH installed. Run: nagamerah --help"
