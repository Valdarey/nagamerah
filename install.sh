#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0.2"
LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT

# Linux check
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "[!] NAGAMERAH hanya mendukung Linux."
    exit 1
fi

# Python version check
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
    echo "[!] Python 3.10 atau lebih baru diperlukan."
    exit 1
fi

# pipx check
if ! command -v pipx >/dev/null 2>&1; then
    echo "[!] pipx tidak ditemukan."
    echo "[+] Install dengan: sudo apt install pipx python3-venv"
    exit 1
fi

# Installation
echo "[*] Installing NAGAMERAH v${VERSION}..."

if pipx install . --force >"$LOG_FILE" 2>&1; then
    clear 2>/dev/null || true

    EXECUTABLE="$(command -v nagamerah || true)"

    cat <<'EOF'

███╗   ██╗ █████╗  ██████╗  █████╗ ███╗   ███╗███████╗██████╗  █████╗ ██╗  ██╗
████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗██║  ██║
██╔██╗ ██║███████║██║  ███╗███████║██╔████╔██║█████╗  ██████╔╝███████║███████║
██║╚██╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║██╔══██║
██║ ╚████║██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝

        Threat Intelligence & IOC Enrichment CLI Tool

EOF

    echo "  [+] Installation completed successfully"
    echo "  [+] Version      : ${VERSION}"
    echo "  [+] Executable  : ${EXECUTABLE:-nagamerah}"
    echo
    echo "  Run 'nagamerah --help' to get started."
    echo
else
    echo
    echo "[!] Installation failed."
    echo "[!] Error details:"
    cat "$LOG_FILE"
    exit 1
fi
