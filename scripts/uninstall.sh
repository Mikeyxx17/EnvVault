#!/usr/bin/env bash
#
# Remove the installed envvault program. Does not delete source checkouts.
# Optionally purge one project's Vault directory after an explicit phrase.
#
# Never prints Secret Values.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: uninstall.sh [--purge-project <dir>]

  Removes ~/.local/bin/envvault if it is a regular file.
  --purge-project <dir>  also deletes <dir>/.envvault and <dir>/envvault.json
                         after you type "purge". Use only for a throwaway test
                         project. Does not securely erase disk blocks.
EOF
}

PURGE_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --purge-project) PURGE_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "uninstall.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

BIN="${HOME}/.local/bin/envvault"

echo "This will remove:"
if [ -f "$BIN" ] && [ ! -L "$BIN" ]; then
    echo "- program: $BIN"
else
    echo "- no installed envvault binary in ~/.local/bin"
fi
if [ -n "$PURGE_DIR" ]; then
    echo "- project data: $PURGE_DIR/.envvault"
    echo "- project file: $PURGE_DIR/envvault.json"
fi
echo "Source checkouts are not deleted."
echo "If machine unlock was enabled, run 'envvault keystore disable' first while the program still exists."

printf "Type 'uninstall' to confirm: "
read -r phrase
[ "$phrase" = uninstall ] || { echo "confirmation phrase did not match; nothing was deleted" >&2; exit 1; }

if [ -n "$PURGE_DIR" ]; then
    printf "Type 'purge' to delete project Vault files: "
    read -r phrase
    [ "$phrase" = purge ] || { echo "confirmation phrase did not match; nothing was deleted" >&2; exit 1; }
    if [ -L "$PURGE_DIR/.envvault" ] || [ -L "$PURGE_DIR/envvault.json" ]; then
        echo "refusing to delete a symlink" >&2
        exit 2
    fi
    if [ -d "$PURGE_DIR/.envvault" ]; then
        rm -rf "$PURGE_DIR/.envvault"
        echo "removed: $PURGE_DIR/.envvault"
    fi
    if [ -f "$PURGE_DIR/envvault.json" ]; then
        rm -f "$PURGE_DIR/envvault.json"
        echo "removed: $PURGE_DIR/envvault.json"
    fi
fi

if [ -f "$BIN" ] && [ ! -L "$BIN" ]; then
    rm -f "$BIN"
    echo "removed: $BIN"
fi

echo "Uninstall finished"
echo "This is not a secure disk wipe. Backups and filesystem history may remain."
