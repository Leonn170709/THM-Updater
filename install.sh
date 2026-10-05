#!/bin/bash
# Keep custom runtimes and state in a persistent directory owned by this user.
set -euo pipefail
[ "$(id -u)" != 0 ] || { echo 'Run without sudo as the worker owner.' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
updater_dir=${THM_UPDATER_DIR:-"$source_dir/data"}
umask 077
python3 "$source_dir/runtime.py" "$updater_dir"
if [ "$source_dir" != "$(cd -- "$updater_dir" && pwd)" ]; then
    install -m 600 "$source_dir/sync.py" "$updater_dir/sync.py"
fi
printf 'Public key (Base64 DER):\n'
openssl pkey -in "$updater_dir/signing.pem" -pubout -outform DER | base64 -w0
printf '\nRun the worker from its runtime directory: python3 sync.py config.json --watch\n'
