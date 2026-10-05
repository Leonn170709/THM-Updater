# THM Updater

Public source for the build and feed publisher. HTTP serving, authorization and member data remain private.

- Keep repo and deployed updater code synchronized in both directions. Deploy repo fixes to the server; copy server fixes back before finishing. Compare code hashes after synchronization. Never synchronize private configuration, keys, credentials, databases, logs or runtime data into Git.
- `sync.py` builds trusted commits and publishes signed feeds. The deployed branch is only `26.2`.
- `runtime.py` installs checksum-verified dependencies in a user-owned persistent directory. `install.sh` takes `THM_UPDATER_DIR`, defaulting to `./data`. It does not manage the API or process supervisor.
- Configuration paths are relative to `config.json`. Public examples must not contain host usernames, platform names or deployment filesystem paths.
- Run `python3 -m unittest -v`, `bash -n install.sh` and `git diff --check` after changes. Do not launch Minecraft.
- Keep secrets and generated data out of Git. Deliberately update the source allowlist when adding files.
- Work on `main` and use Conventional Commits. Commit and publish only when asked.
