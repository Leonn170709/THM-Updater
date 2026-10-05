# THM Updater

Build and publish verified THM Addon updates for Minecraft **26.2**. This repository contains the publisher, portable dependency installer and tests. The HTTP API, token validator and membership integration stay private.

## Files

- `sync.py`: isolated exact-commit builds, verified release mirroring and signed feed publication.
- `runtime.py` and `install.sh`: install Java and shader tools in a user-owned persistent directory.
- `test_sync.py` and `test_runtime.py`: publisher, integrity and installer regression tests.
- Example configuration and build properties. They contain no real credentials or private keys.

The worker polls every two minutes. Development builds use trusted version branches, with this deployment restricted to `26.2`. Stable assets must match GitHub's SHA-256 digest, their release tag and their declared supported branch.

JARs are verified and published before the feed is signed and replaced atomically. The feed contains at most 100 entries and stays below 700 KiB. Older JARs remain on disk. Labels use `THMaddons <version> <seven-character commit SHA>`.

## Server setup

Use an existing unprivileged account and a persistent directory. Git, Python 3.13+, OpenSSL, `dpkg-deb` and standard C/C++ libraries must already be available. The installer keeps Java, shader tools, Gradle and build dependencies in the chosen directory; it installs no global packages.

The default runtime directory is `./data`. Prepare it before installing:

```bash
umask 077
mkdir -p data
chmod 700 data
cp config.example.json data/config.json
cp secrets.properties.example data/secrets.properties
```

Set the real HTTPS origin in `data/config.json` and the actual build settings in `data/secrets.properties`. Preserve the existing server-only signing key when updating a deployed installation. For a new installation with no trust key, generate one on the server:

```bash
openssl genpkey -algorithm Ed25519 -out data/signing.pem
chmod 600 data/signing.pem data/secrets.properties data/config.json
```

Set `api.updater` and `update.publicKey` in the private build properties. The public key is Base64 DER; the client must already contain the updater code and trust that key. Never generate a replacement key merely to reinstall dependencies.

Run the installer without sudo:

```bash
bash install.sh
```

`THM_UPDATER_DIR` can select a different persistent directory. Configuration paths resolve relative to the configuration file, independently of the working directory.

Run the installed worker from its runtime directory:

```bash
cd data
python3 sync.py config.json --watch
```

Your process supervisor handles startup and logs. The installer does not register services or alter the private API. Failures preserve the previous feed and retry after two minutes.

## Private HTTP integration

The worker opens no HTTP port. The existing private API exposes the runtime `files/` directory through authenticated routes:

```text
updates/feed.json
updates/<branch>/dev/<full-commit-sha>.jar
updates/<branch>/stable/<release-tag>.jar
```

Every feed and JAR GET must validate the existing personal UUID Bearer token and current membership. Return `401` for invalid credentials and `403` for valid nonmembers. Keep files outside static roots, send `Cache-Control: no-store` for the feed, and cap JAR responses at 32 MiB. Feed and artifact URLs share one HTTPS origin.

## Checks and synchronization

```bash
python3 -m unittest -v
bash -n install.sh
git diff --check
```

Keep the repo and deployed code synchronized in both directions. Deploy repo changes to the worker; copy server fixes back into the repo. Compare code hashes. Private keys, real configuration, credentials and generated state remain server-only.

The Git allowlist permits source and example files only. Do not copy the live runtime directory into this repository. See `SECURITY.md` for the review scope and trust boundary.
