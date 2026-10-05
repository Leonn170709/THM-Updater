#!/usr/bin/env python3
"""Build and mirror trusted THM version branches, then atomically sign the feed."""
import base64
import fcntl
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

MAX_JAR = 32 * 1024 * 1024
MAX_PAYLOAD = 700 * 1024
REPOSITORY = 'https://github.com/Leonn170709/THM-Addons.git'
API = 'https://api.github.com/repos/Leonn170709/THM-Addons'
SAFE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z')
SHA = re.compile(r'[a-f0-9]{40}\Z')
ARTIFACT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}/(?:dev/[a-f0-9]{40}|stable/[A-Za-z0-9][A-Za-z0-9._-]{0,99})\.jar\Z')


def load_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text())
    for name in ['files', 'key', 'secrets', 'checkout', 'state', 'javaHome', 'binDir', 'gradleHome']:
        if name in config:
            config[name] = str((path.parent / config[name]).resolve())
    return config


def run(*args, cwd=None, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    return result.stdout.decode().strip()


def atomic_write(path, data, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.publish-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(name).unlink(missing_ok=True)


class UnsupportedBranch(ValueError):
    pass


def jar_metadata(path, branches, commit=None, digest=None):
    if not 0 < Path(path).stat().st_size <= MAX_JAR:
        raise ValueError('Artifact exceeds JAR size limit')
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if digest is not None and (not re.fullmatch(r'sha256:[a-f0-9]{64}', digest) or digest[7:] != actual):
        raise ValueError('Missing or mismatched GitHub SHA-256 digest')
    with zipfile.ZipFile(path) as jar:
        info = jar.getinfo('fabric.mod.json')
        if info.file_size > 64 * 1024 or len([n for n in jar.namelist() if n == 'fabric.mod.json']) != 1:
            raise ValueError('Invalid fabric metadata size or duplicate entry')
        data = json.loads(jar.read(info))
        if sum(entry.file_size for entry in jar.infolist()) > 256 * 1024 * 1024:
            raise ValueError('Excessive decompressed JAR size')
        if jar.testzip() is not None:
            raise ValueError('Corrupt JAR')
    branch = data.get('custom', {}).get('github:branch', '')
    sha = data.get('custom', {}).get('github:sha', '')
    version = data.get('version', '')
    minecraft = data.get('depends', {}).get('minecraft', '')
    if data.get('id') != 'thm-addon':
        raise ValueError('Wrong addon id')
    if not isinstance(branch, str) or not SAFE.fullmatch(branch) or branch not in branches:
        raise UnsupportedBranch('Absent or unsupported artifact branch')
    if not SHA.fullmatch(sha) or (commit is not None and sha != commit):
        raise ValueError('Artifact commit does not match source')
    if not isinstance(version, str) or not 0 < len(version) <= 80:
        raise ValueError('Invalid addon version')
    if not isinstance(minecraft, str) or not re.fullmatch(r'[0-9][A-Za-z0-9._-]{0,19}', minecraft):
        raise ValueError('Expected exact Minecraft version')
    return dict(branch=branch, commit=sha, version=version, minecraft=minecraft, sha256=actual)


def limited_text(value, limit, fallback):
    text = (value or '').strip() or fallback
    # The Java client caps UTF-16 length, including both halves of emoji.
    return text.encode('utf-16-le')[:limit * 2].decode('utf-16-le', errors='ignore')


def sign_feed(entries, key):
    public_der = subprocess.run(['openssl', 'pkey', '-in', str(key), '-pubout', '-outform', 'DER'],
                                check=True, capture_output=True, timeout=15).stdout
    if len(public_der) != 44 or not public_der.startswith(bytes.fromhex('302a300506032b6570032100')):
        raise ValueError('Expected an Ed25519 signing key')
    # Feed fields are copied from the verified JAR, never inferred from asset names.
    rows = [{k: v for k, v in e.items() if k != '_time'} for e in sorted(entries, key=lambda e: e['_time'], reverse=True)[:100]]
    for row in rows:
        row['title'] = limited_text(f"THMaddons {row['version']} {row['commit'][:7]}", 200, row['commit'])
        row['notes'] = limited_text(row['notes'], 20000, row['title'])
    while True:
        payload = json.dumps(dict(format=1, entries=rows), ensure_ascii=False, separators=(',', ':')).encode()
        if len(payload) < MAX_PAYLOAD:
            break
        rows.pop()
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / 'payload'
        source.write_bytes(payload)
        signature = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(source)], check=True, capture_output=True, timeout=15).stdout
        public = Path(tmp) / 'public.pem'
        public.write_text(run('openssl', 'pkey', '-in', str(key), '-pubout'))
        sig = Path(tmp) / 'signature'
        sig.write_bytes(signature)
        run('openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(public), '-in', str(source), '-sigfile', str(sig))
    return json.dumps(dict(payload=base64.b64encode(payload).decode(), signature=base64.b64encode(signature).decode()), separators=(',', ':')).encode(), rows


def artifact_path(root, relative):
    if not isinstance(relative, str) or not ARTIFACT.fullmatch(relative):
        raise ValueError('Unsafe artifact path')
    destination = Path(root).resolve() / relative
    if destination.resolve() != destination:
        raise ValueError('Artifact path contains a symlink')
    return destination


def publish_artifact(source, root, relative, expected):
    destination = artifact_path(root, relative)
    destination.parent.parent.mkdir(parents=True, exist_ok=True)
    destination.parent.mkdir(exist_ok=True)
    destination.parent.parent.chmod(0o755)
    destination.parent.chmod(0o755)
    if destination.exists():
        if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
            raise ValueError('Immutable artifact collision')
    else:
        data = Path(source).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('Artifact changed before publication')
        atomic_write(destination, data)
    if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
        raise ValueError('Published artifact hash mismatch')


def publish(entries, config):
    # Recheck every retained JAR before the feed can refer to it.
    for entry in entries:
        url = urllib.parse.urlsplit(entry['url'])
        base = urllib.parse.urlsplit(config['origin'])
        if (url.scheme, url.netloc) != (base.scheme, base.netloc) or not entry['url'].startswith(config['origin'] + '/'):
            raise ValueError('Feed artifact has another origin')
        relative = entry['url'][len(config['origin']) + 1:]
        file = artifact_path(config['files'], relative)
        metadata = jar_metadata(file, config['branches'], entry['commit'], 'sha256:' + entry['sha256'])
        if any(metadata[k] != entry[k] for k in metadata):
            raise ValueError('Feed metadata differs from hosted JAR')
    envelope, rows = sign_feed(entries, config['key'])
    atomic_write(Path(config['files']) / 'feed.json', envelope)
    kept = {e['url'] for e in rows}
    return [e for e in entries if e['url'] in kept]


class HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if (url.scheme != 'https' or url.hostname not in {'github.com', 'api.github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
                or url.username or url.password or url.port not in (None, 443)):
            raise ValueError('Untrusted asset redirect')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, target=None):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in {'github.com', 'api.github.com'}
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError('Untrusted download URL')
    request = urllib.request.Request(url, headers={'User-Agent': 'THM-Updater', 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    limit = MAX_JAR if target else 8 * 1024 * 1024
    deadline = time.monotonic() + 120
    with urllib.request.build_opener(HttpsOnly()).open(request, timeout=30) as response:
        if int(response.headers.get('Content-Length', 0)) > limit:
            raise ValueError('Oversized response')
        data = bytearray()
        while chunk := response.read1(64 * 1024):
            if time.monotonic() > deadline:
                raise TimeoutError('Download exceeded time limit')
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('Oversized response')
    if target:
        Path(target).write_bytes(data)
    else:
        return json.loads(data)


def build_dev(config, repo, branch, sha, worktrees):
    relative = f'{branch}/dev/{sha}.jar'
    hosted = artifact_path(config['files'], relative)
    if hosted.exists():
        # Recover an immutable JAR if publication stopped before saving state.
        metadata = jar_metadata(hosted, [branch], sha)
    else:
        with tempfile.TemporaryDirectory(dir=worktrees, prefix='build-') as tmp:
            work = Path(tmp) / 'source'
            run('git', '-C', str(repo), 'worktree', 'add', '--detach', str(work), sha)
            try:
                shutil.copyfile(config['secrets'], work / 'secrets.properties')
                (work / 'secrets.properties').chmod(0o600)
                env = {name: os.environ[name] for name in ['PATH', 'JAVA_HOME', 'GRADLE_USER_HOME', 'LANG', 'LC_ALL', 'TZ'] if name in os.environ}
                env.update(THM_UPDATE_BRANCH=branch, GITHUB_SHA=sha,
                           GITHUB_REF_NAME=branch, GITHUB_REF_TYPE='branch')
                log = Path(config['state']).parent / 'last-build.log'
                with log.open('wb') as out:
                    log.chmod(0o600)
                    subprocess.run(['./gradlew', '--no-daemon', 'build', '--console=plain'], cwd=work, env=env, stdout=out, stderr=subprocess.STDOUT, check=True)
                candidates = [p for p in (work / 'build/libs').glob('THM-Addons-*.jar') if not p.name.endswith(('-sources.jar', '-javadoc.jar', '-dev.jar'))]
                if len(candidates) != 1:
                    raise ValueError('Expected one remapped addon JAR')
                metadata = jar_metadata(candidates[0], [branch], sha)
                publish_artifact(candidates[0], config['files'], relative, metadata['sha256'])
            finally:
                run('git', '-C', str(repo), 'worktree', 'remove', '--force', str(work))
    title = run('git', '-C', str(repo), 'log', '-1', '--format=%s', sha)
    notes = run('git', '-C', str(repo), 'log', '-1', '--format=%b', sha) or title
    return dict(metadata, channel='DEV', title=limited_text(title, 200, sha), notes=limited_text(notes, 20000, title or sha), url=config['origin'] + '/' + relative, _time=int(run('git', '-C', str(repo), 'show', '-s', '--format=%ct', sha)))


def mirror_stable(config, repo, release, asset):
    tag = release['tag_name']
    if not SAFE.fullmatch(tag):
        raise ValueError('Unsafe release tag')
    digest = asset.get('digest', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', digest or ''):
        raise ValueError('Release asset has no SHA-256 digest')
    sha = run('git', '-C', str(repo), 'rev-parse', '--verify', f'refs/tags/{tag}^{{commit}}')
    with tempfile.TemporaryDirectory(dir=Path(config['state']).parent) as tmp:
        artifact = Path(tmp) / 'release.jar'
        if asset.get('size', MAX_JAR + 1) > MAX_JAR:
            raise ValueError('Oversized release asset')
        download(asset['browser_download_url'], artifact)
        metadata = jar_metadata(artifact, config['branches'], sha, digest)
        branch = metadata['branch']
        run('git', '-C', str(repo), 'merge-base', '--is-ancestor', sha, f'refs/remotes/origin/{branch}')
        relative = f'{branch}/stable/{tag}.jar'
        publish_artifact(artifact, config['files'], relative, metadata['sha256'])
    from datetime import datetime
    return dict(metadata, channel='STABLE', title=limited_text(release.get('name'), 200, tag), notes=limited_text(release.get('body'), 20000, release.get('name') or tag), url=config['origin'] + '/' + relative, _time=datetime.fromisoformat(release['published_at'].replace('Z', '+00:00')).timestamp())


def sync(config):
    state = Path(config['state'])
    state.parent.mkdir(parents=True, exist_ok=True)
    if not config['branches'] or any(not SAFE.fullmatch(b) for b in config['branches']):
        raise ValueError('Invalid supported branches')
    origin = urllib.parse.urlsplit(config['origin'])
    if (origin.scheme != 'https' or not origin.hostname or origin.query or origin.fragment
            or origin.username or origin.password or origin.port not in (None, 443) or config['origin'].endswith('/')):
        raise ValueError('Invalid HTTPS origin')
    # One job owns the worktrees, state, and feed at a time.
    with (state.parent / 'sync.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        old = json.loads(state.read_text()) if state.exists() else dict(entries=[], dev={})
        entries = old['entries']
        if len(entries) > 100:
            raise ValueError('Oversized stored feed history')
        repo = Path(config['checkout'])
        worktrees = state.parent / 'worktrees'
        worktrees.mkdir(exist_ok=True)
        if not repo.exists():
            run('git', 'clone', '--bare', REPOSITORY, str(repo))
        run('git', '-C', str(repo), 'remote', 'set-url', 'origin', REPOSITORY)
        run('git', '-C', str(repo), 'worktree', 'prune')
        failures = deque(maxlen=20)
        for branch in config['branches']:
            try:
                run('git', '-C', str(repo), 'fetch', 'origin', f'+refs/heads/{branch}:refs/remotes/origin/{branch}')
                sha = run('git', '-C', str(repo), 'rev-parse', f'refs/remotes/origin/{branch}')
                if old['dev'].get(branch) == sha:
                    continue
                entry = build_dev(config, repo, branch, sha, worktrees)
                entries = publish([e for e in entries if e['url'] != entry['url']] + [entry], config)
                old.update(entries=entries)
                old['dev'][branch] = sha
                atomic_write(state, json.dumps(old).encode(), 0o600)
                print(f'Published DEV {branch} {sha}', flush=True)
            except Exception as error:
                failures.append(f'DEV {branch}: {type(error).__name__}')
        assets_db = sqlite3.connect(state.parent / 'release-assets.db')
        assets_db.execute('CREATE TABLE IF NOT EXISTS release_assets (asset_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL)')
        try:
            run('git', '-C', str(repo), 'fetch', '--tags', 'origin')
            page = 1
            while True:
                releases = download(f'{API}/releases?per_page=100&page={page}')
                if not releases:
                    break
                for release in releases:
                    if release['draft'] or release['prerelease']:
                        continue
                    # Each asset may carry a different supported version branch.
                    for asset_page in range(1, 101):
                        assets = (release['assets'] if asset_page == 1 and len(release['assets']) < 100
                                  else download(f"{API}/releases/{release['id']}/assets?per_page=100&page={asset_page}"))
                        for asset in assets:
                            if not asset['name'].startswith('THM-Addons-') or not asset['name'].endswith('.jar') or asset['name'].endswith(('-sources.jar', '-javadoc.jar', '-dev.jar')):
                                continue
                            identity = str(asset['id'])
                            fingerprint = json.dumps([asset.get('digest'), asset.get('updated_at'), release['tag_name'], release.get('updated_at'), config['branches']])
                            if assets_db.execute('SELECT fingerprint FROM release_assets WHERE asset_id=?', (identity,)).fetchone() == (fingerprint,):
                                continue
                            try:
                                entry = mirror_stable(config, repo, release, asset)
                                entries = publish([e for e in entries if e['url'] != entry['url']] + [entry], config)
                                old.update(entries=entries)
                                atomic_write(state, json.dumps(old).encode(), 0o600)
                                assets_db.execute('INSERT OR REPLACE INTO release_assets VALUES (?, ?)', (identity, fingerprint))
                                assets_db.commit()
                                print(f"Published STABLE {entry['branch']} {release['tag_name']}", flush=True)
                            except UnsupportedBranch:
                                assets_db.execute('INSERT OR REPLACE INTO release_assets VALUES (?, ?)', (identity, fingerprint))
                                assets_db.commit()
                                continue
                            except Exception as error:
                                failures.append(f"STABLE asset {identity}: {type(error).__name__}: {error}" if isinstance(error, ValueError) else f'STABLE asset {identity}: {type(error).__name__}')
                        if len(assets) < 100:
                            break
                    else:
                        raise ValueError('Release asset pagination limit exceeded')
                if len(releases) < 100:
                    break
                page += 1
        except Exception as error:
            failures.append(f'GitHub releases: {type(error).__name__}')
        finally:
            assets_db.close()
        # Build failures preserve the last feed and report a worker error.
        if failures:
            raise RuntimeError('; '.join(failures))
        print(f'Sync complete: {len(entries)} entries; free disk {shutil.disk_usage(config["files"]).free // (1024*1024)} MiB', flush=True)


def worker(config, watch=False):
    binaries = []
    if config.get('javaHome'):
        os.environ['JAVA_HOME'] = config['javaHome']
        binaries.append(config['javaHome'] + '/bin')
    if config.get('binDir'):
        binaries.append(config['binDir'])
    if binaries:
        os.environ['PATH'] = os.pathsep.join(binaries) + os.pathsep + os.defpath
    if config.get('gradleHome'):
        os.environ['GRADLE_USER_HOME'] = config['gradleHome']
    while True:
        try:
            sync(config)
        except Exception as error:
            # Keep failures visible to the process supervisor.
            print(f'Error: THM updater failed: {error}', file=sys.stderr, flush=True)
            if not watch:
                return 1
        if not watch:
            return 0
        time.sleep(120)


if __name__ == '__main__':
    try:
        config = load_config(sys.argv[1])
        sys.exit(worker(config, '--watch' in sys.argv[2:]))
    except Exception as error:
        print(f'Error: THM updater configuration failed: {error}', file=sys.stderr, flush=True)
        sys.exit(1)
