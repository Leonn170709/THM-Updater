"""Install verified runtime dependencies inside a private persistent directory."""
import hashlib
import json
import lzma
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

from sync import atomic_write, load_config, publish, sign_feed

HOSTS = {'api.adoptium.net', 'github.com', 'release-assets.githubusercontent.com',
         'objects.githubusercontent.com', 'deb.debian.org'}


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname not in HOSTS or parsed.username
            or parsed.password or parsed.port not in (None, 443)):
        raise ValueError('Untrusted runtime download URL')


class HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, destination, limit):
    check_url(url)
    request = urllib.request.Request(url, headers={'User-Agent': 'THM-Updater/1.0'})
    deadline = time.monotonic() + 300
    with urllib.request.build_opener(HttpsOnly()).open(request, timeout=30) as response:
        if int(response.headers.get('Content-Length', 0)) > limit:
            raise ValueError('Oversized runtime download')
        size = 0
        with Path(destination).open('wb') as out:
            while chunk := response.read1(64 * 1024):
                if time.monotonic() > deadline:
                    raise TimeoutError('Runtime download exceeded time limit')
                size += len(chunk)
                if size > limit:
                    raise ValueError('Oversized runtime download')
                out.write(chunk)


def verify_digest(path, expected):
    if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('Invalid runtime SHA-256 digest')
    with Path(path).open('rb') as source:
        actual = hashlib.file_digest(source, 'sha256').hexdigest()
    if actual != expected:
        raise ValueError('Runtime SHA-256 mismatch')


def extract_jdk(archive, destination):
    with tarfile.open(archive) as tar:
        size = count = 0
        for member in tar:
            size += member.size
            count += 1
            if size > 1024 * 1024 * 1024 or count > 20000:
                raise ValueError('Oversized expanded JDK archive')
        tar.extractall(destination, filter='data')
    roots = list(Path(destination).iterdir())
    if len(roots) != 1 or not (roots[0] / 'bin/java').is_file():
        raise ValueError('Unexpected JDK archive layout')
    return roots[0]


def install(root):
    root = Path(root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    for name in ['config.json', 'signing.pem', 'secrets.properties']:
        file = root / name
        if file.is_symlink() or not file.is_file():
            raise ValueError('Prepare server-only config.json, signing.pem and secrets.properties before installing')
        file.chmod(0o600)
    sign_feed([], root / 'signing.pem')
    config = json.loads((root / 'config.json').read_text())
    origin = urllib.parse.urlsplit(config['origin'])
    if (origin.scheme != 'https' or not origin.hostname or origin.username or origin.password
            or origin.port not in (None, 443) or origin.query or origin.fragment or config['origin'].endswith('/')):
        raise ValueError('Configure a valid HTTPS feed origin')
    config.update(branches=['26.2'], files='files', key='signing.pem', secrets='secrets.properties',
                  checkout='source.git', state='state.json', javaHome='runtime/jdk',
                  binDir='runtime/bin', gradleHome='gradle')
    for name in ['runtime', 'runtime/bin', 'gradle', 'files']:
        (root / name).mkdir(mode=0o700, parents=True, exist_ok=True)
    if not (root / 'runtime/jdk/bin/java').is_file():
        arch = {'aarch64': 'aarch64', 'x86_64': 'x64'}[platform.machine()]
        with tempfile.TemporaryDirectory(dir=root / 'runtime') as temp:
            temp = Path(temp)
            metadata = temp / 'metadata.json'
            fetch(f'https://api.adoptium.net/v3/assets/latest/25/hotspot?architecture={arch}&image_type=jdk&os=linux&vendor=eclipse', metadata, 1024 * 1024)
            package = json.loads(metadata.read_text())[0]['binary']['package']
            archive = temp / 'jdk.tar.gz'
            fetch(package['link'], archive, 512 * 1024 * 1024)
            verify_digest(archive, package['checksum'])
            shutil.move(extract_jdk(archive, temp / 'extract'), root / 'runtime/jdk')
    if not (root / 'runtime/bin/glslangValidator').is_file():
        arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
        with tempfile.TemporaryDirectory(dir=root / 'runtime') as temp:
            temp = Path(temp)
            index = temp / 'Packages.xz'
            fetch(f'https://deb.debian.org/debian/dists/trixie/main/binary-{arch}/Packages.xz', index, 64 * 1024 * 1024)
            fields = {}
            size = 0
            with lzma.open(index, 'rt', encoding='utf-8') as source:
                while line := source.readline(64 * 1024 + 1):
                    if len(line) > 64 * 1024:
                        raise ValueError('Oversized package index line')
                    size += len(line)
                    if size > 256 * 1024 * 1024:
                        raise ValueError('Oversized expanded package index')
                    if line.strip():
                        if not line[0].isspace() and ': ' in line:
                            name, value = line.rstrip().split(': ', 1)
                            fields[name] = value
                    elif fields.get('Package') == 'glslang-tools':
                        break
                    else:
                        fields = {}
            if fields.get('Package') != 'glslang-tools':
                raise ValueError('Shader compiler package not found')
            archive = temp / 'shader.deb'
            fetch('https://deb.debian.org/debian/' + fields['Filename'], archive, 64 * 1024 * 1024)
            verify_digest(archive, fields['SHA256'])
            subprocess.run(['dpkg-deb', '--extract', str(archive), str(temp / 'extract')], check=True, timeout=60)
            binary = temp / 'extract/usr/bin/glslangValidator'
            destination = root / 'runtime/bin/glslangValidator'
            shutil.copyfile(binary.resolve(), destination)
            destination.chmod(0o700)
    subprocess.run([str(root / 'runtime/jdk/bin/java'), '-version'], check=True, timeout=15)
    subprocess.run([str(root / 'runtime/bin/glslangValidator'), '--version'], check=True, timeout=15)
    atomic_write(root / 'config.json', json.dumps(config).encode(), 0o600)
    atomic_write(root / 'gradle/gradle.properties', b'org.gradle.jvmargs=-Xmx768m\norg.gradle.workers.max=2\n', 0o600)
    if not (root / 'files/feed.json').exists():
        publish([], load_config(root / 'config.json'))


if __name__ == '__main__':
    install(sys.argv[1])
