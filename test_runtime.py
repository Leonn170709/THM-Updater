import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import runtime
import sync


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_https_hosts_credentials_ports_and_redirects(self):
        for url in ['http://deb.debian.org/a', 'https://user:secret@github.com/a',
                    'https://github.com:8443/a', 'https://example.com/a']:
            with self.assertRaises(ValueError):
                runtime.fetch(url, self.root / 'download', 10)
            with self.assertRaises(ValueError):
                runtime.HttpsOnly().redirect_request(runtime.urllib.request.Request('https://github.com/a'), None, 302, '', {}, url)
        runtime.check_url('https://release-assets.githubusercontent.com/a')

    def test_download_limits_and_digest_rejection(self):
        for late in [False, True]:
            response = io.BytesIO(b'oversized')
            response.headers = {}
            with patch.object(runtime.urllib.request, 'build_opener') as opener, patch.object(runtime.time, 'monotonic', side_effect=[0, 301 if late else 1]):
                opener.return_value.open.return_value = response
                with self.assertRaises(TimeoutError if late else ValueError):
                    runtime.fetch('https://github.com/a', self.root / 'download', 3)
                self.assertEqual((self.root / 'download').stat().st_size, 0)
        package = self.root / 'package'
        package.write_bytes(b'package')
        runtime.verify_digest(package, hashlib.sha256(b'package').hexdigest())
        for digest in ['', '0' * 64]:
            with self.assertRaises(ValueError):
                runtime.verify_digest(package, digest)

    def test_archive_traversal_symlinks_and_expanded_size_rejected(self):
        for kind in ['traversal', 'link', 'oversized']:
            archive = self.root / (kind + '.tar')
            if kind == 'oversized':
                info = tarfile.TarInfo('jdk/bin/java')
                info.size = 2 * 1024 * 1024 * 1024
                archive.write_bytes(info.tobuf() + b'\0' * 1024)
            else:
                self.write_unsafe_archive(archive, kind)
            with self.assertRaises((ValueError, tarfile.FilterError)):
                runtime.extract_jdk(archive, self.root / 'extract')
            self.assertFalse((self.root / 'outside').exists())

    def write_unsafe_archive(self, archive, kind):
        with tarfile.open(archive, 'w') as tar:
            info = tarfile.TarInfo('../outside' if kind == 'traversal' else 'jdk/bin/java')
            if kind == 'link':
                info.type = tarfile.SYMTYPE
                info.linkname = '../../../outside'
                tar.addfile(info)
            else:
                info.size = 1
                tar.addfile(info, io.BytesIO(b'x'))

    def test_existing_runtime_install_preserves_key_and_private_properties(self):
        (self.root / 'config.json').write_text(json.dumps({'origin': 'https://updates.example.com/updates'}))
        key = self.root / 'signing.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(key)], check=True, capture_output=True)
        key_before = key.read_bytes()
        properties = self.root / 'secrets.properties'
        properties.write_text('private-test-setting=keep\n')
        for filename in ['runtime/jdk/bin/java', 'runtime/bin/glslangValidator']:
            file = self.root / filename
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('#!/bin/sh\nexit 0\n')
            file.chmod(0o700)
        with patch.object(runtime, 'fetch', side_effect=AssertionError('Unexpected download')):
            runtime.install(self.root)
        self.assertEqual(key.read_bytes(), key_before)
        self.assertEqual(properties.read_text(), 'private-test-setting=keep\n')
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o700)
        self.assertTrue((self.root / 'files/feed.json').exists())
        config = sync.load_config(self.root / 'config.json')
        self.assertEqual(config['files'], str(self.root / 'files'))
        self.assertEqual(config['branches'], ['26.2'])


if __name__ == '__main__':
    unittest.main()
