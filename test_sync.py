import base64
import hashlib
import json
import io
import contextlib
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import sync


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / 'key.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(self.key)], check=True, capture_output=True)
        self.sha = 'a' * 40
        self.jar = self.root / 'addon.jar'
        self.config = dict(branches=['26.2'], origin='https://updates.example.com/updates', files=str(self.root / 'files'), key=str(self.key), state=str(self.root / 'state.json'))
        self.write_jar()

    def write_jar(self, branch='26.2', sha=None, id='thm-addon'):
        with zipfile.ZipFile(self.jar, 'w') as jar:
            jar.writestr('fabric.mod.json', json.dumps(dict(id=id, version='0.3.0', custom={'github:branch': branch, 'github:sha': sha or self.sha}, depends={'minecraft': '26.2'})))

    def entry(self, timestamp=1, channel='DEV'):
        return dict(sync.jar_metadata(self.jar, ['26.2']), channel=channel, title='Title "quoted"', notes='Line one\nLine two', url=self.config['origin'] + '/26.2/dev/' + self.sha + '.jar', _time=timestamp)

    def test_branch_and_commit_selection(self):
        self.assertEqual(sync.jar_metadata(self.jar, ['26.2'], self.sha)['minecraft'], '26.2')
        for branch in ['', '1.21.11', '../26.2']:
            self.write_jar(branch)
            with self.assertRaises(ValueError):
                sync.jar_metadata(self.jar, ['26.2'])
        self.write_jar(sha='b' * 40)
        with self.assertRaises(ValueError):
            sync.jar_metadata(self.jar, ['26.2'], self.sha)
        self.write_jar(id='another-addon')
        with self.assertRaises(ValueError):
            sync.jar_metadata(self.jar, ['26.2'])

    def test_detached_dev_build_embeds_branch_despite_ambient_ci(self):
        repo = self.root / 'repo'
        repo.mkdir()
        sync.run('git', 'init', str(repo))
        sync.run('git', '-C', str(repo), 'config', 'user.email', 'test@example.com')
        sync.run('git', '-C', str(repo), 'config', 'user.name', 'Test')
        wrapper = repo / 'gradlew'
        wrapper.write_text('''#!/usr/bin/env python3
import json, os, pathlib, zipfile
branch = os.environ.get('GITHUB_HEAD_REF') or (
    os.environ.get('GITHUB_REF_NAME', '') if os.environ.get('GITHUB_REF_TYPE') == 'branch' else '')
out = pathlib.Path('build/libs')
out.mkdir(parents=True)
with zipfile.ZipFile(out / 'THM-Addons-0.3.0.jar', 'w') as jar:
    jar.writestr('fabric.mod.json', json.dumps(dict(id='thm-addon', version='0.3.0',
        custom={'github:branch': branch, 'github:sha': os.environ['GITHUB_SHA']},
        depends={'minecraft': '26.2'})))
assert os.environ['THM_UPDATE_BRANCH'] == branch
assert 'GITHUB_TOKEN' not in os.environ and 'SERVICE_SECRET' not in os.environ
assert 'SSH_AUTH_SOCK' not in os.environ
''')
        wrapper.chmod(0o700)
        sync.run('git', '-C', str(repo), 'add', 'gradlew')
        sync.run('git', '-C', str(repo), 'commit', '-m', 'Build fixture')
        sha = sync.run('git', '-C', str(repo), 'rev-parse', 'HEAD')
        secrets = self.root / 'secrets.properties'
        secrets.write_text('')
        worktrees = self.root / 'worktrees'
        worktrees.mkdir()
        config = dict(self.config, secrets=str(secrets))
        with patch.dict(os.environ, GITHUB_HEAD_REF='untrusted-pr', GITHUB_REF_NAME='wrong',
                        GITHUB_REF_TYPE='tag', GITHUB_SHA='b' * 40, THM_UPDATE_BRANCH='wrong',
                        GITHUB_TOKEN='test-only', SERVICE_SECRET='test-only', SSH_AUTH_SOCK='test-only'):
            entry = sync.build_dev(config, repo, '26.2', sha, worktrees)
        hosted = Path(config['files']) / ('26.2/dev/' + sha + '.jar')
        self.assertEqual(sync.jar_metadata(hosted, ['26.2'], sha)['branch'], '26.2')
        self.assertEqual(entry['commit'], sha)
        self.assertFalse(list(worktrees.iterdir()))
        real_run = subprocess.run
        def refuse_rebuild(args, **kwargs):
            if args[0] == './gradlew':
                raise AssertionError('Recovery must reuse the verified immutable JAR')
            return real_run(args, **kwargs)
        with patch.object(sync.subprocess, 'run', side_effect=refuse_rebuild):
            recovered = sync.build_dev(config, repo, '26.2', sha, worktrees)
        self.assertEqual(recovered['sha256'], entry['sha256'])

    def test_missing_and_wrong_digest_rejected_before_publication(self):
        digest = hashlib.sha256(self.jar.read_bytes()).hexdigest()
        self.assertEqual(sync.jar_metadata(self.jar, ['26.2'], digest='sha256:' + digest)['sha256'], digest)
        for value in ['', 'md5:' + digest, 'sha256:' + '0' * 64]:
            with self.assertRaises(ValueError):
                sync.jar_metadata(self.jar, ['26.2'], digest=value)
        release = dict(tag_name='v1', published_at='2026-10-01T00:00:00Z')
        with self.assertRaises(ValueError):
            sync.mirror_stable(self.config, self.root, release, dict(digest=None))
        self.assertFalse(Path(self.config['files']).exists())

    def test_artifact_paths_reject_traversal_and_external_symlinks(self):
        entry = self.entry()
        root = Path(self.config['files'])
        for relative in ['../outside.jar', str(self.jar), '26.2/dev/../outside.jar']:
            with self.assertRaises(ValueError):
                sync.publish_artifact(self.jar, root, relative, entry['sha256'])
        relative = '26.2/dev/' + self.sha + '.jar'
        sync.publish_artifact(self.jar, root, relative, entry['sha256'])
        sync.publish([entry], self.config)
        previous = (root / 'feed.json').read_bytes()
        (root / relative).unlink()
        (root / relative).symlink_to(self.jar)
        with self.assertRaises(ValueError):
            sync.publish([entry], self.config)
        self.assertEqual((root / 'feed.json').read_bytes(), previous)
        (root / relative).unlink()
        shutil.rmtree(root / '26.2')
        (root / '26.2').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            sync.publish_artifact(self.jar, root, relative, entry['sha256'])
        self.assertFalse((self.root / 'dev').exists())

    def test_non_ed25519_key_preserves_previous_feed(self):
        entry = self.entry()
        sync.publish_artifact(self.jar, self.config['files'], '26.2/dev/' + self.sha + '.jar', entry['sha256'])
        sync.publish([entry], self.config)
        feed = Path(self.config['files']) / 'feed.json'
        previous = feed.read_bytes()
        wrong = self.root / 'ec.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', str(wrong)], check=True, capture_output=True)
        with self.assertRaises(ValueError):
            sync.publish([entry], dict(self.config, key=str(wrong)))
        self.assertEqual(feed.read_bytes(), previous)

    def test_download_policy_bounds_size_time_and_redirects(self):
        for url in ['http://github.com/a', 'https://user:secret@github.com/a', 'https://github.com:8443/a', 'https://example.com/a']:
            with self.assertRaises(ValueError):
                sync.download(url)
            with self.assertRaises(ValueError):
                sync.HttpsOnly().redirect_request(sync.urllib.request.Request('https://github.com/a'), None, 302, '', {}, url)
        for late in [False, True]:
            response = io.BytesIO(b'oversized')
            response.headers = {}
            with patch.object(sync.urllib.request, 'build_opener') as opener, patch.object(sync, 'MAX_JAR', 3), patch.object(sync.time, 'monotonic', side_effect=[0, 121 if late else 1]):
                opener.return_value.open.return_value = response
                target = self.root / 'download.jar'
                with self.assertRaises(TimeoutError if late else ValueError):
                    sync.download('https://github.com/a', target)
                self.assertFalse(target.exists())

    def test_relative_config_paths_resolve_from_config_directory(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps(dict(self.config, files='files', key='key.pem', javaHome='runtime/jdk')))
        loaded = sync.load_config(config)
        self.assertEqual(loaded['files'], str(self.root / 'files'))
        self.assertEqual(loaded['key'], str(self.key))
        self.assertEqual(loaded['javaHome'], str(self.root / 'runtime/jdk'))

    def test_signed_exact_bytes_order_history_limits_and_tampering(self):
        entries = [self.entry(i, 'DEV' if i % 2 else 'STABLE') for i in range(120)]
        envelope, rows = sync.sign_feed(entries, self.key)
        envelope = json.loads(envelope)
        payload = base64.b64decode(envelope['payload'])
        signature = base64.b64decode(envelope['signature'])
        source, sig, pub = [self.root / name for name in ['payload', 'signature', 'public.pem']]
        source.write_bytes(payload)
        sig.write_bytes(signature)
        pub.write_text(sync.run('openssl', 'pkey', '-in', str(self.key), '-pubout'))
        verify = ['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(pub), '-in', str(source), '-sigfile', str(sig)]
        self.assertEqual(subprocess.run(verify, capture_output=True).returncode, 0)
        self.assertEqual(len(rows), 100)
        self.assertEqual(rows[0]['channel'], 'DEV')
        self.assertEqual(json.loads(payload)['entries'][0]['title'], 'THMaddons 0.3.0 aaaaaaa')
        self.assertEqual(json.loads(payload)['entries'][0]['notes'], 'Line one\nLine two')
        self.assertNotIn('_time', rows[0])
        source.write_bytes(payload.replace(b'0.3.0', b'0.3.1'))
        self.assertNotEqual(subprocess.run(verify, capture_output=True).returncode, 0)
        large = [dict(self.entry(i), notes='\U0001f600' * 20000) for i in range(100)]
        data, rows = sync.sign_feed(large, self.key)
        self.assertLess(len(base64.b64decode(json.loads(data)['payload'])), sync.MAX_PAYLOAD)
        self.assertLess(len(data), 1024 * 1024)
        self.assertGreater(len(rows), 0)

    def test_atomic_feed_keeps_previous_when_hash_or_signing_fails(self):
        entry = self.entry()
        relative = '26.2/dev/' + self.sha + '.jar'
        sync.publish_artifact(self.jar, self.config['files'], relative, entry['sha256'])
        sync.publish([entry], self.config)
        feed = Path(self.config['files']) / 'feed.json'
        previous = feed.read_bytes()
        published = Path(self.config['files']) / relative
        published.write_bytes(b'tampered')
        with self.assertRaises(ValueError):
            sync.publish([entry], self.config)
        self.assertEqual(feed.read_bytes(), previous)
        with self.assertRaises(ValueError):
            sync.publish_artifact(self.jar, self.config['files'], relative, entry['sha256'])
        published.write_bytes(self.jar.read_bytes())
        with patch.object(sync, 'sign_feed', side_effect=RuntimeError('signing failed')):
            with self.assertRaises(RuntimeError):
                sync.publish([entry], self.config)
        self.assertEqual(feed.read_bytes(), previous)

    def test_release_commit_must_belong_to_declared_branch(self):
        repo = self.root / 'repo'
        repo.mkdir()
        sync.run('git', 'init', str(repo))
        sync.run('git', '-C', str(repo), 'config', 'user.email', 'test@example.com')
        sync.run('git', '-C', str(repo), 'config', 'user.name', 'Test')
        sync.run('git', '-C', str(repo), 'commit', '--allow-empty', '-m', 'First')
        first = sync.run('git', '-C', str(repo), 'rev-parse', 'HEAD')
        sync.run('git', '-C', str(repo), 'update-ref', 'refs/remotes/origin/26.2', first)
        sync.run('git', '-C', str(repo), 'commit', '--allow-empty', '-m', 'Unrelated release')
        sha = sync.run('git', '-C', str(repo), 'rev-parse', 'HEAD')
        sync.run('git', '-C', str(repo), 'tag', 'v1')
        self.write_jar(sha=sha)
        release = dict(tag_name='v1', name='Release', body='Notes', published_at='2026-10-01T00:00:00Z')
        asset = dict(size=self.jar.stat().st_size, digest='sha256:' + hashlib.sha256(self.jar.read_bytes()).hexdigest(), browser_download_url='https://github.com/test.jar')
        def download(url, target):
            target.write_bytes(self.jar.read_bytes())
        with patch.object(sync, 'download', side_effect=download):
            with self.assertRaises(subprocess.CalledProcessError):
                sync.mirror_stable(self.config, repo, release, asset)
            self.assertFalse(Path(self.config['files']).exists())
            sync.run('git', '-C', str(repo), 'update-ref', 'refs/remotes/origin/26.2', sha)
            entry = sync.mirror_stable(self.config, repo, release, asset)
            self.assertEqual(entry['commit'], sha)
            self.assertTrue((Path(self.config['files']) / '26.2/stable/v1.jar').exists())

    def test_failed_build_retries_and_never_advances_successful_sha(self):
        repo = self.root / 'source.git'
        repo.mkdir()
        config = dict(self.config, checkout=str(repo), secrets=str(self.root / 'secrets'))
        state = Path(config['state'])
        old = dict(entries=[], dev={'26.2': 'b' * 40})
        state.write_text(json.dumps(old))
        feed = Path(config['files']) / 'feed.json'
        feed.parent.mkdir()
        feed.write_bytes(b'previous signed feed')
        def git(*args, **kwargs):
            return self.sha if 'rev-parse' in args else ''
        with patch.object(sync, 'run', side_effect=git), patch.object(sync, 'download', return_value=[]), patch.object(sync, 'build_dev', side_effect=RuntimeError('build failed')) as build:
            for _ in range(2):
                with self.assertRaises(RuntimeError):
                    sync.sync(config)
            self.assertEqual(build.call_count, 2)
        self.assertEqual(json.loads(state.read_text()), old)
        self.assertEqual(feed.read_bytes(), b'previous signed feed')
        old['dev']['26.2'] = self.sha
        state.write_text(json.dumps(old))
        with patch.object(sync, 'run', side_effect=git), patch.object(sync, 'download', return_value=[]), patch.object(sync, 'build_dev') as build:
            sync.sync(config)
            build.assert_not_called()

    def test_worker_reports_failures_and_retries_after_two_minutes(self):
        stderr = io.StringIO()
        with patch.dict(os.environ), patch.object(sync, 'sync', side_effect=[RuntimeError('failed build'), None]) as job, patch.object(sync.time, 'sleep', side_effect=[None, KeyboardInterrupt]) as sleep, contextlib.redirect_stderr(stderr):
            with self.assertRaises(KeyboardInterrupt):
                sync.worker(self.config, watch=True)
            self.assertEqual(job.call_count, 2)
            self.assertEqual(sleep.call_args_list[0].args, (120,))
        self.assertIn('Error: THM updater failed: failed build', stderr.getvalue())

    def test_unicode_notes_obey_java_utf16_limit(self):
        text = sync.limited_text('😀' * 20000, 20000, 'Fallback')
        self.assertEqual(len(text.encode('utf-16-le')) // 2, 20000)
        self.assertEqual(sync.limited_text('   ', 200, 'Fallback'), 'Fallback')

    def test_release_fingerprints_skip_downloads_and_recheck_added_branches(self):
        repo = self.root / 'source.git'
        repo.mkdir()
        config = dict(self.config, checkout=str(repo), secrets=str(self.root / 'secrets'))
        state = Path(config['state'])
        state.write_text(json.dumps(dict(entries=[], dev={'26.2': self.sha, '1.21.11': self.sha})))
        Path(config['files']).mkdir()
        release = dict(id=1, tag_name='v1', draft=False, prerelease=False, assets=[dict(id=10, name='THM-Addons-0.3.0.jar', digest='sha256:' + 'a' * 64, updated_at='2026-10-01')])
        def git(*args, **kwargs):
            return self.sha if 'rev-parse' in args else ''
        with patch.object(sync, 'run', side_effect=git), patch.object(sync, 'download', return_value=[release]) as download, patch.object(sync, 'mirror_stable', side_effect=sync.UnsupportedBranch('unsupported')) as mirror, contextlib.redirect_stdout(io.StringIO()):
            sync.sync(config)
            sync.sync(config)
            self.assertEqual(mirror.call_count, 1)
            config['branches'] = ['26.2', '1.21.11']
            sync.sync(config)
            self.assertEqual(mirror.call_count, 2)
            self.assertTrue(all('/releases?' in call.args[0] for call in download.call_args_list))

    def test_worker_selects_persistent_jdk_shader_and_gradle_cache(self):
        jdk = self.root / 'runtime/jdk'
        binary_dir = self.root / 'runtime/bin'
        (jdk / 'bin').mkdir(parents=True)
        binary_dir.mkdir(parents=True)
        compiler = binary_dir / 'glslangValidator'
        compiler.write_text('#!/bin/sh\nexit 0\n')
        compiler.chmod(0o700)
        config = dict(self.config, javaHome=str(jdk), binDir=str(binary_dir), gradleHome=str(self.root / 'gradle'))
        def check_environment(_config):
            self.assertEqual(os.environ['JAVA_HOME'], str(jdk))
            self.assertEqual(os.environ['GRADLE_USER_HOME'], str(self.root / 'gradle'))
            self.assertEqual(shutil.which('glslangValidator'), str(compiler))
            self.assertTrue(os.environ['PATH'].startswith(str(jdk / 'bin') + ':'))
        with patch.dict(os.environ), patch.object(sync, 'sync', side_effect=check_environment):
            self.assertEqual(sync.worker(config), 0)


if __name__ == '__main__':
    unittest.main()
