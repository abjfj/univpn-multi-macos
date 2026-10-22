"""Synthetic builds prove dispatch and refusal; no vendor files or live network."""
import argparse
from dataclasses import replace
import io
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import univpn_multi as tool
import univpn_profiles as profiles


def synthetic_build(version, offset):
    """Two deliberately different layouts, not claims of real version support."""
    payloads, rules = {}, []
    for relative, port in zip(profiles.SOURCE_FILES, ('rpc', 'rpc', 'backend_initial')):
        before = b'\xbf' + struct.pack('<I', 29191)
        payload = (bytes.fromhex('cffaedfe07000001') + b'\0' * (offset - 8) + before
                   + b'UniVPN\0' + version.encode() + relative.encode())
        edits = (profiles.Edit('Synthetic port', offset, before, port=port, prefix=b'\xbf'),)
        rules.append(profiles.BinaryRule(relative, tool.digest(payload), 2, edits))
        payloads[relative] = payload
    return profiles.BuildProfile('synthetic-' + version, (version,), 'x86_64', tuple(rules)), payloads


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.first, self.first_files = synthetic_build('test-a', 64)
        self.second, self.second_files = synthetic_build('test-b', 112)
        patcher = mock.patch.object(profiles, 'BUILD_PROFILES', (self.first, self.second))
        patcher.start()
        self.addCleanup(patcher.stop)

    def app(self, version, payloads, name='UniVPN.app'):
        app = self.root / name
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/Resources').mkdir()
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleShortVersionString': version, 'CFBundleVersion': 'synthetic',
            'CFBundleIdentifier': 'work.VPNClient', 'CFBundleExecutable': 'UniVPN'}))
        for relative, payload in payloads.items():
            path = app / 'Contents/MacOS' / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            path.chmod(0o755)
        (app / tool.RUNTIME_CONFIG).write_bytes(
            b'[GLOBAL]\nClientName = UniVPN\n[ADVANCED]\nClientReConnectTimeValue = 5\n')
        return app

    def record(self, profile):
        return {'version': profile.versions[0], 'source_sha256': profile.hashes()}

    def test_two_versions_select_their_own_offsets_and_leave_source_unchanged(self):
        for profile, files in ((self.first, self.first_files), (self.second, self.second_files)):
            app = self.app(profile.versions[0], files, profile.id + '.app')
            before = tool.tree_record(app)
            report, originals, selected = tool.inspect_source(app)
            self.assertTrue(report['supported'])
            self.assertEqual(selected, profile)
            self.assertEqual(report['profile'], profile.id)
            for relative, original in originals.items():
                result = tool.patch(original, relative, 3, profile=selected)
                edit = profile.binary(relative).edits[0]
                self.assertEqual(result[edit.offset:edit.offset + 5],
                                 b'\xbf' + struct.pack('<I', tool.ports(3)[edit.port]))
            self.assertEqual(tool.tree_record(app), before)

    def test_build_records_actual_version_and_profile_and_can_be_verified(self):
        app = self.app('test-b', self.second_files)
        output = self.root / 'output'
        with mock.patch.object(tool.os, 'geteuid', return_value=501):
            tool.build(argparse.Namespace(number=3, source=app, output=output))
        result = output / 'instance-003/UVP003.app'
        manifest = tool.load_manifest(result)
        self.assertEqual(manifest['version'], 'test-b')
        self.assertEqual(manifest['source_profile'], self.second.id)
        self.assertEqual(manifest['architecture'], 'x86_64')
        self.assertEqual(manifest['source_sha256'], self.second.hashes())
        data = (result / 'Contents/MacOS/UVP003').read_bytes()
        self.assertEqual(data[112:117], b'\xbf' + struct.pack('<I', tool.ports(3)['rpc']))

    def test_unknown_version_has_report_and_build_creates_nothing(self):
        app = self.app('not-reviewed', self.first_files)
        before = tool.tree_record(app)
        report, _, profile = tool.inspect_source(app)
        self.assertFalse(report['supported'])
        self.assertIsNone(profile)
        self.assertEqual(report['version'], 'not-reviewed')
        self.assertEqual(report['sha256'], self.first.hashes())
        self.assertIn('尚未适配', report['reason'])
        output = self.root / 'must-not-exist'
        with mock.patch.object(tool.os, 'geteuid', return_value=501), \
                mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(tool.Refused, '未生成、安装或修改'):
                tool.build(argparse.Namespace(number=2, source=app, output=output))
            run.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual(tool.tree_record(app), before)

    def test_same_version_with_changed_hash_is_not_patched(self):
        app = self.app('test-a', dict(self.first_files, UniVPN=self.first_files['UniVPN'] + b'changed'))
        with mock.patch.object(tool, 'patch') as patch:
            report, _, _ = tool.inspect_source(app)
            patch.assert_not_called()
        self.assertFalse(report['supported'])
        self.assertIn('SHA256', report['reason'])

    def test_files_from_two_builds_never_form_a_compatible_app(self):
        second_same_version = replace(self.second, versions=('test-a',))
        app = self.app('test-a', dict(self.first_files, UniVPN=self.second_files['UniVPN']))
        with mock.patch.object(profiles, 'BUILD_PROFILES', (self.first, second_same_version)):
            report, _, selected = tool.inspect_source(app)
        self.assertFalse(report['supported'])
        self.assertIsNone(selected)
        self.assertIn('混合组件', report['reason'])

    def test_arm64_universal_and_mixed_architectures_are_reported_and_refused(self):
        for label, header in (('arm64', bytes.fromhex('cffaedfe0c000001')),
                              ('universal', bytes.fromhex('cafebabe00000002'))):
            files = {relative: header + data[8:] for relative, data in self.first_files.items()}
            app = self.app('test-a', files, label + '.app')
            with mock.patch.object(tool, 'patch') as patch:
                report, _, _ = tool.inspect_source(app)
                patch.assert_not_called()
            self.assertFalse(report['supported'])
            self.assertEqual(report['architecture'], label)
        app = self.app('test-a', dict(self.first_files, UniVPN=b'unknown'), 'mixed.app')
        self.assertEqual(tool.inspect_source(app)[0]['architecture'], 'mixed')

    def test_ambiguous_build_rules_are_refused(self):
        app = self.app('test-a', self.first_files)
        duplicate = replace(self.first, id='ambiguous-copy')
        with mock.patch.object(profiles, 'BUILD_PROFILES', (self.first, duplicate)):
            report, _, _ = tool.inspect_source(app)
        self.assertFalse(report['supported'])
        self.assertIn('多份适配规则', report['reason'])

    def test_matching_hash_still_requires_original_instruction_bytes(self):
        app = self.app('test-a', self.first_files)
        broken_rule = replace(self.first.binaries[0], edits=(
            replace(self.first.binaries[0].edits[0], before=b'wrong'),))
        broken_profile = replace(self.first, binaries=(broken_rule, *self.first.binaries[1:]))
        with mock.patch.object(profiles, 'BUILD_PROFILES', (broken_profile,)):
            report, _, _ = tool.inspect_source(app)
            with self.assertRaises(tool.Refused):
                tool.require_source(app)
        self.assertFalse(report['supported'])
        self.assertIn('前置检查失败', report['reason'])

    def test_bundle_identity_mismatch_is_refused(self):
        app = self.app('test-a', self.first_files)
        plist = app / 'Contents/Info.plist'
        info = plistlib.loads(plist.read_bytes())
        info['CFBundleExecutable'] = 'DifferentClient'
        plist.write_bytes(plistlib.dumps(info))
        self.assertFalse(tool.inspect_source(app)[0]['supported'])

    def test_missing_or_symlinked_component_is_refused(self):
        app = self.app('test-a', self.first_files)
        helper = app / 'Contents/MacOS' / profiles.HELPER
        helper.unlink()
        report, _, _ = tool.inspect_source(app)
        self.assertFalse(report['supported'])
        self.assertIn('error', report['binaries'][profiles.HELPER])
        helper.symlink_to(app / 'Contents/MacOS/UniVPN')
        self.assertFalse(tool.inspect_source(app)[0]['supported'])

    def test_malformed_plist_has_a_clear_refusal(self):
        app = self.app('test-a', self.first_files)
        (app / 'Contents/Info.plist').write_bytes(b'<?xml version="1.0"?><plist><broken>')
        with self.assertRaisesRegex(tool.Refused, 'Info.plist'):
            tool.inspect_source(app)

    def test_inspect_returns_nonzero_for_unknown_build_but_preserves_json_report(self):
        app = self.app('unknown', self.first_files)
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['univpn_multi.py', 'inspect', '--source', str(app)]), \
                mock.patch.object(sys, 'platform', 'darwin'), mock.patch('sys.stdout', output):
            self.assertEqual(tool.main(), 1)
        self.assertFalse(json.loads(output.getvalue())['supported'])

    def test_profiles_lists_reviewed_versions_without_reading_any_client(self):
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['univpn_multi.py', 'profiles']), \
                mock.patch.object(tool, 'inspect_source') as inspect, mock.patch('sys.stdout', output):
            self.assertEqual(tool.main(), 0)
            inspect.assert_not_called()
        self.assertEqual([item['versions'][0] for item in json.loads(output.getvalue())], ['test-a', 'test-b'])

    def test_legacy_manifest_is_inferred_but_wrong_profile_or_hash_is_refused(self):
        legacy = self.record(self.first)
        self.assertEqual(tool.manifest_profile(legacy), self.first)
        current = dict(legacy, source_profile=self.first.id, architecture='x86_64')
        self.assertEqual(tool.manifest_profile(current), self.first)
        for fields in ({'source_profile': self.second.id}, {'architecture': 'arm64'},
                       {'source_sha256': self.second.hashes()}, {'version': 'unknown'}):
            with self.assertRaises(tool.Refused):
                tool.manifest_profile(dict(current, **fields))

    def test_unknown_new_refuses_before_lock_selection_config_sudo_or_routes(self):
        app = self.app('unknown', self.first_files)
        for dry_run in (False, True):
            with mock.patch.object(tool, 'SOURCE', app), \
                    mock.patch.object(tool.os, 'geteuid', return_value=501), \
                    mock.patch.object(tool, 'new_window_lock') as lock, \
                    mock.patch.object(tool, 'select_new_instance') as select, \
                    mock.patch.object(tool, 'prepare_instance_config') as prepare, \
                    mock.patch.object(tool, 'inherit_original_config') as inherit, \
                    mock.patch.object(tool, 'ensure_gateway_protection') as protect, \
                    mock.patch.object(tool.subprocess, 'run') as run:
                with self.assertRaises(tool.Refused):
                    tool.new_window(argparse.Namespace(dry_run=dry_run))
                for operation in (lock, select, prepare, inherit, protect, run):
                    operation.assert_not_called()

    def test_idle_copy_of_another_build_is_not_reused_or_overwritten(self):
        apps = self.root / 'Applications'
        (apps / 'UniVPN.app').mkdir(parents=True)
        old_copy = apps / 'UVP002.app'
        old_copy.mkdir()
        def state(app, product):
            return {'ui': [1], 'helper': [2], 'backend': [3]} if product == 'UniVPN' else {
                'ui': [], 'helper': [], 'backend': []}
        with mock.patch.object(tool, 'checked_processes', side_effect=state), \
                mock.patch.object(tool, 'load_manifest', return_value=self.record(self.first)), \
                mock.patch.object(tool, 'clean_orphan_helper') as cleanup:
            selected = tool.select_new_instance(apps, profile_id=self.second.id)
            cleanup.assert_not_called()
        self.assertEqual(selected, (3, apps / 'UVP003.app'))
        self.assertTrue(old_copy.is_dir())

    def test_repair_never_uses_a_different_original_build(self):
        manifest = dict(self.record(self.first), patch_revision=1)
        with mock.patch.object(tool.os, 'geteuid', return_value=0), \
                mock.patch.object(tool, 'load_manifest', return_value=manifest), \
                mock.patch.object(tool, 'require_source', return_value=(self.second_files, self.second, {})), \
                mock.patch.object(tool, 'clean_orphan_helper') as cleanup, \
                mock.patch.object(tool, 'atomic_write') as write:
            with self.assertRaisesRegex(tool.Refused, '来源不同'):
                tool.repair(argparse.Namespace(number=2))
            cleanup.assert_not_called()
            write.assert_not_called()

    def test_new_refuses_a_staged_copy_from_another_build_before_sudo(self):
        staged = self.root / 'build/instance-003/UVP003.app'
        staged.mkdir(parents=True)
        target = self.root / 'Applications/UVP003.app'
        with mock.patch.object(tool, '__file__', str(self.root / 'univpn_multi.py')), \
                mock.patch.object(tool.os, 'geteuid', return_value=501), \
                mock.patch.object(tool, 'require_source', return_value=(
                    self.second_files, self.second, {'version': 'test-b'})), \
                mock.patch.object(tool, 'select_new_instance', return_value=(3, target)), \
                mock.patch.object(tool, 'load_manifest', return_value=self.record(self.first)), \
                mock.patch.object(tool, 'prepare_instance_config') as prepare, \
                mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaisesRegex(tool.Refused, '不同客户端构建'):
                tool.new_window(argparse.Namespace(dry_run=False))
            prepare.assert_not_called()
            run.assert_not_called()
        self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
