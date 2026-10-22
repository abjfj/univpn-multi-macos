import json
import argparse
import subprocess
from contextlib import nullcontext
import struct
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import univpn_multi as tool


class NewWindowTests(unittest.TestCase):
    empty = {'ui': [], 'helper': [], 'backend': []}
    active = {'ui': [11], 'helper': [12], 'backend': [13]}
    profile = tool.compatibility.BUILD_PROFILES[0]
    source_match = ({}, profile, {'version': profile.versions[0]})

    def test_idle_original_is_first_and_existing_tunnels_are_not_touched(self):
        with tempfile.TemporaryDirectory() as temp:
            apps = Path(temp)
            original = apps / 'UniVPN.app'
            original.mkdir()
            with mock.patch.object(tool, 'checked_processes', return_value=self.empty), \
                    mock.patch.object(tool, 'clean_orphan_helper') as cleanup:
                self.assertEqual(tool.select_new_instance(apps), (1, original))
                cleanup.assert_not_called()

    def test_reuses_idle_installed_copy_even_if_lower_number_is_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            apps = Path(temp)
            (apps / 'UniVPN.app').mkdir()
            installed = apps / 'UVP004.app'
            installed.mkdir()
            def state(app, product):
                return self.active if product == 'UniVPN' else self.empty
            with mock.patch.object(tool, 'checked_processes', side_effect=state), \
                    mock.patch.object(tool, 'load_manifest'):
                self.assertEqual(tool.select_new_instance(apps), (4, installed))

    def test_backend_without_ui_is_busy_and_not_reused(self):
        with tempfile.TemporaryDirectory() as temp:
            apps = Path(temp)
            (apps / 'UniVPN.app').mkdir()
            (apps / 'UVP002.app').mkdir()
            def state(app, product):
                if product == 'UniVPN':
                    return self.active
                if product == 'UVP002':
                    return {'ui': [], 'helper': [], 'backend': [13]}
                return self.empty
            with mock.patch.object(tool, 'checked_processes', side_effect=state):
                self.assertEqual(tool.select_new_instance(apps), (3, apps / 'UVP003.app'))

    def test_dry_run_never_installs_starts_or_changes_configuration(self):
        with mock.patch.object(tool.os, 'geteuid', return_value=501), \
                mock.patch.object(tool, 'require_source', return_value=self.source_match), \
                mock.patch.object(tool, 'select_new_instance', return_value=(3, Path('/Applications/UVP003.app'))), \
                mock.patch.object(tool.subprocess, 'run') as run, \
                mock.patch.object(tool, 'prepare_instance_config') as prepare, \
                mock.patch.object(tool, 'inherit_original_config') as inherit, \
                mock.patch.object(tool, 'ensure_gateway_protection') as protect, \
                mock.patch.object(tool, 'build') as build:
            tool.new_window(argparse.Namespace(dry_run=True))
            run.assert_not_called()
            prepare.assert_not_called()
            inherit.assert_not_called()
            protect.assert_not_called()
            build.assert_not_called()

    def test_first_launch_key_matches_install_template_and_valid_timer_survives(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / 'UVP003.app'
            ini = app / tool.RUNTIME_CONFIG
            ini.parent.mkdir(parents=True)
            template = b'[GLOBAL]\nClientName = UVP003\n[ADVANCED]\nClientReConnectTimeValue = 0\n'
            ini.write_bytes(template)
            with mock.patch.object(tool.Path, 'home', return_value=root), \
                    mock.patch.object(tool, 'load_manifest'), \
                    mock.patch.object(tool, 'checked_processes', return_value=self.empty), \
                    mock.patch.object(tool.os, 'geteuid', return_value=501):
                tool.prepare_instance_config(app, 3)
                home = root / '.UVP003'
                config = home / 'sysconfig.ini'
                key = home / 'key.ini'
                self.assertEqual(tool.parse_ini(config.read_bytes()).getint(
                    'ADVANCED', 'ClientReConnectTimeValue'), 5)
                self.assertEqual(tool.parse_ini(key.read_bytes()).get('GLOBAL', 'VerifyValue'),
                                 tool.digest(template))
                saved = config.read_bytes() + b'[Session0]\nProfileName = saved.ini\nProfileUser = keep\n'
                config.write_bytes(saved)
                key_before = key.read_bytes()
                tool.prepare_instance_config(app, 3)
                self.assertEqual(config.read_bytes(), saved)
                self.assertEqual(key.read_bytes(), key_before)
                self.assertEqual(ini.read_bytes(), template)

    def test_configuration_preparation_refuses_an_active_backend(self):
        with mock.patch.object(tool, 'load_manifest'), \
                mock.patch.object(tool.os, 'geteuid', return_value=501), \
                mock.patch.object(tool, 'checked_processes', return_value={'ui': [], 'helper': [], 'backend': [13]}), \
                mock.patch.object(tool, 'atomic_write') as write:
            with self.assertRaises(tool.Refused):
                tool.prepare_instance_config(Path('/Applications/UVP003.app'), 3)
            write.assert_not_called()

    def test_busy_window_is_not_activated_by_new(self):
        attrs = mock.Mock(st_mode=0o104755)
        with mock.patch.object(tool, 'load_manifest', return_value={'patch_revision': 2}), \
                mock.patch.object(tool.os, 'geteuid', return_value=501), \
                mock.patch.object(tool.Path, 'stat', return_value=attrs), \
                mock.patch.object(tool, 'checked_processes', return_value=self.active), \
                mock.patch.object(tool.subprocess, 'run') as run:
            with self.assertRaises(tool.Refused):
                tool.start(argparse.Namespace(number=2, new_window=True))
            run.assert_not_called()

    def test_new_window_lock_rejects_overlapping_launches(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            with tool.new_window_lock(output):
                with self.assertRaises(tool.Refused):
                    with tool.new_window_lock(output):
                        self.fail('A second launcher acquired the same lock')

    def test_installation_failure_never_launches_ui_or_initializes_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = root / 'Applications/UVP003.app'
            staged = root / 'build/instance-003/UVP003.app'
            staged.mkdir(parents=True)
            with mock.patch.object(tool, '__file__', str(root / 'univpn_multi.py')), \
                    mock.patch.object(tool.os, 'geteuid', return_value=501), \
                    mock.patch.object(tool, 'require_source', return_value=self.source_match), \
                    mock.patch.object(tool, 'new_window_lock', return_value=nullcontext()), \
                    mock.patch.object(tool, 'select_new_instance', return_value=(3, app)), \
                    mock.patch.object(tool, 'load_manifest', return_value={
                        'version': self.profile.versions[0], 'source_sha256': self.profile.hashes()}), \
                    mock.patch.object(tool.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['sudo'])) as run, \
                    mock.patch.object(tool, 'prepare_instance_config') as prepare, \
                    mock.patch.object(tool, 'inherit_original_config') as inherit, \
                    mock.patch.object(tool, 'ensure_gateway_protection') as protect, \
                    mock.patch.object(tool, 'start') as start:
                with self.assertRaises(subprocess.CalledProcessError):
                    tool.new_window(argparse.Namespace(dry_run=False))
                self.assertEqual(run.call_args.args[0][:2], ['/usr/bin/sudo', sys.executable])
                self.assertEqual(run.call_args.args[0][-2:], ['install', str(staged.resolve())])
                prepare.assert_not_called()
                inherit.assert_not_called()
                protect.assert_not_called()
                start.assert_not_called()

    def test_installed_copy_is_reused_without_sudo_and_ui_starts_as_current_user(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp) / 'UVP003.app'
            app.mkdir()
            with mock.patch.object(tool.os, 'geteuid', return_value=501), \
                    mock.patch.object(tool, 'require_source', return_value=self.source_match), \
                    mock.patch.object(tool, 'new_window_lock', return_value=nullcontext()), \
                    mock.patch.object(tool, 'select_new_instance', return_value=(3, app)), \
                    mock.patch.object(tool.subprocess, 'run') as run, \
                    mock.patch.object(tool, 'prepare_instance_config') as prepare, \
                    mock.patch.object(tool, 'inherit_original_config') as inherit, \
                    mock.patch.object(tool, 'ensure_gateway_protection') as protect, \
                    mock.patch.object(tool, 'start') as start:
                tool.new_window(argparse.Namespace(dry_run=False))
                run.assert_not_called()
                prepare.assert_called_once_with(app, 3)
                inherit.assert_called_once_with(app, 3, overwrite=False)
                protect.assert_called_once_with()
                self.assertEqual(start.call_args.args[0].number, 3)
                self.assertTrue(start.call_args.args[0].new_window)

    def test_new_window_requests_route_privileges_only_when_some_gateway_is_missing(self):
        import gateway_routes as gateway
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / '.UniVPN/config'
            directory.mkdir(parents=True)
            (directory / 'test.ini').write_text('[GLOBAL]\nGatewayAddress = 8.8.8.8\n')
            with mock.patch.object(tool.Path, 'home', return_value=root), \
                    mock.patch.object(gateway, 'inspect_plan', return_value=([], {}, [{'add': True}])), \
                    mock.patch.object(tool.subprocess, 'run') as run:
                tool.ensure_gateway_protection()
                self.assertEqual(run.call_args.args[0][0], '/usr/bin/sudo')
                self.assertEqual(run.call_args.args[0][-1], 'protect')
                self.assertTrue(run.call_args.args[0][-2].endswith('/gateway_routes.py'))
            with mock.patch.object(tool.Path, 'home', return_value=root), \
                    mock.patch.object(gateway, 'inspect_plan', return_value=([], {}, [{'add': False}])), \
                    mock.patch.object(tool.subprocess, 'run') as run:
                tool.ensure_gateway_protection()
                run.assert_not_called()


class InheritOriginalTests(unittest.TestCase):
    profile = b'[GLOBAL]\niConnectionType = 1\nGatewayAddress = 192.0.2.1\nGatewayPort = 443\n'
    original = (b'[GLOBAL]\nClientName = UniVPN\n[ADVANCED]\nClientReConnectTimeValue = 0\n'
                b'[Session0]\nConnectType = 1\nRemPwd = 1\nAutoLogin = 1\nAuthType = 0\n'
                b'ProfileName = alpha.ini\nProfileUser = test-account\nProfileInfo = SEALED_RECORD\n')
    target = b'[GLOBAL]\nClientName = UVP003\n[ADVANCED]\nClientReConnectTimeValue = 5\n'

    def fixture(self, root):
        source, target = root / '.UniVPN', root / '.UVP003'
        for home in (source, target):
            home.mkdir(mode=0o700)
            (home / 'config').mkdir(mode=0o700)
        (source / 'sysconfig.ini').write_bytes(self.original)
        (source / 'config/alpha.ini').write_bytes(self.profile)
        (target / 'sysconfig.ini').write_bytes(self.target)
        (target / 'key.ini').write_bytes(b'keep-the-instance-key')
        return source, target

    def invoke(self, root, overwrite=False):
        with mock.patch.object(tool.Path, 'home', return_value=root), \
                mock.patch.object(tool, 'load_manifest'), \
                mock.patch.object(tool.os, 'geteuid', return_value=501), \
                mock.patch.object(tool, 'checked_processes', return_value=NewWindowTests.empty):
            tool.inherit_original_config(root / 'UVP003.app', 3, overwrite)

    def test_saved_credentials_and_gateway_are_copied_without_original_identity_or_autologin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target = self.fixture(root)
            self.invoke(root)
            data = (target / 'sysconfig.ini').read_bytes()
            ini = tool.parse_ini(data)
            self.assertEqual(ini.get('GLOBAL', 'ClientName'), 'UVP003')
            self.assertEqual(ini.getint('ADVANCED', 'ClientReConnectTimeValue'), 5)
            self.assertEqual(ini.get('Session0', 'ProfileUser'), 'test-account')
            self.assertEqual(ini.get('Session0', 'ProfileInfo'), 'SEALED_RECORD')
            self.assertEqual(ini.getint('Session0', 'RemPwd'), 1)
            self.assertEqual(ini.getint('Session0', 'AutoLogin'), 0)
            self.assertEqual((target / 'config/alpha.ini').read_bytes(), self.profile)
            self.assertEqual((target / 'sysconfig.ini').stat().st_mode & 0o777, 0o600)
            self.assertEqual((target / 'config/alpha.ini').stat().st_mode & 0o777, 0o600)
            self.assertEqual((target / 'key.ini').read_bytes(), b'keep-the-instance-key')
            self.assertEqual((source / 'sysconfig.ini').read_bytes(), self.original)
            self.assertEqual((source / 'config/alpha.ini').read_bytes(), self.profile)
            self.invoke(root)
            self.assertEqual((target / 'sysconfig.ini').read_bytes(), data)

    def test_existing_profile_is_preserved_unless_explicitly_synced_and_then_backed_up(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target = self.fixture(root)
            old = self.profile.replace(b'443', b'444')
            (target / 'config/alpha.ini').write_bytes(old)
            saved = self.target + b'[Session0]\nProfileName = alpha.ini\nProfileInfo = TARGET_RECORD\n'
            (target / 'sysconfig.ini').write_bytes(saved)
            self.invoke(root)
            self.assertEqual((target / 'sysconfig.ini').read_bytes(), saved)
            self.assertEqual((target / 'config/alpha.ini').read_bytes(), old)
            self.invoke(root, overwrite=True)
            self.assertEqual((target / 'config/alpha.ini').read_bytes(), self.profile)
            self.assertEqual(tool.parse_ini((target / 'sysconfig.ini').read_bytes()).get(
                'Session0', 'ProfileInfo'), 'SEALED_RECORD')
            backup = next((target / '.multi-backups').glob('inherit-original-*'))
            self.assertEqual((backup / 'sysconfig.ini').read_bytes(), saved)
            self.assertEqual((backup / 'config/alpha.ini').read_bytes(), old)

    def test_failed_copy_rolls_back_files_and_session_index(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target = self.fixture(root)
            (source / 'config/zeta.ini').write_bytes(self.profile)
            real_write = tool.atomic_write
            def fail_second_profile(path, data, mode):
                if path == target / 'config/zeta.ini':
                    raise OSError('simulated write failure')
                real_write(path, data, mode)
            with mock.patch.object(tool, 'atomic_write', side_effect=fail_second_profile):
                with self.assertRaises(OSError):
                    self.invoke(root)
            self.assertFalse((target / 'config/alpha.ini').exists())
            self.assertFalse((target / 'config/zeta.ini').exists())
            self.assertEqual((target / 'sysconfig.ini').read_bytes(), self.target)

    def test_symlinks_are_rejected_and_credentials_are_never_printed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, target = self.fixture(root)
            (source / 'config/escape.ini').symlink_to(source / 'config/alpha.ini')
            with self.assertRaises(tool.Refused):
                self.invoke(root)
            (source / 'config/escape.ini').unlink()
            with mock.patch('builtins.print') as output:
                self.invoke(root)
                text = str(output.call_args_list)
                self.assertNotIn('SEALED_RECORD', text)
                self.assertNotIn('test-account', text)

    def test_original_without_a_saved_password_keeps_the_password_empty(self):
        source = self.original.replace(b'RemPwd = 1', b'RemPwd = 0').replace(b'SEALED_RECORD', b'')
        updated, selected, remembered = tool.merge_original_sessions(
            self.target, source, [('alpha.ini', self.profile)], set())
        self.assertEqual(len(selected), 1)
        self.assertEqual(remembered, 0)
        self.assertEqual(tool.parse_ini(updated).get('Session0', 'ProfileInfo'), '')


class GuardTests(unittest.TestCase):
    def test_invalid_reconnect_timer_is_corrected_without_losing_sessions(self):
        data = (b'[ADVANCED]\r\nClientReConnectTimeValue = 0\r\nClientAutoBoot = 0\r\n'
                b'[Session0]\r\nProfileName = vpn.ini\r\nProfileUser = keep\r\n'
                b'[Other]\r\nClientReConnectTimeValue = 0\r\n')
        fixed = tool.normalize_reconnect_timer(data)
        self.assertEqual(fixed, data.replace(b'ClientReConnectTimeValue = 0',
                                            b'ClientReConnectTimeValue = 5', 1))
        self.assertEqual(tool.normalize_reconnect_timer(fixed), fixed)
        self.assertEqual(tool.parse_ini(fixed).get('Session0', 'ProfileUser'), 'keep')
        for value in (1, 5, 1440):
            valid = b'[ADVANCED]\nClientReConnectTimeValue = ' + str(value).encode() + b'\n'
            self.assertEqual(tool.normalize_reconnect_timer(valid), valid)
        missing = b'[ADVANCED]\nClientAutoBoot = 0\n'
        self.assertEqual(tool.normalize_reconnect_timer(missing), missing)
        for value in (-1, 1441):
            invalid = b'[ADVANCED]\nClientReConnectTimeValue = ' + str(value).encode() + b'\n'
            self.assertEqual(tool.parse_ini(tool.normalize_reconnect_timer(invalid)).getint(
                'ADVANCED', 'ClientReConnectTimeValue'), 5)
        with self.assertRaises(tool.Refused):
            tool.normalize_reconnect_timer(b'[ADVANCED]\nClientReConnectTimeValue = unknown\n')

    def test_recover_index_preserves_existing_settings_and_is_idempotent(self):
        data = b'[GLOBAL]\nClientName = UVP002\n[Session0]\nProfileName = existing.ini\nProfileUser = keep-me\n'
        profile = b'[GLOBAL]\niConnectionType = 1\nGatewayAddress = example.invalid\n'
        restored, added = tool.recover_session_index(data, [('existing.ini', profile), ('new.ini', profile)])
        self.assertTrue(restored.startswith(data))
        self.assertEqual(added, ['new.ini'])
        parsed = tool.parse_ini(restored)
        self.assertEqual(parsed.get('Session0', 'ProfileUser'), 'keep-me')
        self.assertEqual(parsed.get('Session1', 'ProfileName'), 'new.ini')
        self.assertEqual(parsed.getint('Session1', 'AutoLogin'), 0)
        self.assertEqual(tool.recover_session_index(restored, [('new.ini', profile)]), (restored, []))
        with self.assertRaises(tool.Refused):
            tool.recover_session_index(data, [('bad\nname.ini', profile)])

    def test_paired_config_hash_preserves_other_key_fields(self):
        key = b'[GLOBAL]\nVerifyValue = ' + b'0' * 64 + b'\nOther = keep\n[Elsewhere]\nVerifyValue = untouched\n'
        config, _ = tool.recover_session_index(b'[GLOBAL]\nClientName = UVP002\n',
                                               [('vpn.ini', b'[GLOBAL]\niConnectionType = 1\n')])
        result = tool.update_verify_value(key, tool.digest(config))
        parsed = tool.parse_ini(result)
        self.assertEqual(parsed.get('GLOBAL', 'VerifyValue'), tool.digest(config))
        self.assertEqual(parsed.get('GLOBAL', 'Other'), 'keep')
        self.assertEqual(parsed.get('Elsewhere', 'VerifyValue'), 'untouched')

    def test_only_runtime_ini_can_change_in_installed_record(self):
        app = Path(__file__).resolve().parents[1] / 'build/instance-002/UVP002.app'
        if not app.exists():
            self.skipTest('需要本地生成副本')
        baseline = tool.tree_record(app)
        changed = dict(baseline)
        changed[tool.RUNTIME_CONFIG] = {'sha256': 'changed'}
        # Mock only ownership checking on a normal-user test directory.
        with mock.patch.object(tool, 'tree_record', return_value=changed):
            tool.load_manifest(app, installed=True)
            with self.assertRaises(tool.Refused):
                tool.load_manifest(app, installed=False)
        changed['Contents/MacOS/UVP002'] = {'sha256': 'changed'}
        with mock.patch.object(tool, 'tree_record', return_value=changed):
            with self.assertRaises(tool.Refused):
                tool.load_manifest(app, installed=True)

    def test_cleanup_never_signals_a_running_tunnel_or_ui(self):
        for state in ({'ui': [1], 'helper': [2], 'backend': []},
                      {'ui': [], 'helper': [2], 'backend': [3]}):
            with mock.patch.object(tool, 'checked_processes', return_value=state), mock.patch.object(tool.os, 'kill') as kill:
                with self.assertRaises(tool.Refused):
                    tool.clean_orphan_helper(Path('/Applications/UVP002.app'), 'UVP002')
                kill.assert_not_called()

    def test_cleanup_rechecks_executable_path(self):
        state = {'ui': [], 'helper': [2], 'backend': []}
        with mock.patch.object(tool, 'checked_processes', return_value=state), \
                mock.patch.object(tool, 'process_path', return_value=Path('/Applications/UniVPN.app/Contents/MacOS/promote/UniVPNPromoteService')), \
                mock.patch.object(tool.os, 'kill') as kill:
            with self.assertRaises(tool.Refused):
                tool.clean_orphan_helper(Path('/Applications/UVP002.app'), 'UVP002')
            kill.assert_not_called()

    def test_bad_number_and_port_separation(self):
        for number in (-1, 0, 1, 1000):
            with self.assertRaises(tool.Refused):
                tool.identity(number)
        all_ports = []
        for number in range(2, 1000):
            all_ports.extend(tool.ports(number).values())
        self.assertEqual(len(all_ports), len(set(all_ports)))
        self.assertTrue(all(1024 < p < 65536 for p in all_ports))
        self.assertFalse({19060, 29191, 29192}.intersection(all_ports))

    def test_expected_bytes_and_equal_length_are_required(self):
        self.assertEqual(tool.replace_at(b'abcd', 1, b'bc', b'XY'), b'aXYd')
        for before, after in ((b'zz', b'xx'), (b'bc', b'X')):
            with self.assertRaises(tool.Refused):
                tool.replace_at(b'abcd', 1, before, after)

    def test_unsupported_binary_is_rejected(self):
        for relative in tool.SOURCE_FILES:
            with self.assertRaises(tool.Refused):
                tool.patch(b'not a vendor binary', relative, 2)

    def test_external_and_absolute_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp) / 'test.app'
            app.mkdir()
            link = app / 'escape'
            for target in ('../outside', '/System/Library'):
                link.symlink_to(target)
                with self.assertRaises(tool.Refused):
                    tool.tree_record(app)
                link.unlink()
            (app / 'file').write_text('safe')
            link.symlink_to('file')
            self.assertEqual(tool.tree_record(app)['escape'], {'link': 'file'})


@unittest.skipUnless(tool.SOURCE.exists(), '本机未安装 UniVPN；跳过真实文件只读检查')
class InstalledSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals = tool.read_source(tool.SOURCE)

    def test_real_profile_and_multiple_instance_isolation(self):
        for number in (2, 3, 999):
            assigned = tool.ports(number)
            for relative, original in self.originals.items():
                result = tool.patch(original, relative, number)
                self.assertEqual(len(result), len(original))
                self.assertNotIn(b'UniVPN', result)
                self.assertIn(tool.identity(number).encode(), result)
                if relative == 'UniVPN':
                    self.assertEqual(result[0xF5DCB:0xF5DCF], struct.pack('<I', assigned['rpc']))
                    self.assertEqual(result[0xF5E7A:0xF5E7E], struct.pack('<I', assigned['rpc']))
                    self.assertEqual(result[0xF7F4D:0xF7F51], struct.pack('<I', assigned['plugin_initial']))
                    self.assertIn(b'pkill -9 ' + tool.identity(number).encode() + b'PromoteService', result)
                    self.assertIn(b'04755', result)
                    self.assertNotIn(b'04777', result)
                elif relative.startswith('promote/'):
                    self.assertEqual(result[0x57C7:0x57CB], struct.pack('<I', assigned['rpc']))
                    self.assertIn(b'pkill -9 ' + tool.identity(number).encode() + b'CS', result)
                else:
                    self.assertEqual(result[0x11856:0x1185A], struct.pack('<I', assigned['backend_initial']))
                    self.assertNotIn(b'univpn_proxy', result)
                altered = bytearray(original)
                altered[-1] ^= 1
                with self.assertRaises(tool.Refused):
                    tool.patch(bytes(altered), relative, number)
        # Prove that memory patching did not write to source files.
        self.assertEqual(tool.read_source(tool.SOURCE), self.originals)

    def test_cold_rpc_start_is_retried_without_cross_instance_port_scan(self):
        original = self.originals['UniVPN']
        legacy = tool.patch(original, 'UniVPN', 2, revision=1)
        self.assertEqual(tool.digest(legacy), '9435548780c65eaf389cefe22a5a2007ecc18bf645f1fb3c571f5e74e8b970f2')
        current = tool.repair_payload(original, legacy, 2, revision=1)
        retry_count = current[0xF5E72]
        fallback_bound = struct.unpack_from('<I', current, 0xF5EF7)[0]
        self.assertEqual(retry_count, 15)
        self.assertEqual(fallback_bound, tool.ports(2)['rpc'])
        # Reproduce the observed listener-ready time: original tries t=0,1 and fails.
        listener_ready = 1.114
        self.assertFalse(any(t >= listener_ready for t in range(legacy[0xF5E72])))
        self.assertTrue(any(t >= listener_ready for t in range(retry_count)))
        changed = [i for i, (a, b) in enumerate(zip(legacy, current)) if a != b]
        self.assertTrue(all(i == 0xF5E72 or 0xF5EF7 <= i < 0xF5EFB for i in changed))
        with self.assertRaises(tool.Refused):
            tool.repair_payload(original, b'not the installed UI', 2, revision=1)


class GeneratedAppTests(unittest.TestCase):
    def setUp(self):
        self.app = Path(__file__).resolve().parents[1] / 'build/instance-002/UVP002.app'
        if not self.app.exists():
            self.skipTest('先运行 build --number 2 以验证生成结果')

    def test_payload_and_non_privileged_staging(self):
        record = tool.load_manifest(self.app)
        self.assertEqual(record['patch_revision'], 2)
        self.assertEqual(record['ports'], tool.ports(2))
        self.assertFalse((self.app / 'Contents/MacOS/UVP002Update').exists())
        self.assertFalse((self.app / 'Contents/MacOS/update_help').exists())
        self.assertEqual((self.app / 'Contents/MacOS/UVP002').stat().st_mode & 0o7777, 0o644)
        for path in self.app.rglob('*'):
            if not path.is_symlink():
                self.assertFalse(path.stat().st_mode & 0o6000, str(path))

    def test_tampering_is_detected_in_a_temporary_copy(self):
        # A tiny app fixture exercises the full-tree guard without copying vendor payloads.
        with tempfile.TemporaryDirectory() as temp:
            app = Path(temp) / 'UVP002.app'
            (app / 'Contents/Resources').mkdir(parents=True)
            (app / 'payload').write_text('before')
            data = json.loads((self.app / tool.MARKER).read_text())
            data['files'] = tool.tree_record(app)
            (app / tool.MARKER).write_text(json.dumps(data))
            (app / 'payload').write_text('after')
            with self.assertRaisesRegex(tool.Refused, '离线生成记录'):
                tool.load_manifest(app)


if __name__ == '__main__':
    unittest.main()
