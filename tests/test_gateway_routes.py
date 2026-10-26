import copy
from contextlib import contextmanager
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gateway_routes as routes


class GatewayRouteTests(unittest.TestCase):
    physical = {'interface': 'en0', 'via': '192.168.1.1'}
    # Use real global addresses so the same public-address guards are exercised.
    gateways = ['8.8.8.8', '1.1.1.1']

    def test_native_table_parsing_retains_exact_prefix_and_scope(self):
        table = routes.parse_routes('''Routing tables
Internet:
Destination Gateway Flags Netif Expire
default 192.168.1.1 UGScg en0
8.8.8.8 10.0.0.1 UGH utun5
8.8.8.8/31 192.168.1.1 UGS2 en0
8.8.8.8/31 10.0.0.1 UGS2I utun5
192.168.1 link#12 UCS en0 !
''')
        found = routes.exact_route('8.8.8.8/31', table)
        self.assertEqual(found['interface'], 'en0')
        self.assertEqual(found['flags'], 'UGS2')
        self.assertEqual(table[-1]['network'], '192.168.1.0/24')
        self.assertEqual(table[0]['network'], '0.0.0.0/0')

    def test_fallback_is_distinct_from_vendor_host_route_and_does_not_change_default(self):
        current = [dict(network='0.0.0.0/0', via='10.0.0.1', interface='utun5', flags='UGS'),
                   dict(network='8.8.8.8/32', via='10.0.0.1', interface='utun5', flags='UGHS')]
        plan = routes.route_plan(self.gateways, self.physical, current)
        self.assertEqual({p['network'] for p in plan}, {'8.8.8.8/31', '1.1.1.0/31'})
        self.assertTrue(all(p['interface'] == 'en0' and p['add'] for p in plan))
        self.assertTrue(all(p['network'] != '0.0.0.0/0' for p in plan))

    def test_existing_different_route_is_never_overwritten(self):
        current = [dict(network='8.8.8.8/31', via='10.0.0.1', interface='utun5', flags='UGS')]
        with self.assertRaises(routes.Refused):
            routes.route_plan(['8.8.8.8'], self.physical, current)

    def kernel(self, existing=None):
        table = copy.deepcopy(existing or [])
        state = {'schema': 1, 'routes': []}
        operations = []
        def change(verb, item):
            operations.append((verb, copy.deepcopy(item)))
            if verb == 'add':
                table.append(dict(item, flags='UGS2'))
            elif verb == 'change':
                current = routes.exact_route(item['network'], table)
                if current is None:
                    raise routes.Refused('simulated missing route')
                current.update(item)
            else:
                table[:] = [r for r in table if not routes.owned_match(item, r)]
        def save(value):
            state.clear()
            state.update(copy.deepcopy(value))
        return table, state, operations, change, save

    def test_protect_is_idempotent_and_restore_removes_only_owned_entries(self):
        unchanged = [dict(network='0.0.0.0/0', via='10.0.0.1', interface='utun5', flags='UGS'),
                     dict(network='8.8.8.8/31', flags='UGS', **self.physical)]
        table, state, ops, change, save = self.kernel(unchanged)
        plan = routes.route_plan(self.gateways, self.physical, table)
        with mock.patch.object(routes, 'route_table', side_effect=lambda: copy.deepcopy(table)), \
                mock.patch.object(routes, 'load_state', side_effect=lambda: copy.deepcopy(state)), \
                mock.patch.object(routes, 'save_state', side_effect=save), \
                mock.patch.object(routes, 'change_route', side_effect=change):
            routes.protect(plan)
            routes.protect(plan)
            self.assertEqual(len([op for op in ops if op[0] == 'add']), 1)
            routes.restore()
            self.assertEqual(table, unchanged)
            self.assertEqual(state['routes'], [])

    def test_partial_failure_rolls_back_only_new_entries(self):
        unchanged = [dict(network='0.0.0.0/0', via='10.0.0.1', interface='utun5', flags='UGS')]
        table, state, ops, change, save = self.kernel(unchanged)
        plan = routes.route_plan(self.gateways, self.physical, table)
        def fail_second(verb, item):
            if verb == 'add' and item['network'] == '8.8.8.8/31':
                raise routes.Refused('simulated route failure')
            change(verb, item)
        with mock.patch.object(routes, 'route_table', side_effect=lambda: copy.deepcopy(table)), \
                mock.patch.object(routes, 'load_state', side_effect=lambda: copy.deepcopy(state)), \
                mock.patch.object(routes, 'save_state', side_effect=save), \
                mock.patch.object(routes, 'change_route', side_effect=fail_second):
            with self.assertRaises(routes.Refused):
                routes.protect(plan)
            self.assertEqual(table, unchanged)
            self.assertEqual(state['routes'], [])
            self.assertTrue(all(item['network'] != '0.0.0.0/0' for _, item in ops))

    def test_restore_refuses_unmarked_or_changed_route(self):
        item = dict(network='8.8.8.8/31', **self.physical)
        for current in (dict(item, flags='UGS'), dict(item, via='10.0.0.1', flags='UGS2')):
            with mock.patch.object(routes, 'load_state', return_value={'schema': 1, 'routes': [item]}), \
                    mock.patch.object(routes, 'route_table', return_value=[current]), \
                    mock.patch.object(routes, 'change_route') as change:
                with self.assertRaises(routes.Refused):
                    routes.restore()
                change.assert_not_called()

    def test_failed_rollback_keeps_recovery_record_for_remaining_route(self):
        table, state, ops, change, save = self.kernel()
        plan = routes.route_plan(self.gateways, self.physical, table)
        def fail(verb, item):
            if verb == 'delete' or item['network'] == '8.8.8.8/31':
                raise routes.Refused('simulated failure')
            change(verb, item)
        with mock.patch.object(routes, 'route_table', side_effect=lambda: copy.deepcopy(table)), \
                mock.patch.object(routes, 'load_state', side_effect=lambda: copy.deepcopy(state)), \
                mock.patch.object(routes, 'save_state', side_effect=save), \
                mock.patch.object(routes, 'change_route', side_effect=fail):
            with self.assertRaises(routes.Refused):
                routes.protect(plan)
            self.assertEqual(len(table), 1)
            self.assertEqual(len(state['pending']), 1)
            self.assertTrue(routes.owned_match(state['pending'][0]['after'], table[0]))
            # A retry reconciles the persisted intent and can remove the route.
            with mock.patch.object(routes, 'change_route', side_effect=change):
                routes.restore()
            self.assertEqual(table, [])
            self.assertEqual(state['routes'], [])

    @contextmanager
    def managed_kernel(self, existing, records):
        table, state, ops, change, save = self.kernel(existing)
        state['routes'] = copy.deepcopy(records)
        with mock.patch.object(routes, 'route_table', side_effect=lambda: copy.deepcopy(table)), \
                mock.patch.object(routes, 'load_state', side_effect=lambda: copy.deepcopy(state)), \
                mock.patch.object(routes, 'save_state', side_effect=save), \
                mock.patch.object(routes, 'change_route', side_effect=change), \
                mock.patch.object(routes, 'on_link', return_value=True):
            yield table, state, ops, change, save

    def old_routes(self):
        return [dict(network=network, via='192.168.0.1', interface='en0')
                for network in ('1.1.1.0/31', '8.8.8.8/31')]

    def test_owned_old_gateway_is_migrated_and_restore_uses_the_new_exit(self):
        old = self.old_routes()
        unrelated = dict(network='0.0.0.0/0', via='10.0.0.1', interface='utun5', flags='UGS')
        with self.managed_kernel([unrelated, *[dict(item, flags='UGS2') for item in old]], old) as kernel:
            table, state, ops, _, _ = kernel
            plan = routes.route_plan(self.gateways, self.physical, table)
            self.assertTrue(all(item.get('refresh') and not item['add'] for item in plan))
            routes.protect(plan)
            self.assertEqual([verb for verb, _ in ops], ['change', 'change'])
            self.assertTrue(all(item['via'] == self.physical['via'] for item in state['routes']))
            self.assertNotIn('pending', state)
            routes.protect(routes.route_plan(self.gateways, self.physical, table))
            self.assertEqual(len(ops), 2)
            routes.restore()
            self.assertEqual(table, [unrelated])
            self.assertEqual(state['routes'], [])

    def test_migration_can_change_physical_interface(self):
        old = self.old_routes()[:1]
        new_physical = dict(via='192.168.2.1', interface='en1')
        with self.managed_kernel([dict(old[0], flags='UGS2')], old) as kernel:
            table, state, _, _, _ = kernel
            routes.protect(routes.route_plan(['1.1.1.1'], new_physical, table))
            self.assertEqual(table[0]['interface'], 'en1')
            self.assertEqual(state['routes'][0]['via'], '192.168.2.1')

    def test_proto2_marker_without_matching_private_record_is_never_adopted(self):
        old = self.old_routes()[:1]
        for records in ([], [dict(old[0], via='192.168.9.1')]):
            with self.managed_kernel([dict(old[0], flags='UGS2')], records) as kernel:
                table, state, ops, _, _ = kernel
                # Includes a missing prefix too: refuse before adding any route.
                with self.assertRaisesRegex(routes.Refused, '有效恢复记录'):
                    routes.protect(routes.route_plan(self.gateways, self.physical, table))
                self.assertEqual(ops, [])
                self.assertEqual(state['routes'], records)

    def test_ownership_record_without_kernel_marker_is_not_sufficient(self):
        old = self.old_routes()[:1]
        with self.managed_kernel([dict(old[0], flags='UGS')], old) as kernel:
            _, _, ops, _, _ = kernel
            plan = [dict(network=old[0]['network'], **self.physical, add=False, refresh=True)]
            with self.assertRaises(routes.Refused):
                routes.protect(plan)
            self.assertEqual(ops, [])

    def test_new_router_must_be_directly_reachable_before_migration(self):
        old = self.old_routes()
        with self.managed_kernel([dict(item, flags='UGS2') for item in old], old) as kernel:
            table, state, ops, _, _ = kernel
            with mock.patch.object(routes, 'on_link', return_value=False):
                with self.assertRaisesRegex(routes.Refused, '直连'):
                    routes.protect(routes.route_plan(self.gateways, self.physical, table))
            self.assertEqual(ops, [])
            self.assertNotIn('pending', state)

    def test_second_migration_failure_restores_old_exits_and_private_record(self):
        old = self.old_routes()
        with self.managed_kernel([dict(item, flags='UGS2') for item in old], old) as kernel:
            table, state, ops, change, _ = kernel
            before = copy.deepcopy(table)
            def fail_second(verb, item):
                # The full intention must already be durable before any change.
                self.assertEqual(len(state['pending']), 2)
                if verb == 'change' and item['network'] == old[1]['network'] and item['via'] == self.physical['via']:
                    raise routes.Refused('simulated migration failure')
                change(verb, item)
            with mock.patch.object(routes, 'change_route', side_effect=fail_second):
                with self.assertRaises(routes.Refused):
                    routes.protect(routes.route_plan(self.gateways, self.physical, table))
            self.assertEqual(table, before)
            self.assertCountEqual(state['routes'], old)
            self.assertNotIn('pending', state)
            self.assertEqual([verb for verb, _ in ops], ['change', 'change'])

    def test_failed_add_after_migration_also_rolls_back_the_migration(self):
        old = self.old_routes()[:1]
        with self.managed_kernel([dict(old[0], flags='UGS2')], old) as kernel:
            table, state, _, change, _ = kernel
            def fail_add(verb, item):
                if verb == 'add':
                    raise routes.Refused('simulated add failure')
                change(verb, item)
            with mock.patch.object(routes, 'change_route', side_effect=fail_add):
                with self.assertRaises(routes.Refused):
                    routes.protect(routes.route_plan(self.gateways, self.physical, table))
            self.assertEqual(table, [dict(old[0], flags='UGS2')])
            self.assertEqual(state['routes'], old)

    def test_failed_migration_rollback_leaves_intent_that_restore_can_reconcile(self):
        old = self.old_routes()
        with self.managed_kernel([dict(item, flags='UGS2') for item in old], old) as kernel:
            table, state, _, change, _ = kernel
            def fail(verb, item):
                if item['network'] == old[1]['network'] or item['via'] == old[0]['via']:
                    raise routes.Refused('simulated failure')
                change(verb, item)
            with mock.patch.object(routes, 'change_route', side_effect=fail):
                with self.assertRaisesRegex(routes.Refused, '未能安全回滚'):
                    routes.protect(routes.route_plan(self.gateways, self.physical, table))
            self.assertTrue(state['pending'])
            routes.restore()
            self.assertEqual(table, [])
            self.assertEqual(state['routes'], [])

    def test_interrupted_migration_with_mixed_old_and_new_exits_can_be_restored(self):
        old = self.old_routes()
        new = [dict(item, **self.physical) for item in old]
        current = [dict(new[0], flags='UGS2'), dict(old[1], flags='UGS2')]
        with self.managed_kernel(current, old) as kernel:
            table, state, _, _, _ = kernel
            state['pending'] = [{'before': a, 'after': b} for a, b in zip(old, new)]
            routes.restore()
            self.assertEqual(table, [])
            self.assertEqual(state['routes'], [])
            self.assertNotIn('pending', state)

    def test_pending_intent_does_not_authorize_deleting_a_foreign_route(self):
        old = self.old_routes()[:1]
        current = [dict(old[0], via='192.168.8.1', flags='UGS2')]
        with self.managed_kernel(current, old) as kernel:
            _, state, ops, _, _ = kernel
            state['pending'] = [{'before': old[0], 'after': dict(old[0], **self.physical)}]
            before = copy.deepcopy(state)
            with self.assertRaisesRegex(routes.Refused, '其他程序修改'):
                routes.restore()
            self.assertEqual(ops, [])
            self.assertEqual(state, before)

    def test_route_replaced_after_preflight_is_not_changed(self):
        old = self.old_routes()[:1]
        with self.managed_kernel([dict(old[0], flags='UGS2')], old) as kernel:
            table, state, ops, _, _ = kernel
            plan = routes.route_plan(['1.1.1.1'], self.physical, table)
            snapshots = [copy.deepcopy(table), [dict(old[0], via='192.168.8.1', flags='UGS')]]
            with mock.patch.object(routes, 'route_table', side_effect=snapshots):
                with self.assertRaisesRegex(routes.Refused, '归属检查后发生变化'):
                    routes.protect(plan)
            self.assertEqual(ops, [])

    def test_change_command_retains_marker_and_selects_the_physical_interface(self):
        item = dict(self.old_routes()[0], **self.physical)
        with mock.patch.object(routes, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as run:
            routes.change_route('change', item)
        self.assertEqual(run.call_args.args[0], ['/sbin/route', '-n', 'change', '-net', item['network'],
                                               item['via'], '-ifp', 'en0', '-static', '-proto2'])

    def test_write_ahead_save_failure_never_changes_the_kernel(self):
        old = self.old_routes()[:1]
        with self.managed_kernel([dict(old[0], flags='UGS2')], old) as kernel:
            table, _, ops, _, _ = kernel
            with mock.patch.object(routes, 'save_state', side_effect=OSError('simulated disk failure')):
                with self.assertRaises(routes.Refused):
                    routes.protect(routes.route_plan(['1.1.1.1'], self.physical, table))
            self.assertEqual(ops, [])
            self.assertEqual(table, [dict(old[0], flags='UGS2')])

    def test_post_change_save_failure_rolls_back_with_the_intention_still_durable(self):
        old = self.old_routes()[:1]
        with self.managed_kernel([dict(old[0], flags='UGS2')], old) as kernel:
            table, state, _, _, save = kernel
            calls = 0
            def fail_after_change(value):
                nonlocal calls
                calls += 1
                if calls == 2:
                    self.assertTrue(state['pending'])
                    raise OSError('simulated disk failure after kernel change')
                save(value)
            with mock.patch.object(routes, 'save_state', side_effect=fail_after_change):
                with self.assertRaises(OSError):
                    routes.protect(routes.route_plan(['1.1.1.1'], self.physical, table))
            self.assertEqual(table, [dict(old[0], flags='UGS2')])
            self.assertEqual(state['routes'], old)
            self.assertNotIn('pending', state)

    def test_root_protect_recomputes_the_plan_inside_the_lock(self):
        held = False
        @contextmanager
        def lock():
            nonlocal held
            held = True
            try:
                yield
            finally:
                held = False
        def inspect(*args):
            self.assertTrue(held)
            return [], self.physical, []
        def protect(plan):
            self.assertTrue(held)
        with mock.patch.object(sys, 'argv', ['gateway_routes.py', 'protect']), \
                mock.patch.object(sys, 'platform', 'darwin'), \
                mock.patch.object(routes.os, 'geteuid', return_value=0), \
                mock.patch.dict(routes.os.environ, {'SUDO_UID': '501'}), \
                mock.patch.object(routes.pwd, 'getpwuid', return_value=mock.Mock(pw_dir='/tmp/test-user')), \
                mock.patch.object(routes, 'route_lock', side_effect=lock), \
                mock.patch.object(routes, 'inspect_plan', side_effect=inspect) as detection, \
                mock.patch.object(routes, 'protect', side_effect=protect):
            routes.main()
            detection.assert_called_once()

    def test_private_state_accepts_legacy_and_valid_journals_but_refuses_bad_entries(self):
        old = self.old_routes()[:1]
        legacy = {'schema': 1, 'routes': old}
        pending = dict(legacy, pending=[{'before': old[0], 'after': dict(old[0], **self.physical)}])
        attrs = mock.Mock(st_mode=0o100600, st_uid=0, st_nlink=1)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'state.json'
            with mock.patch.object(routes, 'STATE', path), \
                    mock.patch.object(Path, 'lstat', return_value=attrs):
                for record in (legacy, pending):
                    path.write_text(json.dumps(record))
                    self.assertEqual(routes.load_state(), record)
                bad = copy.deepcopy(pending)
                bad['pending'][0]['after']['network'] = '9.9.9.8/31'
                for record in (bad, dict(legacy, pending=[{'after': old[0]}]),
                               dict(legacy, routes=[dict(old[0], via=123)])):
                    path.write_text(json.dumps(record))
                    with self.assertRaises(routes.Refused):
                        routes.load_state()

    def test_full_tunnel_default_does_not_get_selected_as_physical_uplink(self):
        def result(argv):
            if argv[0].endswith('networksetup'):
                out = 'Device: en0\nDevice: en1\n'
            elif '-ifscope' in argv and 'en0' in argv:
                out = 'gateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,STATIC>\n'
            elif '-ifscope' in argv:
                return subprocess.CompletedProcess(argv, 1, '', 'no route')
            else:
                out = 'gateway: 10.0.0.1\ninterface: utun5\n'
            return subprocess.CompletedProcess(argv, 0, out, '')
        with mock.patch.object(routes, 'run', side_effect=result):
            self.assertEqual(routes.uplink(), self.physical)
            with self.assertRaises(routes.Refused):
                routes.uplink('utun5')

    def test_private_gateways_and_symlink_profiles_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            folder = home / '.UniVPN/config'
            folder.mkdir(parents=True)
            file = folder / 'test.ini'
            file.write_text('[GLOBAL]\nGatewayAddress = 192.168.1.20\n')
            with self.assertRaises(routes.Refused):
                routes.public_gateways(home, ['test.ini'])
            file.write_text('[GLOBAL]\nGatewayAddress = 8.8.8.8\n')
            self.assertEqual(routes.public_gateways(home, ['test.ini']), ['8.8.8.8'])
            (folder / 'link.ini').symlink_to(file)
            with self.assertRaises(routes.Refused):
                routes.public_gateways(home, ['link.ini'])

    def test_gateway_discovery_includes_every_saved_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            folder = home / '.UniVPN/config'
            folder.mkdir(parents=True)
            addresses = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '208.67.222.222']
            for number, address in enumerate(addresses):
                (folder / f'gateway-{number}.ini').write_text('[GLOBAL]\nGatewayAddress = ' + address + '\n')
            self.assertEqual(set(routes.public_gateways(home)), set(addresses))
            self.assertEqual(routes.public_gateways(home, ['gateway-2.ini']), ['9.9.9.9'])

    def test_extending_to_four_gateways_preserves_two_existing_protected_routes(self):
        addresses = self.gateways + ['9.9.9.9', '208.67.222.222']
        existing = [dict(item, flags='UGS2') for item in routes.route_plan(self.gateways, self.physical, [])]
        # Strip the planner-only add marker from the kernel fixture.
        for item in existing:
            item.pop('add')
        table, state, ops, change, save = self.kernel(existing)
        state['routes'] = [{k: item[k] for k in ('network', 'via', 'interface')} for item in existing]
        with mock.patch.object(routes, 'route_table', side_effect=lambda: copy.deepcopy(table)), \
                mock.patch.object(routes, 'load_state', side_effect=lambda: copy.deepcopy(state)), \
                mock.patch.object(routes, 'save_state', side_effect=save), \
                mock.patch.object(routes, 'change_route', side_effect=change):
            routes.protect(routes.route_plan(addresses, self.physical, table))
            self.assertEqual(len(state['routes']), 4)
            self.assertEqual([verb for verb, _ in ops], ['add', 'add'])
            self.assertEqual(table[:2], existing)

    def test_existing_protection_supplies_on_link_gateway_when_physical_default_is_gone(self):
        current = [dict(network='8.8.8.8/31', flags='UGS2', **self.physical)]
        good = subprocess.CompletedProcess([], 0, 'interface: en0\nflags: <UP,HOST,DONE,LLINFO>\n', '')
        bad = subprocess.CompletedProcess([], 0, 'interface: utun5\nflags: <UP,GATEWAY,DONE>\n', '')
        with mock.patch.object(routes, 'run', return_value=good):
            self.assertEqual(routes.protected_uplink(self.gateways, current), self.physical)
        with mock.patch.object(routes, 'run', return_value=bad):
            with self.assertRaises(routes.Refused):
                routes.protected_uplink(self.gateways, current)


if __name__ == '__main__':
    unittest.main()
