import copy
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
            self.assertEqual(len(state['routes']), 1)
            self.assertTrue(routes.owned_match(state['routes'][0], table[0]))

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
