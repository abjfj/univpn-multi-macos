#!/usr/bin/env python3
"""Protect VPN transport gateways from another tunnel's default-route takeover."""
import argparse
import fcntl
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from contextlib import contextmanager

from univpn_multi import Refused, atomic_write, parse_ini

STATE = Path('/var/run/univpn-multi-gateway-routes.json')


@contextmanager
def route_lock():
    descriptor = os.open(STATE.with_suffix('.lock'), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        attrs = os.fstat(descriptor)
        if not stat.S_ISREG(attrs.st_mode) or attrs.st_uid != 0 or attrs.st_nlink != 1 or attrs.st_mode & 0o077:
            raise Refused('路由锁文件权限异常。')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('另一个路由修复或撤销命令正在运行，请稍后重试。') from None
        yield
    finally:
        os.close(descriptor)


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True)


def fields(output):
    return {key.strip(): value.strip() for line in output.splitlines()
            if ':' in line for key, value in [line.split(':', 1)]}


def uplink(interface=None):
    if interface is not None and not re.fullmatch(r'en\d+', interface):
        raise Refused('物理出口必须为 en0 等以太网/Wi-Fi 接口，不能指定 utun。')
    devices = [interface] if interface else re.findall(
        r'(?m)^Device: (en\d+)$', run(['/usr/sbin/networksetup', '-listallhardwareports']).stdout)
    choices = []
    for device in dict.fromkeys(devices):
        result = run(['/sbin/route', '-n', 'get', '-ifscope', device, 'default'])
        info = fields(result.stdout)
        if result.returncode or info.get('interface') != device or 'UP' not in info.get('flags', ''):
            continue
        try:
            gateway = ipaddress.IPv4Address(info.get('gateway', ''))
        except ipaddress.AddressValueError:
            continue
        if gateway.is_unspecified or gateway.is_loopback or gateway.is_multicast:
            continue
        choices.append({'interface': device, 'via': str(gateway)})
    current = fields(run(['/sbin/route', '-n', 'get', 'default']).stdout).get('interface')
    preferred = [choice for choice in choices if choice['interface'] == current]
    if len(preferred) == 1:
        return preferred[0]
    if len(choices) != 1:
        raise Refused('无法唯一确定物理出口；请用 --interface en0 指定当前 Wi-Fi/以太网接口。')
    return choices[0]


def numeric_network(destination):
    if destination == 'default':
        return '0.0.0.0/0'
    address, separator, bits = destination.partition('/')
    octets = address.split('.')
    if not 1 <= len(octets) <= 4 or not all(part.isdigit() for part in octets):
        raise ValueError('not an IPv4 destination')
    width = int(bits) if separator else len(octets) * 8
    return str(ipaddress.IPv4Network('.'.join(octets + ['0'] * (4 - len(octets))) + f'/{width}', strict=False))


def parse_routes(output):
    routes, columns = [], None
    for line in output.splitlines():
        row = line.split()
        if 'Destination' in row and 'Netif' in row:
            columns = {name: row.index(name) for name in ('Destination', 'Gateway', 'Flags', 'Netif')}
            continue
        if not columns or len(row) <= max(columns.values()):
            continue
        try:
            network = numeric_network(row[columns['Destination']])
        except ValueError:
            continue
        routes.append({'network': network, 'via': row[columns['Gateway']],
                       'interface': row[columns['Netif']], 'flags': row[columns['Flags']]})
    if columns is None:
        raise Refused('无法识别本机 IPv4 路由表格式，未修改。')
    return routes


def route_table():
    result = run(['/usr/sbin/netstat', '-rn', '-f', 'inet'])
    if result.returncode:
        raise Refused('读取 IPv4 路由表失败。')
    return parse_routes(result.stdout)


def exact_route(network, routes):
    matches = [route for route in routes if route['network'] == network and 'I' not in route['flags']]
    if len(matches) > 1:
        raise Refused('存在多个同前缀全局路由，未猜测或覆盖。')
    return matches[0] if matches else None


def public_gateways(home, names=None):
    directory = home / '.UniVPN/config'
    if any(p.is_symlink() or not p.is_dir() for p in (directory.parent, directory)):
        raise Refused('原版网关目录必须是实际目录。')
    if names is None:
        names = [p.name for p in sorted(directory.glob('*.ini'))]
    if not names:
        raise Refused('原版尚未保存网关配置。')
    result = []
    for name in names:
        if Path(name).name != name or not name.endswith('.ini'):
            raise Refused('请只传入原版 config 目录中的 INI 文件名。')
        path = directory / name
        attrs = path.lstat()
        if not stat.S_ISREG(attrs.st_mode) or attrs.st_nlink != 1:
            raise Refused('网关配置必须是独立普通文件。')
        # No credential fields are printed or copied into the route state.
        try:
            config = parse_ini(path.read_bytes())
            address = ipaddress.IPv4Address(config.get('GLOBAL', 'GatewayAddress'))
        except Exception:
            raise Refused('此修复仅接受配置中明确指定的 IPv4 公网网关。') from None
        if not address.is_global or address.is_multicast:
            raise Refused('此修复仅处理公网网关，不改动私网目标或域名解析。')
        result.append(str(address))
    return sorted(set(result))


def protected_uplink(addresses, routes, interface=None):
    """Recover the physical exit when a full tunnel removes its default route."""
    if interface is not None and not re.fullmatch(r'en\d+', interface):
        raise Refused('物理出口不能为 utun。')
    prefixes = {str(ipaddress.IPv4Network(ip + '/31', strict=False)) for ip in addresses}
    candidates = {(r['interface'], r['via']) for r in routes
                  if r['network'] in prefixes and '2' in r['flags'] and 'I' not in r['flags']
                  and re.fullmatch(r'en\d+', r['interface'])
                  and (interface is None or interface == r['interface'])}
    valid = []
    for device, gateway in candidates:
        try:
            ipaddress.IPv4Address(gateway)
        except ipaddress.AddressValueError:
            continue
        if on_link({'interface': device, 'via': gateway}):
            valid.append({'interface': device, 'via': gateway})
    if len(valid) != 1:
        raise Refused('无法从现有保护路由验证物理出口；请指定当前物理网卡或先检查网络。')
    return valid[0]


def on_link(physical):
    """Verify the router belongs to the physical link, not a route through a VPN."""
    result = run(['/sbin/route', '-n', 'get', '-ifscope', physical['interface'], physical['via']])
    info = fields(result.stdout)
    flags = info.get('flags', '')
    return (not result.returncode and info.get('interface') == physical['interface']
            and 'UP' in flags and 'GATEWAY' not in flags)


def inspect_plan(home, names=None, interface=None):
    addresses = public_gateways(home, names)
    current = route_table()
    try:
        physical = uplink(interface)
    except Refused:
        physical = protected_uplink(addresses, current, interface)
    return addresses, physical, route_plan(addresses, physical, current)


def route_plan(addresses, physical, routes):
    plan = []
    # The vendor removes its /32 on every route-monitor refresh. A distinct /31
    # remains a physical fallback while that /32 is absent, covering one neighbour.
    for network in sorted({str(ipaddress.IPv4Network(address + '/31', strict=False)) for address in addresses}):
        item = dict(network=network, **physical)
        existing = exact_route(network, routes)
        if existing and any(existing[key] != item[key] for key in ('via', 'interface')):
            if '2' not in existing['flags'] or not re.fullmatch(r'en\d+', existing['interface']):
                raise Refused(f'{network} 已有不同出口的非保护路由，拒绝覆盖；请先检查现有网络配置。')
            # Normal users cannot read the root-private ownership record. This is
            # only a preview; protect must verify that record before changing it.
            item['refresh'] = True
        item['add'] = existing is None
        plan.append(item)
    return plan


def owned_match(item, current):
    return bool(current and '2' in current['flags'] and all(
        current[key] == item[key] for key in ('network', 'via', 'interface')))


def load_state():
    if not STATE.exists() and not STATE.is_symlink():
        return {'schema': 1, 'routes': []}
    attrs = STATE.lstat()
    if not stat.S_ISREG(attrs.st_mode) or attrs.st_nlink != 1 or attrs.st_uid != 0 or attrs.st_mode & 0o077:
        raise Refused('路由恢复记录的类型、所有权或私有权限异常。')
    data = json.loads(STATE.read_bytes())
    if not isinstance(data, dict) or data.get('schema') != 1 or not isinstance(data.get('routes'), list):
        raise Refused('路由恢复记录格式不受支持。')
    pending = data.get('pending', [])
    if not isinstance(pending, list):
        raise Refused('路由迁移恢复记录格式不受支持。')
    entries = list(data['routes'])
    for operation in pending:
        if (not isinstance(operation, dict) or set(operation) != {'before', 'after'}
                or not isinstance(operation.get('after'), dict)):
            raise Refused('路由迁移恢复记录格式不受支持。')
        if operation.get('before') is not None:
            if not isinstance(operation['before'], dict) or operation['before'].get('network') != operation['after'].get('network'):
                raise Refused('路由迁移前后前缀不一致。')
            entries.append(operation['before'])
        entries.append(operation['after'])
    for route in entries:
        if (not isinstance(route, dict) or set(route) != {'network', 'via', 'interface'}
                or not all(isinstance(value, str) for value in route.values())):
            raise Refused('路由恢复条目的字段格式异常。')
        network = ipaddress.IPv4Network(route['network'])
        if network.prefixlen != 31 or not network.network_address.is_global or not network.broadcast_address.is_global:
            raise Refused('恢复记录包含公网 /31 以外的路由。')
        ipaddress.IPv4Address(route['via'])
        if not re.fullmatch(r'en\d+', route['interface']):
            raise Refused('恢复记录包含非物理出口。')
    return data


def save_state(state):
    atomic_write(STATE, (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode(), 0o600)


def change_route(verb, item):
    argv = ['/sbin/route', '-n', verb, '-net', item['network'], item['via'], '-ifp', item['interface']]
    if verb in ('add', 'change'):
        argv += ['-static', '-proto2']
    result = run(argv)
    if result.returncode:
        raise Refused(f'网关回退路由 {verb} 失败：{result.stderr.strip() or result.stdout.strip()}')


def route_entry(item):
    return {key: item[key] for key in ('network', 'via', 'interface')}


def record_route(state, network, entry):
    state['routes'] = [item for item in state['routes'] if item['network'] != network]
    if entry is not None:
        state['routes'].append(entry)


def settle_pending(state):
    """Reconcile write-ahead intentions after interruption, without changing routes."""
    pending = state.get('pending', [])
    for operation in pending:
        old, new = operation['before'], operation['after']
        current = exact_route(new['network'], route_table())
        if owned_match(new, current):
            record_route(state, new['network'], new)
        elif old is not None and owned_match(old, current):
            record_route(state, old['network'], old)
        elif current is None:
            record_route(state, new['network'], None)
        else:
            raise Refused('待恢复的保护路由已被其他程序修改，未自动处理；迁移记录保持不变。')
    if pending:
        state.pop('pending')
        save_state(state)


def protect(plan):
    state = load_state()
    settle_pending(state)
    before = json.loads(json.dumps(state))
    operations = []
    # Validate every conflict before modifying even the first route. A PROTO2
    # marker alone is insufficient: its exact current exit must be in our state.
    for item in plan:
        new = route_entry(item)
        current = exact_route(new['network'], route_table())
        if current and all(current[key] == new[key] for key in ('via', 'interface')):
            continue
        old = route_entry(current) if current else None
        if current and (old not in state['routes'] or not owned_match(old, current)):
            raise Refused(f'{new["network"]} 的旧出口不属于本工具的有效恢复记录，拒绝覆盖。')
        operations.append({'before': old, 'after': new})
    targets = {(op['after']['interface'], op['after']['via']) for op in operations if op['before'] is not None}
    for device, gateway in targets:
        if not on_link({'interface': device, 'via': gateway}):
            raise Refused('无法确认新物理网关在当前网卡直连，未迁移保护路由。')
    attempted = []
    try:
        if operations:
            # Keep the whole transaction until its final save, including during
            # rollback. A crash can leave any mix of old/new exits in the kernel.
            state['pending'] = operations
            save_state(state)
        for operation in operations:
            old, new = operation['before'], operation['after']
            current = exact_route(new['network'], route_table())
            if (old is None and current is not None) or (old is not None and not owned_match(old, current)):
                raise Refused('保护路由在归属检查后发生变化，停止修改。')
            attempted.append(operation)
            change_route('change' if old else 'add', new)
            if not owned_match(new, exact_route(new['network'], route_table())):
                raise Refused('保护路由的出口或所有权标记校验失败。')
            record_route(state, new['network'], new)
            save_state(state)
        if operations:
            state.pop('pending')
            save_state(state)
    except BaseException as error:
        recovery = json.loads(json.dumps(before))
        remaining = []
        for operation in reversed(attempted):
            old, new = operation['before'], operation['after']
            try:
                current = exact_route(new['network'], route_table())
                if owned_match(new, current):
                    change_route('change' if old else 'delete', old or new)
                elif current is None and old is not None:
                    change_route('add', old)
                current = exact_route(new['network'], route_table())
                if old is not None and owned_match(old, current):
                    record_route(recovery, old['network'], old)
                elif current is None:
                    record_route(recovery, new['network'], None)
                    if old is not None:
                        remaining.append(operation)
                elif owned_match(new, current):
                    record_route(recovery, new['network'], new)
                    remaining.append(operation)
                else:
                    recovery.setdefault('pending', []).append(operation)
                    remaining.append(operation)
            except (Refused, OSError):
                recovery.setdefault('pending', []).append(operation)
                remaining.append(operation)
        try:
            save_state(recovery)
        except OSError as save_error:
            raise Refused(f'回滚后未能保存恢复结果；请先检查 {STATE} 中的现有恢复记录。') from save_error
        if remaining:
            raise Refused(f'部分路由未能安全回滚，恢复记录保留在 {STATE}，请先检查再 protect 或 restore。') from error
        raise
    added = sum(op['before'] is None for op in operations)
    migrated = len(operations) - added
    print(f'物理出口保护已检查，共 {len(plan)} 条 /31；本次新增 {added} 条，迁移旧出口 {migrated} 条。')


def restore():
    state = load_state()
    settle_pending(state)
    # Validate all entries before deleting any, so unrelated changed routes are retained.
    for item in state['routes']:
        current = exact_route(item['network'], route_table())
        if current and not owned_match(item, current):
            raise Refused('已记录路由已被其他程序修改，未删除；请先检查。')
    for item in list(state['routes']):
        if owned_match(item, exact_route(item['network'], route_table())):
            change_route('delete', item)
        state['routes'].remove(item)
        save_state(state)
    print('已撤销本工具记录的网关回退路由。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inspect', 'protect', 'restore'))
    parser.add_argument('--interface', help='物理网卡，例如 en0；通常自动检测')
    parser.add_argument('--profile', action='append', help='原版 INI 文件名；可重复，默认处理所有已保存的网关')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise Refused('此工具仅支持 macOS。')
    if args.command in ('protect', 'restore') and os.geteuid() != 0:
        raise Refused('修改路由需要 sudo；inspect 可直接运行。')
    if args.command == 'restore':
        with route_lock():
            restore()
        return
    uid = int(os.environ.get('SUDO_UID', '-1')) if os.geteuid() == 0 else os.getuid()
    if uid <= 0:
        raise Refused('请从登录用户通过 sudo 运行，以确定原版配置目录。')
    home = Path(pwd.getpwuid(uid).pw_dir)
    if args.command == 'protect':
        # Recompute inside the lock, after sudo, rather than using a stale plan
        # from before the user entered their administrator password.
        with route_lock():
            addresses, physical, plan = inspect_plan(home, args.profile, args.interface)
            protect(plan)
        return
    addresses, physical, plan = inspect_plan(home, args.profile, args.interface)
    print(f'物理出口：{physical["interface"]}；{len(addresses)} 个网关共用 {len(plan)} 条 /31 回退路由。每条额外包含一个相邻公网 IP。')
    for item in plan:
        status = '旧出口：待提权核对归属并迁移' if item.get('refresh') else ('待添加' if item['add'] else '已有，无需添加')
        print(f'{item["network"]} -> {item["via"]} ({item["interface"]})：{status}')
    print('仅检查，未修改路由、默认出口、VPN 或 DNS。')


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError) as error:
        print(f'停止：{error}', file=sys.stderr)
        sys.exit(1)
