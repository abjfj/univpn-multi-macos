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
        result = run(['/sbin/route', '-n', 'get', '-ifscope', device, gateway])
        info = fields(result.stdout)
        # Only accept an on-link router, not a route to an old router through a VPN.
        flags = info.get('flags', '')
        if not result.returncode and info.get('interface') == device and 'UP' in flags and 'GATEWAY' not in flags:
            valid.append({'interface': device, 'via': gateway})
    if len(valid) != 1:
        raise Refused('无法从现有保护路由验证物理出口；请指定当前物理网卡或先检查网络。')
    return valid[0]


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
            raise Refused('所需 /31 已有不同出口的路由，拒绝覆盖；请先检查现有网络配置。')
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
    if data.get('schema') != 1 or not isinstance(data.get('routes'), list):
        raise Refused('路由恢复记录格式不受支持。')
    for route in data['routes']:
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
    if verb == 'add':
        argv += ['-static', '-proto2']
    result = run(argv)
    if result.returncode:
        raise Refused(f'网关回退路由 {verb} 失败：{result.stderr.strip() or result.stdout.strip()}')


def protect(plan):
    state = load_state()
    before = json.loads(json.dumps(state))
    added = []
    try:
        for item in plan:
            current = exact_route(item['network'], route_table())
            if current:
                if any(current[key] != item[key] for key in ('via', 'interface')):
                    raise Refused('路由在检查后发生变化，停止添加。')
                continue
            entry = {key: item[key] for key in ('network', 'via', 'interface')}
            change_route('add', entry)
            added.append(entry)
            if entry not in state['routes']:
                state['routes'].append(entry)
            save_state(state)
            if not owned_match(entry, exact_route(entry['network'], route_table())):
                raise Refused('新增路由的出口或所有权标记校验失败。')
    except BaseException as error:
        # Roll back only entries actually added by this invocation and still marked ours.
        remaining = []
        for item in reversed(added):
            try:
                current = exact_route(item['network'], route_table())
                if owned_match(item, current):
                    change_route('delete', item)
                elif current:
                    remaining.append(item)
            except (Refused, OSError):
                remaining.append(item)
        recovery = json.loads(json.dumps(before))
        for item in remaining:
            if item not in recovery['routes']:
                recovery['routes'].append(item)
        save_state(recovery)
        if remaining:
            raise Refused(f'部分路由未能安全回滚，恢复记录保留在 {STATE}，请先检查再 restore。') from error
        raise
    print(f'物理出口保护已检查，共 {len(plan)} 条 /31；本次新增 {len(added)} 条。')


def restore():
    state = load_state()
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
    addresses, physical, plan = inspect_plan(Path(pwd.getpwuid(uid).pw_dir), args.profile, args.interface)
    print(f'物理出口：{physical["interface"]}；{len(addresses)} 个网关共用 {len(plan)} 条 /31 回退路由。每条额外包含一个相邻公网 IP。')
    for item in plan:
        print(f'{item["network"]} -> {item["via"]} ({item["interface"]})：' + ('待添加' if item['add'] else '已有，无需添加'))
    if args.command == 'protect':
        with route_lock():
            protect(plan)
    else:
        print('仅检查，未修改路由、默认出口、VPN 或 DNS。')


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError) as error:
        print(f'停止：{error}', file=sys.stderr)
        sys.exit(1)
