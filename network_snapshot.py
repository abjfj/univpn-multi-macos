#!/usr/bin/env python3
"""Save local, read-only network evidence. Does not read UniVPN accounts or logs."""
import argparse
import os
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='新的私有输出目录；不覆盖已有目录')
    args = parser.parse_args()
    os.umask(0o077)
    args.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    commands = {
        'system.txt': ['/usr/bin/sw_vers'],
        'interfaces.txt': ['/sbin/ifconfig', '-a'],
        'routes-ipv4.txt': ['/usr/sbin/netstat', '-rn', '-f', 'inet'],
        'routes-ipv6.txt': ['/usr/sbin/netstat', '-rn', '-f', 'inet6'],
        'dns.txt': ['/usr/sbin/scutil', '--dns'],
        'proxy.txt': ['/usr/sbin/scutil', '--proxy'],
        'processes.txt': ['/bin/ps', '-axo', 'pid=,comm='],
    }
    failed = []
    for name, command in commands.items():
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (args.directory / name).write_bytes(result.stdout)
        if result.returncode:
            failed.append(name)
    print(f'只读快照已保存：{args.directory.resolve()}')
    print('包含本机网络地址、内网路由和 DNS，仅在本地保存。')
    if failed:
        print('部分命令未成功：' + ', '.join(failed))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
