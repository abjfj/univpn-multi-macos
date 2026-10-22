#!/usr/bin/env python3
"""Auto-detect reviewed macOS UniVPN builds; refuse unknown or incompatible clients."""
import argparse
import ctypes
import configparser
import fcntl
import hashlib
import json
import os
import plistlib
import pwd
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from xml.parsers.expat import ExpatError

import univpn_profiles as compatibility

SOURCE = Path('/Applications/UniVPN.app')
PATCH_REVISION = 2
MARKER = 'Contents/Resources/univpn-multi-manifest.json'
RUNTIME_CONFIG = 'Contents/MacOS/sysconfig.ini'
SOURCE_FILES = compatibility.SOURCE_FILES


class Refused(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(number):
    if not 2 <= number <= 999:
        raise Refused('实例编号必须在 2–999 之间。')
    return f'UVP{number:03d}'


def ports(number):
    identity(number)
    # Keep clear of the original 29191 RPC and 29192 plugin listener, and of each other.
    base = 31000 + 3 * number
    return {'rpc': base, 'plugin_initial': base + 1, 'backend_initial': base + 2}


def replace_at(data, offset, before, after):
    if len(before) != len(after) or data[offset:offset + len(before)] != before:
        raise Refused(f'补丁前置字节不符：{offset:#x}')
    return data[:offset] + after + data[offset + len(before):]


def binary_architecture(data):
    if data[:4] in (bytes.fromhex('cafebabe'), bytes.fromhex('cafebabf'),
                    bytes.fromhex('bebafeca'), bytes.fromhex('bfbafeca')):
        return 'universal'
    if data[:4] == bytes.fromhex('cffaedfe') and len(data) >= 8:
        cpu = struct.unpack_from('<I', data, 4)[0]
        return {0x01000007: 'x86_64', 0x0100000C: 'arm64'}.get(cpu, 'unknown')
    return 'unknown'


def profile_for_binary(data, relative):
    """Internal convenience for byte-level tests; App selection checks all files."""
    matches = [profile for profile in compatibility.BUILD_PROFILES
               if any(rule.relative == relative and rule.sha256 == digest(data)
                      for rule in profile.binaries)]
    if not matches:
        raise Refused(f'不支持的文件 SHA256：{relative}；未找到已审核的适配规则。')
    if any(profile.binary(relative) != matches[0].binary(relative)
           or profile.architecture != matches[0].architecture for profile in matches[1:]):
        raise Refused('同一文件匹配多份不同规则，拒绝猜测补丁。')
    return matches[0]


def patch(data, relative, number, revision=PATCH_REVISION, profile=None):
    """Apply only the selected exact-build rule, with every byte guard retained."""
    product = identity(number).encode('ascii')
    if revision not in (1, PATCH_REVISION):
        raise Refused('未知的补丁修订版本。')
    profile = profile or profile_for_binary(data, relative)
    rule = profile.binary(relative)
    if digest(data) != rule.sha256:
        raise Refused(f'不支持的文件 SHA256：{relative}；不能只凭版本号应用补丁。')
    if profile.architecture != 'x86_64' or binary_architecture(data) != profile.architecture:
        raise Refused('当前补丁引擎仅支持规则中已审核的 x86_64 Mach-O。')
    if data.count(b'UniVPN') != rule.identity_count:
        raise Refused('产品身份字符串数量不符。')
    result = data.replace(b'UniVPN', product)
    assigned = ports(number)
    for edit in rule.edits:
        if edit.since_revision <= revision:
            after = edit.prefix + struct.pack('<I', assigned[edit.port]) if edit.port else edit.after
            result = replace_at(result, edit.offset, edit.before, after)
    if rule.pac_count:
        if result.count(b'univpn') != rule.pac_count:
            raise Refused('PAC 文件名数量不符。')
        result = result.replace(b'univpn', product.lower())
    if len(result) != len(data) or b'UniVPN' in result:
        raise Refused('补丁长度或身份隔离校验失败。')
    return result


def source_file(source, relative):
    """Read only regular files through real directories within the App."""
    path = source / relative
    for parent in path.parents:
        if parent.is_symlink():
            raise Refused(f'源文件路径包含符号链接：{relative}')
        if parent == source:
            break
    if path.is_symlink() or not path.is_file():
        raise Refused(f'源文件缺失或不是普通文件：{relative}')
    return path.read_bytes()


def inspect_source(source):
    """Collect non-secret metadata, then match one whole reviewed build in memory."""
    if source.is_symlink() or not source.is_dir():
        raise Refused('源 App 必须是实际目录。')
    try:
        info = plistlib.loads(source_file(source, 'Contents/Info.plist'))
    except (plistlib.InvalidFileException, ValueError, TypeError, ExpatError):
        raise Refused('源 App 的 Info.plist 无法解析。') from None
    if not isinstance(info, dict):
        raise Refused('源 App 的 Info.plist 不是字典。')
    version = info.get('CFBundleShortVersionString', '')
    if not isinstance(version, str):
        version = ''
    bundle_version = info.get('CFBundleVersion', '')
    report = {'version': version, 'bundle_version': bundle_version if isinstance(bundle_version, str) else '',
              'architecture': 'unknown', 'supported': False, 'profile': None,
              'reason': '', 'sha256': {}, 'binaries': {}}
    originals = {}
    for relative in SOURCE_FILES:
        try:
            data = source_file(source, 'Contents/MacOS/' + relative)
        except (Refused, OSError):
            report['binaries'][relative] = {'error': '文件缺失、不可读或路径类型不受支持'}
            continue
        originals[relative] = data
        report['sha256'][relative] = digest(data)
        report['binaries'][relative] = {'sha256': digest(data), 'architecture': binary_architecture(data)}
    architectures = {item.get('architecture', 'unknown') for item in report['binaries'].values()}
    report['architecture'] = next(iter(architectures)) if len(architectures) == 1 else 'mixed'
    candidates = [profile for profile in compatibility.BUILD_PROFILES if version in profile.versions]
    matches = [profile for profile in candidates if report['sha256'] == profile.hashes()
               and report['architecture'] == profile.architecture
               and info.get('CFBundleIdentifier') == profile.bundle_id
               and info.get('CFBundleExecutable') == profile.executable]
    if len(originals) != len(SOURCE_FILES):
        reason = '客户端组件缺失或布局不兼容，请查看 binaries 中的文件检查结果。'
    elif report['architecture'] != 'x86_64':
        reason = f'暂不支持 {report["architecture"]} 架构的补丁；不会套用 x86_64 规则。'
    elif not version:
        reason = '客户端未提供有效版本号，无法选择适配规则。'
    elif not candidates:
        reason = f'尚未适配此版本 {version}；请保留检查报告，等待增加已验证规则。'
    elif not matches:
        reason = '版本号已识别，但核心 SHA256 或 Bundle 身份不匹配，可能是其他构建或混合组件。'
    elif len(matches) != 1:
        reason = '同时匹配多份适配规则，拒绝猜测。'
    else:
        profile = matches[0]
        try:
            for relative, data in originals.items():
                patch(data, relative, 2, profile=profile)
        except (Refused, KeyError, StopIteration) as error:
            reason = f'规则 {profile.id} 的补丁前置检查失败：{error}'
        else:
            report.update(supported=True, profile=profile.id, reason='已匹配已审核规则，所有补丁前置检查通过。')
            return report, originals, profile
    report['reason'] = reason
    return report, originals, None


def require_source(source):
    report, originals, profile = inspect_source(source)
    if profile is None:
        raise Refused(f'无法自动适配 UniVPN {report["version"] or "未知版本"} '
                      f'({report["architecture"]})：{report["reason"]} '
                      '未生成、安装或修改客户端；可运行 inspect 查看只读报告。')
    return originals, profile, report


def read_source(source):
    return require_source(source)[0]


def manifest_profile(manifest):
    """Infer old records too, but never trust an arbitrary profile ID alone."""
    matches = [profile for profile in compatibility.BUILD_PROFILES
               if manifest.get('version') in profile.versions
               and manifest.get('source_sha256') == profile.hashes()
               and manifest.get('source_profile', profile.id) == profile.id
               and manifest.get('architecture', profile.architecture) == profile.architecture]
    if len(matches) != 1:
        raise Refused('副本的来源构建未匹配唯一的已审核规则，拒绝修改或启动。')
    return matches[0]


def tree_record(app, installed=False):
    """Hash all payload files and symlink targets; reject escaping links/special files."""
    root = app.resolve()
    records = {}
    for path in [app, *sorted(app.rglob('*'))]:
        relative = path.relative_to(app).as_posix()
        attrs = path.lstat()
        if path.is_symlink():
            target = os.readlink(path)
            if os.path.isabs(target) or not path.resolve().is_relative_to(root) or not path.exists():
                raise Refused(f'App 中存在外部或失效符号链接：{relative}')
            records[relative] = {'link': target}
            continue
        if installed and (attrs.st_uid != 0 or attrs.st_gid != 0 or attrs.st_mode & 0o022):
            raise Refused(f'安装权限异常（需要 root:wheel 且组/其他用户不可写）：{relative}')
        if path.is_dir():
            records[relative] = {'directory': True}
        elif path.is_file():
            if relative != MARKER:
                records[relative] = {'sha256': digest(path.read_bytes())}
        else:
            raise Refused(f'App 中存在特殊文件：{relative}')
    return records


def load_manifest(app, installed=False):
    if app.is_symlink() or not app.is_dir():
        raise Refused('实例 App 必须是实际目录。')
    marker = app / MARKER
    if marker.is_symlink() or not marker.is_file():
        raise Refused('缺少普通文件形式的实例记录。')
    manifest = json.loads(marker.read_text())
    product = identity(manifest['number'])
    if manifest.get('schema') != 1 or manifest.get('product') != product:
        raise Refused('实例记录格式或身份不符。')
    if app.name != product + '.app':
        raise Refused('实例 App 不能重命名。')
    if manifest.get('ports') != ports(manifest['number']):
        raise Refused('端口记录不符。')
    manifest_profile(manifest)
    actual_files = tree_record(app, installed)
    expected_files = dict(manifest['files'])
    if installed:
        # This INI is vendor-managed runtime data, not an immutable executable asset.
        # Its presence, regular-file type, root ownership and write permissions remain checked.
        for records in (actual_files, expected_files):
            if set(records.get(RUNTIME_CONFIG, {})) != {'sha256'}:
                raise Refused('运行时系统配置必须为普通文件。')
            records[RUNTIME_CONFIG] = {'runtime_config': True}
    if actual_files != expected_files:
        raise Refused('实例文件与离线生成记录不一致；请重新生成，不能更新覆盖。')
    for relative, expected in manifest['binaries'].items():
        if digest((app / relative).read_bytes()) != expected:
            raise Refused('实例可执行文件校验失败。')
    with (app / 'Contents/Info.plist').open('rb') as f:
        info = plistlib.load(f)
    if info.get('CFBundleExecutable') != product or info.get('CFBundleIdentifier') != f'local.univpn.multi.{product.lower()}':
        raise Refused('Bundle 身份不符。')
    return manifest


def build(args):
    if os.geteuid() == 0:
        raise Refused('请以普通用户生成副本；只有安装步骤使用 sudo。')
    product = identity(args.number)
    source = args.source.absolute()
    originals, profile, report = require_source(source)
    template = normalize_reconnect_timer(source_file(source, RUNTIME_CONFIG))
    tree_record(source)  # Validate every link before copying.
    output = args.output.absolute()
    if output.resolve().is_relative_to(source.resolve()):
        raise Refused('输出目录不能位于源 App 内。')
    output.mkdir(parents=True, exist_ok=True)
    target = output / f'instance-{args.number:03d}'
    target.mkdir(mode=0o700)  # Deliberately refuses existing and failed instance directories.
    app = target / f'{product}.app'
    shutil.copytree(source, app, symlinks=True, copy_function=shutil.copyfile)
    # Rename vendor paths in the private copy, deepest first. Framework links are unchanged.
    for path in sorted(app.rglob('*'), key=lambda p: len(p.parts), reverse=True):
        if 'UniVPN' in path.name:
            path.rename(path.with_name(path.name.replace('UniVPN', product)))
    # An unpatched updater must never overwrite/reconfigure this experimental client.
    for relative in (f'Contents/MacOS/{product}Update', 'Contents/MacOS/update_help'):
        path = app / relative
        if path.exists():
            path.unlink()
    binaries = {}
    for relative, data in originals.items():
        changed = relative.replace('UniVPN', product)
        payload = patch(data, relative, args.number, profile=profile)
        dest = app / 'Contents/MacOS' / changed
        dest.write_bytes(payload)
        binaries[dest.relative_to(app).as_posix()] = digest(payload)
    # The installed vendor template uses 0, but the backend's reader accepts 1..1440.
    # An invalid timer makes it recreate the user INI, discarding every SessionN entry.
    config = app / RUNTIME_CONFIG
    config.write_bytes(template)
    plist = app / 'Contents/Info.plist'
    with plist.open('rb') as f:
        info = plistlib.load(f)
    info.update(CFBundleExecutable=product, CFBundleName=product, CFBundleDisplayName=product,
                CFBundleIdentifier=f'local.univpn.multi.{product.lower()}')
    with plist.open('wb') as f:
        plistlib.dump(info, f)
    # No setuid permission in build output; UI is deliberately non-executable before installation.
    for path in [app, *app.rglob('*')]:
        if path.is_symlink():
            continue
        relative = path.relative_to(app)
        src = source / str(relative).replace(product, 'UniVPN')
        executable = src.exists() and bool(src.stat().st_mode & 0o111)
        path.chmod(0o755 if path.is_dir() or executable else 0o644)
    (app / 'Contents/MacOS' / product).chmod(0o644)
    manifest = {
        'schema': 1, 'number': args.number, 'product': product, 'version': report['version'],
        'source_profile': profile.id, 'architecture': profile.architecture,
        'patch_revision': PATCH_REVISION,
        'validation': 'offline-only; no VPN login or dual-tunnel verification',
        'ports': ports(args.number),
        'source_sha256': {k: digest(v) for k, v in originals.items()},
        'binaries': binaries, 'updater_removed': True, 'files': tree_record(app),
    }
    (app / MARKER).write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    load_manifest(app)
    print(f'已生成离线实验副本：{app}\n未安装、未启动、未修改网络。')


def install(args):
    if os.geteuid() != 0:
        raise Refused('安装需要 sudo；安装过程只复制副本和设置权限，不启动 VPN。')
    app = args.app.absolute()
    manifest = load_manifest(app)
    product = manifest['product']
    applications = Path('/Applications')
    if applications.is_symlink():
        raise Refused('/Applications 不能是符号链接。')
    dest = applications / (product + '.app')
    if dest.exists() or dest.is_symlink():
        raise Refused(f'目标已存在，拒绝覆盖：{dest}')
    # A root-only parent keeps the copy inaccessible until validation and permissions finish.
    with tempfile.TemporaryDirectory(prefix='.univpn-multi-', dir=applications) as temporary:
        staged = Path(temporary) / dest.name
        shutil.copytree(app, staged, symlinks=True, copy_function=shutil.copyfile)
        load_manifest(staged)
        for path in [staged, *staged.rglob('*')]:
            if path.is_symlink():
                os.lchown(path, 0, 0)
                continue
            # Use source mode only to preserve executability; discard every special/write bit.
            src = app / path.relative_to(staged)
            executable = bool(src.stat().st_mode & 0o111)
            os.chown(path, 0, 0)
            path.chmod(0o755 if path.is_dir() or executable else 0o644)
        (staged / 'Contents/MacOS' / product).chmod(0o755)
        (staged / 'Contents/MacOS/serviceclient' / (product + 'CS')).chmod(0o4755)
        load_manifest(staged, installed=True)
        # Recheck before publishing; never overwrite an existing application directory.
        if dest.exists() or dest.is_symlink():
            raise Refused('安装期间目标被创建；拒绝覆盖。')
        staged.rename(dest)
    print(f'已安装：{dest}\n尚未启动。以普通用户运行 start 子命令。')


def process_ids(name):
    result = subprocess.run(['/usr/bin/pgrep', '-x', name], capture_output=True, text=True)
    if result.returncode == 1:
        return []
    if result.returncode != 0:
        raise Refused(f'无法检查进程：{name}')
    return [int(value) for value in result.stdout.split()]


def process_path(pid):
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    function = lib.proc_pidpath
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    if function(pid, buffer, len(buffer)) <= 0:
        raise Refused(f'无法确认进程 {pid} 的实际可执行文件路径。')
    return Path(os.fsdecode(buffer.value))


def checked_processes(app, product):
    paths = {
        'ui': app / 'Contents/MacOS' / product,
        'helper': app / 'Contents/MacOS/promote' / (product + 'PromoteService'),
        'backend': app / 'Contents/MacOS/serviceclient' / (product + 'CS'),
    }
    found = {}
    for role, path in paths.items():
        found[role] = process_ids(path.name)
        for pid in found[role]:
            if process_path(pid) != path:
                raise Refused(f'发现同名但路径不属于本实例的进程：{path.name} PID {pid}')
    return found


def clean_orphan_helper(app, product):
    found = checked_processes(app, product)
    if found['ui'] or found['backend']:
        raise Refused('界面或连接后台仍在运行，不自动结束进程；请先正常断开并退出副本。')
    for pid in found['helper']:
        # Check again just before signaling; never target a name globally or kill a tunnel.
        if process_path(pid) != app / 'Contents/MacOS/promote' / (product + 'PromoteService'):
            raise Refused('残留服务的路径发生变化，停止处理。')
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 5
    while process_ids(product + 'PromoteService'):
        if time.monotonic() >= deadline:
            raise Refused('残留服务未响应 SIGTERM；未强制结束，请检查该实例。')
        time.sleep(0.1)


def repair_payload(original, current, number, revision, profile=None):
    if current != patch(original, 'UniVPN', number, revision=revision, profile=profile):
        raise Refused('已安装界面不符合该修订版本的精确补丁，拒绝修复。')
    return patch(original, 'UniVPN', number, profile=profile)


def atomic_write(path, payload, mode):
    descriptor, temporary = tempfile.mkstemp(prefix='.univpn-repair-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            if os.geteuid() == 0:
                os.fchown(stream.fileno(), 0, 0)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def parse_ini(data):
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(data.decode('utf-8-sig'))
    return parser


def normalize_reconnect_timer(data):
    """Correct an invalid native reconnect timer without rewriting unrelated settings."""
    ini = parse_ini(data)
    try:
        value = ini.getint('ADVANCED', 'ClientReConnectTimeValue', fallback=5)
    except ValueError as error:
        raise Refused('重连时间不是整数，拒绝猜测配置格式。') from error
    if 1 <= value <= 1440:
        return data
    sections = re.split(rb'(?m)(^\[[^\r\n]+\][^\r\n]*\r?\n)', data)
    replaced = 0
    for index in range(1, len(sections), 2):
        if sections[index].strip() == b'[ADVANCED]':
            sections[index + 1], replaced = re.subn(
                rb'(?m)^(ClientReConnectTimeValue[ \t]*=[ \t]*)[^\r\n]*',
                lambda match: match.group(1) + b'5', sections[index + 1])
    if replaced != 1:
        raise Refused('无效重连时间的配置格式不明确，未修改。')
    return b''.join(sections)


def recover_session_index(data, profiles):
    """Append missing native SessionN entries, retaining all existing bytes/settings."""
    ini = parse_ini(data)
    used = {int(s[7:]) for s in ini.sections() if re.fullmatch(r'Session\d+', s)}
    indexed = {ini.get(s, 'ProfileName', fallback='').strip() for s in ini.sections()
               if re.fullmatch(r'Session\d+', s)}
    added = []
    output = data
    for name, profile in profiles:
        if name in indexed:
            continue
        if any(c in name for c in '\r\n/\\') or len(name.encode('utf-8')) > 132:
            raise Refused('网关配置文件名不符合客户端长度/字符约束。')
        kind = parse_ini(profile).getint('GLOBAL', 'iConnectionType')
        if kind not in (1, 2):
            raise Refused('发现未支持的网关连接类型，未修改配置。')
        number = next((n for n in range(128) if n not in used), None)
        if number is None:
            raise Refused('会话索引已满，未修改配置。')
        # Defaults match an imported profile: no saved password and no automatic login.
        entry = (f'\n[Session{number}]\nConnectType = {kind}\nRemPwd = 0\nAutoLogin = 0\n'
                 f'AuthType = 0\nLastLoginAddr = \nProfileName = {name}\n'
                 'ProfileUser = \nProfileInfo = \n')
        output += entry.encode('utf-8')
        used.add(number)
        indexed.add(name)
        added.append(name)
    return output, added


def repair_config(args):
    if os.geteuid() != 0:
        raise Refused('需要同步修复 root 所有的副本系统配置，请使用 sudo python3 univpn_multi.py repair-config --number ' + str(args.number))
    product = identity(args.number)
    app = Path('/Applications') / (product + '.app')
    load_manifest(app, installed=True)
    found = checked_processes(app, product)
    if any(found.values()):
        raise Refused('请先通过副本菜单正常退出，界面和后台退出后再修复配置。')
    uid = int(os.environ.get('SUDO_UID', '-1'))
    if uid <= 0:
        raise Refused('请通过原登录用户的 sudo 执行，以便确认用户配置目录。')
    account = pwd.getpwuid(uid)
    home = Path(account.pw_dir) / ('.' + product)
    if home.is_symlink() or not home.is_dir() or home.stat().st_uid != uid:
        raise Refused('用户配置目录的类型或归属异常。')
    config = home / 'sysconfig.ini'
    key = home / 'key.ini'
    profile_dir = home / 'config'
    if profile_dir.is_symlink() or not profile_dir.is_dir():
        raise Refused('缺少实际网关配置目录。')
    for path in (config, key, app / RUNTIME_CONFIG):
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise Refused('系统配置/校验文件不是独立普通文件，拒绝修改。')
    profiles = []
    for path in sorted(profile_dir.glob('*.ini')):
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != uid:
            raise Refused('网关配置的类型或归属异常。')
        profiles.append((path.name, path.read_bytes()))
    if not profiles:
        raise Refused('未发现已保存的网关配置，不做空配置修复。')
    old_config = config.read_bytes()
    updated, added = recover_session_index(normalize_reconnect_timer(old_config), profiles)
    old_key = key.read_bytes()
    updated_key = update_verify_value(old_key, digest(updated))
    targets = (app / RUNTIME_CONFIG, config, key)
    payloads = (updated, updated, updated_key)
    previous = [(p.read_bytes(), p.stat().st_uid, p.stat().st_gid, stat.S_IMODE(p.stat().st_mode)) for p in targets]
    backup = home / '.multi-backups'
    if backup.is_symlink():
        raise Refused('备份目录不能是符号链接。')
    backup.mkdir(mode=0o700, exist_ok=True)
    if backup.stat().st_uid not in (0, uid) or backup.stat().st_mode & 0o077:
        raise Refused('备份目录的所有权或私有权限异常。')
    os.chown(backup, uid, account.pw_gid)
    slot = Path(tempfile.mkdtemp(prefix='paired-config-', dir=backup))
    os.chown(slot, uid, account.pw_gid)
    for label, (data, _, _, _) in zip(('app-sysconfig.ini', 'user-sysconfig.ini', 'key.ini'), previous):
        dest = slot / label
        atomic_write(dest, data, 0o600)
        os.chown(dest, uid, account.pw_gid)
    try:
        for index, (path, data) in enumerate(zip(targets, payloads)):
            atomic_write(path, data, 0o644 if index == 0 else 0o600)
            if index:
                os.chown(path, uid, account.pw_gid)
        if digest(targets[0].read_bytes()) != digest(config.read_bytes()):
            raise Refused('两份系统配置不一致。')
        if parse_ini(key.read_bytes()).get('GLOBAL', 'VerifyValue').lower() != digest(updated):
            raise Refused('配置校验值不一致。')
        load_manifest(app, installed=True)
    except Exception:
        for path, (data, owner, group, mode) in zip(targets, previous):
            atomic_write(path, data, mode)
            os.chown(path, owner, group)
        raise
    print(f'已同步修复 {product} 的安装配置、用户配置及 SHA256 校验值；补回 {len(added)} 个会话索引。')
    if normalize_reconnect_timer(old_config) != old_config:
        print('已将无效重连时间恢复为厂商默认值 5，避免读取时清空会话索引。')
    print(f'备份：{slot}\n未修改网关配置文件或原版客户端；请以普通用户 start。')


def update_verify_value(data, value):
    if not re.fullmatch(r'[a-f0-9]{64}', value):
        raise Refused('校验值必须为 SHA256。')
    text = data.decode('utf-8-sig')
    ini = parse_ini(data)
    if not ini.has_option('GLOBAL', 'VerifyValue'):
        raise Refused('厂商校验记录缺少 GLOBAL/VerifyValue，拒绝猜测格式。')
    # Preserve every other field and section verbatim.
    sections = re.split(r'(?m)(^\[[^\r\n]+\][^\r\n]*\r?\n)', text)
    replaced = False
    for index in range(1, len(sections), 2):
        if sections[index].strip() == '[GLOBAL]':
            sections[index + 1], count = re.subn(r'(?m)^(VerifyValue\s*=\s*)[^\r\n]*',
                                               lambda m: m.group(1) + value, sections[index + 1])
            replaced = count == 1
    if not replaced:
        raise Refused('厂商校验记录格式不明确。')
    return ''.join(sections).encode('utf-8')


def repair(args):
    if os.geteuid() != 0:
        raise Refused('修复已安装副本需要 sudo，因为 App 属于 root；只修改该实例。')
    product = identity(args.number)
    app = Path('/Applications') / (product + '.app')
    manifest = load_manifest(app, installed=True)
    revision = manifest.get('patch_revision', 1)
    if revision == PATCH_REVISION:
        print('副本已是修复版，无需再次修改。')
        return
    originals, profile, _ = require_source(SOURCE)
    if profile.id != manifest_profile(manifest).id:
        raise Refused('原版已更换构建，与待修复副本来源不同，未套用其他版本补丁。')
    original = originals['UniVPN']
    ui = app / 'Contents/MacOS' / product
    previous_ui = ui.read_bytes()
    updated = repair_payload(original, previous_ui, args.number, revision, profile=profile)
    marker = app / MARKER
    previous_marker = marker.read_bytes()
    clean_orphan_helper(app, product)
    try:
        atomic_write(ui, updated, 0o755)
        manifest['patch_revision'] = PATCH_REVISION
        manifest['binaries'][ui.relative_to(app).as_posix()] = digest(updated)
        manifest['files'] = tree_record(app, installed=True)
        atomic_write(marker, (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode(), 0o644)
        load_manifest(app, installed=True)
    except Exception:
        atomic_write(ui, previous_ui, 0o755)
        atomic_write(marker, previous_marker, 0o644)
        raise
    print(f'已修复 {product}：RPC 重试增加到 15 次，停止扫描旧端口。\n未启动客户端；用户配置保持不变。')


def select_new_instance(applications=Path('/Applications'), profile_id=None):
    """Prefer the idle original, then idle installed copies, then a free identity."""
    original = applications / 'UniVPN.app'
    if original.is_symlink() or not original.is_dir():
        raise Refused('未找到实际目录形式的原版 UniVPN.app。')
    if not any(checked_processes(original, 'UniVPN').values()):
        return 1, original
    unused = None
    for number in range(2, 1000):
        product = identity(number)
        app = applications / (product + '.app')
        if app.exists() or app.is_symlink():
            found = checked_processes(app, product)
            if found['ui'] or found['backend']:
                continue
            manifest = load_manifest(app, installed=True)
            if profile_id is not None and manifest_profile(manifest).id != profile_id:
                continue
            return number, app
        if unused is None and not any(checked_processes(app, product).values()):
            unused = (number, app)
    if unused is None:
        raise Refused('没有可用实例编号。')
    return unused


@contextmanager
def new_window_lock(output):
    output.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output / '.new-window.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        attrs = os.fstat(descriptor)
        if not stat.S_ISREG(attrs.st_mode) or attrs.st_uid != os.getuid() or attrs.st_nlink != 1:
            raise Refused('新窗口锁文件的类型或所有权异常。')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Refused('另一个新窗口正在准备或启动，请稍后重试。') from error
        yield
    finally:
        os.close(descriptor)


def prepare_instance_config(app, number):
    """Initialize native INIs for an idle copy, preserving existing credentials/settings."""
    if os.geteuid() == 0:
        raise Refused('用户配置必须由普通用户准备。')
    product = identity(number)
    load_manifest(app, installed=True)
    found = checked_processes(app, product)
    if found['ui'] or found['backend']:
        raise Refused('实例已开始运行，未修改用户配置；请重新执行 new。')
    home = Path.home() / ('.' + product)
    if home.is_symlink():
        raise Refused('实例用户目录不能是符号链接。')
    home.mkdir(mode=0o700, exist_ok=True)
    if not home.is_dir() or home.stat().st_uid != os.getuid():
        raise Refused('实例用户目录的类型或所有权异常。')
    config, key = home / 'sysconfig.ini', home / 'key.ini'
    for path in (config, key):
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.stat().st_nlink != 1)):
            raise Refused('实例配置必须是独立普通文件。')
    template = (app / RUNTIME_CONFIG).read_bytes()
    previous = config.read_bytes() if config.exists() else None
    updated = normalize_reconnect_timer(previous if previous is not None else template)
    if previous is not None and updated != previous:
        profiles = []
        profile_dir = home / 'config'
        if profile_dir.is_symlink():
            raise Refused('网关目录不能是符号链接。')
        for path in sorted(profile_dir.glob('*.ini')):
            if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
                raise Refused('网关配置的类型或所有权异常。')
            profiles.append((path.name, path.read_bytes()))
        updated, _ = recover_session_index(updated, profiles)
        backup = home / '.multi-backups'
        if backup.is_symlink():
            raise Refused('备份目录不能是符号链接。')
        backup.mkdir(mode=0o700, exist_ok=True)
        if backup.stat().st_uid != os.getuid() or backup.stat().st_mode & 0o077:
            raise Refused('备份目录必须归当前用户所有且为私有目录。')
        slot = Path(tempfile.mkdtemp(prefix='new-window-', dir=backup))
        atomic_write(slot / 'sysconfig.ini', previous, 0o600)
        print(f'已备份并修复该副本的无效重连时间：{slot}')
    # Native VerifyValue covers the install template, not the mutable user INI.
    # Seed only a missing key, so first launch does not recreate the template as zeros.
    if not key.exists():
        atomic_write(key, ('[GLOBAL]\nVerifyValue = ' + digest(template) + '\n').encode(), 0o600)
    if previous is None or updated != previous:
        atomic_write(config, updated, 0o600)


def merge_original_sessions(target, source, profiles, existing_names, overwrite=False):
    """Transfer native saved fields verbatim; never decrypt or enable automatic login."""
    for name, _ in profiles:
        if not name or any(c in name for c in '\r\n/\\') or len(name.encode('utf-8')) > 132:
            raise Refused('网关配置文件名不符合客户端约束，未复制。')
    source_ini = parse_ini(source)
    source_sessions = {}
    for section in source_ini.sections():
        if re.fullmatch(r'Session\d+', section):
            name = source_ini.get(section, 'ProfileName', fallback='')
            if name:
                if name in source_sessions:
                    raise Refused('原版存在重复会话名称，未复制。')
                source_sessions[name] = section
    target_ini = parse_ini(target)
    occupied = set(existing_names) | {
        target_ini.get(s, 'ProfileName', fallback='') for s in target_ini.sections()
        if re.fullmatch(r'Session\d+', s)}
    selected = [(name, data) for name, data in profiles if overwrite or name not in occupied]
    updated, _ = recover_session_index(target, selected)
    fields = ('ConnectType', 'RemPwd', 'AuthType', 'LastLoginAddr',
              'ProfileName', 'ProfileUser', 'ProfileInfo')
    remembered = 0
    for name, _ in selected:
        parsed = parse_ini(updated)
        section = next(s for s in parsed.sections()
                       if re.fullmatch(r'Session\d+', s) and parsed.get(s, 'ProfileName', fallback='') == name)
        values = dict(parsed[section])
        if name in source_sessions:
            original_section = source_sessions[name]
            for key in fields:
                if source_ini.has_option(original_section, key):
                    values[key] = source_ini.get(original_section, key)
        values['AutoLogin'] = '0'
        if any('\r' in value or '\n' in value for value in values.values()):
            raise Refused('会话字段包含多行内容，未复制。')
        body = ''.join(f'{key} = {value}\n' for key, value in values.items()).encode('utf-8')
        parts = re.split(rb'(?m)(^\[[^\r\n]+\][^\r\n]*\r?\n)', updated)
        for i in range(1, len(parts), 2):
            if parts[i].strip() == f'[{section}]'.encode():
                parts[i + 1] = body + b'\n'
        updated = b''.join(parts)
        remembered += values.get('RemPwd') == '1' and bool(values.get('ProfileInfo'))
    return updated, selected, remembered


def inherit_original_config(app, number, overwrite=False):
    """Copy authorized local profiles and stored credentials into an idle instance."""
    if os.geteuid() == 0:
        raise Refused('原版配置继承必须由普通用户执行。')
    product = identity(number)
    load_manifest(app, installed=True)
    found = checked_processes(app, product)
    if found['ui'] or found['backend']:
        raise Refused('实例正在运行，未同步原版配置；请先正常退出该副本。')
    source = Path.home() / '.UniVPN'
    target = Path.home() / ('.' + product)
    if source.is_symlink() or target.is_symlink():
        raise Refused('配置目录不能是符号链接。')
    if not (source / 'sysconfig.ini').exists() or not (source / 'config').exists():
        print('原版尚无可继承的网关配置。')
        return
    for directory in (source, source / 'config', target):
        if directory.is_symlink() or not directory.is_dir() or directory.stat().st_uid != os.getuid():
            raise Refused('配置目录的类型或所有权异常，未同步。')

    def read_private(path):
        attrs = path.lstat()
        if not stat.S_ISREG(attrs.st_mode) or attrs.st_nlink != 1 or attrs.st_uid not in (0, os.getuid()):
            raise Refused('发现不是独立普通文件的配置，未同步。')
        return path.read_bytes()

    original = read_private(source / 'sysconfig.ini')
    profiles = [(p.name, read_private(p)) for p in sorted((source / 'config').glob('*.ini'))]
    # The original may save preferences while connected; use a consistent snapshot.
    if original != read_private(source / 'sysconfig.ini') or any(
            data != read_private(source / 'config' / name) for name, data in profiles):
        raise Refused('原版正在写入配置，未同步；稍后重新执行即可。')
    profile_dir = target / 'config'
    if profile_dir.is_symlink():
        raise Refused('副本网关目录不能是符号链接。')
    profile_dir.mkdir(mode=0o700, exist_ok=True)
    if not profile_dir.is_dir() or profile_dir.stat().st_uid != os.getuid():
        raise Refused('副本网关目录的类型或所有权异常。')
    config = target / 'sysconfig.ini'
    previous = read_private(config)
    existing = {p.name for p in profile_dir.glob('*.ini')}
    try:
        updated, selected, remembered = merge_original_sessions(previous, original, profiles, existing, overwrite)
    except (configparser.Error, UnicodeError):
        raise Refused('原版或副本配置格式无法读取，未同步。') from None
    if not selected:
        print('副本已存在这些网关，保留现有设置；可用 --sync-original 同步原版的同名配置和已保存账密。')
        return
    changes = [(profile_dir / name, payload) for name, payload in selected] + [(config, updated)]
    old = [(path, read_private(path) if path.exists() or path.is_symlink() else None)
           for path, _ in changes]
    backup = target / '.multi-backups'
    if backup.is_symlink():
        raise Refused('备份目录不能是符号链接。')
    backup.mkdir(mode=0o700, exist_ok=True)
    if backup.stat().st_uid != os.getuid() or backup.stat().st_mode & 0o077:
        raise Refused('备份目录必须为当前用户的私有目录。')
    slot = Path(tempfile.mkdtemp(prefix='inherit-original-', dir=backup))
    (slot / 'config').mkdir(mode=0o700)
    for path, data in old:
        if data is not None:
            relative = path.relative_to(target)
            atomic_write(slot / relative, data, 0o600)
    found = checked_processes(app, product)
    if found['ui'] or found['backend']:
        raise Refused('实例已开始运行，未写入继承配置。')
    written = []
    try:
        for path, data in changes:
            atomic_write(path, data, 0o600)
            written.append(path)
    except Exception:
        for path, data in reversed(old):
            if path in written:
                if data is None:
                    path.unlink()
                else:
                    atomic_write(path, data, 0o600)
        raise
    print(f'已继承原版 {len(selected)} 个网关，其中 {remembered} 个含已保存密码记录；请选择网关并手动登录。')


def ensure_gateway_protection():
    """Fill missing public-gateway fallbacks before any new client can connect."""
    directory = Path.home() / '.UniVPN/config'
    if not directory.exists() or not any(directory.glob('*.ini')):
        return
    # Imported lazily: the route tool reuses this module's INI and atomic-write helpers.
    import gateway_routes as gateway
    try:
        _, _, plan = gateway.inspect_plan(Path.home())
    except gateway.Refused as error:
        raise Refused(f'网关出口检查失败：{error}') from None
    if any(item['add'] for item in plan):
        print('需要补充已保存网关的物理出口保护；请按终端提示输入 Mac 管理员密码。', flush=True)
        subprocess.run(['/usr/bin/sudo', sys.executable, str(Path(__file__).resolve().with_name('gateway_routes.py')),
                        'protect'], check=True)
    else:
        print('所有已保存网关的物理出口保护均已存在。')


def new_window(args):
    if os.geteuid() == 0:
        raise Refused('请直接运行 new，不要加 sudo；需要安装时命令会自行调用 sudo。')
    # Resolve before the lock directory, config writes, route checks or sudo calls.
    # Even opening the original must not silently skip compatibility detection.
    _, profile, report = require_source(SOURCE)
    print(f'已识别 UniVPN {report["version"]} ({profile.architecture})；适配规则：{profile.id}')
    output = Path(__file__).resolve().parent / 'build'
    if args.dry_run:
        number, app = select_new_instance(profile_id=profile.id)
        action = '打开原版' if number == 1 else ('复用已安装副本' if app.exists() else '生成、安装并打开新副本')
        print(f'计划：{action} {app}；未修改文件或启动客户端。')
        return
    with new_window_lock(output):
        number, app = select_new_instance(profile_id=profile.id)
        if number == 1:
            ensure_gateway_protection()
            if any(checked_processes(app, 'UniVPN').values()):
                raise Refused('原版状态发生变化，请重新执行 new。')
            subprocess.run(['/usr/bin/open', '-n', str(app)], check=True)
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                found = checked_processes(app, 'UniVPN')
                if found['ui'] and found['helper'] and found['backend']:
                    print('已打开原版 UniVPN，请在窗口中选择网关并登录。')
                    return
                time.sleep(0.25)
            raise Refused('原版启动就绪超时，请检查原版界面；未自动停止任何进程。')
        if not app.exists():
            staged = output / f'instance-{number:03d}' / app.name
            if not staged.exists():
                if staged.parent.exists():
                    raise Refused(f'存在未完成的生成目录：{staged.parent}；请先检查，未自动删除。')
                build(argparse.Namespace(number=number, source=SOURCE, output=output))
            staged_manifest = load_manifest(staged)
            if manifest_profile(staged_manifest).id != profile.id:
                raise Refused('已有生成目录来自不同客户端构建，未覆盖或安装；请先检查该目录。')
            print('首次使用此副本需要安装；请在终端输入 Mac 管理员密码。', flush=True)
            subprocess.run(['/usr/bin/sudo', sys.executable, str(Path(__file__).resolve()),
                            'install', str(staged)], check=True)
        prepare_instance_config(app, number)
        inherit_original_config(app, number, overwrite=getattr(args, 'sync_original', False))
        ensure_gateway_protection()
        start(argparse.Namespace(number=number, new_window=True))


def start(args):
    if os.geteuid() == 0:
        raise Refused('界面必须以普通用户启动。')
    product = identity(args.number)
    app = Path('/Applications') / (product + '.app')
    manifest = load_manifest(app, installed=True)
    if manifest.get('patch_revision', 1) < PATCH_REVISION:
        raise Refused(f'已安装的是旧版启动补丁；请先运行 sudo python3 univpn_multi.py repair --number {args.number}')
    backend = app / 'Contents/MacOS/serviceclient' / (product + 'CS')
    if stat.S_IMODE(backend.stat().st_mode) != 0o4755:
        raise Refused('连接后台权限必须为 root:wheel 04755。')
    found = checked_processes(app, product)
    if found['ui']:
        if getattr(args, 'new_window', False):
            raise Refused('选中的副本已被打开，请重新执行 new 选择另一个实例。')
        subprocess.run(['/usr/bin/open', str(app)], check=True)
        print('副本界面已在运行，已请求将其激活。')
        return
    if found['backend']:
        raise Refused('连接后台仍在运行，可能已有隧道；请先正常断开并退出该副本，不自动结束连接。')
    if found['helper']:
        clean_orphan_helper(app, product)
        print('已清理本实例残留的提权服务；没有结束连接后台。')
    # Configuration recovery is explicit. In particular, restore the native timer's
    # valid range before adding indices, or the backend will discard them on read.
    held = []
    try:
        for port in manifest['ports'].values():
            sock = socket.socket()
            held.append(sock)
            sock.bind(('127.0.0.1', port))
    except OSError as error:
        raise Refused(f'实例预期端口不可用：{error}') from error
    finally:
        for sock in held:
            sock.close()
    subprocess.run(['/usr/bin/open', '-n', str(app)], check=True)
    deadline = time.monotonic() + 20
    seen_ui = False
    while time.monotonic() < deadline:
        found = checked_processes(app, product)
        seen_ui = seen_ui or bool(found['ui'])
        if found['ui'] and found['helper'] and found['backend']:
            print('副本界面、提权服务和连接后台均已运行。请在窗口中选择或添加网关并登录；尚未验证 VPN 连通。')
            return
        if seen_ui and not found['ui']:
            raise Refused(f'副本界面已退出；启动未成功。请检查 ~/.{product}/log 中的启动错误。')
        time.sleep(0.25)
    raise Refused(f'等待副本后台就绪超时；请检查界面提示及 ~/.{product}/log。未自动结束可能存在的连接。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('profiles', help='列出内置已审核版本和构建规则，不读取客户端或配置')
    inspect = sub.add_parser('inspect', help='只读识别版本、架构和适配规则；不兼容时返回非零状态')
    inspect.add_argument('--source', type=Path, default=SOURCE)
    create = sub.add_parser('build', help='只生成离线副本，不安装或启动')
    create.add_argument('--source', type=Path, default=SOURCE)
    create.add_argument('--number', type=int, default=2)
    create.add_argument('--output', type=Path, default=Path(__file__).resolve().parent / 'build')
    for name in ('verify', 'install'):
        action = sub.add_parser(name)
        action.add_argument('app', type=Path)
    launch = sub.add_parser('start', help='校验已安装副本并请求打开界面（会改变运行状态）')
    launch.add_argument('--number', type=int, default=2)
    automatic = sub.add_parser('new', help='自动选择空闲实例，按需生成和安装，再打开一个窗口')
    automatic.add_argument('--dry-run', action='store_true', help='只显示将选择的实例，不创建、安装或启动')
    automatic.add_argument('--sync-original', action='store_true',
                           help='启动前备份并同步原版同名网关和已保存账密；默认仅继承缺少的网关')
    fix = sub.add_parser('repair', help='修复已安装旧副本的 RPC 冷启动问题；需要 sudo')
    fix.add_argument('--number', type=int, default=2)
    cfg = sub.add_parser('repair-config', help='同步修复两份系统配置、索引及校验值；需要 sudo')
    cfg.add_argument('--number', type=int, default=2)
    args = parser.parse_args()
    if args.command == 'profiles':
        print(json.dumps([{'id': profile.id, 'versions': profile.versions,
                           'architecture': profile.architecture, 'sha256': profile.hashes()}
                          for profile in compatibility.BUILD_PROFILES], ensure_ascii=False, indent=2))
        return 0
    if sys.platform != 'darwin':
        raise Refused('此工具仅支持 macOS。')
    if args.command == 'inspect':
        report, _, _ = inspect_source(args.source)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report['supported'] else 1
    elif args.command == 'build':
        build(args)
    elif args.command == 'verify':
        data = load_manifest(args.app, installed=args.app.absolute().parent == Path('/Applications'))
        print(f"完整性校验通过：{data['product']}；验证范围：{data['validation']}")
    elif args.command == 'install':
        install(args)
    elif args.command == 'start':
        start(args)
    elif args.command == 'new':
        new_window(args)
    elif args.command == 'repair':
        repair(args)
    elif args.command == 'repair-config':
        repair_config(args)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Refused, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f'停止：{error}', file=sys.stderr)
        sys.exit(1)
