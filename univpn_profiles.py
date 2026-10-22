"""Reviewed, exact-build compatibility rules. No downloaded or user-forced rules."""
from dataclasses import dataclass
from typing import Optional, Tuple


UI = 'UniVPN'
HELPER = 'promote/UniVPNPromoteService'
BACKEND = 'serviceclient/UniVPNCS'
SOURCE_FILES = (UI, HELPER, BACKEND)


@dataclass(frozen=True)
class Edit:
    name: str
    offset: int
    before: bytes
    after: bytes = b''
    port: Optional[str] = None
    prefix: bytes = b''
    since_revision: int = 1


@dataclass(frozen=True)
class BinaryRule:
    relative: str
    sha256: str
    identity_count: int
    edits: Tuple[Edit, ...]
    pac_count: int = 0


@dataclass(frozen=True)
class BuildProfile:
    id: str
    versions: Tuple[str, ...]
    architecture: str
    binaries: Tuple[BinaryRule, ...]
    bundle_id: str = 'work.VPNClient'
    executable: str = 'UniVPN'

    def binary(self, relative):
        return next(rule for rule in self.binaries if rule.relative == relative)

    def hashes(self):
        return {rule.relative: rule.sha256 for rule in self.binaries}


# Adding a version requires its own reviewed hashes, instruction checks and tests.
# Sharing a version number or finding a port constant is not enough to select a rule.
BUILD_PROFILES = (
    BuildProfile(
        id='univpn-10781.19.0.1214-x86_64-r1',
        versions=('10781.19.0.1214',),
        architecture='x86_64',
        binaries=(
            BinaryRule(
                UI, 'c0fed6a4bf6d150df6413263283984bf4c9ef51e371da37fd45f033e8ad28408', 30,
                (
                    Edit('RPC initialization', 0xF5DC8, bytes.fromhex('c745b407720000'),
                         port='rpc', prefix=bytes.fromhex('c745b4')),
                    Edit('RPC connection', 0xF5E79, bytes.fromhex('bf07720000'),
                         port='rpc', prefix=bytes.fromhex('bf')),
                    Edit('Plugin listener', 0xF7F4C, bytes.fromhex('bf08720000'),
                         port='plugin_initial', prefix=bytes.fromhex('bf')),
                    Edit('Cold-start retries', 0xF5E6F, bytes.fromhex('837db002'),
                         after=bytes.fromhex('837db00f'), since_revision=2),
                    Edit('Disable legacy port scan', 0xF5EF4, bytes.fromhex('817db40c720000'),
                         port='rpc', prefix=bytes.fromhex('817db4'), since_revision=2),
                    Edit('Backend permission check', 0xF3520, bytes.fromhex('48817dd0ff090000'),
                         after=bytes.fromhex('48817dd0ed090000')),
                    Edit('Backend authorization mode', 0x206E90, b'04777', after=b'04755'),
                    Edit('Directory authorization mode', 0x206EA9, b'04777', after=b'00755'),
                ),
            ),
            BinaryRule(
                HELPER, 'd36a2e951c52e344a414b449b41f017248d127f1234ac1e83f9b80a290a53c9e', 8,
                (Edit('RPC listener', 0x57C6, bytes.fromhex('bf07720000'),
                      port='rpc', prefix=bytes.fromhex('bf')),),
            ),
            BinaryRule(
                BACKEND, '426a59bb1342ec5cff995581c9b3d1fbba622b7bcc623dc468a16c9b5b4f19f1', 7,
                (Edit('Backend listener', 0x11853, bytes.fromhex('c745c0744a0000'),
                      port='backend_initial', prefix=bytes.fromhex('c745c0')),),
                pac_count=2,
            ),
        ),
    ),
)
