# UniVPN Multi for macOS

在同一台 Mac 上运行多个 UniVPN 窗口，分别连接不同 VPN 网关。一个命令自动选择空闲实例，按需生成、安装并启动客户端副本。

```sh
./vpn-new
```

这是一个**按已审核构建规则自动适配的实验工具**。工具自动读取客户端版本、架构和核心文件哈希，选择唯一匹配的规则；未适配或不兼容时明确提示并停止。截至 2026-10-20，用户已验证三个 VPN 同时登录并保持在线至少 2 分钟；四个同时连接、各内网业务、DNS 和断线恢复尚未完整验收。打开窗口、进程就绪或文件校验通过，均不代表 VPN 连接及业务验收通过。

仓库仅包含工具源码、测试和文档。客户端必须由用户自行安装，本仓库不分发厂商 App、网关配置、账号、密码记录或运行日志。

## 支持环境

- macOS；实测环境为 Apple Silicon、macOS 26.5、Rosetta。
- Python **3.9 或更新版本**，仅使用标准库，无需 `pip install`。
- 原版安装于 `/Applications/UniVPN.app`，由工具自动识别并匹配内置规则，无需手选版本。
- **目前内置已验证规则仅覆盖 `10781.19.0.1214 / x86_64` 的指定构建。** 多版本识别和规则分发机制已经具备，其他真实构建仍需取得样本并审核规则后加入；不表示任意版本已经可用。
- 三个原始可执行文件必须整体匹配同一份规则的[精确 SHA256](docs/ANALYSIS.md#兼容性门槛)。版本号相同但文件不同、混合组件、原生 arm64 或 Universal 构建，当前均会明确拒绝。
- 原版可单独正常登录。希望复用网关及已保存密码时，先在原版中保存配置，并按需勾选“记住密码”。

客户端的认证、短信验证码、证书校验及网关策略仍由原软件执行。脚本不会替用户提交验证码。

## 快速开始

```sh
git clone git@github.com:abjfj/univpn-multi-macos.git
cd univpn-multi-macos

# 列出当前内置的已审核版本规则
python3 univpn_multi.py profiles

# 只读识别本机版本、架构、哈希和兼容性
python3 univpn_multi.py inspect

# 预览下一次会打开哪个实例
./vpn-new --dry-run

# 打开下一个窗口，随后在窗口中选择网关并登录
./vpn-new
```

每次运行 `./vpn-new`：

1. 只读识别原版并校验所匹配规则的全部补丁前置条件。未适配或不兼容时，在创建生成目录、配置写入、sudo 或路由修改之前停止。
2. 原版的界面、提权服务和连接后台均已退出时，优先打开原版。
3. 否则复用同一构建的空闲已安装副本；没有时自动创建 `UVP002`、`UVP003` 等新副本。其他构建的副本不覆盖、不复用。
4. 副本启动前继承原版中尚未存在的网关、地址、端口、用户名和厂商保存的密码记录，关闭自动登录。已有同名配置默认保留。
5. 检查所有原版已保存网关的物理出口保护，缺少时补齐，再启动窗口。

`inspect` 输出 JSON，包含 `version`、`architecture`、`supported`、`profile`、`reason` 及三个核心文件的 SHA256。未适配构建返回 `supported: false` 和非零退出状态；不会按相近版本猜测偏移，也没有跳过兼容性校验的强制参数。报告不读取网关 INI、账号、登录记录或日志。可以用 `--source /path/to/UniVPN.app` 只读检查其他安装副本，详见[版本适配说明](docs/COMPATIBILITY.md)。

首次安装副本、或需要增加网关保护路由时，会在终端调用 `sudo`，按提示输入 **Mac 管理员密码**。请以普通用户执行 `./vpn-new`，不要给整个命令加 `sudo`。脚本不接收明文 VPN 密码参数，不解密或输出保存的密码记录；不同客户端版本的记录兼容性没有保证。

重复执行即可打开更多窗口。仍有界面或连接后台的副本会被视为占用，不会为复用它而断开连接。实例编号支持 2–999，这只是命名范围，不是并发能力保证。

要用原版的最新同名配置和已保存登录记录更新即将启动的空闲副本：

```sh
./vpn-new --sync-original
```

覆盖前会备份到该副本的 `~/.UVPnnn/.multi-backups/inherit-original-*` 私有目录，复制的文件权限为 `0600`。不会同步正在运行的副本，不修改原版配置，也不复制原版的程序身份和 `key.ini`。

## 网关出口保护

全隧道 VPN 可能接管默认路由，导致其他 VPN 的公网网关被送入它的隧道，表现为先连接的掉线或新增连接超时。客户端还会暂时删除自身的 `/32` 网关路由，因此本工具为保存的网关添加独立的 **`/31` 物理出口回退路由**。

每条 `/31` 额外包含一个相邻公网 IP。工具不修改默认路由、业务网段、DNS 或认证；现有同前缀路由出口不一致时会拒绝覆盖。当前仅支持原版配置中直接指定的 **IPv4 公网地址**，不支持域名、IPv6 或私网网关。仅保存在副本中的网关不在自动发现范围内。

`vpn-new` 会自动检查全部原版已保存网关。也可手动操作：

```sh
# 只读查看计划
python3 gateway_routes.py inspect

# 保留已有保护，只补缺少的条目
sudo python3 gateway_routes.py protect

# 正常断开相关 VPN 后，撤销本工具记录的路由
sudo python3 gateway_routes.py restore
```

多个物理出口无法唯一判断时，可给 `inspect` / `protect` 传入 `--interface en0`；只处理某些配置时可重复传入 `--profile 'gateway-a.ini'`。恢复记录为 `/var/run/univpn-multi-gateway-routes.json`，仅 root 可读写，撤销时核对前缀、下一跳、接口及 PROTO2 标记。没有安装后台守护进程；换网络或重启后需要重新检查。详见[路由排障](docs/TROUBLESHOOTING.md#第二条连接后第一条掉线或第三条无法建立连接)。

## 手动命令

通常使用 `./vpn-new` 即可。需要分步检查时：

```sh
# 离线生成：不安装、不启动，拒绝覆盖已有生成目录
python3 univpn_multi.py build --number 2
python3 univpn_multi.py verify build/instance-002/UVP002.app

# 安装到 /Applications；拒绝覆盖已存在的 App
sudo python3 univpn_multi.py install build/instance-002/UVP002.app

# 普通用户启动指定副本；此命令不执行配置继承或网关保护
python3 univpn_multi.py start --number 2
```

不要从 `build/` 直接运行副本，不要移动或重命名已安装的 App。生成目录中的 UI 故意不可执行，安装后才设置运行权限。副本的未适配升级程序被移除；网关强制升级流程不受支持。当前支持的原始构建未签名，工具不添加开发者签名或公证，也不要求关闭 SIP。

旧副本修复、配置错误和退出移除，见[故障排查](docs/TROUBLESHOOTING.md)。

## 验证与限制

所有实例仍共享 macOS 的系统路由、DNS 和代理。网关保护只维持公网控制连接的物理出口，不能解决重叠业务网段、分域 DNS、代理覆盖或服务器端并发限制。

- 不同内网目标的路由和域名解析需逐项验证。
- 相同目标 IP 同时属于不同内网时，普通目的地址路由无法区分，应考虑分别运行在虚拟机等隔离系统中。
- 界面存在选择最大 utun 编号显示 IPv4 地址的原逻辑，显示归属可能不准确，应以路由和真实业务结果判断。
- 后台或插件可能在初始端口绑定失败时尝试其他端口；启动前检查预期端口仍不能替代运行后的核对。

只读网络快照可用于比较连接前后状态，输出包含网络地址和 DNS 等本机信息，请保留在本地：

```sh
python3 network_snapshot.py build/snapshots/before
```

项目测试：

```sh
python3 -m unittest discover -s tests -v
```

离线测试使用临时文件和模拟路由，不连接 VPN、不修改系统网络。安装了受支持原版或存在生成副本时，还会执行相应的只读文件检查；缺少它们时跳过。自动检查不分发或安装厂商客户端。完整实测边界及业务验收步骤见[验证说明](docs/VALIDATION.md)。

## 项目结构

| 路径 | 用途 |
|---|---|
| `vpn-new` | 无需指定编号的启动入口 |
| `univpn_multi.py` | 构建、校验、安装、启动、修复、配置继承 |
| `univpn_profiles.py` | 已审核构建规则、哈希、独立补丁偏移及前置字节 |
| `gateway_routes.py` | 公网网关物理出口保护及撤销 |
| `network_snapshot.py` | 只读网络快照 |
| `tests/` | 标准库 unittest 测试 |
| `docs/ANALYSIS.md` | 二进制身份、端口、偏移及配置机制 |
| `docs/COMPATIBILITY.md` | 自动识别行为、拒绝条件及新版本接入 |
| `docs/TROUBLESHOOTING.md` | 启动、配置、路由及移除操作 |
| `docs/VALIDATION.md` | 已验证结果、限制及验收步骤 |
| `CONTRIBUTING.md` | 开发检查及提交要求 |

`build/`、本地研究资料、配置、日志和备份均不纳入版本管理。

## 参考

方案参考 [UsernameFull/univpn-multi](https://github.com/UsernameFull/univpn-multi)，研究时上游提交为 `0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121`。上游面向 Windows；本项目针对 macOS Mach-O、进程和网络行为独立实现，不复用 Windows 二进制偏移、服务注册或 TAP 驱动。参考项目与厂商软件说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
