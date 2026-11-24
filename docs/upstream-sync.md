# 本地改版与上游同步

## 仓库和分支

- 正式源码仓库：当前工作区的 `src/ProxiFyre`；后续代码修改和 Git 操作均在此目录进行。
- 官方远程：`upstream`，地址为 `https://github.com/wiresock/proxifyre.git`。
- 个人推送远程：`origin`，本地配置地址为 `https://github.com/yunyuehuang/proxifyre.git`；首次推送前，需要在该账号下创建对应 Fork。
- 官方基线：`v2.7.0`，提交 `c1757d8e60e8a85e526a638026a05e97d167e03a`。仓库保留官方完整历史，并非独立初始化的源码快照。
- 本地开发分支：`feature/split-tcp-udp-proxies`。
- TCP/UDP 分开选择代理的提交：`5f7ab90`。
- `external/ndisapi` 继续作为上游 Git 子模块管理；按主仓库记录的提交更新。

`downloads/proxifyre-source` 是早期源码参考目录。正式代码以本仓库为准；先前生成的补丁 ZIP 和离线安装包也不会随着 Git 提交自动更新。

## 首次保存分支到个人远程

`upstream` 是官方仓库，当前个人账号没有写权限；推送自定义分支使用 `origin`。本地 `remote.pushDefault` 和开发分支的 `pushRemote` 已设为 `origin`，并已移除开发分支对 `upstream/main` 的跟踪。

1. 登录 GitHub，打开 <https://github.com/wiresock/proxifyre/fork>，在 `yunyuehuang` 账号下创建名为 `proxifyre` 的 Fork。
2. 在 Git 客户端中选择远程 `origin` 推送，或在本仓库运行：

```powershell
git push --set-upstream origin feature/split-tcp-udp-proxies
```

首次推送成功后，开发分支跟踪 `origin/feature/split-tcp-udp-proxies`。官方更新仍通过下节的 `fetch upstream` 和 `merge upstream/main` 合入。

若个人仓库采用其他地址，先运行 `git remote set-url origin <个人仓库地址>`，再推送。命令行 Git 可能需要单独完成 GitHub 登录；图形客户端中已有的登录不一定能被命令行凭据助手复用。

## 合并官方后续更新

在 Windows PowerShell 中进入本仓库。先检查当前工作区，已有修改应先提交或妥善保存，再开始合并。

```powershell
Set-Location -LiteralPath 'C:\code\me\fast\src\ProxiFyre'
git status --short
git switch feature/split-tcp-udp-proxies
git fetch upstream --tags
git log --oneline -n 10 HEAD..upstream/main
git merge upstream/main
git submodule update --init --recursive
```

逐条执行并确认成功，再执行下一条。`fetch` 获取官方更新，`merge` 将更新合入本地开发分支，保留已有自定义提交。如果需要只跟进某次正式发布，可将 `git merge upstream/main` 替换为 `git merge <已核实的发布标签>`。

当前机器访问 GitHub 如需使用本地 SOCKS5，可仅为该次命令指定代理，不修改全局 Git 配置：

```powershell
git -c http.proxy=socks5h://127.0.0.1:7897 fetch upstream --tags
git -c http.proxy=socks5h://127.0.0.1:7897 submodule update --init --recursive
```

有冲突时，用 `git status` 定位冲突文件，解决后暂存具体文件并运行 `git commit` 完成合并。需要放弃仍在进行中的合并时使用 `git merge --abort`。

## 合并后验证

核心行为：同一应用的 TCP/UDP 可以匹配不同代理；同一协议仍由第一条匹配规则决定；排除、地址族不支持和监听端口缺失的处理正确。

本机可使用 WSL Ubuntu 对生产路由头运行独立 C++20 回归测试；该命令不依赖 Windows 驱动或 GoogleTest：

```powershell
wsl.exe -d Ubuntu --exec g++ -std=c++20 -Wall -Wextra -Werror -pthread /mnt/c/code/me/fast/src/ProxiFyre/netlib/test/portable/protocol_routing_policy_test.cpp -o /tmp/proxifyre-protocol-routing-tests
wsl.exe -d Ubuntu --exec /tmp/proxifyre-protocol-routing-tests
```

完整 Windows 构建和测试按 `docs/gui.md` 的 Build and test 执行，原生 ownership 测试按 `netlib/README.md` 执行。安装器构建按 `docs/installer.md` 执行。

本次迁入前，核心 C++ 回归及 40 项配置校验测试通过；迁入后核对全部 11 个改动文件与已测试源码一致，并重新运行核心回归通过。当前机器尚缺 Visual Studio C++/CLI 工具链，没有生成修改后的 Windows 应用或替换现有服务。
