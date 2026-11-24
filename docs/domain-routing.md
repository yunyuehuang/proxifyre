# 按域名分配代理

本地修改版支持把进程、TCP/UDP 协议和域名条件组合起来选择 SOCKS5 代理。参见仓库根目录的 `app-config.domain-routing.sample.json`。原有不含域名条件的配置继续按原规则运行。

## 配置与匹配顺序

每条 `proxies` 规则新增两个可选数组：

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `domains` | 完整域名匹配 | `["store.steampowered.com"]` |
| `domainSuffixes` | 匹配域名本身及所有子域名 | `["steamcontent.com"]` |

`steamcontent.com` 后缀匹配 `steamcontent.com` 和 `cdn.steamcontent.com`，不匹配 `evilsteamcontent.com`。两个数组之间是“或”，与进程和协议条件之间是“且”。两数组都省略或为空时，规则匹配所有目标地址，可用于兜底。

域名不区分大小写，支持国际化域名，保存时转成 ASCII/Punycode；每个数组最多 256 项。后缀也可输入 `.example.com` 或 `*.example.com`，其含义同 `example.com`。完整域名不接受通配符；均不接受 URL、路径、端口或 IP 字面量。

规则从上往下选取首个匹配项，**域名规则必须放在对应的兜底规则前面**。进程、协议或域名不匹配时继续下一条；已经匹配的规则若不支持目标地址族或没有可用监听器，仍按原行为阻断，不跳到后面的代理。没有任何匹配规则时直连。

示例配置的效果：

| Steam 的目标 | 协议 | 代理 |
| --- | --- | --- |
| `store.steampowered.com` 或 `steamcontent.com` 及其子域名 | TCP / UDP | `127.0.0.1:7899` |
| 其他域名、无法识别域名、直接访问 IP | TCP | `127.0.0.1:7897` |
| 其他域名、无法识别域名、直接访问 IP | UDP | `127.0.0.1:7898` |

这些端口是示例，需要替换成真实运行的 SOCKS5 服务；UDP 代理必须支持 UDP ASSOCIATE。若仅希望指定域名走代理，删除示例中的两条兜底规则即可。示例域名不代表完整的 Steam 服务器清单。

GUI：编辑规则，在 Traffic 区域点击 **Domains...**，每行输入一个域名或后缀。主列表的 Domains 列显示条件；空条件显示 All destinations。保存后执行 **Apply & Restart**。

## DNS 学习与连接保持

启用任意域名条件后，引擎观察网络适配器上 UDP/TCP 53 的 DNS 请求和响应，包括由 Windows DNS Client 服务代发的查询。支持 IPv4、IPv6、A/AAAA、CNAME 链、DNS 压缩，以及 TCP DNS 的分段、重传和有限乱序。只有与已观察到的请求在连接、事务 ID 和问题上相符的成功响应才更新映射。

映射按 DNS TTL 过期，CNAME 链取最短 TTL，最长保留一天；TTL=0 和成功的无记录响应会替换旧映射。错误或不完整响应不更新映射，已有记录仍到 TTL 才过期。不会主动做反向 DNS 查询。

新连接使用目标 IP 查询域名映射，再执行规则匹配；SOCKS5 请求仍传目标 IP，并不改成远端域名解析。已经选定的 TCP 连接或 UDP 流保持原决定，DNS 更新不会中途更换代理。UDP 流按源/目标地址和端口、进程区分，同一个 UDP socket 访问不同目标可以分配不同代理。UDP 空闲超过 120 秒、TCP 空闲超过两小时后可重新判断；TCP 新 SYN 的序列号变化也会重新判断。启动前已有且未观察到 SYN 的 TCP 连接保持直连，应重启目标程序。

缓存有上限：16,384 条地址绑定、4,096 个待响应查询、1,024 个 TCP DNS 单向流、32,768 个路由决定。DNS 容量不足时无法学习的新地址走后续兜底；路由决定容量不足时丢弃新流的数据，避免因逐出活跃决定而中途更换路由。

## 使用边界

- **这是 DNS 地址映射，不是逐个 HTTP 请求识别域名。** 多个域名共用 CDN IP 时，该 IP 可能同时对应多个域名，按配置中最先匹配的规则选择；无法区分同一 IP 上不同 HTTPS 请求。连接复用同样不会重新判断域名。
- DoH、DoT、程序/系统已有 DNS 缓存、仅经过本机 loopback 的解析、直接访问 IP 等情况可能没有可观察的 DNS 查询，按兜底处理。若该 IP 已由其他查询学到域名，仍可能命中该映射。
- 首次使用建议先启动引擎，再以管理员权限执行 `Clear-DnsClientCache`，然后重新启动 Steam。程序自己的 DNS 缓存也需要退出程序才能清除。
- 不解析分片 DNS 报文；不支持的报文不学习域名。原有的分片转发限制仍然适用，参见 [configuration.md](configuration.md)。
- `dns.mode` 与域名分流是两个独立功能。DNS 53 端口流量始终优先服从全局 DNS Direct/Proxy 策略；两种模式都能学习实际观察到的应答，包括代理回传后还原的 DNS 响应。DNS Proxy 的 `serverOverride` 可用于指定远端 DNS。
- `excludes` 和 LAN bypass 保持原有优先级；命中域名不会强制代理已排除进程或已旁路的 LAN 目标。LAN 解析器的 53 端口仍会被观察。

需要逐请求区分共享 IP、DoH 场景或让代理端解析域名时，应使用额外的 DNS/Fake-IP 或应用层方案；本版本没有实现这些能力。
