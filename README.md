# HY2 + WARP Toolkit

更新：2026-10-26。全新 Ubuntu VPS 的参考安装器：**HY2 / UDP 443 + VLESS WebSocket TLS / TCP 443**，共用选择性 WARP 分流，另附私有备份与同机恢复工具。

公开仓库：[shitanlylee0516/hy2-warp-toolkit](https://github.com/shitanlylee0516/hy2-warp-toolkit)。MIT 许可证。只发布通用源码、测试和文档，不包含节点凭证或真实服务器备份。

## 支持范围

- Ubuntu **22.04 / 24.04**、**x86_64**、systemd、root、公网 IPv4，已安装 Python 3。
- 能连接 Ubuntu 软件源、GitHub、Cloudflare 和 Let's Encrypt。
- 全新、没有网站或代理占用相关目录及端口的 VPS；拒绝覆盖未受管理的现有服务。
- 服务商安全组自行放行 SSH、TCP 80/443、UDP 443；脚本只能设置本机 UFW。
- 不支持 ARM、其他发行版、容器、IPv6-only 或重装系统后的整机恢复。

核心固定为 **sing-box 1.14.4 / linux-amd64**，校验官方发布包 SHA-256。脚本不自动重启服务器。

## 安装

先下载、阅读脚本和条款，再执行。以下命令只适用于全新 VPS：

~~~bash
git clone https://github.com/shitanlylee0516/hy2-warp-toolkit.git
cd hy2-warp-toolkit
sha256sum -c SHA256SUMS
sudo bash install-hy2.sh
~~~

也可下载仓库 ZIP，解压后执行同样的校验和安装命令。两个 shell 脚本分别为独立入口，不会在线执行其他项目脚本。

交互时二选一：有自己的域名，或使用自己的公网 IPv4 申请可信 IP 证书。**两种方式使用相同的双节点及分流设置**，最后显示两条分享链接和一条 HTTPS 订阅链接，可导入 v2rayN。

非交互，有域名：

~~~bash
sudo bash install-hy2.sh --domain node.example.com --email you@example.com --accept-terms
~~~

无域名，将 YOUR_PUBLIC_IPV4 换成本机拥有的公网 IPv4：

~~~bash
sudo bash install-hy2.sh --ip YOUR_PUBLIC_IPV4 --email you@example.com --accept-terms
~~~

可增加 --port 32443 自定义 HY2 UDP 端口；TCP 备用入口仍为 443。排除本地 WARP 端口 40000。内部 TCP 18080 只监听回环，不要对公网放行。

邮箱用于 ACME/Certbot 联系信息，不是节点账号，也不保证到期邮件提醒。--accept-terms 表示同意 [Let's Encrypt 条款](https://letsencrypt.org/repository/) 与 [Cloudflare WARP 条款](https://www.cloudflare.com/application/terms/)，请自行阅读。

同一安装器管理的节点重跑时保留域名、端口、密码、随机订阅路径及 TCP 身份。旧管理状态只新增尚不存在的 TCP 身份；发现独立的未管理 TCP 节点则拒绝接管。**其他脚本部署的节点不要直接运行安装器覆盖**，请使用备份恢复入口。

### 域名和证书

- 有域名：A 记录指向 VPS，使用 DNS-only 灰云，先处理错误 AAAA 记录。普通 Cloudflare 橙云不能承载 HY2。
- 无域名：使用 Certbot >=5.4 的短期 IP 证书，约 6 天有效，每小时检查续期；公网 TCP 80 必须持续可达。
- 有域名模式使用常规续期。不要关闭续期入口、定时器或部署钩子。
- 保持证书验证开启。连接地址是 IP 时，也可通过正确 SNI 验证域名证书，不需要“允许不安全”。

## 结构与分流

~~~text
客户端 ── UDP 443 ── sing-box / HY2
客户端 ── TCP 443 ── Nginx / TLS + WS ── 127.0.0.1:18080 / VLESS
                                      两条节点使用相同分流
~~~

- Google、Gemini、AI Studio、Antigravity 相关 Google/API 域名走 WARP。
- YouTube、youtu.be、youtube-nocookie、googlevideo、ytimg、ggpht 走同一 WARP，减少跳转前后的出口差异。
- Muse、Meta、Facebook、Instagram 及列出的相关资源域名走 WARP。
- 相关域名 UDP 443 被拒绝，使支持回落的客户端使用 TCP；其他流量默认走 VPS 原出口。
- 拒绝回环、私网、链路本地和云元数据目标；WARP SOCKS 只监听本机 40000。

WARP **不保证固定美国 IP、固定出口或第三方账号资格**。首页 HTTP 200、登录后可用与视频实际播放是不同验收项。地区限制也可能因账号而异；脚本不注册 AI 账号或绕过账号资格。

安装器另配置 SSH 放行、Fail2ban、自动安全更新、服务自动拉起及随机订阅路径。失败回退覆盖受管理的部署文件和服务，不撤销软件包、WARP 注册或整机所有设置。

## 备份

备份不停止服务、不重新生成凭证：

~~~bash
sudo bash hy2-backup.sh backup
sudo bash hy2-backup.sh backup --output /var/backups/hy2-oneclick/my-node-backup.tar.gz
~~~

支持标准 /etc/hy2-node 和可选独立 /etc/hy2-tcp。双节点备份核对 UUID、路径、SNI、Host、ALPN、订阅及共用分流，同时保存服务、核心、Nginx、证书续期资料和 WARP 配置。旧单 HY2 节点也可备份。

默认目录 0700、归档 0600，逐文件校验哈希，SQLite 使用在线快照。**归档含真实密码、私钥及 WARP 凭证，不加密。**只作私有保存，不要上传 GitHub、公开网盘或 issue；.gitignore 不能代替人工检查。

## 校验与同机恢复

~~~bash
sudo bash hy2-backup.sh verify /path/to/private-backup.tar.gz
sudo bash hy2-backup.sh restore /path/to/private-backup.tar.gz
~~~

只支持同一机器、系统及基础依赖仍在的配置恢复，检查机器 ID。恢复会重启相关服务并短暂断网，先确保有 SSH 维护连接。

- 检查归档路径、大小、哈希、证书链接、双节点配置和核心语法后才部署。
- 保存当前受影响文件及服务状态；失败尝试回退，回退不完整会明确报错并保留资料。
- 当前存在 TCP 节点时，拒绝用缺少 TCP 数据的旧归档部分恢复。
- 不提供跨机迁移、自动重装系统、任意服务接管或断电/磁盘损坏的整机恢复保证。

## v2rayN 与排错

- HY2 选择 sing-box，路由保持“绕过大陆”，TUN 按需开启。
- 一套实测国内访问设置：MTU 1500、直连 DNS https://dns.alidns.com/dns-query、屏蔽 AAAA。按自己的网络验证，不保证每个环境都必须采用。
- HY2 超时而 TCP 443 可达时，试 TCP-443-Backup；TCP 握手成功不等于 TLS/WS/认证成功。
- Nginx 监听 TCP 443 是正常设计，客户端不要误填内部 18080。
- Google 异常流量先检查跳转出口，不能只凭延迟或首页 200 判断。
- B 站优先使用 HTTPS，不要关闭证书校验或安全连接保护来消除警告。
- Muse 重登或等待名单需区分账号与网络；退出后页面没更新可先刷新，验证码后等待加载，避免连续提交。
- 家中可用、单位失败时，用同一台单位电脑对比办公网络和手机热点，不能直接断定 DPI。

## 离线验证

在 Linux 上运行，不会安装软件、签发证书或改动现用节点：

~~~bash
bash -n install-hy2.sh
bash -n hy2-backup.sh
bash install-hy2.sh --self-test
bash hy2-backup.sh self-test
python3 test_tcp.py
python3 test_offline.py
python3 test_archive_independent.py hy2-backup.sh
python3 test_transactions.py hy2-backup.sh
~~~

脱敏预览：

~~~bash
bash install-hy2.sh --plan --domain node.example.com --email you@example.com
~~~

测试覆盖参数、双节点身份、YouTube 规则、归档损坏/越界拒绝及失败回退。模板/核心/Nginx 的独立检查不等于全新 VPS 完整安装；未在现用服务器运行安装器、生产恢复或重新签发 IP 证书。范围之外请先在可丢弃服务器上评估。

## 安全与许可证

参见 [SECURITY.md](SECURITY.md) 和 [MIT LICENSE](LICENSE)。sing-box、Nginx、Certbot、WARP 各自的许可证或条款仍适用；不重新分发其二进制。

官方：[sing-box 1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)、[Nginx WebSocket](https://nginx.org/en/docs/http/websocket.html)、[短期 IP 证书](https://letsencrypt.org/2026/03/11/shorter-certs-certbot)、[WARP 软件源](https://pkg.cloudflareclient.com/)。
