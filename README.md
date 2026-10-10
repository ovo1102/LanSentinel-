# LanSentinel 局域网威胁感知系统

> 基于 Java Socket 与多线程技术的轻量级局域网安全检测工具，集**网段扫描、蜜罐诱捕、ARP 欺骗检测、统一告警与报告防篡改**于一体。

LanSentinel 是「Java 语言及网络编程」课程的结课项目，面向信息安全方向设计。它既可以作为内网资产梳理与安全基线检查的辅助工具，也通过低交互蜜罐与 ARP 基线比对演示了常见内网攻击的检测原理。

> **法律与合规提示**：本工具内置授权网段强制校验，仅供在**已获得书面授权**的网络环境中学习与自测使用。使用者需自行遵守《中华人民共和国网络安全法》及当地法律法规，禁止用于任何未授权的扫描、探测或攻击行为。

## 目录

- [功能特性](#功能特性)
- [技术栈](#技术栈)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [使用示例](#使用示例)
- [项目结构](#项目结构)
- [核心设计](#核心设计)
- [贡献指南](#贡献指南)
- [常见问题](#常见问题)
- [许可证](#许可证)

## 功能特性

| 模块 | 功能 | 说明 |
| --- | --- | --- |
| 网段扫描 | 主机存活探测 | ICMP 探测为主，TCP 常用端口（135/445/80 等）兜底，适配 Windows 权限限制 |
| 网段扫描 | 多线程端口扫描 | 固定线程池并发 TCP connect 探测，扫描范围与并发数可配置 |
| 网段扫描 | Banner 抓取与服务识别 | 抓取 SSH/FTP/HTTP 等服务指纹，识别服务版本信息 |
| 网段扫描 | 服务一致性检查 | 比对端口预期服务与实际 Banner，发现服务错位、隐蔽后门 |
| 网段扫描 | 主机风险评分 | 依据高危端口知识库与错位服务给出 0~100 风险分 |
| 蜜罐诱捕 | 多协议低交互伪装 | 内置 Telnet（2323）、SSH（2222）、FTP（2121）、HTTP（8080）四类诱饵 |
| 蜜罐诱捕 | 攻击行为捕获 | 记录攻击者来源 IP、凭据尝试、客户端工具指纹、HTTP 请求 |
| 蜜罐诱捕 | 自动攻击研判 | R1 端口扫描检测、R2 暴力破解检测（滑动时间窗口 + 去重） |
| ARP 监控 | IP-MAC 基线比对 | 周期解析系统 ARP 表，检测同一 IP 的 MAC 变更（冒充网关） |
| ARP 监控 | 中间人劫持检测 | 识别同一 MAC 同时映射多个 IP 的异常特征 |
| 安全合规 | 授权网段硬约束 | 所有扫描目标必须位于授权网段（默认 `172.20.85 ~ 172.20.104`），越界即拒绝 |
| 统一告警 | 告警总线 | 各检测模块基于观察者模式向告警中心汇聚事件，模块间零耦合 |
| 图形界面 | Swing 四页签界面 | 网段扫描 / 蜜罐诱捕 / ARP 监控 / 告警中心，后台线程不卡界面 |
| 报告系统 | HTML 报告导出 | 自动生成含概览、主机端口清单、告警汇总的格式化报告 |
| 报告系统 | SHA-256 防篡改 | 报告同时生成 `.sig` 签名文件，支持事后一键完整性校验 |

## 技术栈

- **语言**：Java（JDK 21 验证通过，语法兼容 JDK 17+）
- **网络编程**：`java.net.Socket` / `ServerSocket` / `InetAddress`
- **并发编程**：`ExecutorService` 固定线程池、`ScheduledExecutorService` 定时调度、`SwingWorker`
- **图形界面**：Java Swing（JTabbedPane / JTable / JFileChooser，无第三方依赖）
- **安全相关**：`MessageDigest`（SHA-256）、系统命令解析（`arp -a`）
- **构建方式**：JDK 原生命令编译，无需 Maven/Gradle，无任何第三方库

## 快速开始

### 环境要求

| 项目 | 要求 |
| --- | --- |
| JDK | 17 或更高版本（开发与验证使用 JDK 21） |
| 操作系统 | Windows 10/11（ARP 解析针对 Windows `arp -a` 输出适配，扫描与蜜罐功能跨平台） |
| 网络 | 演示多机联动时，主机需处于或可路由到授权网段 |

检查 Java 环境：

```bash
java -version
javac -version
```

### 安装步骤

1. 克隆仓库：

   ```bash
   git clone https://github.com/ovo1102/LanSentinel-.git
   cd LanSentinel-
   ```

2. 编译全部源码（编译产物输出到 `out/` 目录，已被 `.gitignore` 忽略）：

   ```bash
   javac -encoding UTF-8 -d out -sourcepath src src/sec/lansentinel/Main.java
   ```

### 配置方法

编辑 [`resources/config.properties`](./resources/config.properties)，关键配置项如下：

```properties
# 授权网段（课程分配，程序强制校验，不可逾越）。缩写 172.20.85 表示 172.20.85.0/24 整段
auth.range.start=172.20.85
auth.range.end=172.20.104

# 实际扫描范围（必须是授权网段的子集，演示时可缩小以提速）
scan.range.start=172.20.85.1
scan.range.end=172.20.85.20

# 扫描超时、线程池大小与默认端口
scan.host.timeout=800
scan.port.timeout=500
scan.banner.timeout=1500
scan.thread.pool=50
scan.default.ports=21,22,23,80,135,139,443,445,3306,3389,5900,8080

# 蜜罐诱饵端口
honeypot.ports=2323,2222,2121,8080

# 高危端口知识库（用于风险评分）
risk.high.ports=21,23,445,3389,5900,4444

# ARP 轮询间隔（秒）
arp.interval=30
```

### 启动命令

在**项目根目录**（`resources/` 所在目录）下执行，无参数默认启动图形界面：

```bash
# 图形界面（默认）
java -cp out sec.lansentinel.Main

# 控制台自检模式（无需第二台机器即可验证各模块）
java -cp out sec.lansentinel.Main scan      # 网段扫描 + 授权校验演示
java -cp out sec.lansentinel.Main honeypot  # 蜜罐诱捕 + 模拟攻击自检
java -cp out sec.lansentinel.Main arp       # ARP 欺骗检测自检
```

> Windows PowerShell 下若控制台中文乱码，先执行 `chcp 65001` 切换代码页，再用 `java "-Dstdout.encoding=UTF-8" -cp out sec.lansentinel.Main` 启动。

## 使用示例

### 示例 1：图形界面扫描网段

1. 启动程序后默认进入「网段扫描」页签，IP 与端口已按配置文件预填；
2. 输入授权网段**以外**的 IP（如 `192.168.1.1`）会被弹窗拒绝；
3. 点击「开始扫描」，进度条实时显示进度，在线主机及其开放端口、风险分写入结果表；
4. 点击「导出报告」选择目录，生成 HTML 报告与同名 `.sig` 签名文件。

### 示例 2：验证报告防篡改

1. 扫描完成后导出报告，得到 `report_xxxx.html` 与 `report_xxxx.html.sig`；
2. 用记事本打开 HTML 报告，任意修改一处内容后保存；
3. 在扫描页签点击「校验报告」并选择该文件，程序重新计算 SHA-256 并提示**校验失败：报告已被篡改**。

### 示例 3：蜜罐诱捕（单机自检）

```bash
java -cp out sec.lansentinel.Main honeypot
```

程序自动布设四个诱饵端口，并模拟攻击者行为：对 Telnet 诱饵连续尝试 3 组凭据、快速触碰多个诱饵端口。预期输出：

```text
>>> 触发告警 [CRITICAL] [蜜罐] 127.0.0.1 正在扫描网络（60秒内触碰 3 个诱饵端口）
>>> 触发告警 [WARNING] [蜜罐] 127.0.0.1 正在进行暴力破解（60秒内尝试 3 组凭据）
```

### 示例 4：双机真实联动演示

1. 主机 A 配置静态 IP `172.20.90`（子网掩码 `255.255.255.0`），启动图形界面并在「蜜罐诱捕」页签点击「布防蜜罐」；
2. 主机 B（或虚拟机）配置同网段 IP `172.20.91`，执行 `telnet 172.20.90 2323` 并输入弱口令；
3. 主机 A 的「蜜罐诱捕」页签实时显示来源 IP 与凭据，「告警中心」页签出现暴力破解告警；
4. 在主机 B 运行本工具的扫描功能扫描主机 A，即触发端口扫描告警——扫描器与蜜罐互为攻防验证。

## 项目结构

```text
LanSentinel/
├── resources/
│   └── config.properties              # 授权网段、扫描参数、诱饵端口等配置
├── src/sec/lansentinel/
│   ├── Main.java                      # 程序入口（gui / scan / honeypot / arp 四种模式）
│   ├── core/
│   │   ├── scan/                      # 扫描引擎
│   │   │   ├── ScanEngine.java        # 线程池调度、风险评分
│   │   │   ├── HostDiscovery.java     # 主机存活探测（ICMP + TCP 兜底）
│   │   │   ├── PortScanner.java       # 单主机端口扫描任务
│   │   │   ├── BannerGrabber.java     # 服务 Banner 抓取
│   │   │   └── ServiceChecker.java    # 端口-服务一致性检查
│   │   ├── honeypot/                  # 蜜罐服务
│   │   │   ├── HoneypotServer.java    # 诱饵端口统一布防/撤防
│   │   │   ├── HoneypotListener.java  # 单端口 accept 循环
│   │   │   ├── SessionHandler.java    # 单次攻击会话处理
│   │   │   └── emulator/              # 协议伪装（多态）
│   │   │       ├── ServiceEmulator.java
│   │   │       ├── TelnetEmulator.java
│   │   │       ├── SshEmulator.java
│   │   │       ├── FtpEmulator.java
│   │   │       └── HttpEmulator.java
│   │   ├── arp/                       # ARP 欺骗检测
│   │   │   ├── ArpMonitor.java        # 定时轮询、基线比对
│   │   │   └── ArpTableParser.java    # 解析 arp -a 输出
│   │   └── alert/                     # 告警引擎
│   │       ├── AlertEngine.java       # 告警/事件总线（观察者模式）
│   │       ├── AlertRule.java         # 规则接口
│   │       ├── PortScanRule.java      # R1 端口扫描判定
│   │       └── BruteForceRule.java    # R2 暴力破解判定
│   ├── model/                         # 实体类
│   │   ├── HostInfo.java
│   │   ├── PortInfo.java
│   │   ├── AttackEvent.java
│   │   ├── AlertEvent.java
│   │   └── ArpEntry.java
│   ├── service/
│   │   ├── AuthGuard.java             # 授权网段强制校验
│   │   ├── ConfigManager.java         # 配置文件加载
│   │   └── ReportService.java         # HTML 报告导出与 SHA-256 校验
│   ├── ui/                            # Swing 图形界面
│   │   ├── MainFrame.java
│   │   ├── ScanPanel.java
│   │   ├── HoneypotPanel.java
│   │   ├── ArpPanel.java
│   │   └── AlertPanel.java
│   └── util/
│       ├── IpUtil.java                # IP 解析、网段展开、范围校验
│       └── HashUtil.java              # SHA-256 计算
├── .gitignore
└── README.md
```

## 核心设计

- **分层架构**：表现层（Swing 面板）→ 核心引擎层（扫描 / 蜜罐 / ARP / 报告）→ 支撑层（告警引擎、配置与授权校验），各层单向依赖。
- **观察者模式告警总线**：扫描、蜜罐、ARP 三个检测模块互不引用，统一通过 `AlertEngine` 发布事件与告警；新增检测模块只需实现 `AlertRule` 并注册，无需修改既有代码。
- **策略式协议伪装**：`ServiceEmulator` 接口配合 Telnet/SSH/FTP/HTTP 四种实现，新增伪装协议只需增加一个实现类。
- **三种并发模型**：扫描使用固定线程池、蜜罐每端口一个监听线程加会话缓存池、ARP 监控使用单线程定时调度，分别适配 CPU 密集任务、长连接 accept 与周期任务三类场景。
- **安全工具的伦理设计**：`AuthGuard` 在所有扫描动作前强制执行授权网段校验，从代码层面防止工具被滥用。

## 贡献指南

欢迎通过 Issue 与 Pull Request 改进本项目，建议流程如下：

1. Fork 本仓库并克隆到本地；
2. 基于 `main` 创建特性分支，命名建议 `feature/xxx` 或 `fix/xxx`：

   ```bash
   git checkout -b feature/your-feature
   ```

3. 提交代码前请确认：
   - 代码可通过 `javac -encoding UTF-8 -d out -sourcepath src src/sec/lansentinel/Main.java` 正常编译；
   - 三种控制台自检模式（`scan` / `honeypot` / `arp`）均能正常运行；
   - 新增功能附带必要的中文注释，不引入第三方依赖（如确需依赖，请先在 Issue 中讨论）；
4. 提交信息建议遵循约定式提交格式，如 `feat: 新增TLS证书检查`、`fix: 修复端口占用时崩溃`；
5. 推送分支并发起 Pull Request，在描述中说明改动内容、验证方式与截图（如涉及界面）。

## 常见问题

**Q1：扫描结果显示所有主机都离线？**
当前主机未配置授权网段内的 IP。请在网卡上添加静态 IP（如 `172.20.90`，掩码 `255.255.255.0`），或在同网段准备另一台主机/虚拟机后再扫描。

**Q2：提示“目标不在授权范围”怎么办？**
这是 `AuthGuard` 的安全设计而非错误。请确认目标 IP 属于 `config.properties` 中配置的授权网段；学习自测时只能扫描授权网段内的地址。

**Q3：控制台中文显示乱码？**
Windows 下执行 `chcp 65001`，并使用 `java "-Dstdout.encoding=UTF-8" -cp out sec.lansentinel.Main` 启动；建议直接使用图形界面模式。

**Q4：蜜罐启动提示“端口被占用”？**
`2323/2222/2121/8080` 中某端口已被本机其他程序占用，程序会自动跳过该端口。可关闭占用程序，或在配置文件中修改 `honeypot.ports`。

**Q5：首次监听端口时 Windows 弹出防火墙提示？**
选择“允许访问”即可；若误点了取消，可在「Windows  Defender 防火墙 → 允许应用通过防火墙」中为 Java 放行。

**Q6：ARP 监控为什么基线为 0 条？**
ARP 表是通信后动态学习的缓存。先 `ping` 同网段其他主机或网关，让本机产生 ARP 缓存后再启动监控；程序已兼容中文 Windows 的 GBK 编码与“动态/静态”类型输出。

**Q7：为什么蜜罐不实现真正的登录 Shell？**
这是有意为之的**低交互蜜罐**设计：只模拟服务的登录提示与 Banner，避免蜜罐被攻陷后成为攻击者的跳板。

## 许可证

本项目采用 [MIT License](./LICENSE) 开源，允许在保留版权声明与许可声明的前提下自由使用、修改与分发，软件按“现状”提供，不承担任何使用责任。

再次强调：请勿将本工具用于任何未授权的网络活动。
