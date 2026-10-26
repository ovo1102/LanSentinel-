<div align="center">

# LanSentinel · 局域网威胁感知系统

**基于 Java Socket 与多线程的轻量级局域网安全检测工具**
**网段扫描 · 蜜罐诱捕 · ARP 欺骗检测 · 统一告警 · 报告防篡改**

[![Java](https://img.shields.io/badge/Java-17%2B-orange?logo=openjdk)](https://openjdk.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen)](#技术栈)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-lightgrey?logo=windows)](#环境要求)

</div>

---

> [!WARNING]
> **法律与合规提示**：本工具内置授权网段强制校验（`AuthGuard`），仅供在**已获得书面授权**的网络环境中学习与自测使用。使用者需自行遵守《中华人民共和国网络安全法》及当地法律法规，**禁止用于任何未授权的扫描、探测或攻击行为**。

## 项目简介

LanSentinel（局域网哨兵）是「Java 语言及网络编程」课程的结课项目，面向信息安全方向设计。它以**纯 JDK、零第三方依赖**的方式实现了一个内网安全检测工具：既能做内网资产梳理与安全基线检查，也通过低交互蜜罐与 ARP 基线比对演示了常见内网攻击的检测原理，各检测模块通过观察者模式的告警总线完全解耦。

**四大核心能力：**

| 能力 | 说明 |
| --- | --- |
| 🔍 网段扫描 | 主机存活探测、多线程端口扫描、Banner 抓取、服务一致性检查、0~100 风险评分 |
| 🍯 蜜罐诱捕 | Telnet / SSH / FTP / HTTP 四类低交互诱饵，捕获攻击凭据与工具指纹，自动研判 |
| 🛡️ ARP 欺骗检测 | 周期解析系统 ARP 表，IP-MAC 基线比对，识别冒充网关与中间人劫持 |
| 📊 界面与报告 | Swing 四页签 GUI、HTML 报告导出、SHA-256 签名防篡改校验 |

## 功能特性

<details open>
<summary><b>🔍 网段扫描引擎</b></summary>

- 主机存活探测：ICMP 为主，TCP 常用端口（135/445/80）兜底，适配 Windows 权限限制
- 多线程端口扫描：固定线程池并发 TCP connect，端口范围与并发数可配置
- Banner 抓取与服务识别：提取 SSH / FTP / HTTP 等服务指纹与版本信息
- 服务一致性检查：比对端口预期服务与实际 Banner，发现服务错位、隐蔽后门
- 主机风险评分：基于高危端口知识库与错位服务，输出 0~100 风险分
</details>

<details>
<summary><b>🍯 蜜罐诱捕引擎</b></summary>

- 多协议低交互伪装：Telnet（2323）、SSH（2222）、FTP（2121）、HTTP（8080）四类诱饵
- 攻击行为捕获：记录来源 IP、登录凭据尝试、客户端工具指纹、HTTP 请求
- 自动攻击研判：R1 端口扫描检测、R2 暴力破解检测（60s 滑动时间窗口 + 去重）
- 低交互安全设计：只模拟登录提示与 Banner，蜜罐被攻陷也不会成为攻击跳板
</details>

<details>
<summary><b>🛡️ ARP 欺骗检测引擎</b></summary>

- IP-MAC 基线比对：周期解析 `arp -a`，检测同一 IP 的 MAC 变更（冒充网关）
- 中间人劫持识别：发现同一 MAC 同时映射多个 IP 的异常特征
- 兼容中文 Windows 的 GBK 编码与「动态/静态」类型输出
</details>

<details>
<summary><b>🔒 安全合规与支撑能力</b></summary>

- 授权网段硬约束：所有扫描目标必须位于授权网段（默认 `172.20.85 ~ 172.20.104`），越界即拒绝
- 统一告警总线：各检测模块基于观察者模式向告警中心汇聚事件，模块间零耦合
- HTML 报告导出：含概览、主机端口清单、告警汇总的格式化报告
- SHA-256 防篡改：报告附带 `.sig` 签名文件，支持一键完整性校验
</details>

## 技术栈

| 维度 | 内容 |
| --- | --- |
| 语言 | Java（JDK 21 验证通过，语法兼容 JDK 17+），**无任何第三方依赖** |
| 网络编程 | `java.net.Socket` / `ServerSocket` / `InetAddress` |
| 并发编程 | 固定线程池（扫描）、监听线程 + 缓存线程池（蜜罐）、`ScheduledExecutorService`（ARP）、`SwingWorker`（GUI） |
| 图形界面 | Java Swing（JTabbedPane / JTable / JFileChooser） |
| 安全相关 | `MessageDigest`（SHA-256）、系统命令解析（`arp -a`） |
| 构建方式 | JDK 原生命令编译，无需 Maven / Gradle |

## 架构设计

```text
┌─────────────────────────────────────────────────────┐
│  表现层  ui（MainFrame + 扫描/蜜罐/ARP/告警 四页签）   │
└──────────────────────┬──────────────────────────────┘
                       ▼ 单向依赖
┌─────────────────────────────────────────────────────┐
│  核心引擎层  core.scan / core.honeypot / core.arp     │
└──────────────────────┬──────────────────────────────┘
                       ▼ 统一汇入（观察者模式）
┌─────────────────────────────────────────────────────┐
│  告警总线  core.alert（AlertEngine + AlertRule 策略） │
└─────────────────────────────────────────────────────┘

支撑服务 service：ConfigManager / AuthGuard / ReportService
通用工具 util：IpUtil / HashUtil    数据实体 model：5 个纯数据类
```

**关键设计决策：**

- **观察者模式告警总线**：扫描、蜜罐、ARP 三个模块互不引用，统一通过 `AlertEngine` 发布事件；新增检测模块只需实现 `AlertRule` 接口并注册，无需修改既有代码（开闭原则）。
- **策略式协议伪装**：`ServiceEmulator` 接口 + Telnet/SSH/FTP/HTTP 四种实现，新增伪装协议只需增加一个实现类。
- **三种并发模型**：固定线程池适配 CPU 密集的扫描任务；独立监听线程 + 缓存线程池适配蜜罐长连接 accept；单线程定时调度适配 ARP 周期轮询。
- **安全工具的伦理设计**：`AuthGuard` 在所有扫描动作前强制执行授权网段校验，从代码层面防止工具被滥用。

## 快速开始

### 环境要求

| 项目 | 要求 |
| --- | --- |
| JDK | 17 或更高版本（开发与验证使用 JDK 21） |
| 操作系统 | Windows 10/11（ARP 解析适配 Windows `arp -a` 输出，扫描与蜜罐功能跨平台） |
| 网络 | 多机联动演示时，主机需处于或可路由到授权网段 |

### 编译与运行

```bash
# 1. 克隆仓库
git clone https://github.com/ovo1102/LanSentinel-.git
cd LanSentinel-

# 2. 编译（产物输出到 out/，已被 .gitignore 忽略）
javac -encoding UTF-8 -d out -sourcepath src src/sec/lansentinel/Main.java

# 3. 运行（无参数默认启动图形界面）
java -cp out sec.lansentinel.Main
```

**四种运行模式：**

```bash
java -cp out sec.lansentinel.Main           # 图形界面（默认）
java -cp out sec.lansentinel.Main scan      # M1 网段扫描控制台自检
java -cp out sec.lansentinel.Main honeypot  # M2 蜜罐诱捕 + 模拟攻击自检
java -cp out sec.lansentinel.Main arp       # M3 ARP 欺骗检测自检
```

> [!TIP]
> Windows PowerShell 下若控制台中文乱码，先执行 `chcp 65001`，再使用 `java "-Dstdout.encoding=UTF-8" -cp out sec.lansentinel.Main` 启动。

### 配置说明

编辑 [resources/config.properties](./resources/config.properties)：

```properties
# 授权网段（程序强制校验，不可逾越。缩写 172.20.85 表示 172.20.85.0/24 整段）
auth.range.start=172.20.85
auth.range.end=172.20.104

# 实际扫描范围（必须是授权网段的子集，演示时可缩小以提速）
scan.range.start=172.20.85.1
scan.range.end=172.20.85.20

# 扫描超时(ms)与线程池
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

## 使用示例

### 示例 1：图形界面扫描网段

1. 启动程序后进入「网段扫描」页签，IP 与端口已按配置文件预填；
2. 输入授权网段**以外**的 IP（如 `192.168.1.1`）会被弹窗拒绝；
3. 点击「开始扫描」，进度条实时显示进度，在线主机、开放端口、风险分写入结果表；
4. 点击「导出报告」生成 HTML 报告与同名 `.sig` 签名文件。

### 示例 2：验证报告防篡改

1. 导出报告得到 `report_xxxx.html` 与 `report_xxxx.html.sig`；
2. 用记事本修改报告任意内容后保存；
3. 点击「校验报告」选择该文件，程序重新计算 SHA-256 并提示**校验失败：报告已被篡改**。

### 示例 3：蜜罐诱捕（单机自检）

```bash
java -cp out sec.lansentinel.Main honeypot
```

程序自动布设四个诱饵端口并模拟攻击者行为（连续凭据尝试 + 快速触碰多个诱饵端口），预期输出：

```text
>>> 触发告警 [CRITICAL] [蜜罐] 127.0.0.1 正在扫描网络（60秒内触碰 3 个诱饵端口）
>>> 触发告警 [WARNING] [蜜罐] 127.0.0.1 正在进行暴力破解（60秒内尝试 3 组凭据）
```

### 示例 4：双机真实联动演示

1. 主机 A 配置静态 IP `172.20.90`，启动图形界面并在「蜜罐诱捕」页签点击「布防蜜罐」；
2. 主机 B 配置同网段 IP `172.20.91`，执行 `telnet 172.20.90 2323` 并输入弱口令；
3. 主机 A 蜜罐页签实时显示来源 IP 与凭据，「告警中心」出现暴力破解告警；
4. 在主机 B 运行本工具扫描主机 A，即触发端口扫描告警——**扫描器与蜜罐互为攻防验证**。

## 项目结构

```text
LanSentinel/
├── resources/
│   └── config.properties              # 授权网段、扫描参数、诱饵端口等配置
├── src/sec/lansentinel/
│   ├── Main.java                      # 程序入口（gui / scan / honeypot / arp 四种模式）
│   ├── core/
│   │   ├── scan/                      # M1 扫描引擎
│   │   │   ├── ScanEngine.java        # 线程池调度、风险评分
│   │   │   ├── HostDiscovery.java     # 主机存活探测（ICMP + TCP 兜底）
│   │   │   ├── PortScanner.java       # 单主机端口扫描任务
│   │   │   ├── BannerGrabber.java     # 服务 Banner 抓取
│   │   │   └── ServiceChecker.java    # 端口-服务一致性检查
│   │   ├── honeypot/                  # M2 蜜罐诱捕
│   │   │   ├── HoneypotServer.java    # 诱饵端口统一布防/撤防
│   │   │   ├── HoneypotListener.java  # 单端口 accept 循环
│   │   │   ├── SessionHandler.java    # 单次攻击会话处理
│   │   │   └── emulator/              # 协议伪装（策略模式）
│   │   │       ├── ServiceEmulator.java
│   │   │       ├── TelnetEmulator.java / SshEmulator.java
│   │   │       └── FtpEmulator.java   / HttpEmulator.java
│   │   ├── arp/                       # M3 ARP 欺骗检测
│   │   │   ├── ArpMonitor.java        # 定时轮询、基线比对
│   │   │   └── ArpTableParser.java    # 解析 arp -a 输出
│   │   └── alert/                     # 统一告警引擎
│   │       ├── AlertEngine.java       # 告警总线（观察者模式）
│   │       ├── AlertRule.java         # 规则接口（策略模式）
│   │       ├── PortScanRule.java      # R1 端口扫描判定
│   │       └── BruteForceRule.java    # R2 暴力破解判定
│   ├── model/                         # 实体层：HostInfo / PortInfo / AttackEvent / AlertEvent / ArpEntry
│   ├── service/                       # 服务层
│   │   ├── AuthGuard.java             # 授权网段强制校验
│   │   ├── ConfigManager.java         # 配置文件加载
│   │   └── ReportService.java         # HTML 报告导出与 SHA-256 校验
│   ├── ui/                            # 表现层：MainFrame + 四个功能页签
│   └── util/                          # 工具层：IpUtil / HashUtil
├── .gitignore
├── LICENSE
└── README.md
```

## 常见问题

<details>
<summary><b>Q1：扫描结果显示所有主机都离线？</b></summary>

当前主机未配置授权网段内的 IP。请在网卡上添加静态 IP（如 `172.20.90`，掩码 `255.255.255.0`），或在同网段准备另一台主机/虚拟机后再扫描。
</details>

<details>
<summary><b>Q2：提示「目标不在授权范围」怎么办？</b></summary>

这是 `AuthGuard` 的安全设计而非错误。请确认目标 IP 属于 `config.properties` 中配置的授权网段；学习自测时只能扫描授权网段内的地址。
</details>

<details>
<summary><b>Q3：控制台中文显示乱码？</b></summary>

Windows 下执行 `chcp 65001`，并使用 `java "-Dstdout.encoding=UTF-8" -cp out sec.lansentinel.Main` 启动；建议直接使用图形界面模式。
</details>

<details>
<summary><b>Q4：蜜罐启动提示「端口被占用」？</b></summary>

`2323/2222/2121/8080` 中某端口已被本机其他程序占用，程序会自动跳过该端口。可关闭占用程序，或在配置文件中修改 `honeypot.ports`。
</details>

<details>
<summary><b>Q5：首次监听端口时 Windows 弹出防火墙提示？</b></summary>

选择「允许访问」即可；若误点了取消，可在「Windows Defender 防火墙 → 允许应用通过防火墙」中为 Java 放行。
</details>

<details>
<summary><b>Q6：ARP 监控为什么基线为 0 条？</b></summary>

ARP 表是通信后动态学习的缓存。先 `ping` 同网段其他主机或网关，让本机产生 ARP 缓存后再启动监控；程序已兼容中文 Windows 的 GBK 编码与「动态/静态」类型输出。
</details>

<details>
<summary><b>Q7：为什么蜜罐不实现真正的登录 Shell？</b></summary>

这是有意为之的**低交互蜜罐**设计：只模拟服务的登录提示与 Banner，避免蜜罐被攻陷后成为攻击者的跳板。
</details>

## 贡献指南

欢迎通过 Issue 与 Pull Request 改进本项目：

1. Fork 本仓库，基于 `main` 创建特性分支（`feature/xxx` 或 `fix/xxx`）；
2. 提交前确认：`javac -encoding UTF-8 -d out -sourcepath src src/sec/lansentinel/Main.java` 编译通过，且 `scan` / `honeypot` / `arp` 三种自检模式运行正常；
3. 新增功能附带必要中文注释，不引入第三方依赖（如确需依赖请先在 Issue 中讨论）；
4. 提交信息遵循约定式提交格式，如 `feat: 新增TLS证书检查`、`fix: 修复端口占用时崩溃`。

## 许可证

本项目采用 [MIT License](./LICENSE) 开源，允许在保留版权声明与许可声明的前提下自由使用、修改与分发，软件按「现状」提供，不承担任何使用责任。

**再次强调：请勿将本工具用于任何未授权的网络活动。**
