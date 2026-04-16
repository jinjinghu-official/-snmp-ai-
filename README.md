# SNMP Trap 智能告警监控系统 —— 技术文档

## 1. 项目简介

SNMP Trap 智能告警监控系统是一套面向华为网络设备的**网络故障自动化运维工具**，适用于 eNSP 仿真环境及真实物理网络环境。系统能够实时监听路由器/交换机发送的 SNMP Trap 告警消息，自动解析告警类型，通过 Telnet 连接故障设备采集诊断信息，并支持 AI 辅助分析及自动修复。

### 核心能力

| 功能          | 说明                                                         |
| ------------- | ------------------------------------------------------------ |
| Trap 实时监听 | 绑定 UDP 162 端口，接收 SNMPv2c Trap 报文，自动 BER 解码     |
| 告警智能分类  | 内置 8 类告警规则库，自动匹配 Trap OID 到告警类型和级别      |
| 自动诊断采集  | 收到告警后自动 Telnet 登录设备，执行诊断命令收集接口/路由/协议状态 |
| AI 回调分析   | 将告警 + 诊断结果写入 JSON 文件，等待外部 AI 系统分析并返回修复建议 |
| 内置自动修复  | AI 未响应时，对部分告警类型执行预设的修复命令（如端口 undo shutdown） |
| 图形化管理    | PyQt5 暗色主题界面，可视化设备管理、彩色告警日志、一键清理残留进程 |

### 技术栈

- **语言**：Python 3.x
- **GUI 框架**：PyQt5（Fusion 暗色主题）
- **网络协议**：SNMPv2c（原始 Socket 接收 + 手动 BER 解码）、Telnet
- **打包**：PyInstaller（单文件 exe，无外部依赖）

### 适用环境

- **eNSP 仿真环境**：华为 eNSP 模拟路由器，用于实验和测试
- **真实物理设备**：华为及兼容 VRP 系统的路由器、交换机等网络设备，支持 SNMPv2c Trap + Telnet

---

## 2. 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                  SNMP Trap 智能告警监控系统                    │
│                   (snmp_monitor_gui.py)                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────────┐  ┌───────────────┐  │
│  │  PyQt5 GUI   │  │  MonitorWorker   │  │  告警规则引擎  │  │
│  │  主窗口       │←→│  后台监控线程     │  │  ALARM_DB     │  │
│  │              │  │  (内嵌运行)       │  │  8类告警匹配   │  │
│  └─────────────┘  └───────┬──────────┘  └───────┬───────┘  │
│                            │                     │          │
│  ┌─────────────┐  ┌───────▼──────────┐  ┌───────▼───────┐  │
│  │ 设备管理     │  │  SNMP UDP Socket │  │  TelnetClient │  │
│  │ devices.txt  │  │  0.0.0.0:162    │  │  诊断采集      │  │
│  │ 表格编辑     │  │  BER 解码        │  │  自动修复      │  │
│  └─────────────┘  └──────────────────┘  └───────────────┘  │
├─────────────────────────────────────────────────────────────┤
│  文件接口（与外部 AI 系统对接）                                │
│  pending_alert.json ──→ AI 分析 ──→ repair_response.json    │
└─────────────────────────────────────────────────────────────┘
         ▲                                     │
         │  SNMP Trap (UDP 162)                │  修复命令
    ┌────┴────┐                           ┌────▼────┐
    │  网络设备  │                           │  网络设备  │
    │ 路由器/交换机│                         │ Telnet   │
    └─────────┘                           └─────────┘
```

### 工作流程

收到 Trap 后的处理流程分三步：

1. **STEP 1 — 诊断采集**：Telnet 登录告警源设备，执行该告警类型对应的诊断命令，收集接口状态、路由表、协议邻居等信息
2. **STEP 2 — AI 回调**：将告警详情 + 诊断结果写入 `pending_alert.json`，等待外部 AI 系统读取并写入修复建议到 `repair_response.json`（超时 120 秒）
3. **STEP 3 — 自动修复**：若 AI 返回了批准的修复命令则执行；否则回退到内置修复方案，或仅记录告警等待人工处理

---

## 3. 从零搭建环境

### 3.1 环境要求

| 项目     | 要求                                                         |
| -------- | ------------------------------------------------------------ |
| 操作系统 | Windows 10 / 11（64 位）                                     |
| Python   | 3.8 及以上版本                                               |
| 网络设备 | 华为路由器/交换机（支持 SNMPv2c Trap 和 Telnet），eNSP 仿真环境或真实设备均可 |
| 权限     | 管理员权限（绑定 UDP 162 端口 + 配置防火墙规则）             |

### 3.2 安装 Python

1. 访问 Python 官网：https://www.python.org/downloads/
2. 下载 Python 3.10+ Windows 安装包（64-bit）
3. 运行安装程序，**务必勾选 "Add Python to PATH"**
4. 安装完成后，打开命令提示符验证：

```cmd
python --version
pip --version
```

若显示版本号（如 `Python 3.10.11`），说明安装成功。

### 3.3 安装依赖库

打开命令提示符，执行：

```cmd
pip install PyQt5
```

> 仅需安装 `PyQt5` 一个第三方库。程序使用的 `socket`、`telnetlib`、`subprocess`、`json` 等均为 Python 标准库，无需额外安装。

### 3.4 获取程序文件

将 `SNMP告警监控` 文件夹整体复制到目标目录。文件夹内应包含：

```
SNMP告警监控/
├── SNMP告警监控.exe          # 主程序（已打包，可直接运行）
├── devices.txt               # 设备配置文件（必需）
├── snmp_monitor_gui.py       # GUI 源码
├── snmp_trap_monitor.py      # 监控逻辑源码
├── alert_callback.py         # AI 回调脚本
├── alert_listener.py         # 告警监听脚本
├── check_alert.py            # 告警检查脚本
├── telnet_repair.py          # Telnet 修复脚本
└── SNMP告警监控.spec         # PyInstaller 打包配置
```

---

## 4. 配置网络设备 SNMP Trap

本节以华为路由器为例，配置方法在 eNSP 仿真环境和真实设备上基本一致。

### 4.1 确认网络连通性

运行监控程序的 Windows 主机需与目标网络设备网络互通。

- **eNSP 环境**：eNSP 默认通过虚拟网卡桥接到本机，典型地址为 `192.168.137.x` 网段
- **真实设备**：确保主机与设备管理 IP 在同一网段，或路由可达

验证连通性：

```cmd
ping <设备管理IP>
```

> 如果 ping 不通，检查网络连接、防火墙设置和路由配置。

### 4.2 配置路由器 SNMP Trap

登录路由器（通过 eNSP 终端、Console 或 Telnet），执行以下配置：

```
system-view
snmp-agent sys-info version v2c
snmp-agent community read public
snmp-agent target-host trap address udp-domain <监控主机IP> params securityname public v2c
snmp-agent trap enable
quit
```

配置说明：

| 命令                               | 作用                                        |
| ---------------------------------- | ------------------------------------------- |
| `snmp-agent sys-info version v2c`  | 启用 SNMPv2c 版本                           |
| `snmp-agent community read public` | 设置只读团体字为 `public`                   |
| `snmp-agent target-host trap ...`  | 指定 Trap 接收方为监控主机 IP，UDP 162 端口 |
| `snmp-agent trap enable`           | 全局启用 Trap 发送                          |

> `<监控主机IP>` 是运行监控程序的 Windows 主机 IP，根据实际网络环境修改。如果不确定本机 IP，在命令提示符中执行 `ipconfig` 查看对应网卡（eNSP 虚拟网卡或连接设备管理网段的物理网卡）的 IP 地址。

### 4.3 验证 Trap 发送

在路由器上查看 SNMP 统计：

```
display snmp-agent statistics
```

确认输出的 Trap PDU 计数器在增长（说明路由器正在发送 Trap）。

### 4.4 真实设备额外注意事项

在真实物理设备上部署时，还需注意以下几点：

1. **防火墙放行**：确保监控主机与设备之间的 UDP 162 端口未被中间防火墙拦截
2. **Telnet 服务**：确认设备已开启 Telnet 服务，参考第 10.3 节
3. **管理网段**：建议将 SNMP/Telnet 流量限制在专用管理 VLAN 内
4. **安全加固**：生产环境建议使用更复杂的 SNMP 团体字，并考虑启用 SNMPv3

---

## 5. 配置设备文件

### 5.1 devices.txt 格式

设备文件 `devices.txt` 是纯文本文件，每行一台设备，格式为：

```
IP地址    Telnet密码    设备名称    SNMP团体字
```

各字段之间用 **Tab** 或空格分隔。SNMP 团体字可选，默认为 `public`。

示例：

```
# SNMP Trap 监控系统 - 设备列表
# 格式: IP地址  telnet密码  设备名称  SNMP团体字
# 随时可编辑，修改后立即生效，无需重启
#
192.168.137.2    huawei    Router-Main    public
```

### 5.2 多设备配置示例

```
192.168.137.2    huawei    Router-Core-1    public
192.168.137.3    huawei    Router-Core-2    public
192.168.137.4    cisco123  Switch-Access-1  private
```

### 5.3 配置要点

- **IP 地址**：设备的管理 IP，必须与本机网络互通（eNSP 环境下为虚拟网卡网段，真实设备为管理网段）
- **Telnet 密码**：设备的 Telnet 登录密码，用于自动采集诊断信息和执行修复命令
- **设备名称**：自定义的标识名称，显示在日志中方便识别
- **SNMP 团体字**：必须与设备上 `snmp-agent community` 配置一致

设备文件支持热更新——监控运行期间修改 `devices.txt`，下次收到 Trap 时自动加载新配置，无需重启监控。

---

## 6. 运行程序

### 6.1 方式一：直接运行 exe（推荐）

1. **右键** `SNMP告警监控.exe` → **以管理员身份运行**

   > 管理员权限是必需的，用于绑定 UDP 162 端口和配置 Windows 防火墙入站规则。

2. 程序启动后，界面显示：

   - 上方工具栏：启动/停止、刷新设备、清空日志、清理残留进程、切换工作目录
   - 中间设备表格：显示已配置的设备列表
   - 下方日志区：实时显示监控输出和告警信息
   - 底部状态栏：当前工作目录和监控状态

3. 点击 **"▶ 启动监控"**，日志区显示启动信息：

```
============================================================
  SNMP Trap Monitor + AI Callback + Auto Repair
============================================================
  监听地址:   0.0.0.0:162
  设备文件:   C:\...\devices.txt
  启动时间:   2026-04-16 10:30:00
  管理员权限: 是
  已加载 1 台设备:
      192.168.137.2  pwd:huawei     snmp:public      Router-Main
============================================================

[*] 正在监听 SNMP Trap...
```

4. 此时程序已在监听 UDP 162 端口。当网络设备发送 Trap 时，日志区会实时显示告警详情。

### 6.2 方式二：从源码运行

如果需要修改源码或调试，可以直接用 Python 运行：

```cmd
cd SNMP告警监控
python snmp_monitor_gui.py
```

> 同样建议以管理员身份打开命令提示符。

### 6.3 方式三：重新打包 exe

如果修改了源码需要重新打包：

```cmd
cd SNMP告警监控
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name "SNMP告警监控" --add-data "snmp_trap_monitor.py;." snmp_monitor_gui.py
```

打包完成后，exe 文件在 `dist\SNMP告警监控.exe`，将其复制回程序目录即可。

---

## 7. 使用指南

### 7.1 界面功能区说明

| 区域                        | 功能                                                         |
| --------------------------- | ------------------------------------------------------------ |
| **▶ 启动监控 / ■ 停止监控** | 启动或停止 SNMP Trap 监听。绿色=启动，红色=停止              |
| **↻ 刷新设备**              | 从 `devices.txt` 重新加载设备列表到表格                      |
| **✕ 清空日志**              | 清除界面日志和日志文件                                       |
| **⚙ 清理残留进程**          | 扫描并终止所有占用 UDP 162 端口的残留进程                    |
| **📁 切换工作目录**          | 选择新的工作目录（需先停止监控），切换后自动加载该目录下的配置和日志 |
| **设备表格**                | 双击单元格编辑设备信息，修改后自动保存到 `devices.txt`       |
| **+ 添加设备 / - 删除选中** | 管理设备列表                                                 |
| **告警日志区**              | 彩色实时日志，深色背景便于长时间监控                         |

### 7.2 日志颜色说明

| 颜色   | 含义                                         |
| ------ | -------------------------------------------- |
| 🔴 红色 | CRITICAL — 严重告警（链路断开、CPU 过载等）  |
| 🟡 黄色 | WARNING — 警告（OSPF 邻居变化、ARP 限速等）  |
| 🔵 蓝色 | STEP / CALLBACK — 处理流程步骤和 AI 回调信息 |
| 🟢 青色 | Repair / Solution — 修复操作和解决方案       |
| ⚠️ 橙色 | [!] 警告信息（连接失败等）                   |
| ⚪ 灰色 | 分隔线和常规信息                             |

### 7.3 告警处理流程示例

假设路由器 GE0/0/1 接口被 `shutdown`，设备发送 Link Down Trap：

```
============================================================
  Time:       2026-04-16 10:35:12
  Source:     192.168.137.2
  Trap OID:   1.3.6.1.6.3.1.1.5.3
------------------------------------------------------------
  Alarm:      Link Down
  Severity:   CRITICAL
------------------------------------------------------------
  VarBinds:
    1.3.6.1.2.1.2.2.1.1.3 = 3
    1.3.6.1.2.1.2.2.1.2.3 = GigabitEthernet0/0/1
    1.3.6.1.2.1.2.2.1.8.3 = 2
============================================================

  [STEP 1] 正在采集诊断信息...
  [*] 已连接 Router-Main (192.168.137.2)，正在采集诊断信息...
  --- 诊断输出 ---
  [display interface brief]:
    Interface         PHY   Protocol InUti OutUti
    GE0/0/0           up    up       0.01% 0.01%
    GE0/0/1           down  down     0%    0%
  --- 诊断结束 ---

  [STEP 2] 转发告警进行AI分析...
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  [CALLBACK] 告警已写入 pending_alert.json
  [CALLBACK] 等待AI分析 (最长120秒)...
  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  [CALLBACK] 超时 (120s)。AI未在规定时间内响应。
  [STEP 3] AI未响应，告警文件仍在 pending_alert.json 中等待后续分析。
```

---

## 8. 支持的告警类型

程序内置了 8 类告警规则，通过 Trap OID 和关键字匹配：

| 告警类型          | 级别     | 匹配规则                                       | 自动采集命令                                            | 自动修复             |
| ----------------- | -------- | ---------------------------------------------- | ------------------------------------------------------- | -------------------- |
| **Link Down**     | CRITICAL | OID 含 `1.3.6.1.6.3.1.1.5.3` 或 `hwEntityTrap` | `display interface brief`, `display ip interface brief` | `undo shutdown`      |
| **Link Up**       | INFO     | OID 含 `1.3.6.1.6.3.1.1.5.4` 或 `hwExtLinkUp`  | `display interface brief`                               | 无                   |
| **BGP 邻居变化**  | CRITICAL | OID 含 `hwBgpPeerStateChange`                  | `display bgp peer`, `display bgp routing-table`         | 重新启用 BGP peer    |
| **OSPF 邻居变化** | WARNING  | OID 含 `hwOspfNbrStateChange`                  | `display ospf peer brief`, `display ospf error`         | 无                   |
| **CPU 过载**      | CRITICAL | OID 含 `hwCPUOverloadWarning`                  | `display cpu-usage`, `display process cpu`              | `undo debugging all` |
| **内存过载**      | CRITICAL | OID 含 `hwMemPoolUsageOverflow`                | `display memory-usage`                                  | 无                   |
| **ARP 限速告警**  | WARNING  | OID 含 `hwEthernetARPSpeedLimitAlarm`          | `display arp all`, `display arp anti-attack statistics` | 无                   |
| **VRRP 状态变化** | WARNING  | OID 含 `hwVrrp`                                | `display vrrp`                                          | 无                   |

> 对于未匹配到任何规则的 Trap，系统仍会记录完整的 OID 和 VarBind 信息，标记为 `Unrecognized`。

---

## 9. AI 回调接口

### 9.1 工作机制

系统通过文件接口与外部 AI 系统交互：

```
监控系统                          AI 系统
   │                                │
   ├─ 收到告警 → 诊断采集            │
   ├─ 写入 pending_alert.json  ───→│  AI 读取并分析
   │                                ├─ 写入 repair_response.json
   ├─ 轮询 repair_response.json ←──│
   ├─ 读取修复建议 → 执行修复        │
```

### 9.2 pending_alert.json 格式

AI 系统应监控此文件，读取后删除或标记为已处理：

```json
{
  "alert_id": "a1b2c3d4e5f6",
  "timestamp": "2026-04-16T10:35:12.000000",
  "status": "pending_analysis",
  "alert": {
    "time": "2026-04-16 10:35:12",
    "source": "192.168.137.2",
    "trap_oid": "1.3.6.1.6.3.1.1.5.3",
    "alarm_key": "linkdown",
    "alarm_name": "Link Down",
    "level": "CRITICAL",
    "varbinds": [
      {"oid": "1.3.6.1.2.1.2.2.1.2.3", "value": "GigabitEthernet0/0/1"}
    ],
    "diagnostics": [
      {
        "cmd": "display interface brief",
        "output": "GE0/0/1 down down"
      }
    ]
  }
}
```

### 9.3 repair_response.json 格式

AI 系统分析完成后，将修复建议写入此文件：

```json
{
  "alert_id": "a1b2c3d4e5f6",
  "approved": true,
  "reason": "链路处于 admin down 状态，执行 undo shutdown 恢复",
  "commands": [
    "interface GigabitEthernet0/0/1",
    "undo shutdown",
    "quit"
  ]
}
```

| 字段       | 类型    | 说明                       |
| ---------- | ------- | -------------------------- |
| `alert_id` | string  | 对应告警 ID                |
| `approved` | boolean | 是否批准自动执行修复命令   |
| `reason`   | string  | 分析结论和修复原因         |
| `commands` | array   | 修复命令列表（按顺序执行） |

> 系统会等待最长 120 秒。若超时未收到响应，回退到内置修复方案。

---

## 10. 配合 WorkBuddy 使用（AI 智能分析）

### 10.1 方案概述

WorkBuddy 是一款 AI 编程助手，可以基于监控程序生成的告警文件自动分析网络故障并返回修复命令。两者通过文件接口协同工作，无需额外安装任何服务或 API。

工作流程如下：

```
┌──────────────────┐     pending_alert.json      ┌──────────────────┐
│  SNMP 告警监控系统 │ ──────────────────────────→ │   WorkBuddy       │
│  (exe 或源码)     │                              │  AI 编程助手       │
│                  │  ←────────────────────────── │  (自动化任务)      │
└──────────────────┘   repair_response.json       └──────────────────┘
```

### 10.2 前提条件

| 条件             | 说明                                                         |
| ---------------- | ------------------------------------------------------------ |
| WorkBuddy 已安装 | 在 VS Code 扩展商店搜索 "WorkBuddy" 或访问官网安装           |
| 监控程序工作目录 | 已知 `SNMP告警监控` 文件夹的完整路径（例如 `D:\SNMP告警监控`） |
| WorkBuddy 工作区 | WorkBuddy 打开的工作区可以和监控程序不在同一目录，但需要指向正确的 JSON 文件路径 |

### 10.3 创建 WorkBuddy 自动化任务

在 WorkBuddy 中创建一个**定时自动化任务**，让 AI 持续监控告警文件并在收到新告警时自动分析：

1. 打开 WorkBuddy，进入对话界面
2. 在对话中发送以下指令：

```
请帮我创建一个定时自动化任务：
- 任务名称：SNMP告警AI分析
- 执行频率：每隔3分钟检查一次
- 任务内容：读取 D:\SNMP告警监控\pending_alert.json 文件（请将路径替换为你的实际路径），
  如果文件存在且 status 为 "pending_analysis"，则：
  1. 分析告警内容（告警类型、VarBind 信息、诊断输出）
  2. 根据华为 VRP 命令行语法判断根本原因
  3. 将修复建议写入 D:\SNMP告警监控\repair_response.json，格式如下：
     {"alert_id": "与告警文件中的alert_id一致", "approved": true, "reason": "分析结论", "commands": ["修复命令列表"]}
- 状态：立即启动
```

3. WorkBuddy 会自动创建并启动这个任务。之后每 3 分钟它会检查一次是否有新告警。

### 10.4 手动触发分析

如果不想使用自动化任务，也可以在告警发生时手动让 WorkBuddy 分析：

**方式一：直接发送指令**

在 WorkBuddy 对话中发送：

```
请读取 D:\SNMP告警监控\pending_alert.json，分析这个SNMP告警，
判断故障原因，并将修复命令写入 D:\SNMP告警监控\repair_response.json
```

**方式二：使用切换工作目录功能**

1. 在 WorkBuddy 中点击"切换工作目录"，指向 `D:\SNMP告警监控` 文件夹
2. 发送简短指令：

```
读取 pending_alert.json 分析告警，将修复建议写入 repair_response.json
```

### 10.5 完整协同流程实例

以下是一个从告警产生到修复完成的完整过程：

```
时间线          SNMP 告警监控系统              pending_alert.json          WorkBuddy
────────────────────────────────────────────────────────────────────────────────
10:35:12       收到 Link Down Trap
               自动 Telnet 诊断采集
               写入 pending_alert.json  ──→  文件被创建
               等待 AI 响应（120秒倒计时）

10:36:00                                    WorkBuddy 定时任务触发 ←───
                                              读取 pending_alert.json
                                              分析：GE0/0/1 admin down
                                              写入 repair_response.json ──→

10:36:15       读取 repair_response.json  ←── 文件就绪
               AI 返回: undo shutdown
               执行修复命令
               GE0/0/1 恢复 up

10:36:18       收到 Link Up Trap
               告警已解除 ✓
```

### 10.6 告警分析提示词模板

WorkBuddy 在分析告警时需要理解华为 VRP 设备的命令语法。以下是推荐的系统提示（创建自动化任务时建议包含）：

```
你是一个华为网络设备运维专家。请根据 SNMP Trap 告警信息分析网络故障：

1. 告警分析要点：
   - 根据 alarm_name 和 trap_oid 判断告警类型
   - 根据 varbinds 定位具体接口/协议/模块
   - 根据 diagnostics 中的设备命令输出判断根本原因

2. 常见修复命令（华为 VRP 语法）：
   - 接口故障：interface <name> → undo shutdown → quit
   - OSPF 邻居异常：检查 OSPF 配置、接口开销、网络类型
   - BGP 邻居异常：检查 BGP peer 地址、AS 号、路由策略
   - CPU 过载：undo debugging all，检查进程异常
   - 内存过载：检查内存泄漏进程，重启异常模块

3. 输出格式：
   将响应写入 repair_response.json：
   {
     "alert_id": "从 pending_alert.json 中获取的告警 ID",
     "approved": true,
     "reason": "简要分析结论",
     "commands": ["华为 VRP 修复命令，按执行顺序排列"]
   }

4. 安全原则：
   - 不确定时不批准执行，设置 approved: false
   - shutdown 类命令（关闭接口/协议）绝不自动执行
   - 涉及路由协议重启的命令建议人工确认
```

### 10.7 注意事项

1. **路径一致性**：WorkBuddy 自动化任务中指向的 JSON 文件路径，必须与监控程序实际运行的目录一致。如果使用了"切换工作目录"功能，需要同步更新 WorkBuddy 任务中的路径。

2. **时间窗口**：监控程序等待 AI 响应的最长时间为 120 秒。WorkBuddy 自动化任务的检查间隔建议设置为 1-3 分钟。如果告警高峰期 AI 响应不及时，可以考虑缩短间隔。

3. **并发安全**：当监控程序正在读取 `repair_response.json` 时，WorkBuddy 不应同时写入。由于采用了轮询机制（间隔 2 秒轮询 120 次），正常情况下不会冲突。

4. **approved 字段**：AI 返回 `approved: true` 时监控系统会自动执行修复命令。如果需要人工审核，可让 AI 返回 `approved: false`，此时监控系统仅记录告警不执行修复。

5. **批量告警**：如果短时间内产生多个告警，只有最后一个告警的 `pending_alert.json` 会被保留。建议根据网络规模适当调整告警抑制策略（在路由器上配置 `snmp-agent trap suppress`）。

---

## 11. 故障排除

### 11.1 收不到 Trap 消息

**检查清单：**

1. **管理员权限**：确认 exe 是以管理员身份运行。日志中"管理员权限"应显示"是"
2. **防火墙**：日志中应显示"防火墙规则已就绪 (UDP 162 IN)"。若显示"非管理员权限"，需要以管理员身份运行
3. **路由器配置**：确认已执行 `snmp-agent trap enable` 和 `snmp-agent target-host` 配置
4. **网络连通**：确认本机能 ping 通路由器 IP
5. **端口占用**：点击"⚙ 清理残留进程"按钮，释放 UDP 162 端口后重新启动监控
6. **SNMP 统计**：在路由器上执行 `display snmp-agent statistics`，确认 Trap PDU 计数在增长

### 11.2 端口绑定失败

错误信息：`端口 162 绑定失败: [WinError 10048]`

原因：有其他程序（如 Windows SNMP Service）占用了 UDP 162 端口。

解决：

1. 点击"⚙ 清理残留进程"按钮
2. 如果是 Windows SNMP 服务占用，在管理员命令提示符中执行：

```cmd
net stop snmp
sc config snmp start= disabled
```

### 11.3 Telnet 连接失败

错误信息：`连接失败: [Errno 10060]`

原因：网络不通或设备未开启 Telnet 服务。

在设备上检查并启用：

```
system-view
user-interface vty 0 4
 authentication-mode password
 set authentication password simple huawei
 protocol inbound telnet
 quit
```

### 11.4 程序退出后端口未释放

如果程序异常退出导致端口仍被占用：

1. 重新以管理员身份启动程序
2. 点击"⚙ 清理残留进程"按钮
3. 或手动在命令提示符中执行：

```cmd
netstat -ano -p UDP | findstr ":162"
taskkill /F /PID <PID号>
```

### 11.5 设备文件修改不生效

- 设备文件在**每次收到 Trap 时**重新加载，不是实时加载
- 修改 `devices.txt` 后，等待下一个 Trap 到来自动生效
- 或点击"↻ 刷新设备"按钮更新设备表格（但监控线程内部会在下次告警时加载）

---

## 12. 文件清单

| 文件                   | 说明                                        |
| ---------------------- | ------------------------------------------- |
| `SNMP告警监控.exe`     | 打包后的主程序，双击运行                    |
| `snmp_monitor_gui.py`  | GUI 主程序源码（PyQt5 界面 + 内嵌监控逻辑） |
| `snmp_trap_monitor.py` | 监控逻辑源码（作为参考，exe 中已内嵌）      |
| `devices.txt`          | 设备配置文件，格式见第 5 节                 |
| `alert_callback.py`    | 告警回调脚本，将告警写入 JSON 供 AI 读取    |
| `alert_listener.py`    | 告警监听脚本                                |
| `check_alert.py`       | 告警检查脚本                                |
| `telnet_repair.py`     | Telnet 自动修复脚本                         |
| `pending_alert.json`   | 告警请求文件（运行时自动生成）              |
| `repair_response.json` | AI 修复响应文件（AI 系统写入）              |
| `snmp_alerts.log`      | 告警日志文件（自动追加）                    |
| `SNMP告警监控.spec`    | PyInstaller 打包配置文件                    |

---

## 13. 安全注意事项

- `devices.txt` 中以明文存储了设备 Telnet 密码，请勿将此文件上传到公开仓库或分享给无关人员
- 自动修复功能会直接登录设备执行命令，建议先在 eNSP 仿真环境中验证，生产环境应设置 `approved: false` 由人工确认后再执行
- SNMP 团体字 `public` 为默认值，安全性较低，建议使用更复杂的团体字，并考虑升级至 SNMPv3
