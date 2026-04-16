# -*- coding: utf-8 -*-
"""
SNMP Trap 监控程序 - 告警回调 + Telnet 自动修复
监听 SNMPv2c Trap 报文，通过回调转发告警，并支持远程自动修复。
"""

import sys
import os
import socket
import struct
import json
import threading
import time
import hashlib
from datetime import datetime

if sys.platform == "win32":
    os.system("chcp 65001 >nul 2>&1")

try:
    from pyasn1.codec.ber import decoder
    from pyasn1.type import univ
except ImportError:
    pass  # 不需要 pyasn1，已使用手动 BER 解析

# ============================================================
# 配置项
# ============================================================
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 162

# 设备列表文件 - 编辑此文件可添加/删除/修改设备
# 格式（每行一台设备）: IP地址  密码  设备名称
# 示例:
#   192.168.137.2  huawei  Router-Main
#   10.1.1.1      admin   Spoke-PE1
# 以 # 开头的行是注释，空行会被忽略

# 兼容 PyInstaller 打包
if getattr(sys, 'frozen', False):
    _BASE_DIR = os.path.dirname(sys.executable)
    _BUNDLE_DIR = sys._MEIPASS
else:
    _BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    _BUNDLE_DIR = _BASE_DIR

DEVICE_FILE = os.path.join(_BASE_DIR, "devices.txt")
LOG_FILE = os.path.join(_BASE_DIR, "snmp_alerts.log")
PENDING_ALERT = os.path.join(_BASE_DIR, "pending_alert.json")
REPAIR_RESPONSE = os.path.join(_BASE_DIR, "repair_response.json")

# ============================================================
# 告警规则知识库
# ============================================================
ALARM_DB = {
    "linkdown": {
        "name": "Link Down",
        "oid_patterns": ["1.3.6.1.6.3.1.1.5.3", "hwEntityTrap"],
        "level": "CRITICAL",
        "collect_cmds": [
            "display interface brief",
            "display ip interface brief",
            "display interface [IFNAME] description",
        ],
        "auto_repair": [
            "interface [IFNAME]",
            "undo shutdown",
            "quit",
        ],
    },
    "linkup": {
        "name": "Link Up",
        "oid_patterns": ["1.3.6.1.6.3.1.1.5.4", "hwExtLinkUp"],
        "level": "INFO",
        "collect_cmds": ["display interface brief"],
        "auto_repair": None,
    },
    "bgp": {
        "name": "BGP State Change",
        "oid_patterns": ["hwBgpPeerStateChange", "bgpEstablished", "bgpBackwardTransition"],
        "level": "CRITICAL",
        "collect_cmds": [
            "display bgp peer",
            "display bgp routing-table",
        ],
        "auto_repair": [
            "bgp [ASN]",
            "peer [PEER_IP] enable",
            "quit",
        ],
    },
    "ospf": {
        "name": "OSPF Neighbor Change",
        "oid_patterns": ["hwOspfNbrStateChange", "ospfIfStateChange", "ospfNbrStateChange"],
        "level": "WARNING",
        "collect_cmds": [
            "display ospf peer brief",
            "display ospf error",
        ],
        "auto_repair": None,
    },
    "cpu": {
        "name": "CPU Overload",
        "oid_patterns": ["hwCPUOverloadWarning", "cpu", "hwCpuUsageRising"],
        "level": "CRITICAL",
        "collect_cmds": [
            "display cpu-usage",
            "display process cpu",
        ],
        "auto_repair": [
            "undo debugging all",
        ],
    },
    "memory": {
        "name": "Memory Overload",
        "oid_patterns": ["hwMemPoolUsageOverflow", "memory", "hwMemUsageRising"],
        "level": "CRITICAL",
        "collect_cmds": [
            "display memory-usage",
            "display memory-usage configuration",
        ],
        "auto_repair": None,
    },
    "arp": {
        "name": "ARP Rate Limit",
        "oid_patterns": ["hwEthernetARPSpeedLimitAlarm", "arpThreshold"],
        "level": "WARNING",
        "collect_cmds": [
            "display arp all",
            "display arp anti-attack statistics",
        ],
        "auto_repair": None,
    },
    "vrrp": {
        "name": "VRRP State Change",
        "oid_patterns": ["hwVrrp", "vrrpStateChange"],
        "level": "WARNING",
        "collect_cmds": ["display vrrp"],
        "auto_repair": None,
    },
}


def _parse_length(data, pos):
    if pos >= len(data):
        return 0, pos
    b = data[pos]
    if b < 0x80:
        return b, pos + 1
    num_bytes = b & 0x7F
    length = 0
    for i in range(num_bytes):
        if pos + 1 + i >= len(data):
            break
        length = (length << 8) | data[pos + 1 + i]
    return length, pos + 1 + num_bytes


def decode_ber_oid(oid_bytes):
    if not oid_bytes:
        return ""
    components = []
    components.append(oid_bytes[0] // 40)
    components.append(oid_bytes[0] % 40)
    val = 0
    for b in oid_bytes[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            components.append(val)
            val = 0
    return ".".join(str(c) for c in components)


def parse_varbind(data, pos):
    if pos >= len(data) or data[pos] != 0x30:
        return None, None, pos
    seq_len, pos = _parse_length(data, pos + 1)
    seq_end = pos + seq_len
    if data[pos] != 0x06:
        return None, None, seq_end
    oid_len, pos = _parse_length(data, pos + 1)
    oid_str = decode_ber_oid(data[pos:pos + oid_len])
    pos += oid_len
    val_tag = data[pos]
    val_len, pos = _parse_length(data, pos + 1)
    val_bytes = data[pos:pos + val_len]
    pos += val_len
    if val_tag == 0x02:
        v = val_bytes[0]
        if v & 0x80:
            v -= 256
        for b in val_bytes[1:]:
            v = (v << 8) | b
        val_str = str(v)
    elif val_tag == 0x04:
        try:
            val_str = val_bytes.decode("utf-8")
        except:
            val_str = val_bytes.hex()
    elif val_tag == 0x06:
        val_str = decode_ber_oid(val_bytes)
    elif val_tag in (0x40, 0x41, 0x42, 0x43):
        val_str = ".".join(str(b) for b in val_bytes)
    else:
        val_str = val_bytes.hex()
    return oid_str, val_str, seq_end


def parse_snmp_v2c_trap(data):
    varbinds = []
    try:
        if data[0] != 0x30:
            return varbinds
        total_len, pos = _parse_length(data, 1)
        if data[pos] != 0x02:
            return varbinds
        ver_len, pos = _parse_length(data, pos + 1)
        pos += ver_len
        if data[pos] != 0x04:
            return varbinds
        comm_len, pos = _parse_length(data, pos + 1)
        pos += comm_len
        pdu_tag = data[pos]
        pdu_len, pos = _parse_length(data, pos + 1)
        pdu_end = pos + pdu_len
        for _ in range(3):
            if pos >= pdu_end or data[pos] != 0x02:
                break
            int_len, pos = _parse_length(data, pos + 1)
            pos += int_len
        if pos >= pdu_end or data[pos] != 0x30:
            return varbinds
        vbl_len, pos = _parse_length(data, pos + 1)
        vbl_end = pos + vbl_len
        while pos < vbl_end:
            oid_str, val_str, pos = parse_varbind(data, pos)
            if oid_str:
                varbinds.append((oid_str, val_str))
    except Exception as e:
        print(f"[解析错误] {e}", flush=True)
    return varbinds


def match_alarm(oid_str):
    for key, info in ALARM_DB.items():
        for pattern in info["oid_patterns"]:
            if pattern.lower() in oid_str.lower():
                return key
    if "2011" in oid_str:
        for key, info in ALARM_DB.items():
            if key in oid_str.lower():
                return key
    return None


def log_alert(alert_dict):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"  [{ts}] ALERT FROM {alert_dict.get('source', 'unknown')}\n")
        f.write(json.dumps(alert_dict, indent=2, ensure_ascii=False))
        f.write(f"\n{'='*60}\n")


class TelnetClient:
    def __init__(self, host, password, timeout=10):
        self.host = host
        self.password = password
        self.timeout = timeout
        self.tn = None

    def connect(self):
        import telnetlib
        self.tn = telnetlib.Telnet(self.host, 23, timeout=self.timeout)
        time.sleep(1.5)
        self.tn.read_very_eager()
        output = self._read()
        if "Password:" in output or "password:" in output:
            self._write(self.password)
            time.sleep(1.5)
            self._read()
        return self

    def _write(self, cmd):
        self.tn.write(cmd.encode("ascii") + b"\n")

    def _read(self, sleep=1.0):
        time.sleep(sleep)
        try:
            data = self.tn.read_very_eager()
            return data.decode("gbk", errors="ignore")
        except:
            return ""

    def execute(self, cmd, sleep=1.0):
        self._write(cmd)
        return self._read(sleep)

    def execute_batch(self, cmds):
        results = []
        for cmd in cmds:
            self._write(cmd)
            out = self._read(sleep=1.0)
            results.append({"cmd": cmd, "output": out})
        return results

    def close(self):
        try:
            if self.tn:
                self._write("quit")
                time.sleep(0.5)
                self.tn.close()
        except:
            pass


def collect_diag(router_ip, alarm_key, varbinds):
    """连接路由器并采集诊断信息。"""
    if router_ip not in ROUTERS:
        return None
    cfg = ROUTERS[router_ip]
    alarm_info = ALARM_DB.get(alarm_key)
    if not alarm_info:
        return None

    cmds = list(alarm_info.get("collect_cmds", []))

    # 将 VarBind 中的占位符替换为实际值
    if_dict = {}
    for oid, val in varbinds:
        if "2.2.1.1." in oid or "ifIndex" in oid:
            idx = val
            # 尝试将 ifIndex 映射到 ifDescr —— 需要执行 display interface brief
            if_dict["index"] = idx
        if "2.2.1.2." in oid or "ifDescr" in oid:
            if_dict["name"] = val
        if "2.2.1.8." in oid:
            if_dict["operStatus"] = val

    # 从 VarBind 中提取接口名称
    if_name = None
    for oid, val in varbinds:
        if "ifDescr" in oid or "ifName" in oid:
            if_name = val
            break
        # 华为企业级 OID：接口名称常出现在 VarBind 中
        if isinstance(val, str) and ("Gigabit" in val or "Ethernet" in val or "GE" in val):
            if_name = val
            break

    final_cmds = []
    for cmd in cmds:
        cmd = cmd.replace("[IFNAME]", if_name or "[unknown]")
        final_cmds.append(cmd)

    if not final_cmds:
        final_cmds = ["display interface brief", "display ip routing-table"]

    try:
        client = TelnetClient(router_ip, cfg["password"]).connect()
        print(f"  [*] 已连接 {cfg['name']} ({router_ip})，正在采集诊断信息...", flush=True)
        results = client.execute_batch(final_cmds)

        # 同时执行通用诊断命令
        generic = client.execute_batch([
            "display ip interface brief",
            "display arp",
        ])

        results.extend(generic)
        client.close()
        return results
    except Exception as e:
        print(f"  [!] 连接失败 (3秒后重试): {e}", flush=True)
        time.sleep(3)
        try:
            client = TelnetClient(router_ip, cfg["password"]).connect()
            print(f"  [*] 重试连接 {cfg['name']} ({router_ip})", flush=True)
            results = client.execute_batch(final_cmds)
            generic = client.execute_batch(["display ip interface brief"])
            results.extend(generic)
            client.close()
            return results
        except Exception as e2:
            print(f"  [!] 重试失败: {e2}", flush=True)
            return None


def auto_repair(router_ip, alarm_key, repair_commands, varbinds):
    """在路由器上执行修复命令。"""
    if router_ip not in ROUTERS:
        print(f"  [!] 找不到 {router_ip} 的凭据，无法自动修复", flush=True)
        return False
    cfg = ROUTERS[router_ip]

    # 替换占位符为实际值
    if_name = None
    peer_ip = None
    for oid, val in varbinds:
        if "ifDescr" in oid or "ifName" in oid:
            if_name = val
        if isinstance(val, str) and ("Gigabit" in val or "Ethernet" in val):
            if_name = val

    final_cmds = []
    for cmd in repair_commands:
        cmd = cmd.replace("[IFNAME]", if_name or "[unknown]")
        cmd = cmd.replace("[PEER_IP]", peer_ip or "[unknown]")
        final_cmds.append(cmd)

    try:
        client = TelnetClient(router_ip, cfg["password"]).connect()
        print(f"  [*] 正在 {cfg['name']} ({router_ip}) 上执行自动修复...", flush=True)

        # 如果是配置类命令，需要先进入系统视图
        has_system_view = any("interface" in c or "bgp" in c or "ospf" in c for c in final_cmds)
        if has_system_view:
            client.execute("system-view")

        results = client.execute_batch(final_cmds)

        # 返回用户视图并保存配置
        client.execute("quit")
        client.execute("return")
        time.sleep(1)
        client._write("save")
        time.sleep(1)
        client._write("y")
        time.sleep(1)
        client._write("\r\n")
        time.sleep(2)
        save_out = client._read()
        print(f"  [*] 保存结果: {'成功' if 'successfully' in save_out.lower() else save_out[:100]}", flush=True)

        client.close()

        # 验证修复效果
        print(f"  [*] 验证修复...", flush=True)
        time.sleep(2)
        client2 = TelnetClient(router_ip, cfg["password"]).connect()
        verify = client2.execute_batch(["display interface brief", "display ip interface brief"])
        client2.close()

        print(f"  [*] 已执行修复命令:", flush=True)
        for r in results:
            print(f"      > {r['cmd']}", flush=True)

        return True
    except Exception as e:
        print(f"  [!] 自动修复失败: {e}", flush=True)
        return False


def trigger_callback(alert_dict):
    """将告警信息写入 pending_alert.json，供外部 AI 系统轮询读取分析。"""
    # 生成唯一告警ID，方便AI追踪已处理的告警
    alert_id = hashlib.md5(
        f"{alert_dict.get('time')}{alert_dict.get('source')}{alert_dict.get('trap_oid')}".encode()
    ).hexdigest()[:12]

    request = {
        "alert_id": alert_id,
        "timestamp": datetime.now().isoformat(),
        "status": "pending_analysis",
        "alert": alert_dict,
    }

    with open(PENDING_ALERT, "w", encoding="utf-8") as f:
        json.dump(request, f, indent=2, ensure_ascii=False)

    print(f"\n  {'~'*60}", flush=True)
    print(f"  [CALLBACK] 告警已写入 pending_alert.json", flush=True)
    print(f"  [CALLBACK] Alert ID:  {alert_id}", flush=True)
    print(f"  [CALLBACK] Source:    {alert_dict.get('source')}", flush=True)
    print(f"  [CALLBACK] Alarm:     {alert_dict.get('alarm_name', 'Unknown')}", flush=True)
    print(f"  [CALLBACK] Trap OID:  {alert_dict.get('trap_oid')}", flush=True)
    print(f"  [CALLBACK] Time:      {alert_dict.get('time')}", flush=True)
    print(f"  [CALLBACK] 等待AI分析 (最长120秒)...", flush=True)
    print(f"  {'~'*60}", flush=True)

    # 轮询 repair_response.json（AI 系统会写入此文件）
    max_wait = 120
    for i in range(max_wait):
        if os.path.exists(REPAIR_RESPONSE):
            try:
                with open(REPAIR_RESPONSE, "r", encoding="utf-8") as f:
                    resp = json.load(f)
                if resp.get("commands"):
                    print(f"  [CALLBACK] 收到AI修复响应! ({i+1}s)", flush=True)
                    print(f"  [CALLBACK] 批准: {resp.get('approved')}", flush=True)
                    print(f"  [CALLBACK] 原因: {resp.get('reason', '')}", flush=True)
                    return resp
            except (json.JSONDecodeError, Exception):
                pass
        time.sleep(1)

    print(f"  [CALLBACK] 超时 ({max_wait}s)。AI未在规定时间内响应。", flush=True)
    print(f"  [CALLBACK] 告警文件仍在 pending_alert.json 中等待后续分析。", flush=True)
    return None


def load_devices(filepath):
    """从 devices.txt 加载路由器列表。
    格式: IP地址<空格>Telnet密码<空格>设备名称<空格>SNMP团体字
    - SNMP团体字可选，默认为 'public'
    - 以 # 开头的行是注释，空行被忽略
    - 每次调用重新读取文件，支持热重载
    """
    routers = {}
    if not os.path.exists(filepath):
        print(f"[WARN] Device file not found: {filepath}", flush=True)
        return routers
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    ip, password, name, snmp_community = parts[0], parts[1], parts[2], parts[3]
                    routers[ip] = {"password": password, "name": name, "snmp_community": snmp_community}
                elif len(parts) == 3:
                    ip, password, name = parts[0], parts[1], parts[2]
                    routers[ip] = {"password": password, "name": name, "snmp_community": "public"}
                elif len(parts) == 2:
                    ip, password = parts[0], parts[1]
                    routers[ip] = {"password": password, "name": ip, "snmp_community": "public"}
                else:
                    print(f"[警告] devices.txt 第 {lineno} 行格式错误: {line}", flush=True)
    except Exception as e:
        print(f"[WARN] Failed to read devices.txt: {e}", flush=True)
    return routers


ROUTERS = {}  # 从 devices.txt 动态加载


def handle_alert(source_ip, varbinds):
    """主告警处理函数：匹配告警类型、采集诊断信息、触发AI回调、自动修复。"""
    # 每次处理前重新加载设备列表（热重载）
    global ROUTERS
    ROUTERS = load_devices(DEVICE_FILE)

    trap_oid = ""
    extra = []
    for oid, val in varbinds:
        if oid == "1.3.6.1.6.3.1.1.4.1.0":
            trap_oid = val
        elif oid == "1.3.6.1.2.1.1.3.0":
            continue
        else:
            extra.append({"oid": oid, "value": val})

    alarm_key = match_alarm(trap_oid)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sep = "=" * 60
    dash = "-" * 60
    print(f"\n{sep}", flush=True)
    print(f"  Time:       {now}", flush=True)
    print(f"  Source:     {source_ip}", flush=True)
    print(f"  Trap OID:   {trap_oid}", flush=True)
    print(f"{dash}", flush=True)

    alarm_name = "Unrecognized"
    level = "INFO"
    if alarm_key and alarm_key in ALARM_DB:
        info = ALARM_DB[alarm_key]
        alarm_name = info["name"]
        level = info["level"]
        print(f"  Alarm:      {alarm_name}", flush=True)
        print(f"  Severity:   {level}", flush=True)
    else:
        print(f"  Alarm:      {alarm_name}", flush=True)

    if extra:
        print(f"{dash}", flush=True)
        print(f"  VarBinds:", flush=True)
        for v in extra:
            print(f"    {v['oid']} = {v['value']}", flush=True)
    print(f"{sep}", flush=True)

    # 构建告警字典
    alert_dict = {
        "time": now,
        "source": source_ip,
        "trap_oid": trap_oid,
        "alarm_key": alarm_key,
        "alarm_name": alarm_name,
        "level": level,
        "varbinds": extra,
    }

    # 记录告警到日志文件
    log_alert(alert_dict)

    # 第1步：从路由器采集诊断信息
    if alarm_key and alarm_key in ALARM_DB and source_ip in ROUTERS:
        print(f"\n  [STEP 1] 正在采集诊断信息...", flush=True)
        diag = collect_diag(source_ip, alarm_key, extra)
        if diag:
            alert_dict["diagnostics"] = [
                {"cmd": r["cmd"], "output": r["output"].strip()} for r in diag
            ]
            print(f"  --- 诊断输出 ---", flush=True)
            for r in diag:
                print(f"  [{r['cmd']}]:", flush=True)
                for line in r["output"].strip().split("\n"):
                    if line.strip() and "More" not in line:
                        print(f"    {line.strip()}", flush=True)
            print(f"  --- 诊断结束 ---\n", flush=True)

    # 第2步：转发告警给AI分析
    print(f"  [STEP 2] 转发告警进行AI分析...", flush=True)
    ai_response = trigger_callback(alert_dict)

    # 第3步：若AI已响应则执行修复
    if ai_response:
        if ai_response.get("commands") and ai_response.get("approved"):
            print(f"\n  [STEP 3] 正在执行AI推荐的修复命令...", flush=True)
            auto_repair(source_ip, alarm_key, ai_response["commands"], extra)
        elif ai_response.get("commands") and not ai_response.get("approved"):
            print(f"\n  [STEP 3] AI分析完成但修复未批准:", flush=True)
            print(f"  [STEP 3] 原因: {ai_response.get('reason', 'N/A')}", flush=True)
            for cmd in ai_response.get("commands", []):
                print(f"    > {cmd}", flush=True)
        else:
            print(f"\n  [STEP 3] AI分析结果: {ai_response.get('reason', '无需操作')}", flush=True)
    else:
        # AI未在规定时间内响应 - 回退到内置修复方案
        if alarm_key and alarm_key in ALARM_DB:
            repair = ALARM_DB[alarm_key].get("auto_repair")
            if repair:
                print(f"\n  [STEP 3] AI未响应，使用内置修复方案:", flush=True)
                for cmd in repair:
                    print(f"    > {cmd}", flush=True)
                print(f"  [STEP 3] 如需自动执行，告警文件仍在 pending_alert.json 中。", flush=True)
            else:
                print(f"\n  [STEP 3] AI未响应，告警文件仍在 pending_alert.json 中等待后续分析。", flush=True)
        else:
            print(f"\n  [STEP 3] 未知告警类型，AI未响应，告警文件仍在 pending_alert.json 中。", flush=True)


def _is_admin():
    """检查是否以管理员权限运行（仅 Windows）。"""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_firewall_rule(port):
    """确保 Windows 防火墙允许指定 UDP 端口的入站流量。"""
    import subprocess
    if not _is_admin():
        print(f"  [!] 当前非管理员权限，无法修改防火墙规则", flush=True)
        print(f"  [!] 请右键exe选择'以管理员身份运行'，或在Windows防火墙中手动开放UDP {port}", flush=True)
        print(f"  [!] 否则来自路由器的Trap消息将被防火墙拦截，无法接收", flush=True)
        return False

    rule_name = f"SNMP_Trap_UDP_{port}"
    try:
        # 先删除旧规则再添加新规则，确保规则干净
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, text=True, timeout=10
        )
        add_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=allow",
            "protocol=UDP", f"localport={port}",
            "profile=any",
            "localip=any", "remoteip=any",
            "description=SNMP Trap 监控系统自动创建的防火墙规则",
        ]
        result = subprocess.run(add_cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"  [+] 防火墙规则 '{rule_name}' 已创建 (UDP {port} IN, any->any)", flush=True)
            return True
        else:
            print(f"  [!] 防火墙规则创建失败: {result.stdout.strip()}", flush=True)
            return False
    except Exception as e:
        print(f"  [!] 防火墙设置异常: {e}", flush=True)
        return False


def kill_port_holders(port):
    """终止所有占用指定 UDP 端口的进程。"""
    import subprocess
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "UDP"],
            capture_output=True, text=True, timeout=10,
            encoding="gbk", errors="ignore"
        )
        for line in result.stdout.split("\n"):
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                pid = parts[-1] if parts else None
                if pid and pid.isdigit():
                    # 不要终止自身
                    if int(pid) != os.getpid():
                        print(f"  [!] 端口 {port} 被 PID {pid} 占用，正在终止...", flush=True)
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/PID", pid],
                                capture_output=True, timeout=5
                            )
                            print(f"  [+] PID {pid} 已终止，端口 {port} 已释放。", flush=True)
                            time.sleep(1)
                        except Exception as e:
                            print(f"  [!] 终止 PID {pid} 失败: {e}", flush=True)
    except Exception as e:
        print(f"  [!] 端口检查异常: {e}", flush=True)


def main():
    # 如果有上次残留的实例占用了端口，先释放
    kill_port_holders(LISTEN_PORT)

    # 确保Windows防火墙允许SNMP Trap入站
    fw_ok = ensure_firewall_rule(LISTEN_PORT)

    # 初始加载设备列表
    global ROUTERS
    ROUTERS = load_devices(DEVICE_FILE)

    print("=" * 60, flush=True)
    print("  SNMP Trap Monitor + AI Callback + Auto Repair", flush=True)
    print("=" * 60, flush=True)
    print(f"  监听地址:   {LISTEN_IP}:{LISTEN_PORT}", flush=True)
    print(f"  设备文件:   {DEVICE_FILE}", flush=True)
    print(f"  启动时间:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print(f"  日志文件:   {LOG_FILE}", flush=True)
    print(f"  管理员权限: {'是' if _is_admin() else '否 (Trap可能被防火墙拦截!)'}", flush=True)
    print(f"  按 Ctrl+C 停止", flush=True)
    print("=" * 60, flush=True)
    if ROUTERS:
        print(f"  已加载 {len(ROUTERS)} 台设备:", flush=True)
        for ip, cfg in ROUTERS.items():
            print(f"    {ip:>16s}  pwd:{cfg['password']:<10s}  snmp:{cfg['snmp_community']:<10s}  {cfg['name']}", flush=True)
    else:
        print(f"  [!] 未加载到设备。请编辑 {DEVICE_FILE} 添加路由器。", flush=True)
    print("=" * 60, flush=True)
    print(f"\n[*] 正在监听 SNMP Trap...\n", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((LISTEN_IP, LISTEN_PORT))
    except PermissionError:
        print(f"[!] 端口 {LISTEN_PORT} 需要管理员权限。请以管理员身份运行。", flush=True)
        sock.close()
        sys.exit(1)

    sock.settimeout(1.0)

    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                source_ip = addr[0]
                varbinds = parse_snmp_v2c_trap(data)
                if varbinds:
                    handle_alert(source_ip, varbinds)
                else:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                          f"原始数据 {len(data)} 字节 来自 {source_ip}", flush=True)
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n\n[*] 已停止。", flush=True)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
