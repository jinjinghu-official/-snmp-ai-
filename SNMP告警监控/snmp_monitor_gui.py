# -*- coding: utf-8 -*-
"""
SNMP Trap 监控系统 - 图形化界面
"""

import sys
import os
import json
import time
import subprocess
import threading
import socket
import struct
import hashlib
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QPushButton, QTextEdit, QTableWidget,
    QTableWidgetItem, QLineEdit, QMessageBox, QHeaderView,
    QSplitter, QStatusBar, QSystemTrayIcon, QMenu, QAction,
    QAbstractItemView, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor, QTextCursor

# 兼容 PyInstaller 打包后的路径（仅用于定位内嵌资源）
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = sys._MEIPASS
else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__))

# 内嵌的监控脚本文件路径（打包后在_MEIPASS里）
BUNDLED_MONITOR_SCRIPT = os.path.join(BUNDLE_DIR, "snmp_trap_monitor.py")


# ============================================================
# 监控逻辑 - 直接嵌入GUI，不再启动子进程
# ============================================================
# 以下从 snmp_trap_monitor.py 导入核心逻辑，
# 避免子进程方式导致的新窗口问题和路径耦合问题。

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
        pass
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


# ============================================================
# MonitorSignals & MonitorWorker - 内嵌运行，不启动子进程
# ============================================================
class MonitorSignals(QObject):
    output = pyqtSignal(str)
    finished = pyqtSignal(int)


class MonitorWorker(threading.Thread):
    """
    直接在后台线程中运行 SNMP Trap 监听逻辑，
    不再通过 subprocess 启动子进程，避免产生新窗口。
    """

    def __init__(self, signals, work_dir):
        super().__init__(daemon=True)
        self.signals = signals
        self.work_dir = work_dir  # 工作目录（exe所在目录或自定义目录）
        self.process = None
        self.running = False
        self._sock = None

    def _emit(self, text):
        """线程安全地发送输出到GUI"""
        self.signals.output.emit(text)

    def run(self):
        self.running = True
        try:
            self._run_monitor()
        except Exception as e:
            self._emit(f"[错误] 监控线程异常: {e}")
            self.signals.finished.emit(-1)

    def _run_monitor(self):
        work_dir = self.work_dir
        device_file = os.path.join(work_dir, "devices.txt")
        log_file = os.path.join(work_dir, "snmp_alerts.log")
        pending_alert = os.path.join(work_dir, "pending_alert.json")
        repair_response = os.path.join(work_dir, "repair_response.json")

        LISTEN_IP = "0.0.0.0"
        LISTEN_PORT = 162

        # ---- 辅助函数 ----
        def load_routers():
            routers = {}
            if not os.path.exists(device_file):
                return routers
            try:
                with open(device_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 4:
                            routers[parts[0]] = {"password": parts[1], "name": parts[2], "snmp_community": parts[3]}
                        elif len(parts) == 3:
                            routers[parts[0]] = {"password": parts[1], "name": parts[2], "snmp_community": "public"}
                        elif len(parts) == 2:
                            routers[parts[0]] = {"password": parts[1], "name": parts[0], "snmp_community": "public"}
            except Exception as e:
                self._emit(f"[WARN] 读取设备文件失败: {e}")
            return routers

        def log_alert(alert_dict):
            try:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"  [{ts}] ALERT FROM {alert_dict.get('source', 'unknown')}\n")
                    f.write(json.dumps(alert_dict, indent=2, ensure_ascii=False))
                    f.write(f"\n{'='*60}\n")
            except Exception:
                pass

        def collect_diag(router_ip, alarm_key, varbinds, routers):
            if router_ip not in routers:
                return None
            cfg = routers[router_ip]
            alarm_info = ALARM_DB.get(alarm_key)
            if not alarm_info:
                return None

            cmds = list(alarm_info.get("collect_cmds", []))
            if_name = None
            for oid, val in varbinds:
                if "ifDescr" in oid or "ifName" in oid:
                    if_name = val
                    break
                if isinstance(val, str) and ("Gigabit" in val or "Ethernet" in val or "GE" in val):
                    if_name = val
                    break

            final_cmds = [cmd.replace("[IFNAME]", if_name or "[unknown]") for cmd in cmds]
            if not final_cmds:
                final_cmds = ["display interface brief", "display ip routing-table"]

            try:
                client = TelnetClient(router_ip, cfg["password"]).connect()
                self._emit(f"  [*] 已连接 {cfg['name']} ({router_ip})，正在采集诊断信息...")
                results = client.execute_batch(final_cmds)
                generic = client.execute_batch(["display ip interface brief", "display arp"])
                results.extend(generic)
                client.close()
                return results
            except Exception as e:
                self._emit(f"  [!] 连接失败 (3秒后重试): {e}")
                time.sleep(3)
                try:
                    client = TelnetClient(router_ip, cfg["password"]).connect()
                    self._emit(f"  [*] 重试连接 {cfg['name']} ({router_ip})")
                    results = client.execute_batch(final_cmds)
                    results.extend(client.execute_batch(["display ip interface brief"]))
                    client.close()
                    return results
                except Exception as e2:
                    self._emit(f"  [!] 重试失败: {e2}")
                    return None

        def auto_repair(router_ip, alarm_key, repair_commands, varbinds, routers):
            if router_ip not in routers:
                self._emit(f"  [!] 找不到 {router_ip} 的凭据，无法自动修复")
                return False
            cfg = routers[router_ip]

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
                self._emit(f"  [*] 正在 {cfg['name']} ({router_ip}) 上执行自动修复...")

                has_system_view = any("interface" in c or "bgp" in c or "ospf" in c for c in final_cmds)
                if has_system_view:
                    client.execute("system-view")

                results = client.execute_batch(final_cmds)
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
                self._emit(f"  [*] 保存结果: {'成功' if 'successfully' in save_out.lower() else save_out[:100]}")
                client.close()

                self._emit(f"  [*] 验证修复...")
                time.sleep(2)
                client2 = TelnetClient(router_ip, cfg["password"]).connect()
                verify = client2.execute_batch(["display interface brief", "display ip interface brief"])
                client2.close()

                self._emit(f"  [*] 已执行修复命令:")
                for r in results:
                    self._emit(f"      > {r['cmd']}")
                return True
            except Exception as e:
                self._emit(f"  [!] 自动修复失败: {e}")
                return False

        def trigger_callback(alert_dict):
            alert_id = hashlib.md5(
                f"{alert_dict.get('time')}{alert_dict.get('source')}{alert_dict.get('trap_oid')}".encode()
            ).hexdigest()[:12]

            request = {
                "alert_id": alert_id,
                "timestamp": datetime.now().isoformat(),
                "status": "pending_analysis",
                "alert": alert_dict,
            }
            with open(pending_alert, "w", encoding="utf-8") as f:
                json.dump(request, f, indent=2, ensure_ascii=False)

            self._emit(f"\n  {'~'*60}")
            self._emit(f"  [CALLBACK] 告警已写入 pending_alert.json")
            self._emit(f"  [CALLBACK] Alert ID:  {alert_id}")
            self._emit(f"  [CALLBACK] Source:    {alert_dict.get('source')}")
            self._emit(f"  [CALLBACK] Alarm:     {alert_dict.get('alarm_name', 'Unknown')}")
            self._emit(f"  [CALLBACK] Trap OID:  {alert_dict.get('trap_oid')}")
            self._emit(f"  [CALLBACK] Time:      {alert_dict.get('time')}")
            self._emit(f"  [CALLBACK] 等待AI分析 (最长120秒)...")
            self._emit(f"  {'~'*60}")

            max_wait = 120
            for i in range(max_wait):
                if not self.running:
                    break
                if os.path.exists(repair_response):
                    try:
                        with open(repair_response, "r", encoding="utf-8") as f:
                            resp = json.load(f)
                        if resp.get("commands"):
                            self._emit(f"  [CALLBACK] 收到AI修复响应! ({i+1}s)")
                            self._emit(f"  [CALLBACK] 批准: {resp.get('approved')}")
                            self._emit(f"  [CALLBACK] 原因: {resp.get('reason', '')}")
                            return resp
                    except (json.JSONDecodeError, Exception):
                        pass
                time.sleep(1)

            self._emit(f"  [CALLBACK] 超时 ({max_wait}s)。AI未在规定时间内响应。")
            self._emit(f"  [CALLBACK] 告警文件仍在 pending_alert.json 中等待后续分析。")
            return None

        def handle_alert(source_ip, varbinds, routers):
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
            self._emit(f"\n{sep}")
            self._emit(f"  Time:       {now}")
            self._emit(f"  Source:     {source_ip}")
            self._emit(f"  Trap OID:   {trap_oid}")
            self._emit(f"{dash}")

            alarm_name = "Unrecognized"
            level = "INFO"
            if alarm_key and alarm_key in ALARM_DB:
                info = ALARM_DB[alarm_key]
                alarm_name = info["name"]
                level = info["level"]
                self._emit(f"  Alarm:      {alarm_name}")
                self._emit(f"  Severity:   {level}")
            else:
                self._emit(f"  Alarm:      {alarm_name}")

            if extra:
                self._emit(f"{dash}")
                self._emit(f"  VarBinds:")
                for v in extra:
                    self._emit(f"    {v['oid']} = {v['value']}")
            self._emit(f"{sep}")

            alert_dict = {
                "time": now, "source": source_ip, "trap_oid": trap_oid,
                "alarm_key": alarm_key, "alarm_name": alarm_name,
                "level": level, "varbinds": extra,
            }
            log_alert(alert_dict)

            # Step 1
            if alarm_key and alarm_key in ALARM_DB and source_ip in routers:
                self._emit(f"\n  [STEP 1] 正在采集诊断信息...")
                diag = collect_diag(source_ip, alarm_key, extra, routers)
                if diag:
                    alert_dict["diagnostics"] = [
                        {"cmd": r["cmd"], "output": r["output"].strip()} for r in diag
                    ]
                    self._emit(f"  --- 诊断输出 ---")
                    for r in diag:
                        self._emit(f"  [{r['cmd']}]:")
                        for line in r["output"].strip().split("\n"):
                            if line.strip() and "More" not in line:
                                self._emit(f"    {line.strip()}")
                    self._emit(f"  --- 诊断结束 ---\n")

            # Step 2
            self._emit(f"  [STEP 2] 转发告警进行AI分析...")
            ai_response = trigger_callback(alert_dict)

            # Step 3
            if ai_response:
                if ai_response.get("commands") and ai_response.get("approved"):
                    self._emit(f"\n  [STEP 3] 正在执行AI推荐的修复命令...")
                    auto_repair(source_ip, alarm_key, ai_response["commands"], extra, routers)
                elif ai_response.get("commands") and not ai_response.get("approved"):
                    self._emit(f"\n  [STEP 3] AI分析完成但修复未批准:")
                    self._emit(f"  [STEP 3] 原因: {ai_response.get('reason', 'N/A')}")
                    for cmd in ai_response.get("commands", []):
                        self._emit(f"    > {cmd}")
                else:
                    self._emit(f"\n  [STEP 3] AI分析结果: {ai_response.get('reason', '无需操作')}")
            else:
                if alarm_key and alarm_key in ALARM_DB:
                    repair = ALARM_DB[alarm_key].get("auto_repair")
                    if repair:
                        self._emit(f"\n  [STEP 3] AI未响应，使用内置修复方案:")
                        for cmd in repair:
                            self._emit(f"    > {cmd}")
                        self._emit(f"  [STEP 3] 如需自动执行，告警文件仍在 pending_alert.json 中。")
                    else:
                        self._emit(f"\n  [STEP 3] AI未响应，告警文件仍在 pending_alert.json 中等待后续分析。")
                else:
                    self._emit(f"\n  [STEP 3] 未知告警类型，AI未响应，告警文件仍在 pending_alert.json 中。")

        # ---- 主循环开始 ----
        # 先释放可能残留的旧进程占用的端口
        self._emit("正在检查端口占用...")
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "UDP"],
                capture_output=True, text=True, timeout=10,
                encoding="gbk", errors="ignore"
            )
            for line in result.stdout.split("\n"):
                if ":162" in line and "LISTENING" in line:
                    parts = line.split()
                    pid = parts[-1] if parts else None
                    if pid and pid.isdigit():
                        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, timeout=5)
                        self._emit(f"  [!] 已终止占用端口的残留进程 PID {pid}")
                        time.sleep(1)
        except Exception:
            pass

        # 防火墙规则
        is_admin = False
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass

        if not is_admin:
            self._emit('[!] 当前非管理员权限，无法修改防火墙规则')
            self._emit('[!] 请以管理员身份运行，否则Trap消息可能被防火墙拦截')
        else:
            try:
                rule_name = "SNMP_Trap_UDP_162"
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, text=True, timeout=10
                )
                r = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule_name}", "dir=in", "action=allow",
                     "protocol=UDP", "localport=162", "profile=any",
                     "localip=any", "remoteip=any"],
                    capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0:
                    self._emit(f"[+] 防火墙规则已就绪 (UDP 162 IN)")
                else:
                    self._emit(f'[!] 防火墙设置失败: {r.stdout.strip()}')
            except Exception as e:
                self._emit(f"[!] 防火墙异常: {e}")

        # 加载设备
        routers = load_routers()

        self._emit("=" * 60)
        self._emit("  SNMP Trap Monitor + AI Callback + Auto Repair")
        self._emit("=" * 60)
        self._emit(f"  监听地址:   {LISTEN_IP}:{LISTEN_PORT}")
        self._emit(f"  设备文件:   {device_file}")
        self._emit(f"  启动时间:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._emit(f"  日志文件:   {log_file}")
        self._emit(f"  管理员权限: {'是' if is_admin else '否 (Trap可能被防火墙拦截!)'}")
        if routers:
            self._emit(f"  已加载 {len(routers)} 台设备:")
            for ip, cfg in routers.items():
                self._emit(f"    {ip:>16s}  pwd:{cfg['password']:<10s}  snmp:{cfg['snmp_community']:<10s}  {cfg['name']}")
        else:
            self._emit(f"  [!] 未加载到设备。请编辑 {device_file} 添加路由器。")
        self._emit("=" * 60)
        self._emit(f"\n[*] 正在监听 SNMP Trap...\n")

        # 创建并绑定socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((LISTEN_IP, LISTEN_PORT))
        except PermissionError:
            self._emit(f"[!] 端口 {LISTEN_PORT} 需要管理员权限。请以管理员身份运行。")
            sock.close()
            self.signals.finished.emit(1)
            return
        except OSError as e:
            self._emit(f"[!] 端口 {LISTEN_PORT} 绑定失败: {e}")
            sock.close()
            self.signals.finished.emit(1)
            return

        sock.settimeout(1.0)
        self._sock = sock

        try:
            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    source_ip = addr[0]
                    varbinds = parse_snmp_v2c_trap(data)
                    if varbinds:
                        # 每次处理告警前重新加载设备列表（热重载）
                        routers = load_routers()
                        handle_alert(source_ip, varbinds, routers)
                    else:
                        self._emit(f"\n[{datetime.now().strftime('%H:%M:%S')}] "
                                   f"原始数据 {len(data)} 字节 来自 {source_ip}")
                except socket.timeout:
                    continue
        except Exception as e:
            if self.running:
                self._emit(f"[!] 监听异常: {e}")
        finally:
            sock.close()
            self._sock = None
            self._emit("\n[*] 监控已停止。")
            self.signals.finished.emit(0)

    def stop(self):
        """停止监控线程"""
        self.running = False
        # 关闭socket以解除recvfrom阻塞
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ============================================================
# 设备表格辅助函数
# ============================================================
def load_devices(filepath):
    """从 devices.txt 加载设备列表"""
    devices = []
    if not os.path.exists(filepath):
        return devices
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                devices.append({
                    "ip": parts[0], "password": parts[1],
                    "name": parts[2], "snmp_community": parts[3]
                })
            elif len(parts) == 3:
                devices.append({
                    "ip": parts[0], "password": parts[1],
                    "name": parts[2], "snmp_community": "public"
                })
            elif len(parts) == 2:
                devices.append({
                    "ip": parts[0], "password": parts[1],
                    "name": parts[0], "snmp_community": "public"
                })
    return devices


def save_devices(filepath, devices):
    """保存设备列表到 devices.txt"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# SNMP Trap 监控系统 - 设备列表\n")
        f.write("# 格式: IP地址  telnet密码  设备名称  SNMP团体字\n")
        f.write("# 随时可编辑，修改后立即生效，无需重启\n")
        f.write("#\n")
        for d in devices:
            f.write(f"{d['ip']}\t{d['password']}\t{d['name']}\t{d['snmp_community']}\n")


# ============================================================
# 主窗口
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SNMP Trap 智能告警监控系统")
        self.setMinimumSize(900, 650)
        self.monitor_worker = None
        self.monitor_running = False

        # 工作目录：默认exe所在目录，用户可切换
        self.work_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))

        # 延迟计算的路径
        self._update_paths()

        self._build_ui()
        self._load_device_table()
        self._load_log()

        # 定时刷新日志
        self.log_timer = QTimer()
        self.log_timer.timeout.connect(self._load_log)
        self.log_timer.start(3000)

    def _update_paths(self):
        """根据 work_dir 更新所有文件路径"""
        self.device_file = os.path.join(self.work_dir, "devices.txt")
        self.log_file = os.path.join(self.work_dir, "snmp_alerts.log")
        self.pending_alert = os.path.join(self.work_dir, "pending_alert.json")

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(8, 8, 8, 8)

        # ---- 顶部工具栏 ----
        top_bar = QHBoxLayout()

        self.btn_start = QPushButton("▶ 启动监控")
        self.btn_start.setStyleSheet(
            "QPushButton{background:#27ae60;color:white;font-weight:bold;padding:8px 20px;border-radius:4px;font-size:13px;}"
            "QPushButton:hover{background:#2ecc71;}"
        )
        self.btn_start.clicked.connect(self._toggle_monitor)
        top_bar.addWidget(self.btn_start)

        self.btn_refresh_devices = QPushButton("↻ 刷新设备")
        self.btn_refresh_devices.setStyleSheet("padding:8px 14px;font-size:12px;")
        self.btn_refresh_devices.clicked.connect(self._load_device_table)
        top_bar.addWidget(self.btn_refresh_devices)

        self.btn_clear_log = QPushButton("✕ 清空日志")
        self.btn_clear_log.setStyleSheet("padding:8px 14px;font-size:12px;")
        self.btn_clear_log.clicked.connect(self._clear_log)
        top_bar.addWidget(self.btn_clear_log)

        self.btn_cleanup = QPushButton("⚙ 清理残留进程")
        self.btn_cleanup.setStyleSheet(
            "QPushButton{background:#e67e22;color:white;font-weight:bold;padding:8px 14px;border-radius:4px;font-size:12px;}"
            "QPushButton:hover{background:#f39c12;}"
        )
        self.btn_cleanup.clicked.connect(self._cleanup_processes)
        top_bar.addWidget(self.btn_cleanup)

        self.btn_change_dir = QPushButton("📁 切换工作目录")
        self.btn_change_dir.setStyleSheet("padding:8px 14px;font-size:12px;")
        self.btn_change_dir.clicked.connect(self._change_work_dir)
        top_bar.addWidget(self.btn_change_dir)

        top_bar.addStretch()

        self.lbl_status = QLabel("● 已停止")
        self.lbl_status.setStyleSheet("font-weight:bold;font-size:13px;color:#e74c3c;")
        top_bar.addWidget(self.lbl_status)

        main_layout.addLayout(top_bar)

        # ---- 分割区域: 设备管理 | 告警日志 ----
        splitter = QSplitter(Qt.Vertical)

        # -- 设备管理区 --
        dev_group = QGroupBox("设备管理 (devices.txt)")
        dev_layout = QVBoxLayout(dev_group)

        self.device_table = QTableWidget(0, 4)
        self.device_table.setHorizontalHeaderLabels(["IP 地址", "Telnet 密码", "设备名称", "SNMP 团体字"])
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.device_table.setEditTriggers(QAbstractItemView.DoubleClicked)
        self.device_table.cellChanged.connect(self._on_device_cell_changed)
        self.device_table.setMaximumHeight(200)
        dev_layout.addWidget(self.device_table)

        btn_row = QHBoxLayout()
        self.btn_add_device = QPushButton("+ 添加设备")
        self.btn_add_device.setStyleSheet("padding:6px 12px;")
        self.btn_add_device.clicked.connect(self._add_device_row)
        btn_row.addWidget(self.btn_add_device)

        self.btn_del_device = QPushButton("- 删除选中")
        self.btn_del_device.setStyleSheet("padding:6px 12px;")
        self.btn_del_device.clicked.connect(self._remove_device_row)
        btn_row.addWidget(self.btn_del_device)

        btn_row.addStretch()

        self.lbl_device_count = QLabel("共 0 台设备")
        btn_row.addWidget(self.lbl_device_count)

        dev_layout.addLayout(btn_row)
        splitter.addWidget(dev_group)

        # -- 告警日志区 --
        log_group = QGroupBox("告警日志 & 监控输出")
        log_layout = QVBoxLayout(log_group)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.log_text.setStyleSheet("background:#1e1e1e;color:#d4d4d4;border:none;")
        log_layout.addWidget(self.log_text)

        splitter.addWidget(log_group)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 5)
        main_layout.addWidget(splitter)

        # ---- 状态栏 ----
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"工作目录: {self.work_dir}")

    # ---- 监控控制 ----
    def _toggle_monitor(self):
        if self.monitor_running:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        # 检查 devices.txt 是否存在
        if not os.path.exists(self.device_file):
            reply = QMessageBox.question(
                self, "设备文件不存在",
                f"在 {self.work_dir} 下未找到 devices.txt\n"
                f"是否创建一个空模板？",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                save_devices(self.device_file, [])
                self._load_device_table()
            else:
                return

        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] 正在启动 SNMP Trap 监控...")
        self.log_text.append(f"  工作目录: {self.work_dir}")
        self.log_text.append(f"  设备文件: {self.device_file}")
        self.log_text.append("")

        self.signals = MonitorSignals()
        self.signals.output.connect(self._on_monitor_output)
        self.signals.finished.connect(self._on_monitor_finished)

        self.monitor_worker = MonitorWorker(self.signals, self.work_dir)
        self.monitor_worker.start()

        self.monitor_running = True
        self.btn_start.setText("■ 停止监控")
        self.btn_start.setStyleSheet(
            "QPushButton{background:#e74c3c;color:white;font-weight:bold;padding:8px 20px;border-radius:4px;font-size:13px;}"
            "QPushButton:hover{background:#c0392b;}"
        )
        self.lbl_status.setText("● 运行中")
        self.lbl_status.setStyleSheet("font-weight:bold;font-size:13px;color:#27ae60;")
        self.status_bar.showMessage("监控已启动，正在监听 SNMP Trap...")
        # 监控运行时禁止切换目录
        self.btn_change_dir.setEnabled(False)

    def _stop_monitor(self):
        if self.monitor_worker:
            self.monitor_worker.stop()
            # 等待线程结束（最多5秒）
            self.monitor_worker.join(timeout=5)
            self.monitor_worker = None
        self.monitor_running = False
        self.btn_start.setText("▶ 启动监控")
        self.btn_start.setStyleSheet(
            "QPushButton{background:#27ae60;color:white;font-weight:bold;padding:8px 20px;border-radius:4px;font-size:13px;}"
            "QPushButton:hover{background:#2ecc71;}"
        )
        self.lbl_status.setText("● 已停止")
        self.lbl_status.setStyleSheet("font-weight:bold;font-size:13px;color:#e74c3c;")
        self.log_text.append(f"\n[{datetime.now().strftime('%H:%M:%S')}] 监控已停止。\n")
        self.status_bar.showMessage("监控已停止。")
        self.btn_change_dir.setEnabled(True)

    def _cleanup_processes(self):
        """手动清理所有残留的监控子进程，释放端口。"""
        ts = datetime.now().strftime('%H:%M:%S')
        self.log_text.append(f"[{ts}] 正在扫描残留监控进程...")

        if self.monitor_running:
            self._stop_monitor()

        killed_pids = []
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "UDP"],
                capture_output=True, text=True, timeout=10,
                encoding="gbk", errors="ignore"
            )
            found = False
            for line in result.stdout.split("\n"):
                if ":162" in line:
                    parts = line.split()
                    pid = parts[-1] if parts else None
                    if pid and pid.isdigit():
                        if int(pid) == os.getpid():
                            continue
                        found = True
                        self.log_text.append(
                            f'<span style="color:#f39c12">  发现占用端口的进程 PID {pid}: {line.strip()}</span>'
                        )
                        try:
                            r = subprocess.run(
                                ["taskkill", "/F", "/T", "/PID", pid],
                                capture_output=True, text=True, timeout=5,
                                encoding="gbk", errors="ignore"
                            )
                            if r.returncode == 0:
                                killed_pids.append(pid)
                                self.log_text.append(
                                    f'<span style="color:#27ae60">  ✓ 已终止 PID {pid}</span>'
                                )
                            else:
                                self.log_text.append(
                                    f'<span style="color:#e74c3c">  ✗ 终止 PID {pid} 失败: {r.stdout.strip()}</span>'
                                )
                        except Exception as e:
                            self.log_text.append(
                                f'<span style="color:#e74c3c">  ✗ 终止 PID {pid} 异常: {e}</span>'
                            )
            if not found:
                self.log_text.append(
                    f'<span style="color:#2ecc71">  未发现占用 UDP 162 端口的残留进程，一切正常。</span>'
                )
        except Exception as e:
            self.log_text.append(f'<span style="color:#e74c3c">  扫描异常: {e}</span>')

        time.sleep(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("0.0.0.0", 162))
            s.close()
            self.log_text.append(
                f'<span style="color:#2ecc71">[{ts}] ✓ UDP 162 端口已释放，可以正常启动监控。</span>'
            )
        except OSError:
            s.close()
            self.log_text.append(
                f'<span style="color:#e74c3c">[{ts}] ✗ UDP 162 端口仍被占用，可能需要管理员权限。</span>'
            )

        summary = f"清理完成：终止了 {len(killed_pids)} 个残留进程"
        if killed_pids:
            summary += f" ({', '.join(killed_pids)})"
        self.status_bar.showMessage(summary)

    def _change_work_dir(self):
        """切换工作目录"""
        if self.monitor_running:
            QMessageBox.warning(self, "提示", "请先停止监控再切换工作目录。")
            return

        new_dir = QFileDialog.getExistingDirectory(
            self, "选择工作目录", self.work_dir
        )
        if not new_dir:
            return

        self.work_dir = new_dir
        self._update_paths()

        self._load_device_table()
        self.log_text.clear()
        self._log_mtime = None
        self._load_log()

        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] 工作目录已切换为: {self.work_dir}")
        self.log_text.append(f"  设备文件: {self.device_file}")
        self.log_text.append(f"  日志文件: {self.log_file}")
        self.status_bar.showMessage(f"工作目录: {self.work_dir}")

    def _on_monitor_output(self, line):
        if "CRITICAL" in line:
            color = "#ff6b6b"
        elif "WARNING" in line:
            color = "#feca57"
        elif "STEP" in line or "CALLBACK" in line:
            color = "#48dbfb"
        elif "Repair" in line or "repair" in line:
            color = "#0abde3"
        elif "Solution" in line or "solution" in line:
            color = "#10ac84"
        elif "[*]" in line:
            color = "#d4d4d4"
        elif "[!]" in line:
            color = "#ff9f43"
        elif "=====" in line or "-----" in line or "~" * 20 in line:
            color = "#576574"
        else:
            color = "#d4d4d4"

        self.log_text.append(f'<span style="color:{color}">{line}</span>')
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)

    def _on_monitor_finished(self, code):
        if self.monitor_running:
            self.log_text.append(f"\n[!] 监控进程异常退出，返回码: {code}")
            self._stop_monitor()

    # ---- 设备表格操作 ----
    def _load_device_table(self):
        devices = load_devices(self.device_file)
        self.device_table.blockSignals(True)
        self.device_table.setRowCount(len(devices))
        for row, d in enumerate(devices):
            self.device_table.setItem(row, 0, QTableWidgetItem(d["ip"]))
            self.device_table.setItem(row, 1, QTableWidgetItem(d["password"]))
            self.device_table.setItem(row, 2, QTableWidgetItem(d["name"]))
            self.device_table.setItem(row, 3, QTableWidgetItem(d["snmp_community"]))
        self.device_table.blockSignals(False)
        self.lbl_device_count.setText(f"共 {len(devices)} 台设备")
        self.status_bar.showMessage(
            f"工作目录: {self.work_dir}  |  已加载 {len(devices)} 台设备  |  监控: {'运行中' if self.monitor_running else '已停止'}"
        )

    def _on_device_cell_changed(self, row, col):
        if row < 0 or col < 0:
            return
        ip = self.device_table.item(row, 0)
        pwd = self.device_table.item(row, 1)
        name = self.device_table.item(row, 2)
        snmp = self.device_table.item(row, 3)
        if not ip or not ip.text().strip():
            return
        devices = load_devices(self.device_file)
        new_dev = {
            "ip": ip.text().strip(),
            "password": (pwd.text().strip() if pwd else ""),
            "name": (name.text().strip() if name else ip.text().strip()),
            "snmp_community": (snmp.text().strip() if snmp else "public"),
        }
        found = False
        for i, d in enumerate(devices):
            if d["ip"] == new_dev["ip"]:
                devices[i] = new_dev
                found = True
                break
        if not found:
            devices.append(new_dev)
        save_devices(self.device_file, devices)
        self.lbl_device_count.setText(f"共 {len(devices)} 台设备")

    def _add_device_row(self):
        row = self.device_table.rowCount()
        self.device_table.insertRow(row)
        self.device_table.setItem(row, 0, QTableWidgetItem(""))
        self.device_table.setItem(row, 1, QTableWidgetItem(""))
        self.device_table.setItem(row, 2, QTableWidgetItem(""))
        self.device_table.setItem(row, 3, QTableWidgetItem("public"))
        self.device_table.editItem(self.device_table.item(row, 0))

    def _remove_device_row(self):
        rows = set(i.row() for i in self.device_table.selectedItems())
        if not rows:
            return
        devices = load_devices(self.device_file)
        for row in sorted(rows, reverse=True):
            item = self.device_table.item(row, 0)
            if item:
                ip = item.text().strip()
                devices = [d for d in devices if d["ip"] != ip]
            self.device_table.removeRow(row)
        save_devices(self.device_file, devices)
        self.lbl_device_count.setText(f"共 {len(devices)} 台设备")

    # ---- 日志操作 ----
    def _load_log(self):
        if not os.path.exists(self.log_file):
            return
        try:
            mtime = os.path.getmtime(self.log_file)
            if not hasattr(self, '_log_mtime') or mtime > self._log_mtime:
                self._log_mtime = mtime
                with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if content.strip():
                    current = self.log_text.toPlainText()
                    if content.strip() not in current:
                        self.log_text.append(f"\n--- 日志文件 (snmp_alerts.log) ---")
                        self.log_text.append(f'<span style="color:#576574">{content.strip()}</span>')
        except:
            pass

    def _clear_log(self):
        self.log_text.clear()
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        self._log_mtime = None
        self.log_text.append(f"[{datetime.now().strftime('%H:%M:%S')}] 日志已清空。")

    # ---- 退出清理 ----
    def _kill_all_monitor_processes(self):
        """彻底清理所有占用UDP 162端口的监控进程。"""
        killed = []
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "UDP"],
                capture_output=True, text=True, timeout=10,
                encoding="gbk", errors="ignore"
            )
            for line in result.stdout.split("\n"):
                if ":162" in line and ("LISTENING" in line or ":0" in line.split()[-2:]):
                    parts = line.split()
                    pid = parts[-1] if parts else None
                    if pid and pid.isdigit():
                        if int(pid) == os.getpid():
                            continue
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/T", "/PID", pid],
                                capture_output=True, timeout=5
                            )
                            killed.append(pid)
                        except Exception:
                            pass
        except Exception:
            pass
        return killed

    def closeEvent(self, event):
        # 1. 停止当前监控线程
        if self.monitor_running:
            self._stop_monitor()
        # 2. 再扫一遍，确保没有残留进程占用端口
        killed = self._kill_all_monitor_processes()
        if killed:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                            f"退出时清理了残留进程: {killed}\n")
            except Exception:
                pass
        event.accept()


# ============================================================
# 入口
# ============================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # 暗色主题
    from PyQt5.QtGui import QPalette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 48))
    palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
    palette.setColor(QPalette.Base, QColor(30, 30, 30))
    palette.setColor(QPalette.AlternateBase, QColor(45, 45, 48))
    palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
    palette.setColor(QPalette.ToolTipText, QColor(220, 220, 220))
    palette.setColor(QPalette.Text, QColor(220, 220, 220))
    palette.setColor(QPalette.Button, QColor(45, 45, 48))
    palette.setColor(QPalette.ButtonText, QColor(220, 220, 220))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
