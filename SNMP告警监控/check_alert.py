#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP 告警自动分析与修复脚本
持续监控 pending_alert.json，分析告警 -> 生成修复命令 -> telnet远程执行
"""

import json
import time
import os
import sys
import telnetlib
from datetime import datetime

# 文件路径
PENDING_ALERT_FILE = r"C:\Users\admin\WorkBuddy\Claw\pending_alert.json"
REPAIR_RESPONSE_FILE = r"C:\Users\admin\WorkBuddy\Claw\repair_response.json"
DEVICES_FILE = r"C:\Users\admin\WorkBuddy\Claw\devices.txt"

# 检查间隔（秒）
CHECK_INTERVAL = 30


def load_devices():
    """加载设备列表"""
    devices = {}
    try:
        with open(DEVICES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) >= 4:
                    ip, password, name, community = parts[:4]
                    devices[ip] = {
                        'ip': ip,
                        'password': password,
                        'name': name,
                        'community': community
                    }
    except Exception as e:
        print(f"[错误] 加载设备列表失败: {e}")
    return devices


def analyze_alert(alert_data, devices):
    """
    分析告警并生成修复命令
    返回: (分析结果, 修复命令列表, 建议措施)
    """
    alarm_key = alert_data.get('alarm_key', '')
    alarm_name = alert_data.get('alarm_name', '')
    source_ip = alert_data.get('source', '')
    varbinds = alert_data.get('varbinds', [])
    diagnostics = alert_data.get('diagnostics', [])
    
    # 获取设备信息
    device = devices.get(source_ip, {})
    device_name = device.get('name', source_ip)
    
    # 提取接口信息（如果有）
    interface = None
    for vb in varbinds:
        if 'GigabitEthernet' in str(vb.get('value', '')):
            interface = vb.get('value')
            break
    
    analysis_result = ""
    repair_commands = []
    suggestions = []
    
    # 根据告警类型分析
    if alarm_key == 'linkdown' or 'linkDown' in alarm_name:
        analysis_result = f"接口 {interface or '未知'} 链路断开，可能是物理连接故障或对端设备问题"
        if interface:
            repair_commands = [
                f"interface {interface}",
                "shutdown",
                "undo shutdown",
                f"display interface {interface}"
            ]
        suggestions = [
            "检查物理线缆连接",
            "检查对端设备状态",
            "查看接口光模块状态"
        ]
        
    elif alarm_key == 'linkup' or 'Link Up' in alarm_name:
        analysis_result = f"接口 {interface or '未知'} 链路恢复，连接已重新建立"
        if interface:
            repair_commands = [
                f"display interface {interface}",
                "display ip interface brief",
                "display arp"
            ]
        suggestions = [
            "确认链路稳定性",
            "检查业务是否正常恢复",
            "监控接口流量变化"
        ]
        
    elif 'bgp' in alarm_key.lower() or 'BGP' in alarm_name:
        analysis_result = "BGP邻居关系异常，可能是网络不可达或配置问题"
        repair_commands = [
            "display bgp peer",
            "display bgp error",
            "display ip routing-table protocol bgp"
        ]
        suggestions = [
            "检查BGP邻居IP可达性",
            "核对BGP配置参数",
            "查看BGP错误统计"
        ]
        
    elif 'ospf' in alarm_key.lower() or 'OSPF' in alarm_name:
        analysis_result = "OSPF邻居状态变化，可能影响路由收敛"
        repair_commands = [
            "display ospf peer",
            "display ospf interface",
            "display ospf error"
        ]
        suggestions = [
            "检查OSPF邻居关系",
            "确认区域配置正确",
            "检查Hello/Dead定时器"
        ]
        
    elif 'cpu' in alarm_key.lower() or 'CPU' in alarm_name:
        analysis_result = "设备CPU使用率过高，可能影响设备性能"
        repair_commands = [
            "display cpu-usage",
            "display process cpu",
            "display memory-usage"
        ]
        suggestions = [
            "检查异常进程",
            "考虑流量分流",
            "优化路由策略"
        ]
        
    elif 'memory' in alarm_key.lower() or 'Memory' in alarm_name:
        analysis_result = "设备内存使用率过高"
        repair_commands = [
            "display memory-usage",
            "display process memory",
            "reset recycle-bin"
        ]
        suggestions = [
            "清理不必要的文件",
            "重启非关键服务",
            "考虑设备扩容"
        ]
        
    elif 'authentication' in alarm_key.lower() or '密码' in str(diagnostics):
        analysis_result = "Telnet/SSH认证失败，可能是密码错误或账户锁定"
        repair_commands = [
            "display local-user",
            "display aaa configuration",
            "test-aaa"
        ]
        suggestions = [
            "核对用户名密码",
            "检查AAA配置",
            "确认用户权限"
        ]
        
    else:
        analysis_result = f"收到告警: {alarm_name}，需要进一步分析"
        repair_commands = [
            "display alarm active",
            "display logbuffer",
            "display trapbuffer"
        ]
        suggestions = [
            "查看设备告警信息",
            "分析系统日志",
            "联系技术支持"
        ]
    
    # 检查诊断信息中的认证失败
    for diag in diagnostics:
        if 'Username or password invalid' in str(diag.get('output', '')):
            analysis_result += " | 注意：Telnet认证失败，请检查密码配置"
            suggestions.insert(0, "检查devices.txt中的密码配置是否正确")
    
    return analysis_result, repair_commands, suggestions


def telnet_exec(host, password, commands, alarm_name=""):
    """
    通过telnet连接华为路由器并执行修复命令
    返回: 执行结果列表 或 None(连接失败)
    """
    print(f"\n[Telnet] 正在连接 {host}:23 ...", flush=True)
    tn = None
    try:
        tn = telnetlib.Telnet(host, 23, timeout=15)
    except Exception as e:
        print(f"[Telnet错误] 无法连接到 {host}: {e}", flush=True)
        return None

    time.sleep(1)
    # 读取登录提示
    raw = tn.read_very_eager().decode("gbk", errors="ignore")
    print(f"[Telnet] 登录提示: {raw.strip()}", flush=True)

    # 如果需要密码
    if "Password" in raw or "password" in raw:
        print(f"[Telnet] 发送密码认证...", flush=True)
        tn.write(password.encode("ascii") + b"\n")
        time.sleep(1)
        banner = tn.read_very_eager().decode("gbk", errors="ignore")
        print(f"[Telnet] 登录成功: {banner.strip()}", flush=True)
    else:
        print(f"[Telnet] 已进入系统（无需密码或已自动登录）", flush=True)

    # 判断是否需要进入系统视图（配置类命令需要system-view）
    needs_sysview = any(
        cmd.startswith("interface ") or cmd in ("shutdown", "undo shutdown", "undo shutdown")
        for cmd in commands
    )

    if needs_sysview:
        print("[Telnet] 进入 system-view", flush=True)
        tn.write(b"system-view\n")
        time.sleep(1)
        resp = tn.read_very_eager().decode("gbk", errors="ignore")
        print(resp.strip(), flush=True)

    results = []
    for cmd in commands:
        print(f"\n[Telnet] > {cmd}", flush=True)
        tn.write(cmd.encode("ascii") + b"\n")
        time.sleep(1)
        out = tn.read_very_eager().decode("gbk", errors="ignore")
        # 只显示关键输出，避免刷屏
        output_lines = out.strip().split('\r\n')
        for line in output_lines[-5:]:  # 显示最后5行
            print(f"  {line}", flush=True)
        results.append({"cmd": cmd, "output": out})

    # 返回用户视图并退出
    if needs_sysview:
        tn.write(b"return\n")
        time.sleep(0.5)
        tn.read_very_eager()
    tn.write(b"quit\n")
    time.sleep(0.3)
    try:
        tn.close()
    except:
        pass
    print(f"\n[Telnet] 连接已关闭", flush=True)
    return results


def process_alert():
    """处理待处理的告警：分析 -> 生成修复 -> telnet执行"""
    try:
        # 检查文件是否存在
        if not os.path.exists(PENDING_ALERT_FILE):
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 无待处理告警文件")
            return False
        
        # 读取告警文件
        with open(PENDING_ALERT_FILE, 'r', encoding='utf-8') as f:
            alert_data = json.load(f)
        
        # 检查状态
        if alert_data.get('status') != 'pending_analysis':
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 告警状态: {alert_data.get('status')}，无需处理")
            return False
        
        alert_id = alert_data.get('alert_id', 'unknown')
        alert_info = alert_data.get('alert', {})
        
        print(f"\n{'='*60}")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 发现待处理告警")
        print(f"告警ID:   {alert_id}")
        print(f"告警类型: {alert_info.get('alarm_name', 'Unknown')}")
        print(f"告警源:   {alert_info.get('source', 'Unknown')}")
        print(f"{'='*60}")
        
        # 加载设备信息
        devices = load_devices()
        
        # ========== 第1步：分析告警 ==========
        analysis, commands, suggestions = analyze_alert(alert_info, devices)
        
        print(f"\n[分析] {analysis}")
        print(f"[修复方案] 共 {len(commands)} 条命令:")
        for cmd in commands:
            print(f"       > {cmd}")
        
        # ========== 第2步：写入修复响应文件 ==========
        repair_response = {
            "alert_id": alert_id,
            "timestamp": datetime.now().isoformat(),
            "status": "analyzed",
            "source_ip": alert_info.get('source', ''),
            "alarm_name": alert_info.get('alarm_name', ''),
            "analysis": analysis,
            "repair_commands": commands,
            "suggestions": suggestions,
            "device_info": devices.get(alert_info.get('source', ''), {})
        }
        
        with open(REPAIR_RESPONSE_FILE, 'w', encoding='utf-8') as f:
            json.dump(repair_response, f, ensure_ascii=False, indent=2)
        print(f"[文件] 修复方案已保存至: {REPAIR_RESPONSE_FILE}")
        
        # ========== 第3步：通过telnet执行修复命令 ==========
        source_ip = alert_info.get('source', '')
        device = devices.get(source_ip)
        
        if device and commands:
            print(f"\n[修复] 开始通过telnet远程修复...")
            print(f"[修复] 目标设备: {device.get('name', source_ip)} ({source_ip})")
            
            exec_results = telnet_exec(
                host=device['ip'],
                password=device['password'],
                commands=commands,
                alarm_name=alert_info.get('alarm_name', '')
            )
            
            if exec_results:
                # 修复执行成功，更新状态
                repair_response['status'] = 'repaired'
                repair_response['executed_at'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
                repair_response['execution_results'] = [
                    {r['cmd']: r['output'][:1000]} for r in exec_results
                ]
                
                with open(REPAIR_RESPONSE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(repair_response, f, ensure_ascii=False, indent=2)
                
                print(f"\n[修复完成] telnet修复命令已全部执行，结果已保存")
            else:
                # telnet连接失败
                repair_response['status'] = 'repair_failed'
                repair_response['repair_error'] = f"无法通过telnet连接到 {source_ip}"
                
                with open(REPAIR_RESPONSE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(repair_response, f, ensure_ascii=False, indent=2)
                
                print(f"\n[修复失败] telnet连接 {source_ip} 失败，请检查设备状态")
        else:
            if not device:
                print(f"\n[跳过修复] 设备 {source_ip} 不在设备列表中，无法执行telnet修复")
                repair_response['status'] = 'repair_skipped'
                repair_response['repair_error'] = f"设备 {source_ip} 未在 devices.txt 中找到"
                with open(REPAIR_RESPONSE_FILE, 'w', encoding='utf-8') as f:
                    json.dump(repair_response, f, ensure_ascii=False, indent=2)
            else:
                print(f"\n[跳过修复] 无修复命令需要执行")
        
        # ========== 第4步：更新告警状态 ==========
        final_status = repair_response.get('status', 'resolved')
        alert_data['status'] = 'resolved'
        alert_data['resolved_at'] = datetime.now().isoformat()
        alert_data['analysis'] = analysis
        alert_data['repair_commands'] = commands
        alert_data['repair_status'] = final_status
        
        with open(PENDING_ALERT_FILE, 'w', encoding='utf-8') as f:
            json.dump(alert_data, f, ensure_ascii=False, indent=2)
        
        print(f"[告警] pending_alert.json 状态已更新为: resolved (修复状态: {final_status})")
        return True
        
    except json.JSONDecodeError as e:
        print(f"[错误] JSON解析失败: {e}")
        return False
    except Exception as e:
        print(f"[错误] 处理告警时发生异常: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """主循环"""
    print("=" * 60)
    print("SNMP 告警自动分析与修复系统（含telnet远程修复）")
    print("=" * 60)
    print(f"监控文件: {PENDING_ALERT_FILE}")
    print(f"输出文件: {REPAIR_RESPONSE_FILE}")
    print(f"设备列表: {DEVICES_FILE}")
    print(f"检查间隔: {CHECK_INTERVAL} 秒")
    print("=" * 60)
    print("工作流程: 告警检测 -> 分析生成修复方案 -> telnet远程执行修复")
    print("按 Ctrl+C 停止监控\n")
    
    try:
        while True:
            process_alert()
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\n\n监控已停止")


if __name__ == '__main__':
    main()
