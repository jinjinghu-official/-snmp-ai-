# -*- coding: utf-8 -*-
"""
告警监听器 - 监控 pending_alert.json 并转发给 AI 进行分析
以后台自动化方式运行，轮询 pending_alert.json，
将告警上下文发送给 AI，并写回 repair_response.json。
"""

import sys
import os
import json
import time
from datetime import datetime

PENDING_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pending_alert.json")
RESPONSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repair_response.json")
PROCESSED_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "processed_alerts.log")

# 此文件会被 AI Agent 读取
# 当 AI 检测到待处理告警时，进行分析并写入 repair_response.json


def format_alert_for_ai(alert_data):
    """将告警数据格式化为可读文本，供 AI 分析。"""
    alert = alert_data.get("alert", {})
    lines = [
        f"SNMP Trap 告警 - 需要分析与修复决策",
        f"",
        f"Time:       {alert.get('time')}",
        f"Source IP:  {alert.get('source')}",
        f"Alarm Type: {alert.get('alarm_name', 'Unknown')}",
        f"Alarm Key:  {alert.get('alarm_key')}",
        f"Severity:   {alert.get('level')}",
        f"Trap OID:   {alert.get('trap_oid')}",
        f"",
    ]

    varbinds = alert.get("varbinds", [])
    if varbinds:
        lines.append("VarBinds:")
        for vb in varbinds:
            lines.append(f"  {vb.get('oid')} = {vb.get('value')}")
        lines.append("")

    diag = alert.get("diagnostics", [])
    if diag:
        lines.append("Router Diagnostic Output:")
        for d in diag:
            lines.append(f"  --- {d.get('cmd')} ---")
            for line in d.get("output", "").strip().split("\n"):
                if line.strip():
                    lines.append(f"    {line.strip()}")
            lines.append("")
    else:
        lines.append("未采集到诊断输出。")
        lines.append("")

    lines.append("请分析此告警并决定:")
    lines.append("1. 根本原因是什么？")
    lines.append("2. 应该执行哪些修复命令？")
    lines.append("3. 将响应写入: " + RESPONSE_FILE)
    lines.append("   格式: {\"approved\": true/false, \"commands\": [...], \"reason\": \"...\"}")
    lines.append("")

    return "\n".join(lines)


def main():
    print(f"[告警监听器] 启动于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print(f"[告警监听器] 监控文件: {PENDING_FILE}", flush=True)
    print(f"[告警监听器] 按 Ctrl+C 停止", flush=True)

    try:
        while True:
            if os.path.exists(PENDING_FILE):
                try:
                    with open(PENDING_FILE, "r", encoding="utf-8") as f:
                        alert_data = json.load(f)

                    if alert_data.get("status") == "pending_analysis":
                        # 记录告警到日志
                        with open(PROCESSED_LOG, "a", encoding="utf-8") as f:
                            f.write(f"\n[{datetime.now().isoformat()}] 收到告警\n")
                            f.write(json.dumps(alert_data, indent=2, ensure_ascii=False))
                            f.write("\n")

                        # 标记为处理中
                        alert_data["status"] = "processing"
                        with open(PENDING_FILE, "w", encoding="utf-8") as f:
                            json.dump(alert_data, f, indent=2, ensure_ascii=False)

                        # 格式化并输出，供 AI 读取
                        formatted = format_alert_for_ai(alert_data)
                        print(f"\n{'='*60}", flush=True)
                        print(formatted, flush=True)
                        print(f"{'='*60}\n", flush=True)

                        # 删除待处理文件，避免重复处理
                        try:
                            os.remove(PENDING_FILE)
                        except:
                            pass

                except (json.JSONDecodeError, Exception) as e:
                    print(f"[告警监听器] 读取待处理文件出错: {e}", flush=True)
                    try:
                        os.remove(PENDING_FILE)
                    except:
                        pass

            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n[告警监听器] 已停止。", flush=True)


if __name__ == "__main__":
    main()
