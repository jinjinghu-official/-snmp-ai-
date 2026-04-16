# -*- coding: utf-8 -*-
"""
告警回调脚本
将告警信息写入请求文件，供外部 AI 系统读取并分析。
由 snmp_trap_monitor.py 在收到 Trap 时调用。
"""

import sys
import os
import json
import time
from datetime import datetime

REQUEST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pending_alert.json")
RESPONSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repair_response.json")


def main():
    if len(sys.argv) < 3:
        print("[错误] 用法: alert_callback.py <告警文件> <响应文件>")
        sys.exit(1)

    alert_file = sys.argv[1]
    response_file = sys.argv[2]

    # 读取告警文件
    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        print(f"[错误] 无法读取告警文件: {e}")
        sys.exit(1)

    # 写入请求文件，供 AI 系统读取
    request = {
        "timestamp": datetime.now().isoformat(),
        "alert": alert,
        "status": "pending_analysis",
        "response_file": response_file,
    }

    with open(REQUEST_FILE, "w", encoding="utf-8") as f:
        json.dump(request, f, indent=2, ensure_ascii=False)

    print(f"[CALLBACK] 告警已写入 {REQUEST_FILE}")
    print(f"[CALLBACK] 等待AI分析并返回修复响应...")
    print(f"[CALLBACK] 告警详情:")
    print(f"  告警源:   {alert.get('source')}")
    print(f"  告警类型: {alert.get('alarm_name')}")
    print(f"  Trap OID: {alert.get('trap_oid')}")
    print(f"  时间:     {alert.get('time')}")
    print(f"  VarBinds: {json.dumps(alert.get('varbinds', []), ensure_ascii=False)}")

    if "diagnostics" in alert:
        print(f"  诊断信息:")
        for d in alert["diagnostics"]:
            print(f"    [{d['cmd']}]: {d['output'][:200]}...")

    # 等待 AI 写入修复响应（带超时）
    max_wait = 110  # 秒
    for i in range(max_wait):
        if os.path.exists(response_file):
            with open(response_file, "r", encoding="utf-8") as f:
                resp = json.load(f)
            print(f"[CALLBACK] 收到修复响应!")
            print(f"  批准执行: {resp.get('approved')}")
            print(f"  修复命令: {resp.get('commands', [])}")
            print(f"  原因:     {resp.get('reason', '')}")
            # 清理请求文件
            try:
                os.remove(REQUEST_FILE)
            except:
                pass
            sys.exit(0)
        time.sleep(1)

    print(f"[CALLBACK] 等待AI响应超时 ({max_wait}秒)")
    sys.exit(1)


if __name__ == "__main__":
    main()
