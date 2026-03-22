#!/usr/bin/env bash
set -euo pipefail

openclaw gateway status --json 2>/dev/null | python3 -c '
import json,sys
j=json.load(sys.stdin)
svc=j.get("service",{})
runtime=svc.get("runtime",{})
gw=j.get("gateway",{})
rpc=j.get("rpc",{})
print(f"service: {"loaded" if svc.get("loaded") else "not loaded"}")
print(f"runtime: {runtime.get("status","unknown")} (pid {runtime.get("pid","n/a")})")
print(f"rpc: {"ok" if rpc.get("ok") else "fail"}")
print(f"bind: {gw.get("bindMode","n/a")} ({gw.get("bindHost","n/a")}:{gw.get("port","n/a")})")
print(f"dashboard: http://{gw.get("bindHost","127.0.0.1")}:{gw.get("port",18789)}/")
'
