"""测试通过环境变量系统代理访问 arxlabs"""
import os

# 设置系统级代理 (让到 arxlabs 的连接走本地VPN)
os.environ["HTTP_PROXY"] = "http://127.0.0.1:10808"
os.environ["HTTPS_PROXY"] = "http://127.0.0.1:10808"
os.environ["ALL_PROXY"] = "http://127.0.0.1:10808"

from curl_cffi import requests

arxlabs = "http://4gsz1122562-region-US-sid-H4VhujSZ-t-120:p9xqpky9@us.arxlabs.io:3010"

# 测试1: 只走 arxlabs (靠环境变量的系统代理连接到 arxlabs)
print("=== 测试: arxlabs 为显式代理, 环境变量走本地VPN ===")
try:
    r = requests.get("https://httpbin.org/ip", proxy=arxlabs, timeout=20, impersonate="chrome136")
    print(f"✅ Status: {r.status_code}")
    print(f"   IP: {r.text.strip()}")
except Exception as e:
    print(f"❌ {str(e)[:120]}")

# 对比: 只走本地
print("\n=== 对比: 只走本地代理 ===")
try:
    r = requests.get("https://httpbin.org/ip", proxy="http://127.0.0.1:10808", timeout=20, impersonate="chrome136")
    print(f"✅ IP: {r.text.strip()}")
except Exception as e:
    print(f"❌ {str(e)[:120]}")
