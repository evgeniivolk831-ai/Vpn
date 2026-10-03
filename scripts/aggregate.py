#!/usr/bin/env python3
import base64
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
OUT.mkdir(parents=True, exist_ok=True)

# Only feeds that publish configs after their own reachability/HTTP checks.
# We intentionally do not treat an untested raw dump as "working".
SOURCES = [
    ("Au1rxx-verified", "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt", "base64"),
    ("0xRadikal-verified", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt", "base64"),
    ("morpheus-best", "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt", "text"),
    ("dfantomasd-karing", "https://dfantomasd.github.io/MyVPN-subscription/public/karing.txt", "base64"),
]

SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria://", "hysteria2://", "tuic://", "wg://"
)

def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "GlobalPulse-VLESS/2.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "ignore")

def decode_maybe_b64(s: str) -> str:
    raw = s.strip()
    compact = re.sub(r"\s+", "", raw)
    for candidate in (raw, compact):
        if not candidate:
            continue
        try:
            pad = "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(candidate + pad, validate=False).decode("utf-8", "ignore")
            if "://" in decoded:
                return decoded
        except Exception:
            pass
    return raw

def extract(text: str):
    text = decode_maybe_b64(text)
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.lower().startswith(SCHEMES):
            found.append(line)
            continue
        if not re.match(r"^[A-Za-z0-9+/=_-]{40,}$", line):
            continue
        decoded = decode_maybe_b64(line)
        for item in decoded.splitlines():
            item = item.strip()
            if item.lower().startswith(SCHEMES):
                found.append(item)
    return found

def canonical_key(uri: str):
    return uri.strip().split("#", 1)[0]

def protocol_score(uri: str) -> int:
    low = uri.lower()
    if low.startswith("vless://"):
        score = 100
        if "security=reality" in low or "security%3dreality" in low:
            score += 25
        if "type=xhttp" in low or "type=h2" in low:
            score += 5
        return score
    if low.startswith("hysteria2://"):
        return 95
    if low.startswith("tuic://"):
        return 90
    if low.startswith("trojan://"):
        return 85
    if low.startswith("vmess://"):
        return 60
    if low.startswith("ss://"):
        return 55
    return 0

all_nodes = []
source_stats = {}

for name, url, kind in SOURCES:
    try:
        body = fetch(url)
        nodes = extract(body)
        source_stats[name] = {"ok": True, "nodes": len(nodes), "url": url}
        all_nodes.extend(nodes)
    except Exception as e:
        source_stats[name] = {"ok": False, "nodes": 0, "url": url, "error": str(e)[:240]}

unique = []
seen = set()
for node in all_nodes:
    key = canonical_key(node)
    if key in seen:
        continue
    seen.add(key)
    unique.append(node)

# Prefer censorship-resilient transports and keep diversity across sources.
unique.sort(key=lambda x: (-protocol_score(x), canonical_key(x)))

vless = [x for x in unique if x.lower().startswith("vless://")][:150]
all_top = unique[:200]

def write_lines(path: Path, lines):
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

write_lines(OUT / "GlobalPulse-VLESS.txt", vless)
write_lines(OUT / "GlobalPulse-All.txt", all_top)

payload = "\n".join(all_top)
encoded = base64.b64encode(payload.encode()).decode()
write_lines(OUT / "GlobalPulse-Base64.txt", [encoded])

# Clash Meta/Mihomo: local auto-selection. The client itself tests nodes
# from the user's network, which is stronger evidence for censorship reachability
# than a CI runner in another country.
repo_base = "https://raw.githubusercontent.com/evgeniivolk831-ai/Vpn/main/output/GlobalPulse-Base64.txt"
clash = f'''mixed-port: 7890
mode: rule
allow-lan: false
log-level: warning

proxy-providers:
  GlobalPulse:
    type: http
    url: "{repo_base}"
    interval: 900
    path: ./providers/globalpulse.txt
    health-check:
      enable: true
      url: https://www.gstatic.com/generate_204
      interval: 180
      timeout: 5000
      lazy: false

proxy-groups:
  - name: "GlobalPulse AUTO"
    type: url-test
    use:
      - GlobalPulse
    url: https://www.gstatic.com/generate_204
    interval: 180
    tolerance: 80
    lazy: false

  - name: "GlobalPulse FAILOVER"
    type: fallback
    use:
      - GlobalPulse
    url: https://www.gstatic.com/generate_204
    interval: 120
    timeout: 5000
    lazy: false

  - name: "PROXY"
    type: select
    proxies:
      - "GlobalPulse AUTO"
      - "GlobalPulse FAILOVER"
      - DIRECT

rules:
  - MATCH,PROXY
'''
write_lines(OUT / "GlobalPulse-Auto-Clash.yaml", clash.rstrip("\n").splitlines())

stats = {
    "name": "GlobalPulse VLESS",
    "policy": "verified-upstream-only",
    "sources": source_stats,
    "unique_nodes": len(unique),
    "vless_nodes": len(vless),
    "published_all": len(all_top),
    "published_vless": len(vless),
    "local_auto_selection": True,
    "local_healthcheck_interval_seconds": 180,
    "note": "Upstream CI verification cannot prove reachability from every ISP. The generated Clash/Mihomo profile re-tests nodes from the user's network and auto-selects a live one."
}
(OUT / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(stats, ensure_ascii=False, indent=2))
