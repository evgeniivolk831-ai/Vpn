#!/usr/bin/env python3
import base64
import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
OUT.mkdir(parents=True, exist_ok=True)

SOURCES = [
    ("Au1rxx-v2ray-base64", "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt", "base64"),
    ("zengfr-vless", "https://raw.githubusercontent.com/zengfr/free-vpn-subscribe/main/vpn_sub_vless.txt", "text"),
    ("zengfr-all", "https://raw.githubusercontent.com/zengfr/free-vpn-subscribe/main/vpn_sub_.txt", "text"),
]

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria://", "hysteria2://", "tuic://", "wg://")

def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "GlobalPulse-VLESS/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "ignore")

def decode_maybe_b64(s: str) -> str:
    raw = s.strip()
    candidates = [raw]
    compact = re.sub(r"\s+", "", raw)
    if compact:
        candidates.append(compact)
    for c in candidates:
        try:
            pad = "=" * (-len(c) % 4)
            decoded = base64.b64decode(c + pad, validate=False).decode("utf-8", "ignore")
            if "://" in decoded:
                return decoded
        except Exception:
            pass
    return raw

def extract(text: str):
    text = decode_maybe_b64(text)
    # Also decode individual base64-looking lines where applicable.
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
    # Remove display-only fragments and normalize whitespace.
    uri = uri.strip().split("#", 1)[0]
    return uri

all_nodes = []
source_stats = {}
for name, url, kind in SOURCES:
    try:
        text = fetch(url)
        nodes = extract(text)
        source_stats[name] = {"ok": True, "nodes": len(nodes)}
        all_nodes.extend(nodes)
    except Exception as e:
        source_stats[name] = {"ok": False, "nodes": 0, "error": str(e)[:200]}

unique = []
seen = set()
for node in all_nodes:
    key = canonical_key(node)
    if key in seen:
        continue
    seen.add(key)
    unique.append(node)

# Prefer VLESS/Reality first, then other supported protocols.
def rank(uri):
    low = uri.lower()
    score = 0
    if low.startswith("vless://"):
        score += 100
        if "security=reality" in low or "security%3dreality" in low:
            score += 20
    elif low.startswith("hysteria2://"):
        score += 90
    elif low.startswith("trojan://"):
        score += 80
    elif low.startswith("tuic://"):
        score += 70
    elif low.startswith("vmess://"):
        score += 60
    elif low.startswith("ss://"):
        score += 50
    return -score

unique.sort(key=rank)
vless = [x for x in unique if x.lower().startswith("vless://")][:100]
all_top = unique[:100]

def write_lines(path, lines):
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

write_lines(OUT / "GlobalPulse-VLESS.txt", vless)
write_lines(OUT / "GlobalPulse-All.txt", all_top)

payload = "\n".join(all_top)
encoded = base64.b64encode(payload.encode()).decode()
write_lines(OUT / "GlobalPulse-Base64.txt", [encoded])

stats = {
    "name": "GlobalPulse VLESS",
    "sources": source_stats,
    "unique_nodes": len(unique),
    "vless_nodes": len(vless),
    "published_all": len(all_top),
    "published_vless": len(vless),
}
(OUT / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps(stats, ensure_ascii=False, indent=2))
