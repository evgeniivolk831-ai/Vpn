#!/usr/bin/env python3
# scripts/aggregate.py
import base64
import json
import re
import urllib.parse
import urllib.request
import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
OUT.mkdir(parents=True, exist_ok=True)

MAX_CANDIDATE_VLESS = 300
PUBLISHED_KEYS = 120
V2RAYNG_PUBLISHED_KEYS = 50
MIN_PUBLISHED_KEYS = 1
MAX_ALL = 200
HEALTHCHECK_URL = "https://www.gstatic.com/generate_204"
TCP_CHECK_TIMEOUT = 3.0
TCP_CHECK_WORKERS = 32

SOURCES = [
    ("Au1rxx-verified", "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt", "base64"),
    ("0xRadikal-verified", "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt", "base64"),
    ("morpheus-best", "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/best.txt", "text"),
    ("dfantomasd-karing", "https://dfantomasd.github.io/MyVPN-subscription/public/karing.txt", "base64"),
]

SCHEMES = (
    "vless://", "vmess://", "trojan://", "ss://", "ssr://",
    "hysteria://", "hysteria2://", "tuic://", "wg://",
)


def fetch(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "GlobalPulse/3.0"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", "ignore")


def decode_maybe_b64(value: str) -> str:
    raw = value.strip()
    compact = re.sub(r"\s+", "", raw)
    for candidate in (raw, compact):
        if not candidate:
            continue
        try:
            padded = candidate + "=" * (-len(candidate) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8", "ignore")
            if "://" in decoded:
                return decoded
        except (ValueError, UnicodeError):
            continue
    return raw


def extract(text: str) -> list[str]:
    text = decode_maybe_b64(text)
    found: list[str] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        if line.lower().startswith(SCHEMES):
            found.append(line)
            continue

        if not re.fullmatch(r"[A-Za-z0-9+/=_-]{40,}", line):
            continue

        decoded = decode_maybe_b64(line)
        for item in decoded.splitlines():
            item = item.strip()
            if item.lower().startswith(SCHEMES):
                found.append(item)

    return found


def canonical_key(uri: str) -> str:
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


def tcp_reachable(uri: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(uri)
        if not parsed.hostname or not parsed.port:
            return False
        with socket.create_connection((parsed.hostname, parsed.port), timeout=TCP_CHECK_TIMEOUT):
            return True
    except (OSError, ValueError):
        return False


def filter_reachable(nodes: list[str]) -> tuple[list[str], int]:
    if not nodes:
        return [], 0
    reachable: list[str] = []
    checked = 0
    with ThreadPoolExecutor(max_workers=TCP_CHECK_WORKERS) as pool:
        futures = {pool.submit(tcp_reachable, node): node for node in nodes}
        for future in as_completed(futures):
            checked += 1
            if future.result():
                reachable.append(futures[future])
    reachable.sort(key=lambda item: (-protocol_score(item), canonical_key(item)))
    return reachable, checked


def vless_to_clash(uri: str, index: int) -> dict | None:
    parsed = urllib.parse.urlparse(uri)
    if (
        parsed.scheme.lower() != "vless"
        or not parsed.hostname
        or not parsed.port
        or not parsed.username
    ):
        return None

    query = urllib.parse.parse_qs(parsed.query)

    def one(name: str, default: str | None = None) -> str | None:
        values = query.get(name)
        return urllib.parse.unquote(values[0]) if values else default

    proxy: dict = {
        "name": f"GP-{index:03d}",
        "type": "vless",
        "server": parsed.hostname,
        "port": parsed.port,
        "uuid": urllib.parse.unquote(parsed.username),
        "udp": True,
    }

    security = (one("security") or "").lower()
    network = (one("type") or "tcp").lower().split("?", 1)[0]
    supported_networks = {"tcp", "ws", "grpc", "h2", "http"}
    if network not in supported_networks:
        return None

    if security == "reality" and not one("pbk"):
        return None

    if security != "none":
        proxy["tls"] = True

    if one("sni"):
        proxy["servername"] = one("sni")

    if one("fp"):
        proxy["client-fingerprint"] = one("fp")

    if security == "reality":
        reality_opts = {}
        if one("pbk"):
            reality_opts["public-key"] = one("pbk")
        if one("sid"):
            reality_opts["short-id"] = one("sid")
        if reality_opts:
            proxy["reality-opts"] = reality_opts

    if one("flow"):
        proxy["flow"] = one("flow")

    proxy["network"] = network

    if network == "ws":
        ws_opts = {"path": one("path") or "/"}
        host = one("host")
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts

    elif network == "h2":
        h2_opts = {"path": one("path") or "/"}
        host = one("host") or one("authority")
        if host:
            h2_opts["host"] = [host]
        proxy["h2-opts"] = h2_opts

    elif network == "grpc":
        proxy["grpc-opts"] = {
            "grpc-service-name": one("serviceName") or one("service_name") or ""
        }

    elif network == "http":
        http_opts = {"path": [one("path") or "/"]}
        host = one("host")
        if host:
            http_opts["headers"] = {"Host": [host]}
        proxy["http-opts"] = http_opts

    return proxy


def yaml_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def emit_yaml(value, indent: int = 0) -> list[str]:
    pad = " " * indent

    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.extend(emit_yaml(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {yaml_scalar(item)}")
        return lines

    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                first = True
                for key, child in item.items():
                    prefix = f"{pad}- " if first else f"{pad}  "
                    if isinstance(child, (dict, list)):
                        lines.append(f"{prefix}{key}:")
                        lines.extend(emit_yaml(child, indent + 4))
                    else:
                        lines.append(f"{prefix}{key}: {yaml_scalar(child)}")
                    first = False
            else:
                lines.append(f"{pad}- {yaml_scalar(item)}")
        return lines

    return [f"{pad}{yaml_scalar(value)}"]


def write_lines(path: Path, lines: list[str]) -> None:
    path.write_text(
        "\n".join(lines) + ("\n" if lines else ""),
        encoding="utf-8",
    )


all_nodes: list[str] = []
source_stats: dict = {}

for name, url, _kind in SOURCES:
    try:
        body = fetch(url)
        nodes = extract(body)
        source_stats[name] = {
            "ok": True,
            "nodes": len(nodes),
            "url": url,
        }
        all_nodes.extend(nodes)
    except Exception as exc:
        source_stats[name] = {
            "ok": False,
            "nodes": 0,
            "url": url,
            "error": str(exc)[:240],
        }

unique: list[str] = []
seen: set[str] = set()

for node in all_nodes:
    key = canonical_key(node)
    if key not in seen:
        seen.add(key)
        unique.append(node)

unique.sort(key=lambda item: (-protocol_score(item), canonical_key(item)))

candidate_vless = [
    node for node in unique
    if node.lower().startswith("vless://")
][:MAX_CANDIDATE_VLESS]
all_top = unique[:MAX_ALL]

reachable_vless, checked_vless = filter_reachable(candidate_vless)

e2e_file = Path(os.environ.get("E2E_RESULTS_FILE", OUT / "e2e-vless.json"))
e2e_verified: list[str] = []
e2e_tested = 0
e2e_passed = 0
if e2e_file.exists():
    try:
        e2e_data = json.loads(e2e_file.read_text(encoding="utf-8"))
        e2e_tested = int(e2e_data.get("tested", 0))
        e2e_passed = int(e2e_data.get("e2e_pass", 0))
        passed_latency = {
            canonical_key(item["uri"]): float(item.get("latency_ms") or 10**9)
            for item in e2e_data.get("results", [])
            if item.get("status") == "E2E_PASS" and item.get("uri")
        }
        e2e_verified = [
            node for node in reachable_vless
            if canonical_key(node) in passed_latency
        ]
        e2e_verified.sort(
            key=lambda node: (
                passed_latency[canonical_key(node)],
                -protocol_score(node),
                canonical_key(node),
            )
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"FAIL_CLOSED: invalid E2E results: {exc}") from exc

publish_pool = e2e_verified if e2e_file.exists() else reachable_vless
if e2e_file.exists() and not e2e_verified:
    raise RuntimeError("FAIL_CLOSED: E2E check produced zero verified VLESS nodes")

proxies = []
vless = []
for node in publish_pool:
    if len(proxies) >= PUBLISHED_KEYS:
        break
    try:
        proxy = vless_to_clash(node, len(proxies) + 1)
    except (ValueError, TypeError):
        proxy = None
    if proxy:
        proxies.append(proxy)
        vless.append(node)

if len(proxies) < MIN_PUBLISHED_KEYS:
    raise RuntimeError(
        "FAIL_CLOSED: no TCP-reachable VLESS nodes were found; "
        "refusing to publish a dead subscription"
    )

# Build a genuinely diverse top-50 pool: do not spend the whole pool on
# multiple configs pointing at the same server:port endpoint.
v2rayng_vless = []
seen_endpoints: set[str] = set()
for node in vless:
    try:
        parsed = urllib.parse.urlparse(node)
        endpoint = f"{parsed.hostname}:{parsed.port}"
    except (ValueError, TypeError):
        continue
    if not parsed.hostname or not parsed.port or endpoint in seen_endpoints:
        continue
    seen_endpoints.add(endpoint)
    v2rayng_vless.append(node)
    if len(v2rayng_vless) >= V2RAYNG_PUBLISHED_KEYS:
        break

write_lines(OUT / "GlobalPulse-VLESS.txt", vless)
write_lines(OUT / "GlobalPulse-TCP-Reachable-VLESS.txt", reachable_vless)
write_lines(OUT / "GlobalPulse-All.txt", all_top)

encoded = base64.b64encode(
    "\n".join(vless).encode("utf-8")
).decode("ascii")
v2rayng_encoded = base64.b64encode(
    "\n".join(v2rayng_vless).encode("utf-8")
).decode("ascii")

write_lines(OUT / "GlobalPulse-Base64.txt", [encoded])
write_lines(OUT / "GlobalPulse-Subscription.txt", [encoded])
write_lines(OUT / "GlobalPulse-v2rayNG.txt", [v2rayng_encoded])

write_lines(
    OUT / "GlobalPulse-v2rayNG-SETUP.txt",
    [
        "GlobalPulse v2rayNG — curated local-test pool",
        "",
        "Subscription URL:",
        "https://raw.githubusercontent.com/evgeniivolk831-ai/Vpn/main/output/GlobalPulse-v2rayNG.txt",
        "",
        f"Pool size target: {V2RAYNG_PUBLISHED_KEYS}",
        "The feed is a curated subset of the E2E-verified pool, ranked by measured latency.",
        "",
        "Recommended v2rayNG settings:",
        "1. Enable automatic subscription update.",
        "2. Enable Auto test after updating subscription.",
        "3. Enable Auto sort after testing.",
        "4. Enable Auto delete invalid config after testing only if you accept removing failed profiles.",
        "5. Create a Policy group from this subscription.",
        "6. Use Least Ping / leastPing when available.",
        "7. Enable Test outbounds.",
        "8. Configure Fallback outbound when the installed v2rayNG version exposes it.",
        "",
        "The subscription cannot encode a client-local Policy group. Local testing remains the authoritative selection layer for the phone's current network.",
    ],
)

write_lines(
    OUT / "GlobalPulse-Clash.yaml",
    ["proxies:", *emit_yaml(proxies, 2)],
)

provider_url = (
    "https://raw.githubusercontent.com/"
    "evgeniivolk831-ai/Vpn/main/output/GlobalPulse-Clash.yaml"
)

clash = f"""mixed-port: 7890
mode: rule
allow-lan: false
tcp-concurrent: true
log-level: warning

proxy-providers:
  GlobalPulse:
    type: http
    url: "{provider_url}"
    interval: 900
    path: ./providers/globalpulse.yaml
    health-check:
      enable: true
      url: {HEALTHCHECK_URL}
      interval: 180
      timeout: 5000
      lazy: false

proxy-groups:
  - name: "GlobalPulse AUTO"
    type: url-test
    use:
      - GlobalPulse
    url: {HEALTHCHECK_URL}
    interval: 180
    tolerance: 80
    lazy: false

  - name: "GlobalPulse FAILOVER"
    type: fallback
    use:
      - GlobalPulse
    url: {HEALTHCHECK_URL}
    interval: 120
    timeout: 5000
    lazy: false
    max-failed-times: 2

  - name: "PROXY"
    type: select
    proxies:
      - "GlobalPulse AUTO"
      - "GlobalPulse FAILOVER"
      - DIRECT

rules:
  - MATCH,PROXY
"""

write_lines(OUT / "GlobalPulse-Auto-Clash.yaml", clash.rstrip("\n").splitlines())
write_lines(OUT / "GlobalPulse-Subscription.yaml", clash.rstrip("\n").splitlines())

stats = {
    "name": "GlobalPulse VLESS",
    "policy": "e2e-verified-first-local-auto",
    "sources": source_stats,
    "unique_nodes": len(unique),
    "vless_nodes": len(vless),
    "candidate_vless": len(candidate_vless),
    "tcp_checked_vless": checked_vless,
    "tcp_reachable_vless": len(reachable_vless),
    "e2e_tested_vless": e2e_tested,
    "e2e_verified_vless": e2e_passed,
    "published_keys_target": PUBLISHED_KEYS,
    "v2rayng_published_keys_target": V2RAYNG_PUBLISHED_KEYS,
    "subscription": "output/GlobalPulse-Subscription.txt",
    "v2rayng_subscription": "output/GlobalPulse-v2rayNG.txt",
    "v2rayng_setup": "output/GlobalPulse-v2rayNG-SETUP.txt",
    "mihomo_subscription": "output/GlobalPulse-Subscription.yaml",
    "clash_convertible_vless": len(proxies),
    "published_all": len(all_top),
    "published_vless": len(vless),
    "published_v2rayng": len(v2rayng_vless),
    "local_auto_selection": True,
    "local_healthcheck_interval_seconds": 180,
    "failover_interval_seconds": 120,
    "note": (
        "TCP reachability is a preliminary gate. Main subscription contains only E2E-verified VLESS/Reality/TCP nodes when E2E results are present. "
        "Mihomo performs local HTTP health checks and automatic failover from the user's network. "
        "v2rayNG feed is a smaller latency-ranked subset; v2rayNG local testing remains the final client-side selection layer."
    ),
}

(OUT / "stats.json").write_text(
    json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)

print(json.dumps(stats, ensure_ascii=False, indent=2))
