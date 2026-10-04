#!/usr/bin/env python3
# scripts/e2e_vless_check.py
import argparse
import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)
ATTEMPTS = 3
TIMEOUT_SECONDS = 8
WORKERS = 8
BASE_PORT = 21000


def parse_vless(uri: str) -> dict | None:
    try:
        p = urllib.parse.urlparse(uri.strip())
        if p.scheme.lower() != "vless" or not p.hostname or not p.port or not p.username:
            return None
        q = urllib.parse.parse_qs(p.query)
        get = lambda k: urllib.parse.unquote(q[k][0]) if q.get(k) else None
        security = (get("security") or "none").lower()
        network = (get("type") or "tcp").lower()
        if security != "reality" or network != "tcp" or not get("pbk") or not get("sni"):
            return None
        return {
            "address": p.hostname,
            "port": p.port,
            "uuid": urllib.parse.unquote(p.username),
            "flow": get("flow"),
            "serverName": get("sni"),
            "fingerprint": get("fp") or "chrome",
            "publicKey": get("pbk"),
            "shortId": get("sid") or "",
        }
    except (ValueError, TypeError):
        return None


def check_one(xray: str, uri: str, port: int) -> dict:
    parsed = parse_vless(uri)
    started = time.monotonic()
    result = {
        "uri": uri,
        "status": "UNSUPPORTED",
        "latency_ms": None,
        "median_latency_ms": None,
        "p95_latency_ms": None,
        "success_rate": 0.0,
        "attempts": 0,
        "passed_attempts": 0,
        "error": None,
    }
    if not parsed:
        return result

    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed["address"],
                    "port": parsed["port"],
                    "users": [{
                        "id": parsed["uuid"],
                        "encryption": "none",
                        **({"flow": parsed["flow"]} if parsed["flow"] else {}),
                    }],
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": parsed["serverName"],
                    "fingerprint": parsed["fingerprint"],
                    "publicKey": parsed["publicKey"],
                    "shortId": parsed["shortId"],
                },
            },
        }],
    }

    with tempfile.TemporaryDirectory(prefix="gp-e2e-") as td:
        cfg = Path(td) / "config.json"
        cfg.write_text(json.dumps(config), encoding="utf-8")
        proc = None
        try:
            proc = subprocess.Popen(
                [xray, "run", "-c", str(cfg)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    err = (proc.stderr.read() if proc.stderr else "")[-500:]
                    result["status"] = "XRAY_START_FAILED"
                    result["error"] = err.strip()
                    return result
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                result["status"] = "SOCKS_LISTENER_FAILED"
                return result

            samples = []
            errors = []
            passed = 0
            total = 0
            for target in TEST_URLS:
                for _ in range(ATTEMPTS):
                    total += 1
                    try:
                        started_probe = time.monotonic()
                        curl = subprocess.run(
                            [
                                "curl", "-fsS", "--max-time", str(TIMEOUT_SECONDS),
                                "--socks5-hostname", f"127.0.0.1:{port}",
                                "-o", "/dev/null", "-w", "%{http_code}", target,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=TIMEOUT_SECONDS + 2,
                        )
                        elapsed = round((time.monotonic() - started_probe) * 1000, 1)
                        if curl.returncode == 0 and curl.stdout.strip() in {"204", "200"}:
                            passed += 1
                            samples.append(elapsed)
                        else:
                            errors.append((curl.stderr or curl.stdout)[-240:].strip())
                    except subprocess.TimeoutExpired as exc:
                        errors.append(str(exc))
            result["attempts"] = total
            result["passed_attempts"] = passed
            result["success_rate"] = round(passed / total, 3) if total else 0.0
            if samples:
                ordered = sorted(samples)
                result["latency_ms"] = round(sum(samples) / len(samples), 1)
                mid = len(ordered) // 2
                result["median_latency_ms"] = round(
                    ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2, 1
                )
                p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
                result["p95_latency_ms"] = round(ordered[p95_index], 1)
            if passed == total and total > 0:
                result["status"] = "E2E_PASS"
            else:
                result["status"] = "E2E_FAIL"
                result["error"] = "; ".join(x for x in errors if x)[:500]
            return result
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["status"] = "E2E_FAIL"
            result["error"] = str(exc)
            return result
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--xray", required=True)
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    nodes = [x.strip() for x in Path(args.input).read_text(encoding="utf-8").splitlines() if x.strip()]
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(check_one, args.xray, node, BASE_PORT + i): node
            for i, node in enumerate(nodes)
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(
        key=lambda x: (
            x["status"] != "E2E_PASS",
            -(x.get("success_rate") or 0.0),
            x.get("median_latency_ms") or 10**9,
            x["uri"],
        )
    )
    summary = {
        "engine": "xray-core",
        "test_urls": list(TEST_URLS),
        "attempts_per_target": ATTEMPTS,
        "tested": len(results),
        "e2e_pass": sum(r["status"] == "E2E_PASS" for r in results),
        "e2e_fail": sum(r["status"] == "E2E_FAIL" for r in results),
        "unsupported": sum(r["status"] == "UNSUPPORTED" for r in results),
        "results": results,
    }
    Path(args.output).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in summary if k != "results"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
