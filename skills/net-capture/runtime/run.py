#!/usr/bin/env python3
"""net-capture — capture a target's network traffic to a pcap while it runs. DYNAMIC.

Starts tcpdump, runs the target for a bounded duration, stops the capture, and
summarizes: packet count, talking-to IPs, and DNS queries. Writes the pcap for deeper
analysis. Optionally point --iface at a sinkholed interface for safe detonation.

⚠️ EXECUTES the target and captures on a network interface (usually needs root). rekit
gates this behind --allow-dynamic; run it only where you don't mind the risk.

    python3 run.py <target> [--iface IFACE] [--duration SEC] [--format text|json] [--yes-i-consent]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time


def _consented(a) -> bool:
    return a.yes_i_consent or os.environ.get("REKIT_ALLOW_DYNAMIC") == "1"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="net-capture")
    p.add_argument("target")
    p.add_argument("--iface", default="en0" if sys.platform == "darwin" else "any")
    p.add_argument("--duration", type=int, default=15)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--yes-i-consent", action="store_true")
    a = p.parse_args(argv[1:])
    if not _consented(a):
        print(json.dumps({"ok": False, "error": "net-capture EXECUTES the target",
                          "hint": "run via `rekit run --allow-dynamic net-capture …`"}))
        return 4
    if not os.path.isfile(a.target):
        print(json.dumps({"ok": False, "error": f"target not found: {a.target}"}))
        return 2
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        print(json.dumps({"ok": False, "error": "tcpdump not on PATH",
                          "hint": "install tcpdump (capturing usually needs root)"}))
        return 3

    target = os.path.abspath(a.target)
    pcap = os.path.join(tempfile.mkdtemp(prefix="net_capture_"), "capture.pcap")
    cap = None
    try:
        cap = subprocess.Popen([tcpdump, "-i", a.iface, "-w", pcap, "-U"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        time.sleep(0.6)  # let the capture come up
        if cap.poll() is not None:  # tcpdump died immediately (usually permissions)
            err = (cap.stderr.read() or b"").decode("utf-8", "replace")[:300]
            print(json.dumps({"ok": False, "error": "tcpdump could not start",
                              "detail": err, "hint": "capturing needs root (sudo) / capture perms"}))
            return 1
        try:
            subprocess.run([target], timeout=a.duration, capture_output=True)
        except subprocess.TimeoutExpired:
            pass
        except OSError as exc:
            print(json.dumps({"ok": False, "error": f"could not execute target: {exc}"}))
            return 1
        time.sleep(0.4)
    finally:
        if cap and cap.poll() is None:
            cap.terminate()
            try:
                cap.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cap.kill()

    # summarize the pcap with tcpdump -r
    ips: dict = {}
    dns: list = []
    packets = 0
    rd = subprocess.run([tcpdump, "-nn", "-r", pcap], capture_output=True, text=True)
    for line in (rd.stdout or "").splitlines():
        packets += 1
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            ips[ip] = ips.get(ip, 0) + 1
        if ".53:" in line or " domain" in line:
            dns.append(line.strip()[:160])

    res = {"ok": True, "tool": "tcpdump", "target": target, "iface": a.iface,
           "pcap": pcap, "packets": packets,
           "talkers": dict(sorted(ips.items(), key=lambda x: -x[1])[:30]),
           "dns": dns[:30]}
    if a.format == "json":
        print(json.dumps(res))
        return 0
    print(f"net-capture: {os.path.basename(target)}  iface={a.iface}  {packets} packet(s)")
    if res["talkers"]:
        print("  talkers: " + ", ".join(f"{ip}({n})" for ip, n in list(res["talkers"].items())[:12]))
    if dns:
        print(f"  dns: {len(dns)} query line(s)")
    print(f"  pcap: {pcap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
