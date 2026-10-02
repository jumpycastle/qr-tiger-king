#!/usr/bin/env python3
"""
qr_tiger_king.py — Integrated QR Tiger Subdomain Takeover Scanner

DEFCON / Web Predator Research

Single script that:
  1. Downloads domain lists (Tranco 1M, Majestic, Umbrella, or your own)
  2. Runs parallel DNS lookups for qr.<domain> CNAME → qr1.be
  3. HTTP-checks each hit to classify as:
       UNCLAIMED (Forbidden/404/error → claimable in QR Tiger)
       CLAIMED   (serving content → someone already owns it)

Usage:
  python3 qr_tiger_king.py                          # Tranco 1M, full scan
  python3 qr_tiger_king.py --source majestic        # Majestic Million
  python3 qr_tiger_king.py --source umbrella        # Cisco Umbrella 1M
  python3 qr_tiger_king.py --scan-only domains.txt  # Your own domain list
  python3 qr_tiger_king.py --limit 100000           # Top 100K only
  python3 qr_tiger_king.py --threads 100            # Adjust parallelism
  python3 qr_tiger_king.py --dns-only               # Skip HTTP check

Requirements: Python 3.7+, dnspython (pip install dnspython), requests
"""

import argparse
import csv
import io
import os
import re
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("Error: dnspython not installed. Run: pip install dnspython")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Error: requests not installed. Run: pip install requests")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────
# Colors
# ──────────────────────────────────────────────────────────────

class C:
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[0;36m"
    BOLD = "\033[1m"
    NC = "\033[0m"


# ──────────────────────────────────────────────────────────────
# DNS check for a single domain
# ──────────────────────────────────────────────────────────────

QR_TIGER_PATTERN = re.compile(r"qr1\.be", re.IGNORECASE)


def check_dns(domain: str) -> dict:
    """Check if qr.<domain> has a CNAME pointing to qr1.be."""
    qr_domain = f"qr.{domain}"
    result = {
        "domain": domain,
        "qr_domain": qr_domain,
        "type": None,       # "vulnerable", "has_qr", "no_record"
        "record_type": None,
        "value": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # Check CNAME first
    try:
        answers = resolver.resolve(qr_domain, "CNAME")
        cname_target = str(answers[0].target).rstrip(".")
        if QR_TIGER_PATTERN.search(cname_target):
            result["type"] = "vulnerable"
            result["record_type"] = "CNAME"
            result["value"] = cname_target
        else:
            result["type"] = "has_qr"
            result["record_type"] = "CNAME"
            result["value"] = cname_target
        return result
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.Timeout, dns.resolver.NoNameservers,
            Exception):
        pass

    # Fall back to A/AAAA
    try:
        answers = resolver.resolve(qr_domain, "A")
        result["type"] = "has_qr"
        result["record_type"] = "A"
        result["value"] = str(answers[0])
        return result
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.exception.Timeout, dns.resolver.NoNameservers,
            Exception):
        pass

    result["type"] = "no_record"
    return result


# ──────────────────────────────────────────────────────────────
# HTTP check for a single qr.* domain
# ──────────────────────────────────────────────────────────────

def check_http(domain: str, qr_domain: str, cname_target: str,
               raw_dir: Path) -> dict:
    """Curl a qr.* domain and classify as UNCLAIMED or CLAIMED."""
    result = {
        "domain": domain,
        "qr_domain": qr_domain,
        "cname_target": cname_target,
        "http_status": 0,
        "category": "UNKNOWN",
        "snippet": "",
    }

    raw_file = raw_dir / f"{domain}.txt"

    for scheme in ("https", "http"):
        url = f"{scheme}://{qr_domain}"
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (QR-Tiger-Research)"})
            result["http_status"] = resp.status_code
            body = resp.text

            # Save raw response
            raw_file.write_text(body[:5000], encoding="utf-8")

            trimmed = body.strip()
            snippet = body[:200].replace("\n", " ").replace("\r", " ").replace(",", " ")
            result["snippet"] = snippet

            # Exact "Forbidden" body — QR Tiger's signature unclaimed response
            if trimmed == "Forbidden":
                result["category"] = "UNCLAIMED"
                return result

            status = resp.status_code

            if status == 403:
                result["category"] = "UNCLAIMED"
            elif status == 404:
                result["category"] = "UNCLAIMED"
            elif 300 <= status < 400:
                result["category"] = "CLAIMED"
            elif 200 <= status < 300:
                error_patterns = re.compile(
                    r"forbidden|not found|error|does not exist|no site|page not found",
                    re.IGNORECASE
                )
                if error_patterns.search(snippet):
                    result["category"] = "UNCLAIMED"
                else:
                    result["category"] = "CLAIMED"
            else:
                result["category"] = "UNKNOWN"

            return result

        except requests.exceptions.RequestException:
            if scheme == "http":
                # Both failed
                result["http_status"] = 0
                result["category"] = "UNCLAIMED"
                return result
            continue

    return result


# ──────────────────────────────────────────────────────────────
# Download domain lists
# ──────────────────────────────────────────────────────────────

def download_domains(source: str, work_dir: Path) -> list[str]:
    """Download and parse a domain list from a public source."""

    if source == "tranco":
        print(f"  Source: Tranco Top 1M (research-grade, aggregated list)")
        url = "https://tranco-list.eu/top-1m.csv.zip"
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
            data = zf.read(csv_name).decode("utf-8", errors="replace")
        domains = []
        for line in data.splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domains.append(parts[1].strip())

    elif source == "majestic":
        print(f"  Source: Majestic Million (backlink-based, daily updated)")
        url = "https://downloads.majestic.com/majestic_million.csv"
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        domains = []
        for i, line in enumerate(resp.text.splitlines()):
            if i == 0:
                continue  # skip header
            parts = line.strip().split(",")
            if len(parts) >= 3:
                domains.append(parts[2].strip())

    elif source == "umbrella":
        print(f"  Source: Cisco Umbrella Top 1M (DNS query-based)")
        url = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
            data = zf.read(csv_name).decode("utf-8", errors="replace")
        domains = []
        for line in data.splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 2:
                domains.append(parts[1].strip())

    else:
        print(f"Unknown source: {source}")
        sys.exit(1)

    # Deduplicate and clean
    seen = set()
    clean = []
    for d in domains:
        d = d.strip().rstrip(".")
        if d and d not in seen:
            seen.add(d)
            clean.append(d)

    return clean


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="QR Tiger King — Integrated Subdomain Takeover Scanner"
    )
    parser.add_argument("--source", default="tranco",
                        choices=["tranco", "majestic", "umbrella"],
                        help="Domain list source (default: tranco)")
    parser.add_argument("--scan-only", dest="scan_file", metavar="FILE",
                        help="Scan your own domain list file")
    parser.add_argument("--limit", type=int, default=0,
                        help="Only scan top N domains (default: all)")
    parser.add_argument("--threads", type=int, default=50,
                        help="Parallel workers (default: 50)")
    parser.add_argument("--dns-only", action="store_true",
                        help="Skip HTTP verification")
    args = parser.parse_args()

    # ── Banner ──
    print(f"\n{C.BOLD}{C.CYAN}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║          QR Tiger King — Integrated Takeover Scanner         ║")
    print("║          DNS Scan + HTTP Verification in One Pass            ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"{C.NC}")
    print(f"  Threads: {C.BOLD}{args.threads}{C.NC}")
    mode_label = "DNS only" if args.dns_only else "DNS + HTTP"
    print(f"  Mode:    {C.BOLD}{mode_label}{C.NC}\n")

    # ── Setup output dir ──
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    work_dir = Path(f"./qr_king_{timestamp}")
    work_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Get domains ──
    if args.scan_file:
        print(f"{C.BOLD}[Step 1/3] Loading domain list: {args.scan_file}{C.NC}")
        domains = [
            line.strip() for line in Path(args.scan_file).read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        # Deduplicate
        seen = set()
        clean = []
        for d in domains:
            d = re.sub(r"^https?://", "", d)
            d = re.sub(r"/.*", "", d)
            d = re.sub(r"^www\.", "", d)
            if d and d not in seen:
                seen.add(d)
                clean.append(d)
        domains = clean
    else:
        print(f"{C.BOLD}[Step 1/3] Downloading domain list: {args.source}...{C.NC}")
        domains = download_domains(args.source, work_dir)

    print(f"  {C.GREEN}Loaded {len(domains)} unique domains{C.NC}")

    if args.limit > 0 and args.limit < len(domains):
        domains = domains[:args.limit]
        print(f"  {C.YELLOW}Limited to top {args.limit}{C.NC}")

    total = len(domains)
    print(f"  Domains to scan: {C.BOLD}{total}{C.NC}")

    est_sec = total // max(args.threads, 1)
    est_min = est_sec // 60
    if est_min >= 60:
        print(f"  Estimated time: {C.BOLD}~{est_min // 60}h {est_min % 60}m{C.NC}")
    else:
        print(f"  Estimated time: {C.BOLD}~{est_min}m{C.NC}")

    # Save domain list
    (work_dir / "domains.txt").write_text("\n".join(domains) + "\n")

    # ── Step 2: Parallel DNS scan ──
    print(f"\n{C.BOLD}[Step 2/3] Scanning qr.<domain> for QR Tiger CNAMEs...{C.NC}\n")

    vulnerable = []   # CNAME → qr1.be
    has_qr = []       # qr.* resolves to something else
    no_record = []    # no DNS record

    progress_lock = Lock()
    scanned = [0]
    start_time = time.time()

    def dns_worker(domain):
        result = check_dns(domain)
        with progress_lock:
            scanned[0] += 1
            count = scanned[0]
            if count % 500 == 0:
                pct = count * 100 // total
                print(
                    f"  {C.CYAN}[{count}/{total}] {pct}%  |  "
                    f"CNAME hits: {len(vulnerable)}  |  "
                    f"qr.* exists: {len(has_qr)}{C.NC}",
                    file=sys.stderr
                )
        return result

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(dns_worker, d): d for d in domains}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result["type"] == "vulnerable":
                    vulnerable.append(result)
                    print(
                        f"  {C.RED}⚠  CNAME HIT: {result['qr_domain']}  →  "
                        f"{result['value']}{C.NC}"
                    )
                elif result["type"] == "has_qr":
                    has_qr.append(result)
                else:
                    no_record.append(result)
            except Exception as e:
                pass  # DNS errors are non-fatal

    dns_elapsed = time.time() - start_time

    print(f"\n{C.BOLD}{C.CYAN}── DNS Scan Complete ──{C.NC}")
    print(f"  Domains scanned:    {C.BOLD}{scanned[0]}{C.NC}")
    print(f"  Time:               {C.BOLD}{int(dns_elapsed // 60)}m {int(dns_elapsed % 60)}s{C.NC}")
    print(f"  {C.RED}CNAME → qr1.be:     {C.BOLD}{len(vulnerable)}{C.NC}")
    print(f"  {C.YELLOW}qr.* exists (other): {C.BOLD}{len(has_qr)}{C.NC}")
    print(f"  No qr.* record:     {C.BOLD}{len(no_record)}{C.NC}\n")

    # Write DNS results
    with open(work_dir / "vulnerable_dns.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "qr_subdomain", "cname_target"])
        for v in vulnerable:
            w.writerow([v["domain"], v["qr_domain"], v["value"]])

    with open(work_dir / "has_qr_subdomain.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["domain", "qr_subdomain", "record_type", "value"])
        for h in has_qr:
            w.writerow([h["domain"], h["qr_domain"], h["record_type"], h["value"]])

    (work_dir / "no_record.txt").write_text(
        "\n".join(r["domain"] for r in no_record) + "\n"
    )

    # ── Step 3: HTTP verification ──
    unclaimed = []
    claimed = []

    if args.dns_only:
        print(f"{C.YELLOW}Skipping HTTP check (--dns-only).{C.NC}")
    elif not vulnerable:
        print(f"{C.GREEN}No CNAME hits to HTTP-check. Done.{C.NC}")
    else:
        print(f"{C.BOLD}[Step 3/3] HTTP-checking {len(vulnerable)} CNAME hits...{C.NC}\n")

        raw_dir = work_dir / "raw_responses"
        raw_dir.mkdir(exist_ok=True)

        for i, v in enumerate(vulnerable, 1):
            domain = v["domain"]
            qr_domain = v["qr_domain"]
            cname = v["value"]

            print(f"  {C.CYAN}[{i}/{len(vulnerable)}]{C.NC} {qr_domain:<50}", end="")

            http_result = check_http(domain, qr_domain, cname, raw_dir)

            cat = http_result["category"]
            status = http_result["http_status"]

            if cat == "UNCLAIMED":
                unclaimed.append(http_result)
                reason = "Forbidden body" if status == 200 else \
                         f"{status} Forbidden" if status == 403 else \
                         f"{status} Not Found" if status == 404 else \
                         "connection failed" if status == 0 else \
                         f"{status} error content"
                print(f" {C.GREEN}→ UNCLAIMED ({reason}){C.NC}")
            elif cat == "CLAIMED":
                claimed.append(http_result)
                kind = "redirect" if 300 <= status < 400 else "serving content"
                print(f" {C.RED}→ CLAIMED ({status} {kind}){C.NC}")
            else:
                print(f" {C.YELLOW}→ UNKNOWN (HTTP {status}){C.NC}")

            time.sleep(0.2)

        # Write HTTP results
        with open(work_dir / "unclaimed.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["domain", "qr_subdomain", "cname_target", "http_status"])
            for u in unclaimed:
                w.writerow([u["domain"], u["qr_domain"], u["cname_target"], u["http_status"]])

        with open(work_dir / "claimed.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["domain", "qr_subdomain", "cname_target", "http_status", "snippet"])
            for c in claimed:
                w.writerow([c["domain"], c["qr_domain"], c["cname_target"],
                            c["http_status"], c["snippet"][:200]])

        with open(work_dir / "full_results.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["domain", "qr_subdomain", "cname_target", "http_status",
                         "category", "snippet"])
            for r in unclaimed + claimed:
                w.writerow([r["domain"], r["qr_domain"], r["cname_target"],
                            r["http_status"], r["category"], r["snippet"][:200]])

    # ── Summary ──
    total_elapsed = time.time() - start_time

    print(f"\n{C.BOLD}{C.CYAN}═══════════════════════════════════════════════════════{C.NC}")
    print(f"{C.BOLD}                    SCAN COMPLETE                       {C.NC}")
    print(f"{C.BOLD}{C.CYAN}═══════════════════════════════════════════════════════{C.NC}\n")

    source_label = args.scan_file if args.scan_file else args.source
    print(f"  Source:                {C.BOLD}{source_label}{C.NC}")
    print(f"  Domains scanned:       {C.BOLD}{scanned[0]}{C.NC}")
    print(f"  Total time:            {C.BOLD}{int(total_elapsed // 60)}m {int(total_elapsed % 60)}s{C.NC}")
    print(f"  Threads:               {C.BOLD}{args.threads}{C.NC}\n")

    print(f"{C.BOLD}  DNS Results:{C.NC}")
    print(f"    {C.RED}CNAME → qr1.be:    {C.BOLD}{len(vulnerable)}{C.NC}")
    print(f"    {C.YELLOW}qr.* other:        {C.BOLD}{len(has_qr)}{C.NC}")
    print(f"    No qr.* record:    {C.BOLD}{len(no_record)}{C.NC}\n")

    if not args.dns_only and vulnerable:
        print(f"{C.BOLD}  HTTP Results (of {len(vulnerable)} CNAME hits):{C.NC}")
        print(f"    {C.GREEN}UNCLAIMED (claimable): {C.BOLD}{len(unclaimed)}{C.NC}")
        print(f"    {C.RED}CLAIMED (taken):       {C.BOLD}{len(claimed)}{C.NC}\n")

        if unclaimed:
            print(f"{C.GREEN}{C.BOLD}╔══════════════════════════════════════════════════════╗{C.NC}")
            print(f"{C.GREEN}{C.BOLD}║  ✅  {len(unclaimed)} UNCLAIMED DOMAIN(S) — READY FOR POC          ║{C.NC}")
            print(f"{C.GREEN}{C.BOLD}╚══════════════════════════════════════════════════════╝{C.NC}\n")
            for u in unclaimed:
                print(f"  {C.GREEN}→ {u['qr_domain']}{C.NC}  CNAME → {u['cname_target']}  (HTTP {u['http_status']})")
            print()

        if claimed:
            print(f"{C.RED}{C.BOLD}Claimed domains (already serving content):{C.NC}")
            for c in claimed:
                print(f"  {C.RED}→ {c['qr_domain']}{C.NC}  (HTTP {c['http_status']})")
            print()

    elif vulnerable:
        print(f"{C.RED}{C.BOLD}╔══════════════════════════════════════════════════════╗{C.NC}")
        print(f"{C.RED}{C.BOLD}║  ⚠  {len(vulnerable)} POTENTIAL SUBDOMAIN TAKEOVER(S)!              ║{C.NC}")
        print(f"{C.RED}{C.BOLD}╚══════════════════════════════════════════════════════╝{C.NC}\n")
        for v in vulnerable:
            print(f"  {C.RED}→ {v['qr_domain']}{C.NC}  CNAME → {v['value']}")
        print()

    print(f"{C.BOLD}Output files in: {work_dir}/{C.NC}")
    print(f"  vulnerable_dns.csv      — All CNAME → qr1.be hits")
    if not args.dns_only and vulnerable:
        print(f"  unclaimed.csv           — Forbidden/error (claimable)")
        print(f"  claimed.csv             — Already serving content")
        print(f"  full_results.csv        — All HTTP results with category")
        print(f"  raw_responses/          — Full HTTP response per domain")
    print(f"  has_qr_subdomain.csv    — qr.* resolves but not to qr1.be")
    print(f"  no_record.txt           — No qr.* DNS record")
    print(f"  domains.txt             — Domain list used\n")

    print(f"{C.BOLD}Next steps for responsible disclosure:{C.NC}")
    print(f"  1. Verify each finding manually (dig, browser, curl)")
    print(f"  2. Identify the domain owner (whois, security.txt)")
    print(f"  3. Send disclosure with evidence\n")
    print(f"{C.CYAN}Good luck with Web Predator @ DEFCON!{C.NC}\n")


if __name__ == "__main__":
    main()
