#!/usr/bin/env python3
"""
Wayback Ripper — Full tool (interactive + CLI)

Features included:
- Smart normalization / soft dedupe
- Wayback CDX fetching, filtering, time range
- Hidden/normalized URLs output
- JS extraction (list .js) + endpoint extraction + JS Secret Finder
- Parameter discovery (unique param names)
- Directory tree view
- Keyword/regex search
- Sitemap/XML parser (live + archived)
- Archive comparison (URLs) + Content Diff Mode (compare snapshots by content hash)
- Cloud buckets finder (S3 / GCS / Azure)
- Async super-speed mode for validation/extraction (aiohttp required)
- Alive check + basic fingerprinting
- Automatic fuzz hook (arjun / ffuf) integration (if installed)
- Wayback monitor (store last results and show new URLs)
- Output save options (txt/json/csv)
- Interactive menu loop
- CLI mode for piping (prints plain URLs)
"""

import argparse
import asyncio
import concurrent.futures
import csv
import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import pyfiglet
import requests
from colorama import Fore, Style, init
from tqdm import tqdm

# optional libs
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None

try:
    import aiohttp
except Exception:
    aiohttp = None

init(autoreset=True)

# -------------------------
# Helpers / Banner
# -------------------------
TOOL_NAME = "Wayback Ripper"
VERSION = "1.0"

def banner(silent=False):
    if silent:
        return
    ascii_banner = pyfiglet.figlet_format(TOOL_NAME, width=120)
    print(Fore.CYAN + ascii_banner + Style.RESET_ALL)
    print(Fore.YELLOW + f"🦅 {TOOL_NAME} v{VERSION} — Wayback recon toolbox\n" + Style.RESET_ALL)

def info(msg):
    print(Fore.CYAN + msg + Style.RESET_ALL)

def warn(msg):
    print(Fore.YELLOW + msg + Style.RESET_ALL)

def err(msg):
    print(Fore.RED + msg + Style.RESET_ALL)

# -------------------------
# Smart normalization (soft dedupe)
# -------------------------
def normalize_url(url: str) -> str:
    """
    Normalize URL for soft dedupe:
    - lowercase scheme/host
    - remove default ports
    - add trailing slash for directory-like paths
    - sort query params
    """
    try:
        p = urlparse(url)
        scheme = (p.scheme or "http").lower()
        host = (p.hostname or "").lower()
        netloc = host
        if p.port and not ((scheme == "http" and p.port == 80) or (scheme == "https" and p.port == 443)):
            netloc = f"{host}:{p.port}"

        path = p.path or "/"
        # if last segment has no dot, treat as folder and add trailing slash
        last = path.split("/")[-1]
        if last and "." not in last and not path.endswith("/"):
            path = path + "/"

        qs = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))
        normalized = urlunparse((scheme, netloc, path, "", qs, ""))
        return normalized
    except Exception:
        return url

# -------------------------
# Wayback CDX fetching (sync)
# -------------------------
def fetch_wayback_urls(domain, filters=None, from_year=None, to_year=None, collapse="urlkey"):
    """
    Fetch original URLs from Wayback CDX for domain/*.
    returns normalized unique list.
    filters: list of extensions (e.g. ['.js','.php'])
    """
    cdx = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": collapse
    }
    if from_year:
        params["from"] = str(from_year)
    if to_year:
        params["to"] = str(to_year)

    try:
        r = requests.get(cdx, params=params, timeout=60)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        err(f"Failed CDX request: {e}")
        return []

    if not data or len(data) < 2:
        return []

    raw_urls = [row[0] for row in data[1:] if row]
    normalized = [normalize_url(u) for u in raw_urls]
    unique = sorted(set(normalized))

    if filters:
        fl = [f.lower() for f in filters]
        unique = [u for u in unique if any(u.lower().endswith(e) for e in fl)]
    return unique

# -------------------------
# Wayback snapshot timestamps map
# -------------------------
def fetch_wayback_snapshots(domain, from_year=None, to_year=None):
    """
    Return dict: normalized_url -> latest_timestamp_in_range
    """
    cdx = "http://web.archive.org/cdx/search/cdx"
    params = {
        "url": f"{domain}/*",
        "output": "json",
        "fl": "original,timestamp",
        "collapse": "timestamp"
    }
    if from_year:
        params["from"] = str(from_year)
    if to_year:
        params["to"] = str(to_year)

    try:
        r = requests.get(cdx, params=params, timeout=60)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        err(f"Failed snapshots CDX: {e}")
        return {}

    snap_map = {}
    for row in data[1:]:
        if len(row) >= 2:
            orig, ts = row[0], row[1]
            n = normalize_url(orig)
            # choose latest timestamp (string compare ok)
            if n not in snap_map or ts > snap_map[n]:
                snap_map[n] = ts
    return snap_map

def fetch_wayback_content(original_url, timestamp):
    """
    Fetch archived snapshot content.
    """
    snapshot = f"https://web.archive.org/web/{timestamp}/{original_url}"
    try:
        r = requests.get(snapshot, timeout=20)
        r.raise_for_status()
        return r.text
    except Exception:
        return None

# -------------------------
# JS extractor + endpoint extraction + secret finder
# -------------------------
JS_SECRET_PATTERNS = {
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "JWT-like": re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Bearer Token": re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]+"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    # crude GCP service account JSON indicator
    "GCP Service JSON": re.compile(r"\"type\"\s*:\s*\"service_account\"", re.I),
}

def extract_endpoints_from_text(text):
    # return endpoints that start with / and have typical characters
    found = re.findall(r"(?<![A-Za-z0-9_])\/[a-zA-Z0-9_\-\/\.\?\=\&%:+]+", text)
    return found

def extract_js_and_secrets(domain, from_year=None, to_year=None, secrets=False, async_mode=False, concurrency=200):
    """
    Returns (js_files, endpoints, secrets_found)
    - If async_mode and aiohttp available, uses async fetch for JS files
    - Else fallback to sync
    """
    js_files = fetch_wayback_urls(domain, filters=[".js"], from_year=from_year, to_year=to_year)
    endpoints = []
    secrets_found = []

    if not js_files:
        return [], [], []

    if async_mode and aiohttp:
        # async fetch
        async def _aio_worker_batch(urls_batch):
            sem = asyncio.Semaphore(concurrency)
            async with aiohttp.ClientSession() as session:
                async def _worker(u):
                    async with sem:
                        try:
                            async with session.get(u, timeout=15) as r:
                                if r.status == 200:
                                    text = await r.text()
                                    return u, text
                        except Exception:
                            return u, None
                        return u, None
                tasks = [asyncio.create_task(_worker(u)) for u in urls_batch]
                results = []
                for fut in asyncio.as_completed(tasks):
                    res = await fut
                    results.append(res)
                return results

        # chunk to avoid too many tasks at once
        loop = asyncio.get_event_loop()
        batch_size = 500
        all_results = []
        for i in range(0, len(js_files), batch_size):
            batch = js_files[i:i+batch_size]
            all_results.extend(loop.run_until_complete(_aio_worker_batch(batch)))

        for u, text in all_results:
            if text:
                eps = extract_endpoints_from_text(text)
                endpoints.extend(eps)
                if secrets:
                    for name, rx in JS_SECRET_PATTERNS.items():
                        for m in rx.findall(text):
                            val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m))
                            secrets_found.append(f"{name} in {u}: {val}")
    else:
        # sync fetch
        for u in tqdm(js_files, desc="Scraping JS"):
            try:
                r = requests.get(u, timeout=12)
                if r.status_code == 200 and r.text:
                    text = r.text
                    eps = extract_endpoints_from_text(text)
                    endpoints.extend(eps)
                    if secrets:
                        for name, rx in JS_SECRET_PATTERNS.items():
                            for m in rx.findall(text):
                                val = m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m))
                                secrets_found.append(f"{name} in {u}: {val}")
            except Exception:
                continue

    endpoints = sorted(set(endpoints))
    secrets_found = sorted(set(secrets_found))
    return js_files, endpoints, secrets_found

# -------------------------
# Parameter discovery
# -------------------------
def extract_parameters(urls):
    params = set()
    for u in urls:
        try:
            for k, _ in parse_qsl(urlparse(u).query):
                if k:
                    params.add(k)
        except Exception:
            continue
    return sorted(params)

# -------------------------
# Directory tree view
# -------------------------
def build_directory_tree(urls):
    tree = defaultdict(list)
    for u in urls:
        p = urlparse(u).path
        parts = [x for x in p.strip("/").split("/") if x]
        if not parts:
            tree["/"].append("/")
            continue
        if len(parts) == 1:
            tree["/"].append(parts[0])
        else:
            dirpath = "/" + "/".join(parts[:-1]) + "/"
            tree[dirpath].append(parts[-1])
    return tree

# -------------------------
# Sitemap & XML parser (live + archived)
# -------------------------
def _fetch_text(url, timeout=12):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        content = r.content
        # handle gz
        if url.lower().endswith(".gz") or r.headers.get("Content-Encoding","").lower().find("gzip") != -1:
            try:
                content = gzip.decompress(content)
            except Exception:
                pass
        return content.decode("utf-8", errors="ignore")
    except Exception:
        return None

def parse_sitemaps(domain, from_year=None, to_year=None):
    found_urls = set()
    # try live sitemaps
    for scheme in ("https", "http"):
        for path in ("/sitemap.xml","/sitemap_index.xml"):
            url = f"{scheme}://{domain}{path}"
            text = _fetch_text(url, timeout=8)
            if text:
                locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, flags=re.I)
                found_urls.update(locs)
    # archived sitemaps via CDX
    cdx = "http://web.archive.org/cdx/search/cdx"
    suffixes = ("sitemap.xml","sitemap_index.xml","sitemap.xml.gz","sitemap_index.xml.gz")
    for suffix in suffixes:
        params = {"url": f"{domain}/{suffix}", "output":"json", "fl":"original", "collapse":"timestamp"}
        if from_year: params["from"] = str(from_year)
        if to_year: params["to"] = str(to_year)
        try:
            r = requests.get(cdx, params=params, timeout=20)
            r.raise_for_status()
            data = r.json()
            archive_urls = [row[0] for row in data[1:]] if len(data) > 1 else []
            for au in tqdm(archive_urls, desc=f"parsing {suffix}", leave=False):
                text = _fetch_text(au, timeout=12)
                if text:
                    locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", text, flags=re.I)
                    found_urls.update(locs)
        except Exception:
            continue
    # normalize found urls
    results = sorted(set(normalize_url(u) for u in found_urls if u.startswith("http")))
    return results

# -------------------------
# Archive comparison (URLs only)
# -------------------------
def archive_compare(domain):
    info("First time range (older)")
    s1 = input(" Start year (e.g. 2010): ").strip() or None
    e1 = input(" End year   (e.g. 2015): ").strip() or None
    info("Second time range (newer)")
    s2 = input(" Start year (e.g. 2016): ").strip() or None
    e2 = input(" End year   (e.g. 2020): ").strip() or None

    info("Fetching range1...")
    u1 = fetch_wayback_urls(domain, from_year=s1, to_year=e1)
    info("Fetching range2...")
    u2 = fetch_wayback_urls(domain, from_year=s2, to_year=e2)
    added = sorted(set(u2) - set(u1))
    removed = sorted(set(u1) - set(u2))
    print(Fore.GREEN + f"\nAdded in second range: {len(added)}" + Style.RESET_ALL)
    for a in added: print("+", a)
    if removed:
        print(Fore.YELLOW + f"\nRemoved in second range: {len(removed)}" + Style.RESET_ALL)
        for r in removed: print("-", r)
    if added and input("Save added URLs? (y/n): ").lower().startswith("y"):
        save_results(added, f"{domain}_archive_added_{s2}_{e2}")

# -------------------------
# Content Diff Mode
# -------------------------
def content_diff(domain):
    info("Content Diff Mode compares page contents between ranges.")
    s1 = input(" First start year: ").strip() or None
    e1 = input(" First end year: ").strip() or None
    s2 = input(" Second start year: ").strip() or None
    e2 = input(" Second end year: ").strip() or None
    info("Fetching snapshots for both ranges...")
    map1 = fetch_wayback_snapshots(domain, from_year=s1, to_year=e1)
    map2 = fetch_wayback_snapshots(domain, from_year=s2, to_year=e2)
    all_urls = sorted(set(map1.keys()) | set(map2.keys()))
    changed = []
    only1 = []
    only2 = []
    for u in tqdm(all_urls, desc="Comparing"):
        ts1 = map1.get(u)
        ts2 = map2.get(u)
        if ts1 and ts2:
            c1 = fetch_wayback_content(u, ts1) or ""
            c2 = fetch_wayback_content(u, ts2) or ""
            h1 = hashlib.sha256(c1.encode("utf-8", errors="ignore")).hexdigest()
            h2 = hashlib.sha256(c2.encode("utf-8", errors="ignore")).hexdigest()
            if h1 != h2:
                changed.append((u, ts1, ts2))
        elif ts1 and not ts2:
            only1.append((u, ts1))
        elif ts2 and not ts1:
            only2.append((u, ts2))
    print(Fore.CYAN + f"\nChanged pages: {len(changed)}" + Style.RESET_ALL)
    for u,a,b in changed:
        print("~", u, f"{a} -> {b}")
    if only2:
        print(Fore.GREEN + f"\nNew in second range: {len(only2)}" + Style.RESET_ALL)
        for u,ts in only2: print("+", u)
    if only1:
        print(Fore.YELLOW + f"\nOnly in first range: {len(only1)}" + Style.RESET_ALL)
        for u,ts in only1: print("-", u)
    if (changed or only2 or only1) and input("Save diff results? (y/n): ").lower().startswith("y"):
        rows = []
        for u,a,b in changed: rows.append([u,"changed",a,b])
        for u,ts in only2: rows.append([u,"new_second","",ts])
        for u,ts in only1: rows.append([u,"only_first",ts,""])
        save_results(rows, f"{domain}_content_diff")

# -------------------------
# Cloud buckets finder
# -------------------------
CLOUD_RX = {
    "S3_domain": re.compile(r"(?:https?://)?([a-z0-9\.\-]+)\.s3(?:-website)?(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.I),
    "S3_path": re.compile(r"s3\.amazonaws\.com/([a-z0-9\.\-_]+)", re.I),
    "s3_uri": re.compile(r"s3://([a-z0-9\.\-_]+)", re.I),
    "GCS": re.compile(r"(?:https?://)?storage.googleapis.com/([a-z0-9\.\-_]+)|gs://([a-z0-9\.\-_]+)", re.I),
    "Azure_blob": re.compile(r"(?:https?://)?([a-z0-9\-]+)\.blob\.core\.windows\.net/([a-z0-9\-\_]+)", re.I),
}

def find_cloud_buckets_in_urls_and_text(urls, sample_texts=None):
    findings = defaultdict(set)
    for u in urls:
        for name, rx in CLOUD_RX.items():
            for m in rx.finditer(u):
                groups = [g for g in m.groups() if g]
                if groups:
                    findings[name].add("/".join(groups))
                else:
                    findings[name].add(m.group(0))
    if sample_texts:
        for t in sample_texts:
            for name, rx in CLOUD_RX.items():
                for m in rx.finditer(t):
                    groups = [g for g in m.groups() if g]
                    if groups:
                        findings[name].add("/".join(groups))
                    else:
                        findings[name].add(m.group(0))
    return {k: sorted(v) for k, v in findings.items()}

# -------------------------
# Auto fuzz hook (arjun / ffuf)
# -------------------------
def auto_fuzz_hook(domain, urls, params):
    os.makedirs("outputs", exist_ok=True)
    urls_file = os.path.join("outputs", f"{domain}_urls.txt")
    params_file = os.path.join("outputs", f"{domain}_params.txt")
    with open(urls_file, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))
    with open(params_file, "w", encoding="utf-8") as f:
        f.write("\n".join(params))

    arjun = shutil.which("arjun")
    ffuf = shutil.which("ffuf")

    if arjun:
        info("Running arjun (parameter discovery) ...")
        subprocess.run([arjun, "-i", urls_file, "-oT", os.path.join("outputs", f"{domain}_arjun.txt")])
    else:
        warn("arjun not installed — skipping arjun step")

    if ffuf:
        info("Launching quick ffuf runs (first 50 URLs) ...")
        for i,u in enumerate(urls[:50]):
            out = os.path.join("outputs", f"ffuf_{i}.csv")
            cmd = [ffuf, "-w", params_file, "-u", f"{u}{'&' if '?' in u else '?'}FUZZ=test", "-of", "csv", "-o", out, "-mc", "200,301,302,401,403"]
            subprocess.run(cmd)
        info("ffuf runs completed")
    else:
        warn("ffuf not installed — skipping ffuf")

# -------------------------
# Alive check & fingerprinting (sync + async)
# -------------------------
def check_alive_head(url):
    try:
        r = requests.head(url, timeout=8, allow_redirects=True)
        return url, r.status_code, []
    except Exception:
        return url, None, []

def fingerprint_get(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        tech = []
        if r.headers.get("Server"): tech.append(r.headers.get("Server"))
        if r.headers.get("X-Powered-By"): tech.append(r.headers.get("X-Powered-By"))
        body = (r.text or "").lower()
        if "wp-content" in body: tech.append("WordPress")
        if "laravel" in body: tech.append("Laravel")
        if "drupal" in body: tech.append("Drupal")
        return url, r.status_code, tech
    except Exception:
        return url, None, []

async def _aio_fetch(session, url, method="HEAD"):
    try:
        if method == "HEAD":
            async with session.head(url, timeout=10, allow_redirects=True) as r:
                return url, r.status, []
        else:
            async with session.get(url, timeout=12, allow_redirects=True) as r:
                text = await r.text()
                tech = []
                if r.headers.get("Server"): tech.append(r.headers.get("Server"))
                if r.headers.get("X-Powered-By"): tech.append(r.headers.get("X-Powered-By"))
                body = (text or "").lower()
                if "wp-content" in body: tech.append("WordPress")
                if "laravel" in body: tech.append("Laravel")
                if "drupal" in body: tech.append("Drupal")
                return url, r.status, tech
    except Exception:
        return url, None, []

async def validate_async(urls, fingerprint=False, concurrency=200):
    if aiohttp is None:
        err("aiohttp not installed. Install to use async mode.")
        return []
    sem = asyncio.Semaphore(concurrency)
    results = []

    async with aiohttp.ClientSession() as session:
        async def worker(u):
            async with sem:
                if fingerprint:
                    return await _aio_fetch(session, u, method="GET")
                else:
                    return await _aio_fetch(session, u, method="HEAD")
        tasks = [worker(u) for u in urls]
        for fut in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Async Validating"):
            try:
                res = await fut
                results.append(res)
            except Exception:
                continue
    return results

# -------------------------
# Save options (TXT, JSON, CSV)
# -------------------------
def save_results(data, default_filename="results"):
    if not data:
        warn("No data to save.")
        return
    fmt = input(Fore.CYAN + "Choose format to save (txt/json/csv) [txt]: " + Style.RESET_ALL).strip().lower() or "txt"
    fname = f"{default_filename}"
    if fmt == "json":
        with open(fname + ".json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        info(f"Saved {fname}.json")
    elif fmt == "csv":
        with open(fname + ".csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            # if list of lists/tuples
            if data and isinstance(data[0], (list, tuple)):
                w.writerows(data)
            elif isinstance(data, dict):
                w.writerow(["key","value"])
                for k,v in data.items():
                    if isinstance(v, (list, tuple)):
                        w.writerow([k, ";".join(map(str,v))])
                    else:
                        w.writerow([k, v])
            else:
                for v in data:
                    w.writerow([v])
        info(f"Saved {fname}.csv")
    else:
        with open(fname + ".txt", "w", encoding="utf-8") as f:
            if isinstance(data, dict):
                for k,v in data.items():
                    f.write(f"{k}\t{';'.join(map(str,v))}\n")
            elif data and isinstance(data[0], (list, tuple)):
                for row in data:
                    f.write("\t".join(map(str,row)) + "\n")
            else:
                for item in data:
                    f.write(str(item) + "\n")
        info(f"Saved {fname}.txt")

# -------------------------
# Interactive menu (loop)
# -------------------------
def interactive_loop():
    banner()
    print(Fore.MAGENTA + "Interactive mode — choose an option. Type the number then ENTER." + Style.RESET_ALL)
    while True:
        print()
        print("[1]  Extract all URLs (Wayback)")
        print("[2]  Filter URLs by extension")
        print("[3]  Hidden + Normalized URLs (smart dedupe)")
        print("[4]  JS Extractor + Endpoint extraction (+ optional secrets)")
        print("[5]  Parameter discovery (unique query params)")
        print("[6]  Directory tree view")
        print("[7]  Keyword / regex search (grep)")
        print("[8]  Sitemap & XML parser (live + archived)")
        print("[9]  Archive comparison (URLs)")
        print("[10] Content Diff (compare snapshots content hashes)")
        print("[11] Cloud buckets finder (scan URLs & sample content)")
        print("[12] Alive check (HEAD) / fingerprint (GET)")
        print("[13] Automatic fuzz hook (arjun / ffuf)")
        print("[14] Wayback Change Alerts (monitor)")
        print("[0]  Exit")
        choice = input(Fore.CYAN + "Choice: " + Style.RESET_ALL).strip()
        if choice == "0":
            print("Goodbye 🦅"); break

        if choice == "1":
            domain = input("Domain (example.com): ").strip()
            ffrom = input("From year (optional): ").strip() or None
            fto = input("To year   (optional): ").strip() or None
            urls = fetch_wayback_urls(domain, from_year=ffrom, to_year=fto)
            print(Fore.GREEN + f"Found {len(urls)} URLs" + Style.RESET_ALL)
            for u in urls: print(u)
            if input("Save results? (y/n): ").lower().startswith("y"): save_results(urls, f"{domain}_urls")

        elif choice == "2":
            domain = input("Domain: ").strip()
            exts = input("Extensions (comma separated, e.g. .php,.js): ").strip().split(",")
            exts = [e.strip() for e in exts if e.strip()]
            urls = fetch_wayback_urls(domain, filters=exts)
            print(Fore.GREEN + f"Found {len(urls)} matching URLs" + Style.RESET_ALL)
            for u in urls: print(u)
            if input("Save? (y/n): ").lower().startswith("y"): save_results(urls, f"{domain}_filtered")

        elif choice == "3":
            domain = input("Domain: ").strip()
            urls = fetch_wayback_urls(domain)
            print(Fore.GREEN + f"{len(urls)} unique normalized URLs" + Style.RESET_ALL)
            for u in urls: print(u)
            if input("Save? (y/n): ").lower().startswith("y"): save_results(urls, f"{domain}_normalized")

        elif choice == "4":
            domain = input("Domain: ").strip()
            from_y = input("From year (optional): ").strip() or None
            to_y = input("To year   (optional): ").strip() or None
            use_secrets = input("Scan JS for secrets? (y/n): ").lower().startswith("y")
            use_async = input("Use async JS scraping? (y/n): ").lower().startswith("y") and (aiohttp is not None)
            js_files, endpoints, secrets_found = extract_js_and_secrets(domain, from_year=from_y, to_year=to_y, secrets=use_secrets, async_mode=use_async)
            print(Fore.GREEN + f"JS files: {len(js_files)}, endpoints: {len(endpoints)}, secrets: {len(secrets_found)}" + Style.RESET_ALL)
            if endpoints:
                print("\n-- Endpoints --")
                for e in endpoints: print(e)
            if secrets_found:
                print("\n-- Secrets found --")
                for s in secrets_found: print("[SECRET]", s)
            if input("Save js files & endpoints? (y/n): ").lower().startswith("y"):
                save_results(js_files, f"{domain}_js_files")
                save_results(endpoints, f"{domain}_js_endpoints")
            if secrets_found and input("Save secrets? (y/n): ").lower().startswith("y"):
                save_results(secrets_found, f"{domain}_js_secrets")

        elif choice == "5":
            domain = input("Domain: ").strip()
            urls = fetch_wayback_urls(domain)
            params = extract_parameters(urls)
            print(Fore.GREEN + f"Found {len(params)} unique parameters" + Style.RESET_ALL)
            for p in params: print(p)
            if input("Save? (y/n): ").lower().startswith("y"): save_results(params, f"{domain}_params")

        elif choice == "6":
            domain = input("Domain: ").strip()
            urls = fetch_wayback_urls(domain)
            tree = build_directory_tree(urls)
            for d in sorted(tree.keys()):
                print(Fore.YELLOW + d + Style.RESET_ALL)
                for f in sorted(tree[d]):
                    print("  ", f)
            if input("Save tree? (y/n): ").lower().startswith("y"):
                rows = [[d, f] for d, files in tree.items() for f in files]
                save_results(rows, f"{domain}_tree")

        elif choice == "7":
            domain = input("Domain: ").strip()
            pattern_input = input("Enter keywords/regex (comma-separated): ").strip()
            patterns = [p.strip() for p in pattern_input.split(",") if p.strip()]
            urls = fetch_wayback_urls(domain)
            matches = []
            for u in urls:
                if any(re.search(p, u, re.I) for p in patterns):
                    matches.append(u)
            print(Fore.GREEN + f"Matches: {len(matches)}" + Style.RESET_ALL)
            for m in matches: print(m)
            if input("Save? (y/n): ").lower().startswith("y"): save_results(matches, f"{domain}_grep")

        elif choice == "8":
            domain = input("Domain: ").strip()
            from_y = input("From year (optional): ").strip() or None
            to_y = input("To year   (optional): ").strip() or None
            urls = parse_sitemaps(domain, from_year=from_y, to_year=to_y)
            print(Fore.GREEN + f"Extracted {len(urls)} URLs from sitemaps" + Style.RESET_ALL)
            for u in urls: print(u)
            if input("Save? (y/n): ").lower().startswith("y"): save_results(urls, f"{domain}_sitemap")

        elif choice == "9":
            domain = input("Domain: ").strip()
            archive_compare(domain)

        elif choice == "10":
            domain = input("Domain: ").strip()
            content_diff(domain)

        elif choice == "11":
            domain = input("Domain: ").strip()
            urls = fetch_wayback_urls(domain)
            # sample contents for cloud detection
            sample_texts = []
            limit = int(input("Fetch sample page contents? how many (0-200) [50]: ").strip() or "50")
            for u in tqdm(urls[:limit], desc="Fetching sample contents"):
                try:
                    r = requests.get(u, timeout=8)
                    if r.status_code == 200 and r.text:
                        sample_texts.append(r.text)
                except Exception:
                    continue
            findings = find_cloud_buckets_in_urls_and_text(urls, sample_texts)
            if not findings:
                warn("No cloud bucket patterns found.")
            else:
                print(json.dumps(findings, indent=2))
                if input("Save findings? (y/n): ").lower().startswith("y"):
                    save_results(findings, f"{domain}_cloud_findings")

        elif choice == "12":
            domain = input("Domain: ").strip()
            urls = fetch_wayback_urls(domain)
            tech_flag = input("Fingerprint with GET? (y/n): ").lower().startswith("y")
            use_async = input("Use async validation? (y/n): ").lower().startswith("y") and (aiohttp is not None)
            if use_async and aiohttp:
                results = asyncio.run(validate_async(urls, fingerprint=tech_flag))
            else:
                results = []
                if tech_flag:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                        for res in tqdm(ex.map(fingerprint_get, urls), total=len(urls), desc="Fingerprinting"):
                            results.append(res)
                else:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
                        for res in tqdm(ex.map(check_alive_head, urls), total=len(urls), desc="Checking HEAD"):
                            results.append(res)
            alive = [u for u,s,t in results if s and s < 400]
            print(Fore.GREEN + f"Alive: {len(alive)}" + Style.RESET_ALL)
            for u,s,t in results:
                if s and s < 400:
                    extra = " ".join(t) if t else ""
                    print(f"{u} [{s}] {extra}")
            if input("Save alive list? (y/n): ").lower().startswith("y"): save_results(alive, f"{domain}_alive")

        elif choice == "13":
            domain = input("Domain: ").strip()
            urls = fetch_wayback_urls(domain)
            # prefer alive urls for fuzz
            print("Validating to get alive URLs (HEAD)...")
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                for res in tqdm(ex.map(check_alive_head, urls), total=len(urls), desc="Validating"):
                    results.append(res)
            alive = [u for u,s,_ in results if s and s < 400]
            params = extract_parameters(alive or urls)
            if not params:
                warn("No parameters discovered — arjun may still find some patterns.")
            if input("Run auto-fuzz (arjun / ffuf)? (y/n): ").lower().startswith("y"):
                auto_fuzz_hook(domain, alive or urls, params)

        elif choice == "14":
            domain = input("Domain: ").strip()
            monitor_wayback(domain)

        else:
            warn("Invalid choice — try again.")

# -------------------------
# Wayback monitor helper
# -------------------------
def monitor_wayback(domain, from_year=None, to_year=None):
    cache_dir = ".wayback_cache"
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{domain.replace(':','_')}.txt")
    current = fetch_wayback_urls(domain, from_year=from_year, to_year=to_year)
    prev = []
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            prev = [l.strip() for l in f if l.strip()]
    new = sorted(set(current) - set(prev))
    print(Fore.CYAN + f"Newly archived URLs since last run: {len(new)}" + Style.RESET_ALL)
    for u in new: print("+", u)
    with open(cache_file, "w", encoding="utf-8") as f:
        f.write("\n".join(current))
    if new and input("Save new list? (y/n): ").lower().startswith("y"):
        save_results(new, f"{domain}_wayback_new")

# -------------------------
# Wrapper save for interactive calls (avoid duplicate def)
# -------------------------
def save_results_wrapped(data, default_filename="results"):
    save_results(data, default_filename)

# -------------------------
# CLI entrypoint
# -------------------------
def main():
    parser = argparse.ArgumentParser(prog="wayback_ripper", description="Wayback Ripper — Wayback Machine recon toolkit")
    parser.add_argument("-d", "--domain", help="Target domain (example.com)")
    parser.add_argument("--filter", nargs="+", help="Extensions to filter by (e.g. .php .js)")
    parser.add_argument("--from", dest="from_year", help="Start year (or timestamp)")
    parser.add_argument("--to", dest="to_year", help="End year (or timestamp)")
    parser.add_argument("--js-extract", action="store_true", help="Extract JS files + endpoints")
    parser.add_argument("--js-secrets", action="store_true", help="Also scan JS for secrets (with --js-extract)")
    parser.add_argument("--params", action="store_true", help="Extract unique query parameters")
    parser.add_argument("--tree", action="store_true", help="Show directory tree view")
    parser.add_argument("--grep", nargs="+", help="Search URLs by keywords/regex (space separated)")
    parser.add_argument("--sitemap", action="store_true", help="Parse sitemaps (live + archived)")
    parser.add_argument("--compare", action="store_true", help="Archive compare two ranges (interactive)")
    parser.add_argument("--content-diff", action="store_true", help="Content diff across two ranges (interactive)")
    parser.add_argument("--cloud", action="store_true", help="Find cloud buckets in URLs/sample content")
    parser.add_argument("--alive", action="store_true", help="Check alive (HEAD)")
    parser.add_argument("--tech", action="store_true", help="Fingerprint (GET) — use with --alive")
    parser.add_argument("--async-mode", action="store_true", help="Use async mode (requires aiohttp)")
    parser.add_argument("--fuzz", action="store_true", help="Auto-fuzz (arjun/ffuf) after params/alive")
    parser.add_argument("--monitor", action="store_true", help="Wayback monitor — store/compare local cache")
    parser.add_argument("--silent", action="store_true", help="Suppress banner (useful when piping output)")
    parser.add_argument("--interactive", action="store_true", help="Force interactive menu")
    args = parser.parse_args()

    # If no flags, launch interactive loop
    if not any(vars(args).values()):
        interactive_loop()
        return

    # If interactive forced
    if args.interactive:
        interactive_loop()
        return

    # For CLI mode we require -d
    if not args.domain:
        banner(silent=args.silent is False)
        print("Examples:")
        print("  python wayback_ripper.py -d example.com")
        print("  python wayback_ripper.py -d example.com --js-extract --js-secrets")
        print("  python wayback_ripper.py -d example.com --params --fuzz")
        print("  python wayback_ripper.py -d example.com --content-diff")
        sys.exit(0)

    banner(silent=args.silent is False)

    domain = args.domain
    urls = fetch_wayback_urls(domain, filters=args.filter, from_year=args.from_year, to_year=args.to_year)

    # sitemap
    if args.sitemap:
        sm = parse_sitemaps(domain, args.from_year, args.to_year)
        for u in sm: print(u)
        if not args.silent and input("Save sitemap results? (y/n): ").lower().startswith("y"):
            save_results(sm, f"{domain}_sitemap")
        return

    # compare interactive
    if args.compare:
        archive_compare(domain)
        return

    # content diff interactive
    if args.content_diff:
        content_diff(domain)
        return

    # js extract
    if args.js_extract or args.js_secrets:
        js_files, endpoints, secrets_found = extract_js_and_secrets(domain, from_year=args.from_year, to_year=args.to_year, secrets=args.js_secrets, async_mode=args.async_mode)
        for j in js_files: print(j)
        if endpoints:
            print("\n# Endpoints")
            for e in endpoints: print(e)
        if secrets_found:
            print("\n# Secrets")
            for s in secrets_found: print("[SECRET]", s)
        if not args.silent and input("Save JS results? (y/n): ").lower().startswith("y"):
            save_results(js_files, f"{domain}_js_files")
            save_results(endpoints, f"{domain}_js_endpoints")
            if secrets_found: save_results(secrets_found, f"{domain}_js_secrets")
        return

    # params
    if args.params:
        params = extract_parameters(urls)
        for p in params: print(p)
        if args.fuzz:
            # validate to get alive
            alive = []
            if args.async_mode and aiohttp:
                res = asyncio.run(validate_async(urls, fingerprint=False))
                alive = [u for u,s,_ in res if s and s < 400]
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                    for u,s,_ in ex.map(check_alive_head, urls):
                        if s and s < 400: alive.append(u)
            auto_fuzz_hook(domain, alive or urls, params)
        return

    # tree
    if args.tree:
        tree = build_directory_tree(urls)
        for d in sorted(tree.keys()):
            print(Fore.YELLOW + d + Style.RESET_ALL)
            for f in sorted(tree[d]): print("  ", f)
        return

    # grep
    if args.grep:
        patterns = args.grep
        matches = []
        for u in urls:
            if any(re.search(p, u, re.I) for p in patterns):
                matches.append(u)
        for m in matches: print(m)
        return

    # cloud
    if args.cloud:
        sample_texts = []
        limit = 50
        for u in urls[:limit]:
            try:
                r = requests.get(u, timeout=8)
                if r.status_code == 200 and r.text: sample_texts.append(r.text)
            except Exception:
                continue
        findings = find_cloud_buckets_in_urls_and_text(urls, sample_texts)
        print(json.dumps(findings, indent=2))
        return

    # monitor
    if args.monitor:
        monitor_wayback(domain, from_year=args.from_year, to_year=args.to_year)
        return

    # alive / tech
    if args.alive:
        if args.async_mode and aiohttp:
            results = asyncio.run(validate_async(urls, fingerprint=args.tech))
        else:
            results = []
            if args.tech:
                with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                    for res in tqdm(ex.map(fingerprint_get, urls), total=len(urls), desc="Fingerprinting"):
                        results.append(res)
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
                    for res in tqdm(ex.map(check_alive_head, urls), total=len(urls), desc="Checking HEAD"):
                        results.append(res)
        for u, s, tech in results:
            if s and s < 400:
                extra = " ".join(tech) if tech else ""
                print(f"{u} [{s}] {extra}")
        return

    # default: just print urls for piping
    for u in urls:
        print(u)

if __name__ == "__main__":
    main()
