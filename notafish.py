#!/usr/bin/env python3
"""
NotAFish - Phishing URL Checker
MIT Licensed CLI tool for heuristic phishing URL detection.
"""

import re
import sys
import socket
import argparse
import ipaddress
from urllib.parse import urlparse

# ---------- colors ----------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"
    WHITE   = "\033[37m"
    BRED    = "\033[91m"
    BGREEN  = "\033[92m"
    BYELLOW = "\033[93m"
    BCYAN   = "\033[96m"

LOGO = f"""{C.CYAN}{C.BOLD}
        )    (
       (    )  )
        )  (  (
       _____
      /     \\    {C.WHITE}NOT{C.RED}A{C.WHITE}FISH{C.CYAN}
     ( o   o )   {C.DIM}phishing URL checker{C.RESET}{C.CYAN}
      \\  ^  /
       \\___/
{C.RESET}"""

BANNER = f"""{C.BCYAN}
 _   _       _    _    ______ _     _
| \\ | |     | |  / \\  |  ____(_)   | |
|  \\| | ___ | |_/ _ \\ | |__   _ ___| |__
| . ` |/ _ \\| __\\/_\\ \\|  __| | / __| '_ \\
| |\\  | (_) | |_ /   \\| |    | \\__ \\ | | |
|_| \\_|\\___/ \\__/_/ \\_\\_|    |_|___/_| |_|
{C.RESET}{C.DIM}v1.0.0  |  MIT License  |  github.com/realnishil/notafish{C.RESET}
"""

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "xyz", "top", "club", "tk", "ml", "ga", "cf",
}

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm", "billing",
    "signin", "banking", "webscr", "ebayisapi", "paypal", "appleid",
    "password", "suspend", "unlock", "support", "service",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rb.gy",
}

BRAND_NAMES = [
    "paypal", "apple", "microsoft", "google", "amazon", "facebook",
    "netflix", "instagram", "bankofamerica", "wellsfargo", "chase",
    "linkedin", "ebay", "dropbox", "adobe",
]


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def has_punycode(host: str) -> bool:
    return "xn--" in host.lower()


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def brand_lookalike(host: str):
    base = host.split(".")[-2] if "." in host else host
    for brand in BRAND_NAMES:
        if brand == base:
            continue
        dist = levenshtein(base, brand)
        if 0 < dist <= 2 and len(base) >= 4:
            return brand
    return None


def resolve_host(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False


class Result:
    def __init__(self):
        self.flags = []   # (severity, message)
        self.score = 0

    def add(self, severity: str, message: str, weight: int):
        self.flags.append((severity, message))
        self.score += weight


def analyze(url: str, do_resolve: bool = True) -> Result:
    r = Result()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = (host + path + query).lower()

    if parsed.scheme != "https":
        r.add("MED", "connection is not HTTPS", 10)

    if is_ip(host):
        r.add("HIGH", f"hostname is a raw IP address ({host})", 25)

    if has_punycode(host):
        r.add("HIGH", "hostname contains punycode (xn--), possible homograph attack", 25)

    if host in URL_SHORTENERS:
        r.add("MED", f"known URL shortener ({host})", 15)

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        r.add("MED", f"suspicious top-level domain (.{tld})", 12)

    subdomain_count = max(host.count(".") - 1, 0)
    if subdomain_count >= 3:
        r.add("MED", f"excessive subdomains ({subdomain_count})", 10)

    at_count = url.count("@")
    if at_count:
        r.add("HIGH", "URL contains '@', can mask real destination", 20)

    if "-" in host and any(b in host.replace("-", "") for b in BRAND_NAMES):
        r.add("MED", "hyphenated host resembles a known brand", 12)

    lookalike = brand_lookalike(host)
    if lookalike:
        r.add("HIGH", f"hostname looks similar to brand '{lookalike}' (typosquat?)", 22)

    kw_hits = [k for k in SUSPICIOUS_KEYWORDS if k in full]
    if kw_hits:
        r.add("LOW", f"suspicious keyword(s): {', '.join(kw_hits[:5])}", 5 * min(len(kw_hits), 3))

    if len(url) > 100:
        r.add("LOW", "unusually long URL", 5)

    if host.count(".") == 0:
        r.add("LOW", "no TLD / malformed host", 8)

    port = parsed.port
    if port and port not in (80, 443):
        r.add("MED", f"non-standard port ({port})", 10)

    if do_resolve and host and not is_ip(host):
        if not resolve_host(host):
            r.add("HIGH", "domain does not resolve (DNS failure)", 20)

    r.score = min(r.score, 100)
    return r, parsed


def verdict(score: int):
    if score >= 50:
        return ("DANGEROUS", C.BRED)
    if score >= 25:
        return ("SUSPICIOUS", C.BYELLOW)
    return ("LIKELY SAFE", C.BGREEN)


def severity_color(sev: str) -> str:
    return {"HIGH": C.BRED, "MED": C.BYELLOW, "LOW": C.CYAN}.get(sev, C.WHITE)


def print_report(url: str, result: Result, parsed):
    label, color = verdict(result.score)
    bar_len = 30
    filled = int(bar_len * result.score / 100)
    bar = f"{color}{'█' * filled}{C.DIM}{'░' * (bar_len - filled)}{C.RESET}"

    print(f"{C.BOLD}URL:{C.RESET} {url}")
    print(f"{C.BOLD}Host:{C.RESET} {parsed.hostname}")
    print()
    print(f"{C.BOLD}Risk Score:{C.RESET} {bar} {color}{result.score}/100{C.RESET}")
    print(f"{C.BOLD}Verdict:{C.RESET}    {color}{C.BOLD}[{label}]{C.RESET}")
    print()

    if result.flags:
        print(f"{C.BOLD}Findings:{C.RESET}")
        for sev, msg in result.flags:
            sc = severity_color(sev)
            print(f"  {sc}[{sev:<4}]{C.RESET} {msg}")
    else:
        print(f"{C.GREEN}No suspicious indicators found.{C.RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="notafish",
        description="NotAFish - heuristic phishing URL checker (MIT License)",
    )
    parser.add_argument("url", nargs="?", help="URL to check")
    parser.add_argument("-f", "--file", help="file with one URL per line")
    parser.add_argument("--no-resolve", action="store_true", help="skip DNS resolution check")
    parser.add_argument("--no-banner", action="store_true", help="suppress logo/banner")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args()

    if args.no_color:
        for attr in vars(C):
            if not attr.startswith("_"):
                setattr(C, attr, "")

    if not args.no_banner:
        print(LOGO)
        print(BANNER)

    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)

    urls = []
    if args.url:
        urls.append(args.url.strip())
    if args.file:
        try:
            with open(args.file) as fh:
                urls.extend(line.strip() for line in fh if line.strip())
        except OSError as e:
            print(f"{C.RED}Error reading file: {e}{C.RESET}")
            sys.exit(1)

    for u in urls:
        result, parsed = analyze(u, do_resolve=not args.no_resolve)
        print(f"{C.DIM}{'-' * 50}{C.RESET}")
        print_report(u, result, parsed)


if __name__ == "__main__":
    main()
