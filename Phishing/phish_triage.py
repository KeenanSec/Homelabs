#!/usr/bin/env python3
"""
Automated Phishing Triage & Header Analysis Pipeline (v2)
---------------------------------------------------------
Phase 1 (offline, no keys): header parsing, auth results, Received-hop
tracing, URL + attachment extraction, JSON verdict.

Run everything inside a VM. Do not open attachments. Output URLs are
defanged (hxxp, [.]) so the report is safe to read and share.

Setup:
    export VT_API_KEY=...        # optional, enables VirusTotal
    export URLSCAN_API_KEY=...   # optional

Usage:
    python phish_triage.py sample.eml
    python phish_triage.py sample.eml --authserv mx.google.com
    python phish_triage.py sample.eml --vt --json report.json

--authserv is the id YOUR receiving mail server stamps into
Authentication-Results (e.g. mx.google.com). Only AR headers matching it
are trusted; others are flagged as possibly injected by the sender.
"""

import os
import re
import sys
import json
import time
import hashlib
import argparse
from email import policy
from email.parser import BytesParser

# ---- keys come from the environment only; never hardcode ----
VT_API_KEY = os.environ.get("VT_API_KEY", "")
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "")

URL_RE = re.compile(r'https?://[^\s"\'<>)]+', re.IGNORECASE)
VT_RATE_SLEEP = 16  # free tier is ~4 req/min; 16s keeps us under it


def defang(text):
    """Neutralize a URL or IP so it is not clickable in the report."""
    if not text:
        return text
    return (text.replace("http://", "hxxp://")
                .replace("https://", "hxxps://")
                .replace(".", "[.]"))


def load_email(path):
    if not os.path.isfile(path):
        sys.exit(f"error: no such file: {path}")
    if os.path.getsize(path) == 0:
        sys.exit(f"error: file is empty: {path}")
    if os.path.getsize(path) > 25 * 1024 * 1024:
        sys.exit("error: file larger than 25MB, refusing to parse")
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def parse_auth_results(msg, authserv=None):
    """Read SPF/DKIM/DMARC that a mail server stamped. Only the header
    from YOUR server (authserv) is trustworthy; anything else may have
    been injected by the sender to fake a pass."""
    headers = msg.get_all("Authentication-Results", []) or []
    out = {"spf": None, "dkim": None, "dmarc": None}
    notes = []

    if not headers:
        notes.append("no Authentication-Results header (forwarded mail?) - auth unverified")
        return out, notes

    if authserv:
        trusted = [h for h in headers if h.strip().lower().startswith(authserv.lower())]
        untrusted = len(headers) - len(trusted)
        if untrusted:
            notes.append(f"{untrusted} Authentication-Results header(s) not from {authserv} - possible injection")
        if not trusted:
            notes.append(f"no Authentication-Results from {authserv} - auth unverified")
            return out, notes
    else:
        notes.append("no --authserv given - trusting first AR header without verification")
        trusted = headers[:1]

    raw = " ".join(trusted)
    for mech in out:
        m = re.search(mech + r"=(\w+)", raw, re.IGNORECASE)
        if m:
            out[mech] = m.group(1).lower()
    return out, notes


def trace_received_hops(msg):
    """Received headers are prepended, so reversed() gives oldest-first.
    NOTE: origin guess is IPv4-only and assumes the chain isn't forged.
    (IPv6 + forgery detection intentionally left for a later version.)"""
    hops = list(reversed(msg.get_all("Received", [])))
    ip_re = re.compile(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?')
    trace, origin_ip = [], None
    for h in hops:
        ips = ip_re.findall(h)
        trace.append({"raw": " ".join(h.split())[:200], "ips": ips})
    if trace and trace[0]["ips"]:
        origin_ip = trace[0]["ips"][0]
    return trace, origin_ip


def extract_urls(msg):
    """Pull URLs from text bodies. Failures are recorded, not swallowed.
    (Links inside attachments are NOT parsed yet - later version.)"""
    urls, errors = set(), []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                body = part.get_content()
                urls.update(URL_RE.findall(body))
            except Exception as e:
                errors.append(f"body read failed ({part.get_content_type()}): {e}")
    return sorted(urls), errors


def extract_attachments(msg):
    atts, errors = [], []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            try:
                data = part.get_payload(decode=True) or b""
            except Exception as e:
                errors.append(f"attachment decode failed: {e}")
                continue
            atts.append({
                "filename": part.get_filename(),
                "content_type": part.get_content_type(),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
    return atts, errors


def vt_lookup_hash(sha256):
    if not VT_API_KEY:
        return {"skipped": "no VT_API_KEY"}
    import urllib.request
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": VT_API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {"malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)}
    except Exception as e:
        return {"error": str(e)}


def score(auth, urls, attachments, vt_results):
    """Heuristic, explainable verdict. Weights are hand-picked, not
    statistical - present it as a starting point, not ground truth."""
    reasons, points = [], 0
    if auth.get("spf") in ("fail", "softfail"):
        points += 2; reasons.append(f"SPF {auth['spf']}")
    if auth.get("dkim") == "fail":
        points += 2; reasons.append("DKIM fail")
    if auth.get("dmarc") == "fail":
        points += 3; reasons.append("DMARC fail")
    if len(urls) > 5:
        points += 1; reasons.append(f"{len(urls)} URLs")
    for v in vt_results:
        if isinstance(v, dict) and v.get("malicious", 0) > 0:
            points += 4; reasons.append("VT malicious hit")
    verdict = "Benign"
    if points >= 6:
        verdict = "Malicious"
    elif points >= 2:
        verdict = "Suspicious"
    return {"verdict": verdict, "score": points, "reasons": reasons,
            "note": "heuristic scoring"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("eml")
    ap.add_argument("--authserv", help="trusted receiving mail server id (e.g. mx.google.com)")
    ap.add_argument("--vt", action="store_true", help="enable VirusTotal hash lookups")
    ap.add_argument("--json", metavar="FILE", help="write the report to a file")
    args = ap.parse_args()

    msg = load_email(args.eml)
    auth, auth_notes = parse_auth_results(msg, args.authserv)
    trace, origin_ip = trace_received_hops(msg)
    urls, url_errors = extract_urls(msg)
    attachments, att_errors = extract_attachments(msg)

    vt_results = []
    if args.vt:
        for i, a in enumerate(attachments):
            if i:  # sleep between calls to respect free-tier rate limit
                time.sleep(VT_RATE_SLEEP)
            vt_results.append(vt_lookup_hash(a["sha256"]))

    report = {
        "from": msg.get("From"),
        "subject": msg.get("Subject"),
        "originating_ip": defang(origin_ip),
        "auth_results": auth,
        "auth_notes": auth_notes,
        "url_count": len(urls),
        "urls": [defang(u) for u in urls],
        "attachments": attachments,
        "vt_results": vt_results,
        "errors": url_errors + att_errors,
        "verdict": score(auth, urls, attachments, vt_results),
    }

    out = json.dumps(report, indent=2)
    print(out)
    if args.json:
        with open(args.json, "w") as f:
            f.write(out)
        print(f"\n[written to {args.json}]", file=sys.stderr)


if __name__ == "__main__":
    main()
