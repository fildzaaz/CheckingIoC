"""
email_checker.py
Analisa file .eml untuk mencari indikasi phishing: cek autentikasi
(SPF/DKIM/DMARC), mismatch sender, kata kunci mencurigakan, dan
scan URL + attachment lewat core.py (VirusTotal).

Cara pakai:
    export VT_API_KEY="api_key_kamu"
    python3 email_checker.py path/ke/email.eml
"""

import email
import hashlib
import os
import re
import sys
from email import policy
from email.parser import BytesParser

import core

SUSPICIOUS_KEYWORDS = [
    "verifikasi akun", "verify your account", "segera diverifikasi",
    "akun akan ditutup", "your account will be suspended", "urgent action",
    "klik link berikut", "click the link below", "confirm your identity",
    "unusual activity", "aktivitas tidak biasa", "hadiah", "you have won",
    "limited time", "act now", "update informasi pembayaran",
]


def parse_eml(file_path):
    with open(file_path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def get_domain(email_address):
    if not email_address or "@" not in email_address:
        return None
    return email_address.split("@")[-1].strip(">").lower()


def check_sender_mismatch(msg):
    """Bandingin domain header From vs Reply-To."""
    from_addr = email.utils.parseaddr(msg.get("From", ""))[1]
    reply_to_raw = msg.get("Reply-To", "")
    reply_addr = email.utils.parseaddr(reply_to_raw)[1] if reply_to_raw else None

    from_domain = get_domain(from_addr)
    reply_domain = get_domain(reply_addr) if reply_addr else None
    mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)

    return {"from_domain": from_domain, "reply_to_domain": reply_domain, "mismatch": mismatch}


def check_authentication(msg):
    """
    Baca header Authentication-Results (ditambahkan mail server penerima,
    misal Gmail/Outlook). Kalau header ini tidak ada sama sekali, berarti
    email bukan hasil export dari inbox asli, atau providernya tidak
    menambahkan header ini.
    """
    auth_header = msg.get("Authentication-Results", "")
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}

    for mech in result:
        match = re.search(rf"{mech}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            result[mech] = match.group(1).lower()

    return result


def extract_urls(msg):
    """Ambil semua URL unik dari body plain text maupun HTML."""
    urls = set()
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")

    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:
                continue
            urls.update(url_pattern.findall(content))

    return list(urls)


def extract_attachments(msg):
    """Return list dict {filename, sha256} untuk tiap attachment."""
    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename() or "unknown"
        payload = part.get_payload(decode=True)
        if payload:
            sha256 = hashlib.sha256(payload).hexdigest()
            attachments.append({"filename": filename, "sha256": sha256})
    return attachments


def check_keywords(msg):
    """Cari kata kunci mencurigakan di subject + body plain text."""
    subject = msg.get("Subject", "") or ""
    body_text = ""

    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body_text += part.get_content()
            except Exception:
                continue

    combined = (subject + " " + body_text).lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in combined]


def compute_email_score(auth_result, sender_check, keyword_hits, url_risk_count, attachment_risk_count):
    """
    Scoring heuristik, titik awal buat disesuaikan lagi berdasarkan
    pengalaman kamu sendiri:
      - SPF/DKIM/DMARC fail          -> +2 tiap mekanisme
      - Sender mismatch (From/Reply) -> +2
      - Tiap kata kunci mencurigakan -> +1 (maksimal +3)
      - URL yang VT tandai malicious -> +3 tiap URL
      - Attachment yang VT tandai malicious -> +3 tiap attachment
    """
    score = 0

    for mech in ("spf", "dkim", "dmarc"):
        if auth_result.get(mech) == "fail":
            score += 2

    if sender_check["mismatch"]:
        score += 2

    score += min(len(keyword_hits), 3)
    score += url_risk_count * 3
    score += attachment_risk_count * 3

    if score >= 6:
        category = "High"
    elif score >= 3:
        category = "Medium"
    else:
        category = "Low"

    return score, category


def analyze_email(file_path, vt_api_key):
    msg = parse_eml(file_path)

    auth_result = check_authentication(msg)
    sender_check = check_sender_mismatch(msg)
    keyword_hits = check_keywords(msg)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)

    url_risk_count = 0
    url_results = []
    for url in urls:
        malicious, status = 0, "skipped"
        if vt_api_key:
            result = core.vt_check_url(url, vt_api_key)
            status = result["status"]
            if status == "found":
                malicious = result["stats"].get("malicious", 0)
        if malicious > 0:
            url_risk_count += 1
        url_results.append({"url": url, "malicious": malicious, "status": status})

    attachment_risk_count = 0
    attachment_results = []
    for att in attachments:
        malicious, status = 0, "skipped"
        if vt_api_key:
            result = core.vt_check_hash(att["sha256"], vt_api_key)
            status = result["status"]
            if status == "found":
                malicious = result["stats"].get("malicious", 0)
        if malicious > 0:
            attachment_risk_count += 1
        attachment_results.append({**att, "malicious": malicious, "status": status})

    score, category = compute_email_score(
        auth_result, sender_check, keyword_hits, url_risk_count, attachment_risk_count
    )

    return {
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "auth_result": auth_result,
        "sender_check": sender_check,
        "keyword_hits": keyword_hits,
        "urls": url_results,
        "attachments": attachment_results,
        "score": score,
        "category": category,
    }


def print_report(result):
    print("\n=== Analisa Email ===")
    print(f"Subject : {result['subject']}")
    print(f"From    : {result['from']}")

    print("\n-- Autentikasi --")
    for mech, val in result["auth_result"].items():
        print(f"  {mech.upper():6s}: {val}")

    print("\n-- Sender check --")
    print(f"  From domain     : {result['sender_check']['from_domain']}")
    print(f"  Reply-To domain : {result['sender_check']['reply_to_domain']}")
    print(f"  Mismatch        : {'YA' if result['sender_check']['mismatch'] else 'Tidak'}")

    print("\n-- Kata kunci mencurigakan --")
    print("  " + ", ".join(result["keyword_hits"]) if result["keyword_hits"] else "  Tidak ada")

    print(f"\n-- URL ditemukan ({len(result['urls'])}) --")
    for u in result["urls"]:
        flag = "MALICIOUS" if u["malicious"] > 0 else "clean"
        print(f"  [{flag}] {u['url']} ({u['status']})")

    print(f"\n-- Attachment ditemukan ({len(result['attachments'])}) --")
    for a in result["attachments"]:
        flag = "MALICIOUS" if a["malicious"] > 0 else "clean"
        print(f"  [{flag}] {a['filename']} (sha256: {a['sha256'][:16]}...)")

    print(f"\n=== Skor risk: {result['score']} -> {result['category']} ===")


def main():
    if len(sys.argv) != 2:
        print("Cara pakai: python3 email_checker.py path/ke/email.eml")
        sys.exit(1)

    vt_api_key = os.environ.get("VT_API_KEY")
    if not vt_api_key:
        print("Peringatan: VT_API_KEY belum di-set, URL dan attachment tidak akan dicek online.\n")

    result = analyze_email(sys.argv[1], vt_api_key)
    print_report(result)


if __name__ == "__main__":
    main()
