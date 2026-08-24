"""
vt_lookup.py
Versi CLI, sekarang manggil logic dari core.py biar nggak duplikat
kode sama app.py (versi Streamlit).

Cara pakai:
    python3 vt_lookup.py --url https://contoh-mencurigakan.com
    python3 vt_lookup.py --hash <sha256_hash>
    python3 vt_lookup.py --ip 8.8.8.8

Sebelum jalan, set API key sebagai environment variable:
    export VT_API_KEY="api_key_vt_kamu"
    export ABUSEIPDB_API_KEY="api_key_abuseipdb_kamu"   # cuma dibutuhkan buat --ip
"""

import argparse
import os
import sys
from urllib.parse import urlparse

import core


def get_vt_api_key():
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("Error: VT_API_KEY belum di-set. Jalankan dulu:")
        print('  export VT_API_KEY="api_key_kamu"')
        sys.exit(1)
    return api_key


def get_abuseipdb_api_key():
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("Error: ABUSEIPDB_API_KEY belum di-set. Jalankan dulu:")
        print('  export ABUSEIPDB_API_KEY="api_key_kamu"')
        sys.exit(1)
    return api_key


def get_urlscan_api_key():
    """Opsional, beda dari VT/AbuseIPDB yang wajib. Return None kalau tidak di-set."""
    return os.environ.get("URLSCAN_API_KEY")


def print_vt_stats(target, stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    print(f"\nHasil scan untuk: {target}")
    print(f"  Malicious   : {malicious}/{total}")
    print(f"  Suspicious  : {suspicious}/{total}")
    print(f"  Harmless    : {harmless}/{total}")
    print(f"  Undetected  : {undetected}/{total}")

    if malicious > 0:
        print("  => Kemungkinan berbahaya, hati-hati.")
    elif suspicious > 0:
        print("  => Perlu dicek lebih lanjut secara manual.")
    else:
        print("  => Tidak terdeteksi berbahaya oleh engine yang scan.")


def handle_url(url, vt_api_key):
    result = core.vt_check_url(url, vt_api_key)
    if result["status"] == "submitted":
        print(result["message"])
    else:
        print_vt_stats(url, result["stats"])

    # WHOIS: gratis, tidak perlu API key, langsung jalan
    domain = urlparse(url).netloc
    whois_result = core.get_domain_age(domain)
    print("\n-- WHOIS --")
    if whois_result:
        print(f"  Domain dibuat : {whois_result['creation_date']}")
        print(f"  Umur domain   : {whois_result['age_days']} hari")
        if whois_result["age_days"] < 30:
            print("  => Domain baru, waspada.")
    else:
        print("  Data WHOIS tidak tersedia untuk domain ini.")

    # urlscan.io: opsional, cuma jalan kalau API key di-set
    urlscan_api_key = get_urlscan_api_key()
    if urlscan_api_key:
        print("\n-- urlscan.io (menunggu hasil scan) --")
        urlscan_result = core.urlscan_check(url, urlscan_api_key, max_wait=100)
        if urlscan_result["status"] == "success":
            data = urlscan_result["data"]
            print(f"  Domain      : {data['domain']}")
            print(f"  IP          : {data['ip']}")
            print(f"  Malicious   : {data['malicious']}")
            print(f"  Score       : {data['score']}")
            print(f"  Screenshot  : {data['screenshot_url']}")
            print(f"  Report      : {data['report_url']}")
        else:
            print(f"  {urlscan_result['message']}")


def handle_hash(file_hash, vt_api_key):
    result = core.vt_check_hash(file_hash, vt_api_key)
    if result["status"] == "not_found":
        print(result["message"])
    else:
        print_vt_stats(file_hash, result["stats"])


def handle_ip(ip_address, vt_api_key, abuse_api_key):
    vt_stats = core.vt_check_ip(ip_address, vt_api_key)
    abuse_score = core.abuseipdb_check_ip(ip_address, abuse_api_key)

    vt_malicious = vt_stats.get("malicious", 0) if vt_stats else 0
    vt_total = sum(vt_stats.values()) if vt_stats else 0

    print(f"\nHasil gabungan untuk: {ip_address}")
    print(f"  VirusTotal  : {vt_malicious}/{vt_total} engine menandai malicious")
    print(f"  AbuseIPDB   : confidence score {abuse_score}/100")

    score, category = core.compute_ip_score(vt_malicious, abuse_score)
    print(f"  Skor risk   : {score} -> {category}")


def main():
    parser = argparse.ArgumentParser(description="Threat intel lookup sederhana")
    parser.add_argument("--url", help="URL yang mau dicek (VirusTotal)")
    parser.add_argument("--hash", help="Hash file MD5/SHA1/SHA256 yang mau dicek (VirusTotal)")
    parser.add_argument("--ip", help="IP address yang mau dicek (VirusTotal + AbuseIPDB)")
    args = parser.parse_args()

    if not args.url and not args.hash and not args.ip:
        parser.print_help()
        sys.exit(1)

    if args.url:
        handle_url(args.url, get_vt_api_key())
    if args.hash:
        handle_hash(args.hash, get_vt_api_key())
    if args.ip:
        handle_ip(args.ip, get_vt_api_key(), get_abuseipdb_api_key())


if __name__ == "__main__":
    main()
