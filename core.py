"""
core.py
Logic inti buat manggil VirusTotal & AbuseIPDB, dipakai bareng
oleh CLI (vt_lookup.py) dan web app (app.py) biar nggak duplikat kode.
"""

import base64
import time
from datetime import datetime

import requests
import whois

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
URLSCAN_BASE_URL = "https://urlscan.io/api/v1"


def vt_check_url(url, vt_api_key):
    """Return dict dengan status: 'found', 'submitted', atau 'not_found'."""
    headers = {"x-apikey": vt_api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"{VT_BASE_URL}/urls/{url_id}", headers=headers)

    if response.status_code == 404:
        submit = requests.post(f"{VT_BASE_URL}/urls", headers=headers, data={"url": url})
        submit.raise_for_status()
        return {
            "status": "submitted",
            "stats": None,
            "message": "URL baru disubmit ke VT, coba cek lagi beberapa detik lagi.",
        }

    response.raise_for_status()
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {"status": "found", "stats": stats, "message": None}


def vt_check_hash(file_hash, vt_api_key):
    headers = {"x-apikey": vt_api_key}
    response = requests.get(f"{VT_BASE_URL}/files/{file_hash}", headers=headers)

    if response.status_code == 404:
        return {"status": "not_found", "stats": None, "message": "Hash tidak ditemukan di database VirusTotal."}

    response.raise_for_status()
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {"status": "found", "stats": stats, "message": None}


def vt_check_ip(ip_address, vt_api_key):
    """Return stats dict, atau None kalau IP tidak ditemukan."""
    headers = {"x-apikey": vt_api_key}
    response = requests.get(f"{VT_BASE_URL}/ip_addresses/{ip_address}", headers=headers)

    if response.status_code == 404:
        return None

    response.raise_for_status()
    data = response.json()
    return data["data"]["attributes"]["last_analysis_stats"]


def abuseipdb_check_ip(ip_address, abuse_api_key):
    """Return abuseConfidenceScore (0-100)."""
    headers = {"Key": abuse_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    response = requests.get(f"{ABUSEIPDB_BASE_URL}/check", headers=headers, params=params)
    response.raise_for_status()
    data = response.json()
    return data["data"]["abuseConfidenceScore"]


def get_domain_age(domain):
    """
    Query WHOIS untuk cari umur domain. Return dict {creation_date, age_days}
    atau None kalau data tidak tersedia (banyak domain, terutama yang baru
    atau pakai privacy protection, tidak menampilkan creation_date di WHOIS).
    """
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        # WHOIS kadang balikin list (beberapa registrar punya banyak record)
        if isinstance(creation, list):
            creation = creation[0]

        if not creation:
            return None

        age_days = (datetime.now() - creation).days
        return {"creation_date": str(creation), "age_days": age_days}
    except Exception:
        # WHOIS server tidak selalu bisa diandalkan, banyak kemungkinan error
        # (domain tidak valid, rate limit, server WHOIS down, dst)
        return None


def urlscan_submit(url, api_key):
    """Submit URL ke urlscan.io buat discan. Return scan uuid."""
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    data = {"url": url, "visibility": "unlisted"}
    response = requests.post(f"{URLSCAN_BASE_URL}/scan/", headers=headers, json=data)
    response.raise_for_status()
    return response.json()["uuid"]


def urlscan_get_result(scan_uuid, max_wait=30, poll_interval=5):
    """
    Polling hasil scan sampai selesai atau timeout. urlscan.io butuh waktu
    beberapa detik buat benar-benar 'membuka' URL di browser virtual mereka,
    jadi hasil tidak langsung tersedia begitu submit.
    """
    elapsed = 0
    while elapsed < max_wait:
        response = requests.get(f"{URLSCAN_BASE_URL}/result/{scan_uuid}/")
        if response.status_code == 200:
            return response.json()
        time.sleep(poll_interval)
        elapsed += poll_interval
    return None  # timeout, scan belum selesai


def urlscan_check(url, api_key, max_wait=30):
    """
    Submit + tunggu hasil, lalu ringkas jadi info yang relevan.
    Return dict {status: 'success'|'timeout'|'error', data / message}.
    """
    try:
        scan_uuid = urlscan_submit(url, api_key)
    except Exception as e:
        return {"status": "error", "message": str(e)}

    result = urlscan_get_result(scan_uuid, max_wait=max_wait)
    if result is None:
        return {
            "status": "timeout",
            "message": f"Scan belum selesai setelah {max_wait} detik, cek manual di urlscan.io.",
        }

    verdict = result.get("verdicts", {}).get("overall", {})
    page = result.get("page", {})
    task = result.get("task", {})

    return {
        "status": "success",
        "data": {
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "malicious": verdict.get("malicious", False),
            "score": verdict.get("score", 0),
            "screenshot_url": task.get("screenshotURL"),
            "report_url": task.get("reportURL"),
        },
    }


def compute_ip_score(vt_malicious, abuse_score):
    """
    Threshold digrounded ke dokumentasi resmi AbuseIPDB (noise floor 25)
    dan praktik umum komunitas VT (3+ engine baru dianggap sinyal).
    """
    score = 0

    if vt_malicious >= 3:
        score += 3
    elif vt_malicious >= 1:
        score += 1

    if abuse_score >= 75:
        score += 3
    elif abuse_score >= 50:
        score += 2
    elif abuse_score >= 25:
        score += 1

    if score >= 5:
        category = "High"
    elif score >= 2:
        category = "Medium"
    else:
        category = "Low"

    return score, category
