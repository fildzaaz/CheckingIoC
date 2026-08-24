"""
app.py
Versi web sederhana pakai Streamlit, memanggil logic yang sama
dari core.py (yang juga dipakai vt_lookup.py versi CLI).

Cara jalanin:
    export VT_API_KEY="api_key_vt_kamu"
    export ABUSEIPDB_API_KEY="api_key_abuseipdb_kamu"
    streamlit run app.py
"""

import os
from urllib.parse import urlparse

import streamlit as st
import core


def show_vt_stats(target, stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    st.write(f"**Hasil untuk:** `{target}`")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Malicious", malicious)
    col2.metric("Suspicious", suspicious)
    col3.metric("Harmless", harmless)
    col4.metric("Undetected", undetected)
    st.caption(f"Total engine yang scan: {total}")

    if malicious > 0:
        st.error("Kemungkinan berbahaya, hati-hati.")
    elif suspicious > 0:
        st.warning("Perlu dicek lebih lanjut secara manual.")
    else:
        st.success("Tidak terdeteksi berbahaya oleh engine yang scan.")


st.set_page_config(page_title="Mini TIP", page_icon=":mag:")
st.title("Mini Threat Intel Checker")
st.caption("Aggregator sederhana: VirusTotal + AbuseIPDB")

vt_api_key = os.environ.get("VT_API_KEY")
abuse_api_key = os.environ.get("ABUSEIPDB_API_KEY")

if not vt_api_key:
    st.error("VT_API_KEY belum di-set. Jalankan `export VT_API_KEY=...` di terminal sebelum start Streamlit.")
    st.stop()

check_type = st.selectbox("Mau cek apa?", ["URL", "Hash", "IP Address"])
target = st.text_input(f"Masukkan {check_type}")

if st.button("Cek", type="primary"):
    if not target:
        st.warning("Isi dulu targetnya.")

    elif check_type == "URL":
        with st.spinner("Mengecek ke VirusTotal..."):
            result = core.vt_check_url(target, vt_api_key)
        if result["status"] == "submitted":
            st.info(result["message"])
        else:
            show_vt_stats(target, result["stats"])

        # WHOIS: gratis, tidak perlu API key
        st.divider()
        st.subheader("WHOIS")
        domain = urlparse(target).netloc
        with st.spinner("Mengecek WHOIS..."):
            whois_result = core.get_domain_age(domain)
        if whois_result:
            col1, col2 = st.columns(2)
            col1.metric("Umur domain", f"{whois_result['age_days']} hari")
            col2.write(f"Dibuat: {whois_result['creation_date']}")
            if whois_result["age_days"] < 30:
                st.warning("Domain baru, waspada.")
        else:
            st.caption("Data WHOIS tidak tersedia untuk domain ini.")

        # urlscan.io: opsional
        urlscan_api_key = os.environ.get("URLSCAN_API_KEY")
        if urlscan_api_key:
            st.divider()
            st.subheader("urlscan.io")
            with st.spinner("Menunggu hasil scan urlscan.io (bisa sampai 30 detik)..."):
                urlscan_result = core.urlscan_check(target, urlscan_api_key)
            if urlscan_result["status"] == "success":
                data = urlscan_result["data"]
                col1, col2, col3 = st.columns(3)
                col1.metric("Domain", data["domain"])
                col2.metric("IP", data["ip"])
                col3.metric("Malicious", "Ya" if data["malicious"] else "Tidak")
                if data["screenshot_url"]:
                    st.image(data["screenshot_url"], caption="Screenshot halaman")
                st.link_button("Lihat laporan lengkap", data["report_url"])
            else:
                st.caption(urlscan_result["message"])

    elif check_type == "Hash":
        with st.spinner("Mengecek ke VirusTotal..."):
            result = core.vt_check_hash(target, vt_api_key)
        if result["status"] == "not_found":
            st.warning(result["message"])
        else:
            show_vt_stats(target, result["stats"])

    elif check_type == "IP Address":
        if not abuse_api_key:
            st.error("ABUSEIPDB_API_KEY belum di-set.")
            st.stop()

        with st.spinner("Mengecek ke VirusTotal & AbuseIPDB..."):
            vt_stats = core.vt_check_ip(target, vt_api_key)
            abuse_score = core.abuseipdb_check_ip(target, abuse_api_key)

        vt_malicious = vt_stats.get("malicious", 0) if vt_stats else 0
        vt_total = sum(vt_stats.values()) if vt_stats else 0

        score, category = core.compute_ip_score(vt_malicious, abuse_score)

        col1, col2 = st.columns(2)
        col1.metric("VirusTotal", f"{vt_malicious}/{vt_total}", help="Jumlah engine yang menandai malicious")
        col2.metric("AbuseIPDB", f"{abuse_score}/100", help="Abuse confidence score")

        badge_color = {"Low": "green", "Medium": "orange", "High": "red"}[category]
        st.markdown(f"### Skor risk: {score} -> :{badge_color}[{category}]")
