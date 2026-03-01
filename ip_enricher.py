import requests
import pandas as pd
import time

ABUSE_API_KEY = "8702eec10ce51fc6fb83c72af3bd70ba610d4347d2fe989f3d6a8a0560e10d1a63db00d3a1017b20"
VT_API_KEY = "f23c1895281dcee34b78d2f110e5f1860b82f2c8094253fb90f90ac6fd460905"


def abuseipdb_check(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        return 0, "Unavailable"

    data = response.json().get("data", {})
    score = data.get("abuseConfidenceScore", 0)
    categories = data.get("categories", [])

    return score, ",".join(map(str, categories))


def virustotal_check(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return 0, 0

    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    return malicious, suspicious


def calculate_severity(score):
    if score >= 71:
        return "Critical"
    elif score >= 41:
        return "High"
    elif score >= 11:
        return "Medium"
    else:
        return "Low"


# === MAIN PROGRAM STARTS HERE ===

df = pd.read_excel("ip_input.xlsx")

results = []

for ip in df["IP"]:
    print(f"[+] Processing IP: {ip}")

    abuse_score, abuse_category = abuseipdb_check(ip)
    vt_malicious, vt_suspicious = virustotal_check(ip)

    severity = calculate_severity(abuse_score)

    verdict = "Malicious" if abuse_score > 50 or vt_malicious > 0 else "Benign"

    results.append([
        abuse_score,
        abuse_category,
        severity,
        vt_malicious,
        vt_suspicious,
        verdict
    ])

    # VirusTotal free-tier safety delay
    time.sleep(16)

df[
    [
        "AbuseIPDB Score",
        "Abuse Category",
        "Severity",
        "VT Malicious",
        "VT Suspicious",
        "Final Verdict"
    ]
] = results

df.to_excel("ip_enriched_output.xlsx", index=False)

print("✅ IP enrichment completed successfully")