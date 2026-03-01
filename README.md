# IP Reputation Enrichment Tool 

A Python + Excel based automation tool that enriches IP addresses using free-tier
threat intelligence sources such as AbuseIPDB and VirusTotal.

This project is designed for SOC analysts, students, and security enthusiasts
to perform bulk IP reputation analysis in a controlled and ethical manner.

---

## Features
- Bulk IP reputation lookup via Excel
- Abuse confidence score and threat category
- VirusTotal malicious and suspicious detections
- Severity classification (Low / Medium / High / Critical)
- Free-tier API compliant
- Excel-friendly workflow

---

## Architecture
Excel (IP list) → Python Engine → Threat Intelligence APIs → Excel (Enriched Output)

---

## Requirements
- Python 3.x
- pandas
- requests
- openpyxl

Install dependencies:
```bash
pip install -r requirements.txt
