import os
import sys
import json
import time
import urllib.request

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def fetch_nvd_dataset():
    headers = {
        "User-Agent": "NKAT-AI-Sentinel/2.0 (NVD CVE Dataset Downloader)"
    }

    year_windows = [
        ("2018", "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2018-01-01T00:00:00.000&pubEndDate=2018-03-31T23:59:59.999&resultsPerPage=500"),
        ("2019", "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2019-01-01T00:00:00.000&pubEndDate=2019-03-31T23:59:59.999&resultsPerPage=500"),
        ("2020", "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2020-01-01T00:00:00.000&pubEndDate=2020-03-31T23:59:59.999&resultsPerPage=500"),
        ("2022", "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2022-01-01T00:00:00.000&pubEndDate=2022-03-31T23:59:59.999&resultsPerPage=500"),
        ("2023", "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2023-01-01T00:00:00.000&pubEndDate=2023-03-31T23:59:59.999&resultsPerPage=500"),
        ("2024", "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2024-01-01T00:00:00.000&pubEndDate=2024-03-31T23:59:59.999&resultsPerPage=500"),
    ]

    records = []

    print("[*] Fetching 2,000 real NVD CVE entries from NIST NVD REST API v2.0...")

    for yr, url in year_windows:
        print(f"[*] Requesting NVD REST API ({yr}): {url}")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                if resp.status != 200:
                    print(f"[!] HTTP Error {resp.status} for year {yr}")
                    continue
                
                data = json.loads(resp.read().decode('utf-8'))
                vulnerabilities = data.get("vulnerabilities", [])
                
                for item in vulnerabilities:
                    cve_obj = item.get("cve", {})
                    cve_id = cve_obj.get("id")
                    published = cve_obj.get("published")
                    
                    # Extract English description
                    descriptions = cve_obj.get("descriptions", [])
                    desc_text = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc_text = d.get("value", "").strip()
                            break
                    
                    if not desc_text:
                        continue
                    
                    # Extract CVSS v3.1 / v3.0 metrics
                    metrics = cve_obj.get("metrics", {})
                    cvss_data = None
                    exploitability_score = None
                    
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                        m = metrics["cvssMetricV31"][0]
                        cvss_data = m.get("cvssData", {})
                        exploitability_score = m.get("exploitabilityScore")
                    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                        m = metrics["cvssMetricV30"][0]
                        cvss_data = m.get("cvssData", {})
                        exploitability_score = m.get("exploitabilityScore")
                    
                    if not cvss_data:
                        continue
                        
                    base_severity = cvss_data.get("baseSeverity", "").upper()
                    base_score = cvss_data.get("baseScore", 0.0)
                    attack_vector = cvss_data.get("attackVector", "")
                    
                    if base_severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                        continue

                    records.append({
                        "cve_id": cve_id,
                        "published": published,
                        "description": desc_text,
                        "base_severity": base_severity,
                        "base_score": base_score,
                        "exploitability_score": exploitability_score,
                        "attack_vector": attack_vector
                    })

                print(f"  [+] Extracted {len(records)} total valid NVD records so far")
                time.sleep(6) # Respect rate limits
        except Exception as e:
            print(f"[!] Error pulling window {yr}: {e}")

    os.makedirs("data", exist_ok=True)
    out_file = os.path.join("data", "nvd_cve_dataset.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    print(f"\n Saved {len(records)} verified real NVD CVE entries to {out_file}")

if __name__ == "__main__":
    fetch_nvd_dataset()
