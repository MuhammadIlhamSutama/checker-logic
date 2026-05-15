import os
import time
import requests

# Mapping tipe IoC ke path OTX API
IOC_TYPE_PATHS_OTX = {
    "hash": "file",
    "ip": "IPv4",
}

SCORE_LABEL = {
    range(1, 4): "Low Risk",
    range(4, 8): "Medium Risk",
    range(8, 11): "High Risk",
}

def get_score_label(score):
    for r, label in SCORE_LABEL.items():
        if score in r:
            return label
    return "Unknown"

def check_otx(ioc_value, ioc_type, retries=3, delay=5):

    path_segment = IOC_TYPE_PATHS_OTX.get(ioc_type)
    if not path_segment:
        print(f"[!] Error OTX: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"

    endpoint = "general"
    url = f"https://otx.alienvault.com/api/v1/indicators/{path_segment}/{ioc_value}/{endpoint}"

    api_key = os.getenv("OTX_API_KEY")

    headers = {
        "User-Agent": "EducationalSecurityResearch/1.0 (contact: your_email@domain.com)",
    }
    if api_key:
        headers["X-OTX-API-KEY"] = api_key

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 429:
                print(f"⚠️  Rate limit reached (attempt {attempt}/{retries}). "
                      f"Tunggu {delay}s sebelum retry...")
                time.sleep(delay)
                delay *= 2
                continue

            if response.status_code == 404:
                return "none"

            if response.status_code >= 500:
                print(f"⚠️  OTX Server Error {response.status_code}. Retrying...")
                time.sleep(2)
                continue

            response.raise_for_status()
            data = response.json()

            pulses = data.get("pulse_info", {}).get("count", 0)
            asn = "N/A"
            if ioc_type == "ip":
                asn = data.get("asn", "N/A")

            # =================================================
            # HASH: ambil score + verdict dari analysis
            # =================================================
            verdict = None
            file_score = None

            if ioc_type == "hash":
                analysis_url = (
                    f"https://otx.alienvault.com/api/v1/"
                    f"indicators/file/{ioc_value}/analysis"
                )
                try:
                    analysis_resp = requests.get(
                        analysis_url,
                        headers=headers,
                        timeout=30
                    )
                    if analysis_resp.status_code == 200:
                        analysis_data = analysis_resp.json()
                        plugins = analysis_data.get("analysis", {}).get("plugins", {})

                        # Score dari cuckoo
                        file_score = (
                            plugins
                            .get("cuckoo", {})
                            .get("result", {})
                            .get("info", {})
                            .get("combined_score")
                        )

                        # Verdict dari YARA category
                        detections = (
                            plugins
                            .get("yarad", {})
                            .get("results", {})
                            .get("detection", [])
                        )
                        is_malicious = any(
                            "malicious" in d.get("category", [])
                            for d in detections
                        )
                        if is_malicious:
                            verdict = "malicious"
                        elif file_score is not None:
                            verdict = get_score_label(file_score)

                except requests.exceptions.RequestException:
                    pass

            # =================================================
            # BUILD RESULT
            # =================================================
            result_parts = []

            if pulses > 0:
                result_parts.append(f"{pulses} pulses")

            if ioc_type == "ip" and asn != "N/A":
                result_parts.append(asn)

            if file_score is not None:
                result_parts.append(f"score:{file_score}")

            if verdict:
                result_parts.append(verdict)

            return " ".join(result_parts) if result_parts else "none"

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            print(f"OTX Timeout/Connection Error (percobaan {attempt}/{retries})...")
            if attempt < retries:
                time.sleep(delay)
                continue
            else:
                return "Error: Timeout"

        except requests.exceptions.RequestException as e:
            print(f"[!] Error OTX request fatal: {e}")
            return "Error: Request Failed"

    print("[!] Gagal menghubungi OTX setelah beberapa kali percobaan.")
    return "Error: Connection Failed"