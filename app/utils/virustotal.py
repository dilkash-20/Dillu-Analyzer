import requests
import time
import os


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


def check_hash(sha256_hash, api_key):
    """Check a file hash against VirusTotal."""
    if not api_key:
        return {"error": "No VirusTotal API key configured", "available": False}

    headers = {"x-apikey": api_key}
    try:
        url = f"{VIRUSTOTAL_API_URL}/files/{sha256_hash}"
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            return _parse_vt_response(data)
        elif response.status_code == 404:
            return {
                "available": True,
                "found": False,
                "message": "File not found in VirusTotal database. Consider uploading for analysis.",
            }
        elif response.status_code == 401:
            return {"error": "Invalid VirusTotal API key", "available": False}
        elif response.status_code == 429:
            return {"error": "VirusTotal API rate limit exceeded. Try again later.", "available": False}
        else:
            return {"error": f"VirusTotal API error: HTTP {response.status_code}", "available": False}

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal API request timed out", "available": False}
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to VirusTotal API", "available": False}
    except Exception as e:
        return {"error": f"VirusTotal error: {str(e)}", "available": False}


def upload_file(file_path, api_key):
    """Upload a file to VirusTotal for scanning."""
    if not api_key:
        return {"error": "No VirusTotal API key configured", "available": False}

    headers = {"x-apikey": api_key}
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(
                f"{VIRUSTOTAL_API_URL}/files",
                headers=headers,
                files=files,
                timeout=60,
            )

        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get("data", {}).get("id")
            if analysis_id:
                return _wait_for_analysis(analysis_id, api_key)
        return {"error": f"Upload failed: HTTP {response.status_code}", "available": False}

    except Exception as e:
        return {"error": f"Upload error: {str(e)}", "available": False}


def _wait_for_analysis(analysis_id, api_key, max_wait=60):
    """Wait for VirusTotal analysis to complete."""
    headers = {"x-apikey": api_key}
    url = f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}"

    for _ in range(max_wait // 5):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                status = data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return _parse_analysis_response(data)
                time.sleep(5)
        except Exception:
            time.sleep(5)

    return {"error": "Analysis timed out", "available": True}


def _parse_vt_response(data):
    """Parse VirusTotal file report response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    detections = []
    for engine, result in results.items():
        if result.get("category") in ["malicious", "suspicious"]:
            detections.append({
                "engine": engine,
                "result": result.get("result", "Unknown"),
                "category": result.get("category", "unknown"),
            })

    reputation = attrs.get("reputation", 0)
    
    return {
        "available": True,
        "found": True,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "detection_rate": f"{malicious}/{total}" if total > 0 else "0/0",
        "reputation": reputation,
        "detections": detections[:20],  # Limit to 20 detections
        "stats": stats,
        "threat_names": list(set(d["result"] for d in detections if d["result"])),
        "scan_date": attrs.get("last_analysis_date", "Unknown"),
        "risk_level": "HIGH" if malicious > 5 else ("MEDIUM" if malicious > 0 else "LOW"),
    }


def _parse_analysis_response(data):
    """Parse VirusTotal analysis response."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("stats", {})
    results = attrs.get("results", {})

    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    detections = []
    for engine, result in results.items():
        if result.get("category") in ["malicious", "suspicious"]:
            detections.append({
                "engine": engine,
                "result": result.get("result", "Unknown"),
                "category": result.get("category"),
            })

    return {
        "available": True,
        "found": True,
        "malicious_count": malicious,
        "suspicious_count": stats.get("suspicious", 0),
        "total_engines": total,
        "detection_rate": f"{malicious}/{total}",
        "detections": detections[:20],
        "stats": stats,
        "threat_names": list(set(d["result"] for d in detections if d["result"])),
        "risk_level": "HIGH" if malicious > 5 else ("MEDIUM" if malicious > 0 else "LOW"),
    }
