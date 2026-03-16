import hashlib
import os
import re
import json
import struct
from datetime import datetime


def compute_hashes(file_path):
    """Compute MD5, SHA1, and SHA256 hashes."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


def get_file_info(file_path, original_filename):
    """Get basic file information."""
    stat = os.stat(file_path)
    hashes = compute_hashes(file_path)
    return {
        "filename": original_filename,
        "size": stat.st_size,
        "size_human": _human_size(stat.st_size),
        "upload_time": datetime.now().isoformat(),
        "hashes": hashes,
    }


def _human_size(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def extract_pdf_metadata(file_path):
    """Extract PDF metadata without external libs."""
    metadata = {}
    try:
        with open(file_path, "rb") as f:
            content = f.read()

        # Get PDF version
        header_match = re.search(rb"%PDF-(\d+\.\d+)", content)
        if header_match:
            metadata["pdf_version"] = header_match.group(1).decode()

        # Count pages (rough estimate)
        page_count = len(re.findall(rb"/Type\s*/Page\b", content))
        metadata["page_count"] = page_count

        # Extract info dict
        info_patterns = {
            "title": rb"/Title\s*\(([^)]*)\)",
            "author": rb"/Author\s*\(([^)]*)\)",
            "creator": rb"/Creator\s*\(([^)]*)\)",
            "producer": rb"/Producer\s*\(([^)]*)\)",
            "creation_date": rb"/CreationDate\s*\(([^)]*)\)",
            "mod_date": rb"/ModDate\s*\(([^)]*)\)",
        }
        for key, pattern in info_patterns.items():
            m = re.search(pattern, content)
            if m:
                try:
                    metadata[key] = m.group(1).decode("latin-1", errors="replace")
                except Exception:
                    metadata[key] = "Unknown"

        # Detect encryption
        metadata["encrypted"] = b"/Encrypt" in content

        # Count objects
        obj_count = len(re.findall(rb"\d+\s+\d+\s+obj", content))
        metadata["object_count"] = obj_count

        # Count streams
        stream_count = len(re.findall(rb"\bstream\b", content))
        metadata["stream_count"] = stream_count

    except Exception as e:
        metadata["error"] = str(e)

    return metadata


def detect_javascript(file_path):
    """Detect JavaScript in PDF."""
    results = {
        "has_javascript": False,
        "js_blocks": [],
        "suspicious_patterns": [],
        "risk_level": "LOW",
    }

    suspicious_patterns = {
        "eval()": r"eval\s*\(",
        "unescape()": r"unescape\s*\(",
        "fromCharCode()": r"fromCharCode\s*\(",
        "String.fromCharCode()": r"String\.fromCharCode\s*\(",
        "document.write()": r"document\.write\s*\(",
        "Shellcode patterns": r"%u[0-9a-fA-F]{4}%u[0-9a-fA-F]{4}",
        "Hex encoding": r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}",
        "app.exec()": r"app\.exec\s*\(",
        "this.eval()": r"this\.eval\s*\(",
        "util.printf()": r"util\.printf\s*\(",
        "media.newPlayer()": r"media\.newPlayer\s*\(",
        "Collab.collectEmailInfo()": r"Collab\.collectEmailInfo\s*\(",
    }

    try:
        with open(file_path, "rb") as f:
            content = f.read()

        content_str = content.decode("latin-1", errors="replace")

        # Find JS blocks
        js_markers = ["/JavaScript", "/JS"]
        for marker in js_markers:
            if marker.lower() in content_str.lower():
                results["has_javascript"] = True

        # Extract JS content between stream tags
        streams = re.findall(r"stream\r?\n(.*?)\r?\nendstream", content_str, re.DOTALL)
        for stream in streams[:10]:  # Limit to 10 streams
            for name, pattern in suspicious_patterns.items():
                if re.search(pattern, stream, re.IGNORECASE):
                    if name not in [p["pattern"] for p in results["suspicious_patterns"]]:
                        results["suspicious_patterns"].append({
                            "pattern": name,
                            "severity": "HIGH" if "eval" in name.lower() or "exec" in name.lower() or "shellcode" in name.lower() else "MEDIUM"
                        })

        # Also scan raw content
        for name, pattern in suspicious_patterns.items():
            if re.search(pattern, content_str, re.IGNORECASE):
                if name not in [p["pattern"] for p in results["suspicious_patterns"]]:
                    results["suspicious_patterns"].append({
                        "pattern": name,
                        "severity": "HIGH" if "eval" in name.lower() or "exec" in name.lower() else "MEDIUM"
                    })

        if results["suspicious_patterns"]:
            high_count = sum(1 for p in results["suspicious_patterns"] if p["severity"] == "HIGH")
            results["risk_level"] = "HIGH" if high_count > 0 else "MEDIUM"
        elif results["has_javascript"]:
            results["risk_level"] = "MEDIUM"

    except Exception as e:
        results["error"] = str(e)

    return results


def extract_embedded_files(file_path):
    """Extract embedded file information from PDF."""
    embedded = {
        "has_embedded": False,
        "files": [],
        "suspicious_types": [],
        "risk_level": "LOW",
    }

    dangerous_extensions = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".com"]

    try:
        with open(file_path, "rb") as f:
            content = f.read()

        content_str = content.decode("latin-1", errors="replace")

        # Check for embedded file markers
        if b"/EmbeddedFile" in content or b"/EmbeddedFiles" in content:
            embedded["has_embedded"] = True

        # Find filenames
        filename_patterns = [
            r"/F\s*\(([^)]+)\)",
            r"/UF\s*\(([^)]+)\)",
            r"/Filespec\s*\(([^)]+)\)",
        ]
        found_files = set()
        for pattern in filename_patterns:
            matches = re.findall(pattern, content_str)
            for match in matches:
                if match and len(match) > 2:
                    found_files.add(match)

        for fname in found_files:
            ext = os.path.splitext(fname)[1].lower()
            is_suspicious = ext in dangerous_extensions
            embedded["files"].append({
                "name": fname,
                "extension": ext,
                "suspicious": is_suspicious,
            })
            if is_suspicious and fname not in embedded["suspicious_types"]:
                embedded["suspicious_types"].append(fname)

        # Check for auto-open actions
        auto_actions = []
        if b"/OpenAction" in content:
            auto_actions.append("OpenAction")
        if b"/AA" in content:
            auto_actions.append("Additional Actions (AA)")
        if b"/Launch" in content:
            auto_actions.append("Launch Action")
        if b"/SubmitForm" in content:
            auto_actions.append("SubmitForm Action")

        embedded["auto_actions"] = auto_actions

        if embedded["suspicious_types"] or auto_actions:
            embedded["risk_level"] = "HIGH"
        elif embedded["has_embedded"]:
            embedded["risk_level"] = "MEDIUM"

        # Count streams that might be files
        stream_count = len(re.findall(r"\bstream\b", content_str))
        embedded["stream_count"] = stream_count

    except Exception as e:
        embedded["error"] = str(e)

    return embedded


def scan_with_yara(file_path, rules_path):
    """Scan file with YARA rules."""
    results = {
        "scanned": False,
        "matches": [],
        "rule_count": 0,
        "risk_level": "LOW",
    }

    try:
        import yara
        rules = yara.compile(rules_path)
        results["scanned"] = True

        matches = rules.match(file_path)
        for match in matches:
            severity = match.meta.get("severity", "MEDIUM")
            results["matches"].append({
                "rule": match.rule,
                "description": match.meta.get("description", "No description"),
                "severity": severity,
                "category": match.meta.get("category", "Unknown"),
                "tags": list(match.tags) if match.tags else [],
            })

        results["rule_count"] = len(matches)

        if any(m["severity"] == "HIGH" for m in results["matches"]):
            results["risk_level"] = "HIGH"
        elif results["matches"]:
            results["risk_level"] = "MEDIUM"

    except ImportError:
        # YARA not installed - do manual pattern matching
        results["scanned"] = True
        results["yara_unavailable"] = True
        results["matches"] = _manual_yara_scan(file_path)
        results["rule_count"] = len(results["matches"])
        if any(m["severity"] == "HIGH" for m in results["matches"]):
            results["risk_level"] = "HIGH"
        elif results["matches"]:
            results["risk_level"] = "MEDIUM"
    except Exception as e:
        results["error"] = str(e)

    return results


def _manual_yara_scan(file_path):
    """Fallback manual pattern scanning when YARA unavailable."""
    matches = []
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        content_str = content.decode("latin-1", errors="replace")

        rules = [
            {
                "rule": "PDF_JavaScript_Suspicious",
                "pattern": r"eval\s*\(",
                "description": "Detects suspicious JavaScript eval() usage",
                "severity": "HIGH",
                "category": "JavaScript",
            },
            {
                "rule": "PDF_Unescape_Function",
                "pattern": r"unescape\s*\(",
                "description": "Detects unescape() function used for obfuscation",
                "severity": "HIGH",
                "category": "JavaScript",
            },
            {
                "rule": "PDF_OpenAction",
                "pattern": r"/OpenAction",
                "description": "PDF auto-executes action on open",
                "severity": "HIGH",
                "category": "AutoExecution",
            },
            {
                "rule": "PDF_Launch_Action",
                "pattern": r"/Launch",
                "description": "PDF contains Launch action",
                "severity": "HIGH",
                "category": "AutoExecution",
            },
            {
                "rule": "PDF_Embedded_JavaScript",
                "pattern": r"/JavaScript",
                "description": "Embedded JavaScript detected in PDF",
                "severity": "MEDIUM",
                "category": "JavaScript",
            },
            {
                "rule": "PDF_Embedded_File",
                "pattern": r"/EmbeddedFile",
                "description": "PDF contains embedded files",
                "severity": "MEDIUM",
                "category": "EmbeddedFile",
            },
            {
                "rule": "PDF_URI_Action",
                "pattern": r"/URI",
                "description": "PDF contains URI action (possible phishing)",
                "severity": "MEDIUM",
                "category": "Network",
            },
            {
                "rule": "PDF_Exploit_Util_Printf",
                "pattern": r"util\.printf",
                "description": "Detects util.printf exploit pattern (CVE-2008-2992)",
                "severity": "HIGH",
                "category": "Exploit",
            },
            {
                "rule": "PDF_Shellcode_NOP",
                "pattern": r"\x90{8,}",
                "description": "Possible NOP sled shellcode pattern detected",
                "severity": "HIGH",
                "category": "Shellcode",
            },
            {
                "rule": "PDF_Obfuscated_JS",
                "pattern": r"fromCharCode",
                "description": "Detects fromCharCode obfuscation technique",
                "severity": "MEDIUM",
                "category": "Obfuscation",
            },
        ]

        for rule in rules:
            try:
                if re.search(rule["pattern"], content_str if rule["pattern"] != r"\x90{8,}" else content.decode("latin-1"), re.IGNORECASE):
                    matches.append({
                        "rule": rule["rule"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "tags": [],
                    })
            except Exception:
                pass

    except Exception:
        pass

    return matches


def calculate_risk_score(yara_results, js_results, embedded_results):
    """Calculate overall risk score 0-100."""
    score = 0

    # YARA matches (up to 40 points)
    for match in yara_results.get("matches", []):
        if match["severity"] == "HIGH":
            score += 15
        elif match["severity"] == "MEDIUM":
            score += 8
        else:
            score += 3
    score = min(score, 40)

    # JavaScript analysis (up to 35 points)
    if js_results.get("has_javascript"):
        score += 10
    for pattern in js_results.get("suspicious_patterns", []):
        if pattern["severity"] == "HIGH":
            score += 10
        else:
            score += 5
    score = min(score, 75)

    # Embedded files (up to 25 points)
    if embedded_results.get("has_embedded"):
        score += 5
    if embedded_results.get("auto_actions"):
        score += len(embedded_results["auto_actions"]) * 8
    if embedded_results.get("suspicious_types"):
        score += len(embedded_results["suspicious_types"]) * 10
    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
        color = "#ff2d55"
    elif score >= 50:
        level = "HIGH"
        color = "#ff6b35"
    elif score >= 25:
        level = "MEDIUM"
        color = "#ffd60a"
    else:
        level = "LOW"
        color = "#30d158"

    return {"score": score, "level": level, "color": color}
