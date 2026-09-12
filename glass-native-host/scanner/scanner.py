#!/usr/bin/env python3
"""Local ClamAV + YARA scanner used by the Glass native host."""

import hashlib
import json
import math
import mimetypes
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "rules" / "glass.yar"
RULES_PATH = Path(os.environ.get("GLASS_RULES", str(DEFAULT_RULES_PATH)))
MAX_FILE_SIZE_FOR_HEURISTICS = 50 * 1024 * 1024
EICAR_SIGNATURE = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def entropy(path: Path) -> float:
    try:
        with open(path, "rb") as handle:
            data = handle.read(1024 * 1024)
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        length = len(data)
        result = 0.0
        for count in counts:
            if count == 0:
                continue
            probability = count / length
            result -= probability * math.log2(probability)
        return round(result, 3)
    except Exception:
        return 0.0


def detect_mime_type(path: Path) -> str:
    try:
        result = subprocess.run(
            ["file", "--brief", "--mime-type", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            detected = result.stdout.strip()
            if detected:
                return detected
    except Exception:
        pass
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


def archive_info(path: Path) -> dict:
    result = {"is_zip": False, "entries": []}
    try:
        if not zipfile.is_zipfile(path):
            return result
        result["is_zip"] = True
        with zipfile.ZipFile(path) as archive:
            result["entries"] = archive.namelist()[:100]
    except Exception:
        pass
    return result


def engine_status(clamav: dict, yara: dict) -> dict:
    clam_status = clamav.get("status")
    yara_status = yara.get("status")
    return {
        "clamav": clam_status not in {None, "unavailable", "error"},
        "yara": yara_status == "completed",
        "heuristics": True,
    }


def clamav_scan(path: Path) -> dict:
    try:
        result = subprocess.run(
            ["clamscan", "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "detected": False,
            "raw": "ClamAV is not installed.",
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "detected": False,
            "raw": "ClamAV scan timed out.",
        }
    except Exception as exc:
        return {"status": "error", "detected": False, "raw": str(exc)}

    output = result.stdout.strip() or result.stderr.strip()
    if result.returncode == 0:
        return {"status": "clean", "detected": False, "raw": output}
    if result.returncode == 1:
        return {"status": "threat", "detected": True, "raw": output}
    return {"status": "error", "detected": False, "raw": output}


def eicar_detected(path: Path) -> bool:
    try:
        if path.stat().st_size > 4096:
            return False
        data = path.read_bytes()
        return EICAR_SIGNATURE.encode("ascii") in data
    except Exception:
        return False


def yara_scan(path: Path) -> dict:
    try:
        import yara
    except ImportError:
        return {
            "status": "unavailable",
            "matches": [],
            "error": "yara-python is not installed.",
        }
    if not RULES_PATH.exists():
        return {
            "status": "unavailable",
            "matches": [],
            "error": f"YARA rules not found: {RULES_PATH}",
        }
    try:
        rules = yara.compile(filepath=str(RULES_PATH))
        matches = rules.match(str(path))
        return {
            "status": "completed",
            "matches": [match.rule for match in matches],
        }
    except Exception as exc:
        return {"status": "error", "matches": [], "error": str(exc)}


def heuristic_scan(path: Path) -> list:
    findings = []
    filename = path.name.lower()
    suffixes = [suffix.lower() for suffix in path.suffixes]
    dangerous_extensions = {
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".msi",
        ".com",
    }
    document_extensions = {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".jpg",
        ".jpeg",
        ".png",
        ".txt",
    }
    if len(suffixes) >= 2:
        previous = suffixes[-2]
        current = suffixes[-1]
        if previous in document_extensions and current in dangerous_extensions:
            findings.append(
                {
                    "type": "double_extension",
                    "message": (
                        "File uses a document-like extension followed by "
                        "an executable/script extension."
                    ),
                }
            )
    suspicious_patterns = [
        r"\bcrack\b",
        r"\bkeygen\b",
        r"\bpatch\b",
        r"\bstealer\b",
        r"\bpayload\b",
        r"\bloader\b",
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, filename, re.IGNORECASE):
            findings.append(
                {
                    "type": "filename",
                    "message": f"Filename contains suspicious keyword: {filename}",
                }
            )
            break
    try:
        file_size = path.stat().st_size
        if file_size <= MAX_FILE_SIZE_FOR_HEURISTICS:
            value = entropy(path)
            if value >= 7.5:
                findings.append(
                    {
                        "type": "high_entropy",
                        "message": (
                            f"High file entropy detected ({value}). This can "
                            "indicate compression or packing and is not malware "
                            "by itself."
                        ),
                    }
                )
    except Exception:
        pass
    archive = archive_info(path)
    if archive.get("is_zip"):
        names = [str(name).replace("\\", "/").lower() for name in archive.get("entries", [])]
        if any(name.endswith("vbaproject.bin") or "/vba/" in name for name in names):
            findings.append(
                {
                    "type": "office_macro",
                    "message": "Archive contains an Office macro project (vbaProject.bin).",
                }
            )
        if any(name.endswith((".js", ".jse", ".ps1", ".vbs", ".bat", ".cmd")) for name in names):
            findings.append(
                {
                    "type": "script_in_zip",
                    "message": "Archive contains script files (.js, .ps1, .vbs, or similar).",
                }
            )
    if (
        any(suffix in dangerous_extensions for suffix in suffixes)
        and any(finding.get("type") == "high_entropy" for finding in findings)
    ):
        findings.append(
            {
                "type": "packed_executable",
                "message": "Executable or script has high entropy, which can indicate packing.",
            }
        )
    return findings


def classify_yara_matches(matches: list) -> set:
    categories = set()
    for match in matches:
        if "Networking" in match or "JS_Network" in match:
            categories.add("network")
        if "Process" in match or "PowerShell" in match:
            categories.add("process_execution")
        if "Persistence" in match:
            categories.add("persistence")
        if "Obfuscation" in match or "Packed" in match:
            categories.add("obfuscation")
        if "File_Activity" in match:
            categories.add("file_activity")
        if "Macro" in match or "OLE" in match:
            categories.add("macros")
    return categories


def build_assessment(clamav: dict, yara: dict, heuristics: list, eicar: bool = False) -> dict:
    score = 0
    evidence = []
    categories = classify_yara_matches(yara.get("matches", []))
    clam_available = clamav.get("status") not in {None, "unavailable", "error"}

    if clamav.get("detected") and clam_available:
        score += 90
        evidence.append(
            {
                "source": "CLAMAV",
                "message": "ClamAV identified a known malware signature.",
            }
        )
    elif eicar:
        score += 90
        evidence.append(
            {
                "source": "EICAR",
                "message": "EICAR antivirus test signature was found in the file.",
            }
        )
    if "network" in categories:
        score += 8
        evidence.append(
            {
                "source": "BEHAVIOR",
                "message": (
                    "Network communication capability was detected. "
                    "Networking is common in legitimate software."
                ),
            }
        )
    if "file_activity" in categories:
        score += 5
        evidence.append(
            {
                "source": "BEHAVIOR",
                "message": "File modification or deletion capability was detected.",
            }
        )
    if "process_execution" in categories:
        score += 15
        evidence.append(
            {
                "source": "BEHAVIOR",
                "message": "Process or command execution capability was detected.",
            }
        )
    if "persistence" in categories:
        score += 25
        evidence.append(
            {
                "source": "BEHAVIOR",
                "message": "Persistence-related behavior was detected.",
            }
        )
    if "obfuscation" in categories:
        score += 15
        evidence.append(
            {
                "source": "BEHAVIOR",
                "message": "Obfuscation or encoded-command patterns were detected.",
            }
        )
    if "macros" in categories:
        score += 18
        evidence.append(
            {
                "source": "BEHAVIOR",
                "message": "Office macro or OLE automation markers were detected.",
            }
        )
    if len(categories) >= 2:
        score += 10
        evidence.append(
            {
                "source": "CORRELATION",
                "message": (
                    "Multiple independent behavior categories were observed: "
                    + ", ".join(sorted(categories))
                    + "."
                ),
            }
        )
    if len(categories) >= 3:
        score += 10
        evidence.append(
            {
                "source": "CORRELATION",
                "message": (
                    "Several suspicious behavior categories occur together, "
                    "increasing the assessed risk."
                ),
            }
        )

    for finding in heuristics:
        finding_type = finding.get("type")
        bump = {
            "double_extension": 10,
            "filename": 3,
            "high_entropy": 5,
            "office_macro": 20,
            "script_in_zip": 12,
            "packed_executable": 12,
        }.get(finding_type, 0)
        if bump:
            score += bump
            evidence.append(
                {
                    "source": "HEURISTIC",
                    "message": finding.get("message", ""),
                }
            )

    score = min(score, 100)

    if clamav.get("detected") and clam_available:
        risk = "CRITICAL"
        classification = "MALWARE_DETECTED"
        reason = "A known malware signature was detected by ClamAV."
    elif eicar:
        risk = "CRITICAL"
        classification = "MALWARE_DETECTED"
        reason = "EICAR test signature detected. This is a standard harmless AV test file."
    elif score >= 70:
        risk = "HIGH"
        classification = "HIGH_RISK"
        reason = "Multiple suspicious indicators occur together."
    elif score >= 35:
        risk = "MEDIUM"
        classification = "SUSPICIOUS_BEHAVIOR"
        reason = (
            "The file exhibits suspicious behavior, but the evidence is not "
            "sufficient by itself to classify the file as malware."
        )
    else:
        risk = "LOW"
        classification = "LIKELY_CLEAN"
        if categories == {"network"}:
            reason = (
                "Network-capable behavior was detected, but no strong "
                "independent indicators of malicious activity were found."
            )
        elif categories:
            reason = (
                "Some potentially interesting behavior was detected, but the "
                "available evidence is not sufficient to classify the file as malware."
            )
        else:
            reason = "No strong indicators of malicious behavior were detected."

    return {
        "risk": risk,
        "score": score,
        "classification": classification,
        "reason": reason,
        "behavior_categories": sorted(categories),
        "evidence": evidence,
    }


def scan_path(path: Path) -> dict:
    if not path.exists():
        return {"status": "unavailable", "error": f"File does not exist: {path}"}
    if not path.is_file():
        return {"status": "error", "error": f"Not a regular file: {path}"}
    try:
        file_size = path.stat().st_size
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    clam = clamav_scan(path)
    eicar = eicar_detected(path)
    if eicar and not clam.get("detected"):
        clam = {
            **clam,
            "eicar": True,
            "raw": (clam.get("raw") or "")
            + (" " if clam.get("raw") else "")
            + "EICAR standard antivirus test file detected.",
        }
    yara = yara_scan(path)
    heuristics = heuristic_scan(path)
    assessment = build_assessment(
        clamav=clam, yara=yara, heuristics=heuristics, eicar=eicar
    )

    return {
        "status": "completed",
        "file": {
            "name": path.name,
            "path": str(path),
            "size": file_size,
            "mime_type": detect_mime_type(path),
            "sha256": sha256(path),
            "entropy": entropy(path),
        },
        "engines": engine_status(clam, yara),
        "static_analysis": {
            "clamav": clam,
            "yara": yara,
            "heuristics": heuristics,
            "archive": archive_info(path),
            "eicar": eicar,
        },
        "dynamic_analysis": {
            "status": "skipped",
            "reason": "Automatic browser-download analysis does not execute files.",
        },
        "quarantine": None,
        "assessment": assessment,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "error", "error": "Usage: scanner.py <file>"}))
        return 1
    path = Path(sys.argv[1]).expanduser()
    try:
        report = scan_path(path)
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
