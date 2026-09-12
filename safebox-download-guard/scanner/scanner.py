#!/usr/bin/env python3

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


# =========================================================
# Configuration
# =========================================================

DEFAULT_RULES_PATH = (
    Path(__file__).resolve().parent
    / "rules"
    / "safebox.yar"
)

RULES_PATH = Path(
    os.environ.get(
        "SAFEBOX_RULES",
        str(DEFAULT_RULES_PATH)
    )
)

MAX_FILE_SIZE_FOR_HEURISTICS = 50 * 1024 * 1024


# =========================================================
# Basic helpers
# =========================================================

def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def entropy(path: Path) -> float:
    """
    Calculate Shannon entropy.

    High entropy can indicate compression or packing,
    but high entropy alone is NOT considered malware.
    """

    try:
        with open(path, "rb") as file:
            data = file.read(1024 * 1024)

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

            result -= (
                probability
                * math.log2(probability)
            )

        return round(result, 3)

    except Exception:
        return 0.0


def detect_mime_type(path: Path) -> str:
    """
    Prefer Linux `file` command, then fall back to Python
    mimetypes.
    """

    try:
        result = subprocess.run(
            [
                "file",
                "--brief",
                "--mime-type",
                str(path),
            ],
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

    guessed, _ = mimetypes.guess_type(
        str(path)
    )

    return (
        guessed
        or "application/octet-stream"
    )


def archive_info(path: Path) -> dict:
    result = {
        "is_zip": False,
        "entries": [],
    }

    try:
        if not zipfile.is_zipfile(path):
            return result

        result["is_zip"] = True

        with zipfile.ZipFile(path) as archive:
            result["entries"] = (
                archive.namelist()[:100]
            )

    except Exception:
        pass

    return result


# =========================================================
# ClamAV
# =========================================================

def clamav_scan(path: Path) -> dict:
    """
    Return codes:
        0 -> clean
        1 -> threat found
        2+ -> error
    """

    try:
        result = subprocess.run(
            [
                "clamscan",
                "--no-summary",
                str(path),
            ],
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
        return {
            "status": "error",
            "detected": False,
            "raw": str(exc),
        }

    output = (
        result.stdout.strip()
        or result.stderr.strip()
    )

    if result.returncode == 0:
        return {
            "status": "clean",
            "detected": False,
            "raw": output,
        }

    if result.returncode == 1:
        return {
            "status": "threat",
            "detected": True,
            "raw": output,
        }

    return {
        "status": "error",
        "detected": False,
        "raw": output,
    }


# =========================================================
# YARA
# =========================================================

def yara_scan(path: Path) -> dict:
    """
    YARA matches are behavioral/pattern evidence.
    They are NOT automatically treated as malware.
    """

    try:
        import yara

    except ImportError:
        return {
            "status": "unavailable",
            "matches": [],
            "error": (
                "yara-python is not installed."
            ),
        }

    if not RULES_PATH.exists():
        return {
            "status": "unavailable",
            "matches": [],
            "error": (
                f"YARA rules not found: "
                f"{RULES_PATH}"
            ),
        }

    try:
        rules = yara.compile(
            filepath=str(RULES_PATH)
        )

        matches = rules.match(
            str(path)
        )

        return {
            "status": "completed",
            "matches": [
                match.rule
                for match in matches
            ],
        }

    except Exception as exc:
        return {
            "status": "error",
            "matches": [],
            "error": str(exc),
        }


# =========================================================
# Heuristics
# =========================================================

def heuristic_scan(path: Path) -> list:
    """
    Lightweight structural heuristics.

    These are weak signals and never independently
    classify a file as malware.
    """

    findings = []

    filename = path.name.lower()

    suffixes = [
        suffix.lower()
        for suffix in path.suffixes
    ]

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

    # -----------------------------------------------------
    # Double-extension heuristic
    # -----------------------------------------------------

    if len(suffixes) >= 2:

        previous = suffixes[-2]
        current = suffixes[-1]

        if (
            previous in document_extensions
            and current in dangerous_extensions
        ):
            findings.append({
                "type": "double_extension",
                "message": (
                    "File uses a document-like extension "
                    "followed by an executable/script "
                    "extension."
                ),
            })

    # -----------------------------------------------------
    # Suspicious filename keywords
    # -----------------------------------------------------

    suspicious_patterns = [
        r"\bcrack\b",
        r"\bkeygen\b",
        r"\bpatch\b",
        r"\bstealer\b",
        r"\bpayload\b",
        r"\bloader\b",
    ]

    for pattern in suspicious_patterns:

        if re.search(
            pattern,
            filename,
            re.IGNORECASE
        ):
            findings.append({
                "type": "filename",
                "message": (
                    "Filename contains suspicious "
                    f"keyword: {filename}"
                ),
            })

            break

    # -----------------------------------------------------
    # Entropy
    # -----------------------------------------------------

    try:
        file_size = path.stat().st_size

        if (
            file_size
            <= MAX_FILE_SIZE_FOR_HEURISTICS
        ):
            value = entropy(path)

            if value >= 7.5:
                findings.append({
                    "type": "high_entropy",
                    "message": (
                        f"High file entropy detected "
                        f"({value}). This can indicate "
                        "compression or packing and is "
                        "not malware by itself."
                    ),
                })

    except Exception:
        pass

    return findings


# =========================================================
# Behavioral categories
# =========================================================

def classify_yara_matches(
    matches: list
) -> set:
    """
    Convert YARA rule names into behavior categories.
    """

    categories = set()

    for match in matches:

        if "Networking" in match:
            categories.add("network")

        if "Process" in match:
            categories.add(
                "process_execution"
            )

        if "Persistence" in match:
            categories.add(
                "persistence"
            )

        if "Obfuscation" in match:
            categories.add(
                "obfuscation"
            )

        if "File_Activity" in match:
            categories.add(
                "file_activity"
            )

    return categories


# =========================================================
# Risk assessment
# =========================================================

def build_assessment(
    clamav: dict,
    yara: dict,
    heuristics: list,
) -> dict:
    """
    Combine independent signals.

    Important design principle:

        socket/networking alone
            -> LOW

        one weak suspicious indicator
            -> LOW / MEDIUM

        multiple independent indicators
            -> MEDIUM / HIGH

        known ClamAV malware signature
            -> CRITICAL
    """

    score = 0
    evidence = []

    categories = classify_yara_matches(
        yara.get(
            "matches",
            []
        )
    )

    # -----------------------------------------------------
    # Known malware
    # -----------------------------------------------------

    if clamav.get("detected"):

        score += 90

        evidence.append({
            "source": "CLAMAV",
            "message": (
                "ClamAV identified a known malware "
                "signature."
            ),
        })

    # -----------------------------------------------------
    # Networking
    # -----------------------------------------------------

    if "network" in categories:

        score += 8

        evidence.append({
            "source": "BEHAVIOR",
            "message": (
                "Network communication capability "
                "was detected. Networking is common "
                "in legitimate software and is not "
                "treated as malware by itself."
            ),
        })

    # -----------------------------------------------------
    # File activity
    # -----------------------------------------------------

    if "file_activity" in categories:

        score += 5

        evidence.append({
            "source": "BEHAVIOR",
            "message": (
                "File modification or deletion "
                "capability was detected."
            ),
        })

    # -----------------------------------------------------
    # Process execution
    # -----------------------------------------------------

    if "process_execution" in categories:

        score += 15

        evidence.append({
            "source": "BEHAVIOR",
            "message": (
                "Process or command execution "
                "capability was detected."
            ),
        })

    # -----------------------------------------------------
    # Persistence
    # -----------------------------------------------------

    if "persistence" in categories:

        score += 25

        evidence.append({
            "source": "BEHAVIOR",
            "message": (
                "Persistence-related behavior "
                "was detected."
            ),
        })

    # -----------------------------------------------------
    # Obfuscation
    # -----------------------------------------------------

    if "obfuscation" in categories:

        score += 15

        evidence.append({
            "source": "BEHAVIOR",
            "message": (
                "Obfuscation or encoded-command "
                "patterns were detected."
            ),
        })

    # -----------------------------------------------------
    # Multiple categories
    # -----------------------------------------------------

    if len(categories) >= 2:

        score += 10

        evidence.append({
            "source": "CORRELATION",
            "message": (
                "Multiple independent behavior "
                "categories were observed: "
                + ", ".join(
                    sorted(categories)
                )
                + "."
            ),
        })

    if len(categories) >= 3:

        score += 10

        evidence.append({
            "source": "CORRELATION",
            "message": (
                "Several suspicious behavior "
                "categories occur together, "
                "increasing the assessed risk."
            ),
        })

    # -----------------------------------------------------
    # Heuristics
    # -----------------------------------------------------

    for finding in heuristics:

        finding_type = finding.get(
            "type"
        )

        if finding_type == "double_extension":

            score += 10

            evidence.append({
                "source": "HEURISTIC",
                "message":
                    finding.get(
                        "message",
                        ""
                    ),
            })

        elif finding_type == "filename":

            score += 3

            evidence.append({
                "source": "HEURISTIC",
                "message":
                    finding.get(
                        "message",
                        ""
                    ),
            })

        elif finding_type == "high_entropy":

            score += 5

            evidence.append({
                "source": "HEURISTIC",
                "message":
                    finding.get(
                        "message",
                        ""
                    ),
            })

    score = min(
        score,
        100
    )

    # -----------------------------------------------------
    # Final classification
    # -----------------------------------------------------

    if clamav.get("detected"):

        risk = "CRITICAL"
        classification = "MALWARE_DETECTED"

        reason = (
            "A known malware signature was detected "
            "by ClamAV."
        )

    elif score >= 70:

        risk = "HIGH"
        classification = "HIGH_RISK"

        reason = (
            "Multiple suspicious indicators occur "
            "together."
        )

    elif score >= 35:

        risk = "MEDIUM"
        classification = (
            "SUSPICIOUS_BEHAVIOR"
        )

        reason = (
            "The file exhibits suspicious behavior, "
            "but the evidence is not sufficient by "
            "itself to classify the file as malware."
        )

    else:

        risk = "LOW"
        classification = "LIKELY_CLEAN"

        if categories == {"network"}:

            reason = (
                "Network-capable behavior was detected, "
                "but no strong independent indicators "
                "of malicious activity were found."
            )

        elif categories:

            reason = (
                "Some potentially interesting behavior "
                "was detected, but the available evidence "
                "is not sufficient to classify the file "
                "as malware."
            )

        else:

            reason = (
                "No strong indicators of malicious "
                "behavior were detected."
            )

    return {
        "risk": risk,
        "score": score,
        "classification": classification,
        "reason": reason,
        "behavior_categories": sorted(
            categories
        ),
        "evidence": evidence,
    }


# =========================================================
# Complete scan
# =========================================================

def scan_path(path: Path) -> dict:

    if not path.exists():

        return {
            "status": "unavailable",
            "error": (
                f"File does not exist: {path}"
            ),
        }


    if not path.is_file():

        return {
            "status": "error",
            "error": (
                f"Not a regular file: {path}"
            ),
        }


    try:

        file_size = path.stat().st_size

    except Exception as exc:

        return {
            "status": "error",
            "error": str(exc),
        }


    file_hash = sha256(
        path
    )

    entropy_value = entropy(
        path
    )

    detected_mime = detect_mime_type(
        path
    )


    # -----------------------------------------------------
    # Engines
    # -----------------------------------------------------

    clam = clamav_scan(
        path
    )

    yara = yara_scan(
        path
    )

    heuristics = heuristic_scan(
        path
    )

    archive = archive_info(
        path
    )


    # -----------------------------------------------------
    # Assessment
    # -----------------------------------------------------

    assessment = build_assessment(
        clamav=clam,
        yara=yara,
        heuristics=heuristics,
    )


    # -----------------------------------------------------
    # Final report
    # -----------------------------------------------------

    return {

        "status":
            "completed",

        "file": {

            "name":
                path.name,

            "path":
                str(path),

            "size":
                file_size,

            "mime_type":
                detected_mime,

            "sha256":
                file_hash,

            "entropy":
                entropy_value,
        },

        "static_analysis": {

            "clamav":
                clam,

            "yara":
                yara,

            "heuristics":
                heuristics,

            "archive":
                archive,
        },

        "dynamic_analysis": {

            "status":
                "skipped",

            "reason":
                (
                    "Automatic browser-download "
                    "analysis does not execute files."
                ),
        },

        "quarantine":
            None,

        "assessment":
            assessment,
    }


# =========================================================
# Command-line entry point
# =========================================================

def main() -> int:

    if len(sys.argv) != 2:

        print(
            json.dumps({
                "status": "error",
                "error": (
                    "Usage: scanner.py <file>"
                ),
            })
        )

        return 1


    path = Path(
        sys.argv[1]
    ).expanduser()


    try:

        report = scan_path(
            path
        )

        print(
            json.dumps(
                report,
                indent=2
            )
        )

        return 0

    except Exception as exc:

        print(
            json.dumps({
                "status": "error",
                "error": str(exc),
            })
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
