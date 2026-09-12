#!/usr/bin/env python3
"""Chrome native messaging host for Glass download scanning."""

import json
import os
import struct
import subprocess
import sys
from pathlib import Path

HOST_DIR = Path(__file__).resolve().parent
SCANNER_PATH = HOST_DIR / "scanner" / "scanner.py"
RULES_PATH = HOST_DIR / "scanner" / "rules" / "glass.yar"
MAX_MESSAGE_SIZE = 8 * 1024 * 1024
SCANNER_TIMEOUT = 120

DANGEROUS_STATES = {
    "content",
    "url",
    "host",
    "file",
    "unwanted",
    "blockedTooLarge",
    "sensitiveContentBlock",
    "accountCompromise",
}


def read_message():
    header = sys.stdin.buffer.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise RuntimeError("Invalid Native Messaging header.")
    message_length = struct.unpack("<I", header)[0]
    if message_length > MAX_MESSAGE_SIZE:
        raise RuntimeError(f"Message too large: {message_length} bytes.")
    payload = sys.stdin.buffer.read(message_length)
    if len(payload) != message_length:
        raise RuntimeError("Incomplete Native Messaging message.")
    try:
        return json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON received from extension: {exc}")


def write_message(message):
    encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_MESSAGE_SIZE:
        raise RuntimeError("Response too large for Native Messaging.")
    sys.stdout.buffer.write(struct.pack("<I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def run_scanner(file_path):
    file_path = Path(file_path)
    if not SCANNER_PATH.is_file():
        return {"status": "error", "error": f"Scanner not found: {SCANNER_PATH}"}
    if not file_path.exists():
        return {"status": "unavailable", "error": f"File no longer exists: {file_path}"}
    if not file_path.is_file():
        return {"status": "error", "error": f"Path is not a regular file: {file_path}"}

    environment = os.environ.copy()
    environment["GLASS_RULES"] = str(RULES_PATH)
    try:
        process = subprocess.run(
            [sys.executable, str(SCANNER_PATH), str(file_path)],
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": f"Scanner timed out after {SCANNER_TIMEOUT} seconds.",
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "error": f"Python executable not found: {sys.executable}",
        }
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    if process.returncode != 0:
        return {
            "status": "error",
            "error": process.stderr.strip() or "scanner.py returned an error.",
            "return_code": process.returncode,
        }
    stdout = process.stdout.strip()
    if not stdout:
        return {"status": "error", "error": "scanner.py returned no output."}
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {
            "status": "error",
            "error": "scanner.py returned invalid JSON.",
            "raw_output": stdout[-5000:],
        }


def chrome_blocked_report(path, download):
    exists = path.exists() and path.is_file()
    danger = download.get("danger", "safe")
    return {
        "status": "completed",
        "file": {
            "name": path.name,
            "path": str(path),
            "exists": exists,
            "size": path.stat().st_size if exists else None,
            "mime_type": download.get("mime") or "unknown",
        },
        "static_analysis": {
            "clamav": {
                "status": "not_scanned",
                "detected": False,
                "raw": (
                    "ClamAV scan skipped because Chrome blocked the download "
                    "before Glass could access the file."
                ),
            },
            "yara": {"status": "not_scanned", "matches": []},
            "heuristics": [],
        },
        "dynamic_analysis": {
            "status": "skipped",
            "reason": "Automatic browser-download analysis does not execute files.",
        },
        "quarantine": None,
        "browser": {
            "download_id": download.get("id"),
            "danger": danger,
            "url": download.get("url", ""),
            "final_url": download.get("finalUrl", ""),
            "mime": download.get("mime", ""),
        },
        "assessment": {
            "risk": "CRITICAL",
            "score": 100,
            "reason": f"Chrome reported the download as dangerous: {danger}.",
            "evidence": [
                {
                    "source": "CHROME",
                    "message": f"Chrome danger state: {danger}",
                }
            ],
        },
    }


def scan_download(request):
    download = request.get("download") or {}
    filename = download.get("filename")
    if not filename:
        return {"status": "error", "error": "Download filename is missing."}
    path = Path(filename).expanduser()
    danger = download.get("danger", "safe")
    if danger in DANGEROUS_STATES:
        return chrome_blocked_report(path, download)
    if not path.exists():
        return {
            "status": "unavailable",
            "file": {"name": path.name, "path": str(path), "exists": False},
            "browser": {
                "download_id": download.get("id"),
                "danger": danger,
                "url": download.get("url", ""),
                "final_url": download.get("finalUrl", ""),
                "mime": download.get("mime", ""),
            },
            "assessment": {
                "risk": "UNKNOWN",
                "score": 0,
                "reason": (
                    "Chrome reported the download as safe, but the file is no "
                    "longer available at the expected path."
                ),
                "evidence": [],
            },
        }
    report = run_scanner(path)
    if report.get("status") in {"error", "unavailable"}:
        return report
    report["browser"] = {
        "download_id": download.get("id"),
        "danger": danger,
        "url": download.get("url", ""),
        "final_url": download.get("finalUrl", ""),
        "mime": download.get("mime", ""),
    }
    return report


def handle_request(request):
    if not isinstance(request, dict):
        return {"status": "error", "error": "Request must be a JSON object."}
    action = request.get("action")
    if action == "scan":
        return scan_download(request)
    return {"status": "error", "error": f"Unsupported action: {action}"}


def main():
    while True:
        try:
            request = read_message()
        except Exception as exc:
            try:
                write_message({"status": "error", "error": str(exc)})
            except Exception:
                pass
            continue
        if request is None:
            break
        try:
            response = handle_request(request)
        except Exception as exc:
            response = {"status": "error", "error": str(exc)}
        try:
            write_message(response)
        except Exception:
            break


if __name__ == "__main__":
    main()
