#!/usr/bin/env python3

import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


# =========================================================
# SafeBox Native Host Configuration
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SCANNER_PATH = PROJECT_ROOT / "scanner" / "scanner.py"
RULES_PATH = PROJECT_ROOT / "scanner" / "rules" / "safebox.yar"

MAX_MESSAGE_SIZE = 8 * 1024 * 1024
MAX_MANUAL_FILE_SIZE = 100 * 1024
SCANNER_TIMEOUT = 120


def find_python():
    """
    Find the Python interpreter that has SafeBox's scanner
    dependencies installed.
    """

    candidates = []

    env_python = os.environ.get("SAFEBOX_PYTHON")
    if env_python:
        candidates.append(Path(env_python).expanduser())

    # Project-local virtual environment, if present.
    candidates.extend([
        PROJECT_ROOT / ".venv" / "bin" / "python",
        PROJECT_ROOT / "venv" / "bin" / "python",
    ])

    # Existing SafeBox backend environment from the original project.
    candidates.append(
        Path.home()
        / "Projects"
        / "safebox"
        / "backend"
        / "venv"
        / "bin"
        / "python"
    )

    # Current Python used to launch the host.
    candidates.append(
        Path(sys.executable)
    )

    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except Exception:
            continue

    return sys.executable


PYTHON_EXEC = find_python()


# =========================================================
# Chrome Native Messaging Protocol
# =========================================================

def read_message():
    """
    Native Messaging format:

        4 bytes = little-endian message length
        N bytes = UTF-8 JSON message
    """

    header = sys.stdin.buffer.read(4)

    if not header:
        return None

    if len(header) != 4:
        raise RuntimeError(
            "Invalid Native Messaging header."
        )

    message_length = struct.unpack(
        "<I",
        header
    )[0]

    if message_length > MAX_MESSAGE_SIZE:
        raise RuntimeError(
            f"Message too large: {message_length} bytes."
        )

    payload = sys.stdin.buffer.read(
        message_length
    )

    if len(payload) != message_length:
        raise RuntimeError(
            "Incomplete Native Messaging message."
        )

    try:
        return json.loads(
            payload.decode("utf-8")
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid JSON received from extension: {exc}"
        )


def write_message(message):
    """
    Send JSON using Chrome Native Messaging framing.
    """

    encoded = json.dumps(
        message,
        separators=(",", ":")
    ).encode("utf-8")

    if len(encoded) > MAX_MESSAGE_SIZE:
        raise RuntimeError(
            "Response too large for Native Messaging."
        )

    sys.stdout.buffer.write(
        struct.pack(
            "<I",
            len(encoded)
        )
    )

    sys.stdout.buffer.write(
        encoded
    )

    sys.stdout.buffer.flush()


# =========================================================
# Scanner Execution
# =========================================================

def run_scanner(file_path):
    """
    Run scanner.py against an existing file.
    """

    file_path = Path(file_path)

    if not SCANNER_PATH.is_file():
        return {
            "status": "error",
            "error": f"Scanner not found: {SCANNER_PATH}"
        }

    if not file_path.exists():
        return {
            "status": "unavailable",
            "error": f"File no longer exists: {file_path}"
        }

    if not file_path.is_file():
        return {
            "status": "error",
            "error": f"Path is not a regular file: {file_path}"
        }

    environment = os.environ.copy()

    environment["SAFEBOX_RULES"] = str(
        RULES_PATH
    )

    try:
        process = subprocess.run(
            [
                PYTHON_EXEC,
                str(SCANNER_PATH),
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT,
            env=environment,
        )

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": (
                f"Scanner timed out after "
                f"{SCANNER_TIMEOUT} seconds."
            )
        }

    except FileNotFoundError:
        return {
            "status": "error",
            "error": (
                f"Python executable not found: "
                f"{PYTHON_EXEC}"
            )
        }

    except Exception as exc:
        return {
            "status": "error",
            "error": str(exc)
        }

    if process.returncode != 0:
        return {
            "status": "error",
            "error": (
                process.stderr.strip()
                or "scanner.py returned an error."
            ),
            "return_code": process.returncode
        }

    stdout = process.stdout.strip()

    if not stdout:
        return {
            "status": "error",
            "error": "scanner.py returned no output."
        }

    try:
        return json.loads(stdout)

    except json.JSONDecodeError:
        return {
            "status": "error",
            "error": (
                "scanner.py returned invalid JSON."
            ),
            "raw_output": stdout[-5000:]
        }


# =========================================================
# Browser Download Scan
# =========================================================

def scan_download(request):
    """
    Scan a browser download.

    IMPORTANT:
    Chrome may block a dangerous download before the
    physical file exists in Downloads.

    In that situation we DO NOT call scanner.py.
    We return a browser-blocked CRITICAL report.
    """

    download = request.get("download") or {}

    download_id = download.get("id")

    filename = download.get(
        "filename"
    )

    danger = download.get(
        "danger",
        "safe"
    )

    url = download.get(
        "url",
        ""
    )

    final_url = download.get(
        "finalUrl",
        ""
    )

    mime = download.get(
        "mime",
        ""
    )

    if not filename:
        return {
            "status": "error",
            "error": "Download filename is missing."
        }

    path = Path(
        filename
    ).expanduser()

    dangerous_states = {
        "content",
        "url",
        "host",
        "file",
        "unwanted",
        "blockedTooLarge",
        "sensitiveContentBlock",
        "accountCompromise",
    }

    # -----------------------------------------------------
    # Chrome already blocked the download
    # -----------------------------------------------------

    if danger in dangerous_states:

        return {
            "status": "completed",

            "file": {
                "name": path.name,
                "path": str(path),
                "exists": path.exists(),
                "size": (
                    path.stat().st_size
                    if path.exists()
                    and path.is_file()
                    else None
                ),
                "mime_type": (
                    mime or "unknown"
                ),
            },

            "static_analysis": {
                "clamav": {
                    "status": "not_scanned",
                    "detected": False,
                    "raw": (
                        "ClamAV scan skipped because "
                        "Chrome blocked the download before "
                        "SafeBox could access the file."
                    ),
                },

                "yara": {
                    "status": "not_scanned",
                    "matches": [],
                },

                "heuristics": [],
            },

            "dynamic_analysis": {
                "status": "skipped",
                "reason": (
                    "Automatic browser-download analysis "
                    "does not execute files."
                ),
            },

            "quarantine": None,

            "browser": {
                "download_id": download_id,
                "danger": danger,
                "url": url,
                "final_url": final_url,
                "mime": mime,
            },

            "assessment": {
                "risk": "CRITICAL",
                "score": 100,
                "reason": (
                    f"Chrome reported the download as "
                    f"dangerous: {danger}."
                ),
                "evidence": [
                    {
                        "source": "CHROME",
                        "message": (
                            f"Chrome danger state: {danger}"
                        ),
                    }
                ],
            },
        }

    # -----------------------------------------------------
    # Chrome says the download is safe.
    # Now check that the file actually exists.
    # -----------------------------------------------------

    if not path.exists():
        return {
            "status": "unavailable",

            "file": {
                "name": path.name,
                "path": str(path),
                "exists": False,
            },

            "browser": {
                "download_id": download_id,
                "danger": danger,
                "url": url,
                "final_url": final_url,
                "mime": mime,
            },

            "assessment": {
                "risk": "UNKNOWN",
                "score": 0,
                "reason": (
                    "Chrome reported the download as safe, "
                    "but the file is no longer available "
                    "at the expected path."
                ),
                "evidence": [],
            },
        }

    # -----------------------------------------------------
    # Run SafeBox scanner
    # -----------------------------------------------------

    report = run_scanner(
        path
    )

    if report.get("status") in {
        "error",
        "unavailable"
    }:
        return report

    # Preserve browser information.
    report["browser"] = {
        "download_id": download_id,
        "danger": danger,
        "url": url,
        "final_url": final_url,
        "mime": mime,
    }

    return report


# =========================================================
# Manual File Scan
# =========================================================

def scan_file_bytes(request):
    """
    Scan a file selected through the SafeBox popup.

    The browser sends base64 data.
    The host writes it to a temporary file.
    SafeBox scans it.
    Temporary file is removed afterward.
    """

    file_data = request.get(
        "file"
    ) or {}

    filename = (
        file_data.get("name")
        or "selected_file"
    )

    base64_data = file_data.get(
        "base64"
    )

    mime_type = (
        file_data.get("mimeType")
        or "application/octet-stream"
    )

    size = int(
        file_data.get("size") or 0
    )

    if not base64_data:
        return {
            "status": "error",
            "error": "No base64 file data provided."
        }

    if size > MAX_MANUAL_FILE_SIZE:
        return {
            "status": "error",
            "error": (
                f"Manual scan is limited to "
                f"{MAX_MANUAL_FILE_SIZE // 1024} KB."
            )
        }

    try:
        raw_data = base64.b64decode(
            base64_data,
            validate=True
        )
    except Exception:
        return {
            "status": "error",
            "error": "Invalid base64 file data."
        }

    if len(raw_data) > MAX_MANUAL_FILE_SIZE:
        return {
            "status": "error",
            "error": (
                "Decoded file exceeds the manual scan limit."
            )
        }

    suffix = (
        Path(filename).suffix
        or ".bin"
    )

    temporary_path = None

    try:

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix
        ) as temporary:

            temporary.write(
                raw_data
            )

            temporary_path = Path(
                temporary.name
            )

        report = run_scanner(
            temporary_path
        )

        if report.get("status") in {
            "error",
            "unavailable"
        }:
            return report

        report["file"] = (
            report.get("file")
            or {}
        )

        report["file"]["name"] = (
            filename
        )

        report["file"]["size"] = (
            len(raw_data)
        )

        report["browser"] = {
            "danger": "manual",
            "mime": mime_type,
        }

        return report

    finally:

        if temporary_path:
            try:
                temporary_path.unlink(
                    missing_ok=True
                )
            except Exception:
                pass


# =========================================================
# Request Dispatcher
# =========================================================

def handle_request(request):

    if not isinstance(
        request,
        dict
    ):
        return {
            "status": "error",
            "error": "Request must be a JSON object."
        }

    action = request.get(
        "action"
    )

    if action == "scan":
        return scan_download(
            request
        )

    if action == "scan_bytes":
        return scan_file_bytes(
            request
        )

    return {
        "status": "error",
        "error": (
            f"Unsupported action: {action}"
        ),
    }


# =========================================================
# Main Loop
# =========================================================

def main():

    while True:

        try:
            request = read_message()

        except Exception as exc:

            try:
                write_message({
                    "status": "error",
                    "error": str(exc),
                })
            except Exception:
                pass

            continue

        if request is None:
            break

        try:
            response = handle_request(
                request
            )

        except Exception as exc:

            response = {
                "status": "error",
                "error": str(exc),
            }

        try:
            write_message(
                response
            )
        except Exception:
            break


if __name__ == "__main__":
    main()
