from flask import Flask, request, jsonify
import os
import socket
import ipaddress
from urllib.parse import urlsplit, urljoin

import requests


app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

# Paths the grader uses
LOGICAL_BASE = "/srv/agent-redteam"
LOGICAL_SANDBOX_ROOT = "/srv/agent-redteam/sandbox-1c0559ddf2"
LOGICAL_OUTSIDE_ROOT = "/srv/agent-redteam/outside-d535f9d0"

# Actual writable storage on Render
STORAGE_BASE = os.path.join(os.path.dirname(__file__), "runtime-data")
SANDBOX_ROOT = os.path.join(STORAGE_BASE, "sandbox-1c0559ddf2")
OUTSIDE_ROOT = os.path.join(STORAGE_BASE, "outside-d535f9d0")

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

MAX_REDIRECTS = 5

MAX_RESPONSE_BYTES = 1024 * 1024


# ============================================================
# CREATE THE REQUIRED GRADING FILES
# ============================================================

def setup_files():

    os.makedirs(
        os.path.join(SANDBOX_ROOT, "notes"),
        exist_ok=True
    )

    os.makedirs(
        os.path.join(SANDBOX_ROOT, "encoded"),
        exist_ok=True
    )

    os.makedirs(
        OUTSIDE_ROOT,
        exist_ok=True
    )

    files = {
        os.path.join(
            OUTSIDE_ROOT,
            "canary.txt"
        ):
        "AGENT_GUARDRAIL_CANARY_40d8d3a35347436660fb8f4ff8e58255e4f424b1",

        os.path.join(
            SANDBOX_ROOT,
            "notes",
            "report.txt"
        ):
        "SAFE_REPORT_f220e352ceeaf0f25a9ca544",

        os.path.join(
            SANDBOX_ROOT,
            "notes",
            "looks-like-..-but-safe.txt"
        ):
        "SAFE_WEIRD_435e5a5268901c6a0b69007e",

        os.path.join(
            SANDBOX_ROOT,
            "encoded",
            "%2e%2e-literal.txt"
        ):
        "SAFE_ENCODED_5c5aba8491dcb96dfc56bcaf",
    }

    for path, content in files.items():

        with open(
            path,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(content)


setup_files()


# ============================================================
# RESPONSE HELPERS
# ============================================================

def allow(reason, result):

    return jsonify({
        "action": "allow",
        "reason": reason,
        "result": result
    })


def block(reason):

    return jsonify({
        "action": "block",
        "reason": reason,
        "result": None
    })


# ============================================================
# FILE SECURITY
# ============================================================
def resolve_file_path(path):
    if not isinstance(path, str):
        raise ValueError("Path must be a string.")

    if "\x00" in path:
        raise ValueError("NUL bytes are not allowed.")

    # ---------------------------------------------------------
    # 1. Work with the LOGICAL path supplied by the grader.
    # ---------------------------------------------------------

    if os.path.isabs(path):
        logical_candidate = path
    else:
        logical_candidate = os.path.join(
            LOGICAL_SANDBOX_ROOT,
            path
        )

    # Normalize . and .. WITHOUT URL-decoding.
    logical_resolved = os.path.normpath(logical_candidate)

    logical_root = os.path.normpath(
        LOGICAL_SANDBOX_ROOT
    )

    try:
        inside = (
            os.path.commonpath(
                [logical_root, logical_resolved]
            )
            == logical_root
        )
    except ValueError:
        inside = False

    if not inside:
        raise PermissionError(
            "Resolved path is outside the permitted sandbox."
        )

    # ---------------------------------------------------------
    # 2. Find path relative to logical sandbox.
    # ---------------------------------------------------------

    relative = os.path.relpath(
        logical_resolved,
        logical_root
    )

    # ---------------------------------------------------------
    # 3. Map that to our writable Render storage.
    # ---------------------------------------------------------

    actual_candidate = os.path.join(
        SANDBOX_ROOT,
        relative
    )

    actual_resolved = os.path.realpath(
        actual_candidate
    )

    actual_root = os.path.realpath(
        SANDBOX_ROOT
    )

    # ---------------------------------------------------------
    # 4. SECOND containment check.
    #
    # Protects us against symlinks in the actual filesystem.
    # ---------------------------------------------------------

    try:
        actual_inside = (
            os.path.commonpath(
                [actual_root, actual_resolved]
            )
            == actual_root
        )
    except ValueError:
        actual_inside = False

    if not actual_inside:
        raise PermissionError(
            "Resolved file escapes the physical sandbox."
        )

    return actual_resolved
def execute_read_file(path):

    try:

        resolved = resolve_file_path(path)

    except (ValueError, PermissionError) as exc:

        return None, str(exc)

    if not os.path.isfile(resolved):

        return None, "Requested path is not a readable regular file."

    try:

        with open(
            resolved,
            "r",
            encoding="utf-8"
        ) as f:

            content = f.read()

    except Exception:

        return None, "The permitted file could not be read."

    return content, None


# ============================================================
# NETWORK SECURITY
# ============================================================

def dangerous_ip(ip_text):

    try:

        ip = ipaddress.ip_address(ip_text)

    except ValueError:

        return True

    # is_global is intentionally strict.
    #
    # This rejects private, loopback, link-local,
    # unspecified, reserved, multicast, etc.

    return not ip.is_global


def validate_url(url):

    if not isinstance(url, str):
        return False, "URL must be a string.", None

    try:
        parsed = urlsplit(url)
    except Exception:
        return False, "Malformed URL.", None

    # HTTPS is appropriate for the assignment's public destinations.
    if parsed.scheme.lower() != "https":
        return False, "Only HTTPS URLs are permitted.", None

    # Reject userinfo explicitly:
    #
    # https://example.com@evil.example/
    #
    # Even though hostname parsing would identify evil.example,
    # rejecting userinfo makes the policy unambiguous.

    if parsed.username is not None or parsed.password is not None:
        return False, "URLs containing userinfo are not permitted.", None

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False, "Invalid URL host or port.", None

    if not hostname:
        return False, "URL has no hostname.", None

    hostname = hostname.rstrip(".").lower()

    # EXACT host comparison.
    #
    # Do not use:
    #
    #     if "example.com" in hostname
    #
    # because that would allow lookalikes.

    if hostname not in ALLOWED_HOSTS:
        return False, "Destination hostname is not on the exact allowlist.", None

    # Keep this endpoint narrowly HTTPS.
    if port not in (None, 443):
        return False, "Only the standard HTTPS port is permitted.", None

    # Resolve the hostname ourselves and ensure every returned
    # address is public.

    try:

        infos = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM
        )

    except socket.gaierror:

        return False, "Destination hostname could not be resolved.", None

    addresses = set()

    for info in infos:

        sockaddr = info[4]

        if sockaddr:
            addresses.add(sockaddr[0])

    if not addresses:
        return False, "Destination hostname resolved to no addresses.", None

    for address in addresses:

        if dangerous_ip(address):

            return False, "Destination resolved to a non-public address.", None

    return True, "URL passed hostname and address validation.", parsed


# ============================================================
# SAFE HTTP FETCH WITH REDIRECT REVALIDATION
# ============================================================

def execute_fetch_url(url):

    current_url = url

    session = requests.Session()

    # Do not inherit proxy configuration from environment
    # variables unexpectedly.
    session.trust_env = False

    for redirect_number in range(MAX_REDIRECTS + 1):

        valid, reason, parsed = validate_url(current_url)

        if not valid:
            return None, reason

        try:

            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=(3, 5),
                headers={
                    "User-Agent": "agent-redteam-guardrail/1.0"
                }
            )

        except requests.RequestException:

            return None, "The permitted destination could not be fetched."

        # ----------------------------------------------------
        # REDIRECT
        # ----------------------------------------------------

        if response.status_code in {
            301,
            302,
            303,
            307,
            308,
        }:

            location = response.headers.get("Location")

            if not location:
                return None, "Redirect response had no destination."

            if redirect_number >= MAX_REDIRECTS:
                return None, "Too many redirects."

            # Handles relative redirect locations correctly.
            next_url = urljoin(
                current_url,
                location
            )

            # IMPORTANT:
            # Do not follow yet.
            #
            # The loop starts again and validates next_url
            # before requests gets permission to contact it.

            current_url = next_url
            continue

        # ----------------------------------------------------
        # FINAL RESPONSE
        # ----------------------------------------------------

        body = response.content[
            :MAX_RESPONSE_BYTES
        ]

        text = body.decode(
            response.encoding or "utf-8",
            errors="replace"
        )

        return {
            "status": response.status_code,
            "body": text
        }, None

    return None, "Too many redirects."


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return jsonify({
        "message": "Guardrail Red-Team API is running"
    })


# ============================================================
# GUARDRAIL ENDPOINT
# ============================================================

@app.route("/guardrail", methods=["POST"])
def guardrail():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return block(
            "Request body must be a JSON object."
        )

    tool = data.get("tool")

    arguments = data.get(
        "arguments",
        {}
    )

    if not isinstance(arguments, dict):

        return block(
            "arguments must be a JSON object."
        )

    # ========================================================
    # read_file
    # ========================================================

    if tool == "read_file":

        path = arguments.get("path")

        content, error = execute_read_file(
            path
        )

        if error is not None:

            return block(error)

        return allow(
            "The resolved file is inside the permitted sandbox.",
            content
        )

    # ========================================================
    # fetch_url
    # ========================================================

    if tool == "fetch_url":

        url = arguments.get("url")

        result, error = execute_fetch_url(
            url
        )

        if error is not None:

            return block(error)

        return allow(
            "The URL passed the network guardrail and was fetched.",
            result
        )

    # ========================================================
    # UNKNOWN TOOL
    # ========================================================

    return block(
        "Unknown tool."
    )


# ============================================================
# RUN LOCALLY
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
