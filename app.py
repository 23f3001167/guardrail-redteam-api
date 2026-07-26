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

LOGICAL_SANDBOX_ROOT = "/srv/agent-redteam/sandbox-1c0559ddf2"
LOGICAL_OUTSIDE_ROOT = "/srv/agent-redteam/outside-d535f9d0"

# Render cannot normally write directly under /srv,
# so create equivalent files inside the application directory.
STORAGE_BASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "runtime-data"
)

SANDBOX_ROOT = os.path.join(
    STORAGE_BASE,
    "sandbox-1c0559ddf2"
)

OUTSIDE_ROOT = os.path.join(
    STORAGE_BASE,
    "outside-d535f9d0"
)

# EXACT hosts allowed by the assignment.
ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

MAX_REDIRECTS = 5
MAX_RESPONSE_BYTES = 1024 * 1024


# ============================================================
# CREATE REQUIRED GRADING FILES
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
        raise ValueError(
            "Path must be a string."
        )

    if "\x00" in path:
        raise ValueError(
            "NUL bytes are not allowed."
        )

    # Absolute grader path or relative sandbox path.
    if os.path.isabs(path):

        logical_candidate = path

    else:

        logical_candidate = os.path.join(
            LOGICAL_SANDBOX_ROOT,
            path
        )

    # Normalize real filesystem traversal.
    #
    # Example:
    # notes/../notes/report.txt
    #
    # becomes:
    # notes/report.txt
    #
    # IMPORTANT:
    # Do NOT URL-decode file paths.
    #
    # %2e%2e-literal.txt must remain a literal filename.
    logical_resolved = os.path.normpath(
        logical_candidate
    )

    logical_root = os.path.normpath(
        LOGICAL_SANDBOX_ROOT
    )

    # Check logical containment.
    try:

        logical_inside = (
            os.path.commonpath([
                logical_root,
                logical_resolved
            ])
            == logical_root
        )

    except ValueError:

        logical_inside = False

    if not logical_inside:

        raise PermissionError(
            "Resolved path is outside the permitted sandbox."
        )

    # Get path relative to sandbox.
    relative_path = os.path.relpath(
        logical_resolved,
        logical_root
    )

    # Map logical grader path to Render storage.
    actual_candidate = os.path.join(
        SANDBOX_ROOT,
        relative_path
    )

    # realpath also resolves symlinks.
    actual_resolved = os.path.realpath(
        actual_candidate
    )

    actual_root = os.path.realpath(
        SANDBOX_ROOT
    )

    # Second containment check protects against symlink escape.
    try:

        actual_inside = (
            os.path.commonpath([
                actual_root,
                actual_resolved
            ])
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

        return None, (
            "Requested path is not a readable regular file."
        )

    try:

        with open(
            resolved,
            "r",
            encoding="utf-8"
        ) as f:

            content = f.read()

    except Exception:

        return None, (
            "The permitted file could not be read."
        )

    return content, None


# ============================================================
# IP SECURITY
# ============================================================

def is_dangerous_ip(ip_text):

    try:

        ip = ipaddress.ip_address(
            ip_text
        )

    except ValueError:

        return True

    # Reject private, loopback, link-local, multicast,
    # unspecified, reserved, metadata-like, etc.
    return not ip.is_global


# ============================================================
# URL SECURITY
# ============================================================

def validate_url(url):

    # --------------------------------------------------------
    # BASIC VALIDATION
    # --------------------------------------------------------

    if not isinstance(url, str) or not url:

        return False, (
            "URL must be a non-empty string."
        )

    # Do NOT silently strip whitespace.
    #
    # A security policy should validate exactly what was given.
    if url != url.strip():

        return False, (
            "URL contains leading or trailing whitespace."
        )

    # Reject ASCII control characters.
    if any(
        ord(character) < 32 or ord(character) == 127
        for character in url
    ):

        return False, (
            "URL contains control characters."
        )

    # Backslashes can be interpreted differently by different
    # URL parsers, so reject them.
    if "\\" in url:

        return False, (
            "Backslashes are not permitted in URLs."
        )

    # --------------------------------------------------------
    # PARSE URL
    # --------------------------------------------------------

    try:

        parsed = urlsplit(url)

    except Exception:

        return False, (
            "Malformed URL."
        )

    scheme = parsed.scheme.lower()

    if scheme not in {
        "http",
        "https"
    }:

        return False, (
            "Only HTTP and HTTPS URLs are permitted."
        )

    # Require an authority/host section.
    if not parsed.netloc:

        return False, (
            "URL has no authority."
        )

    # --------------------------------------------------------
    # USERINFO CONFUSION PROTECTION
    # --------------------------------------------------------
    #
    # Example malicious URL:
    #
    # https://example.com@evil.example/
    #
    # The real destination is evil.example.
    # --------------------------------------------------------

    if (
        parsed.username is not None
        or parsed.password is not None
    ):

        return False, (
            "URL userinfo is not permitted."
        )

    try:

        hostname = parsed.hostname
        port = parsed.port

    except ValueError:

        return False, (
            "Invalid hostname or port."
        )

    if not hostname:

        return False, (
            "URL has no hostname."
        )

    # Hostnames are case-insensitive.
    #
    # IMPORTANT:
    # DO NOT use .rstrip(".")
    #
    # We want exact host comparison.
    hostname = hostname.lower()

    # --------------------------------------------------------
    # EXACT HOST ALLOWLIST
    # --------------------------------------------------------
    #
    # Allowed:
    #
    # example.com
    # www.iana.org
    #
    # Blocked:
    #
    # example.com.evil.example
    # sub.example.com
    # www.iana.org.attacker.example
    # example.com.
    # --------------------------------------------------------

    if hostname not in ALLOWED_HOSTS:

        return False, (
            "Destination hostname is not on the exact allowlist."
        )

    # --------------------------------------------------------
    # PORT VALIDATION
    # --------------------------------------------------------

    if scheme == "https":

        expected_port = 443

        if port not in (
            None,
            443
        ):

            return False, (
                "Non-standard HTTPS port is not permitted."
            )

    else:

        expected_port = 80

        if port not in (
            None,
            80
        ):

            return False, (
                "Non-standard HTTP port is not permitted."
            )

    # --------------------------------------------------------
    # DNS RESOLUTION
    # --------------------------------------------------------

    try:

        infos = socket.getaddrinfo(
            hostname,
            expected_port,
            type=socket.SOCK_STREAM
        )

    except (socket.gaierror, OSError):

        return False, (
            "Destination hostname could not be resolved."
        )

    addresses = set()

    for info in infos:

        sockaddr = info[4]

        if sockaddr:

            addresses.add(
                sockaddr[0]
            )

    if not addresses:

        return False, (
            "Destination hostname resolved to no addresses."
        )

    # --------------------------------------------------------
    # PRIVATE / LOOPBACK / LINK-LOCAL CHECK
    # --------------------------------------------------------

    for address in addresses:

        try:

            ip = ipaddress.ip_address(
                address
            )

        except ValueError:

            return False, (
                "Destination resolved to an invalid address."
            )

        if not ip.is_global:

            return False, (
                "Destination resolved to a non-public address."
            )

    return True, (
        "URL passed the network guardrail."
    )


# ============================================================
# SAFE HTTP FETCH
# ============================================================

def execute_fetch_url(url):

    current_url = url

    session = requests.Session()

    # IMPORTANT:
    #
    # We intentionally disable automatic redirects.
    # Every redirect destination must pass validate_url()
    # BEFORE we contact it.

    for redirect_number in range(
        MAX_REDIRECTS + 1
    ):

        # ----------------------------------------------------
        # VALIDATE CURRENT DESTINATION BEFORE CONTACT
        # ----------------------------------------------------

        valid, reason = validate_url(
            current_url
        )

        if not valid:

            return None, reason

        try:

            response = session.get(
                current_url,

                # Never automatically follow redirects.
                allow_redirects=False,

                timeout=(5, 10),

                headers={
                    "User-Agent":
                    "AgentGuardrail/1.0"
                }
            )

        except requests.RequestException:

            return None, (
                "The permitted destination could not be fetched."
            )

        # ----------------------------------------------------
        # REDIRECT HANDLING
        # ----------------------------------------------------

        if response.status_code in {
            301,
            302,
            303,
            307,
            308,
        }:

            if redirect_number >= MAX_REDIRECTS:

                return None, (
                    "Too many redirects."
                )

            location = response.headers.get(
                "Location"
            )

            if not location:

                return None, (
                    "Redirect response had no destination."
                )

            # Convert relative redirects to absolute URLs.
            next_url = urljoin(
                current_url,
                location
            )

            # SECURITY:
            #
            # Validate redirect BEFORE contacting it.
            valid_redirect, redirect_reason = validate_url(
                next_url
            )

            if not valid_redirect:

                return None, (
                    "Redirect blocked: "
                    + redirect_reason
                )

            current_url = next_url

            continue

        # ----------------------------------------------------
        # FINAL RESPONSE
        # ----------------------------------------------------

        body = response.content[
            :MAX_RESPONSE_BYTES
        ]

        try:

            text = body.decode(
                response.encoding or "utf-8",
                errors="replace"
            )

        except Exception:

            text = body.decode(
                "utf-8",
                errors="replace"
            )

        return {
            "status": response.status_code,
            "body": text
        }, None

    return None, (
        "Too many redirects."
    )


# ============================================================
# HOME / HEALTH CHECK
# ============================================================

@app.route(
    "/",
    methods=["GET"]
)
def home():

    return jsonify({
        "message":
        "Guardrail Red-Team API is running"
    })


# ============================================================
# GUARDRAIL ENDPOINT
# ============================================================

@app.route(
    "/guardrail",
    methods=["POST"]
)
def guardrail():

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict
    ):

        return block(
            "Request body must be a JSON object."
        )

    tool = data.get(
        "tool"
    )

    arguments = data.get(
        "arguments",
        {}
    )

    if not isinstance(
        arguments,
        dict
    ):

        return block(
            "arguments must be a JSON object."
        )

    # ========================================================
    # TOOL: read_file
    # ========================================================

    if tool == "read_file":

        path = arguments.get(
            "path"
        )

        content, error = execute_read_file(
            path
        )

        if error is not None:

            return block(
                error
            )

        return allow(
            "The resolved file is inside the permitted sandbox.",
            content
        )

    # ========================================================
    # TOOL: fetch_url
    # ========================================================

    if tool == "fetch_url":

        url = arguments.get(
            "url"
        )

        result, error = execute_fetch_url(
            url
        )

        if error is not None:

            return block(
                error
            )

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
# LOCAL DEVELOPMENT
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
