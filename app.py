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

    if not isinstance(url, str) or not url:
        return False, "URL must be a non-empty string."

    # Validate exactly what the caller supplied.
    if url != url.strip():
        return False, "URL contains leading or trailing whitespace."

    # Control characters are never valid here.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return False, "URL contains control characters."

    # Avoid parser differences involving backslashes.
    if "\\" in url:
        return False, "Backslashes are not permitted in URLs."

    try:
        parsed = urlsplit(url)
    except Exception:
        return False, "Malformed URL."

    # --------------------------------------------------------
    # HTTPS ONLY
    # --------------------------------------------------------

    if parsed.scheme.lower() != "https":
        return False, "Only HTTPS URLs are permitted."

    if not parsed.netloc:
        return False, "URL has no authority."

    # --------------------------------------------------------
    # USERINFO ATTACKS
    # --------------------------------------------------------

    # Blocks:
    # https://example.com@evil.example/
    # https://user@example.com/
    # https://user:password@example.com/

    if parsed.username is not None or parsed.password is not None:
        return False, "URL userinfo is not permitted."

    raw_authority = parsed.netloc

    # Percent encoding has no legitimate use in either allowed
    # hostname. Reject it from the authority entirely.
    if "%" in raw_authority:
        return False, "Encoded URL authority is not permitted."

    # Reject characters that should never occur in our two
    # permitted authorities.
    if any(ch in raw_authority for ch in ("#", "?", "/", "\\")):
        return False, "Invalid characters in URL authority."

    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False, "Invalid hostname or port."

    if not hostname:
        return False, "URL has no hostname."

    hostname = hostname.lower()

    # --------------------------------------------------------
    # EXACT HOST ALLOWLIST
    # --------------------------------------------------------

    # ONLY:
    #
    # example.com
    # www.iana.org

    if hostname not in ALLOWED_HOSTS:
        return False, "Destination hostname is not on the exact allowlist."

    # --------------------------------------------------------
    # CANONICAL AUTHORITY
    # --------------------------------------------------------

    # Accept:
    # example.com
    # example.com:443
    #
    # Reject:
    # example.com.
    # example.com:444
    # example.com.evil.test
    # sub.example.com

    if port is None:
        expected_authority = hostname
    else:
        expected_authority = f"{hostname}:{port}"

    if raw_authority.lower() != expected_authority:
        return False, "URL authority is not in canonical form."

    # HTTPS default port only.
    if port not in (None, 443):
        return False, "Only HTTPS port 443 is permitted."

    # --------------------------------------------------------
    # DNS VALIDATION
    # --------------------------------------------------------

    try:
        infos = socket.getaddrinfo(
            hostname,
            443,
            type=socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError):
        return False, "Destination hostname could not be resolved."

    addresses = set()

    for info in infos:
        sockaddr = info[4]

        if sockaddr:
            addresses.add(sockaddr[0])

    if not addresses:
        return False, "Destination hostname resolved to no addresses."

    # --------------------------------------------------------
    # BLOCK NON-PUBLIC IPs
    # --------------------------------------------------------

    for address in addresses:

        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False, "Destination resolved to an invalid IP address."

        # Blocks private, loopback, link-local, reserved,
        # multicast, unspecified, metadata-like addresses, etc.
        if not ip.is_global:
            return False, "Destination resolved to a non-public address."

    return True, "URL passed the network guardrail."




def execute_fetch_url(url):

    current_url = url

    session = requests.Session()

    for redirect_number in range(MAX_REDIRECTS + 1):

        # Validate EVERY destination before making the request.
        valid, reason = validate_url(current_url)

        if not valid:
            return None, reason

        try:
            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=(5, 10),
                headers={
                    "User-Agent": "AgentGuardrail/1.0"
                }
            )

        except requests.RequestException:
            return None, "The permitted destination could not be fetched."

        # Handle redirects manually.
        if response.status_code in (
            301,
            302,
            303,
            307,
            308
        ):

            if redirect_number >= MAX_REDIRECTS:
                return None, "Too many redirects."

            location = response.headers.get("Location")

            if not location:
                return None, "Redirect response had no destination."

            # Reject suspicious redirect Location values early.
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in location):
                return None, "Redirect contains control characters."

            if "\\" in location:
                return None, "Redirect contains a backslash."

            next_url = urljoin(current_url, location)

            # Critical SSRF protection:
            # validate the final redirect URL BEFORE following it.
            redirect_valid, redirect_reason = validate_url(next_url)

            if not redirect_valid:
                return None, "Redirect blocked: " + redirect_reason

            current_url = next_url
            continue

        body = response.content[:MAX_RESPONSE_BYTES]

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

    return None, "Too many redirects."
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
