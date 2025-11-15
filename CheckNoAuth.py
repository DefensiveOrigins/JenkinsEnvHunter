#!/usr/bin/env python3
"""
CheckNoAuth.py

Read a file with Jenkins hosts (one per line: HOST or HOST:PORT) and check:
 - whether a Jenkins instance is running
 - whether it appears to require authentication

Usage:
  python CheckNoAuth.py [-v] [--ssl] hosts.txt

Options:
  -v, --verbose    Print every HTTP request/response (verbose).
  --ssl            Use https instead of http for connections.
  -t, --timeout    Request timeout in seconds (default: 5).
  -n, --threads    Number of worker threads to use (default: 1).
"""
from __future__ import annotations
import argparse
import sys
import re
import concurrent.futures
from typing import Optional, Tuple, List
from urllib.parse import urlparse
try:
    import requests
    from requests.exceptions import RequestException, SSLError, ConnectionError, Timeout
except Exception:
    print("This script requires the 'requests' library. Install with: pip install requests", file=sys.stderr)
    sys.exit(2)

# Optional progress bar
try:
    from alive_progress import alive_bar
    HAS_ALIVE = True
except Exception:
    HAS_ALIVE = False

DEFAULT_PORT = 8080
DEFAULT_TIMEOUT = 5.0
USER_AGENT = "CheckNoAuth/1.0"

# ANSI colors to make anonymous servers stand out (safe no-op on terminals that don't support)
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "92m"
YELLOW = CSI + "93m"


def parse_host_line(line: str) -> Optional[Tuple[str, int]]:
    """
    Parse a line containing host[:port] or a URL and return (host, port).
    Returns None for blank/comment lines.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    # If the user provided a scheme, use urlparse
    if "://" in s:
        p = urlparse(s)
        host = p.hostname
        port = p.port or DEFAULT_PORT
        return host, port

    # IPv6 in [addr]:port form
    if s.startswith("["):
        # [::1]:8080 or [::1]
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", s)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else DEFAULT_PORT
            return host, port

    # Otherwise split on last colon to allow hostnames with IPv6 colons avoided above.
    if ":" in s:
        host_part, port_part = s.rsplit(":", 1)
        if port_part.isdigit():
            return host_part, int(port_part)
        # If it's not a digit, treat whole thing as hostname (rare)
        return s, DEFAULT_PORT

    return s, DEFAULT_PORT


def detect_jenkins_and_auth(session: requests.Session, scheme: str, host: str, port: int,
                            timeout: float, verbose: bool) -> Tuple[bool, Optional[bool], str]:
    """
    Connect to the host and determine:
      - is_jenkins (bool)
      - requires_auth (True/False/None if unknown)
      - details (human readable string)
    """
    base = f"{scheme}://{host}:{port}"
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    details: List[str] = []
    is_jenkins = False
    requires_auth: Optional[bool] = None

    def do_get(path: str):
        url = base.rstrip("/") + path
        if verbose:
            print(f"> GET {url}")
        try:
            resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=False, verify=(scheme == "https"))
            if verbose:
                print(f"< {resp.status_code} {resp.reason} ({len(resp.content)} bytes)")
                for k, v in resp.headers.items():
                    print(f"  {k}: {v}")
            return resp
        except SSLError:
            raise
        except RequestException as e:
            if verbose:
                print(f"! Request failed: {e}")
            raise

    # Try /api/json first (good for detection)
    try:
        resp_api = do_get("/api/json")
    except Exception as e:
        details.append(f"Error connecting to {base}: {e}")
        return False, None, "; ".join(details)

    # Check headers for Jenkins
    xjenkins = resp_api.headers.get("X-Jenkins")
    server_hdr = resp_api.headers.get("Server", "")
    content_type = resp_api.headers.get("Content-Type", "")

    if xjenkins:
        is_jenkins = True
        details.append(f"Header X-Jenkins: {xjenkins}")

    # Status codes indicating auth/forbidden
    if resp_api.status_code in (401,):
        requires_auth = True
        details.append(f"/api/json returned {resp_api.status_code} (authentication required)")
    elif resp_api.status_code in (403,):
        # 403 could mean forbidden for anonymous -> likely requires auth
        requires_auth = True
        details.append(f"/api/json returned {resp_api.status_code} (forbidden to anonymous)")
    elif resp_api.status_code == 200:
        # Try to parse JSON to find Jenkins-specific fields
        if "application/json" in content_type or resp_api.text.strip().startswith("{"):
            try:
                j = resp_api.json()
                # Jenkins returns JSON with keys like 'mode', 'jobs', 'version' might be in headers though
                if isinstance(j, dict):
                    # presence of expected fields is a strong sign
                    if "jobs" in j or "primaryView" in j or "nodeDescription" in j or "views" in j:
                        is_jenkins = True
                        details.append("/api/json responded with Jenkins-like JSON")
                    # if anon can access JSON, probably does not require auth for basic info
                    requires_auth = False
                    details.append("/api/json accessible anonymously (200)")
            except ValueError:
                # Not valid JSON, keep going
                pass

    # If not conclusive, try root page to look for login form or Jenkins markers
    if not is_jenkins or requires_auth is None:
        try:
            resp_root = do_get("/")
        except Exception as e:
            details.append(f"Error requesting root page: {e}")
            return is_jenkins, requires_auth, "; ".join(details)

        # Redirects to login page
        if resp_root.status_code in (301, 302, 303, 307, 308):
            loc = resp_root.headers.get("Location", "")
            if "/login" in loc or "j_acegi_security" in loc:
                requires_auth = True
                details.append(f"Root redirected to login ({loc})")
            # Also a redirect might indicate Jenkins if Location contains '/jenkins' or similar
            if "jenkins" in loc.lower():
                is_jenkins = True
                details.append(f"Redirect Location suggests Jenkins: {loc}")

        # 200 OK - examine body
        if resp_root.status_code == 200:
            body = resp_root.text
            # Jenkins pages commonly include 'Jenkins' in the title or generator meta tag
            if re.search(r"<title>.*Jenkins.*</title>", body, re.I) or "window.Jenkins" in body or "jenkins-root" in body.lower():
                is_jenkins = True
                details.append("Root page contains Jenkins markers")
            # Jenkins login form uses input named 'j_username'
            if "j_username" in body or "login?from=" in body or "Sign in" in body or "sign in" in body.lower():
                requires_auth = True
                details.append("Root page contains login form or sign-in marker (j_username/login)")
            # If we saw JSON accessible above, we would have set requires_auth=False
            # If nothing indicates auth, and root is 200 and contains Jenkins markers, assume auth not required
            if is_jenkins and requires_auth is None:
                requires_auth = False
                details.append("No login marker found; assuming anonymous access permitted")

        # 401/403 at root also indicates auth
        if resp_root.status_code in (401,):
            requires_auth = True
            details.append(f"Root returned {resp_root.status_code} (authentication required)")
        if resp_root.status_code in (403,):
            requires_auth = True
            details.append(f"Root returned {resp_root.status_code} (forbidden to anonymous)")

    # If still not recognized as Jenkins, do a lightweight check of headers/body for 'Jenkins'
    if not is_jenkins:
        # check Server header
        if "jenkins" in server_hdr.lower():
            is_jenkins = True
            details.append(f"Server header contains 'jenkins': {server_hdr}")
        else:
            # Try small probe for /jnlpJars/jenkins-cli.jar which is commonly present
            try:
                resp_cli = do_get("/jnlpJars/jenkins-cli.jar")
                if resp_cli.status_code == 200 and resp_cli.headers.get("Content-Type", "").startswith("application/java-archive"):
                    is_jenkins = True
                    details.append("/jnlpJars/jenkins-cli.jar accessible")
                elif resp_cli.status_code in (401, 403):
                    # may be Jenkins but protected
                    details.append("/jnlpJars/jenkins-cli.jar returned auth/forbidden; possible Jenkins")
            except Exception:
                pass

    # Final fallback: if any Jenkins clues found in details -> set is_jenkins True
    if not is_jenkins and any("Jenkins" in d or "jenkins" in d.lower() for d in details):
        is_jenkins = True

    # If still unknown, make final note
    if not details:
        details.append("No distinguishing signs found")

    return is_jenkins, requires_auth, "; ".join(details)


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Check a list of hosts to see if Jenkins is running and whether authentication is required."
    )
    p.add_argument("hosts_file", metavar="HOSTS_FILE", help="File containing hosts (one per line: HOST or HOST:PORT).")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose: print HTTP requests and responses.")
    p.add_argument("--ssl", action="store_true", help="Use HTTPS instead of HTTP.")
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Timeout seconds per request (default {DEFAULT_TIMEOUT}).")
    p.add_argument("-n", "--threads", type=int, default=1, help="Number of worker threads to use (default 1).")

    args = p.parse_args(argv)

    scheme = "https" if args.ssl else "http"
    try:
        with open(args.hosts_file, "r", encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except OSError as e:
        print(f"Cannot open hosts file '{args.hosts_file}': {e}", file=sys.stderr)
        sys.exit(2)

    # Build a list of hosts to process (skip comments/blank lines)
    hosts: List[Tuple[str, int]] = []
    for line in raw_lines:
        parsed = parse_host_line(line)
        if parsed is None:
            continue
        host, port = parsed
        if host is None:
            continue
        hosts.append((host, port))

    if not hosts:
        print("No hosts to check.")
        return

    # Status before starting
    print(f"Will check {len(hosts)} hosts using {args.threads} thread(s).")

    if not HAS_ALIVE:
        if not args.verbose:
            # Inform user about missing progress package but don't spam if verbose (they'll see request output)
            print("Install 'alive-progress' to see a progress bar: pip install alive-progress", file=sys.stderr)

    jenkins_count = 0
    anon_count = 0
    # store tuples (host:port, manage_access: Optional[bool])
    anon_servers: List[Tuple[str, Optional[bool]]] = []

    def worker(host: str, port: int):
        """
        Worker executed in thread: create a session and call detect_jenkins_and_auth.
        Returns a tuple:
          (host, port, is_jenkins, requires_auth, details, manage_access, manage_details, error_msg)
        If error_msg is not None then the request failed.
        """
        try:
            s = requests.Session()
            s.headers.update({"User-Agent": USER_AGENT})
            is_jenkins, requires_auth, details = detect_jenkins_and_auth(s, scheme, host, port, timeout=args.timeout, verbose=args.verbose)
            manage_access: Optional[bool] = None
            manage_details = ""
            # If anonymous access allowed, check /manage/ endpoint availability
            if is_jenkins and requires_auth is False:
                try:
                    mgr_url = f"{scheme}://{host}:{port}/manage/"
                    if args.verbose:
                        print(f"> GET {mgr_url}")
                    resp = s.get(mgr_url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                                 timeout=args.timeout, allow_redirects=False, verify=(scheme == "https"))
                    if args.verbose:
                        print(f"< {resp.status_code} {resp.reason} ({len(resp.content)} bytes)")
                    if resp.status_code == 200:
                        manage_access = True
                        manage_details = "/manage/ returned 200"
                        # look for likely manage marker
                        if "Manage Jenkins" in resp.text or "Manage" in resp.text:
                            manage_details += " (contains Manage marker)"
                    elif resp.status_code in (401, 403):
                        manage_access = False
                        manage_details = f"/manage/ returned {resp.status_code} (auth required)"
                    elif resp.status_code in (301, 302, 303, 307, 308):
                        loc = resp.headers.get("Location", "")
                        if "/login" in loc or "j_acegi_security" in loc:
                            manage_access = False
                            manage_details = f"/manage/ redirected to login ({loc})"
                        else:
                            manage_access = None
                            manage_details = f"/manage/ redirected ({loc})"
                    else:
                        manage_access = None
                        manage_details = f"/manage/ returned {resp.status_code}"
                except RequestException as e:
                    manage_access = None
                    manage_details = f"Error checking /manage/: {e}"
            return host, port, is_jenkins, requires_auth, details, manage_access, manage_details, None
        except SSLError as e:
            return host, port, False, None, "", None, "", f"SSL error: {e}"
        except ConnectionError as e:
            return host, port, False, None, "", None, "", f"Connection failed: {e}"
        except Timeout:
            return host, port, False, None, "", None, "", f"Timeout after {args.timeout}s"
        except RequestException as e:
            return host, port, False, None, "", None, "", f"Request failed: {e}"
        except Exception as e:
            return host, port, False, None, "", None, "", str(e)

    # Use ThreadPoolExecutor for multi-threading (defaults to 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.threads)) as exe:
        futures = {exe.submit(worker, h, p): (h, p) for h, p in hosts}

        if HAS_ALIVE:
            with alive_bar(len(hosts), title="Scanning hosts") as bar:
                for fut in concurrent.futures.as_completed(futures):
                    host, port, is_jenkins, requires_auth, details, manage_access, manage_details, error = fut.result()
                    bar()
                    # Print errors immediately
                    if error:
                        print(f"{host}:{port} - ERROR: {error}")
                        continue
                    # Only print per-host when Jenkins found or verbose requested
                    if is_jenkins or args.verbose:
                        j_text = "Yes" if is_jenkins else "No"
                        if requires_auth is True:
                            a_text = "Required"
                            line = f"{host}:{port} - Jenkins: {j_text} - Authentication: {a_text}"
                        elif requires_auth is False:
                            a_text = "Not required"
                            # highlight anonymous servers
                            line = f"{GREEN}{BOLD}{host}:{port} - Jenkins: {j_text} - Authentication: {a_text}{RESET}"
                        else:
                            a_text = "Unknown"
                            line = f"{host}:{port} - Jenkins: {j_text} - Authentication: {a_text}"
                        print(line)
                        if args.verbose:
                            print(f"  Details: {details}")
                            if manage_access is not None or manage_details:
                                print(f"  manage/ check: {manage_access} - {manage_details}")
                        else:
                            # when not verbose, if anonymous and manage/ check produced info, show manage/ status in-line
                            if requires_auth is False:
                                mgr_txt = "unknown"
                                if manage_access is True:
                                    mgr_txt = f"{BOLD}{GREEN}manage/ accessible{RESET}"
                                elif manage_access is False:
                                    mgr_txt = f"{YELLOW}manage/ requires auth{RESET}"
                                elif manage_details:
                                    mgr_txt = manage_details
                                print(f"  -> {mgr_txt}")
                    # Update counts (done in main thread so no locks needed)
                    if is_jenkins:
                        jenkins_count += 1
                        if requires_auth is False:
                            anon_count += 1
                            anon_servers.append((f"{host}:{port}", manage_access))
        else:
            for fut in concurrent.futures.as_completed(futures):
                host, port, is_jenkins, requires_auth, details, manage_access, manage_details, error = fut.result()
                # Print errors immediately
                if error:
                    print(f"{host}:{port} - ERROR: {error}")
                    continue
                # Only print per-host when Jenkins found or verbose requested
                if is_jenkins or args.verbose:
                    j_text = "Yes" if is_jenkins else "No"
                    if requires_auth is True:
                        a_text = "Required"
                        line = f"{host}:{port} - Jenkins: {j_text} - Authentication: {a_text}"
                    elif requires_auth is False:
                        a_text = "Not required"
                        line = f"{GREEN}{BOLD}{host}:{port} - Jenkins: {j_text} - Authentication: {a_text}{RESET}"
                    else:
                        a_text = "Unknown"
                        line = f"{host}:{port} - Jenkins: {j_text} - Authentication: {a_text}"
                    print(line)
                    if args.verbose:
                        print(f"  Details: {details}")
                        if manage_access is not None or manage_details:
                            print(f"  manage/ check: {manage_access} - {manage_details}")
                    else:
                        if requires_auth is False:
                            mgr_txt = "unknown"
                            if manage_access is True:
                                mgr_txt = f"{BOLD}{GREEN}manage/ accessible{RESET}"
                            elif manage_access is False:
                                mgr_txt = f"{YELLOW}manage/ requires auth{RESET}"
                            elif manage_details:
                                mgr_txt = manage_details
                            print(f"  -> {mgr_txt}")
                # Update counts
                if is_jenkins:
                    jenkins_count += 1
                    if requires_auth is False:
                        anon_count += 1
                        anon_servers.append((f"{host}:{port}", manage_access))

    # Summary
    print()
    print("Summary:")
    print(f"  Hosts scanned: {len(hosts)}")
    print(f"  Jenkins servers found: {jenkins_count}")
    print(f"  Servers allowing anonymous access: {anon_count}")
    if anon_servers:
        print()
        print("Servers that did NOT require authentication:")
        for host_port, manage_access in anon_servers:
            if manage_access is True:
                print(f"  {GREEN}{host_port}{RESET} - manage/ accessible")
            elif manage_access is False:
                print(f"  {host_port} - manage/ requires auth")
            else:
                print(f"  {host_port} - manage/: unknown")


if __name__ == "__main__":
    main()