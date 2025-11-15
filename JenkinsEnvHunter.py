import requests
import re
import argparse
from urllib.parse import urljoin, urlparse, urlunparse
from alive_progress import alive_bar
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

SENSITIVE_KEYS = re.compile(r"(user|pass|key|auth|token|secret|cookie|cred)", re.IGNORECASE)
VERBOSE = False
QUIET = False
ERRORS = []
NO_REDIRECT = False
ORIGINAL_BASE = None

# Counter and lock for builds that failed variable enumeration
BUILD_ENUM_FAILS = 0
BUILD_ENUM_LOCK = threading.Lock()

def _ensure_trailing_slash(url: str) -> str:
    return url if url.endswith('/') else url + '/'

def _apply_no_redirect(target_url: str) -> str:
    """
    When NO_REDIRECT is enabled, ensure subsequent requests remain on the
    originally-provided host:port and do not retain any redirect-added
    subfolder while still preserving the meaningful resource suffix
    (e.g. '/job/...', '/api/...').

    Strategy:
      - Replace scheme+netloc with ORIGINAL_BASE's scheme+netloc.
      - Try to detect a meaningful resource segment in the target path:
          1. '/job/'  (job/build paths)
          2. '/api/'  (API endpoints)
      - If found, append the suffix from that resource segment to the
        ORIGINAL_BASE.path. This removes any redirect-added subfolder but
        preserves the actual resource (api/json, job/...).
      - If no resource segment is found, fall back to ORIGINAL_BASE.path.
    """
    if not NO_REDIRECT or not ORIGINAL_BASE:
        return target_url
    try:
        pt = urlparse(target_url)
        pb = urlparse(ORIGINAL_BASE)

        # look for known resource anchors in the redirected path
        resource_idx = -1
        for anchor in ('/job/', '/api/'):
            idx = pt.path.find(anchor)
            if idx != -1:
                resource_idx = idx
                break

        if resource_idx != -1:
            # Preserve ORIGINAL_BASE.path and append the meaningful suffix
            suffix = pt.path[resource_idx:]
            if pb.path and pb.path != '/':
                new_path = pb.path.rstrip('/') + suffix
            else:
                new_path = suffix
        else:
            # No resource anchor found — use ORIGINAL_BASE path (avoid keeping redirect subfolder)
            new_path = pb.path if pb.path else '/'

        replaced = pt._replace(scheme=pb.scheme, netloc=pb.netloc, path=new_path)
        # preserve query/fragment from the target if present
        return urlunparse(replaced)
    except Exception:
        return target_url

def _record_error(message: str, details: str = None):
    # store concise message plus optional details for verbose output
    ERRORS.append((message, details))
    # Always show a short message unless the user asked for quiet
    if not QUIET:
        print(f"[!] {message}")
    # If verbose, show details (exception text / response body)
    if VERBOSE and details:
        print(f"    -> {details}")

def get_all_jobs(base_url, auth_provided):
    base = _ensure_trailing_slash(base_url)
    api_url = urljoin(base, "api/json?tree=jobs[name,url]")
    req_url = _apply_no_redirect(api_url)
    if VERBOSE:
        note = f" (modified to {req_url})" if req_url != api_url else ""
        print(f"[HTTP] GET {req_url}{note}")
    try:
        response = requests.get(req_url, auth=auth_provided, allow_redirects=not NO_REDIRECT)
        if VERBOSE:
            print(f"[HTTP] {response.status_code} {req_url}")
        if response.status_code != 200:
            _record_error(f"Failed to fetch jobs from {req_url} (HTTP {response.status_code})",
                          response.text[:1000] if VERBOSE else None)
            return []
        return response.json().get("jobs", [])
    except requests.RequestException as e:
        _record_error(f"Error fetching jobs from {req_url}: {e}", repr(e))
        return []

def get_builds_for_job(job_url, auth_provided):
    job_base = _ensure_trailing_slash(job_url)
    api_url = urljoin(job_base, "api/json?tree=builds[number,url]")
    req_url = _apply_no_redirect(api_url)
    if VERBOSE:
        note = f" (modified to {req_url})" if req_url != api_url else ""
        print(f"[HTTP] GET {req_url}{note}")
    try:
        response = requests.get(req_url, auth=auth_provided, allow_redirects=not NO_REDIRECT)
        if VERBOSE:
            print(f"[HTTP] {response.status_code} {req_url}")
        if response.status_code != 200:
            _record_error(f"Failed to fetch builds for job {job_url} (HTTP {response.status_code})",
                          response.text[:1000] if VERBOSE else None)
            return []
        return response.json().get("builds", [])
    except requests.RequestException as e:
        _record_error(f"Error fetching builds for job {job_url}: {e}", repr(e))
        return []

def get_env_vars(build_url, auth_provided):
    """
    Fetch environment variables for a build.

    Behavior change:
      - Track failures in BUILD_ENUM_FAILS.
      - Suppress detailed HTTP error messages (like '(HTTP 404)') unless VERBOSE is enabled.
      - When not VERBOSE, still increment failure counter but only show a short notice
        (unless QUIET). Full details are recorded only when VERBOSE.
    """
    global BUILD_ENUM_FAILS
    build_base = _ensure_trailing_slash(build_url)
    env_url = urljoin(build_base, "injectedEnvVars/api/json")
    req_url = _apply_no_redirect(env_url)
    if VERBOSE:
        note = f" (modified to {req_url})" if req_url != env_url else ""
        print(f"[HTTP] GET {req_url}{note}")
    try:
        response = requests.get(req_url, auth=auth_provided, allow_redirects=not NO_REDIRECT)
        if VERBOSE:
            print(f"[HTTP] {response.status_code} {req_url}")
        if response.status_code != 200:
            # increment failure counter (thread-safe)
            with BUILD_ENUM_LOCK:
                BUILD_ENUM_FAILS += 1

            if VERBOSE:
                # record full details when verbose
                _record_error(f"Failed to fetch env vars for build {build_url} (HTTP {response.status_code})",
                              response.text[:1000] if response.text else repr(response))
            return {}
        return response.json().get("envMap", {})
    except requests.RequestException as e:
        # increment failure counter (thread-safe)
        with BUILD_ENUM_LOCK:
            BUILD_ENUM_FAILS += 1

        if VERBOSE:
            _record_error(f"Error fetching env vars for build {build_url}: {e}", repr(e))
        else:
            if not QUIET:
                print(f"[!] Error fetching env vars for build: {build_url}")
        return {}

def scan_env_vars(env_vars):
    findings = {}
    for key, value in env_vars.items():
        if SENSITIVE_KEYS.search(key) or SENSITIVE_KEYS.search(str(value)):
            findings[key] = value
    return findings

def write_finding(output_file, build_url, vars_to_write):
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"[!] Environment variables in build: {build_url}\n")
        for k, v in vars_to_write.items():
            f.write(f"    {k}: {v}\n")
        f.write("\n")

def main():
    global VERBOSE, QUIET, ERRORS, NO_REDIRECT, ORIGINAL_BASE, BUILD_ENUM_FAILS
    parser = argparse.ArgumentParser(description="Scan Jenkins builds for environment variables.")
    parser.add_argument("--url", required=True, help="Base URL of Jenkins (e.g., http://jenkins.local/)")
    parser.add_argument("--user", help="Jenkins username (optional)")
    parser.add_argument("--token", help="Jenkins API token or password (optional)")
    parser.add_argument("--output", help="Output file path (optional)")
    parser.add_argument("--quiet", action="store_true", help="Cuts the verbosity (optional)")
    parser.add_argument("--all", action="store_true", help="Include all environment variables, not just sensitive ones")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show HTTP request/response info (for troubleshooting)")
    parser.add_argument("--noredirect", action="store_true", help="Do not follow redirects and keep requests on the original host:port")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads to use (default: 8)")
    args = parser.parse_args()

    VERBOSE = args.verbose
    QUIET = args.quiet
    NO_REDIRECT = args.noredirect
    ERRORS = []
    ORIGINAL_BASE = _ensure_trailing_slash(args.url)

    auth_provided = (args.user, args.token) if args.user and args.token else None
    output_file = args.output
    max_workers = max(1, args.threads)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Jenkins Build Environment Variables Report\n")
            f.write("=" * 60 + "\n\n")

    if not QUIET:
        print(f"\n[+] Jobs to investigate: (resolving...)")

    seen_values = set()
    total_sensitive_vars = 0
    total_env_vars = 0
    builds_with_sensitive = 0
    k = ""
    job_count = 0
    build_count = 0

    # Threading synchronization primitives
    stats_lock = threading.Lock()
    io_lock = threading.Lock()

    jobs = get_all_jobs(args.url, auth_provided)

    # show the number of jobs that will be investigated before scanning begins
    if not QUIET:
        print(f"\n[+] Jobs to investigate: {len(jobs)}")
        if NO_REDIRECT:
            print("[i] --noredirect enabled: requests will stay on the original host:port")
        if max_workers > 1:
            print(f"[i] Using up to {max_workers} threads for build scanning.")

    # Fetch builds for every job in parallel (so job discovery/build listing is concurrent)
    job_builds = []  # list of tuples (job_index, job_name, build)
    if jobs:
        def _fetch_builds_for_job(idx, job):
            job_name = job.get("name", "")
            job_url = job.get("url", "")
            try:
                builds = get_builds_for_job(job_url, auth_provided)
                return (idx, job_name, builds)
            except Exception as e:
                _record_error(f"Exception fetching builds for job {job_name} ({job_url}): {e}", repr(e))
                return (idx, job_name, [])

        # Use a progress bar for the job-discovery phase (less noisy).
        if not QUIET:
            with ThreadPoolExecutor(max_workers=max_workers) as job_executor:
                future_to_idx = {
                    job_executor.submit(_fetch_builds_for_job, idx, job): idx
                    for idx, job in enumerate(jobs, start=1)
                }
                with alive_bar(len(jobs), title="Locating builds", length=10, theme='smooth', spinner=None, dual_line=True, monitor="Job {count} / {total} ") as job_bar:
                    builds_located = 0
                    for future in as_completed(future_to_idx):
                        try:
                            idx, job_name, builds = future.result()
                        except Exception as e:
                            _record_error(f"Worker raised exception fetching job builds: {e}", repr(e))
                            # advance the progress bar even on error
                            job_bar()
                            continue

                        # Append builds to global list (main thread)
                        for build in builds:
                            job_builds.append((idx, job_name, build))
                        builds_located = len(job_builds)

                        # update counts and bar text, then advance bar
                        job_count += 1
                        job_bar.text(f"Builds located for inspection: {builds_located}")
                        job_bar()
        else:
            # QUIET mode: fetch builds in parallel but don't show a progress bar
            with ThreadPoolExecutor(max_workers=max_workers) as job_executor:
                futures = [
                    job_executor.submit(_fetch_builds_for_job, idx, job)
                    for idx, job in enumerate(jobs, start=1)
                ]
                for future in as_completed(futures):
                    try:
                        idx, job_name, builds = future.result()
                    except Exception as e:
                        _record_error(f"Worker raised exception fetching job builds: {e}", repr(e))
                        continue
                    for build in builds:
                        job_builds.append((idx, job_name, build))

    total_builds = len(job_builds)

    if total_builds == 0:
        if not QUIET:
            print("\n[!] No builds found to scan.")
    else:
        # Worker - processes a single build
        def _process_build(job_idx, job_name, build):
            nonlocal total_sensitive_vars, total_env_vars, builds_with_sensitive, build_count
            build_url = build["url"]
            build_number = build.get("number", "?")
            try:
                env_vars = get_env_vars(build_url, auth_provided)
                findings = scan_env_vars(env_vars)
                vars_to_report = env_vars if args.all else findings

                with stats_lock:
                    build_count += 1
                    if findings:
                        total_sensitive_vars += len(findings)
                        builds_with_sensitive += 1
                    if args.all:
                        total_env_vars += len(env_vars)

                # Print only newly discovered values (synchronized)
                new_values = []
                with stats_lock:
                    for kk, vv in vars_to_report.items():
                        value_id = f"{kk}={vv}"
                        if value_id not in seen_values:
                            seen_values.add(value_id)
                            new_values.append((kk, vv))

                if new_values:
                    with io_lock:
                        for kk, vv in new_values:
                            if not QUIET:
                                print(f"\t \033[1m [+] New value discovered in job '{job_name}' (build #{build_number}): {kk} = \033[0m {vv}\n")

                if vars_to_report and output_file:
                    # serialize file writes
                    with io_lock:
                        write_finding(output_file, build_url, vars_to_report)

            except Exception as e:
                _record_error(f"Exception processing build {build_url}: {e}", repr(e))
                # swallow exception so thread pool can continue

        # Submit all builds to the thread pool and update a single global progress bar as tasks complete.
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_build = {
                executor.submit(_process_build, jb[0], jb[1], jb[2]): jb for jb in job_builds
            }
            with alive_bar(total_builds, title="Scanning builds", length=10, theme='smooth', spinner=None, dual_line=True, monitor="Build {count} / {total} ") as bar:
                for future in as_completed(future_to_build):
                    # if there was an exception it was already recorded in _process_build via _record_error
                    try:
                        future.result()
                    except Exception as e:
                        # record any unexpected exception
                        _record_error(f"Worker raised exception: {e}", repr(e))
                    # update global progress bar and optionally its text
                    with io_lock:
                        bar.text(f"\t Total Sensitive EnvVars Discovered: {total_sensitive_vars} -- Unique: {len(seen_values)} -- Jobs: {len(jobs)} -- Builds processed: {build_count}/{total_builds}")
                    bar()

    # Summary
    print("\n[✓] Scan complete.")
    print(f"    Total Jobs {len(jobs)}      Total Builds {build_count}")
    print(f"    Builds with sensitive data: {builds_with_sensitive}")
    print(f"    Total sensitive vars found: {total_sensitive_vars}")
    # show how many builds failed variable enumeration
    print(f"    Builds failed env enumeration: {BUILD_ENUM_FAILS}")
    if args.all:
        print(f"    Total environment vars seen: {total_env_vars}")
    print(f"    Unique values discovered: {len(seen_values)}")
    if output_file:
        print(f"    Variables Saved To: {output_file}")

    # Print concise error summary at end (unless quiet). Details already printed when VERBOSE.
    if ERRORS and not QUIET:
        print(f"\n[!] {len(ERRORS)} HTTP error(s) encountered during the scan:")
        for idx, (msg, details) in enumerate(ERRORS, 1):
            print(f"    {idx}. {msg}")
            if VERBOSE and details:
                print(f"        Details: {details}")

if __name__ == "__main__":
    main()
