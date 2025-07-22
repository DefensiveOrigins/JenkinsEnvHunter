#!/usr/bin/env python3
"""
JenkinsEnvHunter.py — Scan Jenkins builds for sensitive environment variables.
"""

import re
import sys
import argparse
import requests
from requests.auth import HTTPBasicAuth

DEFAULT_PATTERN = r"(user|pass|key|auth)"

def setup_parser():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-u', '--url', required=True, help='Jenkins base URL')
    parser.add_argument('-n', '--username', required=True, help='Jenkins username or API user')
    parser.add_argument('-t', '--token', required=True, help='Jenkins API token or password')
    parser.add_argument('-p', '--pattern', default=DEFAULT_PATTERN, help='Regex for sensitive var names (case-insensitive)')
    parser.add_argument('-j', '--jobs', nargs='+', help='Only scan specified jobs; default: all jobs')
    parser.add_argument('-o', '--output', help='Write report to FILE instead of console')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    return parser

def get_json(session, url):
    resp = session.get(url, params={'pretty': 'true'})
    resp.raise_for_status()
    return resp.json()

def find_sensitive(env_vars, pattern):
    regex = re.compile(pattern, re.IGNORECASE)
    return {k: v for k, v in env_vars.items() if regex.search(k)}

def scan_jobs(session, base_url, jobs_list, pattern, verbose):
    report = []
    all_jobs = get_json(session, f"{base_url}/api/json")['jobs']
    for job in all_jobs:
        name = job['name']
        if jobs_list and name not in jobs_list:
            continue
        if verbose:
            print(f"🔍 Scanning job: {name}")
        job_info = get_json(session, f"{base_url}/job/{name}/api/json?depth=1")
        for build in job_info.get('builds', []):
            num = build['number']
            if verbose:
                print(f" └ Build #{num}")
            url = f"{base_url}/job/{name}/{num}/injectedEnvVars/export"
            resp = session.get(url, headers={'Accept': 'application/json'})
            if resp.status_code != 200:
                continue
            env = resp.json()
            leaks = find_sensitive(env, pattern)
            if leaks:
                report.append({'job': name, 'build': num, 'leaks': leaks})
    return report

def generate_report(report):
    lines = []
    if report:
        lines.append("⚠️ Sensitive env variables found:")
        for item in report:
            lines.append(f"- {item['job']} build #{item['build']}:")
            for k in item['leaks']:
                lines.append(f"    • {k}")
    else:
        lines.append("✅ No sensitive variables detected.")
    return "\n".join(lines)

def main():
    parser = setup_parser()
    args = parser.parse_args()

    session = requests.Session()
    session.auth = HTTPBasicAuth(args.username, args.token)
    session.verify = True

    try:
        report = scan_jobs(session, args.url, args.jobs, args.pattern, args.verbose)
    except Exception as e:
        print(f"❌ Scan error: {e}", file=sys.stderr)
        sys.exit(1)

    output_text = generate_report(report)

    # Write to file if specified, else to stdout
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_text + "\n")
        print(f"📝 Report written to {args.output}")
    else:
        print(output_text)

if __name__ == "__main__":
    main()
