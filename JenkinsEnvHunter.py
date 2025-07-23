import requests
import re
import argparse
from urllib.parse import urljoin

SENSITIVE_KEYS = re.compile(r"(user|pass|key|auth|token|secret)", re.IGNORECASE)

def get_all_jobs(base_url, auth_provided):
    api_url = urljoin(base_url, "/api/json?tree=jobs[name,url]")
    response = requests.get(api_url, auth=auth_provided) if auth_provided else requests.get(api_url)
    response.raise_for_status()
    return response.json().get("jobs", [])

def get_builds_for_job(job_url, auth_provided):
    api_url = urljoin(job_url, "api/json?tree=builds[number,url]")
    response = requests.get(api_url, auth=auth_provided) if auth_provided else requests.get(api_url)
    response.raise_for_status()
    return response.json().get("builds", [])

def get_env_vars(build_url, auth_provided):
    env_url = urljoin(build_url, "injectedEnvVars/api/json")
    try:
        response = requests.get(env_url, auth=auth_provided) if auth_provided else requests.get(env_url)
        if response.status_code != 200:
            return {}
        return response.json().get("envMap", {})
    except requests.RequestException:
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
    parser = argparse.ArgumentParser(description="Scan Jenkins builds for environment variables.")
    parser.add_argument("--url", required=True, help="Base URL of Jenkins (e.g., http://jenkins.local/)")
    parser.add_argument("--user", help="Jenkins username (optional)")
    parser.add_argument("--token", help="Jenkins API token or password (optional)")
    parser.add_argument("--output", help="Output file path (optional)")
    parser.add_argument("--all", action="store_true", help="Include all environment variables, not just sensitive ones")
    args = parser.parse_args()

    auth_provided = (args.user, args.token) if args.user and args.token else None
    output_file = args.output

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Jenkins Build Environment Variables Report\n")
            f.write("=" * 60 + "\n\n")

    seen_values = set()
    jobs = get_all_jobs(args.url, auth_provided)
    for job in jobs:
        job_name = job["name"]
        job_url = job["url"]
        builds = get_builds_for_job(job_url, auth_provided)

        for build in builds:
            build_url = build["url"]
            build_number = build.get("number", "?")
            print(f"Scanning: {job_name} #{build_number}")

            env_vars = get_env_vars(build_url, auth_provided)
            findings = scan_env_vars(env_vars)
            vars_to_report = env_vars if args.all else findings

            if vars_to_report:
                print(f"✓ {len(vars_to_report)} {'total' if args.all else 'sensitive'} vars")

                for k, v in vars_to_report.items():
                    value_id = f"{k}={v}"
                    if value_id not in seen_values:
                        seen_values.add(value_id)
                        print(f" [+] New value discovered: {k} = {v}")

                if output_file:
                    write_finding(output_file, build_url, vars_to_report)

if __name__ == "__main__":
    main()
