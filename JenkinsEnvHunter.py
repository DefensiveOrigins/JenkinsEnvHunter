import requests
import re
import argparse
from urllib.parse import urljoin
from alive_progress import alive_bar

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
    parser.add_argument("--quiet", action="store_true", help="Cuts the verbosity (optional)")
    parser.add_argument("--all", action="store_true", help="Include all environment variables, not just sensitive ones")
    args = parser.parse_args()

    auth_provided = (args.user, args.token) if args.user and args.token else None
    output_file = args.output

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Jenkins Build Environment Variables Report\n")
            f.write("=" * 60 + "\n\n")

    seen_values = set()
    total_sensitive_vars = 0
    total_env_vars = 0
    builds_with_sensitive = 0
    k=""
    job_count=0
    build_count=0
    jobs = get_all_jobs(args.url, auth_provided)
    for job in jobs:
        job_name = job["name"]
        job_url = job["url"]
        builds = get_builds_for_job(job_url, auth_provided)
        job_count=job_count+1
        if not args.quiet: print(f"\n[+] Scanning job: {job_name} ({len(builds)} builds)")
        with alive_bar(len(builds), title=f"Scanning {job_name[:40].ljust(40)}",length=10,theme='smooth',spinner=None,dual_line=True,monitor="Build {count} / {total} ") as bar:
            for build in builds:
                build_url = build["url"]
                build_number = build.get("number", "?")
                build_count=build_count+1
                if args.quiet: bar.text(f"\t Total Sensitive EnvVars Discovered: {total_sensitive_vars} -- Unique: {len(seen_values)} --  Jobs: {job_count}/{len(jobs)} -- Builds: {build_count} ")
                if not args.quiet: bar.text(f"\t -> Job: {job_name}  \t Build: {build_number}. **TTL Sensitive EV: {total_sensitive_vars} -- Total Unique:{len(seen_values)}")
                env_vars = get_env_vars(build_url, auth_provided)
                findings = scan_env_vars(env_vars)
                vars_to_report = env_vars if args.all else findings

                if findings:
                    total_sensitive_vars += len(findings)
                    builds_with_sensitive += 1

                if args.all:
                    total_env_vars += len(env_vars)

                # Print only newly discovered values
                for k, v in vars_to_report.items():
                    value_id = f"{k}={v}"
                    if value_id not in seen_values:
                        seen_values.add(value_id)
                        if not args.quiet: print(f"\t \033[1m [+] New value discovered: {k} = \033[0m {v}\n")
                if vars_to_report and output_file:
                    write_finding(output_file, build_url, vars_to_report)

                bar()

    print("\n[✓] Scan complete.")
    print(f"    Total Jobs {len(jobs)}      Total Builds {build_count}")
    print(f"    Builds with sensitive data: {builds_with_sensitive}")
    print(f"    Total sensitive vars found: {total_sensitive_vars}")
    if args.all:
        print(f"    Total environment vars seen: {total_env_vars}")
    print(f"    Unique values discovered: {len(seen_values)}")
    if output_file:
        print(f"    Variables Saved To: {output_file}")

if __name__ == "__main__":
    main()
