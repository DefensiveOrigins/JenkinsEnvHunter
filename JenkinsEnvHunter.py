import re
import requests
from requests.auth import HTTPBasicAuth

# Configuration
JENKINS_URL = "https://your-jenkins.example.com"
USERNAME = "your_username"
API_TOKEN = "your_api_token"

# Patterns to detect sensitive variable names
SENSITIVE_PATTERNS = re.compile(r"user|pass|key|auth", re.IGNORECASE)

# Session for HTTP requests (to reuse connections)
session = requests.Session()
session.auth = HTTPBasicAuth(USERNAME, API_TOKEN)
session.verify = True  # Set to False if using self-signed cert

def get_json(url):
    r = session.get(url, params={'pretty': 'true'})
    r.raise_for_status()
    return r.json()

def find_sensitive(env_vars):
    return {k: v for k, v in env_vars.items() if SENSITIVE_PATTERNS.search(k)}

def main():
    jobs = get_json(f"{JENKINS_URL}/api/json")['jobs']
    report = []

    for job in jobs:
        job_name = job['name']
        print(f"🔍 Scanning job: {job_name}")
        job_info = get_json(f"{JENKINS_URL}/job/{job_name}/api/json?depth=1")
        builds = job_info.get('builds', [])
        for build in builds:
            num = build['number']
            print(f" └ Build #{num}")
            # EnvInject stores env vars at /injectedEnvVars/export
            url = f"{JENKINS_URL}/job/{job_name}/{num}/injectedEnvVars/export"
            try:
                resp = session.get(url, headers={'Accept': 'application/json'})
                if resp.status_code == 200:
                    env = resp.json()
                else:
                    continue
            except Exception:
                continue
            sensitive = find_sensitive(env)
            if sensitive:
                report.append({
                    'job': job_name,
                    'build': num,
                    'leaks': sensitive
                })

    # Output report
    if report:
        print("\n⚠️ Sensitive env variables found:")
        for item in report:
            print(f"- {item['job']} build #{item['build']}:")
            for k in item['leaks']:
                print(f"    • {k}")
    else:
        print("\n✅ No sensitive variables detected.")

if __name__ == "__main__":
    main()
