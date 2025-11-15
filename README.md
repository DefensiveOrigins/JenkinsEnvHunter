# JenkinsEnvHunter & CheckNoAuth

This repository contains two helper scripts for inspecting Jenkins instances:

- `JenkinsEnvHunter.py` — enumerates Jenkins jobs and builds, fetches environment variables (including EnvInject), and highlights likely sensitive keys.
- `CheckNoAuth.py` — scans a list of hosts (or a Nessus `.nessus` export) to detect Jenkins instances and whether anonymous access is allowed.

Only run these scripts against systems you own or have explicit permission to test.

## Install from PIP:

``` 
pip install jenkinsenvhunter    
```

Then:

```
jenkins-env-hunter --help
jenkins-check-noauth --help
```

## Requirements

- Python 3.7+
- `requests` (required)
- `alive-progress` (optional, progress bars)




## Install dependencies (if from git clone)

```
pip install requests alive-progress
```

---

## CheckNoAuth.py & jenkins-check-noauth

Purpose: quickly determine which hosts are running Jenkins and whether anonymous access is allowed. The script can also extract hosts from Nessus `.nessus` exports (plugin 65054).

Usage examples (Python and PIP versions listed)
```
# Scan hosts listed in hosts.txt using HTTP
python CheckNoAuth.py -f hosts.txt
jenkins-check-noauth -f hosts.txt

# Scan hosts using HTTPS and 4 threads
python CheckNoAuth.py -f hosts.txt --ssl -n 4
jenkins-check-noauth -f hosts.txt --ssl -n 4

# Extract Jenkins hosts from a Nessus export and scan them
python CheckNoAuth.py -x scan.nessus
jenkins-check-noauth -x scan.nessus

# Verbose output for troubleshooting a single host
python CheckNoAuth.py -f single-host.example.local:8080 -v
jenkins-check-noauth -f single-host.example.local:8080 -v
```

Options summary
```
-f, --file       File with hosts (one per line: HOST, HOST:PORT, http://host:port, [::1]:8080)
-x, --nessus     Nessus .nessus file - extract Jenkins hosts from plugin 65054
-v, --verbose    Print HTTP requests/responses (debug)
--ssl            Use HTTPS (default is HTTP)
-t, --timeout    Request timeout seconds (default: 5)
-n, --threads    Worker threads (default: 1)
```

Output
- Per-host lines indicate whether Jenkins was detected and whether authentication appears required.
- When anonymous access is detected, the script attempts to check `/manage/` and reports its accessibility.
- A final summary lists counts and servers allowing anonymous access.

| ![Check No Auth](images/CheckNoAuth.png) |
|------------------------------------|


---

## JenkinsEnvHunter.py & jenkins-env-hunter

Purpose: enumerate Jenkins jobs and builds and fetch environment variables. Finds likely sensitive variables by default (regex matching `user|pass|key|auth|token|secret`) and can save results to a file.

Usage examples
```
# Scan a Jenkins instance (no auth) and print findings to console
python JenkinsEnvHunter.py --url http://jenkins.example.local/
jenkins-env-hunter --url http://jenkins.example.local/

# Scan and save results to a file
python JenkinsEnvHunter.py --url http://jenkins.example.local/ --output findings.txt
jenkins-env-hunter --url http://jenkins.example.local/ --output findings.txt

# Scan using credentials (authenticated Jenkins)
python JenkinsEnvHunter.py --url https://jenkins.example.local/ --user alice --token myapitoken --output findings.txt
jenkins-env-hunter --url https://jenkins.example.local/ --user alice --token myapitoken --output findings.txt

# Include all environment variables (not only flagged ones)
python JenkinsEnvHunter.py --url http://jenkins.example.local/ --all
jenkins-env-hunter --url http://jenkins.example.local/ --all
```

Options summary
```
--url        Jenkins base URL (required), e.g. http://jenkins.example.local/
--user       Jenkins username (optional)
--token      Jenkins API token or password (optional)
--output     Save findings to a file (optional)
--all        Include all environment variables (not just suspicious ones)
--quiet      Reduce console output
-v, --verbose  Show HTTP request/response info (troubleshooting)
--noredirect   Keep requests on the original host:port (useful when proxied)
--threads    Number of worker threads (default: 8)
```

| ![Env Vars](images/EnvVars.png) |
|-------------------------------|

Notes
- Default sensitive-key matcher is `re.compile(r"(user|pass|key|auth|token|secret)", re.IGNORECASE)`. Edit `JenkinsEnvHunter.py` to change matching rules.
- Use `--noredirect` to avoid following redirects that change host/path in reverse-proxied environments.
- When using `--output`, findings are appended to the specified file.

---


## Example workflow

1. Discover potentially anonymous Jenkins servers:
```
python CheckNoAuth.py -f hosts.txt -n 8
jenkins-check-noauth -f hosts.txt -n 8
```

2. For a discovered server that allows anonymous access, run a targeted environment scan:
```
python JenkinsEnvHunter.py --url http://jenkins.example.local/ --output scan_report.txt
jenkins-env-hunter --url http://jenkins.example.local/ --output scan_report.txt
```

---

## Security & Responsible Use

Only run these tools against systems you own or are authorized to test. Do not attempt to access, enumerate, or exploit services without explicit permission.

---

## Contributing

If you find detection gaps or want to improve regex rules or parsing logic, please open a pull request with non-sensitive test cases or sample output.



