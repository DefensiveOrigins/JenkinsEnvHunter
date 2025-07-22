Scan Jenkins builds for sensitive environment variables

# Overview
JenkinsEnvHunter.py inspects all (or selected) Jenkins jobs and builds, fetches their environment variables (including those from EnvInject), and searches for potentially sensitive keys such as user, pass, key, auth, etc.

# Features
Scans all Jenkins jobs or a specified subset

Searches environment variable names using a customizable regex

Supports verbose console output for real-time progress

Allows saving scan reports to a file

# 
Usage
```
python JenkinsEnvHunter.py -u <JENKINS_URL> -n <USERNAME> -t <API_TOKEN> [-p "<pattern>"] [-j job1 job2 ...] [-o report.txt] [-v]
```

Options
-u, --url         Jenkins base URL (e.g. https://jenkins.local)

-n, --username   Jenkins username or API user

-t, --token       Jenkins API token or password

-p, --pattern     Regex for matching env var names (default: (user|pass|key|auth))

-j, --jobs       List of specific jobs to scan (default: all jobs)

-o, --output   Save the report to a file (default: print to console)

-v, --verbose   Show detailed progress in the console

-h, --help      Display help message and exit

# Examples
```
# Scan entire Jenkins instance:
python JenkinsEnvHunter.py -u https://jenkins.local -n admin -t SECRET_TOKEN

# Scan specific jobs and output to a file:
python JenkinsEnvHunter.py -u … -n … -t … -j deploy build-test -o scan_report.txt -v

# Use a custom search pattern:
python JenkinsEnvHunter.py -u … -n … -t … -p "(secret|token|credential)"
```

# Why use this?
Storing credentials in environment variables is risky. This tool helps:

Audit usage of sensitive keys across builds

Detect accidental leaks early in the pipeline

Encourage use of secure Jenkins credentials management

Parallel scanning support

