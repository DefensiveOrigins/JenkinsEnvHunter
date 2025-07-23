Scan Jenkins builds for sensitive environment variables

# Overview
JenkinsEnvHunter.py inspects all  Jenkins jobs and builds, fetches their environment variables (including those from EnvInject), and searches for potentially sensitive keys such as user, pass, key, auth, etc.

# Features
Scans all Jenkins jobs and builds

Searches environment variable names using a customizable regex

Supports verbose console output for real-time progress

Allows saving scan reports to a file

# Usage

## No Auth Required
```
## Hunt for sensistive env vars and save to file, and be less noisy
python JenkinsEnvHunter.py -url <JENKINS_URL> --output file.txt --quiet

## capture all env vars and save to file and be less noisy
python JenkinsEnvHunter.py -url --all --output file.txt --quiet

## get it all, and be talkative about it (All envs goto file.txt. Sensistive goto stdout)
python JenkinsEnvHunter.py -url --all --output file.txt 
```

## Requires Auth:
```
## capture all env vars and save to file
python JenkinsEnvHunter.py -url <JENKINS_URL> -n <USERNAME> -t <API_TOKEN>  --output file.txt --all
```

Options
```
-u, --url         Jenkins base URL (e.g. https://jenkins.local)

-n, --username   Jenkins username or API user

-t, --token      Jenkins API token or password

--output         Save the report to a file (default: print to console)

-h, --help       Display help message and exit

--all            Gather all environment variables, not just sensitive
```

# Examples
```
# Scan entire Jenkins instance:
python JenkinsEnvHunter.py -url https://jenkins.local 

```

# Why use this?
Storing credentials in environment variables is risky. This tool helps:

Audit usage of sensitive keys across builds

Detect accidental leaks early in the pipeline

Encourage use of secure Jenkins credentials management

Parallel scanning support

