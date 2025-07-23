Scan Jenkins builds for sensitive environment variables

# Overview
JenkinsEnvHunter.py inspects all  Jenkins jobs and builds, fetches their environment variables (including those from EnvInject), and searches for potentially sensitive keys such as user, pass, key, auth, etc.

# Features
Scans all Jenkins jobs and builds

Searches environment variable names using a customizable regex

Supports verbose console output for real-time progress

Allows saving scan reports to a file

## Note: 
I didn't have a great way to test all the diferent authentication types.  If it doesn't work, please make a pull request

# Usage

## No Auth Required
```
## Hunt for sensistive env vars and save to file, and be less noisy
python JenkinsEnvHunter.py -url <JENKINS_URL> --output file.txt --quiet

## capture all env vars and save to file and be less noisy
python JenkinsEnvHunter.py -url <JENKINS_URL> --all --output file.txt --quiet

## get it all, and be talkative about it (All envs goto file.txt. Sensistive goto stdout)
python JenkinsEnvHunter.py -url <JENKINS_URL> --all --output file.txt 
```

## Requires Auth:
```
## capture all env vars and save to file
python JenkinsEnvHunter.py -url <JENKINS_URL> --user <USERNAME> --token <API_TOKEN>  --output file.txt --all
```

Options
```
--url         Jenkins base URL (e.g. https://jenkins.local)

--user   Jenkins username or API user

--token      Jenkins API token or password

--output         Save the report to a file (default: print to console)

--help       Display help message and exit

--all            Gather all environment variables, not just sensitive
```

# Examples
```
# Scan entire Jenkins instance:
python JenkinsEnvHunter.py -url https://jenkins.local 

```



