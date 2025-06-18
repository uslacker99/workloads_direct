# Illumio Workload Rules Extractor

This Python script connects to an Illumio Policy Compute Engine (PCE) to fetch rulesets asynchronously using the `Prefer: respond-async` header, identifies security policy rules that directly reference workloads in the `consumers` field, and exports the results to a CSV file. It is designed for auditing Illumio security policies to identify rules with specific workload references.

## Features
- Connects to an Illumio PCE using the `illumio` Python SDK.
- Fetches rulesets asynchronously with the `Prefer: respond-async` header, falling back to synchronous responses if async is unsupported.
- Configurable timeout (default: 5 minutes), async polling interval (default: 5 seconds), connection retries (default: 2), and max polling attempts (default: 60).
- Extracts rules with workloads in the `consumers` field, including details like ruleset name, rule href, providers, consumers, and ingress services.
- Exports results to `workload_rules.csv` with detailed rule information.
- Provides comprehensive logging (`pce_errors.log`) for debugging, including PCE configuration, async job status, ruleset structures, and errors.

## Prerequisites
- **Python**: Version 3.6 or higher.
- **Illumio PCE**: Access to a PCE instance (e.g., `https://pce.shocknetwork.com:8443`) with valid API credentials and support for async API calls.
- **Python Packages**:
  - `illumio`: Illumio Python SDK (`pip install illumio`).
  - `python-dotenv`: For loading environment variables (`pip install python-dotenv`).
- **PCE API Credentials**: API key and secret with permissions to read rulesets (`/sec_policy/draft/rule_sets`).
- **Network Access**: Outbound HTTPS access to the PCE hostname and port.

## Installation
1. **Clone or Download the Script**:
   - Save `workloads_directly_in_rules.py` to your working directory (e.g., `illumio-rule_analysis_shocknetwork`).

2. **Set Up a Virtual Environment** (recommended):
   ```bash
   python3 -m venv venvs
   source venvs/bin/activate  # On Windows: venvs\Scripts\activate

    Install Dependencies:
    bash

    pip install illumio python-dotenv

    Verify Illumio SDK Version:
    bash

    pip show illumio

    Update if outdated:
    bash

    pip install --upgrade illumio
```
Configuration

    Create a .env File:
        Create a .env file in the script’s directory with the following content:
        env
```
        PCE_HOST=https://pce.shocknetwork.com
        PCE_PORT=8443
        PCE_ORG_ID=1
        PCE_API_KEY=api_xxxxxxxxxxxxxxxx
        PCE_API_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
        PCE_DISABLE_TLS=False
        PCE_API_VERSION=v2
        PCE_RULESETS_TIMEOUT=300
        PCE_ASYNC_POLL_INTERVAL=5
        PCE_MAX_RETRIES=2
        PCE_MAX_POLL_ATTEMPTS=60
```
        Replace values with your PCE details:
            PCE_HOST: PCE hostname (e.g., https://pce.shocknetwork.com).
            PCE_PORT: PCE port (e.g., 8443 or 443).
            PCE_ORG_ID: Organization ID (e.g., 1). Confirm with your PCE administrator.
            PCE_API_KEY and PCE_API_SECRET: API credentials from the PCE.
            PCE_DISABLE_TLS: Set to False for secure connections (recommended). Use True only for self-signed certificates (insecure).
            PCE_API_VERSION: API version (e.g., v2 for /api/v2).
            PCE_RULESETS_TIMEOUT: Timeout for API calls in seconds (default: 300 for 5 minutes). Avoid values above 600 unless necessary.
            PCE_ASYNC_POLL_INTERVAL: Polling interval for async jobs in seconds (default: 5).
            PCE_MAX_RETRIES: Number of connection retries (default: 2).
            PCE_MAX_POLL_ATTEMPTS: Maximum async job polling attempts (default: 60, ~5 minutes with 5-second intervals).
    TLS Certificate Setup (if PCE_DISABLE_TLS=False):
        Obtain the PCE’s SSL certificate from your administrator or export it from a browser.
        Save it (e.g., pce_cert.pem) in the script’s directory.
        Add to .env:
        env
```
        REQUESTS_CA_BUNDLE=/path/to/pce_cert.pem
```
        Or set the environment variable:
        bash
```
        export REQUESTS_CA_BUNDLE=/path/to/pce_cert.pem
```
    Verify PCE Access:
        Test connectivity and credentials:
```        bash

        curl -u "<api_key>:<api_secret>" -H "Prefer: respond-async" https://pce.shocknetwork.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets
```
        If SSL errors occur, use -k temporarily (insecure):
        bash
```
        curl -k -u "<api_key>:<api_secret>" -H "Prefer: respond-async" https://pce.shocknetwork.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets
```
        Expected response: 202 Accepted with a Location header (async) or 200 OK (synchronous). If it fails, check .env settings or network connectivity.

Usage

    Run the Script:
        Activate the virtual environment:
```        bash

        source venvs/bin/activate

        Execute:
        bash

        python3 workloads_directly_in_rules.py
```
    Expected Output:
        Console:

        PCE base URL: https://pce.shocknetwork.com:8443/api/v2
        Successfully connected to PCE at https://pce.shocknetwork.com:8443
        Retrieved <n> rulesets from PCE
        Workload rules written to workload_rules.csv

        Or, if no workload rules exist:

        No rules with workloads found.

        Output file: workload_rules.csv (if workload rules are found).
        Log file: pce_errors.log with detailed debug information.
    Output CSV Format:
        Columns:
            Ruleset Href: Ruleset URL (e.g., /orgs/1/sec_policy/draft/rule_sets/361).
            Ruleset Name: Ruleset name (e.g., Outbound).
            Rule Href: Rule URL (e.g., /orgs/1/sec_policy/draft/rule_sets/361/sec_rules/696).
            Description: Rule description (if any).
            Enabled: Rule status (true or false).
            Providers: Semicolon-separated providers (e.g., IP List: Any (0.0.0.0/0 and ::/0)).
            Consumers: Semicolon-separated consumers, including workloads (e.g., Workload: chunli (/orgs/1/workloads/6f802fc6-5835-487e-900f-aea1bb6240eb)).
            Ingress Services: Semicolon-separated services/ports (e.g., Port: 2710, Proto: 17; Port: 6969, Proto: 17).
        Example:
        csv

        Ruleset Href,Ruleset Name,Rule Href,Description,Enabled,Providers,Consumers,Ingress Services
        /orgs/1/sec_policy/draft/rule_sets/361,Outbound,/orgs/1/sec_policy/draft/rule_sets/361/sec_rules/696,,true,IP List: Any (0.0.0.0/0 and ::/0),Workload: chunli (/orgs/1/workloads/6f802fc6-5835-487e-900f-aea1bb6240eb),Port: 2710, Proto: 17; Port: 6969, Proto: 17; Port: 1337, Proto: 17; Port: 451, Proto: 17

Troubleshooting

    Async Job Timeout or Max Attempts Reached:
        Symptom: Error like Async job did not complete within 3000.0 seconds or 60 attempts. Last status: running.
        Cause: The PCE async job exceeds the configured timeout or polling attempts.
        Solution:
            Increase PCE_MAX_POLL_ATTEMPTS in .env (e.g., PCE_MAX_POLL_ATTEMPTS=120 for ~10 minutes with 5-second intervals).
            Set PCE_RULESETS_TIMEOUT to match (e.g., PCE_RULESETS_TIMEOUT=600 for 120 attempts × 5 seconds).
            Check job status manually:
            bash

            curl -u "<api_key>:<api_secret>" https://pce.shocknetwork.com:8443/api/v2/orgs/1/jobs/<job_id>

            Find <job_id> in pce_errors.log (e.g., /orgs/1/jobs/fecbe52f-0d8c-461b-a053-0e92f1bc2c7e).
            If jobs consistently take long, contact your PCE administrator to investigate large datasets or performance issues.
            Adjust PCE_ASYNC_POLL_INTERVAL (e.g., 10 seconds) to reduce polling frequency, but update PCE_RULESETS_TIMEOUT accordingly.
    Connection Timeout or Failure:
        Symptom: Errors like ConnectTimeoutError or Max retries exceeded.
        Cause: Network issues or incorrect PCE configuration.
        Solution:
            Verify .env settings:
                PCE_HOST (e.g., https://pce.shocknetwork.com).
                PCE_PORT (e.g., 8443).
                PCE_ORG_ID (e.g., 1).
                PCE_RULESETS_TIMEOUT (e.g., 300, not 3000).
            Test connectivity:
            bash

            ping pce.shocknetwork.com
            telnet pce.shocknetwork.com 8443
            curl -u "<api_key>:<api_secret>" https://pce.shocknetwork.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets

            Check for firewall rules blocking outbound traffic.
            Reduce PCE_MAX_RETRIES (e.g., 1) in .env to fail faster during testing.
    Dictionary-Related Errors:
        Symptom: Error like 'dict' object has no attribute 'to_json'.
        Cause: Async responses return dictionaries, not SDK objects, causing incorrect method calls.
        Solution:
            Ensure you’re using the latest script, which removes to_json() calls.
            Check pce_errors.log for ruleset structures (DEBUG level) to verify format.
            If the error persists, share pce_errors.log to debug response structure.
    InsecureRequestWarning (TLS Verification Disabled):
        Symptom: Warning like InsecureRequestWarning: Unverified HTTPS request.
        Cause: PCE_DISABLE_TLS=True bypasses SSL verification.
        Solution:
            Set PCE_DISABLE_TLS=False in .env.
            Install the PCE’s SSL certificate:
                Save it as pce_cert.pem.
                Add to .env: REQUESTS_CA_BUNDLE=/path/to/pce_cert.pem.
                Or set: export REQUESTS_CA_BUNDLE=/path/to/pce_cert.pem.
            Contact your PCE administrator for the certificate if unavailable.
    Async Job Stuck or Failed:
        Symptom: Job status stuck (e.g., running, pending) or fails (failed, cancelled).
        Cause: PCE processing delays, large datasets, or API errors.
        Solution:
            Check pce_errors.log for job status responses and errors.
            Verify job manually (see step 1).
            If status: done but no result.href, contact PCE administrator.
            Try synchronous request by removing Prefer: respond-async in script (edit fetch_rulesets).
    No Workload Rules Found:
        Symptom: Output No rules with workloads found.
        Cause: No rulesets have workloads in consumers.
        Solution:
            Confirm via PCE UI or API:
            bash

            curl -u "<api_key>:<api_secret>" https://pce.shocknetwork.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets

            Check pce_errors.log for processed ruleset names.
            Modify extract_workload_rules to check providers or other fields if needed.
    .env File Issues:
        Symptom: Error like Failed to load .env file.
        Cause: Missing or unreadable .env file.
        Solution:
            Ensure .env exists in the script’s directory.
            Verify permissions:
            bash

            ls -l .env

            Check for typos or formatting errors in .env.
    Illumio SDK Issues:
        Symptom: Unexpected SDK errors.
        Solution:
            Verify SDK version:
            bash

            pip show illumio

            Update:
            bash

            pip install --upgrade illumio

    Contact for Support:
        Provide:
            illumio SDK version (pip show illumio).
            pce_errors.log (redact sensitive info like API keys, hostnames).
            PCE version and expected workload rules.
            Results of curl, ping, or telnet tests.
            Console output and workload_rules.csv status.

Notes

    The script checks consumers for workloads. To include providers or other fields, modify extract_workload_rules.
    Async responses return dictionaries, not SDK objects, so methods like to_json() are not used.
    For large PCE deployments, tune PCE_RULESETS_TIMEOUT, PCE_ASYNC_POLL_INTERVAL, PCE_MAX_RETRIES, and PCE_MAX_POLL_ATTEMPTS.
    Store API credentials securely in .env and avoid hardcoding.
    The script uses /api/v2. For older PCEs, set PCE_API_VERSION=v1 in .env.

License
Provided as-is for use with Illumio PCE. No warranty implied. Use at your own risk.
Acknowledgments

    Built with the illumio Python SDK (https://illumio-py.readthedocs.io).
    Developed to audit Illumio rulesets for direct workload references.
