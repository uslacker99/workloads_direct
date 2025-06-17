# Illumio Workload Rules Extractor

This Python script connects to an Illumio Policy Compute Engine (PCE) to fetch rulesets, identifies rules that directly reference workloads in the `consumers` field, and exports the results to a CSV file. It is useful for auditing or analyzing Illumio security policies to find rules with specific workload references, such as rule 3 in the provided example ruleset.

## Features
- Connects to an Illumio PCE using the `illumio` Python SDK.
- Retrieves all rulesets from the PCE.
- Identifies rules with workloads in the `consumers` field.
- Exports rule details (ruleset href, name, rule href, description, enabled status, providers, consumers, ingress services) to a CSV file.
- Includes detailed logging for debugging and error tracking.

## Prerequisites
- **Python**: Version 3.6 or higher.
- **Illumio PCE**: Access to a PCE instance with valid API credentials.
- **Python Packages**:
  - `illumio`: Illumio Python SDK for interacting with the PCE.
  - `python-dotenv`: For loading environment variables from a `.env` file.
- **PCE API Credentials**: API key and secret with permissions to read rulesets.
- **Network Access**: Ability to reach the PCE hostname and port (e.g., `https://pce.shocknetwork.com:8443`).

## Installation
1. **Clone or Download the Script**:
   - Save `workloads_directly_in_rules.py` to your working directory.

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

    Update if needed:
    bash

    pip install --upgrade illumio

Configuration

    Create a .env File:
        In the same directory as the script, create a .env file with the following content:
        env

        PCE_HOST=https://pce.shocknetwork.com
        PCE_PORT=8443
        PCE_ORG_ID=1
        PCE_API_KEY=api_xxxxxxxxxxxxxxxx
        PCE_API_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
        PCE_DISABLE_TLS=False
        PCE_API_VERSION=v2

        Replace values with your PCE details:
            PCE_HOST: PCE hostname (e.g., https://pce.shocknetwork.com).
            PCE_PORT: PCE port (e.g., 8443).
            PCE_ORG_ID: Organization ID (e.g., 1).
            PCE_API_KEY and PCE_API_SECRET: API credentials from the PCE.
            PCE_DISABLE_TLS: Set to True if using a self-signed certificate (use cautiously).
            PCE_API_VERSION: API version (e.g., v2 for /api/v2, or v1 for /api/v1).
    Verify PCE Access:
        Test connectivity and credentials using curl:
        bash

        curl -k -u "<api_key>:<api_secret>" https://pce.shocknetwork.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets

        If this fails, confirm the hostname, port, org ID, API version, or credentials with your PCE administrator.

Usage

    Run the Script:
        Activate the virtual environment (if used):
        bash

        source venvs/bin/activate

        Execute the script:
        bash

        python3 workloads_directly_in_rules.py

    Expected Output:
        Console output:

        PCE base URL: https://pce.shocknetwork.com:8443/api/v2
        Successfully connected to PCE at https://pce.shocknetwork.com:8443
        Retrieved <n> rulesets from PCE
        Workload rules written to workload_rules.csv

        Or, if no workload rules are found:

        No rules with workloads found.

        Output file: workload_rules.csv (if workload rules exist).
        Log file: pce_errors.log for debugging and error details.
    Output CSV Format:
        The workload_rules.csv file contains the following columns:
            Ruleset Href: URL of the ruleset (e.g., /orgs/1/sec_policy/draft/rule_sets/361).
            Ruleset Name: Name of the ruleset (e.g., Outbound).
            Rule Href: URL of the rule (e.g., /orgs/1/sec_policy/draft/rule_sets/361/sec_rules/696).
            Description: Rule description (if any).
            Enabled: Rule status (true or false).
            Providers: Semicolon-separated list of providers (e.g., IP List: Any (0.0.0.0/0 and ::/0)).
            Consumers: Semicolon-separated list of consumers, including workloads (e.g., Workload: chunli (/orgs/1/workloads/6f802fc6-5835-487e-900f-aea1bb6240eb)).
            Ingress Services: Semicolon-separated list of services or ports (e.g., Port: 2710, Proto: 17; Port: 6969, Proto: 17).
        Example:
        csv

        Ruleset Href,Ruleset Name,Rule Href,Description,Enabled,Providers,Consumers,Ingress Services
        /orgs/1/sec_policy/draft/rule_sets/361,Outbound,/orgs/1/sec_policy/draft/rule_sets/361/sec_rules/696,,true,IP List: Any (0.0.0.0/0 and ::/0),Workload: chunli (/orgs/1/workloads/6f802fc6-5835-487e-900f-aea1bb6240eb),Port: 2710, Proto: 17; Port: 6969, Proto: 17; Port: 1337, Proto: 17; Port: 451, Proto: 17

Troubleshooting

    Script Fails with Connection Error:
        Check pce_errors.log for details.
        Verify .env settings (PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET, PCE_API_VERSION).
        Test PCE connectivity:
        bash

        curl -k -u "<api_key>:<api_secret>" https://pce.shocknetwork.com:8443/api/v2/orgs/1/sec_policy/draft/rule_sets

        If using a self-signed certificate, set PCE_DISABLE_TLS=True in .env.
    No Workload Rules Found:
        If the script outputs No rules with workloads found, confirm that rulesets contain workloads in the consumers field via the PCE UI or API.
        Add debugging to log ruleset names by inserting:
        python

        logging.info(f"Processing ruleset: {ruleset_dict.get('name', 'Unknown')}")

        before workload_rules = extract_workload_rules(ruleset_dict) in the main function.
    Unexpected Ruleset Data:
        If rulesets have unexpected formats, share a sample ruleset (redacted) for script adjustments.
        Check pce_errors.log for parsing errors.
    Illumio SDK Issues:
        Verify SDK version:
        bash

        pip show illumio

        Update if needed:
        bash

        pip install --upgrade illumio

    Contact for Support:
        Provide:
            illumio SDK version (pip show illumio).
            pce_errors.log contents (redact sensitive info).
            PCE version and expected workload rules.
            Results of curl tests.

Notes

    The script checks for workloads in the consumers field only. To include providers or other fields, modify the extract_workload_rules function.
    For large PCE deployments, fetching all rulesets may be slow. Add filters to pce.rule_sets.get() if needed (consult Illumio SDK documentation).
    Securely store API credentials in the .env file and avoid hardcoding them.
    The script assumes the PCE API is at /api/v2. For older PCE versions, set PCE_API_VERSION=v1 in .env.

License
This script is provided as-is for use with Illumio PCE. No warranty is implied. Use at your own risk.
Acknowledgments

    Built with the illumio Python SDK.
    Inspired by the need to audit Illumio rulesets for direct workload references.
# workloads_direct
