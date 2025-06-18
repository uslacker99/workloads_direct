import json
import csv
from pathlib import Path
from illumio import PolicyComputeEngine, IllumioException
import os
from dotenv import load_dotenv
import logging
import requests
import time
import urllib3

# Configure logging
logging.basicConfig(
    filename="pce_errors.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load environment variables from .env file
if not load_dotenv():
    logging.error("Failed to load .env file. Ensure it exists and is readable.")
    raise FileNotFoundError("Failed to load .env file")

# PCE connection configuration
PCE_HOST = os.getenv("PCE_HOST", "https://pce.example.com")
PCE_PORT = int(os.getenv("PCE_PORT", 443))
PCE_ORG_ID = int(os.getenv("PCE_ORG_ID", 1))
PCE_API_KEY = os.getenv("PCE_API_KEY", "api_xxxxxxxxxxxxxxxx")
PCE_API_SECRET = os.getenv("PCE_API_SECRET", "xxxxxxxxxxxxxxxxxxxxxxxx")
PCE_DISABLE_TLS = os.getenv("PCE_DISABLE_TLS", "False").lower() == "true"
PCE_API_VERSION = os.getenv("PCE_API_VERSION", "v2")  # e.g., "v2" or "v1"
PCE_RULESETS_TIMEOUT = float(os.getenv("PCE_RULESETS_TIMEOUT", 300))  # Timeout in seconds (5 minutes)
PCE_ASYNC_POLL_INTERVAL = float(os.getenv("PCE_ASYNC_POLL_INTERVAL", 5))  # Polling interval for async jobs (seconds)
PCE_MAX_RETRIES = int(os.getenv("PCE_MAX_RETRIES", 2))  # Number of retries for connection attempts
PCE_MAX_POLL_ATTEMPTS = int(os.getenv("PCE_MAX_POLL_ATTEMPTS", 60))  # Max poll attempts to prevent infinite loops

# Validate timeout configuration
if PCE_RULESETS_TIMEOUT > 600:
    logging.warning(f"PCE_RULESETS_TIMEOUT is set to {PCE_RULESETS_TIMEOUT} seconds, which is unusually high. Recommended value: 300 (5 minutes).")
    print(f"Warning: PCE_RULESETS_TIMEOUT is {PCE_RULESETS_TIMEOUT} seconds. Consider setting to 300 in .env.")

# Warn about TLS verification
if PCE_DISABLE_TLS:
    logging.warning("PCE_DISABLE_TLS is True. Disabling TLS verification is insecure. Consider setting PCE_DISABLE_TLS=False and installing the PCE certificate.")
    print("Warning: TLS verification is disabled (PCE_DISABLE_TLS=True). This is insecure. See README for details.")

# Function to connect to PCE
def connect_to_pce():
    try:
        # Initialize PCE with API version (e.g., "v2" for /api/v2)
        pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID, version=PCE_API_VERSION)
        pce.set_credentials(PCE_API_KEY, PCE_API_SECRET)
        
        # Configure TLS verification
        pce._session.verify = not PCE_DISABLE_TLS
        
        # Configure retries
        retries = urllib3.util.retry.Retry(
            total=PCE_MAX_RETRIES,
            connect=PCE_MAX_RETRIES,
            read=PCE_MAX_RETRIES,
            redirect=0,
            status=0,
            backoff_factor=1
        )
        pce._session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))
        
        # Log the configuration for debugging
        base_url = f"{PCE_HOST}:{PCE_PORT}/api/{PCE_API_VERSION}"
        logging.info(f"PCE configuration: host={PCE_HOST}, port={PCE_PORT}, org_id={PCE_ORG_ID}, api_version={PCE_API_VERSION}, disable_tls={PCE_DISABLE_TLS}, timeout={PCE_RULESETS_TIMEOUT}, max_retries={PCE_MAX_RETRIES}, max_poll_attempts={PCE_MAX_POLL_ATTEMPTS}")
        logging.info(f"PCE base URL: {base_url}")
        print(f"PCE base URL: {base_url}")
        
        # Validate configuration
        if PCE_HOST == "https://pce.example.com":
            logging.error("PCE_HOST is set to default value. Update PCE_HOST in .env.")
            raise ValueError("Invalid PCE_HOST. Update .env with correct PCE hostname.")
        
        # Test with rulesets endpoint (synchronous)
        try:
            endpoint = f"/orgs/{PCE_ORG_ID}/sec_policy/draft/rule_sets"
            full_url = f"{base_url}{endpoint}"
            logging.info(f"Testing connection with endpoint: {full_url} (timeout: {PCE_RULESETS_TIMEOUT} seconds, retries: {PCE_MAX_RETRIES})")
            response = pce.get(endpoint, timeout=PCE_RULESETS_TIMEOUT)
            logging.info(f"Connection test successful: {response.status_code} {response.reason}")
            print(f"Successfully connected to PCE at {PCE_HOST}:{PCE_PORT}")
        except requests.exceptions.ConnectTimeout as e:
            logging.error(f"Connection test timed out after {PCE_RULESETS_TIMEOUT} seconds: {e}")
            print(f"Error: Connection test timed out after {PCE_RULESETS_TIMEOUT} seconds. Check PCE host, port, and network connectivity.")
            raise IllumioException(f"Connection test timed out: {e}")
        except IllumioException as e:
            logging.error(f"Connection test failed: {e}")
            print(f"Error: Connection test failed: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error during connection test: {e}")
            print(f"Error: Unexpected connection test failure: {e}")
            raise
        
        return pce
    except IllumioException as e:
        logging.error(f"Failed to connect to PCE: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error connecting to PCE: {e}")
        raise

# Function to fetch all rulesets from PCE with async support
def fetch_rulesets(pce):
    try:
        endpoint = f"/orgs/{PCE_ORG_ID}/sec_policy/draft/rule_sets"
        logging.info(f"Fetching rulesets from {endpoint} with timeout of {PCE_RULESETS_TIMEOUT} seconds and Prefer: respond-async")
        
        # Send async request with Prefer: respond-async header
        headers = {"Prefer": "respond-async"}
        response = pce.get(endpoint, headers=headers, timeout=30)  # Short timeout for initial request
        
        if response.status_code == 202:
            # Async job initiated
            job_url = response.headers.get("Location")
            if not job_url:
                raise IllumioException("Async job initiated but no Location header provided")
            logging.info(f"Async job initiated. Job status URL: {job_url}")
            
            # Poll job status until completion or timeout
            start_time = time.time()
            poll_count = 0
            while time.time() - start_time < PCE_RULESETS_TIMEOUT and poll_count < PCE_MAX_POLL_ATTEMPTS:
                job_response = pce.get(job_url, timeout=30)
                job_status = job_response.json()
                logging.debug(f"Job status response: {json.dumps(job_status, indent=2)}")
                status = job_status.get("status", "").lower()
                logging.debug(f"Job status: {status}")
                
                if status in ["completed", "done"]:
                    result_url = job_status.get("result", {}).get("href")
                    if not result_url:
                        raise IllumioException(f"Job {status} but no result URL provided in response: {job_status}")
                    logging.info(f"Job {status}. Fetching results from: {result_url}")
                    
                    # Fetch results
                    results_response = pce.get(result_url, timeout=30)
                    rulesets = results_response.json()
                    logging.info(f"Retrieved {len(rulesets)} rulesets from PCE")
                    print(f"Retrieved {len(rulesets)} rulesets from PCE")
                    return rulesets  # Return list of rulesets
                elif status in ["failed", "cancelled"]:
                    error = job_status.get("error", "Unknown error")
                    raise IllumioException(f"Async job {status}: {error}")
                
                poll_count += 1
                time.sleep(PCE_ASYNC_POLL_INTERVAL)
            
            # Timeout or max polls reached
            raise IllumioException(f"Async job did not complete within {PCE_RULESETS_TIMEOUT} seconds or {PCE_MAX_POLL_ATTEMPTS} attempts. Last status: {status}")
        
        else:
            # Synchronous response (fallback if PCE doesn't support async)
            logging.warning(f"Received synchronous response (status {response.status_code}) instead of async")
            rulesets = response.json()
            logging.info(f"Retrieved {len(rulesets)} rulesets from PCE")
            print(f"Retrieved {len(rulesets)} rulesets from PCE")
            return rulesets
    
    except requests.exceptions.Timeout:
        logging.error("Request timed out after {} seconds".format(PCE_RULESETS_TIMEOUT))
        raise IllumioException("Rulesets request timed out after {} seconds".format(PCE_RULESETS_TIMEOUT))
    except IllumioException as e:
        logging.error(f"Error fetching rulesets: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error fetching rulesets: {e}")
        raise

# Function to extract workload rules
def extract_workload_rules(ruleset):
    workload_rules = []
    
    for rule in ruleset.get("rules", []):
        # Check if any consumer is a workload
        for consumer in rule.get("consumers", []):
            if "workload" in consumer:
                workload_info = consumer["workload"]
                rule_details = {
                    "ruleset_href": ruleset.get("href", ""),
                    "ruleset_name": ruleset.get("name", ""),
                    "rule_href": rule.get("href", ""),
                    "description": rule.get("description", ""),
                    "enabled": str(rule.get("enabled", "")),
                    "providers": [],
                    "consumers": [],
                    "ingress_services": []
                }
                
                # Extract providers
                for provider in rule.get("providers", []):
                    if "label" in provider:
                        label = provider["label"]
                        rule_details["providers"].append(f"Label: {label.get('key', '')}={label.get('value', '')}")
                    elif "ip_list" in provider:
                        rule_details["providers"].append(f"IP List: {provider['ip_list'].get('name', '')}")
                    elif "virtual_service" in provider:
                        rule_details["providers"].append(f"Virtual Service: {provider['virtual_service'].get('name', '')}")
                
                # Extract consumers
                rule_details["consumers"].append(f"Workload: {workload_info.get('hostname', 'Unknown')} ({workload_info.get('href', '')})")
                for consumer in rule.get("consumers", []):
                    if "label" in consumer:
                        label = consumer["label"]
                        rule_details["consumers"].append(f"Label: {label.get('key', '')}={label.get('value', '')}")
                    elif "actors" in consumer:
                        rule_details["consumers"].append(f"Actors: {consumer['actors']}")
                
                # Extract ingress services
                for service in rule.get("ingress_services", []):
                    if "href" in service:
                        rule_details["ingress_services"].append(f"Service: {service.get('name', 'Unknown')}")
                    elif "port" in service:
                        ports = f"Port: {service.get('port', '')}"
                        if service.get("to_port"):
                            ports += f"-{service.get('to_port', '')}"
                        ports += f", Proto: {service.get('proto', '')}"
                        rule_details["ingress_services"].append(ports)
                
                # Convert lists to strings for CSV
                rule_details["providers"] = "; ".join(rule_details["providers"])
                rule_details["consumers"] = "; ".join(rule_details["consumers"])
                rule_details["ingress_services"] = "; ".join(rule_details["ingress_services"])
                
                workload_rules.append(rule_details)
    
    return workload_rules

# Function to write rules to CSV
def write_to_csv(workload_rules, output_file):
    headers = ["Ruleset Href", "Ruleset Name", "Rule Href", "Description", "Enabled", "Providers", "Consumers", "Ingress Services"]
    
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for rule in workload_rules:
            writer.writerow({
                "Ruleset Href": rule["ruleset_href"],
                "Ruleset Name": rule["ruleset_name"],
                "Rule Href": rule["rule_href"],
                "Description": rule["description"],
                "Enabled": rule["enabled"],
                "Providers": rule["providers"],
                "Consumers": rule["consumers"],
                "Ingress Services": rule["ingress_services"]
            })

# Main execution
def main():
    output_file = Path("workload_rules.csv")
    
    # Connect to PCE
    pce = connect_to_pce()
    
    # Fetch all rulesets
    rulesets = fetch_rulesets(pce)
    
    # Process rulesets and extract workload rules
    all_workload_rules = []
    for ruleset in rulesets:
        # Ruleset is already a dict from json response
        logging.debug(f"Ruleset structure: {json.dumps(ruleset, indent=2)}")
        logging.info(f"Processing ruleset: {ruleset.get('name', 'Unknown')}")
        workload_rules = extract_workload_rules(ruleset)
        all_workload_rules.extend(workload_rules)
    
    # Write to CSV
    if all_workload_rules:
        write_to_csv(all_workload_rules, output_file)
        print(f"Workload rules written to {output_file}")
    else:
        print("No rules with workloads found.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Script failed: {e}")
        print(f"Script failed. Check pce_errors.log for details.")