import json
import csv
from pathlib import Path
from illumio import PolicyComputeEngine, IllumioException
import os
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(
    filename="pce_errors.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Load environment variables from .env file
load_dotenv()

# PCE connection configuration
PCE_HOST = os.getenv("PCE_HOST", "https://scp1.illum.io")
PCE_PORT = int(os.getenv("PCE_PORT", 443))
PCE_ORG_ID = int(os.getenv("PCE_ORG_ID", 149))
PCE_API_KEY = os.getenv("PCE_API_KEY", "api_170842bb8af3699d2")
PCE_API_SECRET = os.getenv("PCE_API_SECRET", "f299e6b8606bf224a15ce6768ce4d00436e8661ddc29582d18ee51d79e7ae9ee")
PCE_DISABLE_TLS = os.getenv("PCE_DISABLE_TLS", "False").lower() == "true"
PCE_API_VERSION = os.getenv("PCE_API_VERSION", "v2")  # e.g., "v2" or "v1"

# Function to connect to PCE
def connect_to_pce():
    try:
        # Initialize PCE with API version (e.g., "v2" for /api/v2)
        pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID, version=PCE_API_VERSION)
        pce.set_credentials(PCE_API_KEY, PCE_API_SECRET)
        
        # Configure TLS verification
        pce._session.verify = not PCE_DISABLE_TLS
        logging.info(f"TLS verification set to: {pce._session.verify}")
        
        # Log the base URL for debugging
        base_url = f"{PCE_HOST}:{PCE_PORT}/api/{PCE_API_VERSION}"
        logging.info(f"PCE base URL: {base_url}")
        print(f"PCE base URL: {base_url}")
        
        # Test with rulesets endpoint
        try:
            endpoint = f"/orgs/{PCE_ORG_ID}/sec_policy/draft/rule_sets"
            full_url = f"{base_url}{endpoint}"
            logging.info(f"Testing connection with endpoint: {full_url}")
            response = pce.get(endpoint)
            logging.info(f"Connection test successful: {response}")
            print(f"Successfully connected to PCE at {PCE_HOST}:{PCE_PORT}")
        except IllumioException as e:
            logging.error(f"Connection test failed: {e}")
            print(f"Error: Connection test failed: {e}")
            raise
        
        return pce
    except IllumioException as e:
        logging.error(f"Failed to connect to PCE: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error connecting to PCE: {e}")
        raise

# Function to fetch all rulesets from PCE
def fetch_rulesets(pce):
    try:
        rulesets = pce.rule_sets.get()
        logging.info(f"Retrieved {len(rulesets)} rulesets from PCE")
        print(f"Retrieved {len(rulesets)} rulesets from PCE")
        return rulesets
    except IllumioException as e:
        logging.error(f"Error fetching rulesets: {e}")
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
        # Use ruleset.to_json() directly (returns dict)
        ruleset_dict = ruleset.to_json()
        workload_rules = extract_workload_rules(ruleset_dict)
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
