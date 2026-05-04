#!/usr/bin/env python

# Author Shafie Afridi
# This script will assign Contracts to an existing EPG, and create EPG Labels, if needed.

# list of packages that should be imported for this code to work
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.fv
import cobra.model.pol
import cobra.model.vz
from cobra.internal.codec.xmlcodec import toXMLStr
import os
import yaml # Will need to install pyyaml: pip install pyyaml
from dotenv import load_dotenv # Will need to install python-dotenv: pip install python-dotenv

# Disable warnings from logins without valid Certs.
try:
    import requests.packages.urllib3 as urllib3
except ImportError: # Use ImportError for python 2/3 compatibility for requests.packages
    import urllib3
urllib3.disable_warnings()

# Load environment variables from .env file
load_dotenv()

# --- Configuration Loading ---
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.yaml')

try:
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    print(f"Error: Configuration file '{CONFIG_FILE}' not found.")
    exit(1)
except yaml.YAMLError as e:
    print(f"Error parsing YAML configuration file: {e}")
    exit(1)

# --- APIC Credentials from .env ---
APIC_URL = os.getenv('APIC_URL')
APIC_USERNAME = os.getenv('APIC_USERNAME')
APIC_PASSWORD = os.getenv('APIC_PASSWORD')

if not all([APIC_URL, APIC_USERNAME, APIC_PASSWORD]):
    print("Error: APIC_URL, APIC_USERNAME, or APIC_PASSWORD not set in .env file.")
    exit(1)

# --- Login to APIC ---
print(f"Logging into APIC at {APIC_URL}...")
ls = cobra.mit.session.LoginSession(APIC_URL, APIC_USERNAME, APIC_PASSWORD)
md = cobra.mit.access.MoDirectory(ls)
try:
    md.login()
    print("Successfully logged into APIC.")
except Exception as e:
    print(f"Error logging into APIC: {e}")
    exit(1)

# the top level object Tenant on which operations will be made
polUni = cobra.model.pol.Uni('')

# --- Process Configuration ---
tenant_name = config.get('tenant_name')
if not tenant_name:
    print("Error: 'tenant_name' not found in config.yaml")
    exit(1)

fvTenant = cobra.model.fv.Tenant(polUni, tenant_name)

application_profiles_config = config.get('application_profiles', [])
if not application_profiles_config:
    print("Warning: No 'application_profiles' found in config.yaml. No EPGs will be processed.")

for ap_data in application_profiles_config:
    ap_name = ap_data.get('name')
    if not ap_name:
        print("Warning: Skipping Application Profile with no 'name' defined.")
        continue

    fvAp = cobra.model.fv.Ap(fvTenant, name=ap_name)
    print(f"\nProcessing Application Profile: {ap_name}")

    epgs_config = ap_data.get('epgs', [])
    for epg_data in epgs_config:
        epg_name = epg_data.get('name')
        if not epg_name:
            print("Warning: Skipping EPG with no 'name' defined in AP '{ap_name}'.")
            continue

        fvAEPg = cobra.model.fv.AEPg(fvAp, name=epg_name)
        print(f"  Processing EPG: {epg_name}")

        # --- Contracts ---
        provided_contracts = epg_data.get('provided_contracts', [])
        for contract_name in provided_contracts:
            cobra.model.fv.RsProv(fvAEPg, tnVzBrCPName=contract_name)
            print(f"    Assigned Provided Contract: {contract_name}")

        consumed_contracts = epg_data.get('consumed_contracts', [])
        for contract_name in consumed_contracts:
            cobra.model.fv.RsCons(fvAEPg, tnVzBrCPName=contract_name)
            print(f"    Assigned Consumed Contract: {contract_name}")

        # --- EPG Labels ---
        labels_config = epg_data.get('labels', {})
        if labels_config:
            provider_label = labels_config.get('provider')
            if provider_label and provider_label.get('tag') and provider_label.get('name'):
                cobra.model.vz.ProvLbl(fvAEPg, tag=provider_label['tag'], name=provider_label['name'])
                print(f"    Assigned Provider Label: Tag='{provider_label['tag']}', Name='{provider_label['name']}'")

            consumer_label = labels_config.get('consumer')
            if consumer_label and consumer_label.get('tag') and consumer_label.get('name'):
                cobra.model.vz.ConsLbl(fvAEPg, tag=consumer_label['tag'], name=consumer_label['name'])
                print(f"    Assigned Consumer Label: Tag='{consumer_label['tag']}', Name='{consumer_label['name']}'")

# --- Commit Changes ---
print("\nGenerated MO XML:")
print(toXMLStr(fvTenant))

c = cobra.mit.request.ConfigRequest()
c.addMo(fvTenant)
try:
    md.commit(c)
    print("\nSuccessfully committed changes to APIC.")
except Exception as e:
    print(f"\nError committing changes to APIC: {e}")
    exit(1)

print("\nScript finished.")