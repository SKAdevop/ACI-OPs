#!/usr/bin/env python

import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.pol
import cobra.model.fv
from cobra.internal.codec.xmlcodec import toXMLStr
import os
import yaml # Will need to install pyyaml: pip install pyyaml
from dotenv import load_dotenv # Will need to install python-dotenv: pip install python-dotenv

# Disable warnings
try:
    import requests.packages.urllib3 as urllib3
except ImportError:
    import urllib3
urllib3.disable_warnings()

# Load environment variables from .env file
load_dotenv()

# --- Configuration Loading ---
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config_vpc_access.yaml')

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

# the top level object on which operations will be made
polUni = cobra.model.pol.Uni('')
infraInfra = cobra.model.infra.Infra(polUni)
infraFuncP = cobra.model.infra.FuncP(infraInfra)

# --- Process Configuration ---

# Access Bundle Group (Leaf Policy Group)
abg_config = config.get('access_bundle_group', {})
if not abg_config or not abg_config.get('name'):
    print("Error: 'access_bundle_group' or its 'name' not found in config_vpc_access.yaml")
    exit(1)

abg_attrs = {k: str(v) for k, v in abg_config.items() if k != 'associated_policies'}
infraAccBndlGrp = cobra.model.infra.AccBndlGrp(infraFuncP, **abg_attrs)
print(f"Configuring Access Bundle Group: {abg_config['name']}")

abg_policies = abg_config.get('associated_policies', {})
if abg_policies:
    if abg_policies.get('att_ent_p_tn'):
        cobra.model.infra.RsAttEntP(infraAccBndlGrp, tDn=f"uni/infra/attentp-{abg_policies['att_ent_p_tn']}")
    if abg_policies.get('lacp_pol_tn'):
        cobra.model.infra.RsLacpPol(infraAccBndlGrp, tnLacpLagPolName=abg_policies['lacp_pol_tn'])
    if abg_policies.get('lldp_if_pol_tn'):
        cobra.model.infra.RsLldpIfPol(infraAccBndlGrp, tnLldpIfPolName=abg_policies['lldp_if_pol_tn'])
    if abg_policies.get('stp_if_pol_tn'):
        cobra.model.infra.RsStpIfPol(infraAccBndlGrp, tnStpIfPolName=abg_policies['stp_if_pol_tn'])
    if abg_policies.get('fabric_hif_pol_tn'):
        cobra.model.infra.RsHIfPol(infraAccBndlGrp, tnFabricHIfPolName=abg_policies['fabric_hif_pol_tn'])

# Access Port Profile
app_config = config.get('access_port_profile', {})
if not app_config or not app_config.get('name'):
    print("Error: 'access_port_profile' or its 'name' not found in config_vpc_access.yaml")
    exit(1)

app_attrs = {k: str(v) for k, v in app_config.items() if k != 'port_selectors'}
infraAccPortP = cobra.model.infra.AccPortP(infraInfra, **app_attrs)
print(f"Configuring Access Port Profile: {app_config['name']}")

port_selectors_config = app_config.get('port_selectors', [])
for ps_data in port_selectors_config:
    if not ps_data.get('name'):
        print("Warning: Skipping Port Selector with no 'name' defined.")
        continue

    ps_attrs = {k: str(v) for k, v in ps_data.items() if k != 'port_blocks' and k != 'fexId'}
    infraHPortS = cobra.model.infra.HPortS(infraAccPortP, **ps_attrs)
    print(f"  Configuring Port Selector: {ps_data['name']}")

    # Associate with Access Bundle Group
    if abg_config.get('name'):
        cobra.model.infra.RsAccBaseGrp(infraHPortS, fexId=str(ps_data.get('fexId', '1')), tDn=f"uni/infra/funcprof/accbundle-{abg_config['name']}")

    # Port Blocks
    port_blocks_config = ps_data.get('port_blocks', [])
    for pb_data in port_blocks_config:
        if not pb_data.get('name'):
            print("Warning: Skipping Port Block with no 'name' defined.")
            continue
        pb_attrs = {k: str(v) for k, v in pb_data.items()}
        cobra.model.infra.PortBlk(infraHPortS, **pb_attrs)
        print(f"    Configuring Port Block: {pb_data['name']} (from {pb_data.get('fromPort')}-{pb_data.get('toPort')})")


# Node Profile
np_config = config.get('node_profile', {})
if not np_config or not np_config.get('name'):
    print("Error: 'node_profile' or its 'name' not found in config_vpc_access.yaml")
    exit(1)

np_attrs = {k: str(v) for k, v in np_config.items() if k != 'access_port_profile_tn'}
infraNodeP = cobra.model.infra.NodeP(infraInfra, **np_attrs)
print(f"Configuring Node Profile: {np_config['name']}")

if np_config.get('access_port_profile_tn'):
    cobra.model.infra.RsAccPortP(infraNodeP, tDn=f"uni/infra/accportprof-{np_config['access_port_profile_tn']}")


# EPG Static Path Binding
epg_binding_config = config.get('epg_static_path_binding', {})
if epg_binding_config:
    tenant_name = epg_binding_config.get('tenant_name')
    ap_name = epg_binding_config.get('ap_name')
    epg_name = epg_binding_config.get('epg_name')

    if not all([tenant_name, ap_name, epg_name]):
        print("Warning: Skipping EPG Static Path Binding due to missing tenant, AP, or EPG name.")
    else:
        print(f"\nConfiguring EPG Static Path Binding for Tenant: {tenant_name}, AP: {ap_name}, EPG: {epg_name}")
        fvTenant_epg = cobra.model.fv.Tenant(polUni, tenant_name)
        fvAp_epg = cobra.model.fv.Ap(fvTenant_epg, ap_name)

        epg_attrs = {k: str(v) for k, v in epg_binding_config.get('epg_attributes', {}).items()}
        fvAEPg = cobra.model.fv.AEPg(fvAp_epg, name=epg_name, **epg_attrs)

        path_attachments_config = epg_binding_config.get('path_attachments', [])
        for path_data in path_attachments_config:
            if not path_data.get('tDn'):
                print("Warning: Skipping Path Attachment with no 'tDn' defined.")
                continue
            path_attrs = {k: str(v) for k, v in path_data.items()}
            cobra.model.fv.RsPathAtt(fvAEPg, **path_attrs)
            print(f"  Attached Path: {path_data.get('tDn')} (Encap: {path_data.get('encap')})")


# --- Commit Changes ---
print("\nGenerated MO XML for InfraFuncP:")
print(toXMLStr(infraFuncP))
print("\nGenerated MO XML for InfraInfra (Access Port Profile MO):")
print(toXMLStr(infraInfra))
print("\nGenerated MO XML for InfraNodeP:")
print(toXMLStr(infraNodeP))

c_infra_func = cobra.mit.request.ConfigRequest()
c_infra_func.addMo(infraFuncP)

c_infra_acc_port = cobra.mit.request.ConfigRequest()
c_infra_acc_port.addMo(infraInfra) # infraAccPortP is child of infraInfra

c_infra_node = cobra.mit.request.ConfigRequest()
c_infra_node.addMo(infraNodeP)

# Handle EPG static path binding commit separately
if epg_binding_config:
    fvTenant_epg = cobra.model.fv.Tenant(polUni, epg_binding_config.get('tenant_name'))
    fvAp_epg = cobra.model.fv.Ap(fvTenant_epg, epg_binding_config.get('ap_name'))
    c_epg = cobra.mit.request.ConfigRequest()
    c_epg.addMo(fvAp_epg)


try:
    md.commit(c_infra_func)
    print("\nSuccessfully committed Access Bundle Group changes to APIC.")
except Exception as e:
    print(f"\nError committing Access Bundle Group changes to APIC: {e}")
    exit(1)

try:
    md.commit(c_infra_acc_port)
    print("Successfully committed Access Port Profile changes to APIC.")
except Exception as e:
    print(f"Error committing Access Port Profile changes to APIC: {e}")
    exit(1)

try:
    md.commit(c_infra_node)
    print("Successfully committed Node Profile changes to APIC.")
except Exception as e:
    print(f"Error committing Node Profile changes to APIC: {e}")
    exit(1)

if epg_binding_config:
    try:
        md.commit(c_epg)
        print("Successfully committed EPG Static Path Binding changes to APIC.")
    except Exception as e:
        print(f"Error committing EPG Static Path Binding changes to APIC: {e}")
        exit(1)

print("\nScript finished.")