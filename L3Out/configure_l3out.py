#!/usr/bin/env python

# list of packages that should be imported for this code to work
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.fv
import cobra.model.l3ext
import cobra.model.ospf
import cobra.model.pol
from cobra.internal.codec.xmlcodec import toXMLStr
import os
import yaml # Will need to install pyyaml: pip install pyyaml
from dotenv import load_dotenv # Will need to install python-dotenv: pip install python-dotenv

# Disable warnings from logins without valid Certs.
try:
    import requests.packages.urllib3 as urllib3
except ImportError:
    import urllib3
urllib3.disable_warnings()

# Load environment variables from .env file
load_dotenv()

# --- Configuration Loading ---
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config_l3out.yaml')

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

# --- Process Configuration ---
tenant_name = config.get('tenant_name')
if not tenant_name:
    print("Error: 'tenant_name' not found in config_l3out.yaml")
    exit(1)
fvTenant = cobra.model.fv.Tenant(polUni, tenant_name)

# Create the Context/VRF
vrf_config = config.get('vrf_config', {})
if not vrf_config or not vrf_config.get('name'):
    print("Error: 'vrf_config' or 'vrf_config.name' not found in config_l3out.yaml")
    exit(1)
fvCtx = cobra.model.fv.Ctx(fvTenant, **{k: str(v) for k, v in vrf_config.items()}) # Ensure all values are strings
print(f"Configuring VRF: {vrf_config['name']}")


# Create the L3Out
l3out_config = config.get('l3out_config', {})
if not l3out_config or not l3out_config.get('name'):
    print("Error: 'l3out_config' or 'l3out_config.name' not found in config_l3out.yaml")
    exit(1)
l3extOut_attrs = {k: str(v) for k, v in l3out_config.items() if k not in ['ospf_ext_p', 'logical_node_profile', 'external_network_instance_profile', 'l3_domain_tn', 'vrf_tn']}
l3extOut = cobra.model.l3ext.Out(fvTenant, **l3extOut_attrs)
print(f"Configuring L3Out: {l3out_config['name']}")


# OSPF External Protocol Profile
ospf_ext_p_config = l3out_config.get('ospf_ext_p', {})
if ospf_ext_p_config:
    ospfExtP = cobra.model.ospf.ExtP(l3extOut, **{k: str(v) for k, v in ospf_ext_p_config.items()})


# L3 Domain and VRF Association
l3_domain_tn = l3out_config.get('l3_domain_tn')
if l3_domain_tn:
    cobra.model.l3ext.RsL3DomAtt(l3extOut, tDn=f'uni/l3dom-{l3_domain_tn}')
vrf_tn = l3out_config.get('vrf_tn')
if vrf_tn:
    cobra.model.l3ext.RsEctx(l3extOut, tnFvCtxName=vrf_tn)


# Logical Node Profile and Logical Interface Profile
lnode_profile_config = l3out_config.get('logical_node_profile', {})
if not lnode_profile_config or not lnode_profile_config.get('name'):
    print("Error: 'logical_node_profile' or its 'name' not found in config_l3out.yaml")
    exit(1)

lnode_attrs = {k: str(v) for k, v in lnode_profile_config.items() if k not in ['nodes', 'logical_interface_profile']}
l3extLNodeP = cobra.model.l3ext.LNodeP(l3extOut, **lnode_attrs)
print(f"  Configuring Logical Node Profile: {lnode_profile_config['name']}")

# Nodes for Logical Node Profile
nodes_config = lnode_profile_config.get('nodes', [])
for node_data in nodes_config:
    node_id = node_data.get('id')
    rtr_id = node_data.get('rtrId')
    if node_id and rtr_id:
        l3extRsNodeL3OutAtt = cobra.model.l3ext.RsNodeL3OutAtt(l3extLNodeP, tDn=f'topology/pod-1/node-{node_id}', rtrId=str(rtr_id), rtrIdLoopBack=str(node_data.get('rtrIdLoopBack', 'yes')))
        cobra.model.l3ext.InfraNodeP(l3extRsNodeL3OutAtt, name=u'', descr=u'', nameAlias=u'', spineRole=u'', fabricExtIntersiteCtrlPeering=u'no', annotation=u'', fabricExtCtrlPeering=u'no')
        print(f"    Attached Node: {node_id} with Router ID: {rtr_id}")


lif_profile_config = lnode_profile_config.get('logical_interface_profile', {})
if not lif_profile_config or not lif_profile_config.get('name'):
    print("Error: 'logical_interface_profile' or its 'name' not found in config_l3out.yaml")
    exit(1)

lif_attrs = {k: str(v) for k, v in lif_profile_config.items() if k not in ['egress_qos_dpp_pol_tn', 'ingress_qos_dpp_pol_tn', 'nd_if_pol_tn', 'ospf_if_p', 'paths']}
l3extLIfP = cobra.model.l3ext.LIfP(l3extLNodeP, **lif_attrs)
print(f"    Configuring Logical Interface Profile: {lif_profile_config['name']}")

# QoS and ND Policies
egress_qos_dpp_pol_tn = lif_profile_config.get('egress_qos_dpp_pol_tn')
if egress_qos_dpp_pol_tn:
    cobra.model.l3ext.RsEgressQosDppPol(l3extLIfP, tnQosDppPolName=egress_qos_dpp_pol_tn)
ingress_qos_dpp_pol_tn = lif_profile_config.get('ingress_qos_dpp_pol_tn')
if ingress_qos_dpp_pol_tn:
    cobra.model.l3ext.RsIngressQosDppPol(l3extLIfP, tnQosDppPolName=ingress_qos_dpp_pol_tn)
nd_if_pol_tn = lif_profile_config.get('nd_if_pol_tn')
if nd_if_pol_tn:
    cobra.model.l3ext.RsNdIfPol(l3extLIfP, tnNdIfPolName=nd_if_pol_tn)

# OSPF Interface Policy
ospf_if_p_config = lif_profile_config.get('ospf_if_p', {})
if ospf_if_p_config:
    ospfIfP_attrs = {k: str(v) for k, v in ospf_if_p_config.items() if k != 'ospf_if_pol_tn'}
    ospfIfP = cobra.model.ospf.IfP(l3extLIfP, **ospfIfP_attrs)
    ospf_if_pol_tn = ospf_if_p_config.get('ospf_if_pol_tn')
    if ospf_if_pol_tn:
        cobra.model.ospf.RsIfPol(ospfIfP, tnOspfIfPolName=ospf_if_pol_tn)


# Path Attachments
paths_config = lif_profile_config.get('paths', [])
for path_data in paths_config:
    path_attrs = {k: str(v) for k, v in path_data.items()}
    # Default common attributes, can be overridden by path_data
    # Note: ipv6Dad, encapScope, targetDscp, llAddr, autostate, mac, mode, ifInstT, mtu, annotation
    # were often hardcoded in the original, setting defaults or expecting them in YAML
    default_path_attrs = {
        'ipv6Dad': 'enabled',
        'encapScope': 'local',
        'targetDscp': 'unspecified',
        'llAddr': '::',
        'autostate': 'disabled',
        'mac': '00:22:BD:F8:19:FF', # This might need to be dynamic per interface if not always the same
        'mode': 'regular',
        'ifInstT': 'sub-interface',
        'mtu': 'inherit',
        'annotation': ''
    }
    # Merge defaults with path-specific data, path_data takes precedence
    final_path_attrs = {**default_path_attrs, **path_attrs}

    cobra.model.l3ext.RsPathL3OutAtt(l3extLIfP, **final_path_attrs)
    print(f"      Attached Path: {path_data.get('addr')} on {path_data.get('tDn')}")


# External Network Instance Profile
ext_net_inst_profile_config = l3out_config.get('external_network_instance_profile', {})
if ext_net_inst_profile_config:
    ext_net_inst_profile_attrs = {k: str(v) for k, v in ext_net_inst_profile_config.items() if k != 'subnets'}
    l3extInstP = cobra.model.l3ext.InstP(l3extOut, **ext_net_inst_profile_attrs)
    print(f"  Configuring External Network Instance Profile: {ext_net_inst_profile_config.get('name')}")

    # Subnets for External Network Instance Profile
    subnets_config = ext_net_inst_profile_config.get('subnets', [])
    for subnet_data in subnets_config:
        subnet_attrs = {k: str(v) for k, v in subnet_data.items()}
        cobra.model.l3ext.Subnet(l3extInstP, **subnet_attrs)
        print(f"    Added Subnet: {subnet_data.get('ip')}")


# commit the generated code to APIC
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