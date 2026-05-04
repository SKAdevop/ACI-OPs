This python code will query Cisco ACI (Application Centric Infrastructure) fabric for an interface or multiple interfaces, for their assignment to an epg or multiple epgs. The information is then collected and saved in a csv file in the code location.
The information will list the Leaf or switch id, Tenant, AP and EPG.
Note: operSt value will not be fetched with this code, but the column is created.

Included files are 
1) .env.template
Rename it to .env and populate the info for APIC URL, username and password.
2) auth_utils.py file, that will be needed for creating the APIC session and login tokens.
3) get_leaf_interface_info file, the main code that runs and queries the APIC for interfaces on a specified node and gathers the info in a csv file.

This code is tested with python 3.12
APIC version 5.3(2d)