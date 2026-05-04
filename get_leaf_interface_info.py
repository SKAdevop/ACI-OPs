import os
import csv
from datetime import datetime
import logging
from typing import Any, Dict, List, Optional
import asyncio
import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.infra
import cobra.model.pol
import cobra.model.fv
# Import necessary modules from the project
from dotenv import load_dotenv
from auth_utils import APICAuthenticator, APICAuthenticationError

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global authenticator instance
_authenticator: Optional[APICAuthenticator] = None

async def get_authenticator() -> APICAuthenticator:
    """Get or create the global authenticator instance."""
    global _authenticator
    if _authenticator is None:
        apic_url = os.getenv('APIC_URL', 'https://your-apic.example.com')
        verify_ssl = os.getenv('APIC_VERIFY_SSL', 'false').lower() == 'true'
        username = os.getenv('APIC_USERNAME')
        password = os.getenv('APIC_PASSWORD')

        if not all([apic_url, username, password]):
            logger.error("APIC_URL, APIC_USERNAME, or APIC_PASSWORD not set in environment variables.")
            raise APICAuthenticationError("Missing APIC credentials in environment.")

        _authenticator = APICAuthenticator(apic_url, verify_ssl)
        await _authenticator.authenticate(username, password)
    return _authenticator

async def fetch_apic_class(class_name: str, query_params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Fetch objects of a specific APIC class using the global authenticator.
    """
    try:
        authenticator = await get_authenticator()
        if not authenticator.token:
            return {
                "status": "error",
                "message": "Not authenticated. Please authenticate first.",
                "class_name": class_name
            }
        
        endpoint = f"/api/class/{class_name}.json"
        response = await authenticator.make_authenticated_request(endpoint, params=query_params)
        
        objects = response.get('imdata', [])
        return {
            "status": "success",
            "message": f"Successfully fetched {len(objects)} {class_name} objects",
            "class_name": class_name,
            "count": len(objects),
            "endpoint": endpoint,
            "objects": objects
        }
    except APICAuthenticationError as e:
        return {
            "status": "error",
            "message": f"API request failed: {str(e)}",
            "class_name": class_name
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Unexpected error: {str(e)}",
            "class_name": class_name
        }

async def get_leaf_interface_classes(
    leaf_node_id: str,
    interface_id: Optional[str] = None,
    interface_ids: Optional[List[str]] = None,
    pod_id: str = "1",
    csv_filename: Optional[str] = None
) -> Dict[str, Any]:
    """
    Query interface-to-EPG context for one or more interfaces on a leaf and export CSV.

    Per interface, this tool mirrors the Cisco MO pattern:
    ``/api/node/mo/topology/pod-{pod}/node-{leaf}/sys/phys-[eth...].json`` with
    ``rsp-subtree-include=full-deployment``, ``target-node=all``, and
    ``target-path=l1EthIfToEPg``, then walks ``pconsCtrlrDeployCtx`` children
    to read ``pconsResourceCtx.ctxDn``.

    If that returns nothing, it falls back to ``l1PhysIf`` class-query children,
    then ``fvRsPathAtt`` (path wcard match).

    :param leaf_node_id: Leaf node ID (e.g., "101")
    :param interface_id: Single interface ID (e.g., "eth1/10" or "po10")
    :param interface_ids: Optional list of interfaces (e.g., ["eth1/3", "eth1/4"])
    :param pod_id: Pod ID (default: "1")
    :param csv_filename: Optional CSV file name to write (in server directory)
    :return: Parsed EPG context and CSV export information
    """
    try:
        requested_interfaces: List[str] = []
        if interface_id:
            requested_interfaces.append(interface_id)
        if interface_ids:
            requested_interfaces.extend(interface_ids)
        requested_interfaces = list(dict.fromkeys(requested_interfaces))

        if not requested_interfaces:
            return {
                "status": "error",
                "message": "Provide interface_id or interface_ids.",
                "leaf_node_id": leaf_node_id
            }

        def parse_ctx_dn(ctx_dn: str) -> Dict[str, str]:
            tenant = ""
            app_profile = ""
            epg = ""
            epg_dn = ""
            parts = ctx_dn.split("/")
            for idx, part in enumerate(parts):
                if part.startswith("tn-"):
                    tenant = part.replace("tn-", "", 1)
                    if idx + 2 < len(parts):
                        ap_part = parts[idx + 1]
                        epg_part = parts[idx + 2]
                        if ap_part.startswith("ap-"):
                            app_profile = ap_part.replace("ap-", "", 1)
                        if epg_part.startswith("epg-"):
                            epg = epg_part.replace("epg-", "", 1)
                        epg_dn = "/".join(parts[:idx + 3])
                    break
            return {
                "tenant": tenant,
                "app_profile": app_profile,
                "epg": epg,
                "epg_dn": epg_dn
            }

        def extract_ctx_dns_from_pcons_children(
            children: Optional[List[Dict[str, Any]]]
        ) -> tuple[int, List[str]]:
            """
            Match sample script layout: pconsCtrlrDeployCtx with nested
            pconsResourceCtx children; also accept flat pconsResourceCtx siblings.
            """
            if not children:
                return 0, []
            deploy_count = 0
            ctxs: List[str] = []
            for item in children:
                if "pconsCtrlrDeployCtx" in item:
                    deploy_count += 1
                    pcons = item.get("pconsCtrlrDeployCtx", {})
                    for sub in pcons.get("children") or []:
                        if "pconsResourceCtx" in sub:
                            ctx = (
                                sub.get("pconsResourceCtx", {})
                                .get("attributes", {})
                                .get("ctxDn", "")
                            )
                            if ctx:
                                ctxs.append(ctx)
                if "pconsResourceCtx" in item:
                    ctx = (
                        item.get("pconsResourceCtx", {})
                        .get("attributes", {})
                        .get("ctxDn", "")
                    )
                    if ctx:
                        ctxs.append(ctx)
            return deploy_count, list(dict.fromkeys(ctxs))

        per_interface_results: Dict[str, Any] = {}
        csv_rows: List[Dict[str, str]] = []
        total_ctx_rows = 0

        async def get_interface_oper_st(if_name: str) -> str:
            ethpm_params = {
                "query-target-filter": (
                    f'and(wcard(ethpmPhysIf.dn,"topology/pod-{pod_id}/node-{leaf_node_id}/"),'
                    f'eq(ethpmPhysIf.id,"{if_name}"))'
                )
            }
            ethpm_res = await fetch_apic_class("ethpmPhysIf", ethpm_params)
            if ethpm_res.get("status") != "success":
                return ""
            for eth_obj in ethpm_res.get("objects", []):
                attrs = eth_obj.get("ethpmPhysIf", {}).get("attributes", {})
                if attrs.get("id") == if_name:
                    return attrs.get("operSt", "") or ""
            return ""

        def slim_epg_row(
            if_name: str, oper_st: str, tenant: str, ap: str, epg: str
        ) -> Dict[str, str]:
            return {
                "leaf_node": leaf_node_id,
                "interface": if_name,
                "operSt": oper_st,
                "tenant": tenant,
                "ap": ap,
                "epg": epg,
            }

        for iface in requested_interfaces:
            csv_rows_before_iface = len(csv_rows)
            oper_st = await get_interface_oper_st(iface)

            # Step 1 (interface-first): query fvRsCEpToPathEp for this interface on this leaf.
            fv_query_params = {
                "query-target-filter": (
                    f'and(wcard(fvRsCEpToPathEp.tDn,"/paths-{leaf_node_id}/"),'
                    f'wcard(fvRsCEpToPathEp.tDn,"pathep-[{iface}]"))'
                )
            }
            fv_result = await fetch_apic_class("fvRsCEpToPathEp", fv_query_params)
            fv_objects: List[Dict[str, Any]] = []
            if fv_result.get("status") == "success":
                fv_objects = fv_result.get("objects", [])

            iface_epg_details: List[Dict[str, str]] = []
            interfaces_found = 0
            pcons_rows_for_iface = 0

            # Step 2a: MO query (sample script): full-deployment + l1EthIfToEPg target-path.
            mo_deploy_count = 0
            mo_ctx_dns: List[str] = []
            try:
                authenticator = await get_authenticator()
                mo_path = (
                    f"/api/node/mo/topology/pod-{pod_id}/node-{leaf_node_id}/"
                    f"sys/phys-[{iface}].json"
                )
                mo_resp = await authenticator.make_authenticated_request(
                    mo_path,
                    params={
                        "rsp-subtree-include": "full-deployment",
                        "target-node": "all",
                        "target-path": "l1EthIfToEPg",
                    },
                )
                imdata = mo_resp.get("imdata") or []
                if imdata and "l1PhysIf" in imdata[0]:
                    port_mo = imdata[0]["l1PhysIf"]
                    interfaces_found = 1
                    mo_children = port_mo.get("children")
                    mo_deploy_count, mo_ctx_dns = extract_ctx_dns_from_pcons_children(
                        mo_children
                    )
            except APICAuthenticationError as e:
                logger.warning("l1EthIfToEPg MO query failed for %s: %s", iface, e)

            if mo_deploy_count >= 1 and mo_ctx_dns:
                for ctx_dn in mo_ctx_dns:
                    parsed = parse_ctx_dn(ctx_dn)
                    row = slim_epg_row(
                        iface,
                        oper_st,
                        parsed["tenant"],
                        parsed["app_profile"],
                        parsed["epg"],
                    )
                    iface_epg_details.append(row)
                    csv_rows.append(row)
                    total_ctx_rows += 1
                    pcons_rows_for_iface += 1

            # Step 2b: class-query l1PhysIf + children (if MO path found nothing).
            if pcons_rows_for_iface == 0:
                leaf_dn_marker = f"topology/pod-{pod_id}/node-{leaf_node_id}/"
                l1_query_params = {
                    "query-target-filter": (
                        f'and(wcard(l1PhysIf.dn,"{leaf_dn_marker}"),eq(l1PhysIf.id,"{iface}"))'
                    ),
                    "rsp-subtree": "children",
                    "rsp-subtree-class": "pconsCtrlrDeployCtx,pconsResourceCtx",
                }

                phys_result = await fetch_apic_class("l1PhysIf", l1_query_params)
                if phys_result.get("status") != "success":
                    logger.warning(
                        "l1PhysIf class query failed for %s: %s",
                        iface,
                        phys_result.get("message"),
                    )
                    objects = []
                else:
                    objects = phys_result.get("objects", [])

                for obj in objects:
                    l1_obj = obj.get("l1PhysIf", {})
                    attrs = l1_obj.get("attributes", {})
                    children = l1_obj.get("children", [])
                    if attrs.get("id") != iface:
                        continue

                    interfaces_found += 1
                    deploy_ctx_count, ctx_dns = extract_ctx_dns_from_pcons_children(
                        children
                    )

                    if deploy_ctx_count < 1:
                        continue

                    for ctx_dn in ctx_dns:
                        parsed = parse_ctx_dn(ctx_dn)
                        row = slim_epg_row(
                            iface,
                            oper_st,
                            parsed["tenant"],
                            parsed["app_profile"],
                            parsed["epg"],
                        )
                        iface_epg_details.append(row)
                        csv_rows.append(row)
                        total_ctx_rows += 1
                        pcons_rows_for_iface += 1

            # Step 3 fallback: if no pcons-derived rows, look up static path attachments.
            # Match standard paths and extpaths-style tDn, e.g.:
            # topology/pod-1/paths-101/pathep-[eth1/3]
            # topology/pod-1/paths-101/extpaths-101/pathep-[eth1/8]
            fvrs_rows_for_iface = 0
            if pcons_rows_for_iface == 0:
                fvrs_params = {
                    "query-target-filter": (
                        f'and(wcard(fvRsPathAtt.tDn,"paths-{leaf_node_id}/"),'
                        f'wcard(fvRsPathAtt.tDn,"pathep-[{iface}]"))'
                    )
                }
                fvrs_result = await fetch_apic_class("fvRsPathAtt", fvrs_params)
                if fvrs_result.get("status") == "success":
                    bindings = fvrs_result.get("objects", [])
                    for binding in bindings:
                        b_attrs = binding.get("fvRsPathAtt", {}).get("attributes", {})
                        epg_dn_full = b_attrs.get("dn", "")
                        parsed = parse_ctx_dn(epg_dn_full)
                        row = slim_epg_row(
                            iface,
                            oper_st,
                            parsed["tenant"],
                            parsed["app_profile"],
                            parsed["epg"],
                        )
                        iface_epg_details.append(row)
                        csv_rows.append(row)
                        total_ctx_rows += 1
                        fvrs_rows_for_iface += 1

            if len(csv_rows) == csv_rows_before_iface:
                row = slim_epg_row(iface, oper_st, "", "", "")
                iface_epg_details.append(row)
                csv_rows.append(row)

            per_interface_results[iface] = {
                "status": "success",
                "fvRsCEpToPathEp_count": len(fv_objects),
                "fvRsPathAtt_count": fvrs_rows_for_iface,
                "interfaces_found": interfaces_found,
                "epg_details_count": len(iface_epg_details),
                "epg_details": iface_epg_details
            }

        if not csv_filename:
            joined_ifaces = "_".join([i.replace("/", "-") for i in requested_interfaces])
            csv_filename = f"leaf{leaf_node_id}_{joined_ifaces}_l1PhysIf_ctxDn_epg.csv"

        csv_path = os.path.join(os.path.dirname(__file__), csv_filename)
        csv_headers = [
            "leaf_node",
            "interface",
            "operSt",
            "tenant",
            "ap",
            "epg",
        ]

        no_data_row = {
            "leaf_node": leaf_node_id,
            "interface": ",".join(requested_interfaces),
            "operSt": "",
            "tenant": "",
            "ap": "",
            "epg": "",
        }

        def write_csv_file(target_csv_path: str) -> None:
            with open(target_csv_path, "w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
                writer.writeheader()
                if csv_rows:
                    writer.writerows(csv_rows)
                else:
                    writer.writerow(no_data_row)

        try:
            write_csv_file(csv_path)
        except PermissionError:
            # If the file is locked/open by another process, write a timestamped file.
            base_name, ext = os.path.splitext(csv_filename)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fallback_name = f"{base_name}_{ts}{ext or '.csv'}"
            csv_path = os.path.join(os.path.dirname(__file__), fallback_name)
            write_csv_file(csv_path)

        return {
            "status": "success",
            "message": (
                f"Processed {len(requested_interfaces)} interface(s) on leaf {leaf_node_id}. "
                f"Found {total_ctx_rows} ctxDn-to-EPG mapping row(s)."
            ),
            "leaf_node_id": leaf_node_id,
            "interface_id": interface_id,
            "interface_ids": requested_interfaces,
            "pod_id": pod_id,
            "total_found": total_ctx_rows,
            "csv_file": csv_path,
            "results": per_interface_results
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Failed to process l1PhysIf interface mapping: {str(e)}",
            "leaf_node_id": leaf_node_id,
            "interface_id": interface_id
        }

if __name__ == "__main__":
    async def main():
        # Prompt for APIC credentials if not set in .env
        apic_url = os.getenv('APIC_URL')
        apic_username = os.getenv('APIC_USERNAME')
        apic_password = os.getenv('APIC_PASSWORD')

        # Check for missing credentials in .env, then prompt
        if not apic_url:
            apic_url = input("Enter APIC URL (e.g., https://apic.example.com): ")
            os.environ['APIC_URL'] = apic_url # Set for current session
        if not apic_username:
            apic_username = input("Enter APIC Username: ")
            os.environ['APIC_USERNAME'] = apic_username
        if not apic_password:
            apic_password = input("Enter APIC Password: ")
            os.environ['APIC_PASSWORD'] = apic_password
        
        try:
            # Attempt to authenticate once at the start
            # This will use the environment variables (either from .env or user input)
            authenticator = await get_authenticator()
            logger.info("APIC authentication successful.")
        except APICAuthenticationError as e:
            logger.error(f"APIC authentication failed: {e}. Exiting.")
            return

        # Prompt for leaf node ID
        leaf_node_id = input("Enter Leaf Node ID (e.g., 101): ")
        if not leaf_node_id:
            logger.error("Leaf Node ID cannot be empty. Exiting.")
            return

        # Prompt for interfaces
        interface_choice = input("Do you want to specify a single interface (s) or multiple interfaces (m)? [s/m]: ").lower()
        
        single_interface: Optional[str] = None
        multiple_interfaces: Optional[List[str]] = None

        if interface_choice == 's':
            single_interface = input("Enter a single Interface ID (e.g., eth1/10 or po10): ")
            if not single_interface:
                logger.error("Single interface ID cannot be empty. Exiting.")
                return
        elif interface_choice == 'm':
            interfaces_str = input("Enter multiple Interface IDs, comma-separated (e.g., eth1/3,eth1/4): ")
            if interfaces_str:
                multiple_interfaces = [iface.strip() for iface in interfaces_str.split(',')]
            else:
                logger.error("Multiple interface IDs cannot be empty if 'm' was chosen. Exiting.")
                return
        else:
            logger.error("Invalid choice. Please enter 's' for single or 'm' for multiple interfaces. Exiting.")
            return

        print(f"\nFetching EPG context for Leaf Node ID: {leaf_node_id}")
        if single_interface:
            print(f"Interface: {single_interface}")
        if multiple_interfaces:
            print(f"Interfaces: {', '.join(multiple_interfaces)}")

        result = await get_leaf_interface_classes(
            leaf_node_id=leaf_node_id,
            interface_id=single_interface,
            interface_ids=multiple_interfaces
        )

        print("\n--- Results ---")
        if result["status"] == "success":
            print(result["message"])
            print(f"CSV file generated: {result.get('csv_file')}")
            for iface, details in result["results"].items():
                print(f"\nInterface: {iface}")
                if details["epg_details"]:
                    for epg_detail in details["epg_details"]:
                        print(f"  Tenant: {epg_detail['tenant']}, AP: {epg_detail['ap']}, EPG: {epg_detail['epg']}")
                else:
                    print("  No EPG details found for this interface.")
        else:
            print(f"Error: {result['message']}")
            if "leaf_node_id" in result:
                print(f"Leaf Node ID: {result['leaf_node_id']}")
            if "interface_id" in result:
                print(f"Interface ID: {result['interface_id']}")
    
    asyncio.run(main())
