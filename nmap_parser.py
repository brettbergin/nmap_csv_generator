#!/usr/bin env python3

import argparse
import datetime
import pandas as pd
import xml.etree.ElementTree as ET


def fetch_args():
    """_summary_

    Returns:
        _type_: _description_
    """
    
    parser = argparse.ArgumentParser(description="NMAP XML to CVS Parser.")

    parser.add_argument(
        "--xml_file", "-f", type=str, help="The XML input file (required)"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv", "-c", type=str, help="The CSV output file")
    group.add_argument("--json", "-j", type=str, help="The JSON output file")

    return parser.parse_args()


def parse_nmap_xml(root):
    """_summary_

    Args:
        root (_type_): _description_

    Returns:
        _type_: _description_
    """
    
    scan_results = []

    for host in root.findall("host"):
        _h = {}

        status = host.find("status")
        if status is not None:
            _h["state"] = status.get("state") or ""
            _h["state_reason"] = status.get("reason") or ""

        _os = host.find("os")
        if _os is not None:
            _os_match = _os.find("osmatch")
            if _os_match is not None:
                _h["os_name"] = _os_match.get("name") or ""

        address = host.find("address")
        if address is not None:
            _h["ip_address"] = address.get("addr") or ""
            _h["ip_address_type"] = address.get("addrtype") or ""

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hostname = hostnames.find("hostname")
            if hostname is not None:
                _h["dns_record"] = hostname.get("name") or "None Found"
                _h["dns_record_type"] = hostname.get("type") or "N/A"

        port_list = []
        for port in host.findall(".//port"):
            _p = {}
            _p["protocol"] = port.get("protocol") or "N/A"
            _p["port"] = port.get("portid") or "N/A"

            port_state = port.find("state")
            if port_state is not None:
                _p["port_state"] = port_state.get("state") or "N/A"

            port_service = port.find("service")
            if port_service is not None:
                _p["service_name"] = port_service.get("name") or "N/A"
                _p["service_product"] = port_service.get("product") or "N/A"
                _p["service_tunnel"] = port_service.get("tunnel") or "N/A"
                _p["service_method"] = port_service.get("method") or "N/A"
                _p["service_conf"] = port_service.get("conf") or "N/A"

                cpe = port_service.find("cpe")
                if cpe is not None:
                    cpe_text_data = cpe.text.replace("\t", "").replace("\n", "")
                    _p["service_cpe"] = "{}".format(cpe_text_data or "N/A")

            port_list.append(_p)

        _h["port_list"] = port_list
        scan_results.append(_h)

    return pd.DataFrame(scan_results)


def get_xml_tree_root(xmlfile):
    """_summary_

    Args:
        xmlfile (_type_): _description_

    Raises:
        FileNotFoundError: _description_
        Exception: _description_

    Returns:
        _type_: _description_
    """
    
    try:
        tree = ET.parse(xmlfile)
        root = tree.getroot()
        return root
    
    except FileNotFoundError as fnf_err:
        raise FileNotFoundError(f"Unable to find file. Error: {fnf_err}")        

    except Exception as err:
        raise Exception(f"Unknown Error: {err}")        
   

def transform_data(data, run_time):
    df1 = parse_nmap_xml(data)
    df1["run_time"] = run_time.strftime("%Y-%m-%d_%H:%M:%S")
    
    df2 = df1.explode("port_list")
    df2 = df2["port_list"].apply(pd.Series)

    df3 = df1.join(df2)
    df3 = df3.drop("port_list", axis=1)
    
    return df3

 
def main():
    """_summary_

    Raises:
        Exception: _description_
    """
    now = datetime.datetime.now()
    
    args = fetch_args()
    if not args.xml_file:
        print(f"[+] No provided xml file. See help. Quitting.")
        return

    xml_data = get_xml_tree_root(args.xml_file)
    df = transform_data(xml_data, run_time=now)

    if args.csv:
        df.to_csv(args.csv, index=False)

    if args.json:
        df.to_json(args.json, indent=2, index=False, orient="table")


if __name__ == "__main__":
    main()
