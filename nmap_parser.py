#!/usr/bin env python3

"""
This script is meant to help transform an nmap xml scan result file
and create a new csv file with line items of hosts and the open ports/services
that are discovered during the scan. The goal of this script was to learn more
about the pandas data library and how to utilize it for data transformation 
purposes. 

Example run: ./nmap_parser.py -f some_file.xml -c foo.csv 
alternatively: ./nmap_parser.py -f some_file.xml -j foo.json

Example XML Document Schema:

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="1703822602" startstr="Thu Dec 28 20:03:22 2023" version="7.94" xmloutputversion="1.05">
	<scaninfo type="syn" protocol="tcp" numservices="1000"/>
 
	<host starttime="1703822608" endtime="1703826412">
		<status state="up" reason="arp-response" reason_ttl="0" />
		<address addr="10.250.100.1" addrtype="ipv4" />
		<address addr="90:EC:77:35:F8:14" addrtype="mac" vendor="silicom" />
  
		<hostnames>
			<hostname name="x.example.com" type="PTR" />
		</hostnames>
  
		<ports>

			<port protocol="tcp" portid="22">
				<state state="open" reason="syn-ack" reason_ttl="64" />
				<service name="ssh" product="OpenSSH" version="9.4" extrainfo="protocol 2.0" method="probed" conf="10">
					<cpe>
						cpe:/a:openbsd:openssh:9.4
					</cpe>
				</service>
			</port>
    
			<port protocol="tcp" portid="80">
				<state state="open" reason="syn-ack" reason_ttl="64" />
				<service name="http" product="nginx" method="probed" conf="10">
					<cpe>
						cpe:/a:igor_sysoev:nginx
					</cpe>
				</service>
			</port>
   
			<port protocol="tcp" portid="443">
				<state state="open" reason="syn-ack" reason_ttl="64" />
				<service name="http" product="nginx" tunnel="ssl" method="probed" conf="10">
					<cpe>
						cpe:/a:igor_sysoev:nginx
					</cpe>
				</service>
			</port>
   
		</ports>
	</host>
 </nmaprun>
"""

import argparse
import datetime
import xml.etree.ElementTree as ET

import pandas as pd


def fetch_args() -> argparse.ArgumentParser:
    """
    This function parses the command line arguments
    provided by the user and returns the parsed arguments
    that were found.

    Returns:
        _type_: ArgumentParser object
    """

    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="NMAP XML to CVS Parser.")

    parser.add_argument(
        "--xml_file", "-f", type=str, help="The XML input file (required)"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv", "-c", type=str, help="The CSV output file")
    group.add_argument("--json", "-j", type=str, help="The JSON output file")

    return parser.parse_args()


def parse_nmap_xml(root: str) -> pd.DataFrame:
    """
    This function iterates over all of the host
    objects in the XML document. For each host,
    we continue to generate a list of all of the
    open ports/services per network host. We return
    a pandas Dataframe object to handle later on.

    Args:
        root (_type_): string(xml file path)

    Returns:
        _type_: Pandas DataFrame
    """

    scan_results: list = []

    for host in root.findall("host"):
        _h: dict = {}

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

        port_list: list = []
        for port in host.findall(".//port"):
            _p: dict = {}
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
                    _p["service_cpe"] = f"{cpe_text_data or "N/A"}"

            port_list.append(_p)

        _h["port_list"] = port_list
        scan_results.append(_h)

    return pd.DataFrame(scan_results)


def get_xml_tree_root(xmlfile: str):
    """_summary_

    Args:
        xmlfile (_type_): string of the specified xml file path.

    Raises:
        FileNotFoundError: Raises an error if the file doesnt exist.
        Exception: General catch-all exception is something unknown goes wrong.

    Returns:
        _type_: XML document parsed tree.
    """

    try:
        tree = ET.parse(xmlfile)
        root = tree.getroot()
        return root

    except FileNotFoundError as fnf_err:
        raise FileNotFoundError(f'Unable to find file. Error: {fnf_err}') from fnf_err

    except Exception as err:
        raise Exception(f'Unknown Error Parsing XML file: {err}') from err


def transform_data(data: str, run_time: str) -> pd.DataFrame:
    """
    This function performs multiple things:
    1. Calls the function that parses the XML and returns a pandas dataframe.
    2. Since hosts can have many ports/services we use 'explode' and pd.Series
       to flatten the one-to-many the dataset has within it.
    3. Joins the parsed ports/services back into the host data.
    4. removes the redundant 'port_list' column thats no longer required.

    Args:
        data (_type_): XML document as a string.
        run_time (_type_): datetime.datetime.now() as a string.

    Returns:
        _type_: returns a pd.Dataframe of the transformed data.
    """

    df1: pd.DataFrame = parse_nmap_xml(data)
    df1["run_time"] = run_time

    df2: pd.DataFrame = df1.explode("port_list")
    df2: pd.DataFrame = df2["port_list"].apply(pd.Series)

    df3: pd.DataFrame = df1.join(df2)
    df3: pd.DataFrame = df3.drop("port_list", axis=1)

    return df3


def get_current_datetime():
    """
    Gets the current time, and returns both
    the current time as a datetime object as well as
    a stringified version of the string. This function
    should be called as so: date_obj, date_str = get_current_datetime()

    Returns:
        _type_: returns both the current time as a datetime object as well as
                a stringified version of the string
    """
    now = datetime.datetime.now()
    return now, now.strftime("%Y-%m-%d_%H:%M:%S")


def main():
    """
    This is the programs main function/entrypoint.

    Returns: None
    """
    raw_start, start_time = get_current_datetime()
    print(f"[+] Starting Nmap XML parser @: {start_time}.")

    args = fetch_args()
    if not args.xml_file:
        print("[-] No provided xml file. See help. Quitting.")
        return

    print(f"[+] Using XML File: {args.xml_file}.")
    xml_data = get_xml_tree_root(args.xml_file)
    df = transform_data(xml_data, run_time=start_time)

    if args.csv:
        print(f"[+] Writing output to CSV file: {args.csv}.")
        df.to_csv(args.csv, index=False)

    if args.json:
        print(f"[+] Writing output to JSON file: {args.json}.")
        df.to_json(args.json, indent=2, index=False, orient="table")

    raw_stop, stop_time = get_current_datetime()
    run_duration = raw_stop - raw_start
    print(f"[+] Completed XML -> CSV @: {stop_time}. Duration: {run_duration}.")


if __name__ == "__main__":
    main()
