#!/usr/bin env python3

__doc__ = """
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
from typing import Tuple

import pandas as pd


def fetch_args(args: None = None) -> argparse.Namespace:
    """
    This function parses the command line arguments
    provided by the user and returns the parsed arguments
    that were found.

    Returns:
        _type_: ArgumentParser object
    """

    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="NMAP XML to CVS Parser."
    )

    parser.add_argument(
        "--xml_file", "-f", type=str, help="The XML input file (required)"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv", "-c", type=str, help="The CSV output file")
    group.add_argument("--json", "-j", type=str, help="The JSON output file")

    return parser.parse_args(args)


def parse_host_info(host: ET.Element) -> dict:
    """
    This function accepts an xml elementtree element and
    parses it into a dictionary object data structure.
    The dictionary is returned to to the function caller.

    Args:
    - host: ET.Element

    Returns:
    - host_info: dict
    """
    if not isinstance(host, ET.Element):
        raise ValueError("Host argument must be an elementtree.Element object.")

    host_info = {
        "state": host.find("status").get("state", "")
        if host.find("status") is not None
        else "",
        "state_reason": host.find("status").get("reason", "")
        if host.find("status") is not None
        else "",
        "os_name": host.find("os/osmatch").get("name", "")
        if host.find("os/osmatch") is not None
        else "",
        "ip_address": host.find("address[@addrtype='ipv4']").get("addr", "")
        if host.find("address[@addrtype='ipv4']") is not None
        else "",
        "ip_address_type": "ipv4",
        "dns_record": host.find("hostnames/hostname").get("name", "None Found")
        if host.find("hostnames/hostname") is not None
        else "",
        "dns_record_type": host.find("hostnames/hostname").get("type", "N/A")
        if host.find("hostnames/hostname") is not None
        else "",
        "port_list": [],
    }

    for port in host.findall(".//port"):
        port_info = {
            "protocol": port.get("protocol", "N/A"),
            "port": port.get("portid", "N/A"),
            "port_state": port.find("state").get("state", "N/A")
            if port.find("state") is not None
            else "",
            "service_name": port.find("service").get("name", "N/A")
            if port.find("service") is not None
            else "",
            "service_product": port.find("service").get("product", "N/A")
            if port.find("service") is not None
            else "",
            "service_tunnel": port.find("service").get("tunnel", "N/A")
            if port.find("service") is not None
            else "",
            "service_method": port.find("service").get("method", "N/A")
            if port.find("service") is not None
            else "",
            "service_conf": port.find("service").get("conf", "N/A")
            if port.find("service") is not None
            else "",
            "service_cpe": port.find("service/cpe")
            .text.replace("\t", "")
            .replace("\n", "")
            if port.find("service/cpe") is not None
            else "",
        }
        host_info["port_list"].append(port_info)
    return host_info


def parse_nmap_xml(root: ET.Element) -> pd.DataFrame:
    """
    This function iterates over all of the host
    objects in the XML document. For each host,
    we continue to generate a list of all of the
    open ports/services per network host. We return
    a pandas Dataframe object to handle later on.

    Args:
        root (_type_): ET.ELement

    Returns:
        _type_: Pandas DataFrame
    """
    if not isinstance(root, ET.Element):
        raise ValueError("root argument must be an elementtree.Element object.")

    scan_results = [parse_host_info(host) for host in root.findall("host")]
    return pd.DataFrame(scan_results)


def get_xml_tree_root(xmlfile: str) -> ET.Element:
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
        raise FileNotFoundError(f"Unable to find file. Error: {fnf_err}") from fnf_err

    except Exception as err:
        raise Exception(f"Unknown Error Parsing XML file: {err}") from err


def transform_data(data: ET.Element, run_time: str) -> pd.DataFrame:
    """
    This function performs multiple things:
    1. Calls the function that parses the XML and returns a pandas dataframe.
    2. Since hosts can have many ports/services we use 'explode' and pd.Series
       to flatten the one-to-many the dataset has within it.
    3. Joins the parsed ports/services back into the host data.
    4. removes the redundant 'port_list' column thats no longer required.

    Args:
        - data (ET.Element): Root element of the parsed XML document.
        - run_time (str): Current time as a string.

    Returns:
        _type_: returns a pd.Dataframe of the transformed data.
    """
    if not isinstance(data, ET.Element):
        raise ValueError("data argument must be an element tree from ET.")

    # Create a dataframe from the nmap xml file data.
    df: pd.DataFrame = parse_nmap_xml(data)

    # Add a column 'run_time' so we know when this script was ran.
    df["run_time"] = run_time

    # Explode the 'port_list' column
    exploded_df = df.explode("port_list")

    # Apply pd.Series to the 'port_list' column to convert it into separate columns
    port_df = exploded_df["port_list"].apply(pd.Series)

    # Drop the original 'port_list' column from exploded_df
    exploded_df = exploded_df.drop("port_list", axis=1)

    # Join the new port columns with the exploded_df
    result_df = pd.concat([exploded_df, port_df], axis=1)

    return result_df


def get_current_datetime() -> Tuple[datetime.datetime, str]:
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


def export_results(data_frame: pd.DataFrame, output_file: str, output_type: str):
    """
    This function will export the results of the nmap data based on the output type
    the was requested by the program executor.

    Args:
    - data_frame: A dataframe we plan to export to a file.
    - output_type: the type of output file format we plan to use.
    - output_file: the filename of the outputfile we plan to use.

    Return: output_type
    """

    print(f"[+] Writing output type: {output_type} to file: {output_file}.")

    if output_type == "csv":
        data_frame.to_csv(output_file, index=False)

    if output_type == "json":
        data_frame.to_json(output_file, indent=2, index=False, orient="table")

    return output_type


def determine_output_type(args_csv: str, args_json: str) -> str:
    """
    Determines the output file format based on the provided arguments.

    Args:
        args_csv (str): The file path for CSV output, or None.
        args_json (str): The file path for JSON output, or None.

    Returns:
        str: 'csv' if CSV output is specified, 'json' if JSON output is specified,
             or 'csv' by default if neither is specified.
    """
    if args_csv is not None and args_json is not None:
        raise ValueError(
            "Both CSV and JSON output types cannot be specified at the same time."
        )

    if args_csv is not None:
        return "csv", args_csv
    elif args_json is not None:
        return "json", args_json
    else:
        raise ValueError("Output type must be specified.")


def main() -> None:
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

    output_type, output_file = determine_output_type(args.csv, args.json)
    exc = export_results(
        data_frame=df, output_type=output_type, output_file=output_file
    )

    raw_stop, stop_time = get_current_datetime()
    duration = raw_stop - raw_start
    minutes, seconds = divmod(duration.total_seconds(), 60)

    message = f"[+] {stop_time}: Nmap XML > {exc.upper()} completed. "
    message += f"Duration: {minutes} minutes and {round(seconds, 1)} seconds."
    print(message)


if __name__ == "__main__":
    main()
