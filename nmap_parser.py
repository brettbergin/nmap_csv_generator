#!/usr/bin env python3

import pandas as pd
import xml.etree.ElementTree as ET


NMAP_XML_FILE = 'nmap_output.xml'
JSON_FILE = 'nmap_output.json'
CSV_FILE = 'nmap_output.csv'


def parse_nmap_xml(root):
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
                _h["dns_record"] = hostname.get("name") or ""
                _h["dns_record_type"] = hostname.get("type") or ""

        port_list = []
        for port in host.findall(".//port"):
            _p = {}
            _p["protocol"] = port.get("protocol") or ""
            _p["port"] = port.get("portid") or ""

            port_state = port.find("state")
            if port_state is not None:
                _p["port_state"] = port_state.get("state") or ""

            port_service = port.find("service")
            if port_service is not None:
                _p["service_name"] = port_service.get("name") or ""
                _p["service_product"] = port_service.get("product") or ""
                _p["service_tunnel"] = port_service.get("tunnel") or ""
                _p["service_method"] = port_service.get("method") or ""
                _p["service_conf"] = port_service.get("conf") or ""

                cpe = port_service.find("cpe")
                if cpe is not None:
                    cpe_text_data = cpe.text.replace("\t", "").replace("\n", "")
                    _p["service_cpe"] = "{}".format(cpe_text_data or "")
            
            port_list.append(_p)

        _h["port_list"] = port_list
        scan_results.append(_h)

    return pd.DataFrame(scan_results)


def main():
    tree = ET.parse(NMAP_XML_FILE)
    root = tree.getroot()

    df1 = parse_nmap_xml(root)

    df2 = df1.explode('port_list')
    df2 = df2['port_list'].apply(pd.Series)

    df3 = df1.join(df2)
    df3 = df3.drop('port_list', axis=1)
    
    df3.to_csv(CSV_FILE, index=False)
    df3.to_json(JSON_FILE, index=False, indent=2)


if __name__ == '__main__':
    main()
