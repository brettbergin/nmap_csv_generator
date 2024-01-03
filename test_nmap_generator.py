#!/usr/bin env python3

import datetime
import xml.etree.ElementTree as ET

import pandas as pd
import pytest

from nmap_generator import get_current_datetime
from nmap_generator import get_xml_tree_root
from nmap_generator import fetch_args
from nmap_generator import transform_data
from nmap_generator import parse_nmap_xml
from nmap_generator import parse_host_info


TEST_DATA = {
    "xml_file_valid": "test_nmap_data.xml",
    "xml_file_invalid": "not-a-valid.xml",
}


class TestFetchArgs:
    def test_fetch_args_with_valid_csv(self):
        parsed_args = fetch_args(["-f", "input.xml", "-c", "output.csv"])
        assert parsed_args.xml_file == "input.xml"
        assert parsed_args.csv == "output.csv"
        assert parsed_args.json is None

    def test_fetch_args_with_valid_json(self):
        parsed_args = fetch_args(["-f", "input.xml", "--json", "output.json"])
        assert parsed_args.xml_file == "input.xml"
        assert parsed_args.json == "output.json"
        assert parsed_args.csv is None

    def test_fetch_args_without_required_args(self):
        with pytest.raises(SystemExit):
            fetch_args([])

    def test_fetch_args_with_mutually_exclusive_args(self):
        with pytest.raises(SystemExit):
            fetch_args(["-f", "input.xml", "-c", "output.csv", "-j", "output.json"])


class TestGetCurrentDatetime:
    def test_types_get_current_datetime(self):
        date_obj, date_str = get_current_datetime()

        assert isinstance(date_obj, datetime.datetime)
        assert isinstance(date_str, str)

    def test_get_current_dates_match(self):
        date_obj, date_str = get_current_datetime()
        assert date_obj.strftime("%Y-%m-%d_%H:%M:%S") == date_str

    def test_get_current_datetime(self):
        _, date_str = get_current_datetime()

        try:
            datetime.datetime.strptime(date_str, "%Y-%m-%d_%H:%M:%S")

        except ValueError:
            pytest.fail("Date string format is incorrect")

    def test_get_current_datetime_close_to_now(self):
        date_obj, _ = get_current_datetime()
        now = datetime.datetime.now()

        delta = datetime.timedelta(seconds=3)
        assert now - delta <= date_obj <= now + delta


class TestGetXMLTreeRoot:
    def test_get_xml_tree_root(self):
        test_root = get_xml_tree_root(xmlfile=TEST_DATA["xml_file_valid"])
        assert isinstance(test_root, ET.Element)

    def test_get_xml_tree_root_raises_fnf_err(self):
        with pytest.raises(FileNotFoundError):
            get_xml_tree_root(xmlfile=TEST_DATA["xml_file_invalid"])


class TestParseNmapXML:
    test_xml_root = get_xml_tree_root(TEST_DATA["xml_file_valid"])

    def test_parse_nmap_xml_returns_df(self):
        test_df = parse_nmap_xml(root=self.test_xml_root)
        assert isinstance(test_df, pd.DataFrame)

    def test_parse_nmap_xml_parses_1_test_item(self):
        test_df = parse_nmap_xml(root=self.test_xml_root)
        assert len(test_df) == 1

    def test_parse_nmap_xml_parses_1_test_item(self):
        test_df = parse_nmap_xml(root=self.test_xml_root)

        assert "state" in test_df.columns
        assert "state_reason" in test_df.columns
        assert "os_name" in test_df.columns
        assert "ip_address" in test_df.columns
        assert "ip_address_type" in test_df.columns
        assert "dns_record" in test_df.columns
        assert "dns_record_type" in test_df.columns
        assert "port_list" in test_df.columns


class TestTransformData:
    test_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    def test_tansformer(self):
        test_root = get_xml_tree_root(TEST_DATA["xml_file_valid"])
        df = transform_data(data=test_root, run_time=self.test_time)
        assert isinstance(df, pd.DataFrame)

    def test_transformer_raises_value_error(self):
        with pytest.raises(ValueError) as excinfo:
            transform_data(data=1, run_time=self.test_time)
        assert str(excinfo.value) == "data argument must be an element tree from ET."


class TestParseHostInfo:
    test_xml_root = get_xml_tree_root(TEST_DATA["xml_file_valid"])
    parsed_hosts = test_xml_root.findall("host")

    def test_parse_host_info(self):
        # select only the first host to use in this test.
        test_host = self.parsed_hosts[0]

        output = parse_host_info(test_host)
        assert isinstance(output, dict)
