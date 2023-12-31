# Nmap Data Transformer

### Overview
nmap currently doesn't have a native way of exporting scan results into a CSV format. 
This makes it difficult to analyze the scan results. This script was written to address the lack of native support for CSV as an output file format in nmap. 

**Note:** This script does NOT execute nmap. It simply parses nmap xml documents and transforms
them into CSV or JSON files.

### Example Nmap command to generate the XML file.
```
nmap -sV -oX scan_results.xml 192.168.1.0/24
```

### Example usage:
The `-f` is a required argument. Without it, the script will not run.
Either `-c` or `-j` must be provided. The user can choose whether
to export the scan results into a CSV file or a JSON file. One of these 
must be specified.
```
python nmap_parser.py -f scan_results.xml -c output.csv
python nmap_parser.py --xml_file=output.xml --csv=output.csv

python nmap_parser.py -f scan_results.xml -j output.json
python nmap_parser.py --xml_file= output.xml --json=output.json
```