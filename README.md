# Advanced Port Scanner with Shodan and CVE Lookup 🚀

This is an advanced asynchronous port scanner written in Python. It scans a target for open ports, retrieves banners, identifies services and versions, and performs CVE lookups using the [NVD API](https://nvd.nist.gov/). Additionally, it can integrate with [Shodan](https://www.shodan.io/) to provide extra host details.

## Features ✨

- **Fast asynchronous scanning:** Leverages `asyncio` for concurrent port scanning.
- **Banner grabbing:** Retrieves banners from open ports for service identification.
- **Service detection:** Identifies services (e.g., Apache, SSH, nginx) along with their versions.
- **CVE lookup integration:** Queries the NVD API for known vulnerabilities based on the service and version.
- **Optional Shodan integration:** Retrieves additional host data from Shodan.
- **Report generation:** Produces reports in both JSON and HTML formats.

## Requirements 📦

- Python 3.7+
- Required Python modules:
  - `asyncio`
  - `argparse`
  - `datetime`
  - `json`
  - `requests`
  - `shodan`
  - `time`
  - `ssl`
  - `re`
  - `typing`
  - `pathlib`

You can install the necessary external modules using pip:

```bash
pip install requests shodan
pip install -r requirements.txt
```

## Usage ⚙️
Run the scanner by providing the target IP/hostname and a port range. You can specify the port range either as a range (e.g., 22-1024) or as a comma-separated list (e.g., 22,80,3306).

Examples
Scan a target for ports 22 to 1024 with Shodan integration and HTML report:
```bash
python port_scanner.py 192.168.0.151 -p 22-1024 --shodan -f html
```
Scan specific ports (e.g., 22, 80, 3306) with Shodan integration:
```bash
python main.py 192.168.0.151 -p 22,80,3306 --shodan -f html
```
## Configuration ⚙️
NVD API:
**The scanner uses the NVD API for CVE lookups.** By default, it queries https://services.nvd.nist.gov/rest/json/cves/1.0.

**Shodan API:**
Provide your Shodan API key by modifying the SHODAN_API_KEY variable in the code.

**CVE Cache:**
The application caches CVE results to minimize repeated API calls. The cache expires in 7 days by default.

## Report Generation 📝
The scanner generates a report (in JSON or HTML format) that includes:

- Target information and timestamp.

- Scanning statistics (total scanned ports, total time, average time per port).

- Details of open ports including service name, version, banners, and any found CVEs.

- Shodan data (if enabled).

## License 📄
This project is provided for educational purposes. Use it responsibly and only on systems for which you have explicit permission to scan.

# **Disclaimer** ⚠️
**WARNING:** Unauthorized scanning of systems is illegal and unethical. Use this tool only in controlled environments or with explicit authorization.



# Happy scanning! 🚀
