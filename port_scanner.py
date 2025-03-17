import asyncio
import argparse
from datetime import datetime
import json
import requests
import shodan
import time
import ssl
import re
from typing import Dict, List, Tuple
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
CVE_CACHE_FILE = "cve_cache.json"
CVE_CACHE_EXPIRE_DAYS = 7
SHODAN_API_KEY = "set_your_shodan_api_key_here"


class CVECache:
    """
    A simple cache for storing CVE data to avoid repeated API calls.
    """

    def __init__(self):
        self.cache = {}
        self.cache_file = Path(CVE_CACHE_FILE)
        self.load_cache()

    def load_cache(self):
        """Load the cache from the file if it exists."""
        if self.cache_file.exists():
            with open(self.cache_file, "r", encoding="utf-8") as f:
                self.cache = json.load(f)

    def save_cache(self):
        """Save the cache to the file in UTF-8 encoding."""
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(self.cache, f, indent=2, ensure_ascii=False)

    def get(self, keyword: str) -> List[str]:
        """
        Retrieve CVEs from the cache for a given keyword.

        Args:
            keyword (str): The service and version string.

        Returns:
            List[str]: A list of CVE IDs.
        """
        entry = self.cache.get(keyword)
        if not entry:
            return []
        last_updated = datetime.fromisoformat(entry["last_updated"])
        if (datetime.now() - last_updated).days <= CVE_CACHE_EXPIRE_DAYS:
            return entry["cves"]
        else:
            return []

    def update(self, keyword: str, cves: List[str]):
        """
        Update the cache with new CVE data for a given keyword.

        Args:
            keyword (str): The service and version string.
            cves (List[str]): A list of CVE IDs.
        """
        self.cache[keyword] = {"cves": cves, "last_updated": datetime.now().isoformat()}
        self.save_cache()


cve_cache = CVECache()


def sync_fetch_cves(keyword: str) -> List[str]:
    """
    Synchronously fetch CVEs from the NVD API for the given keyword.

    Args:
        keyword (str): The search keyword.

    Returns:
        List[str]: A list of CVE IDs.
    """
    try:
        params = {
            "keyword": keyword,
            "resultsPerPage": "5"
        }
        response = requests.get(NVD_API_URL, params=params)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("result", {}).get("CVE_Items", [])
        cves = [item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "unknown") for item in cve_items]
        return cves
    except Exception:
        return []


async def fetch_cves(keyword: str) -> List[str]:
    """
    Asynchronously fetch CVEs using a thread for the given keyword.

    Args:
        keyword (str): The search keyword.

    Returns:
        List[str]: A list of CVE IDs.
    """
    return await asyncio.to_thread(sync_fetch_cves, keyword)


async def read_banner(reader, timeout=2, chunk_size=1024) -> str:
    """
    Read data from the reader in chunks to assemble the banner.

    Args:
        reader: The asyncio stream reader.
        timeout (float): Timeout for reading each chunk.
        chunk_size (int): Size of each chunk.

    Returns:
        str: The assembled banner string.
    """
    banner_chunks = []
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(chunk_size), timeout=timeout)
            if not chunk:
                break
            banner_chunks.append(chunk)
    except asyncio.TimeoutError:
        pass
    return b"".join(banner_chunks).decode(errors="ignore").strip()


def identify_service(banner: str) -> Tuple[str, str]:
    """
    Identify the service and its version from the banner string.

    Args:
        banner (str): The service banner.

    Returns:
        tuple: (service_name, version_info)
    """
    service, version = "unknown", ""
    
    # Improved HTTP Server detection
    server_match = re.search(r'(Apache|nginx|IIS)/([\d\.]+)', banner, re.IGNORECASE)
    if server_match:
        service = server_match.group(1).lower()
        version = f"{server_match.group(1)}/{server_match.group(2)}"
        return service, version
    
    # SSH detection
    ssh_match = re.search(r'SSH-(\d+\.\d+)[-_]([^\s]+)', banner)
    if ssh_match:
        version = f"{ssh_match.group(1)} ({ssh_match.group(2)})"
        return "ssh", version
    
    # Generic HTTP detection
    if "Server:" in banner:
        return "http", banner.split("Server:")[-1].split("|")[0].strip()
    
    return service, version


async def scan_port(target: str, port: int, timeout: float) -> Tuple[int, bool, str, float]:
    """
    Scan a single port on the target and retrieve the banner.

    Args:
        target (str): The target IP/hostname.
        port (int): The port to scan.
        timeout (float): Connection timeout in seconds.

    Returns:
        tuple: (port, is_open, banner, scan_time)
    """
    start_time = time.time()
    try:
        ssl_context = ssl.create_default_context() if port == 443 else None
        if port == 443 and ssl_context is not None:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=ssl_context),
            timeout=timeout
        )
        banner = ""
        try:
            if port == 22:
                writer.write(b"SSH-2.0-Client\r\n")
                await writer.drain()
                banner = await read_banner(reader, timeout=5)
            
            elif port in {80, 443, 8080}:
                # Send HTTP request
                req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()
                
                # Read only headers
                try:
                    headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
                    headers_str = headers.decode(errors="ignore")
                    
                    # Extract server information
                    server_info = "Unknown Server"
                    server_match = re.search(r'Server:\s*(.+?)\r\n', headers_str, re.IGNORECASE)
                    if server_match:
                        server_info = server_match.group(1)
                    
                    # Extract additional headers
                    powered_by = ""
                    powered_match = re.search(r'X-Powered-By:\s*(.+?)\r\n', headers_str, re.IGNORECASE)
                    if powered_match:
                        powered_by = f" | Powered by: {powered_match.group(1)}"
                    
                    banner = f"{server_info}{powered_by}"
                
                except asyncio.IncompleteReadError:
                    banner = "Incomplete HTTP response"
            
            else:
                await asyncio.sleep(0.3)
                banner = await read_banner(reader, timeout=3)
        
        except Exception as e:
            banner = f"[Error: {type(e).__name__}: {str(e)}]"
        
        finally:
            writer.close()
            await writer.wait_closed()
        
        return port, True, banner.strip(), time.time() - start_time
    
    except Exception as e:
        return port, False, str(e), time.time() - start_time



async def main_scan(target: str, ports: List[int], timeout: float, max_concurrency: int, shodan_client=None) -> Dict:
    """
    Perform a scan of the target across specified ports, integrate CVE lookup and Shodan data.

    Args:
        target (str): The target IP/hostname.
        ports (List[int]): List or range of ports to scan.
        timeout (float): Connection timeout in seconds.
        max_concurrency (int): Maximum concurrent connections.
        shodan_client: An initialized Shodan API client (optional).

    Returns:
        Dict: A dictionary containing scan results, stats, and Shodan data.
    """
    start_time = time.time()
    results = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "open_ports": [],
        "stats": {"scanned_ports": 0, "total_time": 0.0, "avg_time_per_port": 0.0},
        "shodan_data": {}
    }
    semaphore = asyncio.Semaphore(max_concurrency)

    async def scan_task(port):
        async with semaphore:
            return await scan_port(target, port, timeout)

    tasks = [scan_task(port) for port in ports]
    for future in asyncio.as_completed(tasks):
        port, is_open, banner, port_time = await future
        results["stats"]["total_time"] += port_time
        if is_open:
            service, version = identify_service(banner)
            cves = []
            if service != "unknown":
                search_keyword = f"{service} {version}".strip()
                cached_cves = cve_cache.get(search_keyword)
                if cached_cves:
                    cves = cached_cves
                else:
                    cves = await fetch_cves(search_keyword)
                    cve_cache.update(search_keyword, cves)
            results["open_ports"].append({
                "port": port,
                "banner": banner,
                "service": service,
                "version": version,
                "cves": cves,
                "scan_time": round(port_time, 4)
            })
    results["stats"]["scanned_ports"] = len(ports)
    results["stats"]["total_time"] = round(time.time() - start_time, 2)
    results["stats"]["avg_time_per_port"] = round(results["stats"]["total_time"] / len(ports), 4) if ports else 0

    if shodan_client:
        try:
            shodan_data = shodan_client.host(target)
            results["shodan_data"] = shodan_data
        except Exception as e:
            results["shodan_data"] = {"error": str(e)}

    return results


def generate_report(results: Dict, format: str):
    """
    Generate a scan report in JSON or HTML format.

    Args:
        results (Dict): The scan results.
        format (str): The format for the report ("json" or "html").
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{results['target']}_{timestamp}"
    report_data = {**results}
    if format == "json":
        with open(f"{filename}.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    elif format == "html":
        html_content = f"""
        <html>
        <head><meta charset="UTF-8"><title>Scan Report for {results['target']}</title></head>
        <body>
            <h1>Advanced Port Scan Report</h1>
            <p>Target: {results['target']}</p>
            <p>Timestamp: {results['timestamp']}</p>
            <h2>Statistics</h2>
            <ul>
                <li>Total scanned ports: {results['stats']['scanned_ports']}</li>
                <li>Total time: {results['stats']['total_time']}s</li>
                <li>Average time per port: {results['stats']['avg_time_per_port']}s</li>
                <li>Open ports found: {len(results['open_ports'])}</li>
            </ul>
            <h2>Shodan Data</h2>
            <pre>{json.dumps(results.get('shodan_data', {}), indent=2, ensure_ascii=False)}</pre>
            <h2>Open Ports</h2>
            <table border="1">
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Scan Time</th>
                    <th>Banner</th>
                    <th>CVEs</th>
                </tr>
                {"".join([
                    f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{p['version']}</td><td>{p['scan_time']}s</td><td>{p['banner']}</td><td>{', '.join(p['cves']) if p['cves'] else 'None'}</td></tr>"
                    for p in results["open_ports"]
                ])}
            </table>
        </body>
        </html>
        """
        with open(f"{filename}.html", "w", encoding="utf-8") as f:
            f.write(html_content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with Shodan and CVE lookup")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 22-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Connection timeout (seconds)")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="Max concurrent connections")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan integration")
    parser.add_argument("-f", "--format", choices=["json", "html"], default="html", help="Report format")
    args = parser.parse_args()

    if "-" in args.ports:
        ports = range(*map(int, args.ports.split("-")))
    else:
        ports = list(map(int, args.ports.split(",")))
    shodan_client = shodan.Shodan(SHODAN_API_KEY) if args.shodan and SHODAN_API_KEY else None

    results = asyncio.run(main_scan(args.target, ports, args.timeout, args.concurrency, shodan_client))
    generate_report(results, args.format)

    print("\n=== Scan Summary ===")
    print(f"Target: {results['target']}")
    print(f"Timestamp: {results['timestamp']}")
    print(f"Total scanned ports: {results['stats']['scanned_ports']}")
    print(f"Total time: {results['stats']['total_time']}s")
    print(f"Average time per port: {results['stats']['avg_time_per_port']}s")
    print(f"Open ports found: {len(results['open_ports'])}")
    for port_info in results["open_ports"]:
        print(f"Port: {port_info['port']}, Service: {port_info['service']} {('('+port_info['version']+')' if port_info['version'] else '')}, CVEs: {', '.join(port_info['cves']) if port_info['cves'] else 'None'}")
