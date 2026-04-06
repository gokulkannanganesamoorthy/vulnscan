import requests
import urllib3
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# Suppress insecure request warnings for self-signed certs common on WLCs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WirelessControllerScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/120.0.0.0 Safari/537.36')
        }
        self.results = []

        # Known paths for wireless LAN controller management interfaces
        # and cloud administration dashboards.
        self.wlc_signatures = {
            "Cisco WLC": [
                "/login.html",
                "/screens/login.html"
            ],
            "Ubiquiti UniFi": [
                "/manage",
                "/login"
            ],
            "Aruba Mobility Controller": [
                "/auth/index.html",
                "/screens/wms/wms.login.php"
            ],
            "Ruckus ZoneDirector": [
                "/admin/login.jsp"
            ],
            "TP-Link Omada": [
                "/login"
            ]
        }

        # Common paths where WLC configurations or backups might be mistakenly exposed
        self.config_exposure_paths = [
            "/config.xml",
            "/config.txt",
            "/config.bin",
            "/backup.cfg",
            "/backup.xml",
            "/wlc_backup.cfg",
            "/admin/config.xml",
            "/system.cfg",
            "/.env",
            "/.git/config"
        ]

    def check_wlc_fingerprint(self):
        """Attempts to identify if the target is a known WLC."""
        detected = False
        try:
            # Check base response headers (Server header)
            response = requests.get(
                self.target_url, headers=self.headers, verify=False, timeout=10)

            server_header = response.headers.get("Server", "").lower()
            if "cisco" in server_header or "ui" in server_header or "aruba" in server_header:
                self.results.append({
                    'type': 'WLC Fingerprint Detection',
                    'severity': 'Info',
                    'description': f"Server header reveals potential WLC: {server_header}"
                })
                detected = True

            # Probe known login paths for signatures
            for vendor, paths in self.wlc_signatures.items():
                for path in paths:
                    probe_url = urljoin(self.target_url, path)
                    try:
                        probe_res = requests.get(
                            probe_url, headers=self.headers, verify=False, timeout=5)
                        if probe_res.status_code == 200:
                            # Basic string matching in HTML body to confirm vendor
                            html_content = probe_res.text.lower()
                            if vendor.split()[0].lower() in html_content or "wireless" in html_content:
                                self.results.append({
                                    'type': 'WLC Interface Detected',
                                    'severity': 'Medium',
                                    'description': f"Identified potential {vendor} web management interface at {probe_url}"
                                })
                                detected = True
                                break  # Move to next vendor if found
                    except requests.exceptions.RequestException:
                        continue

        except Exception as e:
            self.results.append({
                'type': 'Error',
                'severity': 'Info',
                'description': f"Failed to fingerprint WLC: {str(e)}"
            })

        return detected

    def check_exposed_configs(self):
        """Probes for exposed configuration backup files."""
        for path in self.config_exposure_paths:
            probe_url = urljoin(self.target_url, path)
            try:
                # We use GET here because if a config exists, it might be auto-downloaded
                # or rendered. We check status and Content-Type.
                response = requests.get(
                    probe_url, headers=self.headers, verify=False, timeout=5, stream=True)

                # Consider it a hit if 200 OK and it looks like a file download
                # or XML/text configuration.
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    # If it's HTML, it might be a soft 404/redirect to login, so ignore.
                    if 'text/html' not in content_type:
                        self.results.append({
                            'type': 'Exposed WLC Configuration',
                            'severity': 'High',
                            'description': (f"Potentially sensitive configuration file found at: {probe_url} "
                                            f"(Content-Type: {content_type}). This could leak PSKs, Admin credentials, and network topology.")
                        })

            except requests.exceptions.RequestException:
                continue

    def run_tests(self):
        """Executes the WLC scanning routines."""
        self.check_wlc_fingerprint()
        self.check_exposed_configs()
        
        # If no results, append a clean status to ensure the key exists in the report
        if not self.results:
            self.results.append({
                'type': 'WLC Security Check',
                'severity': 'Info',
                'description': 'No exposed Wireless Controller interfaces or configurations detected.'
            })
            
        return self.results
