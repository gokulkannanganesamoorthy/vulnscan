import requests
import urllib3
from urllib.parse import urljoin
import json

# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WSNApiAuditor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.headers = {
            'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                           'AppleWebKit/537.36 (KHTML, like Gecko) '
                           'Chrome/120.0.0.0 Safari/537.36'),
            'Accept': 'application/json'
        }
        self.results = []

        # Common API paths for Wireless Sensor Networks (WSN) gateways
        # and 5G Core Network REST APIs (e.g., AMF, SMF).
        self.api_endpoints = [
            "/api/v1/sensors",
            "/api/devices",
            "/api/gateway/status",
            "/wsn/telemetry",
            "/iot/devices",
            "/api/telemetry",
            
            # Common 5G Core REST endpoints 
            "/namf-comm/v1/ue-contexts",
            "/nsmf-pdusession/v1/sm-contexts",
            "/nudm-sdm/v1/shared-data",
            "/nrf-disc/v1/nf-instances",
            
            # General health/debug endpoints that might leak cluster info
            "/health",
            "/metrics",
            "/actuator/env"
        ]

    def test_unauthenticated_access(self):
        """Probes WSN/5G endpoints for unauthenticated access (BOLA/Exposure)."""
        vulnerable_endpoints = []
        
        for path in self.api_endpoints:
            probe_url = urljoin(self.target_url, path)
            try:
                response = requests.get(
                    probe_url, headers=self.headers, verify=False, timeout=5)

                # If the API returns 200 OK without authentication, it's a critical finding
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    
                    # Ensure it's returning data (JSON/XML) and not a soft 404 HTML page
                    if 'json' in content_type or 'xml' in content_type or 'text/plain' in content_type:
                        
                        finding = {
                            'type': 'Unauthenticated WSN/5G API Exposure',
                            'severity': 'Critical',
                            'description': f"Exposed API endpoint found at: {probe_url}. ",
                            'endpoint': probe_url
                        }
                        
                        # Give a snippet of what it leaks if it's JSON
                        if 'json' in content_type:
                            try:
                                data = response.json()
                                snippet = str(data)[:100] + "..."
                                finding['description'] += f"Response snippet: {snippet}"
                            except json.JSONDecodeError:
                                pass
                                
                        self.results.append(finding)
                        vulnerable_endpoints.append(probe_url)

                # Look for misconfigured 403s that might allow OPTIONS or POST
                elif response.status_code == 403:
                     # Check if OPTIONS is allowed (CORS misconfig)
                     options_res = requests.options(probe_url, headers=self.headers, verify=False, timeout=5)
                     allowed_methods = options_res.headers.get('Allow', '')
                     if 'GET' in allowed_methods or 'POST' in allowed_methods:
                          self.results.append({
                            'type': 'API Misconfiguration',
                            'severity': 'Medium',
                            'description': f"Endpoint {probe_url} returned 403, but allows methods: {allowed_methods}."
                        })

            except requests.exceptions.RequestException:
                continue
                
        return vulnerable_endpoints

    def run_tests(self):
        """Executes the WSN/IoT API auditing routines."""
        self.test_unauthenticated_access()
        
        if not self.results:
            self.results.append({
                'type': 'WSN/5G API Check',
                'severity': 'Info',
                'description': 'No unauthenticated Wireless Sensor Network or 5G Core REST endpoints detected.'
            })
            
        return self.results
