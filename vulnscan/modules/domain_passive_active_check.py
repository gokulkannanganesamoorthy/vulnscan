import requests
import dns.resolver
import concurrent.futures
import json
import time
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import socket
import os


class AdvancedSubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()
        self.results = []
        
        # Configure robust DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 5.0
        self.wordlist = self.load_wordlist()

    def load_wordlist(self):
        """Load subdomain wordlist"""
        # Common subdomains
        common = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging', 'test',
            'api', 'docs', 'support', 'shop', 'store', 'app', 'm', 'mobile',
            'login', 'portal', 'dashboard', 'console', 'internal', 'intranet',
            'vpn', 'remote', 'secure', 'payment', 'checkout', 'account'
        ]

        # Additional wordlist from file if available
        try:
            # Use path relative to this file's location to find subdomains.txt in project root
            # This file is in modules/, so we need to go up one level
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            file_path = os.path.join(base_dir, 'subdomains.txt')
            with open(file_path, 'r') as f:
                additional = [line.strip() for line in f if line.strip()]
                return common + additional
        except:
            return common

    def certificate_transparency_enumeration(self):
        """Enumerate subdomains using Certificate Transparency logs"""
        try:
            # Use crt.sh API
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url)
            data = response.json()

            for cert in data:
                name_value = cert['name_value']
                for name in name_value.split('\n'):
                    if name.endswith(self.domain) and name != self.domain:
                        self.subdomains.add(name)
        except Exception as e:
            print(f"Error in Certificate Transparency enumeration: {e}")

    def dns_brute_force(self):
        """Brute force subdomains using DNS resolution"""
        def resolve_subdomain(subdomain):
            try:
                answers = dns.resolver.resolve(
                    f"{subdomain}.{self.domain}", 'A')
                if answers:
                    return f"{subdomain}.{self.domain}"
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(resolve_subdomain, word)
                       for word in self.wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)

    def search_engine_enumeration(self):
        """Enumerate subdomains using search engines"""
        search_engines = [
            f"https://www.google.com/search?q=site:{self.domain}",
            f"https://www.bing.com/search?q=site:{self.domain}",
            f"https://duckduckgo.com/?q=site:{self.domain}"
        ]

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        for engine in search_engines:
            try:
                response = requests.get(engine, headers=headers)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract URLs from search results
                for link in soup.find_all('a'):
                    href = link.get('href', '')
                    if self.domain in href:
                        subdomain = href.split('//')[1].split('/')[0]
                        if subdomain.endswith(self.domain) and subdomain != self.domain:
                            self.subdomains.add(subdomain)
            except Exception as e:
                print(f"Error with {engine}: {e}")

    def virustotal_enumeration(self):
        """Enumerate subdomains using VirusTotal API"""
        try:
            # Note: Requires a VirusTotal API key
            api_key = "YOUR_VIRUSTOTAL_API_KEY"
            url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={self.domain}"
            response = requests.get(url)
            data = response.json()

            if 'subdomains' in data:
                for subdomain in data['subdomains']:
                    self.subdomains.add(subdomain)
        except Exception as e:
            print(f"Error in VirusTotal enumeration: {e}")

    def certificate_enumeration(self):
        """Enumerate subdomains by examining SSL certificates"""
        def get_certificate_subdomain(subdomain):
            try:
                hostname = f"{subdomain}.{self.domain}"
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        x509_cert = x509.load_der_x509_certificate(
                            cert, default_backend())

                        # Extract SANs (Subject Alternative Names)
                        sans = x509_cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        ).value.get_values_for_type(x509.DNSName)

                        for san in sans:
                            if san.endswith(self.domain) and san != self.domain:
                                return san
            except:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(get_certificate_subdomain, word)
                       for word in self.wordlist]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)

    def check_subdomain_takeovers(self):
        """Check for subdomain takeover vulnerabilities"""
        takeover_indicators = {
            'github': ['There isn\'t a GitHub Pages site here', 'githubusercontent.com'],
            'heroku': ['herokucdn.com/error-pages/no-such-app.html', 'herokussl.com'],
            'aws': ['NoSuchBucket', 'Code: NoSuchBucket'],
            'azure': ['Azure Web App - Error 404', 'azurewebsites.net'],
            'gcp': ['404. That’s an error.', 'cloud.google.com'],
            'shopify': ['Sorry, this shop is currently unavailable.', 'myshopify.com'],
            'unbounce': ['The page you are looking for is not found', 'unbouncepages.com']
        }

        for subdomain in self.subdomains:
            try:
                response = requests.get(f"http://{subdomain}", timeout=5)
                content = response.text.lower()

                for service, indicators in takeover_indicators.items():
                    if any(indicator.lower() in content for indicator in indicators):
                        self.results.append({
                            'type': 'Subdomain Takeover',
                            'severity': 'High',
                            'description': f"Potential {service} subdomain takeover: {subdomain}",
                            'subdomain': subdomain
                        })
                        break
            except:
                pass

    def dns_record_enumeration(self):
        """Enumerate important DNS records (TXT, MX, NS)"""
        record_types = ['TXT', 'MX', 'NS', 'SOA']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(self.domain, record_type)
                for rdata in answers:
                    self.results.append({
                        'type': f'DNS Record ({record_type})',
                        'severity': 'Info',
                        'description': f"Found {record_type} record: {rdata.to_text()}",
                        'domain': self.domain,
                        'record_data': rdata.to_text()
                    })
                    
                    # Check for specific misconfigurations in TXT records (SPF/DMARC)
                    if record_type == 'TXT':
                        text = rdata.to_text()
                        if 'v=spf1' in text:
                             if '-all' not in text and '~all' not in text:
                                  self.results.append({
                                    'type': 'Weak SPF Record',
                                    'severity': 'Medium',
                                    'description': f"SPF record may be too permissive (missing -all or ~all): {text}",
                                    'domain': self.domain
                                })
            except Exception as e:
                # Record might not exist, which is fine
                pass

    def run_enumeration(self):
        """Run all subdomain enumeration techniques"""
        print(f"[*] Starting advanced subdomain enumeration for {self.domain}")

        techniques = [
            ("Certificate Transparency", self.certificate_transparency_enumeration),
            ("DNS Brute Force", self.dns_brute_force),
            ("Search Engines", self.search_engine_enumeration),
            ("VirusTotal", self.virustotal_enumeration),
            ("Certificate Analysis", self.certificate_enumeration),
            ("DNS Records", self.dns_record_enumeration)
        ]

        for name, technique in techniques:
            print(f"[*] Running {name} enumeration...")
            technique()
            print(
                f"[*] {name} enumeration completed. Found {len(self.subdomains)} subdomains so far.")

        print(f"[*] Checking for subdomain takeovers...")
        self.check_subdomain_takeovers()

        return {
            'subdomains': list(self.subdomains),
            'takeovers': self.results,
            'total': len(self.subdomains),
            'dns_records': [r for r in self.results if 'DNS Record' in r.get('type', '')]
        }
