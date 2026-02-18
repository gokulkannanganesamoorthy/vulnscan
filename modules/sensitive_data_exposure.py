import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class SensitiveDataExposureTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
        # Robust Retry Logic
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = []

        # Pre-compile Regex Patterns for Performance
        self.pii_patterns = {
            'SSN (US)': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'Credit Card': re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            'Phone Number (Generic)': re.compile(r'\b\+?1?[-.]?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b')
        }

        self.secret_patterns = {
            'AWS Access Key': re.compile(r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])'),
            'AWS Secret Key': re.compile(r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])'),
            'Google API Key': re.compile(r'AIza[0-9A-Za-z-_]{35}'),
            'Slack Token': re.compile(r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
            'Facebook Access Token': re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),
            'GitHub Personal Access Token': re.compile(r'ghp_[0-9a-zA-Z]{36}'),
            'Generic API Key': re.compile(r'(?i)(?:api_key|apikey|secret|token)\s*[:=]\s*[\'"]([A-Za-z0-9-_]{16,})[\'"]'),
            'Private Key Header': re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----')
        }

    def check_sensitive_data(self):
        """Check for sensitive data exposure in the response content"""
        print(f"[*] Checking for sensitive data exposure at {self.target_url}")
        
        try:
            response = self.session.get(self.target_url, timeout=15) # Increased timeout
            content = response.text
            
            # 1. PII Detection
            self._check_pii(content)
            
            # 2. Secret Key Detection
            self._check_secrets(content)
            
            # 3. Comment Analysis
            self._check_comments(content)
            
            # 4. Email Addresses
            self._check_emails(content)

        except Exception as e:
            print(f"[-] Error checking sensitive data: {e}")

        return self.results

    def _check_pii(self, content):
        """Check for PII patterns like SSN, Credit Cards, etc."""
        for name, pattern in self.pii_patterns.items():
            matches = pattern.finditer(content)
            unique_matches = set(m.group() for m in matches)
            if unique_matches:
                 # Filter out common false positives
                 filtered_matches = [m for m in unique_matches if not self._is_false_positive(m, name)]
                 if filtered_matches:
                    self.results.append({
                        'type': 'Potential PII Exposure',
                        'severity': 'High',
                        'description': f"Found {len(filtered_matches)} potential {name} matches.",
                        'url': self.target_url,
                        'matches': list(filtered_matches)[:5] # Limit output
                    })

    def _is_false_positive(self, match, type):
        """Heuristic to filter out likely false positives"""
        # Example implementation
        return False

    def _check_secrets(self, content):
        """Check for potential API keys and secrets"""
        for name, pattern in self.secret_patterns.items():
            matches = pattern.finditer(content)
            unique_matches = set(m.group() for m in matches)
            if unique_matches:
                self.results.append({
                    'type': 'Sensitive Secret Exposure',
                    'severity': 'Critical',
                    'description': f"Found potential {name}.",
                    'url': self.target_url,
                    'matches': [m[:4] + '...' + m[-4:] if len(m) > 8 else 'REDACTED' for m in unique_matches][:5] 
                })

    def _check_comments(self, content):
        """Check for suspicious comments in HTML source"""
        soup = BeautifulSoup(content, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, requests.compat.str) and '<!--' in str(text) or isinstance(text, str) and text.strip().startswith('<!--')) 
        # BS4 handles comments differently depending on parser, better to use regex for raw content sometimes
        
        # Regex for HTML comments
        comment_pattern = r'<!--(.*?)-->'
        matches = re.finditer(comment_pattern, content, re.DOTALL)
        
        suspicious_keywords = ['todo', 'fixme', 'bug', 'admin', 'password', 'secret', 'test', 'debug', 'config']
        
        suspicious_comments = []
        for m in matches:
            comment_text = m.group(1).lower()
            if any(keyword in comment_text for keyword in suspicious_keywords):
                suspicious_comments.append(m.group(0))

        if suspicious_comments:
            self.results.append({
                'type': 'Suspicious Comments',
                'severity': 'Low',
                'description': f"Found {len(suspicious_comments)} suspicious comments.",
                'url': self.target_url,
                'matches': suspicious_comments[:5]
            })

    def _check_emails(self, content):
        """Check for email addresses"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        matches = set(re.findall(email_pattern, content))
        
        if matches:
             self.results.append({
                'type': 'Email Address Disclosure',
                'severity': 'Info',
                'description': f"Found {len(matches)} email addresses.",
                'url': self.target_url,
                'matches': list(matches)[:10]
            })

    def run_tests(self):
        return self.check_sensitive_data()
