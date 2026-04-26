import re
try:
    import numpy as np
except ImportError:
    np = None
from bs4 import BeautifulSoup
import requests


class AIVulnerabilityDetector:
    def __init__(self):
        """Initialize AI-powered vulnerability detector with fallback to rule-based detection"""
        self.models_available = False
        self.models = {}

        if np is None:
            print("[!] numpy not found. AI-powered checks will be limited.")

        # Try to load pre-trained models
        try:
            # We'll skip loading models for now since they don't exist
            # In a production environment, you would have pre-trained models here
            self.models_available = False
            print(
                "[!] Pre-trained models not found. Using rule-based detection instead.")
        except Exception as e:
            print(
                f"[!] Error loading models: {e}. Using rule-based detection instead.")
            self.models_available = False

        # Define patterns for rule-based detection
        self.xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'eval\(',
            r'document\.',
            r'window\.',
            r'alert\(',
            r'confirm\(',
            r'prompt\(',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>'
        ]

        self.sqli_patterns = [
            r'(\s|^)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|alter\s+table)(\s|$)',
            r'(\s|^)(or\s+1\s*=\s*1|or\s+1\s*=\s*1\s*--|\'\s+or\s+\'1\'\s*=\s*\'1)(\s|$)',
            r'(\s|^)(and\s+1\s*=\s*1|and\s+1\s*=\s*1\s*--|\'\s+and\s+\'1\'\s*=\s*\'1)(\s|$)',
            r'(\s|^)(waitfor\s+delay|sleep\s*\(|benchmark\s*\(|pg_sleep\(|dbms_pipe\.receive_message)(\s|$)',
            r'(\s|^)(xp_cmdshell|exec\s*\(|sp_oacreate|sp_adduser)(\s|$)',
            r'(\s|^)(load_file\(|into\s+outfile|into\s+dumpfile)(\s|$)'
        ]

        self.csrf_patterns = [
            r'csrf',
            r'_token',
            r'authenticity_token',
            r'nonce',
            r'xsrf'
        ]

    def predict_xss(self, input_data):
        """Predict XSS vulnerability using rule-based detection"""
        score = 0
        max_score = len(self.xss_patterns)

        for pattern in self.xss_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                score += 1

        probability = score / max_score if max_score > 0 else 0

        return {
            'vulnerability': 'XSS',
            'probability': probability,
            'confidence': 'High' if probability > 0.7 else 'Medium' if probability > 0.4 else 'Low'
        }

    def predict_sqli(self, input_data):
        """Predict SQL injection using rule-based detection"""
        score = 0
        max_score = len(self.sqli_patterns)

        for pattern in self.sqli_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                score += 1

        probability = score / max_score if max_score > 0 else 0

        return {
            'vulnerability': 'SQL Injection',
            'probability': probability,
            'confidence': 'High' if probability > 0.7 else 'Medium' if probability > 0.4 else 'Low'
        }

    def analyze_response(self, response_content):
        """Analyze HTTP response for vulnerabilities"""
        results = []

        try:
            # Parse HTML
            soup = BeautifulSoup(response_content, 'html.parser')

            # Analyze forms
            forms = soup.find_all('form')
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()

                # Check for CSRF protection
                has_csrf = False
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name', '').lower()
                    if any(re.search(pattern, name, re.IGNORECASE) for pattern in self.csrf_patterns):
                        has_csrf = True
                        break

                if not has_csrf:
                    results.append({
                        'vulnerability': 'Missing CSRF Protection',
                        'probability': 0.8,
                        'confidence': 'High',
                        'description': f'Form at {form_action} does not have CSRF protection'
                    })

                # Analyze input fields
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '')
                    input_type = input_tag.get('type', 'text')

                    if input_type in ['text', 'search', 'hidden', 'url', 'email']:
                        # Test for XSS
                        xss_result = self.predict_xss(input_name)
                        if xss_result['probability'] > 0.3:
                            results.append({
                                'vulnerability': 'XSS',
                                'probability': xss_result['probability'],
                                'confidence': xss_result['confidence'],
                                'description': f'Input field "{input_name}" may be vulnerable to XSS'
                            })

                        # Test for SQLi
                        sqli_result = self.predict_sqli(input_name)
                        if sqli_result['probability'] > 0.3:
                            results.append({
                                'vulnerability': 'SQL Injection',
                                'probability': sqli_result['probability'],
                                'confidence': sqli_result['confidence'],
                                'description': f'Input field "{input_name}" may be vulnerable to SQL injection'
                            })

            # Analyze URLs in the page
            urls = re.findall(r'href=[\'"]?([^\'" >]+)', response_content)
            for url in urls:
                # Check for potential IDOR in URLs
                if re.search(r'id=\d+', url):
                    results.append({
                        'vulnerability': 'Potential IDOR',
                        'probability': 0.6,
                        'confidence': 'Medium',
                        'description': f'URL contains ID parameter: {url}'
                    })

                # Check for sensitive parameters
                sensitive_params = ['user', 'admin',
                                    'password', 'token', 'key']
                for param in sensitive_params:
                    if param in url.lower():
                        results.append({
                            'vulnerability': 'Sensitive Parameter Exposure',
                            'probability': 0.5,
                            'confidence': 'Medium',
                            'description': f'URL contains sensitive parameter: {url}'
                        })

            # Analyze JavaScript code
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    # Check for dangerous functions
                    dangerous_functions = [
                        'eval', 'innerHTML', 'outerHTML', 'document.write']
                    for func in dangerous_functions:
                        if func in script.string:
                            results.append({
                                'vulnerability': 'Dangerous JavaScript Function',
                                'probability': 0.7,
                                'confidence': 'High',
                                'description': f'Script uses dangerous function: {func}'
                            })

            # Check for security headers
            security_headers = {
                'Content-Security-Policy': 'CSP',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'X-Frame-Options': 'X-Frame-Options',
                'Strict-Transport-Security': 'HSTS',
                'X-XSS-Protection': 'X-XSS-Protection'
            }

            # Note: In a real implementation, you would check response headers
            # For now, we'll simulate this check
            missing_headers = []
            for header, name in security_headers.items():
                # Simulate missing headers (in real implementation, check actual response)
                missing_headers.append(name)

            if missing_headers:
                results.append({
                    'vulnerability': 'Missing Security Headers',
                    'probability': 0.6,
                    'confidence': 'Medium',
                    'description': f'Missing security headers: {", ".join(missing_headers)}'
                })

        except Exception as e:
            results.append({
                'vulnerability': 'Analysis Error',
                'probability': 0.0,
                'confidence': 'Low',
                'description': f'Error analyzing response: {str(e)}'
            })

        return results
