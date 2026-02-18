import requests
from bs4 import BeautifulSoup
import re
import json
from urllib.parse import urljoin, urlparse
import time
import random
import string
import concurrent.futures


class AdvancedWebAppTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = []
        self.crawled_urls = set()

    def crawl_website(self, max_pages=50):
        """Crawl the website to discover pages and forms"""
        def crawl_page(url, depth=0):
            if depth > 2 or url in self.crawled_urls or len(self.crawled_urls) >= max_pages:
                return

            self.crawled_urls.add(url)

            try:
                response = self.session.get(url, timeout=10)
                if response.status_code != 200:
                    return

                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract forms
                forms = soup.find_all('form')
                for form in forms:
                    self.analyze_form(form, url)

                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and not href.startswith('javascript:'):
                        next_url = urljoin(url, href)
                        if self.is_same_domain(next_url):
                            crawl_page(next_url, depth + 1)
            except Exception as e:
                print(f"Error crawling {url}: {e}")

        crawl_page(self.target_url)
        return self.crawled_urls

    def is_same_domain(self, url):
        """Check if URL belongs to the same domain"""
        target_domain = urlparse(self.target_url).netloc
        url_domain = urlparse(url).netloc
        return target_domain == url_domain

    def analyze_form(self, form, page_url):
        """Analyze a form for security vulnerabilities"""
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')

        # Construct form URL
        form_url = urljoin(page_url, action)

        # Test for CSRF
        csrf_result = self.test_csrf_protection(form, form_url)
        if csrf_result:
            self.results.append(csrf_result)

        # Test for SQL injection
        sqli_result = self.test_sql_injection(form, form_url)
        if sqli_result:
            self.results.append(sqli_result)

        # Test for XSS
        xss_result = self.test_xss(form, form_url)
        if xss_result:
            self.results.append(xss_result)

        # Test for parameter tampering
        tampering_result = self.test_parameter_tampering(form, form_url)
        if tampering_result:
            self.results.append(tampering_result)

    def test_csrf_protection(self, form, form_url):
        """Test form for CSRF protection"""
        # Check for CSRF tokens
        csrf_token_names = ['csrf_token', 'authenticity_token',
                            '_token', 'anticsrf', 'csrfmiddlewaretoken']

        has_csrf_token = False
        for input_tag in form.find_all('input'):
            name = input_tag.get('name', '').lower()
            if any(token_name in name for token_name in csrf_token_names):
                has_csrf_token = True
                break

        if not has_csrf_token:
            return {
                'type': 'Missing CSRF Protection',
                'severity': 'High',
                'description': f"Form at {form_url} does not have CSRF protection",
                'url': form_url
            }

        return None

    def test_sql_injection(self, form, form_url):
        """Test form for SQL injection vulnerabilities"""
        method = form.get('method', 'get').lower()

        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' AND SLEEP(5)--",
            "'; DROP TABLE users--"
        ]

        for payload in sqli_payloads:
            data = {}

            # Prepare form data
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')

                if name:
                    if input_type in ['text', 'search', 'hidden']:
                        data[name] = payload
                    elif input_type == 'submit':
                        data[name] = input_tag.get('value', 'Submit')

            # Send request
            try:
                start_time = time.time()
                if method == 'post':
                    response = self.session.post(
                        form_url, data=data, timeout=10)
                else:
                    response = self.session.get(
                        form_url, params=data, timeout=10)
                response_time = time.time() - start_time

                # Check for SQL injection indicators
                if any(indicator in response.text.lower() for indicator in ['sql syntax', 'mysql_fetch', 'ora-00936', 'microsoft ole db provider']):
                    return {
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'description': f"SQL injection vulnerability detected at {form_url} with payload: {payload}",
                        'url': form_url,
                        'payload': payload
                    }

                # Check for time-based SQL injection
                if response_time > 5:
                    return {
                        'type': 'Time-Based SQL Injection',
                        'severity': 'High',
                        'description': f"Time-based SQL injection detected at {form_url} with payload: {payload}",
                        'url': form_url,
                        'payload': payload
                    }
            except Exception as e:
                print(f"Error testing SQL injection: {e}")

        return None

    def test_xss(self, form, form_url):
        """Test form for XSS vulnerabilities"""
        method = form.get('method', 'get').lower()

        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src='x' onerror=\"alert('XSS')\">",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]

        for payload in xss_payloads:
            data = {}

            # Prepare form data
            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')

                if name:
                    if input_type in ['text', 'search', 'hidden']:
                        data[name] = payload
                    elif input_type == 'submit':
                        data[name] = input_tag.get('value', 'Submit')

            # Send request
            try:
                if method == 'post':
                    response = self.session.post(
                        form_url, data=data, timeout=10)
                else:
                    response = self.session.get(
                        form_url, params=data, timeout=10)

                # Check for XSS in response
                if payload in response.text:
                    return {
                        'type': 'XSS',
                        'severity': 'High',
                        'description': f"XSS vulnerability detected at {form_url} with payload: {payload}",
                        'url': form_url,
                        'payload': payload
                    }
            except Exception as e:
                print(f"Error testing XSS: {e}")

        return None

    def test_parameter_tampering(self, form, form_url):
        """Test form for parameter tampering vulnerabilities"""
        method = form.get('method', 'get').lower()

        # Get original form data
        original_data = {}
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            value = input_tag.get('value', '')

            if name:
                original_data[name] = value

        # Try tampering with parameters
        for param in original_data:
            if param.lower() in ['id', 'user_id', 'product_id', 'order_id']:
                tampered_data = original_data.copy()
                tampered_data[param] = '1'  # Try to access resource with ID 1

                try:
                    if method == 'post':
                        response = self.session.post(
                            form_url, data=tampered_data, timeout=10)
                    else:
                        response = self.session.get(
                            form_url, params=tampered_data, timeout=10)

                    # Check if we got access to a different resource
                    if 'unauthorized' not in response.text.lower() and 'access denied' not in response.text.lower():
                        return {
                            'type': 'Parameter Tampering',
                            'severity': 'Medium',
                            'description': f"Parameter tampering vulnerability detected at {form_url} for parameter: {param}",
                            'url': form_url,
                            'parameter': param
                        }
                except Exception as e:
                    print(f"Error testing parameter tampering: {e}")

        return None

    def test_jwt_security(self):
        """Test for JWT security vulnerabilities"""
        # Look for JWT tokens in responses
        response = self.session.get(self.target_url, timeout=10)

        # JWT pattern
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        tokens = re.findall(jwt_pattern, response.text)

        for token in tokens:
            # Test for 'none' algorithm vulnerability
            try:
                parts = token.split('.')
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))

                if 'alg' in header and header['alg'].lower() == 'none':
                    self.results.append({
                        'type': 'JWT None Algorithm',
                        'severity': 'High',
                        'description': f"JWT token uses 'none' algorithm: {token[:20]}...",
                        'url': self.target_url
                    })

                # Test for weak secret
                if 'alg' in header and header['alg'].lower() == 'hs256':
                    # Try to crack the secret with common passwords
                    common_secrets = ['secret', 'password',
                                      'api_key', 'jwt_secret']
                    for secret in common_secrets:
                        try:
                            decoded = jwt.decode(
                                token, secret, algorithms=['HS256'])
                            self.results.append({
                                'type': 'Weak JWT Secret',
                                'severity': 'High',
                                'description': f"JWT token cracked with weak secret: {secret}",
                                'url': self.target_url
                            })
                            break
                        except:
                            pass
            except:
                pass

    def test_api_security(self):
        """Test API endpoints for security vulnerabilities"""
        # Common API paths
        api_paths = ['/api', '/rest', '/graphql',
                     '/v1', '/v2', '/swagger', '/openapi.json']

        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Test for API-specific vulnerabilities
                    if 'graphql' in path:
                        self.test_graphql_security(url)
                    elif 'swagger' in path or 'openapi' in path:
                        self.results.append({
                            'type': 'Exposed API Documentation',
                            'severity': 'Medium',
                            'description': f"API documentation is exposed at {url}",
                            'url': url
                        })
            except:
                pass

    def test_graphql_security(self, url):
        """Test GraphQL endpoint for security vulnerabilities"""
        # Test for GraphQL introspection
        introspection_query = {
            "query": "{__schema{types{name}}}"
        }

        try:
            response = self.session.post(
                url, json=introspection_query, timeout=10)
            if response.status_code == 200 and '__schema' in response.text:
                self.results.append({
                    'type': 'GraphQL Introspection',
                    'severity': 'High',
                    'description': f"GraphQL introspection is enabled at {url}",
                    'url': url
                })
        except:
            pass

    def run_tests(self):
        """Run all web application security tests"""
        print(f"[*] Starting advanced web app scan for {self.target_url} (UA: {self.session.headers['User-Agent'][:30]}...)")

        # Test XSS
        print("[*] Testing for XSS...")
        self.test_xss_parallel()

        # Test SQL Injection
        print("[*] Testing for SQL Injection...")
        self.test_sqli_parallel()

        # Test JWT security
        print("[*] Testing JWT security...")
        self.test_jwt_security()

        # Test API security
        print("[*] Testing API security...")
        self.test_api_security()

        # Test Security Headers
        print("[*] Testing security headers...")
        self.test_security_headers()

        # Test Cookie Security
        print("[*] Testing cookie security...")
        self.test_cookie_security()

        return self.results

    def test_xss_parallel(self):
        """Test for XSS vulnerabilities using parallelism"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            print(f"[*] Found {len(forms)} forms to test for XSS.")

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self._test_form_xss, form, response.url) for form in forms]
                concurrent.futures.wait(futures)
                
            # Also test URL parameters
            self._test_url_xss()

        except Exception as e:
            print(f"[-] Error testing XSS: {e}")

    def _test_form_xss(self, form, url):
        """Helper to test a single form for XSS"""
        try:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            target_url = urljoin(url, action)
            
            for payload in self.xss_payloads:
                data = {}
                for input_tag in inputs:
                    if input_tag.get('type') in ['text', 'search', 'url', 'email', 'password']:
                        data[input_tag.get('name')] = payload
                    else:
                         data[input_tag.get('name')] = input_tag.get('value', '')
                
                try:
                    if method == 'post':
                        res = self.session.post(target_url, data=data, timeout=5)
                    else:
                        res = self.session.get(target_url, params=data, timeout=5)
                    
                    if payload in res.text:
                         self.results.append({
                            'type': 'Reflected XSS',
                            'severity': 'High',
                            'description': f"XSS vulnerability found in form at {target_url} with payload {payload}",
                            'url': target_url,
                            'payload': payload
                        })
                         return # Stop after finding one XSS in this form to save time
                except:
                    pass
        except Exception as e:
            pass

    def test_sqli_parallel(self):
        """Test for SQL Injection vulnerabilities using parallelism"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            print(f"[*] Found {len(forms)} forms to test for SQLi.")

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self._test_form_sqli, form, response.url) for form in forms]
                concurrent.futures.wait(futures)

            # Also test URL parameters
            self._test_url_sqli()

        except Exception as e:
            print(f"[-] Error testing SQLi: {e}")

    def _test_form_sqli(self, form, url):
        """Helper to test a single form for SQLi"""
        try:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            target_url = urljoin(url, action)
            
            for payload in self.sqli_payloads:
                data = {}
                for input_tag in inputs:
                    if input_tag.get('type') in ['text', 'search', 'url', 'email', 'password']:
                        data[input_tag.get('name')] = payload
                    else:
                        data[input_tag.get('name')] = input_tag.get('value', '')
                
                try:
                    if method == 'post':
                        res = self.session.post(target_url, data=data, timeout=5)
                    else:
                        res = self.session.get(target_url, params=data, timeout=5)
                    
                    # Basic SQL error detection
                    errors = [
                        "SQL syntax", "mysql_fetch", "native client", "ORA-", 
                        "PostgreSQL query", "SQLite/JDBCDriver"
                    ]
                    
                    for error in errors:
                        if error.lower() in res.text.lower():
                            self.results.append({
                                'type': 'SQL Injection',
                                'severity': 'Critical',
                                'description': f"Possible SQL Injection found in form at {target_url} with payload {payload}",
                                'url': target_url,
                                'payload': payload
                            })
                            return
                except:
                    pass
        except:
             pass

    def _test_url_xss(self):
        """Test URL parameters for XSS"""
        parsed = urlparse(self.target_url)
        if not parsed.query:
            return
            
        params = parsed.query.split('&')
        base_url = self.target_url.split('?')[0]
        
        for payload in self.xss_payloads:
            for param in params:
                if '=' in param:
                    key = param.split('=')[0]
                    # Construct new query
                    new_query = f"{key}={payload}"
                    # Rebuild complete URL (simplified for single param injection)
                    target = f"{base_url}?{new_query}"
                    
                    try:
                        res = self.session.get(target, timeout=5)
                        if payload in res.text:
                            self.results.append({
                                'type': 'Reflected XSS (URL)',
                                'severity': 'High',
                                'description': f"XSS vulnerability found in URL parameter {key}",
                                'url': target,
                                'payload': payload
                            })
                    except:
                        pass

    def _test_url_sqli(self):
        """Test URL parameters for SQLi"""
        parsed = urlparse(self.target_url)
        if not parsed.query:
            return
            
        params = parsed.query.split('&')
        base_url = self.target_url.split('?')[0]
        
        for payload in self.sqli_payloads:
            for param in params:
                 if '=' in param:
                    key = param.split('=')[0]
                    new_query = f"{key}={payload}"
                    target = f"{base_url}?{new_query}"
                    
                    try:
                        res = self.session.get(target, timeout=5)
                        errors = ["SQL syntax", "mysql_fetch", "native client", "ORA-", "PostgreSQL query"]
                        for error in errors:
                            if error.lower() in res.text.lower():
                                 self.results.append({
                                    'type': 'SQL Injection (URL)',
                                    'severity': 'Critical',
                                    'description': f"SQL Injection found in URL parameter {key}",
                                    'url': target,
                                    'payload': payload
                                })
                    except:
                        pass
    
    def test_xss(self):
         # Legacy method wrapper
         self.test_xss_parallel()

    def test_sqli(self):
        # Legacy method wrapper
        self.test_sqli_parallel()

    def test_api_security(self):
        """Test API endpoints for security vulnerabilities"""
        # Common API paths
        api_paths = ['/api', '/rest', '/graphql',
                     '/v1', '/v2', '/swagger', '/openapi.json']

        for path in api_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    # Test for API-specific vulnerabilities
                    if 'graphql' in path:
                        self.test_graphql_security(url)
                    elif 'swagger' in path or 'openapi' in path:
                        self.results.append({
                            'type': 'Exposed API Documentation',
                            'severity': 'Medium',
                            'description': f"API documentation is exposed at {url}",
                            'url': url
                        })
            except:
                pass

    def test_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers

            security_headers = {
                'X-Frame-Options': 'Protects against Clickjacking attacks.',
                'Content-Security-Policy': 'Mitigates XSS and data injection attacks.',
                'Strict-Transport-Security': 'Enforces secure (HTTPS) connections.',
                'X-Content-Type-Options': 'Prevents MIME-sniffing.',
                'Referrer-Policy': 'Controls how much referrer information is included with requests.',
                'Permissions-Policy': 'Controls which browser features can be used.'
            }

            for header, description in security_headers.items():
                if header not in headers:
                    self.results.append({
                        'type': 'Missing Security Header',
                        'severity': 'Low', # Keep as Low/Medium to avoid alarm fatigue for common missing headers
                        'description': f"Missing {header} header. {description}",
                        'url': self.target_url
                    })
        except Exception as e:
            print(f"[-] Error checking security headers: {e}")

    def test_cookie_security(self):
        """Check for insecure cookie configurations"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            cookies = response.cookies

            for cookie in cookies:
                issues = []
                if not cookie.secure:
                     issues.append("Missing 'Secure' flag")
                if not cookie.has_nonstandard_attr('HttpOnly') and not cookie.get_nonstandard_attr('HttpOnly'): # Requests cookie jar handling vary
                     # Check if it's actually HttpOnly (requests might not expose this easily depending on version, generic check)
                     # Inspecting raw headers is often more reliable for HttpOnly
                     pass 

                # Re-check via headers for Set-Cookie to be sure about flags
                pass
            
            # Robust check using Set-Cookie header parsing
            if 'Set-Cookie' in response.headers:
                # This catches multiple Set-Cookie headers
                # Note: requests merges them, but we can iterate if we access raw or splitting
                # For simplicity, we just look for flags in the string representation if possible or rely on the cookie jar
                pass

            # Improved Cookie Check iterating properly
            for cookie in self.session.cookies:
                 # Check Secure
                if not cookie.secure:
                    self.results.append({
                        'type': 'Insecure Cookie',
                        'severity': 'Medium',
                        'description': f"Cookie '{cookie.name}' is missing the 'Secure' flag.",
                        'url': self.target_url
                    })
                
                # Check HttpOnly (Requires some heuristic as requests.cookies doesn't always show it clearly on the object)
                # We can check the rest of the cookie attributes if available, but 'httponly' is often a specific attribute
                if not cookie.has_nonstandard_attr('HttpOnly'):
                     self.results.append({
                        'type': 'Insecure Cookie',
                        'severity': 'Medium',
                        'description': f"Cookie '{cookie.name}' may be missing the 'HttpOnly' flag.",
                        'url': self.target_url
                    })

        except Exception as e:
            print(f"[-] Error checking cookie security: {e}")
