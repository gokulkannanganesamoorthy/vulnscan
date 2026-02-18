#!/usr/bin/env python3
from xml.sax.saxutils import escape
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from tqdm import tqdm
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from vulnscan.base.utils import extractHeaders, strength, isProtected, stringToBinary, longestCommonSubstring
from vulnscan.base.sendRequest import sendRequest
from vulnscan.base.extractHTMLInformation import extractHTMLInformation
from vulnscan.base.rangeFinder import rangeFinder
from vulnscan.base.formEvaluate import formEvaluate
from vulnscan.base.modifyManipulateAPI import modifyManipulateAPI
from vulnscan.base.crawl import crawl
from vulnscan.base.prompt import prompt
from vulnscan.base.formParser import formParser
from vulnscan.base.entropy import isRandom
from vulnscan.base.colors import green, yellow, end, run, good, info, bad, white, red
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import statistics
import re
import random
import json
import argparse
import requests
import threading
import queue
import optparse
import nmap
import time
import socket
import ssl
import time
import sys
from progress.bar import Bar
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
from pprint import pprint
import colorama
from vulnscan.base.testing import headers
import concurrent.futures
from pathlib import Path
from fuzzywuzzy import fuzz, process
import html
import secrets
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from vulnscan.modules.advanced_api_checking import GraphQLSecurityTester, APISecurityTester
from vulnscan.modules.advanced_reporting import AdvancedSecurityReporter
from vulnscan.modules.ai_powered_checking import AIVulnerabilityDetector
from vulnscan.modules.cloud_vulnerability_checking import CloudSecurityScanner
from vulnscan.modules.domain_passive_active_check import AdvancedSubdomainEnumerator
from vulnscan.modules.modern_security_platform import ModernSecurityPlatform
from vulnscan.modules.web_app_checking import AdvancedWebAppTester
from vulnscan.modules.sensitive_data_exposure import SensitiveDataExposureTester


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#              IP Information           #                 IP Information                #                IP Information                 #              IP Information           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def get_ip_address(domain_name):
    if not domain_name.startswith(("http://", "https://")):
        domain_name = "http://" + domain_name

    parsed_url = urlparse(domain_name)
    domain_name = parsed_url.netloc  # Extracting domain name from the URL

    ip_address = socket.gethostbyname(domain_name)
    print(f"\nIP Address: {ip_address}")


def get_ip_address(target):
    """Get IP address from domain or URL"""
    # Remove URL scheme if present
    if target.startswith(('http://', 'https://')):
        parsed_url = urlparse(target)
        domain_name = parsed_url.netloc
    else:
        domain_name = target

    try:
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror as e:
        print(f"Error resolving {domain_name}: {e}")
        return None


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#               Port Scanning           #                  Port Scanning                #                 Port Scanning                 #               Port Scanning           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def scan_single_port(target, port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    result = scanner.scan(ip_address, arguments=f'-p {port}')
    if result['scan'][ip_address]['tcp'][int(port)]['state'] == 'open':
        print('\033[32m' + f"Port {port} is open" + '\033[0m')
        port_scan_results.append(f"\n\tPort {port} is open")
    else:
        print('\033[31m' + f"Port {port} is closed" + '\033[0m')
        port_scan_results.append(f"\n\tPort {port} is closed")
    return port_scan_results


def scan_custom_ports(target, ports):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    scanner.scan(
        ip_address, arguments=f'-p {",".join(str(port) for port in ports)} -sT')
    open_ports = []
    closed_ports = []
    port_scan_results = []  # Initialize port_scan_results list

    for port in ports:
        port_state = scanner[ip_address]['tcp'][port]['state']
        if port_state == 'open':
            open_ports.append(port)
        else:
            closed_ports.append(port)

    print('\033[33m' + "Open Ports:" + '\033[0m')
    if open_ports:
        for port in open_ports:
            print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
            port_scan_results.append(f"\n\tPort {port} is open")
    else:
        print("\tNo open ports found in the specified range.")
        port_scan_results.append(
            f"\n\tNo open ports found in the specified range.")

    print('\033[33m' + "Closed Ports:" + '\033[0m')
    if closed_ports:
        for port in closed_ports:
            print('\033[31m' + f"\tPort {port} is closed" + '\033[0m')
            port_scan_results.append(f"\n\tPort {port} is open")
    else:
        print("\tNo closed ports found in the specified range.")
        port_scan_results.append(
            f"\n\tNo open ports found in the specified range.")
    return port_scan_results


def scan_range_of_ports(target, start_port, end_port):
    ip_address = get_ip_address(target)
    scanner = nmap.PortScanner()
    port_range = f"{start_port}-{end_port}"
    result = scanner.scan(ip_address, arguments=f'-p {port_range}')

    port_scan_results = []
    if ip_address in result['scan']:
        port_data = result['scan'][ip_address]

        if 'tcp' in port_data:
            for port, port_info in port_data['tcp'].items():
                if port_info['state'] == 'open':
                    print('\033[32m' + f"\tPort {port} is open" + '\033[0m')
                    port_scan_results.append(f"\n\tPort {port} is open")
        else:
            print(
                '\033[31m' + f"\tNo open ports found in the specified range." + '\033[0m')
            port_scan_results.append(
                "\n\tNo open ports found in the specified range.")
    else:
        print("No scan results found for the target IP.")
        port_scan_results.append(
            "\n\tNo scan results found for the target IP.")

    return port_scan_results


# Function to read subdomains from a file
def from_file(filename):
    with open(filename, 'r') as f:
        subdomains = f.read().split('\n')
        return subdomains

# Function to check if a subdomain is active

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                Domain Enumeration             #                  Domain Enumeration                   #                 Domain Enumeration            #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def check_subdomain(domain, sub):
    subdomain = f"http://{sub.strip()}.{domain}"
    try:
        response = requests.get(subdomain, timeout=5)
        # Print response code
        print(f" Response code for {sub}.{domain}: {response.status_code}")
        if response.status_code == 200:
            return True
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        return False
    return False

# Function to append active subdomains to a list if they exist


def append_if_exists(host, sub):
    if check_subdomain(host, sub):
        with lock:
            active_domains.append(f"{sub}.{host}")

# Function for thread worker to get active subdomains


def get_active():
    while True:
        try:
            i = q.get_nowait()
        except queue.Empty:
            break
        append_if_exists(domain_name, i)
        bar.next()
        q.task_done()

# Function to get command-line arguments


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--input", dest="input_list", default="subdomains.txt",
                      help="read the list from INPUT_FILE", metavar="INPUT_FILE")
    parser.add_option("-t", "--threads", type=int, dest="n_threads", help="Set the number of threads",
                      metavar="N_THREADS", default=12)
    parser.add_option("-u", "--url", dest="target_url", help="Target URL/Domain for the scan", metavar="URL")
    parser.add_option("--scan", dest="scan_type", default="interactive", help="Type of scan to run (e.g., 'comprehensive')", metavar="SCAN_TYPE")
    return parser.parse_args()

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                Domain Fingerprinting          #                  Domain Fingerprinting                #                Domain Fingerprinting          #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def get_server_info(target_domain):
    url = f"http://{target_domain}"
    try:
        response = requests.get(url, timeout=10)  # Timeout set to 10 seconds
        if response.status_code == 200:
            server_header = response.headers.get("Server", "N/A")
            x_powered_by_header = response.headers.get("X-Powered-By", "N/A")

            print(f"\nServer header: {server_header}")
            server_info.append(f"\n\tServer header: {server_header}")
            print(f"X-Powered-By header: {x_powered_by_header}")
            server_info.append(
                f"\n\tX-Powered-By header: {x_powered_by_header}")
        else:
            print(
                f"\nFailed to retrieve data from {url}. Status Code: {response.status_code}")
            server_info.append(
                f"\n\tFailed to retrieve data from {url}. Status Code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"\nFailed to connect to {url}: {str(e)}")
        server_info.append(f"\n\tFailed to connect to {url}: {str(e)}")


# Create a session with a User-Agent header
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Win64; x64) AppleWebKit/537.36 Chrome/87.0.4280.88"

# List of XSS payloads to test
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror=\"alert('XSS')\">",
    # Add more payloads here as needed
]


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                getting form details           #                  getting form details                 #                 getting form details          #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


# Function to retrieve forms from a URL
def get_forms(url):
    response = s.get(url)
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

# Function to extract form details


def form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []

    # Extract input fields
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append(
            {"type": input_type, "name": input_name, "value": input_value}
        )

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Function to check for SQL injection vulnerability


def is_vulnerable(response):
    return False

# Function to perform SQL injection testing


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                SQL Injection          #                  SQL Injection                #                 SQL Injection                 #               SQL Injection           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def test_sql_injection(url):
    # Ensure the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    forms = get_forms(url)
    print(f"\n[+] {len(forms)} forms found on {url}.")
    sql_test_results.append(f"\n\t[+] {len(forms)} forms found on {url}.")
    if (len(forms) == '0'):
        print("\n No SQL Injection detected")

    for form in forms:
        form_details_dict = form_details(form)

        # Initialize variables to track detection for each payload
        single_quote_detected = False
        double_quote_detected = False

        for payload in ["'", "\""]:
            data = {}

            # Create payloads for each input field
            for input_tag in form_details_dict["inputs"]:
                input_name = input_tag["name"]
                input_value = input_tag["value"]
                if input_value:
                    data[input_name] = input_value + payload
                elif input_tag["type"] != "submit":
                    data[input_name] = "test" + payload

            # Construct the URL and make the request
            target_url = urljoin(url, form_details_dict["action"])
            if form_details_dict["method"] == "post":
                response = s.post(target_url, data=data)
            elif form_details_dict["method"] == "get":
                response = s.get(target_url, params=data)

            # Check for SQL injection vulnerability and update detection status
            if is_vulnerable(response):
                if payload == "'":
                    single_quote_detected = True
                elif payload == "\"":
                    double_quote_detected = True
                else:
                    print('\nNo SQL Injection Detected')

        # Print detection status for each payload
        if single_quote_detected:
            print("\nSingle quote SQL injection detected:", target_url)
            sql_test_results.append(
                "\n\tSingle quote SQL injection detected:", target_url)
        else:
            print("\nNo single quote SQL injection detected")
            sql_test_results.append(
                "\n\tNo single quote SQL injection detected")

        if double_quote_detected:
            print("\nDouble quote SQL injection detected:", target_url)
            sql_test_results.append(
                "\n\tDouble quote SQL injection detected:", target_url)
        else:
            print("\nNo double quote SQL injection detected")
            sql_test_results.append(
                "\n\tNo double quote SQL injection detected")


def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url, timeout=10).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    details = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)
        return requests.get(target_url, params=data, timeout=10)

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                  XSS Testing          #                    XSS Testing                #                   XSS Testing                 #                 XSS Testing           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def scan_xss(url):
    # Ensure the URL starts with "http://" or "https://"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    forms = get_all_forms(url)
    print(f"\n[+] Detected {len(forms)} forms on {url}.")
    xss_test_results.append(f"\n\t[+] Detected {len(forms)} forms on {url}.")

    # Initialize a flag to track if any payload is detected
    any_payload_detected = False

    for form in forms:
        form_details = get_form_details(form)

        # Initialize variables to track detection for each payload
        xss_detected = {}

        for payload in xss_payloads:
            response = submit_form(form_details, url, payload)
            if payload in response.content.decode():
                xss_detected[payload] = True
                any_payload_detected = True
            else:
                xss_detected[payload] = False

        # Print detection status for each payload
        for payload, detected in xss_detected.items():
            if detected:
                print(colorama.Fore.RED +
                      f"[!]XSS detected for payload '{payload}': {url}")
                xss_test_results.append(
                    f"\n\t[!]XSS detected for payload '{payload}': {url}")
                print(colorama.Fore.YELLOW + f"[*] Form details:")
                xss_test_results.append(f"\n\t[*] Form details:")
                print(form_details)
                xss_test_results.append("\n\t"+form_details)
            else:
                print(f"\nNo XSS detected for payload '{xss_payloads}'")
                xss_test_results.append(
                    f"\n\tNo XSS detected for payload '{xss_payloads}'")


def banner():
    yellow = "\033[93m"
    white = "\033[0m"
    end = "\033[0m"
    print('''
     %s⚡ %sVuln Scan%s  ⚡%s
    ''' % (yellow, white, yellow, end))


def sanitize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


banner()

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#                 CSRF          #                  CSRF                 #                 CSRF                  #               CSRF            #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def csrf(domain_name):
    lightning = '\033[93;5m ⚡ \033[0m'

    try:
        import concurrent.futures
        from pathlib import Path
    except ImportError:
        print(f"{lightning} Vulnscan is not compatible with Python version 2. Please run it with Python version 3.")
        return

    try:
        from fuzzywuzzy import fuzz, process
    except ImportError:
        print(
            f"{lightning} The 'fuzzywuzzy' library is not installed. Please install it manually by running:\n"
            "    pip install fuzzywuzzy\n"
            "Once installed, restart the program."
        )
        # Exiting to prevent further execution without the dependency
        exit(1)

    # Interactive input for the target domain
    target = domain_name
    target = sanitize_url(target)

    # Additional interactive input for other parameters (you can customize this part)
    delay = int(
        input('%s Enter the delay between requests (default is 0 ): ' % info) or 0)  # Delay: Time between requests (throttling to prevent being flagged as malicious).
    level = int(
        input('%s Enter the number of levels to crawl (default is 2 ): ' % info) or 2)  # Crawl Levels: Depth of URL crawling on the site
    timeout = int(
        input('%s Enter the HTTP request timeout (default is 20 ): ' % info) or 20)  # Timeout: Maximum waiting time for HTTP responses
    threadCount = int(
        input('%s Enter the number of threads (default is 2 ): ' % info) or 2)  # Thread Count: Number of concurrent threads for crawling

    delay_desc = 'Delay between requests'
    level_desc = 'Number of levels to crawl'
    timeout_desc = 'HTTP request timeout'
    threadCount_desc = 'Number of threads'

    csrf_results.append((delay_desc, delay))
    csrf_results.append((level_desc, level))
    csrf_results.append((timeout_desc, timeout))
    csrf_results.append((threadCount_desc, threadCount))

    # Prompt for headers interactively
    headers_input = input(
        '%s Do you want to enter custom HTTP headers? (y/n): ' % info).lower()
    if headers_input == 'y':
        headers = extractHeaders(prompt())
    else:
        from vulnscan.base.testing import headers

    allTokens = []
    weakTokens = []
    tokenDatabase = []
    insecureForms = []

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Crawling the Website
    ######################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Crawling %s[%s1/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Crawling [1/6]')
    dataset = crawl(target, headers, level, threadCount)
    allForms = dataset[0]
    for url_dict in allForms:
        for url, _ in url_dict.items():
            print(url)
            csrf_results.append(url)
    print('\r%s Crawled %i URL(s) and found %i form(s).%-10s' %
          (info, dataset[1], len(allForms), ' '))
    csrf_results.append('\r%s Crawled %i URL(s) and found %i form(s).%-10s' %
                        (info, dataset[1], len(allForms), ' '))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # CSRF Token Evaluation
    #########################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Evaluating %s[%s2/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Evaluating [2/6]')

    formEvaluate(allForms, weakTokens, tokenDatabase, allTokens, insecureForms)

    if weakTokens:
        print('%s Weak token(s) found' % good)
        csrf_results.append('%s Weak token(s) found' % good)
        for weakToken in weakTokens:
            url = list(weakToken.keys())[0]
            token = list(weakToken.values())[0]
            print('%s %s %s' % (info, url, token))
            csrf_results.append('%s %s %s' % (info, url, token))

    if insecureForms:
        print('%s Insecure form(s) found' % good)
        csrf_results.append('%s Insecure form(s) found' % good)
        for insecureForm in insecureForms:
            url = list(insecureForm.keys())[0]
            action = list(insecureForm.values())[0]['action']
            form = action.replace(target, '')
            if form:
                print('%s %s %s[%s%s%s]%s' %
                      (bad, url, green, end, form, green, end))
                csrf_results.append('%s %s %s[%s%s%s]%s' %
                                    (bad, url, green, end, form, green, end))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Replay Attack Analysis
    #########################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Comparing %s[%s3/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Comparing [3/6]')

    uniqueTokens = set(allTokens)
    if len(uniqueTokens) < len(allTokens):
        print('%s Potential Replay Attack condition found' % good)
        csrf_results.append(
            '%s Potential Replay Attack condition found' % good)
        print('%s Verifying and looking for the cause' % run)
        csrf_results.append('%s Verifying and looking for the cause' % run)
        replay = False
        for each in tokenDatabase:
            url, token = next(iter(each.keys())), next(iter(each.values()))
            for each2 in tokenDatabase:
                url2, token2 = next(iter(each2.keys())), next(
                    iter(each2.values()))
                if token == token2 and url != url2:
                    print('%s The same token was used on %s%s%s and %s%s%s' %
                          (good, green, url, end, green, url2, end))
                    csrf_results.append('%s The same token was used on %s%s%s and %s%s%s' %
                                        (good, green, url, end, green, url2, end))
                    replay = True
        if not replay:
            print('%s Further investigation shows that it was a false positive.')
            csrf_results.append(
                '%s Further investigation shows that it was a false positive.')

    p = Path(__file__).parent.joinpath('db/hashes.json')
    with p.open('r') as f:
        hashPatterns = json.load(f)

    if not allTokens:
        print('%s No CSRF protection to test, NO CSRF TOKENS AVAILABLE' % bad)
        csrf_results.append(
            '%s No CSRF protection to test, NO CSRF TOKENS AVAILABLE' % bad)
        return

    print("Length of allTokens:", len(allTokens))
    csrf_results.append(["Length of allTokens", len(allTokens)])

    if len(allTokens) > 0:
        print("Length of first sublist in allTokens:", len(allTokens[0]))
        csrf_results.append([
            "Length of first sublist in allTokens:", len(allTokens[0])])
    else:
        print("Error: allTokens is empty.")
        csrf_results.append("Error: allTokens is empty.")
        return

    if len(allTokens[0]) == 0:
        print("Error: First sublist in allTokens is empty.")
        csrf_results.append("Error: First sublist in allTokens is empty.")
        return

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Hash Pattern Matching
    #########################################################################################################################################################
    #########################################################################################################################################################

    if allTokens and len(allTokens) > 0:
        aToken = allTokens[0]
        if aToken:
            matches = []
            for element in hashPatterns:
                pattern = element['regex']
                if re.match(pattern, aToken):
                    for name in element['matches']:
                        matches.append(name)
            if matches:
                print(
                    '%s Token matches the pattern of the following hash type(s):' % info)
                csrf_results.append(
                    '%s Token matches the pattern of the following hash type(s):' % info)
                for name in matches:
                    print(' %s>%s %s' % (yellow, end, name))
                    csrf_results.append(' %s>%s %s' % (yellow, end, name))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Comparing Tokens , High similarity indicates weak randomness in token generation, making the site vulnerable
    #########################################################################################################################################################
    #########################################################################################################################################################

            def fuzzy(tokens):
                averages = []
                for token in tokens:
                    sameTokenRemoved = False
                    result = process.extract(
                        token, tokens, sbaser=fuzz.partial_ratio)
                    sbases = []
                    for each in result:
                        sbase = each[1]
                        if sbase == 100 and not sameTokenRemoved:
                            sameTokenRemoved = True
                            continue
                        sbases.append(sbase)
                    average = statistics.mean(sbases)
                    averages.append(average)
                return statistics.mean(averages)

            try:
                similarity = fuzzy(allTokens)
                print('%s Tokens are %s%i%%%s similar to each other on average' %
                      (info, green, similarity, end))
                csrf_results.append('%s Tokens are %s%i%%%s similar to each other on average' %
                                    (info, green, similarity, end))
            except statistics.StatisticsError:
                print(
                    '%s No CSRF protection to test, CSRF vulnerability not found' % bad)
                csrf_results.append(
                    '%s No CSRF protection to test, CSRF vulnerability not found' % bad)
        else:
            print("The first element of allTokens is an empty list.")
            csrf_results.append(
                "The first element of allTokens is an empty list.")
    else:
        print("No CSRF tokens available.")
        csrf_results.append("No CSRF tokens available.")

    def staticParts(allTokens):
        strings = list(set(allTokens.copy()))
        commonSubstrings = {}
        for theString in strings:
            strings.remove(theString)
            for string in strings:
                commonSubstring = longestCommonSubstring(theString, string)
                if commonSubstring not in commonSubstrings:
                    commonSubstrings[commonSubstring] = []
                if len(commonSubstring) > 2:
                    if theString not in commonSubstrings[commonSubstring]:
                        commonSubstrings[commonSubstring].append(theString)
                    if string not in commonSubstrings[commonSubstring]:
                        commonSubstrings[commonSubstring].append(string)
        return commonSubstrings

    result = {k: v for k, v in staticParts(allTokens).items() if v}

    if result:
        print('%s Common substring found' % info)
        csrf_results.append('%s Common substring found' % info)
        print(json.dumps(result, indent=4))
        csrf_results.append(json.dumps(result, indent=4))

    simTokens = []
    print(' %s \n Phase: Observing %s[%s4/6%s]%s' %
          (lightning, green, end, green, end))

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Simultaneous Requests || Sends 100 concurrent requests to see if the server issues the same CSRF token , If identical tokens are issued, it may lead to vulnerabilities
    ######################################################################################################################################################
    #########################################################################################################################################################

    csrf_results.append('Phase: Observing [4/6]')
    print('%s 100 simultaneous requests are being made, please wait.' % info)
    csrf_results.append(
        '%s 100 simultaneous requests are being made, please wait.' % info)

    def extractForms(url):
        response = sendRequest(url, {}, headers, True, 0).text
        forms = extractHTMLInformation(url, response)
        for each in forms.values():
            localTokens = set()
            inputs = each['inputs']
            for inp in inputs:
                value = inp['value']
                if value and re.match(r'^[\w\-_]+$', value):
                    if strength(value) > 10:
                        simTokens.append(value)

    # Define goodCandidate before the loop
    goodCandidate = None

    # Limit the number of iterations to 100
    for _ in range(100):
        sample = secrets.choice(tokenDatabase)
        goodToken = list(sample.values())[0]
        if len(goodToken) > 0:
            goodCandidate = list(sample.keys())[0]
            break

    # Check if a valid goodCandidate was found
    if goodCandidate is not None:
        threadpool = concurrent.futures.ThreadPoolExecutor(max_workers=30)
        futures = (threadpool.submit(extractForms, goodCandidate)
                   for _ in range(30))

        # Introduce a timeout for completion
        try:
            # Set a reasonable timeout value
            for i in concurrent.futures.as_completed(futures, timeout=60):
                pass
        except concurrent.futures.TimeoutError:
            print("Timeout reached. Exiting the loop.")
            csrf_results.append("Timeout reached. Exiting the loop.")
        else:
            print("No valid goodCandidate found.")
            csrf_results.append("No valid goodCandidate found.")

    if simTokens:
        if len(set(simTokens)) < len(simTokens):
            print('%s Same tokens were issued for simultaneous requests.' % good)
            csrf_results.append(
                '%s Same tokens were issued for simultaneous requests.' % good)
        else:
            print(simTokens)
            csrf_results.append(simTokens)
    else:
        print('%s Different tokens were issued for simultaneous requests.' % info)
        csrf_results.append(
            '%s Different tokens were issued for simultaneous requests.' % info)

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Mobile Browser Simulation || Simulates a request from a mobile browser to check if CSRF protection is consistent across devices.
    ######################################################################################################################################################
    #########################################################################################################################################################

    print(' %s \n Phase: Testing %s[%s5/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Testing [5/6]')

    parsed = ''
    found = False
    print('%s Finding a suitable form for further testing. It may take a while.' % run)
    csrf_results.append(
        '%s Finding a suitable form for further testing. It may take a while.' % run)
    for form_dict in allForms:
        for url, forms in form_dict.items():
            parsed = formParser(forms, tolerate=True)
            if parsed:
                found = True
                break
        if found:
            break

    if not parsed:
        quit('%s No suitable form found for testing.' % bad)

    origGET = parsed[0]
    origUrl = parsed[1]
    origData = parsed[2]

    print('%s Making a request with CSRF token for comparison.' % run)
    csrf_results.append(
        '%s Making a request with CSRF token for comparison.' % run)
    response = sendRequest(origUrl, origData, headers, origGET, 0)
    originalCode = response.status_code
    originalLength = len(response.text)
    print('%s Status Code: %s' % (info, originalCode))
    csrf_results.append('%s Status Code: %s' % (info, originalCode))
    print('%s Content Length: %i' % (info, originalLength))
    csrf_results.append('%s Content Length: %i' % (info, originalLength))
    print('%s Checking if the resonse is dynamic.' % run)
    csrf_results.append('%s Checking if the resonse is dynamic.' % run)
    response = sendRequest(origUrl, origData, headers, origGET, 0)
    secondLength = len(response.text)
    if originalLength != secondLength:
        print('%s Response is dynamic.' % info)
        csrf_results.append('%s Response is dynamic.' % info)
        tolerableDifference = abs(originalLength - secondLength)
    else:
        print('%s Response isn\'t dynamic.' % info)
        csrf_results.append('%s Response isn\'t dynamic.' % info)
        tolerableDifference = 0

    print('%s Emulating a mobile browser' % run)
    csrf_results.append('%s Emulating a mobile browser' % run)
    print('%s Making a request with mobile browser' % run)
    csrf_results.append('%s Making a request with mobile browser' % run)
    headers['User-Agent'] = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows CE; PPC; 240x320)'
    response = sendRequest(origUrl, {}, headers, True, 0).text
    parsed = extractHTMLInformation(origUrl, response)
    if isProtected(parsed):
        print('%s CSRF protection is enabled for mobile browsers as well.' % bad)
        csrf_results.append(
            '%s CSRF protection is enabled for mobile browsers as well.' % bad)
    else:
        print('%s CSRF protection isn\'t enabled for mobile browsers.' % good)
        csrf_results.append(
            '%s CSRF protection isn\'t enabled for mobile browsers.' % good)

    print('%s Making a request without CSRF token parameter.' % run)
    csrf_results.append(
        '%s Making a request without CSRF token parameter.' % run)

    #########################################################################################################################################################
    #########################################################################################################################################################
    # Token Removal and Manipulation || Checking if the server accepts requests without a valid token aka modified token
    ######################################################################################################################################################
    #########################################################################################################################################################

    data = modifyManipulateAPI(origData, 'remove')
    response = sendRequest(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
            csrf_results.append('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
                csrf_results.append('%s It worked!' % good)
            else:
                print('%s It didn\'t work' % bad)
                csrf_results.append('%s It didn\'t work' % bad)

    print('%s Making a request without CSRF token parameter value.' % run)
    csrf_results.append(
        '%s Making a request without CSRF token parameter value.' % run)
    data = modifyManipulateAPI(origData, 'clear')

    response = sendRequest(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
            csrf_results.append('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
                csrf_results.append('%s It worked!' % good)
            else:
                print('%s It didn\'t work' % bad)
                csrf_results.append('%s It didn\'t work' % bad)

    seeds = rangeFinder(allTokens)

    print('%s Checking if tokens are checked to a specific length' % run)
    csrf_results.append(
        '%s Checking if tokens are checked to a specific length' % run)

    for index in range(len(allTokens[0])):
        data = modifyManipulateAPI(
            origData, 'replace', index=index, seeds=seeds)
        response = sendRequest(origUrl, data, headers, origGET, 0)
        if response.status_code == originalCode:
            if str(originalCode)[0] in ['4', '5']:
                break
            else:
                difference = abs(originalLength - len(response.text))
                if difference <= tolerableDifference:
                    print('%s Last %i chars of token aren\'t being checked' %
                          (good, index + 1))
                    csrf_results.append('%s Last %i chars of token aren\'t being checked' %
                                        (good, index + 1))
                else:
                    break

    print('%s Generating a fake token.' % run)
    csrf_results.append('%s Generating a fake token.' % run)

    data = modifyManipulateAPI(origData, 'generate', seeds=seeds)
    print('%s Making a request with the self generated token.' % run)
    csrf_results.append(
        '%s Making a request with the self generated token.' % run)

    response = sendRequest(origUrl, data, headers, origGET, 0)
    if response.status_code == originalCode:
        if str(originalCode)[0] in ['4', '5']:
            print('%s It didn\'t work' % bad)
            csrf_results.append('%s It didn\'t work' % bad)
        else:
            difference = abs(originalLength - len(response.text))
            if difference <= tolerableDifference:
                print('%s It worked!' % good)
                csrf_results.append('%s It worked!' % good)
            else:
                print('%s It didn\'t work' % bad)
                csrf_results.append('%s It didn\'t work' % bad)

    print(' %s \n Phase: Analysing %s[%s6/6%s]%s' %
          (lightning, green, end, green, end))
    csrf_results.append('Phase: Analysing [6/6]')

    binary = stringToBinary(''.join(allTokens))
    result = isRandom(binary)
    for name, result in result.items():
        if not result:
            print('%s %s : %s%s%s' % (good, name, green, 'non-random', end))
            csrf_results.append('%s %s : %s%s%s' %
                                (good, name, green, 'non-random', end))
        else:
            print('%s %s : %s%s%s' % (bad, name, red, 'random', end))
            csrf_results.append('%s %s : %s%s%s' %
                                (bad, name, red, 'random', end))

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            certificate                #             certificate               #            certificate                #           certificate         #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def certificate(url):
    try:
        hostname = url  # Use the passed `url` parameter
        context = ssl.create_default_context()

        # Set up a connection with a timeout for better robustness
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Retrieve the certificate
                chain = ssock.getpeercert()
                print("SSL Certificate Chain:\n", chain)
                print(f"\nSSL certificate for {hostname} is valid.")
                return chain  # Return the certificate details if needed

    except ssl.SSLError as e:
        # The certificate validation failed
        print(f"SSL certificate validation for {url} failed: {e}")
        return False
    except socket.gaierror as e:
        # Invalid hostname or DNS resolution failed
        print(f"Invalid domain name '{url}': {e}")
        return False
    except socket.timeout as e:
        # Connection timed out
        print(f"Connection to {url} timed out: {e}")
        return False
    except socket.error as e:
        # Failed to connect to the specified domain
        print(f"Failed to connect to {url}: {e}")
        return False
    except Exception as e:
        # Catch any other unexpected exceptions
        print(f"An unexpected error occurred: {e}")
        return False


certificate_results = []


def analyze_certificate(domain, port):
    global certificate_results
    try:
        # Create a socket object
        with socket.create_connection((domain, port)) as sock:
            # Wrap the socket with SSL/TLS context
            with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate information
                cert = ssock.getpeercert(binary_form=True)
                x509_cert = x509.load_der_x509_certificate(
                    cert, default_backend())

                # Extract and display certificate details
                print(f"[+] SSL/TLS Certificate Analysis for {domain}:{port}")
                result = [
                    f"[+] SSL/TLS Certificate Analysis for {domain}:{port}",
                    f"Common Name (CN): {x509_cert.subject.rfc4514_string()}",
                    f"Issuer: {x509_cert.issuer.rfc4514_string()}",
                    f"Serial Number: {x509_cert.serial_number}",
                    f"Not Valid Before: {x509_cert.not_valid_before}",
                    f"Not Valid After: {x509_cert.not_valid_after}",
                    f"Signature Algorithm: {x509_cert.signature_algorithm_oid._name}",
                    f"Version: {x509_cert.version.name}",
                ]
                certificate_results.append(result)
                print("\n".join(result))
    except (socket.timeout, socket.error, ssl.SSLError, ssl.CertificateError, Exception) as e:
        error_message = f"[-] Error occurred for {domain}:{port} - {str(e)}"
        print(error_message)
        certificate_results.append(error_message)
    return certificate_results


location_cache = {}
location_cache = {}

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#               location                #                 location              #              location         #            location           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#

locations_data = []


def get_location(ip_address, api_key):
    global locations_data
    try:
        # Make the API request
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip_address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise an error for HTTP errors (e.g., 4xx, 5xx)

        # Parse the response JSON
        data = response.json()
        result = {
            "ip": data.get("ip"),
            "continent": data.get("continent_name"),
            "country": data.get("country_name"),
            "country_code": data.get("country_code2"),
            "region": data.get("state_prov"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": data.get("time_zone", {}).get("name"),
            "currency": data.get("currency", {}).get("name"),
            "organization": data.get("organization"),
        }
        locations_data.append(result)

        return locations_data

    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as err:
        print(f"Error occurred: {err}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            Directory Enumeration           #              Directory Enumeration                  #           Directory Enumeration           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


directory_results = []


def directory_enumeration(url):
    global directory_results
    # Ensure the base URL ends with a slash
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    if not url.endswith('/'):
        url += '/'

    # Define the path to your subdirectories file
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subdirectories.txt")

    try:
        with open(file_path, "r") as file:
            # Read lines from the file and strip any extra whitespace/newlines
            common_directories = [line.strip()
                                  for line in file if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: File not found at {file_path}")
        return

    print(f"Starting directory enumeration for {url}\n")
    directory_results.append(f"Starting directory enumeration for {url}\n")
    # Use tqdm to create a progress bar
    for directory in tqdm(common_directories, desc="Scanning directories"):
        # Skip entries that look like full URLs without a scheme
        if "://" not in directory and "." in directory:
            print(
                f"[-] Skipping invalid entry (likely a URL without scheme): {directory}")
            continue

        # Ensure the target URL is absolute
        target_url = urljoin(url, directory)

        try:
            # Make a GET request to the target URL
            response = requests.get(target_url, timeout=5)

            # Check the response status code
            if response.status_code == 200:
                print(f"[+] Directory Found: {target_url}")
                directory_results.append(f"[+] Directory Found: {target_url}")
            else:
                print(
                    f"[-] Directory Not Found: {target_url} (Status Code: {response.status_code})")
        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {e}")
            directory_results.append(f"[-] Error: {e}")

    print("\nDirectory enumeration completed.\n")
    directory_results.append("\nDirectory enumeration completed.\n")
    return directory_results

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            Web Application Vulnerability Scanners           #              Web Application Vulnerability Scanners                  #           Web Application Vulnerability Scanners           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


vulnerability_results = []


def web_application_vulnerability_scanner(url):
    global vulnerability_results
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    if vulnerability_results is None:
        vulnerability_results = []  # Initialize if not passed
    options = Options()
    options.headless = True  # Enable headless mode

    # Initialize the WebDriver with headless configuration
    driver = webdriver.Firefox(options=options)

    try:
        import time
        from pprint import pprint
        import zapv2

        vulnerability_results = []  # List to store the results

        zap = zapv2.ZAPv2(apikey="cbq78gjfpin0dgg5j0o7eefjnh")
        zap.urlopen(url)

        # Spider scanning
        zap.spider.scan(url)
        zap.ajaxSpider.scan(url)
        print(f"Spider and Ajax Spider scanning {url} initiated.")
        vulnerability_results.append(
            f"Spider and Ajax Spider scanning {url} initiated.")

        # Passive scanning
        zap.ascan.scan(url)
        while int(zap.pscan.records_to_scan) > 0:
            print('Records to passive scan : ' + zap.pscan.records_to_scan)
            vulnerability_results.append(
                f"'Records to passive scan : ' + zap.pscan.records_to_scan")
            time.sleep(2)
        print('Passive Scan completed')
        vulnerability_results.append(f"Passive Scan completed")

        # Collect Passive scan results
        hosts = ', '.join(zap.core.hosts)
        alerts = zap.core.alerts()
        print('Hosts: {}'.format(hosts))
        print('Alerts: ')
        pprint(alerts)
        vulnerability_results.extend([
            f"Hosts: {hosts}",
            "Alerts: "
        ])
        vulnerability_results.extend(alerts)  # Append all alerts

        # Active scanning
        target = url
        print(f'Active Scanning target {target}')
        vulnerability_results.append(f"Active Scanning target {target}")
        scanID = zap.ascan.scan(target)

        from tqdm import tqdm
        import time

        # Initialize the progress bar
        progress_bar = tqdm(
            total=100, desc="Active Scan Progress", position=0, leave=True)

        last_progress = 0  # Track the last recorded progress to avoid over-updating
        while int(zap.ascan.status(scanID)) < 100:
            # Get the current progress
            current_progress = int(zap.ascan.status(scanID))

            # Update the progress bar by the difference since the last update
            progress_bar.update(current_progress - last_progress)
            last_progress = current_progress  # Update the tracker

            vulnerability_results.append(
                f"Scan progress %: {current_progress}")
            time.sleep(5)  # Check progress every 5 seconds

        # Ensure the progress bar completes
        progress_bar.n = 100
        progress_bar.refresh()
        progress_bar.close()

        print("Active scan completed!")
        vulnerability_results.append("Active Scan completed")

        # Collect Active scan results
        print('Hosts: {}'.format(hosts))
        print('Alerts: ')
        active_alerts = zap.core.alerts(baseurl=target)
        pprint(active_alerts)
        vulnerability_results.extend([
            f"Hosts: {hosts}",
            "Alerts: "
        ])
        vulnerability_results.extend(active_alerts)  # Append all active alerts

        # Summarize vulnerabilities
        for alert in active_alerts:
            name = alert.get('name', 'N/A')
            description = alert.get('description', 'N/A')
            alert_url = alert.get('url', 'N/A')
            print(f"[+] Vulnerability Found: {name}")
            print(f"[+] Description: {description}")
            print(f"[+] URL: {alert_url}")
            vulnerability_results.append(f"[+] Vulnerability Found: {name}")
            vulnerability_results.append(f"[+] Description: {description}")
            vulnerability_results.append(f"[+] URL: {alert_url}")

    except ImportError:
        print("ZAP library not found. Please install it with 'pip install zapv2'")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        vulnerability_results.append(f"An error occurred: {e}")
    driver.quit()
    return vulnerability_results
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            Crawling and Spidering           #              Crawling and Spidering                  #           Crawling and Spidering           #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


crawl_results = []


def crawl_and_spider(url):
    global crawl_results
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    visited = set()
    queue = [url]

    while queue:
        current_url = queue.pop(0)

        if current_url in visited:
            continue

        visited.add(current_url)

        try:
            response = requests.get(current_url)

            if response.status_code == 200:
                print(f"[+] Visited: {current_url}")
                crawl_results.append(f"\n\t[+] Visited: {current_url}")

                soup = BeautifulSoup(response.text, 'html.parser')
                links = soup.find_all('a')

                for link in links:
                    link_url = link.get('href')
                    if link_url:
                        absolute_url = urljoin(current_url, link_url)
                        if absolute_url not in visited:
                            queue.append(absolute_url)
                            crawl_results.append(
                                f"\n\t[+] Found link: {absolute_url}")
            else:
                print(f"[-] Failed to visit: {current_url}")
                crawl_results.append(f"\n\t[-] Failed to visit: {current_url}")

        except requests.exceptions.RequestException as e:
            print(f"[-] Error: {e}")
            crawl_results.append(f"\n\t[-] Error: {e}")

    return crawl_results

################################################################################################################################


def detect_waf(domain_name):
    if not domain_name.startswith(("http://", "https://")):
        domain_name = "http://" + domain_name
    try:
        # Send a request to the URL
        response = requests.get(domain_name)

        # Check for common security headers
        security_headers = [
            'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
            'Content-Security-Policy', 'Strict-Transport-Security', 'Referrer-Policy',
            'Permissions-Policy', 'Feature-Policy'
        ]

        for header in security_headers:
            if header not in response.headers:
                return False

        # Check for common security-related headers
        security_related_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'
        ]

        for header in security_related_headers:
            if header in response.headers:
                return False

        # Check for WAF-specific headers
        waf_headers = [
            'X-AWS-ELB', 'X-AWS-FID', 'X-AWS-FILTERING', 'X-AWS-ID',
            'X-AWS-REQUEST-ID', 'X-AWS-VERSION', 'X-Cache', 'X-Cache-Lookup',
            'X-Edge-Location', 'X-Edge-Response-Result-Cached', 'X-Edge-Response-Result-Error',
            'X-Edge-Response-Result-Uncached'
        ]

        for header in waf_headers:
            if header in response.headers:
                return True

        return True

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return False


################################################################################################################################


def sanitize_html(html_content):
    # Remove HTML tags
    stripped_content = html_content.replace("<", "").replace(">", "")

    # Escape special characters
    escaped_content = html.escape(stripped_content)

    return escaped_content


active_domains = []
location_cache = []
port_scan_results = []
server_info = []
sql_test_results = []
xss_test_results = []
csrf_results = []
certificate_results = []
locations_data = []
directory_results = []
vulnerability_results = []
crawl_results = []

#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #        #       #       #       #        #
#
#            report             #             report            #            report             #           report              #          report        #       #          report        #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #        #       #       #       #        #
#


def generate_report(domain_name, ip_address, options, args, active_domains=None, location_data=None, server_info=None, port_scan_results=None, sql_test_results=None, xss_test_results=None, csrf_results=None, certificate_results=None, locations_data=None, directory_results=None, vulnerability_results=None, crawl_results=None):
    report_filename = f"VulnScan_Report_{time.strftime('%Y%m%d%H%M%S')}.pdf"

    doc = SimpleDocTemplate(report_filename, pagesize=letter)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph(
        f"<u>VulnScan Report - {time.strftime('%Y-%m-%d %H:%M:%S')}</u>", styles['Title']))
    content.append(Spacer(1, 12))
    content.append(
        Paragraph(f"<b>Target Domain:</b> {domain_name}", styles['Normal']))
    content.append(
        Paragraph(f"<b>IP Address:</b> {ip_address}", styles['Normal']))
    content.append(Paragraph(f"<b>Scan Options:</b> {args}", styles['Normal']))
    content.append(Spacer(1, 12))

    if port_scan_results:
        content.append(
            Paragraph("<b>Port Scanning Results:</b>", styles['Heading2']))
        port_scan_results.extend([
            "<br />"+"<b>Suggestions for Open Ports :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Evaluate Each Open Port :</b> Determine whether each open port is necessary for the functioning of your website or if it's potentially a security risk.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Close Unnecessary Ports :</b> For any open ports that aren't needed for your website's operation, consider closing them through your server's firewall configuration or network settings.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Secure Necessary Ports :</b> For ports that are required for your website to function (such as port 80 for HTTP or port 443 for HTTPS), ensure they are properly secured with strong encryption protocols, secure configurations, and up-to-date software."
        ])
        for result in port_scan_results:
            content.append(Paragraph(result, styles['Normal']))
        content.append(Spacer(1, 12))

    if active_domains:
        content.append(
            Paragraph("<b>Active Subdomains:</b>", styles['Heading2']))
        active_domains.extend([
            "<br />"+"<b>Suggestions for Domain Enumeration and Active Sub Domains :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Remove DNS Entries :</b> If you want to completely disable access to certain subdomains, you can remove or modify the DNS records for those subdomains. This prevents users from resolving the IP address associated with those subdomains.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Redirect Subdomains :</b> Instead of completely removing the subdomains, you can set up redirection rules on your server to redirect requests from certain subdomains to the main domain or to a specific page. This way, users won't see the content of the subdomains, but they will be redirected to another location.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Configure Virtual Hosts :</b> If you're using a web server like Apache or Nginx, you can configure virtual hosts to only serve content for specific domains and subdomains. By configuring the virtual hosts appropriately, you can prevent access to certain subdomains.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Use Robots.txt :</b> You can use a robots.txt file to instruct search engines not to index certain subdomains or to exclude them from search results. This won't prevent direct access to the subdomains, but it can help prevent them from appearing in search engine results.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Authentication and Authorization :</b> Implement authentication and authorization mechanisms to restrict access to certain subdomains. This way, even if users know the URL of a subdomain, they won't be able to access it without proper credentials.",
        ])
        for subdomain in active_domains:
            content.append(Paragraph(subdomain, styles['Normal']))
        content.append(Spacer(1, 12))

    if server_info:
        content.append(
            Paragraph("<b>Domain Fingerprinting:</b>", styles['Heading2']))
        server_info.extend([
            "<br />"+"<b>Suggestions for Domain Fingerprinting :</b><br/>"
            ""
            "<br />" +
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Apache :</b> Edit your Apache configuration file (httpd.conf) and ensure that the following directives are set <b>{ 'ServerSignature Off' , 'ServerTokens Prod' }</b> for hiding your apache information",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Nginx :</b> In your Nginx configuration file (nginx.conf), make sure the following directives are set" +
            "<br/>" +
            "<b>{ 'server_tokens off;' }</b> for hiding your HTTP Header information",
            "<b> &nbsp;&nbsp;&nbsp;&nbsp;- PHP :</b> To hide the PHP version information, you can adjust the expose_php directive in your PHP configuration file (php.ini). Set it to Off using <b>{ 'expose_php = Off' }</b>",
        ])
        for info in server_info:  # Iterate over the elements of server_info list
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if sql_test_results:
        content.append(
            Paragraph("<b>SQL Injection Test Results:</b>", styles['Heading2']))
        sql_test_results.extend([
            "<br />"+"<b>Suggestions for SQL Injection :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Don't Use HTML forms :</b> HTMl forms is directly linked with database so use some other options for survey or form related uses ",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Use modern languages :</b> Instead of using normal HTML, CSS, JS use react, php and use NO SQL for Database  "])
        for info in sql_test_results:  # Iterate over the elements of sql_test_results list
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if xss_test_results:
        content.append(
            Paragraph("<b>XSS Testing Results:</b>", styles['Heading2']))
        xss_test_results.extend([
            "<br />"+"<b>Suggestions for SQL Injection :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Don't Trust User Input :</b> Always validate and sanitize user input to prevent malicious scripts from executing.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Use Content Security Policy (CSP) :</b> Implement CSP headers to restrict the sources from which content can be loaded, mitigating XSS attacks.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Encode Output :</b> Encode output data using appropriate encoding methods (such as HTML escaping) to prevent script injection.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Educate Developers :</b> Train developers on secure coding practices to reduce the likelihood of introducing XSS vulnerabilities."
        ])
        for info in xss_test_results:
            sanitized_info = sanitize_html(info)
            content.append(Paragraph(str(sanitized_info), styles['Normal']))
        content.append(Spacer(1, 12))

    if csrf_results:
        content.append(
            Paragraph("<b>CSRF Test Results:</b>", styles['Heading2']))
        csrf_results.extend([
            "<br />"+"<b>Suggestions for CSRF Protection :</b><br/>"
            ""
            "<br />"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Secure Configuration :</b> You can enable or disable this protection in the central-wrapper.conf file.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 1. </b> Stop the Central server.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 2. </b> Open the <installation_folder>/central/conf/central-wrapper.conf file.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 3. </b> Locate the Dcsrf.enabled property and change it to true, to enable CSRF protection.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- 4. </b> Start the Central server."
        ])
        for info in csrf_results:
            # Ensure info is converted to strings
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if certificate_results:
        content.append(
            Paragraph("<b>Certificate Detection Results:</b>", styles['Heading2']))
        certificate_results.extend([
            "<br /><b>Suggestions for SSL/TLS Configuration :</b>",
            "<br/>"+"<b>&nbsp;&nbsp;&nbsp;&nbsp;- Disable Certificate Transparency (CT) :</b> Certificate Transparency is a mechanism for publicly logging SSL certificates. If you have control over your certificate issuance process, you may be able to disable CT logging for your certificates. However, note that this may not be feasible for all certificate authorities (CAs) or certificate types.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Limit OCSP Stapling :</b> Online Certificate Status Protocol (OCSP) stapling is a feature that allows the web server to provide the OCSP response along with the SSL certificate during the SSL handshake. By limiting OCSP stapling, you may reduce the amount of certificate-related information exposed during the handshake.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Custom Error Pages :</b> Customize error pages for SSL/TLS handshake failures. Instead of displaying detailed error messages that may expose certificate details, provide generic error messages to users.<br />",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Web Application Firewall (WAF) :</b> Use a WAF to filter and sanitize HTTP responses from your web server. This can help prevent leaking sensitive certificate details in error messages or responses.<br />",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Load Balancer Configuration :</b> If your website is behind a load balancer or reverse proxy, ensure that the load balancer does not expose sensitive SSL certificate details in headers or error responses.",
            "<b>&nbsp;&nbsp;&nbsp;&nbsp;- Security Headers: </b> Implement security headers such as Content Security Policy (CSP) to mitigate the impact of successful attacks that may expose certificate details."
        ])

        for info in certificate_results:  # Iterate over the elements of certificate_results list
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if locations_data:
        content.append(
            Paragraph("<b>Location Information:</b>", styles['Heading2']))
        for info in locations_data:
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if directory_results:
        content.append(
            Paragraph("<b>Directory Information:</b>", styles['Heading2']))
        for info in directory_results:
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    if vulnerability_results:
        content.append(
            Paragraph("<b>Vulnerability Information:</b>", styles['Heading2']))
        for info in vulnerability_results:
            # Escape special characters in the info
            sanitized_info = escape(str(info))
            content.append(Paragraph(sanitized_info, styles['Normal']))
        content.append(Spacer(1, 12))

    if crawl_results:
        content.append(
            Paragraph("<b>Crawl Information:</b>", styles['Heading2']))
        for info in crawl_results:
            content.append(Paragraph(str(info), styles['Normal']))
        content.append(Spacer(1, 12))

    doc.build(content)
    print(f"\nReport generated: {report_filename}")



class CloudLogger:
    """Thread-safe logger for real-time output"""
    _lock = threading.Lock()

    @staticmethod
    def log(message, level="INFO"):
        with CloudLogger._lock:
            if level == "INFO":
                print(f"[*] {message}")
            elif level == "SUCCESS":
                print(f"[+] {message}")
            elif level == "ERROR":
                print(f"[-] {message}")
            elif level == "WARNING":
                print(f"[!] {message}")
            else:
                print(message)

def run_advanced_scan(domain_name):
    """Run all advanced security scans with real-time feedback"""
    CloudLogger.log("Running Advanced Security Scan (Production Mode)...", "INFO")

    # Initialize results dictionary
    global scan_results
    scan_results = {
        'target': domain_name,
        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
        'findings': {}
    }

    # Run scans in parallel with real-time feedback
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(run_advanced_domain_enum, domain_name): 'domain_enumeration',
            executor.submit(run_cloud_scan, domain_name): 'cloud_vulnerabilities',
            executor.submit(run_web_app_scan, domain_name): 'web_app_vulnerabilities',
            executor.submit(run_api_scan, domain_name): 'api_vulnerabilities',
            executor.submit(run_ai_scan, domain_name): 'ai_findings',
            executor.submit(run_sensitive_data_scan, domain_name): 'sensitive_data_exposure'
        }

        for future in as_completed(futures):
            scan_type = futures[future]
            try:
                result = future.result()
                scan_results['findings'][scan_type] = result
                CloudLogger.log(f"{scan_type.replace('_', ' ').title()} completed", "SUCCESS")
                
                # Immediate feedback on findings count
                if isinstance(result, list):
                    count = len(result)
                elif isinstance(result, dict):
                    count = len(result.get('findings', [])) if 'findings' in result else len(result)
                else:
                    count = 0
                
                if count > 0:
                     CloudLogger.log(f"  -> Found {count} issues in {scan_type.replace('_', ' ')}", "WARNING")

            except Exception as e:
                CloudLogger.log(f"Error in {scan_type}: {str(e)}", "ERROR")
                scan_results['findings'][scan_type] = {'error': str(e)}

    # Generate advanced report
    generate_advanced_report(domain_name)

    return scan_results


def run_advanced_domain_enum(domain_name):
    """Run advanced domain enumeration"""
    enumerator = AdvancedSubdomainEnumerator(domain_name)
    return enumerator.run_enumeration()


def run_cloud_scan(domain_name):
    """Run cloud vulnerability scanning"""
    scanner = CloudSecurityScanner(domain_name)
    return scanner.run_scan()


def run_web_app_scan(domain_name):
    """Run advanced web application scanning"""
    scanner = AdvancedWebAppTester(domain_name)
    return scanner.run_tests()


def run_api_scan(domain_name):
    """Run API security testing"""
    # Test GraphQL endpoints
    graphql_tester = GraphQLSecurityTester(domain_name)
    graphql_results = graphql_tester.run_tests()

    # Test general API security
    api_tester = APISecurityTester(domain_name)
    api_results = api_tester.run_tests()

    return {
        'graphql': graphql_results,
        'general': api_results
    }


def run_ai_scan(domain_name):
    """Run AI-powered vulnerability detection"""
    detector = AIVulnerabilityDetector()

    # Get web content for AI analysis
    try:
        response = requests.get(
            f"https://{domain_name}", headers=headers, timeout=10)
        return detector.analyze_response(response.text)
    except Exception as e:
        return {'error': str(e)}

def run_sensitive_data_scan(domain_name):
    """Run sensitive data exposure scan"""
    domain_with_scheme = ensure_url_scheme(domain_name)
    tester = SensitiveDataExposureTester(domain_with_scheme)
    return tester.run_tests()


def ensure_url_scheme(domain):
    """Ensure the domain has a URL scheme (http:// or https://)"""
    if not domain.startswith(('http://', 'https://')):
        return f"https://{domain}"
    return domain


def run_comprehensive_scan(domain_name):
    """Run comprehensive security scan using ModernSecurityPlatform"""
    print("\n[*] Running Comprehensive Security Scan...")

    platform = ModernSecurityPlatform(domain_name, config={})
    results = platform.run_comprehensive_scan()

    # Update global results
    global scan_results
    scan_results.update(results)

    # Generate report
    generate_advanced_report(domain_name)

    return results


def generate_advanced_report(domain_name):
    """Generate advanced security report"""
    print("\n[*] Generating Advanced Security Report...")

    reporter = AdvancedSecurityReporter(domain_name, scan_results)
    reports = reporter.generate_all_reports()

    print("\n[+] Advanced Reports Generated:")
    for format_type, file_path in reports.items():
        print(f"    - {format_type.upper()}: {file_path}")

    return reports


#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#
#            main               #             main              #            main               #           main                #          main         #       #          main         #
#
#       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #       #
#


def main():
    if __name__ == "__main__":

    # Initialize global results dictionary

    global scan_results
    scan_results = {
        'target': '',
        'timestamp': '',
        'findings': {}
    }

    while True:
        domain_name = input("\nEnter the target domain : ")
        domain_name = ensure_url_scheme(domain_name)
        scan_results['target'] = domain_name
        scan_results['timestamp'] = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S")

        options, args = get_args()
        ip_address = get_ip_address(domain_name)

        if ip_address:
            print('IP Address : ', ip_address)
        else:
            print('Could not resolve IP address. Continuing with domain name.')

        while True:
            print("\n1. Change Domain")
            print("2. Port Scan")
            print("3. Domain Enumeration")
            print("4. Domain Fingerprinting")
            print("5. SQL Injection Testing")
            print("6. XSS Testing")
            print("7. CSRF Detection")
            print("8. SSL/TLS Certificate Detection")
            print("9. Location of the Server")
            print("10. Directory Enumeration")
            print("11. Web Application Vulnerability Scanning")
            print("12. Crawling and Spidering")
            print("13. WAF Detection")
            print("14. Advanced Domain Enumeration")
            print("15. Cloud Vulnerability Scan")
            print("16. Advanced Web Application Scan")
            print("17. API Security Testing")
            print("18. AI-Powered Vulnerability Detection")
            print("19. Comprehensive Security Scan")
            print("20. Running Security Tool Integration")
            print("21. Advanced Report Generation")
            print("22. Sensitive Data Exposure Check")
            print("23. Exit\n")

            choice = input("Enter a choice from the given options (1-23): ")

            if choice == '1':
                break
            elif choice == '2':
                # Port Scan
                print("\n[*] Running Port Scan...")
                port_scan_results = []  # Initialize

                while True:
                    print("\nPort Scanning Options:")
                    print("\n1. Scan a single port")
                    print("2. Scan custom ports")
                    print("3. Scan a range of ports")
                    print("4. Exit Port Scan\n")
                    try:
                        port_option = int(
                            input("\nEnter your choice (1, 2, 3, or 4): "))
                        if port_option == 1:
                            port = input("\nEnter the port number to scan: ")
                            start_time = time.time()
                            result = scan_single_port(domain_name, port)
                            port_scan_results.extend(result)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 2:
                            ports_input = input(
                                "\nEnter the port numbers to scan (comma-separated): ")
                            ports = [int(port.strip())
                                     for port in ports_input.split(",")]
                            start_time = time.time()
                            result = scan_custom_ports(domain_name, ports)
                            port_scan_results.extend(result)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 3:
                            start_port, end_port = map(int, input(
                                "\nEnter the port range to scan (e.g., 1-65535): ").split("-"))
                            start_time = time.time()
                            result = scan_range_of_ports(
                                domain_name, start_port, end_port)
                            port_scan_results.extend(result)
                            elapsed_time = time.time() - start_time
                            print(f"Elapsed time: {elapsed_time:.2f} seconds")
                        elif port_option == 4:
                            print("\nExiting Port Scan...\n")
                            break
                        else:
                            print(
                                "\nInvalid option. Please enter a valid option (1, 2, 3, or 4)")
                    except ValueError:
                        print(
                            "\nInvalid input. Please enter a valid option (1, 2, 3, or 4)")

                # Store results in scan_results
                scan_results['findings']['port_scan'] = port_scan_results
                print("\n[+] Port Scan completed")

            elif choice == '3':
                # Domain Enumeration
                print("\n[*] Running Domain Enumeration...")
                q = queue.Queue()
                for subdomain in from_file(options.input_list):
                    q.put(subdomain)
                bar = Bar("Subdomain scanning...", max=q.qsize())
                session = requests.Session()
                session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                active_domains = []
                lock = threading.Lock()
                q = queue.Queue()
                for subdomain in from_file(options.input_list):
                    q.put(subdomain)
                threads = []
                for i in range(options.n_threads):
                    t = threading.Thread(target=get_active)
                    t.daemon = True
                    t.start()
                    threads.append(t)
                for t in threads:
                    t.join()

                # Store results in scan_results
                scan_results['findings']['domain_enumeration'] = active_domains
                print("\n[+] Domain Enumeration completed")

            elif choice == '4':
                # Domain Fingerprinting
                print("\n[*] Running Domain Fingerprinting...")
                server_info = []
                get_server_info(domain_name)

                # Store results in scan_results
                scan_results['findings']['domain_fingerprinting'] = server_info
                print("\n[+] Domain Fingerprinting completed")

            elif choice == '5':
                # SQL Injection Testing
                print("\n[*] Running SQL Injection Testing...")
                sql_test_results = []
                test_sql_injection(domain_name)

                # Store results in scan_results
                scan_results['findings']['sql_injection'] = sql_test_results
                print("\n[+] SQL Injection Testing completed")

            elif choice == '6':
                # XSS Testing
                print("\n[*] Running XSS Testing...")
                colorama.init()
                xss_test_results = []
                scan_xss(domain_name)
                colorama.deinit()

                # Store results in scan_results
                scan_results['findings']['xss'] = xss_test_results
                print("\n[+] XSS Testing completed")

            elif choice == '7':
                # CSRF Detection
                print("\n[*] Running CSRF Detection...")
                csrf_results = []
                csrf(domain_name)

                # Store results in scan_results
                scan_results['findings']['csrf'] = csrf_results
                print("\n[+] CSRF Detection completed")

            elif choice == '8':
                # SSL/TLS Certificate Detection
                print("\n[*] Running SSL/TLS Certificate Detection...")
                domain = domain_name
                port = 443
                certificate_results = []
                certificate(domain_name)
                analyze_certificate(domain, port)

                # Store results in scan_results
                scan_results['findings']['certificate'] = certificate_results
                print("\n[+] SSL/TLS Certificate Detection completed")

            elif choice == '9':
                # Location of the Server
                print("\n[*] Getting Server Location...")
                api_key = os.getenv("API_KEY")
                location_data = get_location(ip_address, api_key)
                if location_data:
                    print("\nLocation Information:")
                    for key, value in location_data.items():
                        print(f"{key}: {value}")

                # Store results in scan_results
                scan_results['findings']['location'] = location_data
                print("\n[+] Server Location completed")

            elif choice == '10':
                # Directory Enumeration
                print("\n[*] Running Directory Enumeration...")
                directory_results = []
                directory_enumeration(domain_name)

                # Store results in scan_results
                scan_results['findings']['directory_enumeration'] = directory_results
                print("\n[+] Directory Enumeration completed")

            elif choice == '11':
                # Web Application Vulnerability Scanning
                print("\n[*] Running Web Application Vulnerability Scanning...")
                vulnerability_results = []
                web_application_vulnerability_scanner(domain_name)

                # Store results in scan_results
                scan_results['findings']['web_app_vulnerabilities'] = vulnerability_results
                print("\n[+] Web Application Vulnerability Scanning completed")

            elif choice == '12':
                # Crawling and Spidering
                print("\n[*] Running Crawling and Spidering...")
                crawl_results = []
                crawl_and_spider(domain_name)

                # Store results in scan_results
                scan_results['findings']['crawling'] = crawl_results
                print("\n[+] Crawling and Spidering completed")

            elif choice == '13':
                # WAF Detection
                print("\n[*] Running WAF Detection...")
                waf_results = []
                is_secure = detect_waf(domain_name)
                if is_secure:
                    waf_results.append({
                        'type': 'WAF Detection',
                        'severity': 'Info',
                        'description': f"The URL {domain_name} has strong security headers."
                    })
                else:
                    waf_results.append({
                        'type': 'WAF Detection',
                        'severity': 'Medium',
                        'description': f"The URL {domain_name} does not have strong security headers."
                    })

                # Store results in scan_results
                scan_results['findings']['waf_detection'] = waf_results
                print("\n[+] WAF Detection completed")

            elif choice == '14':
                # Advanced Domain Enumeration
                print("\n[*] Running Advanced Domain Enumeration...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                enumerator = AdvancedSubdomainEnumerator(domain_with_scheme)
                results = enumerator.run_enumeration()

                # Store results in scan_results
                scan_results['findings']['advanced_domain_enumeration'] = results
                print("\n[+] Advanced Domain Enumeration completed")

            elif choice == '15':
                # Cloud Vulnerability Scan
                print("\n[*] Running Cloud Vulnerability Scan...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                scanner = CloudSecurityScanner(domain_with_scheme)
                results = scanner.run_scan()

                # Store results in scan_results
                scan_results['findings']['cloud_vulnerabilities'] = results
                print("\n[+] Cloud Vulnerability Scan completed")

            elif choice == '16':
                # Advanced Web Application Scan
                print("\n[*] Running Advanced Web Application Scan...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                scanner = AdvancedWebAppTester(domain_with_scheme)
                results = scanner.run_tests()

                # Store results in scan_results
                scan_results['findings']['advanced_web_app_scan'] = results
                print("\n[+] Advanced Web Application Scan completed")

            elif choice == '17':
                # API Security Testing
                print("\n[*] Running API Security Testing...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                graphql_tester = GraphQLSecurityTester(domain_with_scheme)
                graphql_results = graphql_tester.run_tests()

                api_tester = APISecurityTester(domain_with_scheme)
                api_results = api_tester.run_tests()

                results = {
                    'graphql': graphql_results,
                    'general': api_results
                }

                # Store results in scan_results
                scan_results['findings']['api_security'] = results
                print("\n[+] API Security Testing completed")

            elif choice == '18':
                # AI-Powered Vulnerability Detection
                print("\n[*] Running AI-Powered Vulnerability Detection...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                detector = AIVulnerabilityDetector()

                try:
                    response = requests.get(
                        domain_with_scheme, headers=headers, timeout=10)
                    results = detector.analyze_response(response.text)

                    # Store results in scan_results
                    scan_results['findings']['ai_findings'] = results
                    print("\n[+] AI-Powered Vulnerability Detection completed")
                except Exception as e:
                    scan_results['findings']['ai_findings'] = {'error': str(e)}
                    print(f"\n[-] Error during AI scan: {e}")

            elif choice == '19':
                # Comprehensive Security Scan
                print("\n[*] Running Comprehensive Security Scan...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                results = run_comprehensive_scan(domain_with_scheme)

                # Update scan_results with comprehensive scan results
                scan_results.update(results)
                print("\n[+] Comprehensive Security Scan completed")

            elif choice == '20':
                # Security Tool Integration
                print("\n[*] Running Security Tool Integration...")

                if scan_results['findings']:
                    try:
                        tool_integration = SecurityToolIntegration()
                        export_results = tool_integration.export_all(
                            scan_results, domain_name)

                        print("\n[+] Export Results:")
                        for tool, success in export_results.items():
                            status = "Success" if success else "Failed"
                            print(f"  - {tool}: {status}")
                    except Exception as e:
                        print(f"\n[-] Error during export: {e}")
                else:
                    print("\n[-] No scan results available. Run scans first.")

            elif choice == '21':
                # Advanced Report Generation
                if scan_results['findings']:
                    print("\n[*] Generating Advanced Security Report...")
                    reporter = AdvancedSecurityReporter(
                        domain_name, scan_results)
                    reports = reporter.generate_all_reports()

                    print("\n[+] Reports generated successfully:")
                    for format_type, file_path in reports.items():
                        print(f"  - {format_type.upper()}: {file_path}")
                else:
                    print("\n[-] No scan results available. Run scans first.")

            elif choice == '22':
                # Sensitive Data Exposure
                print("\n[*] Running Sensitive Data Exposure Check...")
                domain_with_scheme = ensure_url_scheme(domain_name)
                tester = SensitiveDataExposureTester(domain_with_scheme)
                
                try:
                    results = tester.run_tests()
                    
                    # Store results
                    if 'findings' not in scan_results:
                        scan_results['findings'] = {}
                    
                    scan_results['findings']['sensitive_data'] = results
                    print("\n[+] Sensitive Data Exposure Check completed")
                    
                    for finding in results:
                        print(f"  - [{finding.get('severity', 'Info')}] {finding.get('description', '')}")
                        
                except Exception as e:
                    print(f"\n[-] Error during sensitive data check: {e}")

            elif choice == '23':
                if scan_results['findings']:
                    print("\n[*] Generating Advanced Security Report...")
                    reporter = AdvancedSecurityReporter(
                        domain_name, scan_results)
                    reports = reporter.generate_all_reports()

                    print("\n[+] Reports generated successfully:")
                    for format_type, file_path in reports.items():
                        print(f"  - {format_type.upper()}: {file_path}")
                print("Thank you for using VulnScan\nExiting...")
                sys.exit()
            else:
                print("\nInvalid option. Please enter a valid option (1-23)")



if __name__ == "__main__":
    main()
