# 🔍 VulnScan
**VulnScan** is a powerful and lightweight **Web Penetration Testing Toolkit** developed over 3 years of research, crafted to assist ethical hackers, security researchers, and developers in identifying web application vulnerabilities quickly and efficiently.
> ⚡ Built with passion. Backed by real-world interviews. Recognized by industry leaders.
---
## 🚀 Features
VulnScan currently includes **21 powerful modules**:

1. Change Target Domain  
   - Function: `ensure_url_scheme`

2. Port Scanning  
   - Functions: `scan_single_port`, `scan_custom_ports`, `scan_range_of_ports`

3. Domain Enumeration  
   - Functions: `from_file`, `check_subdomain`, `append_if_exists`, `get_active`

4. Domain Fingerprinting  
   - Function: `get_server_info`

5. SQL Injection Testing  
   - Functions: `is_vulnerable`, `test_sql_injection`

6. Cross-Site Scripting (XSS) Testing  
   - Functions: `get_forms`, `form_details`, `submit_form`, `scan_xss`

7. CSRF Detection  
   - Function: `csrf`

8. SSL/TLS Certificate Detection  
   - Functions: `certificate`, `analyze_certificate`

9. Server Geolocation  
   - Function: `get_location`

10. Directory Enumeration  
    - Function: `directory_enumeration`

11. Web Application Vulnerability Scanning  
    - Function: `web_application_vulnerability_scanner`

12. Crawling and Spidering  
    - Function: `crawl_and_spider`

13. WAF Detection
    - Function: `detect_waf`

### Advanced Modules
14. **Advanced Domain Enumeration**  
    - Class: `AdvancedSubdomainEnumerator`
    - Method: `run_enumeration`

15. **Cloud Vulnerability Scan**  
    - Class: `CloudSecurityScanner`
    - Method: `run_scan`

16. **Advanced Web Application Scan**  
    - Class: `AdvancedWebAppTester`
    - Method: `run_tests`

17. **API Security Testing**  
    - Classes: `GraphQLSecurityTester`, `APISecurityTester`
    - Methods: `run_tests`

18. **AI-Powered Vulnerability Detection**  
    - Class: `AIVulnerabilityDetector`
    - Method: `analyze_response`

19. **Comprehensive Security Scan**  
    - Function: `run_comprehensive_scan`

20. **Security Tool Integration**  
    - Class: `SecurityToolIntegration`
    - Method: `export_all`

21. **Advanced Report Generation**  
    - Class: `AdvancedSecurityReporter`
    - Method: `generate_all_reports`

> Each module is plug-and-play and optimized for fast, accurate results.

---

## 📦 Installation
```bash
git clone https://github.com/iamgokulkannan/vulnscan.git
cd vulnscan
pip install -r requirements.txt
python pdf_vulnscan_updated.py