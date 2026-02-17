import requests
import threading
import time
import os
import uuid
import socket
import difflib
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from fpdf import FPDF

class SecurityScanner:
    def __init__(self, target_url, threads=10, delay=0.05):
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        # Random User-Agent Rotation (Professional)
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"})
        
        self.results = {}
        self.logs = []
        self.lock = threading.Lock()
        self.request_delay = delay
        self.visited_urls = set()
        
        # Smart 404 Data
        self.soft_404_detected = False
        self.fake_404_length = 0

        # --- EXTENSIVE PAYLOADS ---
        
        # 1. Comprehensive Sensitive Files (Config, Backups, Cloud, Logs)
        self.sensitive_files = [
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.env', '/.env.save', '/.env.example', '/.env.local',
            '/config.php', '/wp-config.php', '/wp-config.php.bak',
            '/.git/config', '/.git/HEAD', '/.svn/entries', '/.DS_Store',
            '/phpinfo.php', '/info.php', '/test.php',
            '/.htaccess', '/.htpasswd', '/passwd', '/shadow', '/etc/passwd',
            '/backup.zip', '/backup.sql', '/dump.sql', '/database.sql',
            '/admin', '/administrator', '/dashboard', '/cpanel',
            '/server-status', '/apache-status',
            '/docker-compose.yml', '/Dockerfile',
            '/aws.yml', '/config.json', '/package.json', '/composer.json',
            '/id_rsa', '/id_rsa.pub', '/known_hosts',
            '/error_log', '/access.log', '/debug.log'
        ]

        # 2. Advanced SQL Injection (Union, Error, Boolean, Time-based)
        self.sql_payloads = [
            "' OR 1=1 --", 
            "' OR '1'='1",
            '" OR "1"="1',
            "' UNION SELECT null, version() --",
            "' UNION SELECT null, table_name FROM information_schema.tables --",
            "admin' --",
            "admin' #",
            "' AND SLEEP(5) --",  # Time-based (MySQL)
            "'; WAITFOR DELAY '0:0:5' --" # Time-based (MSSQL)
        ]
        
        # 3. Advanced XSS (Reflected, Polyglots, Event Handlers)
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\";alert(1);//",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>"
        ]

        # 4. Deep Directory Traversal (Linux & Windows)
        self.traversal_payloads = [
            '../../etc/passwd', 
            '..%2F..%2Fetc%2Fpasswd',
            '../../../etc/passwd',
            '..\\..\\windows\\win.ini',
            '%2e%2e/%2e%2e/etc/passwd'
        ]

        # 5. Top 50 Common Ports
        self.target_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 9090, 27017, 6379, 11211
        ]

    # --- HELPER FUNCTIONS ---
    def log(self, message):
        with self.lock:
            self.logs.append(message)
            print(message)

    def _delay_request(self):
        time.sleep(self.request_delay)

    # --- SMART 404 DETECTION ---
    def _calibrate_404(self):
        random_path = f"/random_{uuid.uuid4().hex[:8]}"
        fake_url = urljoin(self.target, random_path)
        try:
            resp = self.session.get(fake_url, timeout=5)
            if resp.status_code == 200:
                self.soft_404_detected = True
                self.fake_404_length = len(resp.text)
                self.log(f"[*] Soft 404 Detected. Calibrating filter...")
        except: pass

    def _is_false_positive(self, response):
        if response.status_code != 200: return False
        if "404" in response.text or "not found" in response.text.lower(): return True
        if self.soft_404_detected:
            if abs(len(response.text) - self.fake_404_length) < (self.fake_404_length * 0.05):
                return True
        return False

    # ---------------- MAIN RUN ----------------
    def run_scan(self, generate_pdf=True):
        self.log(f"[+] Starting Ultimate Scan on {self.target}")
        
        self._calibrate_404()

        self.log("[*] Phase 1: Subdomain & Asset Discovery...")
        self._scan_subdomains()

        self.log("[*] Phase 2: Server Fingerprinting...")
        self._fingerprint_tech()

        self.log(f"[*] Phase 3: Port Scanning ({len(self.target_ports)} Critical Ports)...")
        self._scan_ports()

        self.log("[*] Phase 4: Crawling & Link Analysis...")
        self._scan_links()

        self.log("[*] Phase 5: Deep Vulnerability Scanning...")
        
        threads = []
        threads.append(threading.Thread(target=self._scan_forms))
        threads.append(threading.Thread(target=self._test_sql_injection))
        threads.append(threading.Thread(target=self._test_xss))
        threads.append(threading.Thread(target=self._scan_sensitive_files))
        threads.append(threading.Thread(target=self._scan_directory_traversal))
        threads.append(threading.Thread(target=self._check_security_headers))
        
        for t in threads: t.start()
        for t in threads: t.join()

        pdf_filename = None
        if generate_pdf:
            self.log("[*] Generating Comprehensive Report...")
            pdf_filename = self._generate_pdf_report()

        self.log("[+] Scan Completed!")
        return self.results, self.logs, pdf_filename

    # ---------------- MODULES ----------------

    def _scan_subdomains(self):
        subs = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    subs.add(entry['name_value'].split('\n')[0])
        except: pass
        self.results['subdomains'] = list(subs)[:20]
        if subs: self.log(f" -> Found {len(subs)} subdomains")

    def _fingerprint_tech(self):
        stack = []
        try:
            resp = self.session.get(self.target, timeout=5)
            headers = resp.headers
            if 'Server' in headers: stack.append(f"Server: {headers['Server']}")
            if 'X-Powered-By' in headers: stack.append(f"Backend: {headers['X-Powered-By']}")
            if 'X-AspNet-Version' in headers: stack.append(f"ASP.NET: {headers['X-AspNet-Version']}")
            soup = BeautifulSoup(resp.text, 'html.parser')
            meta = soup.find("meta", {"name": "generator"})
            if meta: stack.append(f"Generator: {meta['content']}")
        except: pass
        self.results['technology'] = stack

    def _scan_ports(self):
        open_ports = []
        try:
            ip = socket.gethostbyname(self.domain)
            for port in self.target_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                sock.close()
        except: pass
        self.results['open_ports'] = open_ports
        if open_ports: self.log(f" -> Open Ports: {open_ports}")

    def _scan_links(self):
        try:
            if self.target in self.visited_urls: return
            self.visited_urls.add(self.target)
            resp = self.session.get(self.target, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            links = set()
            for a in soup.find_all('a', href=True):
                full = urljoin(self.target, a['href'])
                if self.domain in full: links.add(full)
            self.results['links'] = list(links)
            self.log(f" -> Found {len(links)} internal links")
        except: pass

    def _scan_forms(self):
        try:
            resp = self.session.get(self.target, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = []
            for f in soup.find_all('form'):
                forms.append({'action': f.get('action'), 'method': f.get('method', 'get').upper()})
            self.results['forms'] = forms
        except: pass

    # --- ATTACKS ---

    def _test_sql_injection(self):
        vuln = []
        remediation = {
            "desc": "SQL Injection allows attackers to manipulate queries.",
            "php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id=:id');",
            "python": "cursor.execute('SELECT * FROM users WHERE id=%s', (id,))"
        }
        params = ['id', 'user', 'q', 'search', 'cat', 'view', 'page', 'dir']
        for param in params:
            for payload in self.sql_payloads:
                url = f"{self.target}?{param}={payload}"
                try:
                    start_time = time.time()
                    resp = self.session.get(url, timeout=10)
                    end_time = time.time()
                    
                    if self._is_false_positive(resp): continue
                    
                    text = resp.text.lower()
                    if "syntax error" in text or "mysql" in text or "ora-" in text:
                        vuln.append({
                            'url': url, 
                            'payload': payload, 
                            'severity': 'CRITICAL', # UI Red
                            'remediation': remediation,
                            'evidence': 'Database syntax error reflected in response'
                        })
                        break
                    
                    if (end_time - start_time) > 5 and "SLEEP" in payload:
                        vuln.append({
                            'url': url, 
                            'payload': payload, 
                            'severity': 'CRITICAL', # UI Red
                            'remediation': remediation,
                            'evidence': 'Delayed response confirmed Time-based SQLi'
                        })
                        break

                except: continue
        self.results['sql_injection'] = vuln
        if vuln: self.log(f" -> Found {len(vuln)} SQLi issues")

    def _test_xss(self):
        vuln = []
        remediation = {
            "desc": "XSS allows executing malicious scripts in browser.",
            "php": "echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');",
            "general": "Implement Content Security Policy (CSP)."
        }
        params = ['q', 'search', 'query', 'name', 'msg', 'comment']
        for param in params:
            for payload in self.xss_payloads:
                url = f"{self.target}?{param}={payload}"
                try:
                    self._delay_request()
                    resp = self.session.get(url, timeout=3)
                    if payload in resp.text:
                        vuln.append({
                            'url': url, 
                            'severity': 'HIGH', # UI Orange
                            'remediation': remediation,
                            'evidence': 'Unsanitized input reflected in page source'
                        })
                except: continue
        self.results['xss'] = vuln
        if vuln: self.log(f" -> Found {len(vuln)} XSS issues")

    def _scan_sensitive_files(self):
        found = []
        remediation = {"desc": "Sensitive file exposed.", "apache": "<FilesMatch \"^\\.(env|git|config)\">\nDeny from all\n</FilesMatch>"}
        for f in self.sensitive_files:
            url = urljoin(self.target, f)
            try:
                self._delay_request()
                resp = self.session.get(url, timeout=3, allow_redirects=False)
                if resp.status_code == 200 and not self._is_false_positive(resp):
                    found.append({
                        'file': f, 
                        'url': url, 
                        'severity': 'HIGH', # UI Orange
                        'remediation': remediation,
                        'evidence': 'Publicly accessible sensitive configuration file'
                    })
            except: pass
        self.results['sensitive_files'] = found
        if found: self.log(f" -> Found {len(found)} sensitive files")

    def _scan_directory_traversal(self):
        vuln = []
        remediation = {"desc": "Path Traversal.", "php": "$file = basename($input);"}
        params = ['file', 'view', 'path', 'load', 'read']
        for param in params:
            for payload in self.traversal_payloads:
                url = f"{self.target}?{param}={payload}"
                try:
                    resp = self.session.get(url, timeout=3)
                    if "root:x:0:0" in resp.text or "[extensions]" in resp.text:
                        vuln.append({
                            'url': url, 
                            'severity': 'CRITICAL', # UI Red
                            'remediation': remediation,
                            'evidence': 'System file content leaked via path traversal'
                        })
                        break
                except: continue
        self.results['directory_traversal'] = vuln

    def _check_security_headers(self):
        missing = []
        headers = {
            'X-Frame-Options': {'fix': 'header("X-Frame-Options: SAMEORIGIN");', 'loc': '.htaccess / index.php'},
            'X-XSS-Protection': {'fix': 'header("X-XSS-Protection: 1; mode=block");', 'loc': '.htaccess'},
            'Content-Security-Policy': {'fix': "header(\"Content-Security-Policy: default-src 'self'\");", 'loc': 'index.php'},
            'Strict-Transport-Security': {'fix': 'header("Strict-Transport-Security: max-age=31536000");', 'loc': '.htaccess'},
            'X-Content-Type-Options': {'fix': 'header("X-Content-Type-Options: nosniff");', 'loc': '.htaccess'},
            'Referrer-Policy': {'fix': 'header("Referrer-Policy: no-referrer-when-downgrade");', 'loc': '.htaccess'},
            'Permissions-Policy': {'fix': 'header("Permissions-Policy: geolocation=()");', 'loc': '.htaccess'}
        }
        try:
            resp = self.session.head(self.target, timeout=5)
            for h, info in headers.items():
                if h not in resp.headers:
                    missing.append({
                        'header': h, 
                        'severity': 'LOW', # UI Blue
                        'description': 'Missing Header', 
                        'fix_php': info['fix'], 
                        'loc_php': info['loc'], 
                        'fix_apache': f'Header set {h} ...', 
                        'loc_apache': '.htaccess'
                    })
        except: pass
        self.results['missing_headers'] = missing

    # --- REPORTING ---
    def _generate_pdf_report(self):
        try:
            # Ensure reports folder exists for your updated logic
            if not os.path.exists('static/reports'): os.makedirs('static/reports')
            
            filename = f"report_{uuid.uuid4().hex[:6]}.pdf"
            filepath = os.path.join('static/reports', filename)
            
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 10, "MiniZAP Ultimate Report", ln=True, align='C')
            pdf.ln(10)
            
            pdf.set_font("Arial", "", 12)
            pdf.cell(0, 10, f"Target: {self.target}", ln=True)
            if 'technology' in self.results:
                pdf.cell(0, 10, f"Tech: {', '.join(self.results['technology'])}", ln=True)
            pdf.ln(5)

            for cat, items in self.results.items():
                if items:
                    pdf.set_font("Arial", "B", 14)
                    pdf.set_text_color(200, 0, 0)
                    pdf.cell(0, 10, cat.replace('_', ' ').upper(), ln=True)
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_font("Arial", "", 10)
                    for item in items[:15]: 
                        if isinstance(item, dict):
                            # Professional clean view for PDF
                            display_item = {k:v for k,v in item.items() if k not in ['remediation', 'fix_php', 'loc_php', 'fix_apache', 'loc_apache']}
                            pdf.multi_cell(0, 6, str(display_item))
                        else:
                            pdf.multi_cell(0, 6, str(item))
                        pdf.ln(2)
                    pdf.ln(5)
            
            pdf.output(filepath)
            return filename
        except Exception as e:
            print(f"PDF Error: {e}")
            return None
