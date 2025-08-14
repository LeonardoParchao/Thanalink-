""" 
Developer: Leonardo Teixeira Parchão
Date: 14/08/2025
Project: Thanálink - OSINT Tool
Version: 1.8
"""


import os
import re
import time
import smtplib
import urllib.parse
import dns.resolver
import requests
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QObject
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit,
    QComboBox, QFileDialog, QTextEdit, QProgressBar, QTabWidget, QLabel,
    QHBoxLayout, QMessageBox
)
from bs4 import BeautifulSoup
from PIL import Image
import PyPDF2
import random
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from typing import Dict, List, Set

class EmailOsint:
    """Performs various OSINT checks on an email address."""

    def __init__(self, email_address: str) -> None:
        """Initialize the EmailOsint object."""
        if not isinstance(email_address, str):
            raise TypeError("Email address must be a string")
        if not email_address:
            raise ValueError("Email address cannot be empty")
        self._email_address = email_address

    def check_for_breaches(self) -> dict:
        """Check if the email address has been involved in any known breaches."""
        url = (
            f"https://haveibeenpwned.com/unifiedsearch/{urllib.parse.quote(self._email_address)}"
        )
        headers = {"User-Agent": "OSINT-Tool/1.0"}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json() if response.content else {"Breaches": []}
        except requests.exceptions.RequestException as e:
            if e.response is not None and e.response.status_code == 404:
                return {"Breaches": []}
            raise RuntimeError(f"Failed to perform breach lookup: {e}") from e

    def find_public_info(self) -> list[str]:
        """Find any publicly available information about the email address."""
        url = (
            f"https://whatsmyname.app/?q={urllib.parse.quote(self._email_address)}"
        )
        headers = {"User-Agent": "OSINT-Tool/1.0"}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            if not response.content:
                return []
            soup = BeautifulSoup(response.text, 'html.parser')
            return [a['href'] for a in soup.select('tr:not(:first-child) a[href]')]
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Failed to find public information: {e}") from e

    def validate_mx_record(self) -> bool:
        """Check if the email address has a valid MX record and responds to an SMTP request."""
        try:
            domain = self._email_address.split('@')[-1]
            answers = dns.resolver.resolve(domain, 'MX')
            mx_records = [r.exchange.to_text().rstrip('.') for r in answers]
            for mx in mx_records:
                with smtplib.SMTP(timeout=5) as server:
                    server.connect(mx)
                    server.helo()
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
                dns.resolver.NoNameservers, smtplib.SMTPException) as e:
            raise RuntimeError(f"Failed to validate MX record: {e}") from e


class UsernameSearch:
    """Searches for a username on various platforms."""

    def __init__(self, username: str) -> None:
        """Initialize the UsernameSearch object."""
        if not isinstance(username, str):
            raise TypeError("Username must be a string")
        if not username:
            raise ValueError("Username cannot be empty")
        self._username = username
        self._platform_urls = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
        }

    def search(self) -> dict[str, bool]:
        """Search for the username on various platforms."""
        with requests.Session() as session:
            session.headers.update({
                'User-Agent': 'OSINT-Tool/1.0'
            })
            futures = []
            for platform, url in self._platform_urls.items():
                futures.append(
                    self._async_search(session, platform, url)
                )
            return {
                platform: result.result() if result.exception() is None else False
                for platform, result in zip(self._platform_urls, futures)
            }

    @staticmethod
    async def _async_search(session, platform, url):
        try:
            response = await session.get(url, timeout=5, allow_redirects=False)
            return response.status_code == 200
        except requests.exceptions.RequestException as error:
            if error.response is not None:
                return False
            else:
                raise RuntimeError(
                    f"Failed to retrieve search results for {platform}: {error}"
                ) from error
        except Exception as error:
            if error.args:
                raise RuntimeError(
                    f"An unexpected error occurred while searching for {platform}: {error}"
                ) from error


class DomainOsint:
    """Performs Open Source Intelligence (OSINT) on a domain."""

    def __init__(self, domain: str) -> None:
        """Initialize the DomainOsint object."""
        if not isinstance(domain, str):
            raise TypeError("Domain must be a string")
        if not domain:
            raise ValueError("Domain cannot be empty")
        self._domain = domain

    @property
    def domain(self) -> str:
        """Get the domain."""
        return self._domain

    async def whois_lookup(self) -> str:
        """Perform a WHOIS lookup on the domain."""
        url = f"https://www.whois.com/whois/{self.domain}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    response.raise_for_status()
                    if not response.content:
                        raise RuntimeError("Failed to retrieve WHOIS lookup results")
                    return await response.text()
        except aiohttp.ClientError as error:
            raise RuntimeError(
                f"Failed to perform WHOIS lookup: {error}"
            ) from error

    async def subdomain_enumeration(self) -> list[str]:
        """Enumerate subdomains of the domain."""
        try:
            answers = await aiodns.DNS.resolve(self.domain, "NS")
            subdomains = [
                rdata.to_text().rstrip(".").split(".", 1)[0]
                for rdata in answers
                if rdata.to_text().rstrip(".").split(".", 1)[0] != self.domain
            ]
            if not subdomains:
                raise RuntimeError("Failed to retrieve subdomains")
            return subdomains
        except (aiodns.error.DNSException, aiodns.error.AddressFormatError) as error:
            raise RuntimeError(
                f"Failed to perform subdomain enumeration: {error}"
            ) from error

    async def port_scan(self, top_ports: int = 10) -> list[int]:
        """Scan for open ports on the domain."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389]
        ports = common_ports[: min(top_ports, len(common_ports))]
        open_ports = []
        try:
            ip = await aiodns.DNS.resolve(self.domain, "A")
            for port in ports:
                async with aiohttp.ClientSession() as session:
                    async with session.head(
                        f"http://{ip}:{port}", timeout=1
                    ) as response:
                        if response.status == 200:
                            open_ports.append(port)
            if not open_ports:
                raise RuntimeError("Failed to retrieve open ports")
            return open_ports
        except (aiodns.error.DNSException, aiodns.error.AddressFormatError, aiohttp.ClientError) as error:
            raise RuntimeError(
                f"Failed to perform port scan: {error}"
            ) from error


class DocumentScanner:
    """Scan a document for metadata and extract content."""

    def __init__(self, file_path: str) -> None:
        """Initialize the scanner with a file path."""
        if not isinstance(file_path, str):
            raise TypeError("File path must be a string")
        if not file_path:
            raise ValueError("File path cannot be empty")
        self.file_path = file_path

    def scan(self) -> Dict[str, str]:
        """Scan the document and return the metadata as a dictionary."""
        if not os.path.exists(self.file_path):
            raise RuntimeError("File does not exist")
        if self.file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif')):
            return self._scan_image()
        if self.file_path.lower().endswith('.pdf'):
            return self._scan_pdf()
        raise RuntimeError("Unsupported file type")

    def _scan_image(self) -> Dict[str, str]:
        """Scan the image and return the metadata as a dictionary."""
        try:
            with Image.open(self.file_path) as img:
                info = img.info or {}
                return {
                    'author': info.get('Author', 'N/A'),
                    'created': info.get('Creation Time', 'N/A'),
                    'modified': info.get('Modify Date', 'N/A'),
                    'software': info.get('Software', 'N/A')
                }
        except IOError as e:
            raise RuntimeError("Failed to open image") from e

    def _scan_pdf(self) -> Dict[str, str]:
        """Scan the PDF and return the metadata as a dictionary."""
        try:
            with open(self.file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                metadata = pdf.metadata or {}
                return {
                    'author': metadata.get('/Author', 'N/A'),
                    'created': metadata.get('/CreationDate', 'N/A'),
                    'modified': metadata.get('/ModDate', 'N/A'),
                    'software': metadata.get('/Creator', 'N/A')
                }
        except PyPDF2.PdfReadError as e:
            raise RuntimeError("Failed to read PDF") from e

    def extract_content(self) -> Dict[str, List[str]]:
        """Extract content from the document and return a dictionary of emails, domains, and links."""
        results = {'emails': [], 'domains': [], 'links': []}
        if not self.file_path.lower().endswith('.pdf'):
            return results
        try:
            with open(self.file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                text = "".join(page.extract_text() or "" for page in pdf.pages)
                emails: Set[str] = set(re.findall(r'[\w\.-]+@[\w\.-]+', text))
                results['emails'] = list(emails)
                domains: Set[str] = {email.split('@')[-1] for email in emails}
                results['domains'] = list(domains)
                results['links'] = list(set(re.findall(r'https?://[^\s]+', text)))
                return results
        except PyPDF2.PdfReadError as e:
            raise RuntimeError("Failed to read PDF") from e


class GoogleDorking:
    def __init__(self):
        self.driver = None
        self.options = webdriver.ChromeOptions()
        self.options.add_argument('--headless')
        self.options.add_argument('--disable-gpu')
        self.options.add_argument('--disable-blink-features=AutomationControlled')
        self.options.add_argument('--disable-infobars')
        self.options.add_argument('--window-size=1920,1080')
        self.options.add_argument('--disable-features=ClientSidePhishingDetection')
        self.options.add_argument('--disable-features=SiteIsolation')
        self.options.add_argument('--disable-features=site-per-process')
        self.options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3')
        self.options.add_argument('--no-sandbox')
        self.options.add_argument('--disable-dev-shm-usage')
        self.options.add_argument('--disable-gpu-sandbox')
        self.options.add_argument('--headless=new')

    def _initialize_driver(self):
        if self.driver is None:
            self.driver = webdriver.Chrome(options=self.options)

    def search(self, query, file_type=None, domain=None):
        self._initialize_driver()
        query_parts = [f'"{query}"']
        if file_type:
            query_parts.append(f"filetype:{file_type}")
        if domain:
            query_parts.append(f"site:{domain}")
        time.sleep(random.uniform(1.5, 3.5))
        full_query = " ".join(query_parts)
        url = f"https://www.google.com/search?q={urllib.parse.quote(full_query)}"
        self.driver.get(url)
        time.sleep(random.uniform(2, 3))
        soup = BeautifulSoup(self.driver.page_source, 'html.parser')
        return [
            urllib.parse.unquote(href.split('/url?q=')[1].split('&')[0])
            for a in soup.find_all('a', href=True)
            if (href := a['href']).startswith('/url?q=')
        ]

    def get_results(self, query_parts):
        """Retrieve search results from Google"""
        self._initialize_driver()
        user_agent = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393'
        ])
        self.options.add_argument(f"--user-agent={user_agent}")
        self.driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        self.driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        })

        full_query = " ".join(query_parts)
        url = f"https://www.google.com/search?q={urllib.parse.quote(full_query)}"
        self.driver.get(url)
        time.sleep(random.uniform(2, 3))
        soup = BeautifulSoup(self.driver.page_source, 'html.parser')
        return [
            urllib.parse.unquote(href.split('/url?q=')[1].split('&')[0])
            for a in soup.find_all('a', href=True)
            if (href := a['href']).startswith('/url?q=')
        ]

    def __del__(self):
        if self.driver:
            self.driver.quit()


class Worker(QObject):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, task, *args):
        super().__init__()
        if task is None:
            raise ValueError("Task cannot be null")
        self.task = task
        self.args = args
        self._is_running = True

    def run(self):
        if not self._is_running:
            raise RuntimeError("Worker is not running")

        try:
            if self.task is None:
                raise ValueError("Task is null")
            result = self.task(*self.args)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self._is_running = False


class ThreadController:
    def __init__(self):
        self.workers = []
        self.threads = []

    def start_worker(self, worker):
        if worker is None:
            raise ValueError("Worker cannot be null")
        
        thread = QThread()
        worker.moveToThread(thread)
        
        thread.started.connect(worker.run)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        worker.error.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        
        self.workers.append(worker)
        self.threads.append(thread)
        
        thread.finished.connect(
            lambda: self.cleanup(worker, thread)
        )
        
        thread.start()
        return worker

    def cleanup(self, worker, thread):
        if worker in self.workers:
            self.workers.remove(worker)
        if thread in self.threads:
            self.threads.remove(thread)

    def shutdown(self):
        if self.threads is None:
            return
        for thread in self.threads:
            if thread is None:
                continue
            if thread.isRunning():
                thread.quit()
                thread.wait(2000)


class OSINTTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Tool")
        self.setGeometry(100, 100, 800, 600)
        self.thread_controller = ThreadController()
        self.init_ui()
        
    def init_ui(self):
        tabs = QTabWidget()
        
        tabs.addTab(self.create_dorking_tab(), "Google Dorking")
        tabs.addTab(self.create_email_tab(), "Email OSINT")
        tabs.addTab(self.create_username_tab(), "Username Search")
        tabs.addTab(self.create_domain_tab(), "Domain OSINT")
        tabs.addTab(self.create_document_tab(), "Document Scanner")
        
        self.setCentralWidget(tabs)
    
    def closeEvent(self, event):
        self.thread_controller.shutdown()
        event.accept()
    
    def create_email_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Email Address:"))
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("user@example.com")
        layout.addWidget(self.email_input)
        
        btn_layout = QHBoxLayout()
        self.breach_btn = QPushButton("Check Breaches")
        self.breach_btn.clicked.connect(self.run_breach_check)
        btn_layout.addWidget(self.breach_btn)
        
        self.links_btn = QPushButton("Find Links")
        self.links_btn.clicked.connect(self.run_email_links)
        btn_layout.addWidget(self.links_btn)
        
        self.mx_btn = QPushButton("Validate MX")
        self.mx_btn.clicked.connect(self.run_mx_validation)
        btn_layout.addWidget(self.mx_btn)
        layout.addLayout(btn_layout)
        
        self.email_results = QTextEdit()
        self.email_results.setReadOnly(True)
        layout.addWidget(self.email_results)
        
        tab.setLayout(layout)
        return tab
    
    def create_domain_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Domain:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        layout.addWidget(self.domain_input)
        
        btn_layout = QHBoxLayout()
        self.whois_btn = QPushButton("WHOIS Lookup")
        self.whois_btn.clicked.connect(self.run_whois)
        btn_layout.addWidget(self.whois_btn)
        
        self.subdomain_btn = QPushButton("Find Subdomains")
        self.subdomain_btn.clicked.connect(self.run_subdomain_enum)
        btn_layout.addWidget(self.subdomain_btn)
        
        self.port_btn = QPushButton("Port Scan")
        self.port_btn.clicked.connect(self.run_port_scan)
        btn_layout.addWidget(self.port_btn)
        layout.addLayout(btn_layout)
        
        self.domain_results = QTextEdit()
        self.domain_results.setReadOnly(True)
        layout.addWidget(self.domain_results)
        
        tab.setLayout(layout)
        return tab
    
    def create_username_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Username:"))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("johndoe")
        layout.addWidget(self.username_input)
        
        self.search_btn = QPushButton("Search Platforms")
        self.search_btn.clicked.connect(self.run_username_search)
        layout.addWidget(self.search_btn)
        
        self.username_results = QTextEdit()
        self.username_results.setReadOnly(True)
        layout.addWidget(self.username_results)
        
        tab.setLayout(layout)
        return tab
    
    def create_document_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        file_layout.addWidget(self.file_input)
        
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)
        
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Metadata")
        self.scan_btn.clicked.connect(self.run_document_scan)
        btn_layout.addWidget(self.scan_btn)
        
        self.extract_btn = QPushButton("Extract Content")
        self.extract_btn.clicked.connect(self.run_document_extract)
        btn_layout.addWidget(self.extract_btn)
        layout.addLayout(btn_layout)
        
        self.document_results = QTextEdit()
        self.document_results.setReadOnly(True)
        layout.addWidget(self.document_results)
        
        tab.setLayout(layout)
        return tab
    
    def create_dorking_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Search Query:"))
        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("search terms")
        layout.addWidget(self.query_input)
        
        filters_layout = QHBoxLayout()
        
        filters_layout.addWidget(QLabel("File Type:"))
        self.file_type_combo = QComboBox()
        self.file_type_combo.addItems(['Any', 'PDF', 'DOCX', 'TXT', 'CSV'])
        filters_layout.addWidget(self.file_type_combo)
        
        filters_layout.addWidget(QLabel("Domain:"))
        self.domain_filter = QLineEdit()
        self.domain_filter.setPlaceholderText("example.com")
        filters_layout.addWidget(self.domain_filter)
        layout.addLayout(filters_layout)
        
        btn_layout = QHBoxLayout()
        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.run_dorking_search)
        btn_layout.addWidget(self.search_btn)
        
        self.save_btn = QPushButton("Save Results")
        self.save_btn.clicked.connect(self.save_dorking_results)
        btn_layout.addWidget(self.save_btn)
        layout.addLayout(btn_layout)
        
        self.dorking_results = QTextEdit()
        self.dorking_results.setReadOnly(True)
        layout.addWidget(self.dorking_results)
        
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        tab.setLayout(layout)
        return tab

    def run_breach_check(self):
        email = self.email_input.text().strip()
        if not self.validate_email(email):
            return
            
        self.email_results.clear()
        self.email_results.append("Checking breaches...")
        
        try:
            worker = Worker(EmailOsint(email).breach_lookup)
            worker.finished.connect(self.handle_breach_results)
            worker.error.connect(lambda e: self.email_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.email_results.append(f"Error: {str(e)}")

    def handle_breach_results(self, results):
        breaches = results.get("Breaches", [])
        if not breaches:
            self.email_results.append("No breaches found")
            return
            
        self.email_results.append(f"Found {len(breaches)} breaches:\n")
        for breach in breaches:
            self.email_results.append(
                f"• {breach['Name']} ({breach['BreachDate']})\n"
                f"  Compromised: {', '.join(breach['DataClasses'])}\n"
            )

    def run_email_links(self):
        email = self.email_input.text().strip()
        if not self.validate_email(email):
            return
            
        self.email_results.clear()
        self.email_results.append("Finding associated links...")
        
        try:
            worker = Worker(EmailOsint(email).find_email_links)
            worker.finished.connect(self.handle_email_links)
            worker.error.connect(lambda e: self.email_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.email_results.append(f"Error: {str(e)}")

    def handle_email_links(self, links):
        if not links:
            self.email_results.append("No associated links found")
            return
            
        self.email_results.append(f"Found {len(links)} links:\n")
        for link in links:
            self.email_results.append(f"• {link}")

    def run_mx_validation(self):
        email = self.email_input.text().strip()
        if not self.validate_email(email):
            return
            
        self.email_results.clear()
        self.email_results.append("Validating MX records...")
        
        try:
            worker = Worker(EmailOsint(email).mx_smtp_validation)
            worker.finished.connect(self.handle_mx_validation)
            worker.error.connect(lambda e: self.email_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.email_results.append(f"Error: {str(e)}")

    def handle_mx_validation(self, valid):
        self.email_results.append(
            "MX validation successful" if valid 
            else "MX validation failed or domain not found"
        )

    def run_whois(self):
        domain = self.domain_input.text().strip()
        if not self.validate_domain(domain):
            return
            
        self.domain_results.clear()
        self.domain_results.append("Running WHOIS lookup...")
        
        try:
            worker = Worker(DomainOsint(domain).whois_lookup)
            worker.finished.connect(self.handle_whois_results)
            worker.error.connect(lambda e: self.domain_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.domain_results.append(f"Error: {str(e)}")

    def handle_whois_results(self, result):
        self.domain_results.setPlainText(result)

    def run_subdomain_enum(self):
        domain = self.domain_input.text().strip()
        if not self.validate_domain(domain):
            return
            
        self.domain_results.clear()
        self.domain_results.append("Finding subdomains...")
        
        try:
            worker = Worker(DomainOsint(domain).subdomain_enumeration)
            worker.finished.connect(self.handle_subdomain_results)
            worker.error.connect(lambda e: self.domain_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.domain_results.append(f"Error: {str(e)}")

    def handle_subdomain_results(self, subdomains):
        if not subdomains:
            self.domain_results.append("No subdomains found")
            return
            
        self.domain_results.append(f"Found {len(subdomains)} subdomains:\n")
        for sub in subdomains:
            self.domain_results.append(f"• {sub}")

    def run_port_scan(self):
        domain = self.domain_input.text().strip()
        if not self.validate_domain(domain):
            return
            
        self.domain_results.clear()
        self.domain_results.append("Scanning ports...")
        
        try:
            worker = Worker(DomainOsint(domain).port_scan)
            worker.finished.connect(self.handle_port_scan_results)
            worker.error.connect(lambda e: self.domain_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.domain_results.append(f"Error: {str(e)}")

    def handle_port_scan_results(self, open_ports):
        if not open_ports:
            self.domain_results.append("No open ports found")
            return
            
        self.domain_results.append(f"Open ports on {self.domain_input.text()}:\n")
        for port in open_ports:
            self.domain_results.append(f"• Port {port}")

    def run_username_search(self):
        username = self.username_input.text().strip()
        if not username:
            self.show_error("Please enter a username")
            return
            
        self.username_results.clear()
        self.username_results.append(f"Searching for {username}...")
        
        try:
            worker = Worker(UsernameSearch(username).search)
            worker.finished.connect(self.handle_username_results)
            worker.error.connect(lambda e: self.username_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.username_results.append(f"Error: {str(e)}")

    def handle_username_results(self, results):
        self.username_results.clear()
        self.username_results.append("Search Results:\n")
        
        for platform, exists in results.items():
            status = "✓ Found" if exists else "✗ Not Found"
            self.username_results.append(f"{platform}: {status}")

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Document", "", 
            "Documents (*.pdf *.docx *.txt);;Images (*.png *.jpg *.jpeg)"
        )
        if file_path:
            self.file_input.setText(file_path)

    def run_document_scan(self):
        file_path = self.file_input.text()
        if not file_path:
            self.show_error("Please select a document")
            return
            
        self.document_results.clear()
        self.document_results.append("Scanning document metadata...")
        
        try:
            worker = Worker(DocumentScanner(file_path).scan)
            worker.finished.connect(self.handle_document_scan)
            worker.error.connect(lambda e: self.document_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.document_results.append(f"Error: {str(e)}")

    def handle_document_scan(self, metadata):
        if isinstance(metadata, str): 
            self.document_results.append(f"Error: {metadata}")
            return
            
        self.document_results.clear()
        self.document_results.append("Document Metadata:\n")
        self.document_results.append(f"Author: {metadata.get('author', 'N/A')}")
        self.document_results.append(f"Created: {metadata.get('created', 'N/A')}")
        self.document_results.append(f"Modified: {metadata.get('modified', 'N/A')}")
        self.document_results.append(f"Software: {metadata.get('software', 'N/A')}")

    def run_document_extract(self):
        file_path = self.file_input.text()
        if not file_path:
            self.show_error("Please select a document")
            return
            
        self.document_results.clear()
        self.document_results.append("Extracting content...")
        
        try:
            worker = Worker(DocumentScanner(file_path).extract_content)
            worker.finished.connect(self.handle_document_extract)
            worker.error.connect(lambda e: self.document_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.document_results.append(f"Error: {str(e)}")

    def handle_document_extract(self, content):
        self.document_results.clear()
        self.document_results.append("Extracted Content:\n")
        
        if content['emails']:
            self.document_results.append("\nEmails:")
            for email in content['emails']:
                self.document_results.append(f"• {email}")
                
        if content['domains']:
            self.document_results.append("\nDomains:")
            for domain in content['domains']:
                self.document_results.append(f"• {domain}")
                
        if content['links']:
            self.document_results.append("\nLinks:")
            for link in content['links']:
                self.document_results.append(f"• {link}")
                
        if not any(content.values()):
            self.document_results.append("No extractable content found")


    def run_dorking_search(self):
        query = self.query_input.text().strip()
        if not query:
            self.show_error("Please enter a search query")
            return
            
        file_type = self.file_type_combo.currentText().lower()
        domain = self.domain_filter.text().strip() or None
        
        self.dorking_results.clear()
        self.dorking_results.append("Searching...")
        self.progress_bar.setValue(0)
        
        try:
            worker = Worker(GoogleDorking().search, query, file_type, domain)
            worker.finished.connect(self.handle_dorking_results)
            worker.error.connect(lambda e: self.dorking_results.append(f"Error: {e}"))
            self.thread_controller.start_worker(worker)
        except Exception as e:
            self.dorking_results.append(f"Error: {str(e)}")

    def handle_dorking_results(self, results):
        self.progress_bar.setValue(100)
        
        if not results:
            self.dorking_results.append("No results found")
            return
            
        self.dorking_results.clear()
        self.dorking_results.append(f"Found {len(results)} results:\n")
        for result in results:
            self.dorking_results.append(f"• {result}")

    def save_dorking_results(self):
        if not (results := self.dorking_results.toPlainText()):
            self.show_error("No results to save")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "Text Files (*.txt)"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(results)
                self.dorking_results.append(f"\nResults saved to {file_path}")
            except Exception as e:
                self.show_error(f"Save failed: {str(e)}")

    def validate_email(self, email):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            self.show_error("Please enter a valid email address")
            return False
        return True

    def validate_domain(self, domain):
        if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
            self.show_error("Please enter a valid domain name")
            return False
        return True

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)


if __name__ == '__main__':
    app = QApplication([])
    app.setStyle("Fusion")
    window = OSINTTool()
    window.show()
    app.exec_()

